// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use base64::{engine::general_purpose, Engine as _};
use bs58::Alphabet;
use derivation_path::{ChildIndex, DerivationPath};
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, Curve},
    ProjectivePoint, Scalar, Secp256k1, U256,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 4-byte Key fingerprint
pub type KeyFingerPrint = [u8; 4];

const KEY_SIZE: usize = 32;

/// BIP32 version bytes
#[derive(Debug, Clone, Copy)]
pub enum Prefix {
    /// 'xpub' prefix
    XPub,
    /// 'ypub' prefix
    YPub,
    /// 'zpub' prefix
    ZPub,
    /// 'tpub' prefix
    TPub,
    /// Custom prefix
    Custom(u32),
}

impl Prefix {
    /// Get the prefix as a 4-byte array
    pub fn as_bytes(&self) -> [u8; 4] {
        u32::from(*self).to_be_bytes()
    }
}

impl From<Prefix> for u32 {
    fn from(prefix: Prefix) -> Self {
        match prefix {
            Prefix::XPub => 0x0488b21e,
            Prefix::YPub => 0x049d7cb2,
            Prefix::ZPub => 0x04b24746,
            Prefix::TPub => 0x043587cf,
            Prefix::Custom(prefix) => prefix,
        }
    }
}

impl From<[u8; 4]> for Prefix {
    fn from(prefix: [u8; 4]) -> Self {
        match prefix {
            [0x04, 0x88, 0xb2, 0x1e] => Prefix::XPub,
            [0x04, 0x9d, 0x7c, 0xb2] => Prefix::YPub,
            [0x04, 0xb2, 0x47, 0x46] => Prefix::ZPub,
            [0x04, 0x35, 0x87, 0xcf] => Prefix::TPub,
            _ => Prefix::Custom(u32::from_be_bytes(prefix)),
        }
    }
}

/// Extended public key
#[derive(Clone, Debug)]
pub struct XPubKey {
    /// Prefix (version) as a 4-byte integer
    pub prefix: Prefix,
    /// Parent fingerprint
    pub parent_fingerprint: KeyFingerPrint,
    /// Child number
    pub child_number: u32,
    /// Public key
    pub pubkey: ProjectivePoint,
    /// Root chain code
    pub chain_code: [u8; 32],
    /// Depth
    pub depth: u8,
}

fn base58_encode(serialized: [u8; 78]) -> String {
    let checksum: [u8; 4] = Sha256::digest(Sha256::digest(serialized))[..4]
        .try_into()
        .unwrap();

    let serialized = [&serialized, checksum.as_slice()].concat();
    bs58::encode(serialized)
        .with_alphabet(Alphabet::BITCOIN)
        .into_string()
}

/// Errors while performing keygen
#[derive(Error, Debug)]
pub enum BIP32Error {
    /// Hardened child index is not supported
    #[error("Hardened child index is not supported (yet)")]
    HardenedChildNotSupported,
    /// Invalid chain code
    #[error("Invalid chain code")]
    InvalidChainCode,
    /// Invalid public key, it cannot be the point at infinity
    #[error("Invalid public key, cannot be the point at infinity")]
    PubkeyPointAtInfinity,
    /// Invalid child key, it cannot be greater than the group order (extremely unlikely)
    #[error("Invalid child key, cannot be greater than the group order")]
    InvalidChildScalar,
}

impl XPubKey {
    /// Serialize to string
    /// # Arguments
    /// * `encoded` - If true, the string will be encoded to Base58 with checksum (like Bitcoin addresses)
    pub fn to_string(&self, encoded: bool) -> String {
        let serialized = [
            &self.prefix.as_bytes(),
            self.depth.to_be_bytes().as_slice(),
            &self.parent_fingerprint,
            &self.child_number.to_be_bytes(),
            self.chain_code.as_slice(),
            self.pubkey.to_encoded_point(true).as_bytes(),
        ]
        .concat();

        let serialized: [u8; 78] = serialized.try_into().expect(
            "Invalid serialized extended public key length, must be 78 bytes",
        );

        if encoded {
            base58_encode(serialized)
        } else {
            hex::encode(serialized)
        }
    }
}

/// Derive a child public key from a parent public key and a parent chain code
pub fn derive_child_pubkey(
    parent_pubkey: &ProjectivePoint,
    parent_chain_code: [u8; 32],
    child_number: &ChildIndex,
) -> Result<(Scalar, ProjectivePoint, [u8; 32]), BIP32Error> {
    let mut hmac_hasher =
        Hmac::<sha2::Sha512>::new_from_slice(&parent_chain_code)
            .map_err(|_| BIP32Error::InvalidChainCode)?;

    if child_number.is_normal() {
        hmac_hasher.update(parent_pubkey.to_encoded_point(true).as_bytes());
    } else {
        return Err(BIP32Error::HardenedChildNotSupported);
    }

    hmac_hasher.update(&child_number.to_bits().to_be_bytes());
    let result = hmac_hasher.finalize().into_bytes();
    let (il_int, child_chain_code) = result.split_at(KEY_SIZE);
    let il_int = U256::from_be_slice(il_int);

    // Has a chance of 1 in 2^127
    if il_int > Secp256k1::ORDER {
        return Err(BIP32Error::InvalidChildScalar);
    }

    let pubkey = ProjectivePoint::GENERATOR * Scalar::reduce(il_int);

    let child_pubkey = pubkey + parent_pubkey;

    // Return error if child pubkey is the point at infinity
    if child_pubkey == ProjectivePoint::IDENTITY {
        return Err(BIP32Error::PubkeyPointAtInfinity);
    }

    Ok((
        Scalar::reduce(il_int),
        child_pubkey,
        child_chain_code.try_into().unwrap(),
    ))
}

/// Get the fingerprint of the root public key
pub fn get_finger_print(public_key: &ProjectivePoint) -> KeyFingerPrint {
    let pubkey_bytes: [u8; 33] = public_key
        .to_encoded_point(true)
        .as_bytes()
        .as_ref()
        .try_into()
        .expect("compressed pubkey must be 33 bytes");

    let digest = Ripemd160::digest(Sha256::digest(pubkey_bytes));
    digest[..4].try_into().expect("digest truncated")
}

/// Generate a key ID from a root public key and root chain code
/// # Arguments
/// * `root_pubkey` - Root public key SEC1's compressed form (33 bytes)
/// * `root_chain_code` - Root chain code (32 bytes)
/// # Returns
/// * `key_id` - Base64 encoded string
pub fn generate_key_id(
    root_pubkey: &ProjectivePoint,
    root_chain_code: [u8; 32],
) -> String {
    let id = sha2::Sha256::new()
        .chain_update(root_pubkey.to_encoded_point(true).as_bytes().as_ref())
        .chain_update(root_chain_code)
        .finalize();

    general_purpose::STANDARD_NO_PAD.encode(id)
}

/// Derive the extended public key for a given derivation path and prefix
/// # Arguments
/// * `prefix` - Prefix for the extended public key (`Prefix` has commonly used prefixes)
/// * `chain_path` - Derivation path
///
/// # Returns
/// * `XPubKey` - Extended public key
pub fn derive_xpub(
    prefix: Prefix,
    root_public_key: &ProjectivePoint,
    root_chain_code: [u8; 32],
    chain_path: DerivationPath,
) -> Result<XPubKey, BIP32Error> {
    let mut pubkey = *root_public_key;
    let mut chain_code = root_chain_code;
    let mut parent_fingerprint: [u8; 4] = [0u8; 4];

    let path = chain_path.path();

    let depth = path.len();

    let final_child_num = if depth == 0 {
        &ChildIndex::Normal(0)
    } else {
        &path[depth - 1]
    };

    for child_num in path {
        parent_fingerprint = get_finger_print(&pubkey);
        let (_, child_pubkey, child_chain_code) =
            derive_child_pubkey(&pubkey, chain_code, child_num)?;
        pubkey = child_pubkey;
        chain_code = child_chain_code;
    }

    Ok(XPubKey {
        prefix,
        depth: depth as u8,
        parent_fingerprint,
        child_number: final_child_num.to_u32(),
        chain_code,
        pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ProjectivePoint, [u8; 32]) {
        // let private_key = Scalar::from(Scalar::<Secp256k1>::group_order() - 5);
        let a: u32 = 5;
        let private_key = Scalar::ZERO - Scalar::from(a);

        let root_public_key = ProjectivePoint::GENERATOR * private_key;
        let root_chain_code = Sha256::digest("test".as_bytes());

        (root_public_key, root_chain_code.into())
    }

    #[test]
    fn test_derive_base() {
        let (root_public_key, root_chain_code) = setup();

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m".parse().unwrap(),
        )
        .unwrap();

        let xpub_string = xpub.to_string(true);

        assert_eq!(xpub.child_number, 0);
        assert_eq!(xpub.depth, 0);
        assert_eq!(xpub.parent_fingerprint, [0u8; 4]);

        println!("{}", xpub_string);
        println!("{}", hex::encode(root_chain_code));
        println!(
            "{}",
            hex::encode(root_public_key.to_encoded_point(true).as_bytes())
        );
    }

    #[test]
    fn test_derive_level_1() {
        let (root_public_key, root_chain_code) = setup();

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/0".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub69J3tUsuDC7sgV1yswvgycmUJDywzCVDTfqLzzj6swGgYgFYb9mHpo972CidTGpb2eet5TcStoTMVCHKD9DPtP51qnPK2UMXC9roMkKtz4d", xpub.to_string(true));
        assert_eq!(xpub.child_number, 0);
        assert_eq!(xpub.depth, 1);

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/1".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub69J3tUsuDC7sj7dLhhSwNG3myVgtC1iUjUZdaQejqmPfr2TAPWpfgukduSxPsiNV2ijVkguuSyXNWa8FyYauKe6XYwEsuyWM99JHVCVkhdJ", xpub.to_string(true));
        assert_eq!(xpub.child_number, 1);
        assert_eq!(xpub.depth, 1);

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/2048".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub69J3tUsuDC9RhWVRSaXBrtZs3xqk9x5dtPASJhsoXh2MuSVkpSQUnkTD7jkPRT9khxztEgRqwNraViVNVe8TKYEdJGDMgMyWK997aTEDHzS", xpub.to_string(true));
        assert_eq!(xpub.child_number, 2048);
        assert_eq!(xpub.depth, 1);
    }

    #[test]
    fn test_derive_level_3() {
        let (root_public_key, root_chain_code) = setup();

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/0/1/2".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub6BtgqUiXne324rjh8mh8XfqkDs43PQZpdDr7uMTdnRWjDp6N6rKgUhfa5rFkqGc8AnJaCYoRw5APNkP6MprK6utzetNntGEC1rjPau45fbD", xpub.to_string(true));
        assert_eq!(xpub.child_number, 2);
        assert_eq!(xpub.depth, 3);

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/5/1/5".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub6DDCuvTyeLXwDfsqBGAYez2PBktdAgohyQLLtn6fvn15msBoumm4sLprHPD9BRYZJMhrLGzv5hvzMvjPEh4b1JBc9NAddyAy5Ecsodxe69u", xpub.to_string(true));
        assert_eq!(xpub.child_number, 5);
        assert_eq!(xpub.depth, 3);

        let xpub = derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/234235/12345/123413".parse().unwrap(),
        )
        .unwrap();

        assert_eq!("xpub6DCqoxe9CW573Z4uu975uR6V91C1PVovYT4b816fQ4TUGPyzdKYSKgCvSN4z4hAKzEo7FCaY9pWgXuLgvn27pzetZFwHMeAeeXFYkjPD2z4", xpub.to_string(true));
        assert_eq!(xpub.child_number, 123413);
        assert_eq!(xpub.depth, 3);
    }

    #[test]
    #[should_panic(expected = "HardenedChildNotSupported")]
    fn test_fail_hardended() {
        let (root_public_key, root_chain_code) = setup();

        derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/0'".parse().unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "HardenedChildNotSupported")]
    fn test_fail_hardened_index() {
        let (root_public_key, root_chain_code) = setup();

        derive_xpub(
            Prefix::XPub,
            &root_public_key,
            root_chain_code,
            "m/0/1/2/2147483647'".parse().unwrap(),
        )
        .unwrap();
    }
}
