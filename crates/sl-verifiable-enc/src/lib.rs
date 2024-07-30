#[doc = include_str!("../README.md")]
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use num_bigint_dig::ModInverse;
use rand::{Rng, SeedableRng};
use rand_chacha::{rand_core::CryptoRngCore, ChaCha20Rng};
use rsa::{
    traits::PublicKeyParts, BigUint, Pkcs1v15Encrypt, RsaPrivateKey,
    RsaPublicKey,
};
use sha2::{Digest, Sha256};
use std::ops::Index;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;

pub const SECURITY_PARAM: usize = 120;

// Intentionally not giving too much information about the error
#[derive(Debug, Error)]
pub enum RsaError {
    #[error("Error during encryption")]
    EncError,
    #[error("Error during decryption")]
    DecError,
    #[error("Invalid label inverse")]
    InvalidLabel,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid SIZE parameter, must be equal to the size of the scalar in bytes")]
    InvalidSizeParam,
    #[error("(de)Serialization error")]
    SerdeError(String),
}

pub struct ProofData<G: Group + GroupEncoding> {
    g_r: G::Repr,
    enc_x_r: Vec<u8>,
    enc_r: Vec<u8>,
}

pub struct VerifiableRsaEncryption<G, const SIZE: usize>
where
    G: Group + GroupEncoding + ConstantTimeEq,
    G::Scalar: ConditionallySelectable,
{
    pub seed: [u8; 32],
    pub proofs: Vec<ProofData<G>>,
    pub open_scalars: Vec<G::Scalar>,
    security_param: usize,
}

impl<G, const SIZE: usize> VerifiableRsaEncryption<G, SIZE>
where
    G: Group + GroupEncoding + ConstantTimeEq,
{
    pub fn encrypt_with_proof<R: CryptoRngCore>(
        x: &G::Scalar,
        rsa_pubkey: &RsaPublicKey,
        label: &[u8],
        security_param: Option<usize>,
        rng: &mut R,
    ) -> Result<Self, RsaError>
    where
        <G::Scalar as PrimeField>::Repr: From<[u8; SIZE]>,
    {
        let seed = rng.gen::<[u8; 32]>();
        let security_param = security_param.unwrap_or(SECURITY_PARAM);
        let mut proofs = Vec::with_capacity(SECURITY_PARAM);
        let q_point = G::generator() * x;
        let mut r_list = Vec::with_capacity(SECURITY_PARAM);
        let mut x_plus_r_list = Vec::with_capacity(SECURITY_PARAM);

        for _ in 0..security_param {
            let r = G::Scalar::random(&mut *rng);
            let g_r = G::generator() * r;
            let x_plus_r = *x + r;
            let enc_r =
                rsa_encrypt_with_label(r.to_repr(), label, rsa_pubkey, seed)?;
            let enc_x_plus_r = rsa_encrypt_with_label(
                x_plus_r.to_repr(),
                label,
                rsa_pubkey,
                seed,
            )?;

            r_list.push(r);
            x_plus_r_list.push(x_plus_r);

            proofs.push(ProofData {
                g_r: g_r.to_bytes(),
                enc_x_r: enc_x_plus_r,
                enc_r,
            });
        }
        let challenge = Self::challenge(&q_point, label, &proofs);
        let mut open_scalars = Vec::with_capacity(SECURITY_PARAM);
        for i in 0..security_param {
            let choice_bit = challenge.extract_bit(i);
            let selected = G::Scalar::conditional_select(
                &r_list[i],
                &x_plus_r_list[i],
                choice_bit,
            );
            open_scalars.push(selected);
        }

        Ok(Self {
            open_scalars,
            proofs,
            seed,
            security_param,
        })
    }

    pub fn verify(
        &self,
        q_point: &G,
        rsa_pubkey: &RsaPublicKey,
        label: &[u8],
    ) -> Result<(), RsaError> {
        let challenge = Self::challenge(q_point, label, &self.proofs);
        for i in 0..self.security_param {
            let proof = &self.proofs[i];
            let open_scalar = &self.open_scalars[i];
            let scalar_expo = G::generator() * open_scalar;
            let choice_bit = challenge.extract_bit(i);
            let enc_open_scalar = rsa_encrypt_with_label(
                open_scalar.to_repr(),
                label,
                rsa_pubkey,
                self.seed,
            )?;

            let g_r_option = G::from_bytes(&proof.g_r);
            let g_r = if g_r_option.is_some().unwrap_u8() == 1 {
                g_r_option.unwrap()
            } else {
                return Err(RsaError::VerificationFailed);
            };

            // If choice bit is 0
            let cond_a = {
                let cond1 = g_r.ct_eq(&scalar_expo);
                let cond2 = proof.enc_r.ct_eq(&enc_open_scalar);
                cond1 & cond2
            };
            // If choice bit is 1
            let cond_b = {
                let calc_scalar_expo = *q_point + g_r;
                let cond1 = calc_scalar_expo.ct_eq(&scalar_expo);
                let cond2 = proof.enc_x_r.ct_eq(&enc_open_scalar);
                cond1 & cond2
            };

            let verified =
                Choice::conditional_select(&cond_a, &cond_b, choice_bit)
                    .unwrap_u8();
            if verified != 1 {
                return Err(RsaError::VerificationFailed);
            }
        }
        Ok(())
    }

    pub fn decrypt(
        &self,
        q_point: &G,
        rsa_privkey: &RsaPrivateKey,
        label: &[u8],
    ) -> Result<G::Scalar, RsaError>
    where
        <G::Scalar as PrimeField>::Repr: From<[u8; SIZE]>,
    {
        if self.proofs.len() != self.security_param {
            return Err(RsaError::VerificationFailed);
        }

        for proof in &self.proofs {
            let enc_r = &proof.enc_r;
            let enc_x_r = &proof.enc_x_r;

            let r = rsa_decrypt_with_label(enc_r, label, rsa_privkey)?;
            // If r is not 32 bytes, continue. We expect at least one of the proofs to be valid, assuming the proofs are verified.
            if r.len() != SIZE {
                continue;
            }

            let r: [u8; SIZE] = r.try_into().unwrap();

            // Here we assume that the scalar is 32 bytes and reduced modulo the field order. If not we consider the enc invalide and continue.
            // Some not-so-readable code to have a generic way to convert a byte array to a scalar.

            // If r is not a valid scalar, continue. We expect at least one of the proofs to be valid, assuming the proofs are verified.
            let r_opt = G::Scalar::from_repr(
                <G::Scalar as PrimeField>::Repr::from(r),
            )
            .into();
            let r: G::Scalar = if let Some(r) = r_opt {
                r
            } else {
                continue;
            };

            let x_plus_r =
                rsa_decrypt_with_label(enc_x_r, label, rsa_privkey)?;
            // If x + r is not a valid scalar, continue. We expect at least one of the proofs to be valid, assuming the proofs are verified.
            if x_plus_r.len() != SIZE {
                continue;
            }

            let x_plus_r: [u8; SIZE] = x_plus_r.try_into().unwrap();

            // If x + r is not a valid scalar, continue. We expect at least one of the proofs to be valid, assuming the proofs are verified.
            let x_plus_r_opt = G::Scalar::from_repr(
                <G::Scalar as PrimeField>::Repr::from(x_plus_r),
            )
            .into();
            let x_plus_r: G::Scalar = if let Some(x_plus_r) = x_plus_r_opt {
                x_plus_r
            } else {
                continue;
            };

            let x = x_plus_r - r;
            let calc_public_point = G::generator() * x;
            if calc_public_point == *q_point {
                return Ok(x);
            }
        }

        Err(RsaError::DecError)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        // Adding the sizes
        // Security parameter, g_r size, enc_x_r size (will be same as enc_r size) and scalar size
        bytes.extend_from_slice(&(SECURITY_PARAM as u16).to_be_bytes());
        bytes.extend_from_slice(
            &(self.proofs[0].g_r.as_ref().len() as u16).to_be_bytes(),
        );
        bytes.extend_from_slice(
            &(self.proofs[0].enc_x_r.len() as u16).to_be_bytes(),
        );
        bytes.extend_from_slice(&(SIZE as u16).to_be_bytes());

        for proof in &self.proofs {
            bytes.extend_from_slice(proof.g_r.as_ref());
            bytes.extend_from_slice(proof.enc_x_r.as_ref());
            bytes.extend_from_slice(proof.enc_r.as_ref());
        }
        for scalar in &self.open_scalars {
            bytes.extend_from_slice(scalar.to_repr().as_ref());
        }

        bytes
    }

    pub fn from_bytes<const G_SIZE: usize>(
        data: &[u8],
    ) -> Result<Self, RsaError>
    where
        G::Repr: From<[u8; G_SIZE]>,
        <G::Scalar as PrimeField>::Repr: From<[u8; SIZE]>,
    {
        let res = || {
            if data.len() < 32 + 8 {
                // 32 (seed) + 8 (4 * u16 sizes)
                return Err("Input data too short");
            }

            let mut offset = 0;

            // Read seed
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            // Read sizes
            let security_param =
                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let g_r_size =
                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let enc_size =
                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let scalar_size =
                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if scalar_size != SIZE {
                return Err("Inconsistent scalar size");
            }

            // Calculate number of proofs and open scalars
            let proof_size = g_r_size + 2 * enc_size;
            let remaining_data = data.len() - offset;
            let num_proofs = remaining_data / (proof_size + scalar_size);

            if security_param < 120 {
                return Err("Security param must at least be 120");
            }

            if num_proofs != security_param {
                return Err("Inconsistent number of proofs, must be equal to the security parameter");
            }

            if remaining_data % (proof_size + scalar_size) != 0 {
                return Err("Inconsistent data length");
            }

            // Read proofs
            let mut proofs = Vec::with_capacity(num_proofs);
            for _ in 0..num_proofs {
                if offset + proof_size > data.len() {
                    return Err(
                        "Unexpected end of data while reading proofs",
                    );
                }

                let g_r = G::Repr::from(
                    data[offset..offset + g_r_size]
                        .try_into()
                        .map_err(|_| "Invalid g_r length")?,
                );
                offset += g_r_size;

                let enc_x_r = data[offset..offset + enc_size].to_vec();
                offset += enc_size;

                let enc_r = data[offset..offset + enc_size].to_vec();
                offset += enc_size;

                proofs.push(ProofData {
                    g_r,
                    enc_x_r,
                    enc_r,
                });
            }

            // Read open scalars
            let mut open_scalars = Vec::with_capacity(num_proofs);
            for _ in 0..num_proofs {
                if offset + scalar_size > data.len() {
                    return Err(
                        "Unexpected end of data while reading scalars",
                    );
                }

                let scalar = G::Scalar::from_repr(
                    <G::Scalar as PrimeField>::Repr::from(
                        data[offset..offset + scalar_size]
                            .try_into()
                            .map_err(|_| "Invalid scalar length")?,
                    ),
                );

                let scalar = Option::from(scalar).ok_or("Invalid scalar")?;
                offset += scalar_size;
                open_scalars.push(scalar);
            }

            Ok(Self {
                seed,
                proofs,
                open_scalars,
                security_param,
            })
        };
        res().map_err(|e| RsaError::SerdeError(e.to_string()))
    }

    fn challenge(
        q_point: &G,
        label: &[u8],
        proofs: &[ProofData<G>],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Verified-RSA-encryption");
        hasher.update(q_point.to_bytes());
        for proof in proofs {
            hasher.update(proof.g_r);
            hasher.update(&proof.enc_x_r);
            hasher.update(&proof.enc_r);
        }
        hasher.update(label);
        hasher.finalize().into()
    }
}

fn rsa_encrypt_with_label(
    m: impl AsRef<[u8]>,
    label: &[u8],
    rsa_pubkey: &RsaPublicKey,
    seed: [u8; 32],
) -> Result<Vec<u8>, RsaError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let m_int = BigUint::from_bytes_be(m.as_ref());
    let label_int = label_int_from_bytes(label);
    let plaintext = (m_int * label_int) % rsa_pubkey.n();
    rsa_pubkey
        .encrypt(&mut rng, Pkcs1v15Encrypt, &plaintext.to_bytes_be())
        .map_err(|_| RsaError::EncError)
}

fn rsa_decrypt_with_label(
    ciphertext: &[u8],
    label: &[u8],
    rsa_privkey: &RsaPrivateKey,
) -> Result<Vec<u8>, RsaError> {
    let plaintext = rsa_privkey
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|_| RsaError::DecError)?;

    let n = rsa_privkey.n();
    let label_inv = label_int_from_bytes(label)
        .mod_inverse(n)
        .and_then(|num| num.to_biguint())
        .ok_or(RsaError::InvalidLabel)?;

    let plaintext_int = BigUint::from_bytes_be(&plaintext);
    let message = (plaintext_int * label_inv) % n;
    Ok(message.to_bytes_be())
}

fn label_int_from_bytes(label: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"SL-label-for-RSA");
    hasher.update(label);
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest[..])
}

/// Simple trait to extract a bit from a byte array.
pub trait ExtractBit: Index<usize, Output = u8> {
    /// Extract a bit at given index (in little endian order) from a byte array.
    fn extract_bit(&self, idx: usize) -> Choice {
        let byte_idx = idx >> 3;
        let bit_idx = idx & 0x7;
        let byte = self[byte_idx];
        let mask = 1 << bit_idx;
        Choice::from(((byte & mask) != 0) as u8)
    }
}
impl<const N: usize> ExtractBit for [u8; N] {}

#[cfg(test)]
mod tests {
    use curve25519_dalek::EdwardsPoint;
    use group::Group;
    use k256::{ProjectivePoint, Scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rsa::RsaPrivateKey;
    use subtle::Choice;

    use crate::*;

    #[test]
    fn test_verifiable_rsa_ecdsa() -> Result<(), RsaError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let private_key = Scalar::generate_vartime(&mut rng);

        let public_key = ProjectivePoint::GENERATOR * private_key;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        let rsa_public_key = rsa_private_key.to_public_key();
        let label = b"test-label";
        let verifiable_rsa = VerifiableRsaEncryption::encrypt_with_proof(
            &private_key,
            &rsa_public_key,
            label,
            None,
            &mut rng,
        )?;

        verifiable_rsa.verify(&public_key, &rsa_public_key, label)?;

        let decrypted_x =
            verifiable_rsa.decrypt(&public_key, &rsa_private_key, label)?;

        assert_eq!(private_key, decrypted_x);

        Ok(())
    }

    #[test]
    fn test_verifiable_rsa_25519() -> Result<(), RsaError> {
        use curve25519_dalek::Scalar;
        let mut rng = ChaCha20Rng::from_entropy();
        let private_key = Scalar::random(&mut rng);
        let public_key = EdwardsPoint::generator() * private_key;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        let rsa_public_key = rsa_private_key.to_public_key();
        let label = b"test-label";
        let verifiable_rsa = VerifiableRsaEncryption::encrypt_with_proof(
            &private_key,
            &rsa_public_key,
            label,
            None,
            &mut rng,
        )?;
        let bytes = verifiable_rsa.to_bytes();

        let deserialized: VerifiableRsaEncryption<EdwardsPoint, 32> =
            VerifiableRsaEncryption::from_bytes(&bytes).unwrap();

        deserialized.verify(&public_key, &rsa_public_key, label)?;

        verifiable_rsa.verify(&public_key, &rsa_public_key, label)?;
        let decrypted_x =
            verifiable_rsa.decrypt(&public_key, &rsa_private_key, label)?;
        assert_eq!(private_key, decrypted_x);

        Ok(())
    }

    #[test]
    fn test_serde_k256() -> Result<(), RsaError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let private_key = Scalar::generate_vartime(&mut rng);

        let public_key = ProjectivePoint::GENERATOR * private_key;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        let rsa_public_key = rsa_private_key.to_public_key();
        let label = b"test-label";
        let verifiable_rsa: VerifiableRsaEncryption<ProjectivePoint, 32> =
            VerifiableRsaEncryption::encrypt_with_proof(
                &private_key,
                &rsa_public_key,
                label,
                None,
                &mut rng,
            )?;

        let bytes = verifiable_rsa.to_bytes();
        let deserialized =
            VerifiableRsaEncryption::from_bytes(&bytes).unwrap();
        deserialized.verify(&public_key, &rsa_public_key, label)?;

        let decrypted_x =
            deserialized.decrypt(&public_key, &rsa_private_key, label)?;
        assert_eq!(private_key, decrypted_x);

        Ok(())
    }

    #[test]
    fn test_serde_25519() -> Result<(), RsaError> {
        use curve25519_dalek::Scalar;
        let mut rng = ChaCha20Rng::from_entropy();
        let private_key = Scalar::random(&mut rng);
        let public_key = EdwardsPoint::generator() * private_key;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        let rsa_public_key = rsa_private_key.to_public_key();
        let label = b"test-label";
        let verifiable_rsa: VerifiableRsaEncryption<EdwardsPoint, 32> =
            VerifiableRsaEncryption::encrypt_with_proof(
                &private_key,
                &rsa_public_key,
                label,
                None,
                &mut rng,
            )?;

        let bytes = verifiable_rsa.to_bytes();
        let deserialized =
            VerifiableRsaEncryption::from_bytes(&bytes).unwrap();
        deserialized.verify(&public_key, &rsa_public_key, label)?;

        let decrypted_x =
            deserialized.decrypt(&public_key, &rsa_private_key, label)?;
        assert_eq!(private_key, decrypted_x);

        Ok(())
    }

    #[test]
    fn test_serde_rsa_4096() -> Result<(), RsaError> {
        // Using key-size of 4096 bits to test if the de/serialization works for larger keys
        use curve25519_dalek::Scalar;
        let mut rng = ChaCha20Rng::from_entropy();
        let private_key = Scalar::random(&mut rng);
        let public_key = EdwardsPoint::generator() * private_key;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 4096)
            .expect("Failed to generate RSA private key");
        let rsa_public_key = rsa_private_key.to_public_key();
        let label = b"test-label";
        let verifiable_rsa: VerifiableRsaEncryption<EdwardsPoint, 32> =
            VerifiableRsaEncryption::encrypt_with_proof(
                &private_key,
                &rsa_public_key,
                label,
                None,
                &mut rng,
            )?;

        let bytes = verifiable_rsa.to_bytes();
        let deserialized =
            VerifiableRsaEncryption::from_bytes(&bytes).unwrap();
        deserialized.verify(&public_key, &rsa_public_key, label)?;

        let decrypted_x =
            deserialized.decrypt(&public_key, &rsa_private_key, label)?;
        assert_eq!(private_key, decrypted_x);

        Ok(())
    }

    #[test]
    fn test_extract_bit() {
        let array: [u8; 1] = [0b0100_1110];

        // Check each bit
        assert!(
            array.extract_bit(0).ct_eq(&Choice::from(0)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(1).ct_eq(&Choice::from(1)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(2).ct_eq(&Choice::from(1)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(3).ct_eq(&Choice::from(1)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(4).ct_eq(&Choice::from(0)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(5).ct_eq(&Choice::from(0)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(6).ct_eq(&Choice::from(1)).unwrap_u8() == 1
        );
        assert!(
            array.extract_bit(7).ct_eq(&Choice::from(0)).unwrap_u8() == 1
        );
    }
}
