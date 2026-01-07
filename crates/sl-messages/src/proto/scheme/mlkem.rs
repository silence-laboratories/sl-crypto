// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;
use std::sync::OnceLock;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    generic_array::typenum::Unsigned,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, array::Array};
use rand_core_09::{OsRng, TryCryptoRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, KeyExchange,
    MessageKey, PublicKeyError,
};

// Counter to create a unique nonce.
struct NonceCounter(u32);

impl NonceCounter {
    /// New counter initialized by 0.
    fn new() -> Self {
        Self(0)
    }

    /// Increment counter.
    fn next_nonce<S: AeadCore>(&mut self) -> Nonce<S> {
        // In our design, we use 3-5 nonces per unique symmetric key.
        // If the u32 counter overflows, then calling it is definitely
        // a misuse of the counter, and it's safer to crash than reuse
        // a nonce.
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

type SharedSecret = Zeroizing<Vec<u8>>; // 32 bytes for ML-KEM-768

/// Wrapper that computes bytes on-demand from the key to save space
/// Bytes are lazily computed and cached only when AsRef is called
pub struct MlKemEncapsulationKey {
    key: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
    bytes: OnceLock<Vec<u8>>, // Lazily computed bytes, only allocated if AsRef is called
}

impl Clone for MlKemEncapsulationKey {
    fn clone(&self) -> Self {
        // Clone the key, but create a new empty OnceLock (bytes will be recomputed if needed)
        Self {
            key: self.key.clone(),
            bytes: OnceLock::new(),
        }
    }
}

impl AsRef<[u8]> for MlKemEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        // Compute bytes on-demand and cache them
        self.bytes
            .get_or_init(|| self.key.as_bytes().as_slice().to_vec())
    }
}

impl<'a> TryFrom<&'a [u8]> for MlKemEncapsulationKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // ML-KEM-768 encapsulation key is 1184 bytes
        type Ek = <MlKem768 as KemCore>::EncapsulationKey;
        if bytes.len() != 1184 {
            return Err(PublicKeyError);
        }
        let array: Array<u8, _> =
            bytes.try_into().map_err(|_| PublicKeyError)?;
        let key = Ek::from_bytes(&array);
        Ok(MlKemEncapsulationKey {
            key,
            bytes: OnceLock::new(),
        })
    }
}

impl From<ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>>
    for MlKemEncapsulationKey
{
    fn from(
        ek: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
    ) -> Self {
        // Bytes will be computed lazily when AsRef is first called
        MlKemEncapsulationKey {
            key: ek,
            bytes: OnceLock::new(),
        }
    }
}

impl From<MlKemEncapsulationKey>
    for ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>
{
    fn from(wrapper: MlKemEncapsulationKey) -> Self {
        wrapper.key
    }
}

pub struct AeadMlKemBuilder<S, R = OsRng> {
    decapsulation_key:
        Option<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>,
    encapsulation_key_bytes: Vec<u8>, // Store bytes for public_key() method
    shared_secrets: Pairs<(SharedSecret, Vec<u8>, Vec<u8>), usize>,
    rng: R,
    marker: PhantomData<S>,
}

/// The implementation of EncryptionScheme that uses ML-KEM for key
/// exchange and any implementation of `AeadInPlace`.
pub struct AeadMlKem<S> {
    encapsulation_key_bytes: Vec<u8>, // Own public key bytes (for decryption key derivation)
    shared_secrets: Pairs<(SharedSecret, Vec<u8>), usize>, // (shared_secret, receiver_pk_bytes)
    counter: NonceCounter,
    marker: PhantomData<S>,
}

pub struct AeadMlKemMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

impl<S, R> AeadMlKemBuilder<S, R>
where
    R: TryCryptoRng,
{
    /// Generate a new [`AeadMlKem`] with the supplied RNG.
    /// generate requires CryptoRng (infallible)
    pub fn new(mut rng: R) -> Self
    where
        R: rand_core_09::CryptoRng,
    {
        let (dk, ek) = MlKem768::generate(&mut rng);
        let ek_bytes = ek.as_bytes().as_slice().to_vec();

        Self {
            decapsulation_key: Some(dk),
            encapsulation_key_bytes: ek_bytes,
            shared_secrets: Pairs::new(),
            rng,
            marker: PhantomData,
        }
    }

}

impl<S, R> KeyExchange for AeadMlKemBuilder<S, R>
where
    S: AeadInPlace + KeyInit + Send,
    R: TryCryptoRng,
{
    type PublicKey = MlKemEncapsulationKey;
    type SharedSecret = SharedSecret; // 32 bytes for ML-KEM-768
    type KeyMaterial = Vec<u8>; // Ciphertext (1088 bytes for ML-KEM-768)

    fn establish_shared_secret(
        &mut self,
        receiver_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Vec<u8>), PublicKeyError> {
        let ek = &receiver_pk.key;
        let (ct, k_send) =
            ek.encapsulate(&mut self.rng).map_err(|_| PublicKeyError)?;
        Ok((
            Zeroizing::new(k_send.as_slice().to_vec()),
            ct.as_slice().to_vec(),
        ))
    }

    fn receive_shared_secret(
        &mut self,
        _sender_pk: &Self::PublicKey, // Not used for decapsulation
        key_material: &Vec<u8>,       // Ciphertext
    ) -> Result<Self::SharedSecret, PublicKeyError> {
        // Decapsulate: receiver recovers shared secret using own secret key
        let dk = self.decapsulation_key.as_ref().ok_or(PublicKeyError)?;
        type Ct = ml_kem::Ciphertext<MlKem768>;
        if key_material.len() != 1088 {
            return Err(PublicKeyError);
        }
        let ct: Ct = key_material
            .as_slice()
            .try_into()
            .map_err(|_| PublicKeyError)?;
        let k_recv = dk.decapsulate(&ct).map_err(|_| PublicKeyError)?;
        // SharedKey is an Array type, convert to Vec<u8>
        Ok(Zeroizing::new(k_recv.as_slice().to_vec()))
    }
}

impl<S, R> EncryptionSchemeBuilder for AeadMlKemBuilder<S, R>
where
    S: AeadInPlace + KeyInit + Send,
    R: TryCryptoRng,
{
    type Scheme = AeadMlKem<S>;

    fn public_key(&self) -> &[u8] {
        &self.encapsulation_key_bytes
    }

    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        pk: &[u8],
    ) -> Result<(), PublicKeyError> {
        let receiver_pk = Self::PublicKey::try_from(pk)?;

        // This performs: (shared_secret, ciphertext) = encapsulate(receiver_pk)
        let (shared_secret, ciphertext) =
            self.establish_shared_secret(&receiver_pk)?;

        // The ciphertext will be sent to the receiver later via get_key_material_for_receiver()
        self.shared_secrets
            .push(receiver_index, (shared_secret, ciphertext, pk.to_vec()));
        Ok(())
    }

    // Override defaults for ML-KEM
    fn get_key_material_for_receiver(
        &self,
        receiver_index: usize,
    ) -> Option<&[u8]> {
        // Return the stored ciphertext
        self.shared_secrets
            .find_pair_or_err(receiver_index, ())
            .ok()
            .map(|(_, ct, _)| ct.as_slice())
    }

    fn receive_key_material(
        &mut self,
        sender_pk_bytes: &[u8],
        sender_index: usize,
        key_material: &[u8],
    ) -> Result<(), PublicKeyError> {
        let sender_pk = Self::PublicKey::try_from(sender_pk_bytes)?;

        // Decapsulate using KeyExchange trait method
        let shared_secret =
            self.receive_shared_secret(&sender_pk, &key_material.to_vec())?;

        self.shared_secrets.push(
            sender_index,
            (shared_secret, Vec::new(), sender_pk_bytes.to_vec()),
        );
        Ok(())
    }

    fn build(self) -> Self::Scheme {
        // Convert stored entries: (shared_secret, ciphertext, pk_bytes) -> (shared_secret, pk_bytes)
        let mut scheme_secrets = Pairs::new();
        for (idx, (shared_secret, _, pk_bytes)) in self.shared_secrets.iter()
        {
            scheme_secrets
                .push(*idx, (shared_secret.clone(), pk_bytes.clone()));
        }

        Self::Scheme {
            encapsulation_key_bytes: self.encapsulation_key_bytes,
            shared_secrets: scheme_secrets,
            counter: NonceCounter::new(),
            marker: PhantomData,
        }
    }
}

impl<S> MessageKey for AeadMlKemMessageKey<S>
where
    S: AeadInPlace + KeyInit,
{
    fn message_footer(&self) -> usize {
        S::TagSize::USIZE + S::NonceSize::USIZE
    }

    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        let tag = self
            .cipher
            .encrypt_in_place_detached(&self.nonce, associated_data, buffer)
            .map_err(|_| EncryptionError)?;

        tail[..S::TagSize::USIZE].copy_from_slice(&tag);
        tail[S::TagSize::USIZE..].copy_from_slice(&self.nonce);

        Ok(())
    }
}

impl<S> EncryptionScheme for AeadMlKem<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Key = AeadMlKemMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::Key, EncryptionError> {
        // Same as X25519: get (shared_secret, receiver_pk_bytes)
        let (shared_secret, receiver_pk_bytes) = self
            .shared_secrets
            .find_pair_or_err(receiver, EncryptionError)?;

        // Same key derivation as X25519: Sha256(receiver_pk || shared_secret)
        let key = Zeroizing::new(
            Sha256::new_with_prefix(receiver_pk_bytes.as_slice())
                .chain_update(shared_secret.as_slice())
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());
        let nonce = self.counter.next_nonce::<S>();
        let cipher = S::new(key);

        Ok(AeadMlKemMessageKey { cipher, nonce })
    }

    fn decrypt_message<'m>(
        &self,
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        // Same as X25519: get (shared_secret, _sender_pk_bytes) but use own public key
        let (shared_secret, _sender_pk_bytes) = self
            .shared_secrets
            .find_pair_or_err(sender, EncryptionError)?;

        // Same key derivation as X25519: Sha256(own_pk || shared_secret)
        let key = Zeroizing::new(
            Sha256::new_with_prefix(self.encapsulation_key_bytes.as_slice())
                .chain_update(shared_secret.as_slice())
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());
        let nonce = Nonce::<S>::from_slice(&tail[S::TagSize::USIZE..]);
        let tag = Tag::<S>::from_slice(&tail[..S::TagSize::USIZE]);

        S::new(key)
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| EncryptionError)?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::ChaCha20Poly1305;
    use rand_core_09::{CryptoRng, OsRng, RngCore, TryRngCore};

    struct InfallibleOsRng(OsRng);

    impl RngCore for InfallibleOsRng {
        fn next_u32(&mut self) -> u32 {
            self.0.try_next_u32().unwrap_or_else(|_| {
                panic!("OsRng failed in test - this should never happen")
            })
        }
        fn next_u64(&mut self) -> u64 {
            self.0.try_next_u64().unwrap_or_else(|_| {
                panic!("OsRng failed in test - this should never happen")
            })
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.try_fill_bytes(dest).unwrap_or_else(|_| {
                panic!("OsRng failed in test - this should never happen")
            })
        }
    }

    impl CryptoRng for InfallibleOsRng {}

    #[test]
    fn test_mlkem_key_exchange_and_encryption()
    -> Result<(), Box<dyn std::error::Error>> {
        // 1. Setup Sender and Receiver Builders
        let rng = InfallibleOsRng(OsRng);

        let mut sender_builder =
            AeadMlKemBuilder::<ChaCha20Poly1305, _>::new(rng);


        let mut receiver_builder =
            AeadMlKemBuilder::<ChaCha20Poly1305, _>::new(InfallibleOsRng(
                OsRng,
            ));

        // 2. Exchange Keys
        let receiver_pk_bytes = receiver_builder.public_key();

        // Sender adds receiver's public key -> generates ciphertext (encapsulated key)
        let receiver_index = 1;
        sender_builder
            .receiver_public_key(receiver_index, receiver_pk_bytes)
            .map_err(|e| {
                format!("sender failed to ingest receiver pk: {:?}", e)
            })?;

        let sender_pk_bytes = sender_builder.public_key();

        // Sender gets the ciphertext to send to receiver
        let key_material = sender_builder
            .get_key_material_for_receiver(receiver_index)
            .ok_or("sender should have ciphertext")?;

        // Receiver ingests sender's ciphertext
        let sender_index = 2;
        receiver_builder
            .receive_key_material(sender_pk_bytes, sender_index, key_material)
            .map_err(|e| {
                format!("receiver failed to ingest key material: {:?}", e)
            })?;

        // 3. Build Schemes
        let mut sender_scheme = sender_builder.build();
        let receiver_scheme = receiver_builder.build();

        // 4. Encrypt (Sender -> Receiver)
        let msg = b"Come on Quantum!!!";
        let aad = b"context";

        // Sender gets encryption key for receiver
        let mut encryption_buffer = vec![0u8; msg.len() + 16 + 12]; // msg + tag(16) + nonce(12)
        encryption_buffer[..msg.len()].copy_from_slice(msg);

        let sender_key =
            sender_scheme.encryption_key(receiver_index).map_err(|e| {
                format!("sender failed to get encryption key: {:?}", e)
            })?;

        // Encrypt in place
        sender_key
            .encrypt(aad, &mut encryption_buffer)
            .map_err(|e| format!("encryption failed: {:?}", e))?;

        assert_ne!(
            &encryption_buffer[..msg.len()],
            msg,
            "Ciphertext should differ from plaintext"
        );

        // 5. Decrypt (Receiver <- Sender)
        // Receiver decrypts
        let decrypted = receiver_scheme
            .decrypt_message(aad, &mut encryption_buffer, sender_index)
            .map_err(|e| format!("decryption failed: {:?}", e))?;

        assert_eq!(decrypted, msg, "Decrypted message should match original");

        Ok(())
    }
}
