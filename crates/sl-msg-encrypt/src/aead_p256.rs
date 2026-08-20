// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! P-256 key agreement with authenticated encryption.

use alloc::vec::Vec;
use core::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    consts::{U10, U12, U32},
    generic_array::{GenericArray, typenum::Unsigned},
};
use aes_gcm::Aes256Gcm;
use chacha20::hchacha;
use chacha20poly1305::ChaCha20Poly1305;
use p256::{
    EncodedPoint, PublicKey, SecretKey, ecdh,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    EncryptionError, EncryptionSession, EncryptionSessionBuilder,
    MessageEncryptionKey, PublicKeyError,
};

type SharedKey = Zeroizing<GenericArray<u8, U32>>;

/// Counter used to reserve a unique nonce for each message.
struct NonceCounter(u32);

impl NonceCounter {
    fn new() -> Self {
        Self(0)
    }

    fn next_nonce<S: AeadCore<NonceSize = U12>>(&mut self) -> Nonce<S> {
        // Protocol runs use only a small number of nonces per key. Overflow
        // therefore indicates misuse, and panicking is safer than nonce reuse.
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

/// Key and nonce reserved for one outbound message.
pub struct P256AeadMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

/// Configures a P-256-backed encryption session.
pub struct AeadP256Builder<S> {
    secret: SecretKey,
    own_public_enc: EncodedPoint,
    receivers: Vec<(usize, (SharedKey, PublicKey))>,
    marker: PhantomData<S>,
}

/// Active P-256-backed encryption session.
pub struct AeadP256<S> {
    public_key_enc: EncodedPoint,
    counter: NonceCounter,
    receivers: Vec<(usize, (SharedKey, PublicKey))>,
    marker: PhantomData<S>,
}

/// P-256 key agreement with ChaCha20-Poly1305.
pub type AeadP256ChaChaPoly1305 = AeadP256<ChaCha20Poly1305>;
/// P-256 key agreement with AES-256-GCM.
pub type AeadP256Aes256Gcm = AeadP256<Aes256Gcm>;

/// P-256 and ChaCha20-Poly1305 builder.
pub type AeadP256ChaChaPoly1305Builder = AeadP256Builder<ChaCha20Poly1305>;
/// P-256 and AES-256-GCM builder.
pub type AeadP256Aes256GcmBuilder = AeadP256Builder<Aes256Gcm>;

impl<S> AeadP256Builder<S> {
    /// Generates a new builder with the supplied random number generator.
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        Self::from_secret_key(SecretKey::random(rng))
    }

    /// Creates a builder from an existing P-256 secret key.
    ///
    /// # Security
    ///
    /// This resets the outbound nonce counter. Do not use the same secret key
    /// in more than one outbound session with the same receiver public key, as
    /// that would reuse AEAD key/nonce pairs. Prefer [`Self::new`] for outbound
    /// sessions. Reconstructing a key for decryption-only use does not create
    /// outbound nonce reuse.
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let own_public_enc = secret.public_key().to_encoded_point(false);

        Self {
            secret,
            own_public_enc,
            receivers: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<S> EncryptionSessionBuilder for AeadP256Builder<S>
where
    S: AeadInPlace
        + AeadCore<NonceSize = U12>
        + KeyInit<KeySize = U32>
        + Send,
{
    type Session = AeadP256<S>;

    fn public_key(&self) -> &[u8] {
        self.own_public_enc.as_bytes()
    }

    fn receiver_public_key(
        &mut self,
        _rng: &mut impl CryptoRngCore,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError> {
        let remote = PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| PublicKeyError)?;
        let shared = ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            remote.as_affine(),
        );

        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared.raw_secret_bytes()),
            &GenericArray::default(),
        ));

        self.receivers.push((receiver_index, (shared_key, remote)));

        Ok(())
    }

    fn build(self) -> Self::Session {
        AeadP256 {
            public_key_enc: self.own_public_enc,
            counter: NonceCounter::new(),
            receivers: self.receivers,
            marker: PhantomData,
        }
    }
}

impl<S> MessageEncryptionKey for P256AeadMessageKey<S>
where
    S: AeadInPlace
        + AeadCore<NonceSize = U12>
        + KeyInit<KeySize = U32>
        + Send,
{
    fn encryption_overhead(&self) -> usize {
        S::TagSize::USIZE + S::NonceSize::USIZE
    }

    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (buffer, overhead) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        let tag = self
            .cipher
            .encrypt_in_place_detached(&self.nonce, associated_data, buffer)
            .map_err(|_| EncryptionError)?;

        overhead[..S::TagSize::USIZE].copy_from_slice(&tag);
        overhead[S::TagSize::USIZE..].copy_from_slice(&self.nonce);

        Ok(())
    }
}

impl<S> EncryptionSession for AeadP256<S>
where
    S: AeadInPlace
        + AeadCore<NonceSize = U12>
        + KeyInit<KeySize = U32>
        + Send,
{
    type EncryptionKey = P256AeadMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::EncryptionKey, EncryptionError> {
        let (shared_key, public_key) = self
            .receivers
            .iter()
            .find(|(index, _)| *index == receiver)
            .map(|(_, keys)| keys)
            .ok_or(EncryptionError)?;

        let public_key = public_key.to_encoded_point(false);
        let key = Zeroizing::new(
            Sha256::new_with_prefix(public_key.as_bytes())
                .chain_update(shared_key)
                .finalize(),
        );
        let key = Key::<S>::from_slice(key.as_slice());

        Ok(P256AeadMessageKey {
            cipher: S::new(key),
            nonce: self.counter.next_nonce::<S>(),
        })
    }

    fn expects_encapsulation(&self, _sender: usize) -> Option<usize> {
        None
    }

    fn decrypt_message<'m>(
        &mut self,
        encapsulation: &[u8],
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        if !encapsulation.is_empty() {
            return Err(EncryptionError);
        }

        let (buffer, overhead) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        let (shared_key, _) = self
            .receivers
            .iter()
            .find(|(index, _)| *index == sender)
            .map(|(_, keys)| keys)
            .ok_or(EncryptionError)?;

        let key = Zeroizing::new(
            Sha256::new_with_prefix(self.public_key_enc.as_bytes())
                .chain_update(shared_key)
                .finalize(),
        );
        let key = Key::<S>::from_slice(key.as_slice());

        let nonce = Nonce::<S>::from_slice(&overhead[S::TagSize::USIZE..]);
        let tag = Tag::<S>::from_slice(&overhead[..S::TagSize::USIZE]);

        S::new(key)
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| EncryptionError)?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataDecryption, DataEncryption};

    #[test]
    fn encrypt_and_decrypt_data() {
        let mut rng = rand::thread_rng();
        let mut sender = AeadP256Aes256GcmBuilder::new(&mut rng);
        let mut receiver = AeadP256Aes256GcmBuilder::new(&mut rng);

        sender
            .receiver_public_key(&mut rng, 1, receiver.public_key())
            .unwrap();
        receiver
            .receiver_public_key(&mut rng, 0, sender.public_key())
            .unwrap();

        let mut sender = sender.build();
        let mut receiver = receiver.build();
        let aad = b"associated data";
        let value = [42_u8; 32];
        let mut message = Vec::new();

        sender
            .encryption_key(1)
            .unwrap()
            .encrypt_data(aad, &value, &mut message)
            .unwrap();

        let (decrypted_aad, decrypted): (&[u8], &[u8; 32]) =
            receiver.decrypt_data(0, aad.len(), &mut message).unwrap();

        assert_eq!(decrypted_aad, aad);
        assert_eq!(decrypted, &value);
    }
}
