// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! ML-KEM key encapsulation with generic authenticated encryption.

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    consts::{U12, U32},
    generic_array::typenum::Unsigned,
};
use ml_kem::{
    Ciphertext, Encoded, EncodedSizeUser, KemCore, SharedKey,
    kem::{Decapsulate, Encapsulate},
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    EncryptionError, EncryptionSession, EncryptionSessionBuilder,
    MessageEncryptionKey, PublicKeyError,
};

pub use ml_kem::{MlKem512, MlKem768, MlKem1024};

/// Symmetric message cipher used with ML-KEM shared keys.
pub trait Cipher {
    type State: Sized + Default;

    fn encryption_overhead() -> usize;

    fn encryption_key(state: &mut Self::State, shared_key: &[u8]) -> Self;

    fn decryption_key(shared_key: &[u8]) -> Self;

    fn encrypt(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError>;

    fn decrypt_message<'m>(
        &self,
        associated_data: &[u8],
        buffer: &'m mut [u8],
    ) -> Result<&'m mut [u8], EncryptionError>;
}

/// Outbound key material for one receiver.
struct Receiver<K: KemCore> {
    ciphertext: Option<Ciphertext<K>>,
    shared_key: Arc<Zeroizing<SharedKey<K>>>,
}

/// Configures an ML-KEM-backed encryption session.
pub struct Builder<K: KemCore, C: Cipher> {
    dk: K::DecapsulationKey,
    pk: Encoded<K::EncapsulationKey>,
    receivers: Vec<(usize, Receiver<K>)>,
    marker: PhantomData<C>,
}

/// Active ML-KEM-backed encryption session.
pub struct Session<K: KemCore, C: Cipher> {
    dk: K::DecapsulationKey,
    receivers: Vec<(usize, Receiver<K>)>,
    shared: Vec<(usize, Zeroizing<SharedKey<K>>)>,
    state: C::State,
    marker: PhantomData<C>,
}

/// Cipher and optional encapsulation reserved for one outbound message.
pub struct EncryptionKey<K: KemCore, C: Cipher> {
    encapsulation: Option<Ciphertext<K>>,
    cipher: C,
}

impl<K: KemCore, C: Cipher> Builder<K, C> {
    /// Generates a new builder with the supplied random number generator.
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (dk, ek) = K::generate(rng);

        Self {
            dk,
            pk: ek.as_bytes(),
            receivers: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<K: KemCore, C: Cipher> MessageEncryptionKey for EncryptionKey<K, C> {
    fn encryption_overhead(&self) -> usize {
        C::encryption_overhead()
    }

    fn encapsulation(&self) -> Option<&[u8]> {
        self.encapsulation.as_ref().map(AsRef::as_ref)
    }

    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        self.cipher.encrypt(associated_data, buffer)
    }
}

impl<K, C> EncryptionSessionBuilder for Builder<K, C>
where
    K: KemCore,
    C: Cipher,
{
    type Session = Session<K, C>;

    fn public_key(&self) -> &[u8] {
        &self.pk
    }

    fn receiver_public_key(
        &mut self,
        rng: &mut impl CryptoRngCore,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError> {
        let pk: &Encoded<K::EncapsulationKey> =
            public_key.try_into().map_err(|_| PublicKeyError)?;

        let (ciphertext, shared_key) = K::EncapsulationKey::from_bytes(pk)
            .encapsulate(rng)
            .map_err(|_| PublicKeyError)?;

        self.receivers.push((
            receiver_index,
            Receiver {
                ciphertext: Some(ciphertext),
                shared_key: Arc::new(Zeroizing::new(shared_key)),
            },
        ));

        Ok(())
    }

    fn build(self) -> Self::Session {
        Session {
            dk: self.dk,
            receivers: self.receivers,
            shared: Vec::new(),
            marker: PhantomData,
            state: C::State::default(),
        }
    }
}

impl<K, C> EncryptionSession for Session<K, C>
where
    K: KemCore,
    C: Cipher,
{
    type EncryptionKey = EncryptionKey<K, C>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::EncryptionKey, EncryptionError> {
        let receiver: &mut Receiver<K> = self
            .receivers
            .iter_mut()
            .find(|(index, _)| *index == receiver)
            .map(|(_, receiver)| receiver)
            .ok_or(EncryptionError)?;

        let cipher = C::encryption_key(
            &mut self.state,
            receiver.shared_key.as_ref().as_slice(),
        );
        let encapsulation = receiver.ciphertext.take();

        Ok(EncryptionKey {
            encapsulation,
            cipher,
        })
    }

    fn expects_encapsulation(&self, sender: usize) -> Option<usize> {
        self.shared
            .iter()
            .all(|(index, _)| *index != sender)
            .then_some(K::CiphertextSize::USIZE)
    }

    fn decrypt_message<'m>(
        &mut self,
        encapsulation: &[u8],
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        if let Some((_, shared_key)) =
            self.shared.iter().find(|(index, _)| *index == sender)
        {
            if !encapsulation.is_empty() {
                return Err(EncryptionError);
            }

            return C::decryption_key(shared_key.as_slice())
                .decrypt_message(associated_data, buffer);
        }

        let encapsulation: &Ciphertext<K> =
            encapsulation.try_into().map_err(|_| EncryptionError)?;
        let shared_key = Zeroizing::new(
            self.dk
                .decapsulate(encapsulation)
                .map_err(|_| EncryptionError)?,
        );
        let plaintext = C::decryption_key(shared_key.as_slice())
            .decrypt_message(associated_data, buffer)?;

        self.shared.push((sender, shared_key));

        Ok(plaintext)
    }
}

/// AEAD adapter for the ML-KEM cipher interface.
pub struct AeadCipher<C>(C, u64)
where
    C: AeadInPlace + AeadCore<NonceSize = U12> + KeyInit<KeySize = U32>;

impl<C> Cipher for AeadCipher<C>
where
    C: AeadInPlace + AeadCore<NonceSize = U12> + KeyInit<KeySize = U32>,
{
    type State = u64;

    fn encryption_overhead() -> usize {
        C::TagSize::USIZE + C::NonceSize::USIZE
    }

    fn decrypt_message<'m>(
        &self,
        associated_data: &[u8],
        buffer: &'m mut [u8],
    ) -> Result<&'m mut [u8], EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(C::TagSize::USIZE + C::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        self.0
            .decrypt_in_place_detached(
                Nonce::<C>::from_slice(&tail[C::TagSize::USIZE..]),
                associated_data,
                buffer,
                Tag::<C>::from_slice(&tail[..C::TagSize::USIZE]),
            )
            .map_err(|_| EncryptionError)?;

        Ok(buffer)
    }

    fn encrypt(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(C::TagSize::USIZE + C::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        let mut nonce = Nonce::<C>::default();
        nonce[0..8].copy_from_slice(&self.1.to_le_bytes());

        let tag = self
            .0
            .encrypt_in_place_detached(&nonce, associated_data, buffer)
            .map_err(|_| EncryptionError)?;

        tail[..C::TagSize::USIZE].copy_from_slice(&tag);
        tail[C::TagSize::USIZE..].copy_from_slice(&nonce);

        Ok(())
    }

    fn encryption_key(state: &mut Self::State, shared_key: &[u8]) -> Self {
        *state += 1;

        let key = Zeroizing::new(Sha256::digest(shared_key));

        Self(C::new(Key::<C>::from_slice(key.as_slice())), *state)
    }

    fn decryption_key(shared_key: &[u8]) -> Self {
        let key = Zeroizing::new(Sha256::digest(shared_key));

        Self(C::new(Key::<C>::from_slice(key.as_slice())), 0)
    }
}

/// ML-KEM with AES-256-GCM.
#[cfg(feature = "aes-gcm")]
pub type AesGcm = AeadCipher<aes_gcm::Aes256Gcm>;

/// ML-KEM with ChaCha20-Poly1305.
#[cfg(feature = "chacha20poly1305")]
pub type Chacha20 = AeadCipher<chacha20poly1305::ChaCha20Poly1305>;

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{DataDecryption, DataEncryption};

    use super::*;

    type TestBuilder = Builder<MlKem768, AeadCipher<aes_gcm::Aes256Gcm>>;

    type Plaintext = [u8; 32];

    fn builders() -> (TestBuilder, TestBuilder) {
        let mut rng = rand::thread_rng();
        let mut p1 = TestBuilder::new(&mut rng);
        let mut p2 = TestBuilder::new(&mut rng);

        p1.receiver_public_key(&mut rng, 2, p2.public_key())
            .unwrap();
        p2.receiver_public_key(&mut rng, 1, p1.public_key())
            .unwrap();

        (p1, p2)
    }

    fn send(
        sender: &mut Session<MlKem768, AeadCipher<aes_gcm::Aes256Gcm>>,
        receiver: usize,
        aad: &[u8],
        plaintext: &Plaintext,
    ) -> (bool, Vec<u8>) {
        let key = sender.encryption_key(receiver).unwrap();
        let has_encapsulation = key.encapsulation().is_some();
        let mut message = vec![];

        key.encrypt_data(aad, plaintext, &mut message).unwrap();

        (has_encapsulation, message)
    }

    #[test]
    fn encrypt_data() {
        let (p1, p2) = builders();
        let mut p1 = p1.build();
        let mut p2 = p2.build();
        let plaintext: Plaintext = [123; 32];
        let aad = &[1, 2, 3];

        let (has_encapsulation, mut message) =
            send(&mut p1, 2, aad, &plaintext);

        assert!(has_encapsulation);
        assert!(p2.expects_encapsulation(1).is_some());

        let (decrypted_aad, decrypted): (_, &Plaintext) =
            p2.decrypt_data(1, aad.len(), &mut message).unwrap();

        assert_eq!(p2.expects_encapsulation(1), None);
        assert_eq!(decrypted, &plaintext);
        assert_eq!(decrypted_aad, aad);
    }

    #[test]
    fn encapsulation_is_omitted_after_a_reply() {
        let (p1, p2) = builders();
        let mut p1 = p1.build();
        let mut p2 = p2.build();
        let plaintext: Plaintext = [123; 32];
        let aad = &[1, 2, 3];

        // The first message in each direction needs that direction's
        // independent ML-KEM encapsulation.
        let (has_encapsulation, mut message) =
            send(&mut p1, 2, aad, &plaintext);
        assert!(has_encapsulation);
        p2.decrypt_data::<Plaintext>(1, aad.len(), &mut message)
            .unwrap();

        let (has_encapsulation, mut reply) =
            send(&mut p2, 1, aad, &plaintext);
        assert!(has_encapsulation);
        p1.decrypt_data::<Plaintext>(2, aad.len(), &mut reply)
            .unwrap();

        // Successful replies acknowledge the encapsulations, so subsequent
        // messages omit them on both sides.
        let (has_encapsulation, mut message) =
            send(&mut p1, 2, aad, &plaintext);
        assert!(!has_encapsulation);
        assert_eq!(p2.expects_encapsulation(1), None);
        p2.decrypt_data::<Plaintext>(1, aad.len(), &mut message)
            .unwrap();

        let (has_encapsulation, mut reply) =
            send(&mut p2, 1, aad, &plaintext);
        assert!(!has_encapsulation);
        assert_eq!(p1.expects_encapsulation(2), None);
        p1.decrypt_data::<Plaintext>(2, aad.len(), &mut reply)
            .unwrap();
    }
}
