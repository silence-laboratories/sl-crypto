// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! X25519 key agreement with generic authenticated encryption.

use alloc::vec::Vec;
use core::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, KeyInit,
    consts::{U10, U12, U32},
    generic_array::GenericArray,
};
use chacha20::hchacha;
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use super::aead_session::{
    AeadMessageKey as CommonAeadMessageKey, AeadSession, ReceiverKey,
};
use crate::{EncryptionSessionBuilder, PublicKeyError};

/// X25519-backed AEAD session.
pub type AeadX25519<S> = AeadSession<S>;

/// Key and nonce reserved for one outbound message.
pub type AeadX25519MessageKey<S> = CommonAeadMessageKey<S>;

/// Compatibility alias for [`AeadX25519MessageKey`].
#[deprecated(note = "use AeadX25519MessageKey instead")]
pub type AeadMessageKey<S> = AeadX25519MessageKey<S>;

/// Configures an X25519-backed encryption session.
pub struct AeadX25519Builder<S> {
    secret: ReusableSecret,
    public_key: PublicKey,
    receivers: Vec<ReceiverKey>,
    marker: PhantomData<S>,
}

/// Active X25519-backed encryption session.
///
/// X25519 key agreement with ChaCha20-Poly1305.
#[cfg(feature = "chacha20poly1305")]
pub type AeadX25519ChaChaPoly1305 =
    AeadX25519<chacha20poly1305::ChaCha20Poly1305>;

/// X25519 and ChaCha20-Poly1305 builder.
#[cfg(feature = "chacha20poly1305")]
pub type AeadX25519ChaChaPoly1305Builder =
    AeadX25519Builder<chacha20poly1305::ChaCha20Poly1305>;

impl<S> AeadX25519Builder<S> {
    /// Generates a new builder with the supplied random number generator.
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let secret = ReusableSecret::random_from_rng(rng);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            receivers: Vec::new(),
            marker: PhantomData,
        }
    }

    /// Creates a builder from an existing X25519 reusable secret.
    ///
    /// # Security
    ///
    /// This resets the outbound nonce counter. Do not use the same secret in
    /// more than one outbound session with the same receiver public key, as
    /// that would reuse AEAD key/nonce pairs. Prefer [`Self::new`] for outbound
    /// sessions. Reconstructing a secret for decryption-only use does not
    /// create outbound nonce reuse.
    pub fn from_secret(secret: ReusableSecret) -> Self {
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            receivers: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<S> EncryptionSessionBuilder for AeadX25519Builder<S>
where
    S: AeadInPlace
        + AeadCore<NonceSize = U12>
        + KeyInit<KeySize = U32>
        + Send,
{
    type Session = AeadX25519<S>;

    fn public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn receiver_public_key(
        &mut self,
        _rng: &mut impl CryptoRngCore,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError> {
        let public_key: [u8; 32] =
            public_key.try_into().map_err(|_| PublicKeyError)?;
        let public_key = PublicKey::from(public_key);

        let shared_secret = self.secret.diffie_hellman(&public_key);

        if !shared_secret.was_contributory() {
            return Err(PublicKeyError);
        }

        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));

        self.receivers.push((
            receiver_index,
            (shared_key, public_key.as_bytes().to_vec()),
        ));

        Ok(())
    }

    fn build(self) -> Self::Session {
        AeadSession::new(self.public_key.as_bytes().to_vec(), self.receivers)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::ChaCha20Poly1305;

    use super::*;
    use crate::{DataDecryption, DataEncryption, EncryptionSession};

    #[test]
    fn encrypt_and_decrypt_data() {
        let mut rng = rand::thread_rng();
        let mut sender = AeadX25519Builder::<ChaCha20Poly1305>::new(&mut rng);
        let mut receiver =
            AeadX25519Builder::<ChaCha20Poly1305>::new(&mut rng);

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
