// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! P-256 key agreement with authenticated encryption.

use alloc::vec::Vec;
use core::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, KeyInit,
    consts::{U10, U12, U32},
    generic_array::GenericArray,
};
use chacha20::hchacha;
use p256::{
    EncodedPoint, PublicKey, SecretKey, ecdh,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::aead_session::{
    AeadMessageKey as CommonAeadMessageKey, AeadSession, ReceiverKey,
};

use crate::{EncryptionSessionBuilder, PublicKeyError};

/// P-256-backed AEAD session.
pub type AeadP256<S> = AeadSession<S>;

/// Key and nonce reserved for one outbound message.
pub type AeadP256MessageKey<S> = CommonAeadMessageKey<S>;

/// Compatibility alias for [`AeadP256MessageKey`].
#[deprecated(note = "use AeadP256MessageKey instead")]
pub type P256AeadMessageKey<S> = AeadP256MessageKey<S>;

/// Configures a P-256-backed encryption session.
pub struct AeadP256Builder<S> {
    secret: SecretKey,
    own_public_enc: EncodedPoint,
    receivers: Vec<ReceiverKey>,
    marker: PhantomData<S>,
}

/// Active P-256-backed encryption session.
///
/// P-256 key agreement with ChaCha20-Poly1305.
#[cfg(feature = "chacha20poly1305")]
pub type AeadP256ChaChaPoly1305 =
    AeadP256<chacha20poly1305::ChaCha20Poly1305>;
/// P-256 and ChaCha20-Poly1305 builder.
#[cfg(feature = "chacha20poly1305")]
pub type AeadP256ChaChaPoly1305Builder =
    AeadP256Builder<chacha20poly1305::ChaCha20Poly1305>;

/// P-256 key agreement with AES-256-GCM.
#[cfg(feature = "aes-gcm")]
pub type AeadP256Aes256Gcm = AeadP256<aes_gcm::Aes256Gcm>;
/// P-256 and AES-256-GCM builder.
#[cfg(feature = "aes-gcm")]
pub type AeadP256Aes256GcmBuilder = AeadP256Builder<aes_gcm::Aes256Gcm>;

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

        self.receivers.push((
            receiver_index,
            (
                shared_key,
                remote.to_encoded_point(false).as_bytes().to_vec(),
            ),
        ));

        Ok(())
    }

    fn build(self) -> Self::Session {
        AeadSession::new(
            self.own_public_enc.as_bytes().to_vec(),
            self.receivers,
        )
    }
}

#[cfg(all(test, feature = "aes-gcm"))]
mod tests {
    use super::*;
    use crate::{DataDecryption, DataEncryption, EncryptionSession};

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
