// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use aead::{
    consts::{U10, U32},
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
};
use aes_gcm::Aes256Gcm;
use chacha20::hchacha;
use chacha20poly1305::ChaCha20Poly1305;
use p256::{
    ecdh,
    elliptic_curve::sec1::ToEncodedPoint,
    EncodedPoint, PublicKey, SecretKey,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, MessageKey,
    PublicKeyError,
};

type SharedKey = Zeroizing<GenericArray<u8, U32>>;

// Counter to create a unuque nonce.
struct NonceCounter(u32);

impl NonceCounter {
    fn new() -> Self {
        Self(0)
    }

    fn next_nonce<S: AeadCore>(&mut self) -> Nonce<S> {
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

/// AEAD message key for [`AeadP256`] (ChaCha20-Poly1305 or AES-GCM, etc.).
pub struct P256AeadMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

impl<S> MessageKey for P256AeadMessageKey<S>
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
pub struct AeadP256Builder<S> {
    secret: SecretKey,
    own_public_enc: EncodedPoint,
    pk: Pairs<(SharedKey, PublicKey), usize>,
    marker: PhantomData<S>,
}

pub struct AeadP256<S> {
    public_key_enc: EncodedPoint,
    counter: NonceCounter,
    pk: Pairs<(SharedKey, PublicKey), usize>,
    marker: PhantomData<S>,
}

/// P-256 key exchange with ChaCha20-Poly1305.
pub type AeadP256ChaChaPoly1305 = AeadP256<ChaCha20Poly1305>;
/// P-256 key exchange with AES-256-GCM.
pub type AeadP256Aes256Gcm = AeadP256<Aes256Gcm>;

/// P-256 + ChaCha20-Poly1305 builder.
pub type AeadP256ChaChaPoly1305Builder = AeadP256Builder<ChaCha20Poly1305>;
/// P-256 + AES-256-GCM builder.
pub type AeadP256Aes256GcmBuilder = AeadP256Builder<Aes256Gcm>;

impl<S> AeadP256Builder<S> {
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let secret = SecretKey::random(rng);
        Self::from_secret_key(secret)
    }

    pub fn from_secret_key(secret: SecretKey) -> Self {
        let own_public_enc = secret.public_key().to_encoded_point(false);

        Self {
            secret,
            own_public_enc,
            pk: Pairs::new(),
            marker: PhantomData,
        }
    }
}

impl<S> EncryptionSchemeBuilder for AeadP256Builder<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Scheme = AeadP256<S>;

    fn public_key(&self) -> &[u8] {
        self.own_public_enc.as_bytes()
    }

    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        pk: &[u8],
    ) -> Result<(), PublicKeyError> {
        let remote = PublicKey::from_sec1_bytes(pk).map_err(|_| PublicKeyError)?;
        let shared = ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), remote.as_affine());

        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared.raw_secret_bytes()),
            &GenericArray::default(),
        ));

        self.pk.push(receiver_index, (shared_key, remote));

        Ok(())
    }

    fn build(self) -> Self::Scheme {
        Self::Scheme {
            public_key_enc: self.own_public_enc,
            counter: NonceCounter::new(),
            pk: self.pk,
            marker: PhantomData,
        }
    }
}

impl<S> EncryptionScheme for AeadP256<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Key = P256AeadMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::Key, EncryptionError> {
        let (key, public_key) =
            self.pk.find_pair_or_err(receiver, EncryptionError)?;

        let enc = public_key.to_encoded_point(false);
        let key = Zeroizing::new(
            Sha256::new_with_prefix(enc.as_bytes())
                .chain_update(key)
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());

        let nonce = self.counter.next_nonce::<S>();
        let cipher = S::new(key);

        Ok(P256AeadMessageKey { cipher, nonce })
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

        let (key, _public_key) =
            self.pk.find_pair_or_err(sender, EncryptionError)?;

        let key = Zeroizing::new(
            Sha256::new_with_prefix(self.public_key_enc.as_bytes())
                .chain_update(key)
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
