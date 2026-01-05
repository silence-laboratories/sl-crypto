// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    consts::{U10, U32},
    generic_array::{GenericArray, typenum::Unsigned},
};
use chacha20::hchacha;
use sha2::{Digest, Sha256};
use rand_core::{CryptoRng as CryptoRng09, OsRng as OsRng09}; // v0.9
use rand_core_06::{CryptoRng as CryptoRng06, RngCore as RngCore06}; // v0.6 // v0.6use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

type SharedKey = Zeroizing<GenericArray<u8, U32>>;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, KeyExchange, MessageKey,
    PublicKeyError,
};

/// Wrapper for x25519_dalek::PublicKey that implements TryFrom<&[u8]>
#[derive(Clone, Copy)]
pub struct X25519PublicKey(pub PublicKey);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a [u8]> for X25519PublicKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| PublicKeyError)?;
        Ok(X25519PublicKey(PublicKey::from(array)))
    }
}

impl From<PublicKey> for X25519PublicKey {
    fn from(pk: PublicKey) -> Self {
        X25519PublicKey(pk)
    }
}

impl From<X25519PublicKey> for PublicKey {
    fn from(wrapper: X25519PublicKey) -> Self {
        wrapper.0
    }
}

/// Empty key material for X25519 (no additional material to exchange)
#[derive(Clone, Copy, Default)]
pub struct EmptyKeyMaterial;

impl AsRef<[u8]> for EmptyKeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

// Counter to create a unuque nonce.
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

pub struct AeadX25519Builder<S> {
    secret: ReusableSecret,
    public_key: PublicKey,
    pk: Pairs<(SharedKey, PublicKey), usize>,
    marker: PhantomData<S>,
}

/// The implementation of EncryptionScheme that uses x25519 for key
/// exchange and any implementation of `AeadInPlace`.
pub struct AeadX25519<S> {
    public_key: PublicKey,
    counter: NonceCounter,
    pk: Pairs<(SharedKey, PublicKey), usize>,
    marker: PhantomData<S>,
}

pub struct AeadMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

impl<S> AeadX25519Builder<S> {
    /// Generate a new [`AeadX25519`] with the supplied RNG.
    pub fn new(rng: &mut (impl RngCore06 + CryptoRng06)) -> Self {
        let secret = ReusableSecret::random_from_rng(rng);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            pk: Pairs::new(),
            marker: PhantomData,
        }
    }

    /// Create a new [`AeadX25519`] from provided `ReusableSecret`.
    pub fn from_secret(secret: ReusableSecret) -> Self {
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
            pk: Pairs::new(),
            marker: PhantomData,
        }
    }
}

impl<S> KeyExchange for AeadX25519Builder<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type PublicKey = X25519PublicKey;
    type SharedSecret = SharedKey;
    type KeyMaterial = EmptyKeyMaterial; // No additional material for X25519

    fn establish_shared_secret(
        &mut self,
        receiver_pk: &Self::PublicKey,
        _rng: &mut impl CryptoRng09,
    ) -> Result<(Self::SharedSecret, EmptyKeyMaterial), PublicKeyError> {
        // DH computation using our secret key and receiver's public key
        let pk: PublicKey = receiver_pk.0.clone();
        let shared_secret = self.secret.diffie_hellman(&pk);
        if !shared_secret.was_contributory() {
            return Err(PublicKeyError);
        }
        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));
        Ok((shared_key, EmptyKeyMaterial))
    }

    fn receive_shared_secret(
        &mut self,
        sender_pk: &Self::PublicKey,
        _key_material: &EmptyKeyMaterial,
    ) -> Result<Self::SharedSecret, PublicKeyError> {
        // For DH, same as establish (symmetric)
        let mut rng = OsRng09;
        self.establish_shared_secret(sender_pk, &mut rng)
            .map(|(ss, _)| ss)
    }
}

impl<S> EncryptionSchemeBuilder for AeadX25519Builder<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Scheme = AeadX25519<S>;

    fn public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        pk: &[u8],
    ) -> Result<(), PublicKeyError> {
        let receiver_pk = Self::PublicKey::try_from(pk)?;

        // This calls the establish_shared_secret() we implemented above
        use rand_core::OsRng;
        let (shared_secret, _key_material) = self.establish_shared_secret(
            &receiver_pk,
            &mut OsRng09,
        )?;

        // Convert X25519PublicKey wrapper back to PublicKey for storage
        let pk_inner: PublicKey = receiver_pk.into();
        self.pk.push(receiver_index, (shared_secret, pk_inner));

        Ok(())
    }

    fn build(self) -> Self::Scheme {
        Self::Scheme {
            public_key: self.public_key,
            counter: NonceCounter::new(),
            pk: self.pk,
            marker: PhantomData,
        }
    }
}

impl<S> MessageKey for AeadMessageKey<S>
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

impl<S> EncryptionScheme for AeadX25519<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Key = AeadMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::Key, EncryptionError> {
        let (key, public_key) =
            self.pk.find_pair_or_err(receiver, EncryptionError)?;

        let key = Zeroizing::new(
            Sha256::new_with_prefix(public_key)
                .chain_update(key)
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());

        let nonce = self.counter.next_nonce::<S>();
        let cipher = S::new(key);

        Ok(AeadMessageKey { cipher, nonce })
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
            Sha256::new_with_prefix(self.public_key)
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
