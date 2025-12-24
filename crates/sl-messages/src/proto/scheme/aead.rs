// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use aead::{
    consts::{U10, U32},
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
};
use chacha20::hchacha;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

type SharedKey = Zeroizing<GenericArray<u8, U32>>;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, MessageKey,
    PublicKeyError,
};

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
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
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
        let pk: [u8; 32] = pk.try_into().map_err(|_| PublicKeyError)?;
        let pk = PublicKey::from(pk);

        let shared_secret = self.secret.diffie_hellman(&pk);

        if !shared_secret.was_contributory() {
            return Err(PublicKeyError);
        }

        let shared_key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));

        self.pk.push(receiver_index, (shared_key, pk));

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
