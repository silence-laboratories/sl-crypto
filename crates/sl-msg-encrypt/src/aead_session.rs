// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Common AEAD session machinery for the public-key agreement backends.

use alloc::vec::Vec;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    consts::{U12, U32},
    generic_array::{GenericArray, typenum::Unsigned},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{EncryptionError, EncryptionSession, MessageEncryptionKey};

pub(crate) type SharedKey = Zeroizing<GenericArray<u8, U32>>;
pub(crate) type ReceiverKey = (usize, (SharedKey, Vec<u8>));

/// Counter used to reserve a unique nonce for each message.
pub(crate) struct NonceCounter(u32);

impl NonceCounter {
    pub(crate) fn new() -> Self {
        Self(0)
    }

    pub(crate) fn next_nonce<S: AeadCore<NonceSize = U12>>(
        &mut self,
    ) -> Nonce<S> {
        // Protocol runs use only a small number of nonces per key. Overflow
        // therefore indicates misuse, and panicking is safer than nonce reuse.
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

/// Key and nonce reserved for one outbound message.
pub struct AeadMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

/// Common session implementation shared by the key-agreement backends.
pub struct AeadSession<S> {
    public_key: Vec<u8>,
    counter: NonceCounter,
    receivers: Vec<ReceiverKey>,
    marker: core::marker::PhantomData<S>,
}

impl<S> AeadSession<S> {
    pub(crate) fn new(
        public_key: Vec<u8>,
        receivers: Vec<ReceiverKey>,
    ) -> Self {
        Self {
            public_key,
            counter: NonceCounter::new(),
            receivers,
            marker: core::marker::PhantomData,
        }
    }
}

fn cipher<S>(public_key: &[u8], shared_key: &SharedKey) -> S
where
    S: AeadInPlace + AeadCore<NonceSize = U12> + KeyInit<KeySize = U32>,
{
    let key = Zeroizing::new(
        Sha256::new_with_prefix(public_key)
            .chain_update(shared_key)
            .finalize(),
    );
    S::new(Key::<S>::from_slice(key.as_slice()))
}

impl<S> MessageEncryptionKey for AeadMessageKey<S>
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

impl<S> EncryptionSession for AeadSession<S>
where
    S: AeadInPlace
        + AeadCore<NonceSize = U12>
        + KeyInit<KeySize = U32>
        + Send,
{
    type EncryptionKey = AeadMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::EncryptionKey, EncryptionError> {
        let (_, (shared_key, public_key)) = self
            .receivers
            .iter()
            .find(|(index, _)| *index == receiver)
            .ok_or(EncryptionError)?;

        Ok(AeadMessageKey {
            cipher: cipher::<S>(public_key, shared_key),
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

        let nonce = Nonce::<S>::from_slice(&overhead[S::TagSize::USIZE..]);
        let tag = Tag::<S>::from_slice(&overhead[..S::TagSize::USIZE]);

        cipher::<S>(&self.public_key, shared_key)
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| EncryptionError)?;

        Ok(buffer)
    }
}
