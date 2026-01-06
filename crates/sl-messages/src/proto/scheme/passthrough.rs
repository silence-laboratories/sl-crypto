// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand_core::TryCryptoRng;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, KeyExchange, MessageKey,
    PublicKeyError,
};

pub struct PassThroughEncryptionBuilder;

pub struct PassThroughMessageKey;

pub struct PassThroughEncryption;

/// Wrapper for Vec<u8> that implements TryFrom<&[u8]> with PublicKeyError
#[derive(Clone)]
pub struct PassthroughPublicKey(pub Vec<u8>);

impl AsRef<[u8]> for PassthroughPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<PassthroughPublicKey> for Vec<u8> {
    fn from(wrapper: PassthroughPublicKey) -> Self {
        wrapper.0
    }
}

impl<'a> TryFrom<&'a [u8]> for PassthroughPublicKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(PassthroughPublicKey(bytes.to_vec()))
    }
}

/// Empty key material for passthrough (no actual key exchange)
#[derive(Clone, Copy, Default)]
pub struct PassthroughKeyMaterial;

impl AsRef<[u8]> for PassthroughKeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl KeyExchange for PassThroughEncryptionBuilder {
    type PublicKey = PassthroughPublicKey;
    type SharedSecret = Vec<u8>;
    type KeyMaterial = PassthroughKeyMaterial;

    fn establish_shared_secret(
        &mut self,
        _receiver_pk: &Self::PublicKey,
        _rng: &mut impl TryCryptoRng,
    ) -> Result<(Self::SharedSecret, PassthroughKeyMaterial), PublicKeyError> {
        Ok((Vec::new(), PassthroughKeyMaterial))
    }

    fn receive_shared_secret(
        &mut self,
        _sender_pk: &Self::PublicKey,
        _key_material: &PassthroughKeyMaterial,
    ) -> Result<Self::SharedSecret, PublicKeyError> {
        Ok(Vec::new())
    }
}

impl EncryptionSchemeBuilder for PassThroughEncryptionBuilder {
    type Scheme = PassThroughEncryption;

    fn public_key(&self) -> &[u8] {
        &[]
    }

    fn receiver_public_key(
        &mut self,
        _receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError> {
        if !public_key.is_empty() {
            return Err(PublicKeyError);
        }

        Ok(())
    }

    fn build(self) -> Self::Scheme {
        PassThroughEncryption
    }
}

impl MessageKey for PassThroughMessageKey {
    fn message_footer(&self) -> usize {
        0
    }

    fn encrypt(
        self,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        Ok(())
    }
}

impl EncryptionScheme for PassThroughEncryption {
    type Key = PassThroughMessageKey;

    fn encryption_key(
        &mut self,
        _receiver: usize,
    ) -> Result<Self::Key, EncryptionError> {
        Ok(PassThroughMessageKey)
    }

    fn decrypt_message<'m>(
        &self,
        _associated_data: &[u8],
        buffer: &'m mut [u8],
        _sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        Ok(buffer)
    }
}
