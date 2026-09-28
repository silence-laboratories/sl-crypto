// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Pass-through implementation of the encryption session traits.
//!
//! This module preserves message bytes without encryption. It is useful when
//! encryption is disabled while retaining the same session API.

use rand_core::CryptoRngCore;

use crate::{
    EncryptionError, EncryptionSession, EncryptionSessionBuilder,
    MessageEncryptionKey, PublicKeyError,
};

pub struct PassThroughEncryptionBuilder;

pub struct PassThroughEncryptionKey;

pub struct PassThroughEncryption;

impl EncryptionSessionBuilder for PassThroughEncryptionBuilder {
    type Session = PassThroughEncryption;

    fn public_key(&self) -> &[u8] {
        &[]
    }

    fn receiver_public_key(
        &mut self,
        _rng: &mut impl CryptoRngCore,
        _receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError> {
        if !public_key.is_empty() {
            return Err(PublicKeyError);
        }

        Ok(())
    }

    fn build(self) -> Self::Session {
        PassThroughEncryption
    }
}

impl MessageEncryptionKey for PassThroughEncryptionKey {
    fn encryption_overhead(&self) -> usize {
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

impl EncryptionSession for PassThroughEncryption {
    type EncryptionKey = PassThroughEncryptionKey;

    fn encryption_key(
        &mut self,
        _receiver: usize,
    ) -> Result<Self::EncryptionKey, EncryptionError> {
        Ok(PassThroughEncryptionKey)
    }

    fn expects_encapsulation(&self, _sender: usize) -> Option<usize> {
        None
    }

    fn decrypt_message<'m>(
        &mut self,
        encapsulation: &[u8],
        _associated_data: &[u8],
        buffer: &'m mut [u8],
        _sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        if !encapsulation.is_empty() {
            return Err(EncryptionError);
        }

        Ok(buffer)
    }
}
