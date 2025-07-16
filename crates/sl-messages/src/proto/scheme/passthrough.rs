// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use super::*;

pub struct PassThroughEncryptionBuilder;

pub struct PassThroughMessageKey;

pub struct PassThroughEncryption;

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
