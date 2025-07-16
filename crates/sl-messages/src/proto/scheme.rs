// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(dead_code)]


use crate::proto::encrypted::MessageKey;

pub mod aead;
pub mod passthrough;

#[derive(Debug)]
pub struct PublicKeyError;

#[derive(Debug)]
pub struct EncryptionError;

pub trait EncryptionSchemeBuilder {
    type Scheme: EncryptionScheme;

    /// Return external representation of own public key
    fn public_key(&self) -> &[u8];

    /// Sets or updates the public key for a specified receiver index.
    ///
    /// This function is used to associate a public key with a designated
    /// receiver identified by an index. It facilitates secure communication
    /// setup by ensuring that messages can be encrypted such that only the
    /// receiver with the corresponding private key can decrypt them.
    ///
    /// # Parameters
    ///
    /// - `receiver_index`: An integer value that uniquely identifies the
    ///   receiver within the system. This index is used to specify which
    ///   receiver the public key is associated with.
    ///
    /// - `public_key`: A byte slice representing the public key of the receiver.
    ///   This key is used in cryptographic operations to ensure that only
    ///   the intended receiver can decrypt messages encrypted with this key.
    ///
    ///
    /// # Errors
    ///
    /// - `PublicKeyError`: An error is returned if the public key cannot be
    ///   set due to invalid formatting, an invalid receiver index, or any
    ///   other issue encountered in the operation. The precise error variant
    ///   provides further details on the nature of the failure.
    ///
    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError>;

    fn build(self) -> Self::Scheme;
}

/// Represents an encryption scheme interface for in-place AEAD and
/// managing key exchange.
///
/// A type implementing EncryptionScheme encapsulates two
/// functionalities:
///
/// - An AEAD algorithm such as ChaCha20 or AES-GCM and its
///   implementation details, such as nonce generation.
///
/// - The derivation of encryption keys for one or more pairs of parties.
///   The concrete type of public/private key pair and key exchange is
///   an implementation detail.
///
pub trait EncryptionScheme: Send {
    type Key: MessageKey;

    /// Create an instance of an encryption key for a specified
    /// receiver.
    ///
    /// `Self::Key` contains all key material required to encrypt a
    /// single message.
    ///
    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::Key, EncryptionError>;

    /// Decrypts the provided data buffer and return plaintext with
    /// scheme specific tag/nonce.
    ///
    /// # Parameters
    ///
    /// - `associated_data`: A byte slice containing additional
    ///   authenticated data (AAD) that will be used along with the
    ///   buffer to ensure the integrity and authenticity of the
    ///   decryption process. This data is not encrypted but plays a
    ///   role in verifying the encrypted data.
    ///
    /// - `buffer`: A mutable byte slice holding the encrypted data
    ///   that will be decrypted in place. Upon successful decryption,
    ///   this buffer will contain the plaintext data.
    ///
    /// - `sender`: An index or identifier representing the sender of
    ///   the message. This might be used to retrieve or derive
    ///   encryption keys.
    ///
    /// # Errors
    ///
    /// - `EncryptionError`: This function may return an
    ///   `EncryptionError` in several situations such as when the
    ///   decryption key is not found, when the input data is tampered
    ///   with or if the cryptographic verification of the AAD fails.
    ///
    fn decrypt_message<'m>(
        &self,
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError>;
}
