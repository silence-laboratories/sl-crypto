// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! KEM-backed message encryption for round-based multiparty protocols.
//!
//! This crate combines a key encapsulation mechanism (KEM) with symmetric
//! message encryption. It manages KEM key material, per-message nonces,
//! optional encapsulation transport, and cached shared secrets.
//!
//! # Lifecycle
//!
//! Encryption has two phases:
//!
//! 1. [`EncryptionSessionBuilder`] configures the session. Creating a builder
//!    corresponds to KEM `Gen`, while
//!    [`EncryptionSessionBuilder::receiver_public_key`] runs `Encap` for each
//!    receiver.
//! 2. [`EncryptionSessionBuilder::build`] consumes the builder and returns an
//!    active [`EncryptionSession`] with a fixed set of receivers.
//!
//! An active session reserves a [`MessageEncryptionKey`] for each outbound
//! message. The key contains all state required for one encryption operation,
//! including a unique nonce and, when required, the receiver's KEM
//! encapsulation.
//!
//! # Protocol model
//!
//! Communication is round-based for each receiver. A sender does not create
//! another message for a receiver until it has processed that receiver's reply
//! to the previous message. Messages for different receivers may be prepared
//! and encrypted in parallel.
//!
//! The first message to a receiver carries the KEM encapsulation. The receiver
//! runs `Decap`, authenticates and decrypts the message, and caches the
//! resulting shared secret before replying. Later messages omit the
//! encapsulation.
//!
//! [`EncryptionSession::expects_encapsulation`] reports whether the next
//! message from a sender must carry an encapsulation and, if so, its serialized
//! length.
//!
//! If a protocol run fails before a reply is received, that run is abandoned or
//! restarted instead of continuing with another message to the same receiver.
//!
//! # Message formats
//!
//! The core encryption traits operate on caller-owned byte slices and do not
//! prescribe an enclosing transport format. A message format is responsible
//! for:
//!
//! - serializing [`MessageEncryptionKey::encapsulation`] when present;
//! - including the encapsulation in authenticated data;
//! - reserving [`MessageEncryptionKey::encryption_overhead`] trailing bytes;
//! - passing ciphertext and its trailing overhead to
//!   [`EncryptionSession::decrypt_message`].
//!
//! # Partial encryption
//!
//! [`DataEncryption`] and [`DataDecryption`] encrypt and decrypt one typed value
//! embedded in a larger message. This supports broadcast messages containing
//! one independently encrypted value for each receiver.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(test)]
extern crate std;

use bytemuck::{AnyBitPattern, NoUninit};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct PublicKeyError;

#[derive(Debug)]
pub struct EncryptionError;

#[cfg(feature = "aead-x25519")]
pub mod aead_x25519;
#[cfg(feature = "aead-x25519")]
pub use aead_x25519 as aead;
#[cfg(feature = "aead-p256")]
pub mod aead_p256;
#[cfg(any(feature = "aead-x25519", feature = "aead-p256"))]
mod aead_session;
#[cfg(feature = "ml-kem")]
pub mod ml;

pub mod passthrough;

/// Builds an [`EncryptionSession`] backed by one or more KEM operations.
///
/// An implementation owns the local KEM key material and the encapsulations
/// prepared for its receivers. Creating an implementation of this trait
/// corresponds to the KEM `Gen` operation: it generates (or restores) the
/// local decapsulation key and its corresponding encapsulation public key.
///
/// A builder can prepare an independent KEM encapsulation for each receiver.
/// After all receivers have been registered, [`EncryptionSessionBuilder::build`]
/// consumes the builder and starts the active session.
pub trait EncryptionSessionBuilder {
    type Session: EncryptionSession;

    /// Returns the serialized representation of the local KEM public key.
    ///
    /// The returned bytes can be shared with a sender that needs to perform
    /// `Encap` for this instance. The serialization format is defined by the
    /// implementation.
    fn public_key(&self) -> &[u8];

    /// Runs KEM `Encap` for a receiver and stores the resulting key material.
    ///
    /// `public_key` must be the receiver's serialized KEM public key. On
    /// success, the implementation associates the resulting shared secret and
    /// ciphertext with `receiver_index`; the ciphertext is later made
    /// available to the receiver as part of message encryption. Each receiver
    /// index must be unique, so this method must not be called more than once
    /// for the same index.
    ///
    /// # Parameters
    ///
    /// - `rng`: Cryptographically secure randomness used by `Encap`.
    /// - `receiver_index`: The identifier of the receiver.
    /// - `public_key`: The receiver's serialized KEM public key.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError`] if the public key is malformed or if KEM
    /// encapsulation fails.
    fn receiver_public_key(
        &mut self,
        rng: &mut impl CryptoRngCore,
        receiver_index: usize,
        public_key: &[u8],
    ) -> Result<(), PublicKeyError>;

    /// Finalizes configuration and returns the active encryption session.
    fn build(self) -> Self::Session;
}

/// Provides message encryption and decryption for an active session.
///
/// A value implementing this trait owns the local KEM decapsulation key and
/// the KEM encapsulations prepared for its receivers. It combines those KEM
/// operations with an AEAD or another [`MessageEncryptionKey`]
/// implementation:
///
/// - [`encryption_key`](Self::encryption_key) retrieves the shared secret
///   created by `Encap` for a receiver and creates the key used for one
///   message.
/// - [`decrypt_message`](Self::decrypt_message) runs `Decap` on the sender's
///   encapsulation and uses the resulting shared secret to decrypt the
///   message in place.
///
/// Receiver and sender identifiers are application-defined indexes. They must
/// be used consistently when configuring the builder and processing messages.
///
/// # Usage modes
///
/// A format layer can use a [`MessageEncryptionKey`] to encrypt a complete
/// framed message for one receiver. The format decides which bytes remain
/// visible as authenticated data and where to place optional encapsulation and
/// trailing encryption overhead.
///
/// Alternatively, [`DataEncryption`] encrypts one value embedded in a larger
/// message. For example, an `N`-party broadcast message can contain `N`
/// independently encrypted values, one for each receiver. A key is reserved
/// for each receiver, after which the values may be encrypted in parallel.
/// Associated data should bind each encrypted value to its containing message
/// and intended position or receiver so it cannot be moved to another message
/// or vector entry.
///
/// # Protocol assumptions
///
/// Communication is round-based for each receiver. At most one outbound
/// encrypted message may be outstanding for a receiver: the caller must
/// process that receiver's reply before requesting another encryption key for
/// the same receiver. Having two independent outbound messages in flight for
/// one
/// receiver is considered a protocol design error.
///
/// Calls to [`EncryptionSession::encryption_key`] are serialized through the
/// mutable session so that the implementation can reserve a unique nonce and
/// update other per-message state. Keys for different receivers may then be
/// used independently, allowing their messages to be constructed and
/// encrypted in parallel.
///
/// The first outbound message for a receiver carries the KEM encapsulation.
/// The receiver decapsulates and caches the shared secret before producing its
/// reply. Because the next outbound message is not created until that reply is
/// processed, subsequent messages can omit the encapsulation. If transport or
/// processing fails before a reply is received, that protocol run is abandoned
/// or restarted rather than continued with another message to the receiver.
pub trait EncryptionSession {
    /// The per-message encryption key produced by this session.
    type EncryptionKey: MessageEncryptionKey;

    /// Reserves and returns the key material for one message to `receiver`.
    ///
    /// This method mutates the session to reserve a nonce and any other
    /// scheme-specific per-message state. The returned
    /// [`MessageEncryptionKey`] is self-contained and may be moved to a worker
    /// for message construction and encryption.
    ///
    /// Its [`MessageEncryptionKey::encapsulation`] contains the KEM
    /// encapsulation when it must be sent to the receiver. The receiver must
    /// have been registered with the builder before it was consumed by
    /// [`EncryptionSessionBuilder::build`].
    ///
    /// A caller must not request another key for the same receiver until the
    /// reply to the previous message has been processed. Keys for different
    /// receivers may be outstanding concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if no key material is configured for the
    /// receiver.
    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::EncryptionKey, EncryptionError>;

    /// Returns the encapsulation length expected from `sender`.
    ///
    /// `Some(len)` means that the next message from `sender` must contain a
    /// serialized KEM encapsulation of exactly `len` bytes. `None` means that
    /// the session has already cached the sender's shared secret and no
    /// encapsulation is expected.
    fn expects_encapsulation(&self, sender: usize) -> Option<usize>;

    /// Decrypts a message in place and returns its plaintext.
    ///
    /// `encapsulation` is the serialized KEM ciphertext produced by `Encap`.
    /// The implementation runs `Decap` with its local decapsulation key and
    /// uses the resulting shared secret to derive the message decryption key.
    ///
    /// `buffer` must contain the ciphertext followed by the algorithm-specific
    /// bytes written by [`MessageEncryptionKey::encrypt`]. In particular, its
    /// final [`MessageEncryptionKey::encryption_overhead`] bytes must contain
    /// the encryption overhead, such as an authentication tag and nonce. On
    /// success, the ciphertext is replaced with plaintext and the returned
    /// slice excludes those trailing overhead bytes.
    ///
    /// `associated_data` is authenticated but not encrypted; it includes the
    /// caller-provided data and, for the first message, the KEM encapsulation
    /// from [`MessageEncryptionKey::encapsulation`].
    ///
    /// `sender` identifies the sender whose encapsulation is being processed.
    /// Implementations may cache the result of `Decap` for this identifier.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if the encapsulation is malformed, key
    /// derivation fails, the buffer is too short, or authentication fails.
    fn decrypt_message<'m>(
        &mut self,
        encapsulation: &[u8],
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError>;
}

pub trait MessageEncryptionKey: Sized {
    /// Returns the number of trailing bytes reserved for encryption overhead.
    ///
    /// For a typical AEAD this is the combined size of its authentication tag
    /// and nonce. It does not include the optional KEM encapsulation returned
    /// by [`MessageEncryptionKey::encapsulation`].
    fn encryption_overhead(&self) -> usize;

    /// Returns the KEM encapsulation to include as authenticated data.
    ///
    /// This is the serialized ciphertext produced by `Encap`. It is not
    /// encrypted, but is authenticated together with the caller-provided
    /// additional data so the recipient can run `Decap` and derive the
    /// message key. Under the round-based protocol described by
    /// [`EncryptionSession`], the encapsulation is needed only in the first
    /// outbound message for a receiver. The receiver caches the derived shared
    /// secret before replying, so subsequent messages do not repeat it.
    ///
    /// Returns `None` when this message does not need to carry an
    /// encapsulation.
    fn encapsulation(&self) -> Option<&[u8]> {
        None
    }

    /// Encrypts the plaintext portion of `buffer` in place.
    ///
    /// The final [`encryption_overhead`](Self::encryption_overhead) bytes of
    /// `buffer` must be reserved by the caller. On success, those bytes are
    /// filled according to the encryption algorithm, typically with
    /// an authentication tag and nonce. The preceding bytes are replaced with
    /// ciphertext.
    ///
    /// `associated_data` is authenticated together with the message but is not
    /// encrypted or modified.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if the buffer is too short or encryption
    /// fails.
    ///
    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError>;
}

/// Encrypts one value within a larger, otherwise independently encoded
/// message.
///
/// This is the partial-encryption interface. A typical use is an `N`-party
/// broadcast message containing a vector of `N` encrypted values, one for each
/// receiver. The caller reserves a [`MessageEncryptionKey`] for each receiver;
/// because those keys are independent, the values may be encrypted in
/// parallel before the enclosing message is broadcast.
///
/// The caller should use associated data to bind an encrypted value to its
/// enclosing message, protocol round, and vector position or receiver. The
/// enclosing message format remains the caller's responsibility.
pub trait DataEncryption {
    /// Encrypts `data` and appends its encoded representation to `buffer`.
    ///
    /// The appended bytes have the following layout:
    ///
    /// ```text
    /// [ associated-data | encapsulation? | ciphertext | encryption-overhead ]
    /// ```
    ///
    /// `aad` and the optional [`MessageEncryptionKey::encapsulation`] remain
    /// unencrypted but are authenticated. The byte representation of `data` is
    /// copied into newly appended space in `buffer`, where the copy is replaced
    /// with ciphertext. `data` itself is not modified. The final
    /// [`MessageEncryptionKey::encryption_overhead`] bytes are filled by the
    /// encryption algorithm.
    ///
    /// `T` must implement [`NoUninit`] so that its complete byte representation
    /// can be read safely. The caller is responsible for choosing a stable
    /// external representation when encrypted data crosses platform or version
    /// boundaries.
    ///
    /// This method consumes the message encryption key; a key is reserved for
    /// exactly one encryption operation.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptionError`] if memory reservation or encryption fails.
    /// On error, the original length and contents of `buffer` are preserved;
    /// any bytes appended before an encryption failure are zeroized first.
    fn encrypt_data<T>(
        self,
        aad: &[u8],
        data: &T,
        buffer: &mut Vec<u8>,
    ) -> Result<(), EncryptionError>
    where
        T: NoUninit;
}

impl<K: MessageEncryptionKey> DataEncryption for K {
    fn encrypt_data<T>(
        self,
        aad: &[u8],
        payload: &T,
        buffer: &mut Vec<u8>,
    ) -> Result<(), EncryptionError>
    where
        T: NoUninit,
    {
        let encapsulation = self.encapsulation();
        let encapsulation_size = encapsulation.map_or(0, <[u8]>::len);
        let payload = bytemuck::bytes_of(payload);
        let total_size = encapsulation_size
            + aad.len()
            + payload.len()
            + self.encryption_overhead();

        let offset = buffer.len();

        buffer
            .try_reserve(total_size)
            .map_err(|_| EncryptionError)?;

        buffer.extend(aad);
        if let Some(encapsulation) = encapsulation {
            buffer.extend(encapsulation);
        }
        buffer.extend(payload);
        buffer.extend(core::iter::repeat_n(0, self.encryption_overhead()));

        let (aad, plaintext) =
            buffer[offset..].split_at_mut(encapsulation_size + aad.len());

        if self.encrypt(aad, plaintext).is_err() {
            buffer[offset..].zeroize();
            buffer.truncate(offset);

            return Err(EncryptionError);
        }

        Ok(())
    }
}

/// Decrypts a partially encrypted component of a larger message.
pub trait DataDecryption {
    /// Decrypts a value sent by `sender` and returns its additional data and
    /// typed plaintext.
    ///
    /// The plaintext is returned as a reference into `buffer`. If the alignment
    /// of `T` is greater than one, its position after the additional data and
    /// optional encapsulation may not satisfy that alignment. In that case,
    /// authenticated decryption may succeed but this method returns
    /// [`EncryptionError`] when converting the plaintext to `&T`.
    fn decrypt_data<'m, T>(
        &mut self,
        sender: usize,
        aad: usize,
        buffer: &'m mut [u8],
    ) -> Result<(&'m [u8], &'m T), EncryptionError>
    where
        T: AnyBitPattern;
}

impl<S> DataDecryption for S
where
    S: EncryptionSession,
{
    fn decrypt_data<'m, T>(
        &mut self,
        sender: usize,
        aad_len: usize,
        buffer: &'m mut [u8],
    ) -> Result<(&'m [u8], &'m T), EncryptionError>
    where
        T: AnyBitPattern,
    {
        let encapsulation_len =
            self.expects_encapsulation(sender).unwrap_or(0);
        let authenticated_len = aad_len
            .checked_add(encapsulation_len)
            .ok_or(EncryptionError)?;

        let (authenticated_data, encrypted_data) = buffer
            .split_at_mut_checked(authenticated_len)
            .ok_or(EncryptionError)?;

        let (aad, encapsulation) = authenticated_data
            .split_at_checked(aad_len)
            .ok_or(EncryptionError)?;

        let plaintext = self.decrypt_message(
            encapsulation,
            authenticated_data,
            encrypted_data,
            sender,
        )?;

        let valid_value = bytemuck::try_from_bytes::<T>(plaintext).is_ok();

        if !valid_value {
            plaintext.zeroize();
            return Err(EncryptionError);
        }

        let value = bytemuck::from_bytes(plaintext);

        Ok((aad, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passthrough::PassThroughEncryptionBuilder;

    #[test]
    fn conversion_error_zeroizes_plaintext() {
        let aad = b"associated data";
        let payload = [42_u8; 32];
        let mut message = Vec::new();
        let mut session = PassThroughEncryptionBuilder.build();

        session
            .encryption_key(0)
            .unwrap()
            .encrypt_data(aad, &payload, &mut message)
            .unwrap();

        assert!(
            session
                .decrypt_data::<[u8; 31]>(0, aad.len(), &mut message)
                .is_err()
        );
        assert_eq!(&message[..aad.len()], aad);
        assert!(message[aad.len()..].iter().all(|byte| *byte == 0));
    }
}
