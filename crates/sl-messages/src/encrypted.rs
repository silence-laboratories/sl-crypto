// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Whole-message framing for [`sl_msg_encrypt`] sessions.
//!
//! This module connects the message format owned by `sl-messages` to the
//! format-independent encryption traits from `sl-msg-encrypt`. It constructs
//! complete messages, places optional encapsulations and encryption overhead,
//! and parses the same layout during in-place decryption.
//!
//! Encapsulation presence is not encoded with a separate marker. During
//! decryption, [`EncryptionSession::expects_encapsulation`] determines whether
//! the message contains one and how many bytes it occupies. The protocol and
//! session state must therefore remain synchronized for each sender.

use alloc::{vec, vec::Vec};
use core::{marker::PhantomData, ops::Deref, time::Duration};

use bytemuck::{AnyBitPattern, NoUninit};
use zeroize::Zeroize;

pub use sl_msg_encrypt::{
    aead_x25519::AeadX25519Builder,
    passthrough::{
        PassThroughEncryption, PassThroughEncryptionBuilder,
        PassThroughEncryptionKey,
    },
    DataDecryption, DataEncryption, EncryptionError, EncryptionSession,
    EncryptionSessionBuilder, MessageEncryptionKey, PublicKeyError,
};

use crate::message::*;

pub type DefaultEncryptionScheme =
    sl_msg_encrypt::aead_x25519::AeadX25519ChaChaPoly1305Builder;

/// Provides access to the authenticated and decrypted parts of a message.
///
/// This value borrows the input buffer passed to [`EncryptedMessage::decrypt`].
/// Dropping it zeroizes the decrypted payload and trailer in that buffer. The
/// unencrypted additional data is not zeroized.
///
/// The body is a `T` reference into that buffer. If the alignment of `T` is
/// greater than one, its position after the header, optional encapsulation, and
/// additional data may not satisfy that alignment. In that case, authenticated
/// decryption may succeed but [`EncryptedMessage::decrypt`] returns `None`
/// instead of constructing this value.
pub struct DecryptedMessage<'m, T: AnyBitPattern + NoUninit> {
    data: &'m [u8],
    body: &'m mut T,
    trailer: &'m mut [u8],
}

impl<T: AnyBitPattern + NoUninit> DecryptedMessage<'_, T> {
    /// Returns the fixed-size portion of the message.
    pub fn body(&self) -> &T {
        self.body
    }

    /// Returns the variable-size portion of the message.
    pub fn trailer(&self) -> &[u8] {
        self.trailer
    }

    /// Returns the caller-provided additional data.
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<T: AnyBitPattern + NoUninit> Deref for DecryptedMessage<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.body
    }
}

impl<T: AnyBitPattern + NoUninit> Drop for DecryptedMessage<'_, T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(self.body).zeroize();
        self.trailer.zeroize();
    }
}

impl<S> EncryptedMessage for S where S: EncryptionSession {}

/// Decrypts complete messages encoded by [`MessageBuilder`].
///
/// The encoded message has the following layout:
///
/// ```text
/// [ header | encapsulation? | additional-data | payload | trailer | encryption-overhead ]
/// ```
///
/// The header, optional encapsulation, and additional data remain visible but
/// are authenticated. The payload and trailer are encrypted. Encapsulation
/// presence and length come from
/// [`EncryptionSession::expects_encapsulation`], rather than from a marker in
/// the encoded message.
pub trait EncryptedMessage: EncryptionSession {
    /// Decrypts a complete message in `buffer`.
    ///
    /// Decryption replaces the ciphertext in `buffer` with plaintext and
    /// returns a view containing the caller-provided additional data, typed
    /// payload, and variable-length trailer. Dropping that view zeroizes the
    /// payload and trailer.
    ///
    /// `additional_data` is the length of the caller-provided additional data;
    /// it does not include the message header or optional encapsulation.
    /// `sender` identifies the session peer whose encapsulation state and
    /// decryption key must be used.
    ///
    /// `T` is interpreted directly from the decrypted byte representation. The
    /// protocol is responsible for choosing a stable representation when
    /// messages cross platform or version boundaries.
    ///
    /// # Returns
    ///
    /// Returns `None` if the message lengths are invalid, the expected
    /// encapsulation cannot be extracted, authentication or decryption fails,
    /// or the plaintext cannot provide a correctly sized and aligned `T`.
    fn decrypt<'msg, T>(
        &mut self,
        buffer: &'msg mut [u8],
        additional_data: usize,
        sender: usize,
    ) -> Option<DecryptedMessage<'msg, T>>
    where
        T: AnyBitPattern + NoUninit,
    {
        let encapsulation_len =
            self.expects_encapsulation(sender).unwrap_or(0);
        let encapsulation_end =
            MESSAGE_HEADER_SIZE.checked_add(encapsulation_len)?;
        let authenticated_len =
            encapsulation_end.checked_add(additional_data)?;

        let (authenticated_data, encrypted_data) =
            buffer.split_at_mut_checked(authenticated_len)?;
        let encapsulation =
            authenticated_data.get(MESSAGE_HEADER_SIZE..encapsulation_end)?;

        let plaintext = self
            .decrypt_message(
                encapsulation,
                authenticated_data,
                encrypted_data,
                sender,
            )
            .ok()?;

        let payload_len = core::mem::size_of::<T>();

        let valid_payload = plaintext
            .split_at_mut_checked(payload_len)
            .and_then(|(payload, _)| {
                bytemuck::try_from_bytes_mut::<T>(payload).ok()
            })
            .is_some();

        if !valid_payload {
            plaintext.zeroize();
            return None;
        }

        let (payload, trailer) = plaintext.split_at_mut(payload_len);

        Some(DecryptedMessage {
            data: &authenticated_data[encapsulation_end..],
            body: bytemuck::from_bytes_mut(payload),
            trailer,
        })
    }
}

/// Constructs a complete message encrypted for one receiver.
///
/// The builder owns the complete output allocation and a one-message
/// [`MessageEncryptionKey`]. Its payload and trailer are initialized directly
/// in that allocation before encryption. `T` is encoded using its complete byte
/// representation, so protocols should use a stable representation for data
/// that crosses platform or version boundaries.
pub struct MessageBuilder<T, K> {
    key: K,
    buffer: Vec<u8>,
    additional_data: usize,
    trailer: usize,
    marker: PhantomData<T>,
}

impl<T, K> MessageBuilder<T, K>
where
    T: AnyBitPattern + NoUninit,
    K: MessageEncryptionKey,
{
    const T_SIZE: usize = core::mem::size_of::<T>();

    /// Encodes the message identifier, lifetime, and flags into the header.
    pub fn with_header(
        mut self,
        id: &MsgId,
        ttl: Duration,
        flags: u16,
    ) -> Self {
        if let Some(header) =
            self.buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>()
        {
            MsgHdr::encode(header, id, ttl, flags);
        }

        self
    }

    /// Initializes the fixed-size message payload in the output allocation.
    pub fn with_body<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let payload = &mut self.buffer
            [MESSAGE_HEADER_SIZE + self.additional_data..][..Self::T_SIZE];

        f(bytemuck::from_bytes_mut(payload));

        self
    }

    /// Initializes the variable-size encrypted trailer in the output
    /// allocation.
    pub fn with_tailer<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut [u8]),
    {
        let trailer = &mut self.buffer
            [MESSAGE_HEADER_SIZE + self.additional_data + Self::T_SIZE..]
            [..self.trailer];

        f(trailer);

        self
    }

    /// Encrypts the payload and trailer and returns the complete message.
    ///
    /// This consumes both the builder and its one-message encryption key. The
    /// header, optional encapsulation, and additional data are passed to the
    /// encryption algorithm as associated data.
    ///
    /// Returns `None` if the message cannot be split according to its format or
    /// encryption fails.
    pub fn encrypt(self) -> Option<Bytes> {
        let mut buffer = self.buffer;
        let (associated_data, plaintext) = buffer.split_at_mut_checked(
            MESSAGE_HEADER_SIZE + self.additional_data,
        )?;

        self.key.encrypt(associated_data, plaintext).ok()?;

        Some(Bytes::from(buffer))
    }

    /// Returns mutable references to the payload and trailer.
    ///
    /// Both references point directly into the eventual output allocation. The
    /// returned trailer excludes the trailing encryption overhead.
    pub fn payload(&mut self) -> (&mut T, &mut [u8]) {
        let overhead_offset =
            self.buffer.len() - self.key.encryption_overhead();
        let body = &mut self.buffer
            [MESSAGE_HEADER_SIZE + self.additional_data..overhead_offset];
        let (payload, trailer) = body.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(payload), trailer)
    }
}

/// Constructs and encrypts a complete framed message for one receiver.
///
/// This extension trait is implemented for every [`MessageEncryptionKey`]. The
/// message header, optional encapsulation, and caller-provided additional data
/// are authenticated but remain unencrypted. The fixed-size payload and
/// variable-size trailer are encrypted.
pub trait MessageEncryption: Sized {
    /// Allocates a complete message and returns its builder.
    ///
    /// This method consumes the one-message encryption key. It copies `aad` and
    /// the key's optional [`MessageEncryptionKey::encapsulation`] into the
    /// allocation, creates zero-initialized space for `T` and `trailer` bytes,
    /// and reserves the key's
    /// [`MessageEncryptionKey::encryption_overhead`] at the end.
    ///
    /// `aad` is caller-provided authenticated data. `trailer` is the length of
    /// the variable-size encrypted portion following the fixed-size payload.
    fn message<T>(
        self,
        aad: Option<&[u8]>,
        trailer: usize,
    ) -> MessageBuilder<T, Self>
    where
        T: AnyBitPattern + NoUninit;
}

impl<K: MessageEncryptionKey> MessageEncryption for K {
    fn message<T>(
        self,
        aad: Option<&[u8]>,
        trailer: usize,
    ) -> MessageBuilder<T, Self>
    where
        T: AnyBitPattern + NoUninit,
    {
        let encapsulation = self.encapsulation();
        let encapsulation_len = encapsulation.map_or(0, <[u8]>::len);
        let additional_data = aad.unwrap_or(&[]).len();
        let message_size = MESSAGE_HEADER_SIZE
            + encapsulation_len
            + additional_data
            + core::mem::size_of::<T>()
            + trailer
            + self.encryption_overhead();

        let mut buffer = vec![0; message_size];

        if let Some(encapsulation) = encapsulation {
            buffer[MESSAGE_HEADER_SIZE..][..encapsulation_len]
                .copy_from_slice(encapsulation);
        }

        if let Some(aad) = aad {
            buffer[MESSAGE_HEADER_SIZE + encapsulation_len..][..aad.len()]
                .copy_from_slice(aad);
        }

        MessageBuilder {
            key: self,
            buffer,
            trailer,
            additional_data: additional_data + encapsulation_len,
            marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use sl_msg_encrypt::{
        passthrough::PassThroughEncryptionBuilder, EncryptionSessionBuilder,
    };

    use super::*;

    fn enc_dec<B: EncryptionSessionBuilder>(mut sender: B, mut receiver: B) {
        let mut rng = rand::thread_rng();
        let message_id = MsgId::from([1; 32]);
        let ttl = Duration::from_secs(10);

        sender
            .receiver_public_key(&mut rng, 1, receiver.public_key())
            .unwrap();
        receiver
            .receiver_public_key(&mut rng, 0, sender.public_key())
            .unwrap();

        let mut sender = sender.build();
        let mut receiver = receiver.build();
        let body = [2_u8; 32];
        let aad = [3_u8; 23];

        let message = sender
            .encryption_key(1)
            .unwrap()
            .message::<[u8; 32]>(Some(&aad), 0)
            .with_header(&message_id, ttl, 0)
            .with_body(|payload| payload.copy_from_slice(&body))
            .encrypt()
            .unwrap();

        let mut message = BytesMut::from(message);
        let decrypted = receiver
            .decrypt::<[u8; 32]>(&mut message, aad.len(), 0)
            .unwrap();

        assert_eq!(&*decrypted, &body);
        assert_eq!(decrypted.data(), &aad);

        drop(decrypted);

        let payload_offset = MESSAGE_HEADER_SIZE + aad.len();
        assert!(message[payload_offset..payload_offset + body.len()]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn default_scheme() {
        let mut rng = rand::thread_rng();
        let sender = DefaultEncryptionScheme::new(&mut rng);
        let receiver = DefaultEncryptionScheme::new(&mut rng);

        enc_dec(sender, receiver);
    }

    #[test]
    fn pass_through_scheme() {
        enc_dec(PassThroughEncryptionBuilder, PassThroughEncryptionBuilder);
    }
}
