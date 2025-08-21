// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{marker::PhantomData, ops::Deref, time::Duration};

use bytemuck::{AnyBitPattern, NoUninit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;

use crate::{message::*, proto::scheme};

pub use scheme::{EncryptionError, EncryptionScheme};

/// Default encryption scheme
pub type Scheme = scheme::aead::AeadX25519Builder<ChaCha20Poly1305>;

/// Provides access to parts of a decrypted message.
pub struct DecryptedMessage<'m, T: AnyBitPattern + NoUninit> {
    data: &'m [u8],        // additional data
    body: &'m mut T,       // message payload (fixed-size portion)
    trailer: &'m mut [u8], // message trailer (variable-size portion)
}

impl<T: AnyBitPattern + NoUninit> DecryptedMessage<'_, T> {
    /// Return a reference to fixed-size portion of the message.
    pub fn body(&self) -> &T {
        self.body
    }

    /// Return a reference to a variable-size portion of the message.
    pub fn trailer(&self) -> &[u8] {
        self.trailer
    }

    /// Return an additional data.
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

impl<S> EncryptedMessage for S where S: EncryptionScheme {}

/// A wrapper for a message of type T with support for in-place
/// encryption/decryption with additional data.
///
/// Format of encrypted message:
///
/// [ msg-header | additional-data | payload | trailer | message-footer ]
///
/// `payload | trailer` are encrypted.
///
/// `trailer` is a variable-size portion of the message.
///
/// `payload` is the external representation of `T`.
///
pub trait EncryptedMessage: EncryptionScheme {
    /// Decrypt message and return references to the payload, trailer
    /// and additional data bytes.
    fn decrypt<'msg, T>(
        &self,
        buffer: &'msg mut [u8],
        additional_data: usize,
        sender: usize,
    ) -> Option<DecryptedMessage<'msg, T>>
    where
        T: AnyBitPattern + NoUninit,
    {
        let t_size: usize = core::mem::size_of::<T>();

        let ad_len = additional_data.checked_add(MESSAGE_HEADER_SIZE)?;

        let (associated_data, body) = buffer.split_at_mut_checked(ad_len)?;

        let plaintext =
            self.decrypt_message(associated_data, body, sender).ok()?;

        if t_size > plaintext.len() {
            // if decrypted plaintext is too small then zeroize
            // it. The following split will fail and return None.
            plaintext.zeroize();
            return None;
        }

        let (msg, trailer) = plaintext.split_at_mut_checked(t_size)?;

        Some(DecryptedMessage {
            data: &associated_data[MESSAGE_HEADER_SIZE..],
            body: bytemuck::from_bytes_mut(msg),
            trailer,
        })
    }
}

///
pub trait MessageKey: Sized {
    /// Size of message footer.
    fn message_footer(&self) -> usize;

    /// Encrypts the provided data buffer. The message footer located
    /// at the end of the buffer.
    ///
    /// # Parameters
    ///
    /// - `associated_data`: A byte slice containing additional
    ///   authenticated data (AAD) that will be used to ensure the
    ///   integrity and authenticity of the encrypted data. This data is
    ///   not encrypted but is included in the integrity check.
    ///
    /// - `buffer`: A mutable byte slice containing the plaintext data
    ///   that will be encrypted in place. Upon successful encryption,
    ///   this buffer will contain the ciphertext data.
    ///
    /// # Errors
    ///
    ///   `EncryptionError` if issues arise incorrect buffer lengths,
    ///   or any other problems during the encryption process. The
    ///   error provides specific details about the nature of the
    ///   failure.
    ///
    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError>;

    /// Construct a message builder, specifying the additional data
    /// and trailer size.
    fn message<T>(
        self,
        ad: Option<&[u8]>,
        trailer: usize,
    ) -> MessageBuilder<T, Self>
    where
        T: AnyBitPattern + NoUninit,
    {
        let additional_data = ad.unwrap_or(&[]).len();
        let size = MESSAGE_HEADER_SIZE
            + additional_data
            + core::mem::size_of::<T>()
            + trailer
            + self.message_footer();

        let mut buffer = vec![0; size];

        if let Some(ad) = ad {
            buffer[MESSAGE_HEADER_SIZE..][..ad.len()].copy_from_slice(ad);
        }

        MessageBuilder {
            key: self,
            buffer,
            trailer,
            additional_data,
            marker: PhantomData,
        }
    }
}

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
    K: MessageKey,
{
    const T_SIZE: usize = core::mem::size_of::<T>();

    pub fn with_header(
        mut self,
        id: &MsgId,
        ttl: Duration,
        flags: u16,
    ) -> Self {
        if let Some(hdr) =
            self.buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>()
        {
            MsgHdr::encode(hdr, id, ttl, flags);
        }

        self
    }

    pub fn with_body<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let msg = &mut self.buffer
            [MESSAGE_HEADER_SIZE + self.additional_data..][..Self::T_SIZE];

        f(bytemuck::from_bytes_mut(msg));

        self
    }

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

    pub fn encrypt(self) -> Option<Bytes> {
        let mut buffer = self.buffer;

        let (associated_data, plaintext) = buffer.split_at_mut_checked(
            MESSAGE_HEADER_SIZE + self.additional_data,
        )?;

        self.key.encrypt(associated_data, plaintext).ok()?;

        Some(Bytes::from(buffer))
    }

    /// Return a mutable references to message payload object and trailer.
    pub fn payload(&mut self) -> (&mut T, &mut [u8]) {
        let tag_offset = self.buffer.len() - self.key.message_footer();

        // body = hdr | ad | payload | trailer | overhead
        let body = &mut self.buffer
            [MESSAGE_HEADER_SIZE + self.additional_data..tag_offset];

        let (msg, trailer) = body.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::proto::scheme::{
        EncryptionSchemeBuilder, passthrough::PassThroughEncryptionBuilder,
    };

    use super::*;

    fn enc_dec<S: EncryptionSchemeBuilder>(mut s: S, mut r: S) {
        let msg_id = MsgId::from([1; 32]);
        let ttl = Duration::from_secs(10);

        s.receiver_public_key(1, r.public_key()).unwrap();
        r.receiver_public_key(0, s.public_key()).unwrap();

        let mut s = s.build();
        let r = r.build();

        let body = [2u8; 32];
        let ad = [3u8; 23];

        let msg = s
            .encryption_key(1)
            .unwrap()
            .message::<[u8; 32]>(Some(&ad), 0)
            .with_header(&msg_id, ttl, 0)
            .with_body(|b| b.copy_from_slice(&body))
            .encrypt()
            .unwrap();

        let mut msg = BytesMut::from(msg);

        let m = r.decrypt::<[u8; 32]>(&mut msg, ad.len(), 0).unwrap();

        assert_eq!(&*m, &body);
    }

    #[test]
    fn def_scheme() {
        let mut rng = rand::thread_rng();
        let sender = Scheme::new(&mut rng);
        let receiver = Scheme::new(&mut rng);

        enc_dec(sender, receiver);
    }

    #[test]
    fn identity_scheme() {
        let sender = PassThroughEncryptionBuilder;
        let receiver = PassThroughEncryptionBuilder;

        enc_dec(sender, receiver);
    }
}
