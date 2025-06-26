// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{marker::PhantomData, ops::Deref, time::Duration};

use bytemuck::{AnyBitPattern, NoUninit};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;

use crate::message::*;

pub use crate::proto::scheme::EncryptionScheme;

/// Default encryption scheme
pub type Scheme = crate::proto::scheme::AeadX25519<ChaCha20Poly1305>;

pub struct PlaintextPayload<'m, T: AnyBitPattern + NoUninit> {
    data: &'m [u8],
    body: &'m mut T,
    trailer: &'m mut [u8],
}

impl<T: AnyBitPattern + NoUninit> PlaintextPayload<'_, T> {
    pub fn body(&self) -> &T {
        self.body
    }

    pub fn trailer(&self) -> &[u8] {
        self.trailer
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<T: AnyBitPattern + NoUninit> Deref for PlaintextPayload<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.body
    }
}

impl<T: AnyBitPattern + NoUninit> Drop for PlaintextPayload<'_, T> {
    fn drop(&mut self) {
        bytemuck::bytes_of_mut(self.body).zeroize();
        self.trailer.zeroize();
    }
}

/// A wrapper for a message of type T with support for in-place
/// encryption/decryption with additional data.
///
/// Format of encrypted message:
///
/// [ msg-hdr | additional-data | payload | trailer | tag + nonce ]
///
/// `payload | trailer` are encrypted.
///
/// `trailer` is a variable-sized part of the message.
///
/// `payload` is the external representation of `T`.
///
pub struct EncryptedMessage<T> {
    buffer: Vec<u8>,
    additional_data: usize,
    trailer: usize,
    marker: PhantomData<T>,
}

impl<T: AnyBitPattern + NoUninit> EncryptedMessage<T> {
    const T_SIZE: usize = core::mem::size_of::<T>();

    /// Size of the whole message with additional data and trailer bytes.
    pub fn size(
        ad: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> usize {
        MESSAGE_HEADER_SIZE + ad + Self::T_SIZE + trailer + scheme.overhead()
    }

    /// Allocate EncryptedMessage
    pub fn allocate(
        additional_data: Option<&[u8]>,
        trailer: usize,
        overhead: usize,
    ) -> Self {
        let additional_data = additional_data.unwrap_or_default();

        let buffer_size = MESSAGE_HEADER_SIZE
            + additional_data.len()
            + Self::T_SIZE
            + trailer
            + overhead;

        let mut buffer = vec![0; buffer_size];

        buffer[MESSAGE_HEADER_SIZE..][..additional_data.len()]
            .copy_from_slice(additional_data);

        Self {
            additional_data: additional_data.len(),
            buffer,
            trailer,
            marker: PhantomData,
        }
    }

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

    /// Allocate a message with passed ID and TTL and additional
    /// trailer bytes.
    pub fn new(
        id: &MsgId,
        ttl: Duration,
        flags: u16,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        Self::new_with_ad(id, ttl, flags, 0, trailer, scheme)
    }

    /// Allocate a message with passed ID and TTL and additional data
    /// and trailer bytes.
    pub fn new_with_ad(
        id: &MsgId,
        ttl: Duration,
        flags: u16,
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
    ) -> Self {
        let mut buffer =
            vec![0u8; Self::size(additional_data, trailer, scheme)];

        if let Some(hdr) = buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>() {
            MsgHdr::encode(hdr, id, ttl, flags);
        }

        Self {
            buffer,
            additional_data,
            trailer,
            marker: PhantomData,
        }
    }

    /// Return a mutable references to message payload object, trailer
    /// and additional data byte slices.
    pub fn payload_with_ad(
        &mut self,
        scheme: &dyn EncryptionScheme,
    ) -> (&mut T, &mut [u8], &mut [u8]) {
        let tag_offset = self.buffer.len() - scheme.overhead();

        // body = hdr | ad | payload | trailer | overhead
        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..tag_offset];

        let (additional_data, msg_and_trailer) =
            body.split_at_mut(self.additional_data);

        let (msg, trailer) = msg_and_trailer.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer, additional_data)
    }

    /// Return a mutable reference to message payload object and trailer byte slice.
    pub fn payload(
        &mut self,
        scheme: &dyn EncryptionScheme,
    ) -> (&mut T, &mut [u8]) {
        let (msg, trailer, _) = self.payload_with_ad(scheme);

        (msg, trailer)
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

    /// Encrypt message.
    pub fn encrypt(
        self,
        scheme: &mut dyn EncryptionScheme,
        receiver: usize,
    ) -> Option<Bytes> {
        let mut buffer = self.buffer;

        let last = buffer.len() - scheme.overhead();
        let (msg, tail) = buffer.split_at_mut(last);

        let (associated_data, plaintext) =
            msg.split_at_mut(MESSAGE_HEADER_SIZE + self.additional_data);

        scheme
            .encrypt(associated_data, plaintext, tail, receiver)
            .ok()?;

        Some(Bytes::from(buffer))
    }

    /// Decrypt message and return references to the payload, trailer
    /// and additional data bytes.
    pub fn decrypt_with_ad<'msg>(
        buffer: &'msg mut [u8],
        additional_data: usize,
        trailer: usize,
        scheme: &dyn EncryptionScheme,
        sender: usize,
    ) -> Option<PlaintextPayload<'msg, T>> {
        if buffer.len() != Self::size(additional_data, trailer, scheme) {
            return None;
        }

        let (associated_data, body) =
            buffer.split_at_mut(MESSAGE_HEADER_SIZE + additional_data);

        let (ciphertext, tail) =
            body.split_at_mut(body.len() - scheme.overhead());

        scheme
            .decrypt(associated_data, ciphertext, tail, sender)
            .ok()?;

        let (msg, trailer) = ciphertext.split_at_mut(Self::T_SIZE);

        Some(PlaintextPayload {
            data: &associated_data[MESSAGE_HEADER_SIZE..],
            body: bytemuck::from_bytes_mut(msg),
            trailer,
        })
    }

    /// Decrypte message and return reference to the payload and trailer bytes.
    pub fn decrypt<'msg>(
        buffer: &'msg mut [u8],
        trailer: usize,
        scheme: &dyn EncryptionScheme,
        sender: usize,
    ) -> Option<PlaintextPayload<'msg, T>> {
        Self::decrypt_with_ad(buffer, 0, trailer, scheme, sender)
    }
}
