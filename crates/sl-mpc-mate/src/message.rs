//! This module provides implementation of data structures to handle
//! message passing between parties of a MPC protocol.
//!
//! To create a new message use [Builder].
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::time::Duration;

use aead::{
    consts::U10,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    AeadCore,
    AeadInPlace,
    KeyInit,
    Nonce,
    Tag,
};
use bincode::{
    de::{
        read::{BorrowReader, Reader, SliceReader},
        Decoder,
    },
    enc::{
        write::{SliceWriter, Writer},
        Encoder,
    },
    error::{DecodeError, EncodeError},
    Encode,
};

use chacha20::hchacha;
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use ed25519_dalek::{Signature, Signer, Verifier};
use elliptic_curve::group::GroupEncoding;
use sha2::Sha256;

pub use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
pub use x25519_dalek::{PublicKey, ReusableSecret};

type AEAD = ChaCha20Poly1305;

pub const MESSAGE_ID_SIZE: usize = 32;
pub const MESSAGE_HEADER_SIZE: usize = MESSAGE_ID_SIZE + 4;

pub const TAG_SIZE: usize = <AEAD as AeadCore>::TagSize::USIZE;
pub const NONCE_SIZE: usize = <AEAD as AeadCore>::NonceSize::USIZE;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum InvalidMessage {
    /// A buffer is too short for new content
    BufferTooShort,

    /// We are trying to read more data than available
    MessageTooShort,

    ///
    MissingData(&'static str),

    /// Message payload is allocate but not filled with data
    MissingPayload,

    /// Message signature verification failed
    InvalidSignature,

    ///  Message decryption failed
    InvalidTag,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct InstanceId([u8; 32]);

impl From<[u8; 32]> for InstanceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
pub struct MessageTag(pub(crate) u64);

impl MessageTag {
    pub fn tag(tag: u64) -> Self {
        Self(tag)
    }

    pub fn tag1(tag: u32, param: u32) -> Self {
        Self(tag as u64 | param as u64 >> 32)
    }

    pub fn tag2(tag: u32, param1: u16, param2: u16) -> Self {
        Self(tag as u64 | param1 as u64 >> 32 | param2 as u64 >> 48)
    }

    pub fn to_le_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Hash, PartialOrd, Eq)]
pub struct MsgId([u8; MESSAGE_ID_SIZE]);

impl Borrow<[u8]> for MsgId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl MsgId {
    pub const ZERO_ID: MsgId = MsgId([0; MESSAGE_ID_SIZE]);

    pub fn new(
        instance: &InstanceId,
        sender_pk: &[u8; PUBLIC_KEY_LENGTH],
        receiver_pk: Option<&[u8; PUBLIC_KEY_LENGTH]>,
        tag: MessageTag,
    ) -> Self {
        Self(
            Sha256::new()
                .chain_update(tag.to_le_bytes())
                .chain_update(sender_pk)
                .chain_update(
                    receiver_pk.unwrap_or(&[0; PUBLIC_KEY_LENGTH]),
                )
                .chain_update(&instance.0)
                .finalize()
                .into(),
        )
    }

    pub fn broadcast(
        instance: &InstanceId,
        sender_pk: &[u8; PUBLIC_KEY_LENGTH],
        tag: MessageTag,
    ) -> Self {
        Self::new(instance, sender_pk, None, tag)
    }
}

impl From<[u8; MESSAGE_ID_SIZE]> for MsgId {
    fn from(id: [u8; MESSAGE_ID_SIZE]) -> Self {
        Self(id)
    }
}

pub enum Kind {
    Ask,
    Pub,
}

pub struct MsgHdr {
    pub id: MsgId,
    pub ttl: Duration,
    pub kind: Kind,
}

impl MsgHdr {
    pub fn from(msg: &[u8]) -> Option<Self> {
        if msg.len() >= MESSAGE_HEADER_SIZE {
            let (hdr, body) = msg.split_at(MESSAGE_HEADER_SIZE);

            let body_len = body.len();
            // FIXME: implicit assumption that Signature::BYTES > TAG_SIZE + NONCE_SIZE
            if body_len > 0 && body_len <= TAG_SIZE + NONCE_SIZE {
                return None;
            }

            let ttl = Duration::new(
                u32::from_le_bytes(
                    hdr[MESSAGE_ID_SIZE..].try_into().unwrap(),
                ) as u64,
                0,
            );

            Some(Self {
                id: MsgId(hdr[..MESSAGE_ID_SIZE].try_into().unwrap()),
                ttl,
                kind: if body_len == 0 { Kind::Ask } else { Kind::Pub },
            })
        } else {
            None
        }
    }
}

pub struct AskMsg;

impl AskMsg {
    pub fn allocate(id: &MsgId, ttl: u32) -> Vec<u8> {
        Builder::<Signed>::allocate_inner(id, ttl, 0, 0).buffer
    }
}

/// Marker for a signed message
#[derive(Debug)]
pub struct Signed;

/// Marker for an encrypted message
#[derive(Debug)]
pub struct Encrypted;

#[derive(Debug)]
pub struct Builder<K> {
    buffer: Vec<u8>,
    kind: PhantomData<K>,
}

pub trait UnderConstruction {
    fn writer(&mut self) -> SliceWriter;

    fn encode<T: Encode>(
        &mut self,
        value: &T,
    ) -> Result<(), EncodeError> {
        let mut writer = self.writer();
        let config = bincode::config::standard();

        bincode::encode_into_writer(value, &mut writer, config)
    }
}

impl Builder<Signed> {
    pub fn allocate(
        id: &MsgId,
        ttl: u32,
        payload: usize,
    ) -> Builder<Signed> {
        Self::allocate_inner(id, ttl, payload, Signature::BYTE_SIZE)
    }

    /// Sign the message with passed signing_key return underlying buffer.
    pub fn sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>, InvalidMessage> {
        let Self {
            mut buffer,
            kind: _,
        } = self;

        let last = buffer.len() - Signature::BYTE_SIZE;
        let (msg, tail) = buffer.split_at_mut(last);

        let sign = signing_key.sign(msg);

        tail.copy_from_slice(&sign.to_bytes());

        Ok(buffer)
    }
}

impl UnderConstruction for Builder<Signed> {
    fn writer(&mut self) -> SliceWriter {
        let last = self.buffer.len() - Signature::BYTE_SIZE;
        SliceWriter::new(&mut self.buffer[MESSAGE_HEADER_SIZE..last])
    }
}

impl Builder<Encrypted> {
    pub fn allocate(
        id: &MsgId,
        ttl: u32,
        payload: usize,
    ) -> Builder<Encrypted> {
        Self::allocate_inner(id, ttl, payload, TAG_SIZE + NONCE_SIZE)
    }

    pub fn encrypt(
        self,
        start: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Result<Vec<u8>, InvalidMessage> {
        let Self {
            mut buffer,
            kind: _,
        } = self;

        let last = buffer.len() - (TAG_SIZE + NONCE_SIZE);
        let (msg, tail) = buffer.split_at_mut(last);

        let shared_secret = secret.diffie_hellman(public_key);

        let key = hchacha::<U10>(
            &shared_secret.to_bytes().into(),
            &GenericArray::default(),
        );

        let cipher = AEAD::new(&key);

        let (data, plaintext) = msg.split_at_mut(start);

        let nonce = Nonce::<AEAD>::default(); // FIXME(arm) random!!!

        let tag = cipher
            .encrypt_in_place_detached(&nonce, data, plaintext)
            .map_err(|_| InvalidMessage::BufferTooShort)?;

        tail[..TAG_SIZE].copy_from_slice(&tag);
        tail[TAG_SIZE..].copy_from_slice(&nonce);

        Ok(buffer)
    }
}

impl UnderConstruction for Builder<Encrypted> {
    fn writer(&mut self) -> SliceWriter {
        let last = self.buffer.len() - (TAG_SIZE + NONCE_SIZE);
        SliceWriter::new(&mut self.buffer[MESSAGE_HEADER_SIZE..last])
    }
}

impl<K> Builder<K> {
    // internal constructor
    fn allocate_inner(
        id: &MsgId,
        ttl: u32,
        payload: usize,
        trailer: usize,
    ) -> Self {
        let mut buffer =
            vec![0u8; MESSAGE_HEADER_SIZE + payload + trailer];

        buffer[..MESSAGE_ID_SIZE].copy_from_slice(&id.0);
        buffer[MESSAGE_ID_SIZE..MESSAGE_ID_SIZE + 4]
            .copy_from_slice(&ttl.to_le_bytes());

        Self {
            buffer,
            kind: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct Message<'a> {
    buffer: &'a mut [u8],
}

impl<'a> Message<'a> {
    pub fn from_buffer(
        buffer: &'a mut [u8],
    ) -> Result<Self, InvalidMessage> {
        if buffer.len() < MESSAGE_HEADER_SIZE {
            return Err(InvalidMessage::BufferTooShort);
        }

        Ok(Self { buffer })
    }

    pub fn id(&self) -> MsgId {
        let id = &self.buffer[..MESSAGE_ID_SIZE];

        MsgId(id.try_into().unwrap())
    }

    /// Verify a signature at end of the message using passed verify_key.
    pub fn verify(
        &self,
        verify_key: &VerifyingKey,
    ) -> Result<SliceReader, InvalidMessage> {
        let (msg, sign) = self
            .buffer
            .split_at(self.buffer.len() - Signature::BYTE_SIZE);
        let sign = Signature::from_slice(sign)
            .map_err(|_| InvalidMessage::InvalidSignature)?;

        verify_key
            .verify(msg, &sign)
            .map_err(|_| InvalidMessage::InvalidSignature)?;

        Ok(SliceReader::new(&self.buffer[MESSAGE_HEADER_SIZE..]))
    }

    pub fn decrypt(
        &mut self,
        start: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Result<SliceReader, InvalidMessage> {
        let (data, rest) = self.buffer.split_at_mut(start);

        if rest.len() <= TAG_SIZE + NONCE_SIZE {
            return Err(InvalidMessage::MessageTooShort);
        }

        let (ciphertext, tail) =
            rest.split_at_mut(rest.len() - TAG_SIZE - NONCE_SIZE);

        let tag = Tag::<AEAD>::from_slice(&tail[..TAG_SIZE]);
        let nonce = Nonce::<AEAD>::from_slice(&tail[TAG_SIZE..]);

        let shared_secret = secret.diffie_hellman(public_key);

        let key = hchacha::<U10>(
            &shared_secret.to_bytes().into(),
            &GenericArray::default(),
        );

        let cipher = AEAD::new(&key);

        cipher
            .decrypt_in_place_detached(&nonce, data, ciphertext, &tag)
            .map_err(|_| InvalidMessage::InvalidTag)?;

        Ok(SliceReader::new(ciphertext))
    }
}

pub struct MessageReader;

impl MessageReader {
    pub fn borrow_decode<'de, D, R>(src: R) -> Result<D, DecodeError>
    where
        R: BorrowReader<'de>,
        D: bincode::de::BorrowDecode<'de>,
    {
        let mut decoder = bincode::de::DecoderImpl::new(
            src,
            bincode::config::standard(),
        );
        D::borrow_decode(&mut decoder)
    }
}

pub struct EncodeWrapper<T>(pub T);

pub trait Encodable {
    fn encode<E: Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), EncodeError>;
}

impl<T: GroupEncoding> Encodable for EncodeWrapper<T> {
    fn encode<E: Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_bytes().as_ref())
    }
}

pub struct FixedArray<U: ArrayLength<u8>>(pub GenericArray<u8, U>);

impl<U: ArrayLength<u8>> From<GenericArray<u8, U>> for FixedArray<U> {
    fn from(data: GenericArray<u8, U>) -> Self {
        Self(data)
    }
}

impl<U: ArrayLength<u8>> FixedArray<U> {
    pub fn encode<E: Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }

    pub fn decode<D: Decoder>(
        decoder: &mut D,
    ) -> Result<GenericArray<u8, U>, DecodeError> {
        let mut array = GenericArray::default();

        decoder.claim_bytes_read(U::USIZE)?;
        decoder.reader().read(array.as_mut())?;

        Ok(array)
    }
}

// pub fn as_array<U: ArrayLength<u8>>(g: GenericArray<u8, U>) -> [u8; U::USIZE] {
// }

// impl<'de> MessageReader<'de> for SliceReader<'de> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_message() {
        let sk = SigningKey::from_bytes(&rand::random());

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(0),
        );

        let mut msg = Builder::<Signed>::allocate(&msg_id, 254, 8);

        msg.encode(&[1u8; 8]).unwrap();

        println!("msg {:?}", msg);

        let mut bytes = msg.sign(&sk).unwrap();

        let msg = Message::from_buffer(&mut bytes[..]).unwrap();

        msg.verify(&sk.verifying_key()).unwrap();

        println!("signed msg {:?}", bytes);
    }
}
