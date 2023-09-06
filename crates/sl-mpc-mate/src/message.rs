//! This module provides implementation of data structures to handle
//! message passing between parties of a MPC protocol.
//!
//! To create a new message use [Builder].
use std::borrow::Borrow;
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Add, Deref, DerefMut, Mul};
use std::time::Duration;

use aead::{
    consts::U10,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    AeadCore, AeadInPlace, KeyInit, Nonce, Tag,
};

use bincode::{
    de::{
        read::{BorrowReader, Reader, SliceReader},
        BorrowDecode, BorrowDecoder, Decoder,
    },
    enc::{
        write::{SliceWriter, Writer},
        Encoder,
    },
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

use chacha20::hchacha;
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use ed25519_dalek::{Signature, Signer, Verifier};
use elliptic_curve::{
    group::GroupEncoding, CurveArithmetic, FieldBytes, NonZeroScalar,
    PrimeField,
};
use sha2::Sha256;

pub use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
pub use x25519_dalek::{PublicKey, ReusableSecret};

use crate::ByteArray;

type Aead = ChaCha20Poly1305;

pub const MESSAGE_ID_SIZE: usize = 32;
pub const MESSAGE_HEADER_SIZE: usize = MESSAGE_ID_SIZE + 4;

pub const TAG_SIZE: usize = <Aead as AeadCore>::TagSize::USIZE;
pub const NONCE_SIZE: usize = <Aead as AeadCore>::NonceSize::USIZE;

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

    /// Other party's public key is identiry point
    EncPublicKey,

    /// Message decryption failed
    InvalidTag,

    ///
    DecodeError,

    /// Missing expected message
    RecvError,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct InstanceId([u8; 32]);

impl From<[u8; 32]> for InstanceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MessageTag(u64);

impl MessageTag {
    pub const fn tag(tag: u64) -> Self {
        Self(tag)
    }

    pub const fn tag1(tag: u32, param: u32) -> Self {
        Self(tag as u64 | param as u64 >> 32)
    }

    pub const fn tag2(tag: u32, param1: u16, param2: u16) -> Self {
        Self(tag as u64 | param1 as u64 >> 32 | param2 as u64 >> 48)
    }

    pub const fn to_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

#[derive(PartialEq, Clone, Copy, Hash, PartialOrd, Eq)]
pub struct MsgId([u8; MESSAGE_ID_SIZE]);

impl Borrow<[u8]> for MsgId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MsgId({self:X})")
    }
}

impl fmt::UpperHex for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl fmt::LowerHex for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl MsgId {
    pub const ZERO_ID: MsgId = MsgId([0; MESSAGE_ID_SIZE]);

    /// Create ID for a P2P message.
    pub fn new(
        instance: &InstanceId,
        sender_pk: &[u8; PUBLIC_KEY_LENGTH],
        receiver_pk: Option<&[u8; PUBLIC_KEY_LENGTH]>,
        tag: MessageTag,
    ) -> Self {
        Self(
            Sha256::new()
                .chain_update(tag.to_bytes())
                .chain_update(sender_pk)
                .chain_update(receiver_pk.unwrap_or(&[0; PUBLIC_KEY_LENGTH]))
                .chain_update(instance.0)
                .finalize()
                .into(),
        )
    }

    /// Create ID for a broadcast message, without a designated receiver.
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

#[derive(Debug, Eq, Copy, Clone, PartialEq)]
pub enum Kind {
    Ask,
    Pub,
}

pub struct MsgHdr {
    pub id: MsgId,
    pub ttl: Duration,
    pub kind: Kind,
}

impl fmt::Debug for MsgHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MsgHdr(id: {:X}, ttl: {}, kind: {:?})",
            self.id,
            self.ttl.as_secs(),
            self.kind
        )
    }
}

// FIXME convert to TryFrom<&[u8]> ?
impl MsgHdr {
    pub fn from(msg: &[u8]) -> Option<Self> {
        if msg.len() >= MESSAGE_HEADER_SIZE {
            let (hdr, body) = msg.split_at(MESSAGE_HEADER_SIZE);

            let body_len = body.len();
            // FIXME: implicit assumption that Signature::BYTES
            //    > TAG_SIZE + NONCE_SIZE
            if body_len > 0 && body_len <= TAG_SIZE + NONCE_SIZE {
                return None;
            }

            let ttl = Duration::new(
                u32::from_le_bytes(hdr[MESSAGE_ID_SIZE..].try_into().unwrap())
                    as u64,
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

/// Builder of a message.
#[derive(Debug)]
pub struct Builder<K> {
    buffer: Vec<u8>,
    kind: PhantomData<K>,
}

/// Counter to create a unuque nonce.
#[derive(Default)]
pub struct NonceCounter(u32);

impl NonceCounter {
    /// New counter initialize by 0.
    pub fn new() -> Self {
        Self(0)
    }

    /// Increment counter.
    pub fn next_nonce(&mut self) -> Self {
        self.0 = self.0.wrapping_add(1);
        Self(self.0)
    }

    // Consume counter and create a nonce. This way
    // we can't create two equal nonces from the same counter.
    //
    // This is private method and should be called
    // from encrypt() to avoid using generated nonce
    // more than once.
    fn nonce(self) -> Nonce<Aead> {
        let mut nonce = Nonce::<Aead>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

pub trait UnderConstruction {
    fn writer(&mut self) -> SliceWriter;

    fn encode<T: Encode>(&mut self, value: &T) -> Result<(), EncodeError> {
        let mut writer = self.writer();
        let config = bincode::config::standard();

        bincode::encode_into_writer(value, &mut writer, config)
    }
}

pub trait IntoPayloadSize {
    fn payload_size(&self) -> usize;
}

impl IntoPayloadSize for usize {
    fn payload_size(&self) -> usize {
        *self
    }
}

impl<D: Encode> IntoPayloadSize for &D {
    fn payload_size(&self) -> usize {
        let mut encoder = bincode::enc::EncoderImpl::new(
            bincode::enc::write::SizeWriter::default(),
            bincode::config::standard(),
        );

        self.encode(&mut encoder)
            .expect("cant measure size of message");

        encoder.into_writer().bytes_written
    }
}

impl Builder<Signed> {
    /// Allocate a Signed (usually broadcast) message.
    pub fn allocate(
        id: &MsgId,
        ttl: u32,
        payload: impl IntoPayloadSize,
    ) -> Builder<Signed> {
        Self::allocate_inner(
            id,
            ttl,
            payload.payload_size(),
            Signature::BYTE_SIZE,
        )
    }

    /// Sign the message with passed signing_key, consume builder
    /// and return underlying buffer.
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

    /// Helper method to allocate, encode and sign a message.
    pub fn encode<E: Encode>(
        msg_id: &MsgId,
        ttl: Duration,
        signing_key: &SigningKey,
        msg: &E,
    ) -> Result<Vec<u8>, InvalidMessage> {
        let mut buf = Self::allocate(msg_id, ttl.as_secs() as u32, msg);
        buf.encode(msg).map_err(|_| InvalidMessage::DecodeError)?;
        buf.sign(signing_key)
    }
}

impl UnderConstruction for Builder<Signed> {
    fn writer(&mut self) -> SliceWriter {
        let last = self.buffer.len() - Signature::BYTE_SIZE;
        SliceWriter::new(&mut self.buffer[MESSAGE_HEADER_SIZE..last])
    }
}

impl Builder<Encrypted> {
    /// Allocate a builder of an encrypted (usually P2P) message.
    pub fn allocate(
        id: &MsgId,
        ttl: u32,
        payload: impl IntoPayloadSize,
    ) -> Builder<Encrypted> {
        Self::allocate_inner(
            id,
            ttl,
            payload.payload_size(),
            TAG_SIZE + NONCE_SIZE,
        )
    }

    /// Encrypt message.
    pub fn encrypt(
        self,
        start: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
        counter: NonceCounter,
    ) -> Result<Vec<u8>, InvalidMessage> {
        let Self {
            mut buffer,
            kind: _,
        } = self;

        let last = buffer.len() - (TAG_SIZE + NONCE_SIZE);
        let (msg, tail) = buffer.split_at_mut(last);

        // TODO Review key generation!!!
        let shared_secret = secret.diffie_hellman(public_key);

        if !shared_secret.was_contributory() {
            return Err(InvalidMessage::EncPublicKey);
        }

        let key = hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        );

        let cipher = Aead::new(&key);

        let (data, plaintext) = msg.split_at_mut(start);

        let nonce = counter.nonce();

        let tag = cipher
            .encrypt_in_place_detached(&nonce, data, plaintext)
            .map_err(|_| InvalidMessage::BufferTooShort)?;

        tail[..TAG_SIZE].copy_from_slice(&tag);
        tail[TAG_SIZE..].copy_from_slice(&nonce);

        Ok(buffer)
    }

    /// Create encrypted message
    pub fn encode<E: Encode>(
        msg_id: &MsgId,
        ttl: Duration,
        secret: &ReusableSecret,
        public_key: &PublicKey,
        msg: &E,
        counter: NonceCounter,
    ) -> Result<Vec<u8>, InvalidMessage> {
        let mut buf = Self::allocate(msg_id, ttl.as_secs() as u32, msg);
        buf.encode(msg).map_err(|_| InvalidMessage::DecodeError)?;
        buf.encrypt(MESSAGE_HEADER_SIZE, secret, public_key, counter)
    }
}

impl UnderConstruction for Builder<Encrypted> {
    fn writer(&mut self) -> SliceWriter {
        let last = self.buffer.len() - (TAG_SIZE + NONCE_SIZE);
        SliceWriter::new(&mut self.buffer[MESSAGE_HEADER_SIZE..last])
    }
}

impl<K> Builder<K> {
    // internal constructor, common method for Signed and Encrypted messages.
    fn allocate_inner(
        id: &MsgId,
        ttl: u32,
        payload: usize,
        trailer: usize,
    ) -> Self {
        let mut buffer = vec![0u8; MESSAGE_HEADER_SIZE + payload + trailer];

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
    pub const HDR_SIZE: usize = MESSAGE_HEADER_SIZE;
    pub const SIGN_SIZE: usize = Signature::BYTE_SIZE;

    pub fn from_buffer(buffer: &'a mut [u8]) -> Result<Self, InvalidMessage> {
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
        let (msg, sign) =
            self.buffer.split_at(self.buffer.len() - Self::SIGN_SIZE);
        let sign = Signature::from_slice(sign)
            .map_err(|_| InvalidMessage::InvalidSignature)?;

        verify_key
            .verify(msg, &sign)
            .map_err(|_| InvalidMessage::InvalidSignature)?;

        Ok(SliceReader::new(&self.buffer[Self::HDR_SIZE..]))
    }

    /// Helper method to serify message signature and decode payload.
    pub fn verify_and_decode<D: Decode>(
        self,
        verify_key: &VerifyingKey,
    ) -> Result<D, InvalidMessage> {
        let reader = self.verify(verify_key)?;

        MessageReader::decode(reader).map_err(|_| InvalidMessage::DecodeError)
    }

    /// The same as verify_and_decode() but decodes using borrow decoder.
    pub fn verify_and_borrow_decode<'de, D: BorrowDecode<'de>>(
        &'de self,
        verify_key: &VerifyingKey,
    ) -> Result<D, InvalidMessage> {
        let reader = self.verify(verify_key)?;

        MessageReader::borrow_decode(reader)
            .map_err(|_| InvalidMessage::DecodeError)
    }

    /// Decrypt message and return payload reader.
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

        let tag = Tag::<Aead>::from_slice(&tail[..TAG_SIZE]);
        let nonce = Nonce::<Aead>::from_slice(&tail[TAG_SIZE..]);

        // TODO Review key generation!!!
        let shared_secret = secret.diffie_hellman(public_key);

        let key = hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        );

        let cipher = Aead::new(&key);

        cipher
            .decrypt_in_place_detached(nonce, data, ciphertext, tag)
            .map_err(|_| InvalidMessage::InvalidTag)?;

        Ok(SliceReader::new(ciphertext))
    }

    /// Helper method to decrypt and decode message.
    pub fn decrypt_and_decode<D: Decode>(
        &mut self,
        start: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Result<D, InvalidMessage> {
        let reader = self.decrypt(start, secret, public_key)?;

        MessageReader::decode(reader).map_err(|_| InvalidMessage::DecodeError)
    }

    /// The same as decrypt_and_decode() but using a borrow decoder.
    pub fn decrypt_and_borrow_decode<'de, D: BorrowDecode<'de>>(
        &'de mut self,
        start: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Result<D, InvalidMessage> {
        let reader = self.decrypt(start, secret, public_key)?;

        MessageReader::borrow_decode(reader)
            .map_err(|_| InvalidMessage::DecodeError)
    }
}

pub struct MessageReader;

impl MessageReader {
    pub fn borrow_decode<'de, D, R>(src: R) -> Result<D, DecodeError>
    where
        R: BorrowReader<'de>,
        D: bincode::de::BorrowDecode<'de>,
    {
        let mut decoder =
            bincode::de::DecoderImpl::new(src, bincode::config::standard());
        D::borrow_decode(&mut decoder)
    }

    pub fn decode<D, R>(src: R) -> Result<D, DecodeError>
    where
        R: Reader,
        D: bincode::de::Decode,
    {
        let mut decoder =
            bincode::de::DecoderImpl::new(src, bincode::config::standard());
        D::decode(&mut decoder)
    }
}

// TODO move to a separate module.

/// Wrapper to provide bincode serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opaque<T, K = ()>(pub T, pub PhantomData<K>);

impl<K, R, T: Mul<R>> Mul<R> for Opaque<T, K> {
    type Output = T::Output;

    fn mul(self, rhs: R) -> T::Output {
        self.0.mul(rhs)
    }
}

impl<K, R, T: Add<R>> Add<R> for Opaque<T, K> {
    type Output = T::Output;

    fn add(self, rhs: R) -> T::Output {
        self.0.add(rhs)
    }
}

impl<T, K> Opaque<T, K> {
    pub fn from_inner<F: From<T>>(self) -> F {
        F::from(self.0)
    }
}

impl<T, K> From<T> for Opaque<T, K> {
    fn from(v: T) -> Self {
        Self(v, PhantomData)
    }
}

impl<T, K> Deref for Opaque<T, K> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, K> DerefMut for Opaque<T, K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<U: ArrayLength<u8>> Encode for Opaque<GenericArray<u8, U>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<U: ArrayLength<u8>> Decode for Opaque<GenericArray<u8, U>> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = GenericArray::default();

        decoder.claim_bytes_read(U::USIZE)?;
        decoder.reader().read(array.as_mut())?;

        Ok(Opaque(array, PhantomData))
    }
}

impl<const N: usize> Encode for Opaque<[u8; N]> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<const N: usize> Decode for Opaque<[u8; N]> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = [0; N];

        decoder.claim_bytes_read(N)?;
        decoder.reader().read(&mut array)?;

        Ok(Opaque(array, PhantomData))
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<[u8; N]> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<const N: usize> Encode for Opaque<&[u8; N]> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<&'de [u8; N]> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(N)?;

        Ok(Opaque(
            unsafe { &*(array.as_ptr() as *const [u8; N]) },
            PhantomData,
        ))
    }
}

impl<const N: usize> Encode for Opaque<ByteArray<N>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<const N: usize> Encode for Opaque<&ByteArray<N>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<const N: usize> Decode for Opaque<ByteArray<N>> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = [0; N];

        decoder.claim_bytes_read(N)?;
        decoder.reader().read(&mut array)?;

        Ok(Opaque(ByteArray(array), PhantomData))
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<ByteArray<N>> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<&'de ByteArray<N>> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(N)?;

        Ok(Opaque(
            unsafe { &*(array.as_ptr() as *const ByteArray<N>) },
            PhantomData,
        ))
    }
}

impl<U: ArrayLength<u8>> Encode for Opaque<&GenericArray<u8, U>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<'de, U: ArrayLength<u8>> BorrowDecode<'de>
    for Opaque<&'de GenericArray<u8, U>>
{
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(U::USIZE)?;

        Ok(Opaque(array.into(), PhantomData))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GR;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PFR;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NZ;

impl<T: GroupEncoding> Encode for Opaque<T, GR> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_bytes().as_ref())
    }
}

impl<T: PrimeField> Encode for Opaque<T, PF> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_repr().as_ref())
    }
}

impl<T: PrimeField> Encode for Opaque<&T, PFR> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_repr().as_ref())
    }
}

impl<C: CurveArithmetic> Encode for Opaque<NonZeroScalar<C>, NZ> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.as_ref().to_repr().as_ref())
    }
}

impl<T: GroupEncoding> Decode for Opaque<T, GR> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = T::Repr::default();

        decoder.reader().read(array.as_mut())?;

        let value = T::from_bytes(&array);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<T: PrimeField> Decode for Opaque<T, PF> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = T::Repr::default();

        decoder.reader().read(array.as_mut())?;

        let value = T::from_repr(array);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<C: CurveArithmetic> Decode for Opaque<NonZeroScalar<C>, NZ> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = FieldBytes::<C>::default();

        decoder.reader().read(array.as_mut())?;

        let value = C::Scalar::from_repr(array).and_then(NonZeroScalar::new);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<'de, T: GroupEncoding> BorrowDecode<'de> for Opaque<T, GR> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, T: PrimeField> BorrowDecode<'de> for Opaque<T, PF> {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, C: CurveArithmetic> BorrowDecode<'de>
    for Opaque<NonZeroScalar<C>, NZ>
{
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

#[cfg(test)]
mod tests {
    use crate::SessionId;

    use super::*;

    #[test]
    fn opaque_into() {
        let buf = [0u8; 32];

        let o1: Opaque<&[u8; 32]> = Opaque::from(&buf);

        let o2: Opaque<[u8; 32]> = Opaque::from([0u8; 32]);

        let s1: SessionId = o1.from_inner();
        let s2: SessionId = o2.from_inner();

        assert_eq!(s1, s2);
    }

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

    #[test]
    fn encrypt_message() {
        let mut rng = rand::thread_rng();

        let inst = InstanceId::from(rand::random::<[u8; 32]>());

        let sk1 = SigningKey::from_bytes(&rand::random());
        let vk1 = sk1.verifying_key();
        let en1 = ReusableSecret::random_from_rng(&mut rng);
        let pk1 = PublicKey::from(&en1);

        let sk2 = SigningKey::from_bytes(&rand::random());
        let vk2 = sk2.verifying_key();

        let en2 = ReusableSecret::random_from_rng(&mut rng);
        let pk2 = PublicKey::from(&en2);

        let msg_id = MsgId::new(
            &inst,
            vk1.as_bytes(),
            Some(vk2.as_bytes()),
            MessageTag::tag(1),
        );

        let mut nonce = NonceCounter::new();

        let mut msg = Builder::<Encrypted>::encode(
            &msg_id,
            Duration::new(10, 0),
            &en1,
            &pk2,
            &(1u32, 2u64),
            nonce.next_nonce(),
        )
        .unwrap();

        let mut msg = Message::from_buffer(&mut msg).unwrap();

        let data: (u32, u64) = msg
            .decrypt_and_decode(MESSAGE_HEADER_SIZE, &en2, &pk1)
            .unwrap();

        assert_eq!(data, (1u32, 2u64));
    }
}
