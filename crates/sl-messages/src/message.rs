// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{fmt, ops::Deref, time::Duration};

use bytemuck::{AnyBitPattern, NoUninit};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MESSAGE_ID_SIZE: usize = 32;
pub const MESSAGE_HEADER_SIZE: usize = MESSAGE_ID_SIZE + 2 + 2;

pub use bytes::{Bytes, BytesMut};

#[derive(Debug, Copy, Clone, PartialEq, Zeroize)]
pub struct InstanceId([u8; 32]);

impl InstanceId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for InstanceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MessageTag([u8; 8]);

impl MessageTag {
    pub const fn tag(tag: u64) -> Self {
        Self(tag.to_le_bytes())
    }

    /// Define a family of tags indexed by some parameter.
    pub const fn tag1(tag: u32, param: u32) -> Self {
        Self::tag(tag as u64 | ((param as u64) << 32))
    }

    /// Define a familty of tags indexed by pair of parameters.
    pub const fn tag2(tag: u32, param1: u16, param2: u16) -> Self {
        Self::tag(
            tag as u64 | ((param1 as u64) << 32) | ((param2 as u64) << 48),
        )
    }

    /// Convert the tag to an array of bytes.
    pub const fn to_bytes(&self) -> [u8; 8] {
        self.0
    }
}

#[derive(
    PartialEq, Clone, Copy, Hash, PartialOrd, Eq, AnyBitPattern, NoUninit,
)]
#[repr(C)]
pub struct MsgId([u8; MESSAGE_ID_SIZE]);

impl Deref for MsgId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
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

    /// Create message ID for given instance id, sender, receiver and
    /// message tag.
    pub fn new(
        instance: &InstanceId,
        sender: &[u8],
        receiver: Option<&[u8]>,
        tag: MessageTag,
    ) -> Self {
        Self(
            Sha256::default()
                .chain_update(tag.to_bytes())
                .chain_update(sender)
                .chain_update(receiver.unwrap_or(&[]))
                .chain_update(instance.0)
                .finalize()
                .into(),
        )
    }

    /// Create message ID for a broadcast message, without a designated receiver.
    pub fn broadcast(
        instance: &InstanceId,
        sender: &[u8],
        tag: MessageTag,
    ) -> Self {
        Self::new(instance, sender, None, tag)
    }

    /// Return as slice of bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; MESSAGE_ID_SIZE]> for MsgId {
    fn from(id: [u8; MESSAGE_ID_SIZE]) -> Self {
        Self(id)
    }
}

// Try to convert a byte slice into a reference to MsgId. It will
// succeed if passed slice is at least MESSAGE_ID_SIZE bytes.
impl<'a> TryFrom<&'a [u8]> for &'a MsgId {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value
            .first_chunk::<MESSAGE_ID_SIZE>()
            .and_then(|id| bytemuck::try_cast_ref(id).ok())
            .ok_or(())
    }
}

// The same as above but return MsgId value.
impl<'a> TryFrom<&'a [u8]> for MsgId {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let msg_id: &MsgId = value.try_into()?;
        Ok(*msg_id)
    }
}

// It is always possible to get MsgId from &MsgHdr
impl From<&MsgHdr> for MsgId {
    fn from(value: &MsgHdr) -> Self {
        *value.id()
    }
}

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct MsgHdr {
    data: [u8; MESSAGE_HEADER_SIZE],
}

impl fmt::Debug for MsgHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MsgHdr(id: {:X}, flags: {:04X}, ttl: {})",
            self.id(),
            self.flags(),
            self.ttl().as_secs(),
        )
    }
}

// Try convert a byte slice into a reference to MsgHdr. It will
// succeed is given slice is at least MESSAGE_HEADER_SIZE bytes.
impl<'a> TryFrom<&'a [u8]> for &'a MsgHdr {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value
            .first_chunk::<MESSAGE_HEADER_SIZE>()
            .and_then(|hdr| bytemuck::try_cast_ref(hdr).ok())
            .ok_or(())
    }
}

// The same above but tries to convert into MsgHdr value.
impl<'a> TryFrom<&'a [u8]> for MsgHdr {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let hdr: &MsgHdr = value.try_into()?;
        Ok(*hdr)
    }
}

impl MsgHdr {
    pub const MAX_TTL: u64 = (0xffff - 255) * 10 + 250;
    pub const ONE_RECEIVER: u16 = 0x8000;
    pub const CUSTOM_FLAGS_MASK: u16 = 0x0fff;

    /// Decode message id field.
    pub fn id(&self) -> &MsgId {
        self.data[..MESSAGE_ID_SIZE].try_into().unwrap()
    }

    /// Decode flags field.
    pub fn flags(&self) -> u16 {
        u16::from_le_bytes(
            self.data[MESSAGE_ID_SIZE..][2..].try_into().unwrap(),
        )
    }

    /// Decode TTL field.
    pub fn ttl(&self) -> Duration {
        let secs: u16 = u16::from_le_bytes(
            self.data[MESSAGE_ID_SIZE..][..2].try_into().unwrap(),
        );

        match secs {
            0..256 => Duration::from_secs(secs as u64),
            256.. => Duration::from_secs((secs - 255) as u64 * 10 + 250),
        }
    }

    /// Encode header parts into given buffer.
    pub fn encode(
        hdr: &mut [u8; MESSAGE_HEADER_SIZE],
        id: &MsgId,
        ttl: Duration,
        flags: u16,
    ) {
        let ttl = ttl.as_secs();
        let ttl = match ttl {
            0..256 => ttl as u16,
            256..Self::MAX_TTL => {
                let ttl = (ttl + 9) / 10 - 26;
                let ttl = ttl + 256;

                ttl as u16
            }
            _ => 0xffff,
        };
        let data: u32 = (ttl as u32) | ((flags as u32) << 16);

        hdr[..MESSAGE_ID_SIZE].copy_from_slice(&id.0);
        hdr[MESSAGE_ID_SIZE..].copy_from_slice(&data.to_le_bytes());
    }

    pub fn is_one_receiver(&self) -> bool {
        (self.flags() & Self::ONE_RECEIVER) != 0
    }
}

/// Allocate message and initalize it from given parts.
pub fn allocate_message(
    id: &MsgId,
    ttl: Duration,
    flags: u16,
    payload: &[u8],
) -> Bytes {
    let mut buffer = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());

    buffer.resize(MESSAGE_HEADER_SIZE, 0);

    MsgHdr::encode(buffer.as_mut_slice().try_into().unwrap(), id, ttl, flags);

    buffer.extend_from_slice(payload);

    Bytes::from(buffer)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn msg_hdr() {
        let data = [0u8; MESSAGE_HEADER_SIZE + 1];

        assert!(<&MsgHdr>::try_from(&data[..]).is_ok());

        assert!(<&MsgHdr>::try_from(&data[..MESSAGE_HEADER_SIZE]).is_ok());

        assert!(
            <&MsgHdr>::try_from(&data[..MESSAGE_HEADER_SIZE - 1]).is_err()
        );
    }

    #[test]
    fn msg_tags() {
        let t1 = MessageTag::tag(0x1020304050607080);

        assert_eq!(
            t1.to_bytes(),
            [0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10]
        );

        let t2 = MessageTag::tag1(0x10203040, 0xAABBCCDD);

        assert_eq!(
            t2.to_bytes(),
            [0x40, 0x30, 0x20, 0x10, 0xDD, 0xCC, 0xBB, 0xAA]
        );

        let t3 = MessageTag::tag2(0x10203040, 0xEEFF, 0xDEAD);

        assert_eq!(
            t3.to_bytes(),
            [0x40, 0x30, 0x20, 0x10, 0xFF, 0xEE, 0xAD, 0xDE]
        );
    }

    #[test]
    fn ttl() {
        let id = MsgId::from([1; 32]);

        let mut hdr = [0; MESSAGE_HEADER_SIZE];

        for (s, s2) in [
            (1, 1),
            (255, 255),
            (256, 260),
            (257, 260),
            (260, 260),
            (261, 270),
            (270, 270),
            (271, 280),
            (655800, MsgHdr::MAX_TTL),
        ] {
            MsgHdr::encode(&mut hdr, &id, Duration::from_secs(s), 0);

            eprintln!("{} {:?}", s, hdr);

            let h1 = <&MsgHdr>::try_from(hdr.as_slice()).unwrap();
            assert_eq!(h1.ttl(), Duration::from_secs(s2));
        }
    }
}
