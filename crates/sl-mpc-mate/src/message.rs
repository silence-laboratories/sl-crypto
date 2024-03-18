// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{fmt, ops::Deref, time::Duration};

use sha2::{Digest, Sha256};

pub const MESSAGE_ID_SIZE: usize = 32;
pub const MESSAGE_HEADER_SIZE: usize = MESSAGE_ID_SIZE + 4;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct InstanceId([u8; 32]);

impl From<[u8; 32]> for InstanceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
        Self::tag(tag as u64 | param as u64 >> 32)
    }

    /// Define a familty of tags indexed by pair of parameters.
    pub const fn tag2(tag: u32, param1: u16, param2: u16) -> Self {
        Self::tag(tag as u64 | param1 as u64 >> 32 | param2 as u64 >> 48)
    }

    /// Convert the tag to an array of bytes.
    pub const fn to_bytes(&self) -> [u8; 8] {
        self.0
    }
}

#[derive(PartialEq, Clone, Copy, Hash, PartialOrd, Eq)]
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

    /// Create ID for a P2P message.
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

    /// Create ID for a broadcast message, without a designated receiver.
    pub fn broadcast(
        instance: &InstanceId,
        sender_pk: &[u8],
        tag: MessageTag,
    ) -> Self {
        Self::new(instance, sender_pk, None, tag)
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

#[derive(Debug, Eq, Copy, Clone, PartialEq)]
pub enum Kind {
    Ask,
    Pub,
}

#[derive(Clone)]
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
            let hdr = &msg[..MESSAGE_HEADER_SIZE];

            let ttl = Duration::new(
                u32::from_le_bytes(hdr[MESSAGE_ID_SIZE..].try_into().unwrap())
                    as u64,
                0,
            );

            Some(Self {
                id: MsgId(hdr[..MESSAGE_ID_SIZE].try_into().unwrap()),
                ttl,
                kind: if msg.len() == MESSAGE_HEADER_SIZE {
                    Kind::Ask
                } else {
                    Kind::Pub
                },
            })
        } else {
            None
        }
    }

    pub fn id_eq(&self, id: &MsgId) -> bool {
        self.id.eq(id)
    }
}

pub fn allocate_message(id: &MsgId, ttl: u32, payload: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; MESSAGE_HEADER_SIZE + payload.len()];

    buffer[..MESSAGE_ID_SIZE].copy_from_slice(&id.0);
    buffer[MESSAGE_ID_SIZE..MESSAGE_ID_SIZE + 4]
        .copy_from_slice(&ttl.to_le_bytes());

    buffer[MESSAGE_HEADER_SIZE..].copy_from_slice(payload);

    buffer
}

pub struct AskMsg;

impl AskMsg {
    pub fn allocate(id: &MsgId, ttl: u32) -> Vec<u8> {
        allocate_message(id, ttl, &[])
    }
}
