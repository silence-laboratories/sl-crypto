// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{borrow::Borrow, time::Duration};

use crate::{
    message::{MessageTag, MsgHdr, MsgId},
    relay::{MessageSendError, Relay},
};

use super::traits::ProtocolParticipant;

/// Message delivery mode for a protocol round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundMode {
    /// Expect broadcast messages.
    Broadcast,
    /// Expect point-to-point messages addressed to this participant.
    P2P,
}

impl RoundMode {
    fn receiver(self, me: usize) -> Option<usize> {
        match self {
            Self::Broadcast => None,
            Self::P2P => Some(me),
        }
    }
}

/// A helper that tracks expected message IDs in one protocol round.
///
/// A message is "pending" while its ID is still expected from another
/// participant. This can be used together with
/// `BufferedMsgRelay::wait_for()`:
///
/// ```ignore
/// let mut round = MessageRound::broadcast(setup, tag);
/// while !round.is_complete() {
///     let msg = relay.wait_for(|id| round.is_pending(id)).await?;
///     round.mark_received_message(&msg);
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct MessageRound {
    pending: Vec<PendingMessage>,
    ttl: Duration,
}

#[derive(Clone, Debug)]
struct PendingMessage {
    id: MsgId,
    sender: usize,
}

impl MessageRound {
    /// Build a broadcast round from all parties except
    /// `setup.participant_index()`.
    pub fn new<P: ProtocolParticipant>(setup: &P, tag: MessageTag) -> Self {
        Self::broadcast(setup, tag)
    }

    /// Build a broadcast round from all parties except
    /// `setup.participant_index()`.
    pub fn broadcast<P: ProtocolParticipant>(
        setup: &P,
        tag: MessageTag,
    ) -> Self {
        Self::from_parties(
            setup,
            tag,
            setup.all_other_parties(),
            RoundMode::Broadcast,
        )
    }

    /// Build a point-to-point round from all parties except
    /// `setup.participant_index()`.
    pub fn p2p<P: ProtocolParticipant>(setup: &P, tag: MessageTag) -> Self {
        Self::from_parties(
            setup,
            tag,
            setup.all_other_parties(),
            RoundMode::P2P,
        )
    }

    /// Build a round from a custom sender list and delivery mode.
    ///
    /// Sender equal to `setup.participant_index()` is ignored.
    pub fn from_parties<P, I, T>(
        setup: &P,
        tag: MessageTag,
        parties: I,
        mode: RoundMode,
    ) -> Self
    where
        P: ProtocolParticipant,
        I: IntoIterator<Item = T>,
        T: Borrow<usize>,
    {
        let my_party_index = setup.participant_index();
        let receiver = mode.receiver(my_party_index);

        let mut pending = parties
            .into_iter()
            .map(|sender_index| *sender_index.borrow())
            .filter(|sender_index| *sender_index != my_party_index)
            .map(|sender| PendingMessage {
                id: setup.msg_id_from(sender, receiver, tag),
                sender,
            })
            .collect::<Vec<_>>();

        pending.sort_unstable_by(|a, b| a.id.as_slice().cmp(b.id.as_slice()));
        pending.dedup_by(|a, b| a.id == b.id);

        Self {
            pending,
            ttl: setup.message_ttl(),
        }
    }

    fn pending_position(&self, id: &MsgId) -> Result<usize, usize> {
        self.pending.binary_search_by(|pending| {
            pending.id.as_slice().cmp(id.as_slice())
        })
    }

    /// Returns `true` if message with this ID is still pending in the round.
    pub fn is_pending(&self, id: &MsgId) -> bool {
        self.pending_position(id).is_ok()
    }

    /// Return sender party index for the pending message with this ID.
    pub fn pending_sender(&self, id: &MsgId) -> Option<usize> {
        self.pending_position(id)
            .ok()
            .map(|idx| self.pending[idx].sender)
    }

    /// Parse a message header and return sender party index for the
    /// corresponding pending message ID.
    pub fn pending_sender_message(&self, msg: &[u8]) -> Option<usize> {
        <&MsgHdr>::try_from(msg)
            .ok()
            .and_then(|hdr| self.pending_sender(hdr.id()))
    }

    /// Mark message ID as received.
    ///
    /// Returns `true` if ID was pending and is removed now.
    pub fn mark_received(&mut self, id: &MsgId) -> bool {
        self.mark_received_with_sender(id).is_some()
    }

    /// Mark message ID as received and return its sender party index.
    ///
    /// Returns `None` if ID was not pending.
    pub fn mark_received_with_sender(&mut self, id: &MsgId) -> Option<usize> {
        self.pending_position(id)
            .ok()
            .map(|idx| self.pending.remove(idx).sender)
    }

    /// Parse a message header and mark its ID as received.
    ///
    /// Returns `false` if the message has no valid header or if the ID
    /// was not pending.
    pub fn mark_received_message(&mut self, msg: &[u8]) -> bool {
        self.mark_received_message_with_sender(msg).is_some()
    }

    /// Parse a message header, mark its ID as received and return sender
    /// party index.
    pub fn mark_received_message_with_sender(
        &mut self,
        msg: &[u8],
    ) -> Option<usize> {
        <&MsgId>::try_from(msg)
            .ok()
            .and_then(|id| self.mark_received_with_sender(id))
    }

    /// Number of messages still pending in this round.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Returns `true` when all round messages were received.
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty()
    }

    /// Ask relay to deliver all currently pending round messages.
    pub async fn ask_pending<R: Relay>(
        &self,
        relay: &R,
    ) -> Result<usize, MessageSendError> {
        let count = self.pending.len();
        for pending in &self.pending {
            relay.ask(&pending.id, self.ttl).await?;
        }

        Ok(count)
    }
}
