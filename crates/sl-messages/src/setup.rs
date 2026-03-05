// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Protocol setup primitives for participant identity and round tracking.
//!
//! This module defines the shared context required to run a protocol
//! execution (`ProtocolParticipant`), including party keys, local party
//! index, instance ID, and message TTL.
//!
//! It also provides helpers for message-flow coordination:
//! - `AllOtherParties` to iterate peers except self.
//! - `RoundMode` and `MessageRound` to derive and track expected message IDs
//!   (broadcast or p2p), mark arrivals, and request pending messages.
//! - `check_abort()` to validate a candidate abort message signature for a
//!   specific party (callers must pre-filter by abort message ID/tag).
//!
//! Use these types to keep message acceptance deterministic and tied to one
//! protocol instance.

use std::{borrow::Borrow, time::Duration};

pub use signature::{SignatureEncoding, Signer, Verifier};

use crate::{
    message::{InstanceId, MessageTag, MsgHdr, MsgId},
    relay::{MessageSendError, Relay},
    signed::SignedMessage,
};

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains an error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

/// An iterator for parties in range 0..total except me.
pub struct AllOtherParties {
    total: usize,
    me: usize,
    curr: usize,
}

impl Iterator for AllOtherParties {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let val = self.curr;

            if val >= self.total {
                return None;
            }

            self.curr += 1;

            if val != self.me {
                return Some(val);
            }
        }
    }
}

impl ExactSizeIterator for AllOtherParties {
    fn len(&self) -> usize {
        self.total - 1
    }
}

/// A type that provides protocol participant details.
///
/// Construction of a value of this type should carefully validate the
/// verifying keys of all parties. It is crucial to recognize the keys
/// of all participants using either a database of known keys or X.509
/// certificates.
///
/// The type defines how messages will be signed and how to verify the
/// signatures.
///
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of a SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type used to verify signed messages, a verifying key. `AsRef<[u8]>` is
    /// used to get external representation of the key to derive
    /// message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Returns total number of participants of a distributed
    /// protocol.
    fn total_participants(&self) -> usize;

    /// Returns the verifying key for messages from a participant with
    /// the given index.
    fn verifier(&self, index: usize) -> &Self::MessageVerifier;

    /// Returns a signer to sign messages from the participant.
    fn signer(&self) -> &Self::MessageSigner;

    /// Returns an index of the participant in a protocol.
    /// This is a value in range 0..self.total_participants()
    fn participant_index(&self) -> usize;

    /// Returns the protocol's execution instance ID.
    ///
    /// Each execution of a distributed protocol requires a unique
    /// instance ID to derive the IDs of all messages within that
    /// execution.
    fn instance_id(&self) -> &InstanceId;

    /// Returns message Time To Live.
    fn message_ttl(&self) -> Duration;

    /// Returns a reference to participant's own verifier.
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Returns an iterator of all participants except self.
    fn all_other_parties(&self) -> AllOtherParties {
        AllOtherParties {
            curr: 0,
            total: self.total_participants(),
            me: self.participant_index(),
        }
    }

    /// Generates an ID for a message from this party to another party,
    /// or for a broadcast message if the receiver is `None`.
    fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        self.msg_id_from(self.participant_index(), receiver, tag)
    }

    /// Generates an ID for a message from a given sender to a given
    /// receiver. The receiver is identified by its index and is
    /// `None` for a broadcast message.
    fn msg_id_from(
        &self,
        sender: usize,
        receiver: Option<usize>,
        tag: MessageTag,
    ) -> MsgId {
        let receiver = receiver
            .map(|p| self.verifier(p))
            .map(AsRef::<[u8]>::as_ref);

        MsgId::new(
            self.instance_id(),
            self.verifier(sender).as_ref(),
            receiver.as_ref().map(AsRef::as_ref),
            tag,
        )
    }

    /// Hash of the setup message received from the initiator that
    /// starts the protocol execution.
    fn setup_hash(&self) -> &[u8] {
        &[]
    }
}

impl<M: ProtocolParticipant> ProtocolParticipant for &M {
    type MessageSignature = M::MessageSignature;
    type MessageSigner = M::MessageSigner;
    type MessageVerifier = M::MessageVerifier;

    fn total_participants(&self) -> usize {
        (**self).total_participants()
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        (**self).verifier(index)
    }

    fn signer(&self) -> &Self::MessageSigner {
        (**self).signer()
    }

    fn participant_index(&self) -> usize {
        (**self).participant_index()
    }

    fn participant_verifier(&self) -> &Self::MessageVerifier {
        (**self).participant_verifier()
    }

    fn instance_id(&self) -> &InstanceId {
        (**self).instance_id()
    }

    fn message_ttl(&self) -> Duration {
        (**self).message_ttl()
    }

    fn setup_hash(&self) -> &[u8] {
        (**self).setup_hash()
    }
}

/// Returns a passed error if `msg` is a valid abort message from `party_id`.
///
/// This helper only checks signature/message-shape validity for the
/// provided party key. It does not verify that `msg` belongs to the
/// abort round.
///
/// Callers are expected to pre-filter candidate messages, for example
/// by tracking pending abort IDs:
///
/// ```ignore
/// let abort_round = MessageRound::broadcast(setup, ABORT_MESSAGE_TAG);
/// if abort_round.is_pending(id) {
///     check_abort(setup, msg, party_id, make_error)?;
/// }
/// ```
///
/// Return value handling:
/// - `Err(err(party_id))`: valid signature for `party_id`; treat this as
///   an authenticated abort and stop with that error.
/// - `Ok(())`: signature/message verification failed; when the caller has
///   already matched abort message ID, this means "abort-looking but not
///   authenticated" (e.g. invalid signature), so ignore it and continue.
pub fn check_abort<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

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
    ) -> Result<(), MessageSendError> {
        for pending in &self.pending {
            relay.ask(&pending.id, self.ttl).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Mutex};

    use signature::Error as SignatureError;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        message::allocate_message,
        relay::{BufferedMsgRelay, Bytes, BytesMut, SimpleMessageRelay},
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(250);

    #[derive(Clone)]
    struct NoSignature;

    impl SignatureEncoding for NoSignature {
        type Repr = [u8; 0];
    }

    impl TryFrom<&[u8]> for NoSignature {
        type Error = ();

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            if value.is_empty() {
                Ok(Self)
            } else {
                Err(())
            }
        }
    }

    impl TryInto<[u8; 0]> for NoSignature {
        type Error = ();

        fn try_into(self) -> Result<[u8; 0], Self::Error> {
            Ok([])
        }
    }

    #[derive(Clone)]
    struct NoSigningKey;

    impl Signer<NoSignature> for NoSigningKey {
        fn try_sign(
            &self,
            _msg: &[u8],
        ) -> Result<NoSignature, SignatureError> {
            Ok(NoSignature)
        }
    }

    #[derive(Clone)]
    struct NoVerifyingKey([u8; 32]);

    impl NoVerifyingKey {
        fn new(id: usize) -> Self {
            let mut out = [0; 32];
            out[0..8].copy_from_slice(&(id as u64).to_le_bytes());
            Self(out)
        }
    }

    impl AsRef<[u8]> for NoVerifyingKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Verifier<NoSignature> for NoVerifyingKey {
        fn verify(
            &self,
            _msg: &[u8],
            _signature: &NoSignature,
        ) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    struct TestParticipant {
        me: usize,
        verifiers: Vec<NoVerifyingKey>,
        signer: NoSigningKey,
        instance: InstanceId,
    }

    impl TestParticipant {
        fn new(total: usize, me: usize) -> Self {
            Self {
                me,
                verifiers: (0..total).map(NoVerifyingKey::new).collect(),
                signer: NoSigningKey,
                instance: InstanceId::from([7u8; 32]),
            }
        }
    }

    impl ProtocolParticipant for TestParticipant {
        type MessageSignature = NoSignature;
        type MessageSigner = NoSigningKey;
        type MessageVerifier = NoVerifyingKey;

        fn total_participants(&self) -> usize {
            self.verifiers.len()
        }

        fn verifier(&self, index: usize) -> &Self::MessageVerifier {
            &self.verifiers[index]
        }

        fn signer(&self) -> &Self::MessageSigner {
            &self.signer
        }

        fn participant_index(&self) -> usize {
            self.me
        }

        fn instance_id(&self) -> &InstanceId {
            &self.instance
        }

        fn message_ttl(&self) -> Duration {
            Duration::from_secs(10)
        }
    }

    #[derive(Default)]
    struct AskRecorderRelay {
        asks: Mutex<Vec<(MsgId, Duration)>>,
    }

    impl AskRecorderRelay {
        fn asks(&self) -> Vec<(MsgId, Duration)> {
            self.asks.lock().unwrap().clone()
        }
    }

    impl Relay for AskRecorderRelay {
        async fn ask(
            &self,
            id: &MsgId,
            ttl: Duration,
        ) -> Result<(), MessageSendError> {
            self.asks.lock().unwrap().push((*id, ttl));
            Ok(())
        }

        async fn feed(
            &self,
            _message: Bytes,
        ) -> Result<(), MessageSendError> {
            Ok(())
        }

        async fn next(&mut self) -> Option<BytesMut> {
            None
        }
    }

    #[test]
    fn message_round_broadcast() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(11);
        let round = MessageRound::broadcast(&setup, tag);

        assert_eq!(round.pending_len(), 3);
        assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
        assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
        assert!(round.is_pending(&setup.msg_id_from(3, None, tag)));
        assert!(!round.is_pending(&setup.msg_id_from(1, None, tag)));
    }

    #[test]
    fn message_round_p2p() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(12);
        let round = MessageRound::p2p(&setup, tag);

        assert_eq!(round.pending_len(), 3);
        assert!(round.is_pending(&setup.msg_id_from(0, Some(1), tag)));
        assert!(round.is_pending(&setup.msg_id_from(2, Some(1), tag)));
        assert!(round.is_pending(&setup.msg_id_from(3, Some(1), tag)));
        assert!(!round.is_pending(&setup.msg_id_from(0, None, tag)));
    }

    #[test]
    fn message_round_from_parties_skips_me() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(13);
        let senders = vec![0, 1, 2];
        let round = MessageRound::from_parties(
            &setup,
            tag,
            &senders,
            RoundMode::Broadcast,
        );

        assert_eq!(round.pending_len(), 2);
        assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
        assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
        assert!(!round.is_pending(&setup.msg_id_from(1, None, tag)));
    }

    #[test]
    fn message_round_from_parties_accepts_array_literal() {
        let setup = TestParticipant::new(4, 0);
        let tag = MessageTag::tag(16);
        let round = MessageRound::from_parties(
            &setup,
            tag,
            [1, 2],
            RoundMode::Broadcast,
        );

        assert_eq!(round.pending_len(), 2);
        assert!(round.is_pending(&setup.msg_id_from(1, None, tag)));
        assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
        assert!(!round.is_pending(&setup.msg_id_from(3, None, tag)));
    }

    #[test]
    fn message_round_from_parties_handles_large_input() {
        let setup = TestParticipant::new(300, 299);
        let tag = MessageTag::tag(18);
        let round = MessageRound::from_parties(
            &setup,
            tag,
            0..256,
            RoundMode::Broadcast,
        );

        assert_eq!(round.pending_len(), 256);
        assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
        assert!(round.is_pending(&setup.msg_id_from(255, None, tag)));
        assert!(!round.is_pending(&setup.msg_id_from(256, None, tag)));
    }

    #[test]
    fn mark_received_message_removes_id() {
        let setup = TestParticipant::new(3, 1);
        let tag = MessageTag::tag(14);
        let mut round = MessageRound::broadcast(&setup, tag);

        let id = setup.msg_id_from(0, None, tag);
        let msg =
            allocate_message(&id, Duration::from_secs(5), 0, &[1, 2, 3]);

        assert!(round.mark_received_message(msg.as_ref()));
        assert!(!round.is_pending(&id));
        assert!(!round.mark_received_message(msg.as_ref()));
        assert!(!round.mark_received_message(&[]));
        assert_eq!(round.pending_len(), 1);
        assert!(!round.is_complete());
    }

    #[test]
    fn pending_sender_and_mark_received_with_sender() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(19);
        let mut round = MessageRound::broadcast(&setup, tag);
        let id0 = setup.msg_id_from(0, None, tag);
        let id2 = setup.msg_id_from(2, None, tag);

        assert_eq!(round.pending_sender(&id0), Some(0));
        assert_eq!(round.pending_sender(&id2), Some(2));
        assert_eq!(round.mark_received_with_sender(&id2), Some(2));
        assert_eq!(round.pending_sender(&id2), None);
        assert!(!round.mark_received(&id2));

        let msg = allocate_message(&id0, Duration::from_secs(5), 0, &[1]);
        assert_eq!(round.pending_sender_message(msg.as_ref()), Some(0));
        assert_eq!(round.pending_sender_message(&[]), None);
        assert_eq!(
            round.mark_received_message_with_sender(msg.as_ref()),
            Some(0)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ask_pending_asks_all_pending_messages() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(15);
        let round = MessageRound::broadcast(&setup, tag);
        let relay = AskRecorderRelay::default();

        round.ask_pending(&relay).await.unwrap();

        let asks = relay.asks();
        let asked_ids =
            asks.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
        let expected = setup
            .all_other_parties()
            .map(|sender| setup.msg_id_from(sender, None, tag))
            .collect::<HashSet<_>>();

        assert_eq!(asks.len(), 3);
        assert_eq!(asked_ids, expected);
        assert!(asks.iter().all(|(_, ttl)| *ttl == setup.message_ttl()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_round_wait_for_end_to_end() {
        let setup = TestParticipant::new(4, 1);
        let tag = MessageTag::tag(17);
        let other_tag = MessageTag::tag(99);
        let mut round = MessageRound::broadcast(&setup, tag);

        let service = SimpleMessageRelay::new();
        let tx = service.connect();
        let mut relay = BufferedMsgRelay::new(service.connect());

        // Ask for round messages and one extra message that does not belong
        // to the round. The extra one should stay buffered.
        round.ask_pending(&relay).await.unwrap();
        let extra_id = setup.msg_id_from(0, None, other_tag);
        relay.ask(&extra_id, setup.message_ttl()).await.unwrap();

        tx.send(allocate_message(
            &setup.msg_id_from(3, None, tag),
            setup.message_ttl(),
            0,
            &[3],
        ))
        .await
        .unwrap();
        tx.send(allocate_message(
            &setup.msg_id_from(0, None, tag),
            setup.message_ttl(),
            0,
            &[0],
        ))
        .await
        .unwrap();
        tx.send(allocate_message(
            &setup.msg_id_from(2, None, tag),
            setup.message_ttl(),
            0,
            &[2],
        ))
        .await
        .unwrap();
        tx.send(allocate_message(&extra_id, setup.message_ttl(), 0, &[10]))
            .await
            .unwrap();

        for _ in 0..3 {
            let msg = timeout(
                TEST_TIMEOUT,
                relay.wait_for(|id| round.is_pending(id)),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(round.mark_received_message(msg.as_ref()));
        }

        assert!(round.is_complete());
        assert_eq!(round.pending_len(), 0);
        assert_eq!(relay.buffered_len(), 1);

        let msg = timeout(TEST_TIMEOUT, relay.next()).await.unwrap().unwrap();
        assert_eq!(<&MsgId>::try_from(msg.as_ref()).ok(), Some(&extra_id));
    }
}
