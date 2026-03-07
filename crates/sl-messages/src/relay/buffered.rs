// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{Deref, DerefMut};

#[cfg(feature = "setup")]
use bytemuck::{AnyBitPattern, NoUninit};

#[cfg(feature = "setup")]
use crate::{
    setup::{validate_abort_message, MessageRound, ProtocolParticipant},
    signed::SignedMessage,
};

use crate::relay::*;

pub struct BufferedMsgRelay<R: Relay> {
    relay: R,
    buffer: Vec<BytesMut>,
}

impl<R: Relay> BufferedMsgRelay<R> {
    /// Construct a `BufferedMsgRelay` by wrapping a `Relay`.
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            buffer: vec![],
        }
    }

    pub fn with_capacity(relay: R, capacity: usize) -> Self {
        Self {
            relay,
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Wait for particular messages based on predicate.
    pub async fn wait_for(
        &mut self,
        predicate: impl Fn(&MsgId) -> bool,
    ) -> Option<BytesMut> {
        self.wait_for_limited(0, |id| predicate(id).then_some(()))
            .await
            .map(|(msg, _)| msg)
    }

    /// Wait for a message whose `MsgId` matches `predicate`, with an optional
    /// bound on how many unmatched messages may be buffered.
    ///
    /// The predicate maps a `MsgId` to `Option<O>`:
    /// - `Some(out)` means a match and this returns `Some((message, out))`.
    /// - `None` means no match and the message may be buffered.
    ///
    /// If `max_buffered == 0`, buffering is unbounded (same behavior as
    /// `wait_for`).
    ///
    /// For `max_buffered > 0`, this returns `None` when there is no buffered
    /// match and:
    /// - the current buffer is already full (`buffer.len() >= max_buffered`), or
    /// - receiving one more unmatched message fills the buffer.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe only if the wrapped [`Relay`] is cancel-safe
    /// for [`Relay::next`] (and [`Relay::flush`], which is awaited before
    /// receiving). `BufferedMsgRelay` does not add extra cancellation hazards,
    /// but it cannot strengthen the guarantees of the underlying relay.
    pub async fn wait_for_limited<O, F>(
        &mut self,
        max_buffered: usize,
        mut predicate: F,
    ) -> Option<(BytesMut, O)>
    where
        F: FnMut(&MsgId) -> Option<O>,
    {
        // First, look into the input buffer.
        if let Some((idx, out)) =
            self.buffer.iter().enumerate().find_map(|(idx, msg)| {
                let hdr = <&MsgHdr>::try_from(msg.as_ref()).ok()?;
                let out = predicate(hdr.id())?;
                Some((idx, out))
            })
        {
            // there is a buffered message matching the predicate.
            return Some((self.buffer.swap_remove(idx), out));
        }

        // Must have room for at least one unmatched message.
        if max_buffered > 0 && self.buffer.len() >= max_buffered {
            return None;
        }

        // Flush outbound relay messages.
        self.relay.flush().await.ok()?;

        loop {
            let msg = self.relay.next().await?;

            if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_ref()) {
                if let Some(out) = predicate(hdr.id()) {
                    // good, return it
                    return Some((msg, out));
                } else {
                    // push into the buffer
                    self.buffer.push(msg);
                    // and try again after checking max size of buffer.
                    if max_buffered > 0 && self.buffer.len() >= max_buffered {
                        return None;
                    }
                }
            }
        }
    }

    /// Receive a message for a specific ID.
    pub async fn recv(&mut self, id: &MsgId, ttl: u32) -> Option<BytesMut> {
        self.relay
            .ask(id, Duration::from_secs(ttl as _))
            .await
            .ok()?;
        self.wait_for(|msg| msg.eq(id)).await
    }

    /// Return all buffered messages.
    pub fn buffered(&self) -> impl Iterator<Item = &[u8]> {
        self.buffer.iter().map(|m| m.as_ref())
    }

    /// Return the number of buffered messages.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl<R: Relay> Relay for BufferedMsgRelay<R> {
    fn feed(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> {
        self.relay.feed(message)
    }

    fn flush(&self) -> impl Future<Output = Result<(), MessageSendError>> {
        self.relay.flush()
    }

    async fn next(&mut self) -> Option<BytesMut> {
        if let Some(msg) = self.buffer.pop() {
            return Some(msg);
        }
        self.relay.next().await
    }

    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(id, ttl).await
    }
}

impl<R: Relay + SplitSender> SplitSender for BufferedMsgRelay<R> {
    fn split_sender(&self) -> impl Sender + 'static {
        self.relay.split_sender()
    }
}

impl<R: Relay> Deref for BufferedMsgRelay<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl<R: Relay> DerefMut for BufferedMsgRelay<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.relay
    }
}

/// Errors returned by `BufferedMsgRelay::process_signed`.
#[cfg(feature = "setup")]
pub enum BufferedError {
    /// A valid abort message was received from this party.
    Abort(usize),
    /// No matching message could be received.
    Recv,
    /// Send/ask error.
    Send,
    /// Invalid message format.
    InvalidMessage,
}

#[cfg(feature = "setup")]
#[derive(Clone, Copy)]
enum WaitForRoundMessage {
    Abort { party_id: usize },
    Round { party_id: usize },
}

#[cfg(feature = "setup")]
fn match_round_message(
    round: &MessageRound,
    abort: Option<&MessageRound>,
    id: &MsgId,
) -> Option<WaitForRoundMessage> {
    abort
        .and_then(|abort| abort.pending_sender(id))
        .map(|party_id| WaitForRoundMessage::Abort { party_id })
        .or_else(|| {
            round
                .pending_sender(id)
                .map(|party_id| WaitForRoundMessage::Round { party_id })
        })
}

#[cfg(feature = "setup")]
impl<R: Relay> BufferedMsgRelay<R> {
    /// Processes all pending messages for `round`, optionally observing an
    /// `abort` round at the same time.
    ///
    /// The method receives messages until `round` is complete. For each
    /// matching round message, `handler` is called with `(message, party_id)`.
    ///
    /// If `handler` returns `Ok(true)`, the message is treated as ignored and
    /// the sender is not marked as received for `round`. Returning `Ok(false)`
    /// marks the sender as received.
    ///
    /// Abort messages are validated with `setup`; a valid abort returns
    /// `BufferedError::Abort` for the aborting party.
    ///
    /// # Errors
    ///
    /// Returns `BufferedError::Recv` when no matching message can be received,
    /// and propagates errors from abort validation and `handler`.
    pub async fn process_round<P, E, F>(
        &mut self,
        setup: &P,
        limit: usize,
        mut round: MessageRound,
        abort: Option<&MessageRound>,
        mut handler: F,
    ) -> Result<(), E>
    where
        P: ProtocolParticipant,
        F: FnMut(BytesMut, usize) -> Result<bool, E>,
        E: From<BufferedError>,
    {
        while !round.is_complete() {
            let (msg, wait_match) = self
                .wait_for_limited(limit, |id| {
                    match_round_message(&round, abort, id)
                })
                .await
                .ok_or(BufferedError::Recv)?;

            let party_id = match wait_match {
                WaitForRoundMessage::Abort { party_id } => {
                    validate_abort_message(
                        setup,
                        &msg,
                        party_id,
                        BufferedError::Abort,
                    )?;

                    // At this point, we figured out that the received message
                    // has a valid msg-id but invalid signature. Ignore it.
                    continue;
                }
                WaitForRoundMessage::Round { party_id } => party_id,
            };

            let id = <&MsgId>::try_from(msg.as_ref())
                .copied()
                .unwrap_or(MsgId::ZERO_ID);

            if handler(msg, party_id)? {
                continue;
            }

            // Mark as received only after successful auth + parse.
            round.mark_received(&id);
        }

        Ok(())
    }

    /// Processes a round of signed messages and calls `handler` for each valid
    /// signed payload.
    ///
    /// This is a typed wrapper around [`Self::process_round`]:
    /// messages are verified with `setup.verifier(party_id)` and decoded as
    /// `SignedMessage<T, _>`. Invalid signatures or malformed payloads are
    /// ignored and do not mark the sender as received.
    ///
    /// `handler` receives `(&value, trailer, party_id)` for each valid message.
    ///
    /// # Errors
    ///
    /// Propagates errors returned by [`Self::process_round`] and by `handler`.
    pub async fn process_signed<P, T, E, F>(
        &mut self,
        setup: &P,
        limit: usize,
        round: MessageRound,
        abort: Option<&MessageRound>,
        mut handler: F,
    ) -> Result<(), E>
    where
        T: AnyBitPattern + NoUninit,
        P: ProtocolParticipant,
        F: FnMut(&T, &[u8], usize) -> Result<(), E>,
        E: From<BufferedError>,
    {
        self.process_round(setup, limit, round, abort, |msg, party_id| {
            let Some((val, trailer)) =
                SignedMessage::<T, _>::verify_with_trailer(
                    &msg,
                    setup.verifier(party_id),
                )
            else {
                return Ok(true);
            };

            handler(&val, trailer, party_id)?;

            Ok::<_, E>(false)
        })
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::{sleep, timeout};

    use crate::{
        message::{allocate_message, InstanceId, MessageTag, MsgId},
        relay::{
            BufferedMsgRelay, Bytes, BytesMut, Relay, SimpleMessageRelay,
        },
    };

    fn mk_msg(id: &MsgId) -> Bytes {
        allocate_message(id, Duration::from_secs(10), 0, &[0, 255])
    }

    const TEST_TIMEOUT: Duration = Duration::from_millis(250);

    #[tokio::test]
    async fn out_of_order_messages() {
        let instance = InstanceId::from([1u8; 32]);

        let r = SimpleMessageRelay::new();

        let c = r.connect();

        let mut brelay = BufferedMsgRelay::new(r.connect());

        let sender = [1; 32];
        let id1 = MsgId::new(&instance, &sender, None, MessageTag::tag(1));
        let id2 = MsgId::new(&instance, &sender, None, MessageTag::tag(2));

        brelay.ask(&id1, Duration::from_secs(10)).await.unwrap();
        brelay.ask(&id2, Duration::from_secs(10)).await.unwrap();

        let h = tokio::spawn(async move {
            let m1 = brelay.wait_for(|id| id == &id1).await;

            let m2 = brelay.next().await;

            (m1, m2)
        });

        c.send(mk_msg(&id2)).await.unwrap();
        sleep(Duration::from_millis(10)).await;
        c.send(mk_msg(&id1)).await.unwrap();

        let (m1, m2) = timeout(TEST_TIMEOUT, h).await.unwrap().unwrap();

        assert_eq!(
            m1.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );

        assert_eq!(
            m2.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id2)
        );
    }

    #[tokio::test]
    async fn wait_for_limited_returns_none_on_limit() {
        let instance = InstanceId::from([1u8; 32]);

        let r = SimpleMessageRelay::new();

        let c = r.connect();
        let mut brelay = BufferedMsgRelay::new(r.connect());

        let sender = [1; 32];
        let id1 = MsgId::new(&instance, &sender, None, MessageTag::tag(1));
        let id2 = MsgId::new(&instance, &sender, None, MessageTag::tag(2));
        let id3 = MsgId::new(&instance, &sender, None, MessageTag::tag(3));

        brelay.ask(&id1, Duration::from_secs(10)).await.unwrap();
        brelay.ask(&id2, Duration::from_secs(10)).await.unwrap();
        brelay.ask(&id3, Duration::from_secs(10)).await.unwrap();

        c.send(mk_msg(&id2)).await.unwrap();
        sleep(Duration::from_millis(10)).await;
        c.send(mk_msg(&id3)).await.unwrap();

        let m = timeout(
            TEST_TIMEOUT,
            brelay.wait_for_limited(2, |id| (id == &id1).then_some(())),
        )
        .await
        .unwrap();
        assert!(m.is_none());
        assert_eq!(brelay.buffered_len(), 2);
    }

    #[tokio::test]
    async fn wait_for_limited_returns_none_when_buffer_is_already_full() {
        let instance = InstanceId::from([1u8; 32]);

        let r = SimpleMessageRelay::new();

        let c = r.connect();
        let mut brelay = BufferedMsgRelay::new(r.connect());

        let sender = [1; 32];
        let id1 = MsgId::new(&instance, &sender, None, MessageTag::tag(1));
        let id2 = MsgId::new(&instance, &sender, None, MessageTag::tag(2));

        brelay.ask(&id1, Duration::from_secs(10)).await.unwrap();

        // Fill local buffer to capacity with a non-matching message.
        brelay.buffer.push(BytesMut::from(mk_msg(&id2)));
        assert_eq!(brelay.buffered_len(), 1);

        // Ensure a matching relay message is available; first bounded call
        // should still return None immediately due to full local buffer.
        c.send(mk_msg(&id1)).await.unwrap();

        let m = timeout(
            TEST_TIMEOUT,
            brelay.wait_for_limited(1, |id| (id == &id1).then_some(())),
        )
        .await
        .unwrap();
        assert!(m.is_none());

        // The previous call must not consume the relay message.
        let m = timeout(TEST_TIMEOUT, brelay.wait_for(|id| id == &id1))
            .await
            .unwrap();
        assert_eq!(
            m.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );
    }

    #[tokio::test]
    async fn wait_for_limited_returns_live_match_and_mapped_output() {
        let instance = InstanceId::from([1u8; 32]);

        let r = SimpleMessageRelay::new();

        let c = r.connect();
        let mut brelay = BufferedMsgRelay::new(r.connect());

        let sender = [1; 32];
        let id1 = MsgId::new(&instance, &sender, None, MessageTag::tag(1));

        brelay.ask(&id1, Duration::from_secs(10)).await.unwrap();
        c.send(mk_msg(&id1)).await.unwrap();

        let m = timeout(
            TEST_TIMEOUT,
            brelay.wait_for_limited(1, |id| (id == &id1).then_some(7u8)),
        )
        .await
        .unwrap();

        assert_eq!(
            m.as_ref()
                .map(|(m, _)| m.as_ref())
                .and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );
        assert_eq!(m.as_ref().map(|(_, out)| *out), Some(7u8));
        assert_eq!(brelay.buffered_len(), 0);
    }

    #[tokio::test]
    async fn wait_for_limited_returns_buffered_match_when_full() {
        let instance = InstanceId::from([1u8; 32]);

        let r = SimpleMessageRelay::new();
        let mut brelay = BufferedMsgRelay::new(r.connect());

        let sender = [1; 32];
        let id1 = MsgId::new(&instance, &sender, None, MessageTag::tag(1));
        let id2 = MsgId::new(&instance, &sender, None, MessageTag::tag(2));

        // Fill the local buffer to capacity with one matching and one non-matching message.
        brelay.buffer.push(BytesMut::from(mk_msg(&id1)));
        brelay.buffer.push(BytesMut::from(mk_msg(&id2)));
        assert_eq!(brelay.buffered_len(), 2);

        // Should return the matching buffered message even when buffer is full.
        let m = timeout(
            TEST_TIMEOUT,
            brelay.wait_for_limited(2, |id| (id == &id1).then_some(9u8)),
        )
        .await
        .unwrap();
        assert_eq!(
            m.as_ref()
                .map(|(m, _)| m.as_ref())
                .and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );
        assert_eq!(m.as_ref().map(|(_, out)| *out), Some(9u8));
        assert_eq!(brelay.buffered_len(), 1);

        let m = timeout(TEST_TIMEOUT, brelay.next()).await.unwrap();
        assert_eq!(
            m.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id2)
        );
    }
}
