// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{Deref, DerefMut};

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
        self.wait_for_bounded(0, predicate).await
    }

    /// Wait for messages based on a predicate, with an optional buffer bound.
    ///
    /// If `max_buffered == 0`, this behaves exactly like `wait_for`.
    /// If there is no buffered match and the current buffer has already reached
    /// `max_buffered`, return `None` immediately.
    /// Otherwise, if buffering another unmatched message would reach or exceed
    /// `max_buffered`, return `None`.
    pub async fn wait_for_bounded(
        &mut self,
        max_buffered: usize,
        predicate: impl Fn(&MsgId) -> bool,
    ) -> Option<BytesMut> {
        // First, look into the input buffer.
        if let Some(idx) = self.buffer.iter().position(|msg| {
            <&MsgHdr>::try_from(msg.as_ref())
                .ok()
                .filter(|hdr| predicate(hdr.id()))
                .is_some()
        }) {
            // there is a buffered message matching the predicate.
            return Some(self.buffer.swap_remove(idx));
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
                if predicate(hdr.id()) {
                    // good, return it
                    return Some(msg);
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

    #[tokio::test(flavor = "multi_thread")]
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

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_bounded_returns_none_on_limit() {
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
            brelay.wait_for_bounded(2, |id| id == &id1),
        )
        .await
        .unwrap();
        assert!(m.is_none());
        assert_eq!(brelay.buffered_len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_bounded_returns_none_when_buffer_is_already_full() {
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
            brelay.wait_for_bounded(1, |id| id == &id1),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_for_bounded_returns_buffered_match_when_full() {
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
            brelay.wait_for_bounded(2, |id| id == &id1),
        )
        .await
        .unwrap();
        assert_eq!(
            m.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );
        assert_eq!(brelay.buffered_len(), 1);

        let m = timeout(TEST_TIMEOUT, brelay.next()).await.unwrap();
        assert_eq!(
            m.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id2)
        );
    }
}
