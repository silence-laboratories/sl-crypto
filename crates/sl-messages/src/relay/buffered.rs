// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{Deref, DerefMut};

use crate::relay::*;

pub struct BufferedMsgRelay<R: Relay> {
    relay: R,
    buffer: Vec<BytesMut>,
}

impl<R: Relay> BufferedMsgRelay<R> {
    /// Construct a BufferedMsgRelay by wrapping up a Relay object
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
        // first, look into the input buffer
        if let Some(idx) = self.buffer.iter().position(|msg| {
            <&MsgHdr>::try_from(msg.as_ref())
                .ok()
                .filter(|hdr| predicate(hdr.id()))
                .is_some()
        }) {
            // there is a buffered message matching the predicate.
            return Some(self.buffer.swap_remove(idx));
        }

        // flush output message messages.
        self.relay.flush().await.ok()?;

        loop {
            let msg = self.relay.next().await?;

            if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_ref()) {
                if predicate(hdr.id()) {
                    // good, return it
                    return Some(msg);
                } else {
                    // push into the buffer and try again
                    self.buffer.push(msg);
                }
            }
        }
    }

    /// Function to receive message based on certain ID
    pub async fn recv(&mut self, id: &MsgId, ttl: u32) -> Option<BytesMut> {
        self.relay
            .ask(id, Duration::from_secs(ttl as _))
            .await
            .ok()?;
        self.wait_for(|msg| msg.eq(id)).await
    }

    /// Return all buffered messages
    pub fn buffered(&self) -> impl Iterator<Item = &[u8]> {
        self.buffer.iter().map(|m| m.as_ref())
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
        message::{InstanceId, MessageTag, MsgId, allocate_message},
        relay::{BufferedMsgRelay, Bytes, Relay, SimpleMessageRelay},
    };

    fn mk_msg(id: &MsgId) -> Bytes {
        allocate_message(id, Duration::from_secs(10), 0, &[0, 255])
    }

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

        let (m1, m2) = timeout(Duration::from_millis(10), h)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            m1.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id1)
        );

        assert_eq!(
            m2.as_deref().and_then(|m| <&MsgId>::try_from(m).ok()),
            Some(&id2)
        );
    }
}
