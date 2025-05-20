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

    fn next(&mut self) -> impl Future<Output = Option<BytesMut>> {
        self.relay.next()
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
