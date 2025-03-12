// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::coord::*;

pub struct BufferedMsgRelay<R: Relay> {
    relay: R,
    in_buf: Vec<Vec<u8>>,
}

impl<R: Relay> BufferedMsgRelay<R> {
    /// Construct a BufferedMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            in_buf: vec![],
        }
    }

    pub fn with_capacity(relay: R, capacity: usize) -> Self {
        Self {
            relay,
            in_buf: Vec::with_capacity(capacity),
        }
    }

    /// Wait for particular messages based on predicate.
    pub async fn wait_for(
        &mut self,
        predicate: impl Fn(&MsgId) -> bool,
    ) -> Option<Vec<u8>> {
        // first, look into the input buffer
        if let Some(idx) = self.in_buf.iter().position(|msg| {
            <&MsgHdr>::try_from(msg.as_slice())
                .ok()
                .filter(|hdr| predicate(hdr.id()))
                .is_some()
        }) {
            // there is a buffered message matching the predicate.
            return Some(self.in_buf.swap_remove(idx));
        }

        // flush output message messages.
        self.relay.flush().await.ok()?;

        loop {
            let msg = self.relay.next().await?;

            if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_slice()) {
                if predicate(hdr.id()) {
                    // good, return it
                    return Some(msg);
                } else {
                    // push into the buffer and try again
                    self.in_buf.push(msg);
                }
            }
        }
    }

    /// Function to receive message based on certain ID
    pub async fn recv(&mut self, id: &MsgId, ttl: u32) -> Option<Vec<u8>> {
        self.relay.ask(id, ttl).await.ok()?;
        self.wait_for(|msg| msg.eq(id)).await
    }

    /// Return all buffered messages
    pub fn buffered(&self) -> impl Iterator<Item = &[u8]> {
        self.in_buf.iter().map(|m| m.as_ref())
    }

    /// Return all buffered messages and allow change
    pub fn buffered_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        self.in_buf.iter_mut().map(|m| m.as_mut())
    }
}

impl<R: Relay> Stream for BufferedMsgRelay<R> {
    type Item = R::Item;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(msg) = this.in_buf.pop() {
            Poll::Ready(Some(msg))
        } else {
            this.relay.poll_next_unpin(cx)
        }
    }
}

impl<R: Relay> Sink<Vec<u8>> for BufferedMsgRelay<R> {
    type Error = R::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_ready_unpin(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.get_mut().relay.start_send_unpin(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_flush_unpin(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_close_unpin(cx)
    }
}

impl<R: Relay> Relay for BufferedMsgRelay<R> {}

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
