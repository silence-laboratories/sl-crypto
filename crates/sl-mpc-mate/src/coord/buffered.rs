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
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            in_buf: vec![],
        }
    }

    pub async fn wait_for(
        &mut self,
        predicate: impl Fn(&MsgId) -> bool,
    ) -> Option<Vec<u8>> {
        // first, look into the input buffer
        if let Some(idx) = self.in_buf.iter().position(|msg| {
            MsgHdr::from(msg).filter(|hdr| predicate(&hdr.id)).is_some()
        }) {
            // good catch, remove from the buffer and return
            return Some(self.in_buf.swap_remove(idx));
        }

        loop {
            // well, we have to poll_next() something suitable.
            let msg = self.relay.next().await?;

            let id = if let Some(hdr) = MsgHdr::from(&msg) {
                hdr.id
            } else {
                // FIXME here we drop an invalid message. How to handle?
                continue;
            };

            if predicate(&id) {
                // good, got it, return
                return Some(msg);
            } else {
                // push into the buffer and try again
                self.in_buf.push(msg);
            }
        }
    }

    pub async fn recv(&mut self, id: &MsgId, ttl: u32) -> Option<Vec<u8>> {
        let msg = AskMsg::allocate(id, ttl);

        self.relay.send(msg).await.ok()?;

        self.wait_for(|msg| msg.eq(id)).await
    }
}

impl<R: Relay> Stream for BufferedMsgRelay<R> {
    type Item = R::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(msg) = self.in_buf.pop() {
            Poll::Ready(Some(msg))
        } else {
            self.relay.poll_next_unpin(cx)
        }
    }
}

impl<R: Relay> Sink<Vec<u8>> for BufferedMsgRelay<R> {
    type Error = R::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.relay.start_send_unpin(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.relay.poll_close_unpin(cx)
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
