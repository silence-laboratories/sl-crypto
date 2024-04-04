// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BinaryHeap, HashMap},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

pub use futures_util::{Sink, SinkExt, Stream, StreamExt};

use crate::{coord::Relay, message::*};

use super::{MessageRelayService, MessageSendError};

#[derive(Debug)]
struct Expire(Instant, MsgId, Kind);

impl PartialEq for Expire {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for Expire {}

impl PartialOrd for Expire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expire {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

#[derive(Debug)]
enum MsgEntry {
    Waiters((Instant, Vec<mpsc::Sender<Vec<u8>>>)),
    Ready(Vec<u8>),
}

/// Implementation of in-memory message relay to run local test etc.
pub struct MessageRelay {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    queue: Vec<Vec<u8>>,
    inner: Arc<Mutex<Inner>>,
}

impl Stream for MessageRelay {
    type Item = Vec<u8>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(msg) = self.queue.pop() {
            Poll::Ready(Some(msg))
        } else {
            self.rx.poll_recv(cx)
        }
    }
}

impl Sink<Vec<u8>> for MessageRelay {
    type Error = MessageSendError;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        let this = &mut *self;

        let hdr = MsgHdr::from(&item).ok_or(MessageSendError)?;

        let mut inner = this.inner.lock().unwrap();

        if hdr.kind == Kind::Ask {
            if let Some(msg) = inner.recv(hdr.id, hdr.ttl, &this.tx) {
                this.queue.push(msg);
            }
        } else {
            inner.send(item);
        }

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Relay for MessageRelay {}

#[derive(Debug, Default)]
pub struct SimpleMessageRelay {
    inner: Arc<Mutex<Inner>>,
}

impl SimpleMessageRelay {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }

    pub fn connect(&self) -> MessageRelay {
        let (tx, rx) = mpsc::channel(100);

        MessageRelay {
            rx,
            tx,
            queue: vec![],
            inner: self.inner.clone(),
        }
    }

    pub fn messages(&self) -> Vec<MsgId> {
        self.inner
            .lock()
            .unwrap()
            .messages
            .keys()
            .cloned()
            .collect()
    }

    pub fn send(&self, msg: Vec<u8>) {
        self.inner.lock().unwrap().send(msg);
    }
}

impl MessageRelayService for SimpleMessageRelay {
    type MessageRelay = MessageRelay;

    async fn connect(&self) -> Option<Self::MessageRelay> {
        Some(Self::connect(self))
    }
}

#[derive(Debug, Default)]
struct Inner {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
}

impl Inner {
    pub fn new() -> Self {
        Self {
            expire: BinaryHeap::new(),
            messages: HashMap::new(),
        }
    }

    fn cleanup_later(&mut self, id: MsgId, expire: Instant, kind: Kind) {
        self.expire.push(Expire(expire, id, kind));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(ent) = self.expire.peek() {
            if ent.0 > now {
                break;
            }

            let Expire(_, id, kind) = self.expire.pop().unwrap();

            if let Entry::Occupied(ocp) = self.messages.entry(id) {
                match ocp.get() {
                    MsgEntry::Ready(_) => {
                        if kind == Kind::Pub {
                            ocp.remove();
                        }
                    }

                    MsgEntry::Waiters((expire, _)) => {
                        if kind == Kind::Ask && *expire <= now {
                            ocp.remove();
                        }
                    }
                }
            }
        }
    }

    pub fn send(&mut self, msg: Vec<u8>) {
        let MsgHdr { id, ttl, kind } = MsgHdr::from(&msg).unwrap();
        let now = Instant::now();
        let expire = now + ttl;

        assert!(kind == Kind::Pub);

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => match ocp.get_mut() {
                MsgEntry::Waiters((_, b)) => {
                    // wake up all waiters
                    for tx in b.drain(..) {
                        let msg = msg.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(msg).await;
                        });
                    }
                    // and replace with a Read message
                    ocp.insert(MsgEntry::Ready(msg));

                    // remember to cleanup this entry later
                    self.cleanup_later(id, expire, kind);
                }
                MsgEntry::Ready(_) => {
                    // ignore dups
                }
            },

            Entry::Vacant(vac) => {
                vac.insert(MsgEntry::Ready(msg));

                self.cleanup_later(id, expire, kind);
            }
        }
    }

    fn recv(
        &mut self,
        id: MsgId,
        ttl: Duration,
        tx: &mpsc::Sender<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let now = Instant::now();
        let expire = now + ttl;

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready(msg) => {
                        // send the message immediately
                        return Some(msg.clone());
                    }

                    MsgEntry::Waiters((prev, b)) => {
                        // join other waiters
                        *prev = expire.max(*prev);
                        b.push(tx.clone());

                        // remember to cleanup this entry later
                        self.cleanup_later(id, expire, Kind::Ask);
                    }
                }
            }

            Entry::Vacant(vac) => {
                // This is the first ASK for the message
                vac.insert(MsgEntry::Waiters((expire, vec![tx.clone()])));

                self.cleanup_later(id, expire, Kind::Ask);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expire() {
        let now = Instant::now();

        let e1 = Expire(now, MsgId::ZERO_ID, Kind::Pub);
        let e2 = Expire(now, MsgId::ZERO_ID, Kind::Pub);
        let e3 =
            Expire(now + Duration::new(10, 0), MsgId::ZERO_ID, Kind::Pub);
        assert!(e1 >= e2);
        assert!(e1 > e3);
    }

    #[tokio::test]
    async fn coord() {
        let sk = &[100];

        let coord = SimpleMessageRelay::new();

        let mut c1 = coord.connect();

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            sk,
            None,
            MessageTag::tag(0),
        );

        let msg_to_send = allocate_message(&msg_id, 10, &[0; 5]);
        c1.send(msg_to_send.clone()).await.unwrap();

        let mut c2 = coord.connect();

        c2.send(AskMsg::allocate(&msg_id, 100)).await.unwrap();

        let msg_recv = c2.next().await.unwrap();

        assert_eq!(msg_to_send, msg_recv);
    }
}
