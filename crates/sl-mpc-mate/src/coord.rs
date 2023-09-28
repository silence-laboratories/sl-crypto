use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BinaryHeap, HashMap};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

pub use futures_util::{Sink, SinkExt, Stream, StreamExt};

use crate::message::*;

pub trait Relay:
    Stream<Item = Vec<u8>>
    + Sink<Vec<u8>, Error = InvalidMessage>
    + Unpin
    + 'static
{
}

impl<T> Relay for T
where
    T: Stream<Item = Vec<u8>>,
    T: Sink<Vec<u8>, Error = InvalidMessage>,
    T: Unpin,
    T: 'static,
{
}

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

    pub fn put(&mut self, msg: Vec<u8>) {
        self.in_buf.push(msg)
    }

    pub async fn wait_for(
        &mut self,
        predicate: impl Fn(&MsgId) -> bool,
    ) -> Option<Vec<u8>> {
        // first, look into the input buffer
        if let Some(idx) = self.in_buf.iter().position(|msg| {
            MsgHdr::from(msg)
                .filter(|hdr| predicate(&hdr.id))
                .is_some()
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
                // FIXME here we simple drop invaid message. How to handle?
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

        self.send(msg).await.ok()?;

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
        self.0.partial_cmp(&other.0).map(Ordering::reverse)
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
    type Error = InvalidMessage;

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

        let hdr =
            MsgHdr::from(&item).ok_or(InvalidMessage::MessageTooShort)?;

        let mut inner = this.inner.lock().unwrap();

        if hdr.kind == Kind::Ask {
            if let Some(msg) = inner.recv(hdr.id, hdr.ttl, &this.tx) {
                this.queue.push(msg);
            }
        } else {
            tracing::info!("pub msg {:X}", hdr.id);
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
                    tracing::info!("msg send dup {:?}", id)
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
                        if *prev < expire {
                            *prev = expire;
                        }
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
        let sk = SigningKey::from_bytes(&rand::random());

        let coord = SimpleMessageRelay::new();

        let mut c1 = coord.connect();

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(0),
        );

        c1.send(
            Builder::<Signed>::encode(
                &msg_id,
                Duration::new(10, 0),
                &sk,
                &(0u32, 255u64),
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let mut c2 = coord.connect();

        c2.send(AskMsg::allocate(&msg_id, 100)).await.unwrap();

        let mut msg = c2.next().await.unwrap();

        let payload: (u32, u64) = Message::verify_and_decode(
            Message::from_buffer(&mut msg).unwrap(),
            &sk.verifying_key(),
        )
        .unwrap();

        assert_eq!(payload, (0u32, 255u64));
    }
}
