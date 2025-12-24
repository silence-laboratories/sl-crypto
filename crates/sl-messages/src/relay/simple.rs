// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BinaryHeap, HashMap},
    future::poll_fn,
    mem,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::Instant,
};

pub use crate::{message::MESSAGE_HEADER_SIZE, relay::*};

pub(crate) struct Expire {
    pub expire: Instant,
    pub id: MsgId,
}

impl Expire {
    pub(crate) fn new(expire: Instant, id: MsgId) -> Self {
        Self { expire, id }
    }
}

impl PartialEq for Expire {
    fn eq(&self, other: &Self) -> bool {
        self.expire.eq(&other.expire)
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
        other.expire.cmp(&self.expire)
    }
}

pub trait InputQueue: Default + Send + Sync {
    /// Current number of messages in the queue.
    fn message_count(&self) -> usize;

    /// Push new message.
    fn push_message(&mut self, message: BytesMut);

    /// Pop a message from the queue.
    fn pop_message(&mut self) -> Option<BytesMut>;
}

impl InputQueue for Vec<BytesMut> {
    fn message_count(&self) -> usize {
        self.len()
    }

    fn push_message(&mut self, message: BytesMut) {
        self.push(message)
    }

    fn pop_message(&mut self) -> Option<BytesMut> {
        self.pop()
    }
}

struct MessageQueue<Q> {
    queue: Q,
    waker: Vec<Waker>,
    closed: bool,
}

pub struct WeakMessageQueueHandle<Q>(Weak<Mutex<MessageQueue<Q>>>);

pub struct MessageQueueHandle<Q>(Arc<Mutex<MessageQueue<Q>>>);

impl<Q: InputQueue> Default for MessageQueueHandle<Q> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(MessageQueue {
            queue: Q::default(),
            waker: Vec::with_capacity(1),
            closed: false,
        })))
    }
}

impl<Q> MessageQueueHandle<Q> {
    pub fn weak(&self) -> WeakMessageQueueHandle<Q> {
        WeakMessageQueueHandle(Arc::downgrade(&self.0))
    }
}

impl<Q> WeakMessageQueueHandle<Q> {
    pub fn upgrade(&self) -> Option<MessageQueueHandle<Q>> {
        Weak::upgrade(&self.0).map(MessageQueueHandle)
    }
}

impl<Q> Clone for MessageQueueHandle<Q> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Q: InputQueue> MessageQueue<Q> {
    fn push(&mut self, message: BytesMut) {
        self.queue.push_message(message);
        if let Some(waker) = self.waker.pop() {
            waker.wake();
        }
    }

    fn close(&mut self) {
        self.closed = true;

        for waker in mem::take(&mut self.waker) {
            waker.wake()
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<BytesMut>> {
        if self.closed {
            return Poll::Ready(None);
        }

        if let Some(msg) = self.queue.pop_message() {
            Poll::Ready(Some(msg))
        } else {
            let waker = cx.waker();
            if !self.waker.iter().any(|w| w.will_wake(waker)) {
                self.waker.push(waker.clone());
            }

            Poll::Pending
        }
    }
}

impl<Q: InputQueue> MessageQueueHandle<Q> {
    pub fn push(&self, message: BytesMut) {
        self.0.lock().unwrap().push(message);
    }

    pub fn close(&self) {
        self.0.lock().unwrap().close();
    }

    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<BytesMut>> {
        self.0.lock().unwrap().poll_recv(cx)
    }
}

enum MsgEntry<Q> {
    Waiters(Vec<WeakMessageQueueHandle<Q>>),
    Ready(Bytes),
}

pub type SimpleMessageRelay = MsgRelay<Vec<BytesMut>>;

#[derive(Clone)]
pub struct MsgRelay<Q> {
    inner: Arc<Mutex<Inner<Q>>>,
}

impl<Q: InputQueue> MsgRelay<Q> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                expire: BinaryHeap::new(),
                messages: HashMap::new(),
                externals: vec![],
            })),
        }
    }

    fn handle_message(&self, msg: Bytes, tx: Option<&MessageQueueHandle<Q>>) {
        self.inner.lock().unwrap().handle_message(msg, tx);
    }

    pub fn send(&self, msg: Bytes) {
        self.handle_message(msg, None);
    }

    /// Create connection. If `external` is true then new connection
    /// will receive all ASK messages from all other connections.
    pub fn connection(&self, external: bool) -> MsgRelayConnection<Q> {
        let queue = MessageQueueHandle::default();
        if external {
            self.inner.lock().unwrap().externals.push(queue.weak());
        }

        MsgRelayConnection {
            inner: self.inner.clone(),
            queue,
        }
    }

    /// Create internal connection. I won't recevice ASK messages from
    /// other connections.
    pub fn connect(&self) -> MsgRelayConnection<Q> {
        self.connection(false)
    }
}

#[derive(Clone)]
struct SimpleSender<Q> {
    inner: Arc<Mutex<Inner<Q>>>,
    queue: MessageQueueHandle<Q>,
}

pub struct MsgRelayConnection<Q> {
    inner: Arc<Mutex<Inner<Q>>>,
    queue: MessageQueueHandle<Q>,
}

impl<Q: InputQueue> MsgRelayConnection<Q> {
    pub fn get(&mut self, id: &MsgId) -> Option<Bytes> {
        let tbl = self.inner.lock().ok()?;

        match tbl.messages.get(id) {
            Some(MsgEntry::Ready(msg)) => Some(msg.clone()),
            _ => None,
        }
    }
}

struct Inner<Q> {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry<Q>>,
    externals: Vec<WeakMessageQueueHandle<Q>>,
}

impl<Q: InputQueue> Inner<Q> {
    fn cleanup_later(&mut self, id: MsgId, expire: Instant) {
        self.expire.push(Expire::new(expire, id));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(ent) = self.expire.peek() {
            if ent.expire > now {
                break;
            }

            self.messages.remove(&ent.id);
            self.expire.pop();
        }
    }

    fn handle_message(
        &mut self,
        msg: Bytes,
        tx: Option<&MessageQueueHandle<Q>>,
    ) {
        let hdr = match <&MsgHdr>::try_from(msg.as_ref()) {
            Ok(hdr) => hdr,
            Err(_) => return,
        };

        let is_ask = msg.len() == MESSAGE_HEADER_SIZE;

        let now = Instant::now();
        let msg_id = *hdr.id();
        let msg_expire = now + hdr.ttl();
        let one_receiver = hdr.is_one_receiver();

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(msg_id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready(msg) => {
                        if is_ask {
                            // Got an ASK for a Ready message.
                            // Send the message immediately.
                            if let Some(q) = tx {
                                let msg = if <&MsgHdr>::try_from(msg.as_ref())
                                    .map(|hdr| hdr.is_one_receiver())
                                    .unwrap_or(false)
                                {
                                    let msg = core::mem::take(msg);
                                    ocp.remove();
                                    msg
                                } else {
                                    msg.clone()
                                };

                                q.push(BytesMut::from(msg));
                            }
                        }
                    }

                    MsgEntry::Waiters(waiters) => {
                        if is_ask {
                            // join other waiters
                            if let Some(tx) = tx {
                                waiters.push(tx.weak());
                            }
                        } else {
                            if one_receiver && waiters.len() == 1 {
                                let w = waiters.pop().unwrap();
                                if let Some(q) = w.upgrade() {
                                    q.push(BytesMut::from(msg));
                                }
                                ocp.remove_entry();
                                return;
                            }

                            // wake up all waiters
                            for w in waiters.drain(..) {
                                if let Some(q) = w.upgrade() {
                                    q.push(BytesMut::from(msg.clone()));
                                }
                            }

                            // and replace with a Read message
                            ocp.insert(MsgEntry::Ready(msg));
                        };
                    }
                }
            }

            Entry::Vacant(vac) => {
                if is_ask {
                    // This is the first ASK for the message
                    if let Some(q) = tx {
                        vac.insert(MsgEntry::Waiters(vec![q.weak()]));
                    }

                    // broadcast ASK message to all external
                    // connections.
                    let mut i = 0;
                    while let Some(w) = self.externals.get(i) {
                        if let Some(q) = w.upgrade() {
                            q.push(msg.clone().into());
                            i += 1;
                        } else {
                            self.externals.swap_remove(i);
                        }
                    }
                } else {
                    vac.insert(MsgEntry::Ready(msg));
                };

                self.cleanup_later(msg_id, msg_expire);
            }
        };
    }
}

impl<Q: InputQueue> Sender for SimpleSender<Q> {
    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        let q = (message.len() == MESSAGE_HEADER_SIZE).then_some(&self.queue);

        self.inner.lock().unwrap().handle_message(message, q);

        Ok(())
    }
}

impl<Q: InputQueue> Relay for MsgRelayConnection<Q> {
    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        let q = (message.len() == MESSAGE_HEADER_SIZE).then_some(&self.queue);

        self.inner.lock().unwrap().handle_message(message, q);

        Ok(())
    }

    fn next(&mut self) -> impl Future<Output = Option<BytesMut>> {
        poll_fn(|cx| self.queue.poll_recv(cx))
    }
}

impl<Q: InputQueue + 'static> SplitSender for MsgRelayConnection<Q> {
    fn split_sender(&self) -> impl Sender + 'static {
        SimpleSender {
            inner: self.inner.clone(),
            queue: self.queue.clone(),
        }
    }
}

impl<Q: InputQueue + 'static> InjectMessage for MsgRelayConnection<Q> {
    fn inject_message(&self, msg: Bytes) {
        assert!(msg.len() > MESSAGE_HEADER_SIZE);
        self.inner.lock().unwrap().handle_message(msg, None)
    }
}

impl<Q: InputQueue> MessageRelayService for MsgRelay<Q> {
    type MessageRelay = MsgRelayConnection<Q>;

    async fn connect(&self) -> Option<Self::MessageRelay> {
        Some(self.connect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_msg(ttl: u32, size: usize) -> Vec<u8> {
        let mut msg = vec![0; 32 + 4 + size];

        msg[32..32 + 4].copy_from_slice(&ttl.to_be_bytes());

        msg
    }

    #[test]
    fn expire() {
        let now = Instant::now();

        let e1 = Expire::new(now, MsgId::from([0; 32]));
        let e2 =
            Expire::new(now + Duration::from_secs(10), MsgId::from([0; 32]));

        assert!(e1 > e2);
    }

    #[test]
    fn handle_msg() {
        let app = MsgRelay::<Vec<BytesMut>>::new();

        let msg = Bytes::from(dummy_msg(10, 100));

        let _hdr = <&MsgHdr>::try_from(msg.as_ref()).unwrap();

        app.handle_message(msg, None);
    }

    #[tokio::test]
    async fn coord() {
        let sk = &[100];

        let coord = MsgRelay::<Vec<BytesMut>>::new();

        let c1 = coord.connect();

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            sk,
            None,
            MessageTag::tag(0),
        );

        let msg_to_send =
            allocate_message(&msg_id, Duration::from_secs(10), 0, &[0; 5]);
        c1.send(msg_to_send.clone()).await.unwrap();

        let mut c2 = coord.connect();

        c2.send(allocate_message(&msg_id, Duration::from_secs(100), 0, &[]))
            .await
            .unwrap();

        let msg_recv = c2.next().await.unwrap();

        assert_eq!(msg_to_send, msg_recv);
    }
}
