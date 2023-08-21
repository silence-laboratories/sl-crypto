use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::{sync::oneshot, time::timeout};

use crate::message::*;

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
    Waiters((Instant, Vec<oneshot::Sender<Vec<u8>>>)),
    Ready(Vec<u8>),
}

#[derive(Clone)]
pub struct MessageRelay {
    inner: Arc<Mutex<CoordInner>>,
}
unsafe impl Send for MessageRelay {}

impl MessageRelay {
    /// Send or publish a message. Other parties could receive
    /// the message by MsgId.
    pub fn send(&self, msg: Vec<u8>) {
        if let Some(hdr) = MsgHdr::from(&msg) {
            println!("send {:?} {}", hdr.id, msg.len());
            self.inner.lock().unwrap().send(hdr, msg, None);
        }
    }

    /// Ask the message relay for a message with given ID and
    /// wait for it up to given timeout.
    pub async fn recv(self, id: MsgId, ttl: u32) -> Option<Vec<u8>> {
        let msg = AskMsg::allocate(&id, ttl);
        let hdr = MsgHdr::from(&msg).unwrap();

        println!("want {:?}", id);

        let (tx, rx) = oneshot::channel();

        self.inner.lock().unwrap().send(hdr, msg, Some(tx));

        timeout(Duration::new(ttl as u64, 0), async { rx.await.ok() })
            .await
            .ok()?
    }
}

#[derive(Debug)]
pub struct SimpleMessageRelay {
    inner: Arc<Mutex<CoordInner>>,
}

impl SimpleMessageRelay {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoordInner::new())),
        }
    }

    pub fn connect(&self) -> MessageRelay {
        MessageRelay {
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

#[derive(Debug)]
struct CoordInner {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
}

impl CoordInner {
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

    fn send(
        &mut self,
        hdr: MsgHdr,
        msg: Vec<u8>,
        mut tx: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let MsgHdr { id, ttl, kind } = hdr;

        debug_assert!(kind == Kind::Pub || tx.is_some());

        let now = Instant::now();
        let expire = now + ttl;

        // we have a locked state, let's cleanup some old entries
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => {
                match ocp.get_mut() {
                    MsgEntry::Ready(msg) => {
                        if matches!(kind, Kind::Ask) {
                            // got an ASK for a Ready message
                            // send the message immediately
                            let _ = tx.take().unwrap().send(msg.clone());
                        }
                    }

                    MsgEntry::Waiters((prev, b)) => {
                        if kind == Kind::Ask {
                            // join other waiters
                            if *prev < expire {
                                *prev = expire;
                            }
                            b.push(tx.take().unwrap());
                        } else {
                            // wake up all waiters
                            for tx in b.drain(..) {
                                let msg = msg.clone();
                                let _ = tx.send(msg.clone());
                            }
                            // and replace with a Read message
                            ocp.insert(MsgEntry::Ready(msg));
                        }

                        // remember to cleanup this entry later
                        self.cleanup_later(id, expire, kind);
                    }
                }
            }

            Entry::Vacant(vac) => {
                if matches!(kind, Kind::Ask) {
                    // This is the first ASK for the message
                    vac.insert(MsgEntry::Waiters((
                        expire,
                        vec![tx.take().unwrap()],
                    )));
                } else {
                    vac.insert(MsgEntry::Ready(msg));
                }

                self.cleanup_later(id, expire, kind);
            }
        }
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

        let c1 = coord.connect();

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(0),
        );

        c1.send(
            Builder::<Signed>::encode(&msg_id, 10, &sk, &(0u32, 255u64))
                .unwrap(),
        );

        let c2 = coord.connect();

        let mut msg = c2.recv(msg_id, 100).await.unwrap();

        let payload: (u32, u64) = Message::verify_and_decode(
            Message::from_buffer(&mut msg).unwrap(),
            &sk.verifying_key(),
        )
        .unwrap();

        assert_eq!(payload, (0u32, 255u64));
    }
}
