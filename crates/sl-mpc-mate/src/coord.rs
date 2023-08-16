use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;

use crate::message::*;
use crate::state::*;

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

enum MsgEntry {
    Waiters((Instant, Vec<mpsc::Sender<Vec<u8>>>)),
    Ready(Vec<u8>),
}

#[derive(Clone)]
pub struct Sender {
    tx: mpsc::Sender<Vec<u8>>,
    inner: Arc<Mutex<CoordInner>>,
}

impl Sender {
    pub fn send(&mut self, msg: Vec<u8>) {
        if let Some(hdr) = MsgHdr::from(&msg) {
            self.inner
                .lock()
                .unwrap()
                .handle_message(hdr, msg, &self.tx);
        }
    }
}

pub struct Receiver {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Receiver {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

pub struct Coord {
    inner: Arc<Mutex<CoordInner>>,
}

impl Coord {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoordInner::new())),
        }
    }

    pub fn connect(&self) -> (Sender, Receiver) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);

        let send = Sender {
            tx,
            inner: self.inner.clone(),
        };
        let recv = Receiver { rx };

        (send, recv)
    }
}

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

    fn cleanup_later(
        &mut self,
        id: MsgId,
        expire: Instant,
        kind: Kind,
    ) {
        self.expire.push(Expire(expire, id, kind));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(ent) = self.expire.peek() {
            if ent.0 < now {
                break;
            }

            let Expire(_, id, kind) = self.expire.pop().unwrap();

            if let Entry::Occupied(ocp) = self.messages.entry(id) {
                match ocp.get() {
                    MsgEntry::Ready(_) => {
                        if matches!(kind, Kind::Pub) {
                            ocp.remove();
                        }
                    }

                    MsgEntry::Waiters((expire, _)) => {
                        if matches!(kind, Kind::Ask) && *expire <= now {
                            ocp.remove();
                        }
                    }
                }
            }
        }
    }

    pub fn handle_message(
        &mut self,
        hdr: MsgHdr,
        msg: Vec<u8>,
        tx: &mpsc::Sender<Vec<u8>>,
    ) {
        let MsgHdr { id, ttl, kind } = hdr;

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
                            let tx = tx.clone();
                            let msg = msg.clone();
                            tokio::spawn(async move {
                                // ignore send error
                                let _ = tx.send(msg).await;
                            });
                        } else {
                            // ignore the duplicate message
                        }
                    }

                    MsgEntry::Waiters((prev, b)) => {
                        if matches!(kind, Kind::Ask) {
                            // join other waiters
                            if *prev < expire {
                                *prev = expire;
                            }
                            b.push(tx.clone());
                        } else {
                            // wake up all waiters
                            for s in b.drain(..) {
                                let msg = msg.clone();
                                tokio::spawn(async move {
                                    let _ = s.send(msg).await;
                                });
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
                        vec![tx.clone()],
                    )));
                } else {
                    vac.insert(MsgEntry::Ready(msg));
                }

                self.cleanup_later(id, expire, kind);
            }
        }
    }
}

impl OutputQueue for Sender {
    fn wait(&mut self, msg_id: &MsgId, ttl: u32) {
        self.send(AskMsg::allocate(msg_id, ttl));
    }

    fn publish(&mut self, msg: Vec<u8>) {
        self.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(id: &MsgId, sk: &SigningKey) -> Vec<u8> {
        let mut msg = Builder::<Signed>::allocate(&id, 254, 8);

        let mut writer = msg.writer();

        let config = bincode::config::standard();

        bincode::encode_into_writer(&[1u8; 8], &mut writer, config)
            .unwrap();

        msg.sign(&sk).unwrap()
    }

    #[tokio::test]
    async fn coord() {
        let sk = SigningKey::from_bytes(&rand::random());

        let coord = Coord::new();

        let (mut tx1, mut rx1) = coord.connect();

        let msg_id = MsgId::new(
            &InstanceId::from([0; 32]),
            &sk.verifying_key().as_bytes(),
            None,
            MessageTag::tag(0),
        );

        tx1.wait(&msg_id, 100);

        let (mut tx2, _rx2) = coord.connect();

        tx2.send(make_msg(&msg_id, &sk));

        let mut mbody = rx1.recv().await.unwrap();

        let msg = Message::from_buffer(&mut mbody).unwrap();

        let mut reader = msg.verify(&sk.verifying_key()).unwrap();

        let config = bincode::config::standard();

        let payload: [u8; 8] =
            bincode::decode_from_reader(&mut reader, config).unwrap();

        //        let payload: [u8; 8] = msg.decode().unwrap();

        assert_eq!(payload, [1; 8]);
    }
}
