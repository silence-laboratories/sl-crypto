#![allow(dead_code)]

use std::{
    collections::HashSet,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use crate::coord::simple::{MessageRelay, SimpleMessageRelay};
use crate::coord::*;

type Cond = Box<dyn FnMut(&HashSet<MsgId>, usize) -> bool + Send>;

struct Inject {
    msg: Vec<u8>,
    cond: Cond,
}

pub struct EvilPlay {
    drop_msg: Vec<(MsgId, Option<usize>)>,
    seen_msg: HashSet<MsgId>,
    injects: Vec<Inject>,
}

impl EvilPlay {
    pub fn new() -> Self {
        Self {
            drop_msg: vec![],
            seen_msg: HashSet::new(),
            injects: vec![],
        }
    }

    pub fn drop_message(mut self, msg: MsgId, party: Option<usize>) -> Self {
        self.drop_msg.extend(&[(msg, party)]);

        self
    }

    pub fn inject_message<F>(mut self, msg: Vec<u8>, cond: F) -> Self
    where
        F: FnMut(&HashSet<MsgId>, usize) -> bool + Send + 'static,
    {
        let cond = Box::new(cond);
        self.injects.push(Inject { msg, cond });

        self
    }

    fn injection(&mut self, party: usize) -> Option<Vec<u8>> {
        for (i, inject) in self.injects.iter_mut().enumerate() {
            if (inject.cond)(&self.seen_msg, party) {
                let inject = self.injects.swap_remove(i);
                return Some(inject.msg);
            }
        }

        None
    }

    fn poll_next<R: Relay>(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut R,
        party: usize,
    ) -> Poll<Option<Vec<u8>>> {
        // injections
        if let Some(msg) = self.injection(party) {
            return Poll::Ready(Some(msg));
        }

        // receive and drops
        loop {
            match client.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,

                Poll::Ready(None) => return Poll::Ready(None),

                Poll::Ready(Some(msg)) => {
                    if let Some(MsgHdr { id, .. }) = MsgHdr::from(&msg) {
                        // check drops
                        if self.drop_msg.iter().any(|(mid, idx)| {
                            mid.eq(&id) && idx.unwrap_or(party) == party
                        }) {
                            continue;
                        }
                    }

                    return Poll::Ready(Some(msg));
                }
            }
        }
    }

    fn start_send<R: Relay>(
        &mut self,
        client: &mut R,
        _index: usize,
        msg: Vec<u8>,
    ) -> Result<(), InvalidMessage> {
        if let Some(hdr) = MsgHdr::from(&msg) {
            self.seen_msg.insert(hdr.id);
        }

        client.start_send_unpin(msg)
    }
}

impl Default for EvilPlay {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Connection {
    inner: Arc<Mutex<EvilPlay>>,
    relay: MessageRelay,
    index: usize,
    input: Vec<Vec<u8>>,
}

pub struct EvilMessageRelay {
    inner: Arc<Mutex<EvilPlay>>,
    relay: SimpleMessageRelay,
    conns: AtomicUsize,
}

impl EvilMessageRelay {
    pub fn new(screenplay: EvilPlay) -> Self {
        Self {
            inner: Arc::new(Mutex::new(screenplay)),
            relay: SimpleMessageRelay::new(),
            conns: AtomicUsize::new(0),
        }
    }

    pub fn connect(&self) -> Connection {
        let relay = self.relay.connect();
        let inner = self.inner.clone();
        let index = self.conns.fetch_add(1, Ordering::SeqCst);

        Connection {
            relay,
            inner,
            index,
            input: vec![],
        }
    }
}

impl MessageRelayService<Connection> for EvilMessageRelay {
    fn connect(&self) -> Connection {
        Self::connect(self)
    }
}

impl Stream for Connection {
    type Item = Vec<u8>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        this.inner
            .lock()
            .unwrap()
            .poll_next(cx, &mut this.relay, this.index)
    }
}

impl Sink<Vec<u8>> for Connection {
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

        this.inner.lock().unwrap().start_send(
            &mut this.relay,
            this.index,
            item,
        )
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
