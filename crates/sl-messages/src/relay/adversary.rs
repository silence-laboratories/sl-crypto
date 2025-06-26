// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    Bytes, BytesMut,
    message::{MsgHdr, MsgId},
    relay::{
        MessageRelayService, MessageSendError, Relay,
        simple::{MsgRelayConnection, SimpleMessageRelay},
    },
};

type Cond = Box<dyn FnMut(&HashSet<MsgId>, usize) -> bool + Send>;

struct Inject {
    msg: BytesMut,
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
        let mut bytes = BytesMut::with_capacity(msg.len());
        bytes.extend_from_slice(&msg);
        let cond = Box::new(cond);
        self.injects.push(Inject { msg: bytes, cond });

        self
    }

    fn injection(&mut self, party: usize) -> Option<BytesMut> {
        for (i, inject) in self.injects.iter_mut().enumerate() {
            if (inject.cond)(&self.seen_msg, party) {
                let inject = self.injects.swap_remove(i);
                return Some(inject.msg);
            }
        }

        None
    }
}

impl Default for EvilPlay {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Connection {
    inner: Arc<Mutex<EvilPlay>>,
    relay: MsgRelayConnection<Vec<BytesMut>>,
    index: usize,
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
        }
    }
}

impl MessageRelayService for EvilMessageRelay {
    type MessageRelay = Connection;

    async fn connect(&self) -> Option<Self::MessageRelay> {
        Some(Self::connect(self))
    }
}

impl Relay for Connection {
    async fn next(&mut self) -> Option<BytesMut> {
        let party = self.index;

        // injections
        if let Some(msg) = self.inner.lock().unwrap().injection(party) {
            return Some(msg);
        }

        // receive and drops
        loop {
            let msg = self.relay.next().await?;

            if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_ref()) {
                // check drops
                if self.inner.lock().unwrap().drop_msg.iter().any(
                    |(mid, idx)| {
                        mid == hdr.id() && idx.unwrap_or(party) == party
                    },
                ) {
                    continue;
                }
            }

            return Some(msg);
        }
    }

    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_ref()) {
            self.inner.lock().unwrap().seen_msg.insert(*hdr.id());
        }

        self.relay.feed(msg).await
    }
}
