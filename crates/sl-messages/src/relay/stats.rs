// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::relay::*;

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub send_count: usize,
    pub flush_count: usize,
    pub send_size: usize,
    pub recv_size: usize,
    pub recv_count: usize,
    pub wait_time: Duration,
    pub wait_times: Vec<(MsgId, Duration)>,
    pub ask_count: usize,
}

impl Stats {
    pub fn alloc() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn inner(stats: Arc<Mutex<Self>>) -> Self {
        stats.lock().unwrap().clone()
    }
}

struct StatSender<S> {
    sender: S,
    stats: Arc<Mutex<Stats>>,
}

pub struct RelayStats<R: Relay> {
    relay: R,
    stats: Arc<Mutex<Stats>>,
}

impl<R: Relay> RelayStats<R> {
    pub fn new(relay: R, stats: Arc<Mutex<Stats>>) -> Self {
        Self { relay, stats }
    }
}

fn count_feed(stats: &Mutex<Stats>, message_len: usize) {
    if let Ok(mut stats) = stats.lock() {
        stats.send_size += message_len;
        if message_len == MESSAGE_HEADER_SIZE {
            stats.ask_count += 1;
        }
        stats.send_count += 1;
    }
}

impl<R: Relay + Send + Sync> Relay for RelayStats<R> {
    async fn next(&mut self) -> Option<BytesMut> {
        let start = Instant::now();
        let msg = self.relay.next().await;
        let wait_time = start.elapsed();

        if let Ok(mut stats) = self.stats.lock() {
            if let Some(msg) = &msg {
                stats.recv_size += msg.len();
                if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_ref()) {
                    stats.wait_times.push((*hdr.id(), wait_time));
                }
            }

            stats.recv_count += 1;
            stats.wait_time += wait_time;
        }

        msg
    }

    fn feed(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> {
        count_feed(&self.stats, message.len());
        self.relay.feed(message)
    }

    fn flush(&self) -> impl Future<Output = Result<(), MessageSendError>> {
        self.relay.flush()
    }

    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(id, ttl).await
    }
}

impl<R: Relay + SplitSender> SplitSender for RelayStats<R> {
    fn split_sender(&self) -> impl Sender + 'static {
        let sender = self.relay.split_sender();

        StatSender {
            sender,
            stats: self.stats.clone(),
        }
    }
}

impl<S: Sender> Sender for StatSender<S> {
    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        count_feed(&self.stats, message.len());
        self.sender.feed(message).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.sender.flush().await
    }
}

impl<R: Relay> Deref for RelayStats<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl<R: Relay> DerefMut for RelayStats<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.relay
    }
}
