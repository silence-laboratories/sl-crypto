// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use crate::coord::*;

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub send_count: usize,
    pub send_size: usize,
    pub recv_size: usize,
    pub recv_count: usize,
    pub wait_time: Duration,
    pub wait_times: Vec<(MsgId, Duration)>,
}

impl Stats {
    pub fn alloc() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn inner(stats: Arc<Mutex<Self>>) -> Self {
        stats.lock().unwrap().clone()
    }
}

pub struct RelayStats<R: Relay> {
    relay: R,
    stats: Arc<Mutex<Stats>>,
    waiting: Option<Instant>,
}

impl<R: Relay> RelayStats<R> {
    pub fn new(relay: R, stats: Arc<Mutex<Stats>>) -> Self {
        Self {
            relay,
            stats,
            waiting: None,
        }
    }
}

impl<R: Relay> Stream for RelayStats<R> {
    type Item = <R as Stream>::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.relay.poll_next_unpin(cx) {
            Poll::Ready(Some(msg)) => {
                let waiting = self.waiting.take();
                let mut stats = self.stats.lock().unwrap();

                stats.recv_size += msg.len();
                stats.recv_count += 1;

                let wait_time = waiting
                    .map(|start| start.elapsed())
                    .unwrap_or(Duration::new(0, 0));

                if let Some(hdr) = MsgHdr::from(&msg) {
                    stats.wait_times.push((hdr.id, wait_time));
                }

                stats.wait_time += wait_time;

                Poll::Ready(Some(msg))
            }

            Poll::Ready(None) => Poll::Ready(None),

            Poll::Pending => {
                if self.waiting.is_none() {
                    self.waiting = Some(Instant::now());
                }

                Poll::Pending
            }
        }
    }
}

impl<R: Relay> Sink<Vec<u8>> for RelayStats<R> {
    type Error = <R as Sink<Vec<u8>>>::Error;

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
        let mut stats = self.stats.lock().unwrap();

        stats.send_size += item.len();
        stats.send_count += 1;

        drop(stats);

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

impl<R: Relay> Relay for RelayStats<R> {}

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
