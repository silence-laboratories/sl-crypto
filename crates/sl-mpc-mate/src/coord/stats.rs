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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match this.relay.poll_next_unpin(cx) {
            Poll::Ready(Some(msg)) => {
                let waiting = this.waiting.take();
                let mut stats = this.stats.lock().unwrap();

                stats.recv_size += msg.len();
                stats.recv_count += 1;

                let wait_time = waiting
                    .map(|start| start.elapsed())
                    .unwrap_or(Duration::new(0, 0));

                if let Ok(hdr) = <&MsgHdr>::try_from(msg.as_slice()) {
                    stats.wait_times.push((*hdr.id(), wait_time));
                }

                stats.wait_time += wait_time;

                Poll::Ready(Some(msg))
            }

            Poll::Ready(None) => Poll::Ready(None),

            Poll::Pending => {
                if this.waiting.is_none() {
                    // mark the beginning of message waiting
                    this.waiting = Some(Instant::now());
                }

                Poll::Pending
            }
        }
    }
}

impl<R: Relay> Sink<Vec<u8>> for RelayStats<R> {
    type Error = <R as Sink<Vec<u8>>>::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_ready_unpin(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        let _ = self.stats.lock().map(|mut stats| {
            stats.send_size += item.len();
            stats.send_count += 1;
        });

        self.get_mut().relay.start_send_unpin(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_flush_unpin(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().relay.poll_close_unpin(cx)
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
