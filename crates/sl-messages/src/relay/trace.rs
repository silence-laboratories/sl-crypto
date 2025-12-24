// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::time::Duration;

use crate::{
    message::MsgId,
    relay::{MessageSendError, Relay, Sender, SplitSender},
    Bytes, BytesMut,
};

pub trait TraceNextExt: Relay + Sized {
    fn trace_next<F>(self, trace: F) -> TraceNext<Self, F>
    where
        F: Fn(Option<(&MsgId, usize)>) + Send + Sync,
    {
        TraceNext { relay: self, trace }
    }
}

impl<R: Relay + Sized> TraceNextExt for R {}

pub trait TraceFeedExt: Relay + Sized {
    fn trace_feed<F>(self, trace: F) -> TraceFeed<Self, F>
    where
        F: Fn(&MsgId, usize) + Send + Sync,
    {
        TraceFeed { relay: self, trace }
    }
}

impl<R: Relay + Sized> TraceFeedExt for R {}

pub trait TraceAskExt: Relay + Sized {
    fn trace_ask<F>(self, trace: F) -> TraceAsk<Self, F>
    where
        F: Fn(&MsgId, Duration) + Send + Sync,
    {
        TraceAsk { relay: self, trace }
    }
}

impl<R: Relay + Sized> TraceAskExt for R {}

pub struct TraceNext<R, F> {
    relay: R,
    trace: F,
}

pub struct TraceFeed<R, F> {
    relay: R,
    trace: F,
}

pub struct TraceSender<R, F> {
    sender: R,
    trace: F,
}

pub struct TraceAsk<R, F> {
    relay: R,
    trace: F,
}

impl<R: Relay, F> Relay for TraceNext<R, F>
where
    F: Fn(Option<(&MsgId, usize)>) + Send + Sync,
{
    async fn next(&mut self) -> Option<BytesMut> {
        let msg = self.relay.next().await;

        let id = msg.as_ref().and_then(|m| {
            <&MsgId>::try_from(m.as_ref()).ok().map(|id| (id, m.len()))
        });

        (self.trace)(id);

        msg
    }

    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        self.relay.feed(msg).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.relay.flush().await
    }

    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(id, ttl).await
    }
}

impl<R: Relay + SplitSender, F> SplitSender for TraceNext<R, F>
where
    F: Fn(Option<(&MsgId, usize)>) + Send + Sync,
{
    fn split_sender(&self) -> impl Sender + 'static {
        self.relay.split_sender()
    }
}

impl<R: Relay, F> Relay for TraceFeed<R, F>
where
    F: Fn(&MsgId, usize) + Send + Sync,
{
    async fn next(&mut self) -> Option<BytesMut> {
        self.relay.next().await
    }

    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        if let Ok(id) = <&MsgId>::try_from(msg.as_ref()) {
            (self.trace)(id, msg.len());
        }

        self.relay.feed(msg).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.relay.flush().await
    }

    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(id, ttl).await
    }
}

impl<R: Relay + SplitSender, F> SplitSender for TraceFeed<R, F>
where
    F: Fn(&MsgId, usize) + Send + Sync + Clone + 'static,
{
    fn split_sender(&self) -> impl Sender + 'static {
        TraceSender::new(self.relay.split_sender(), self.trace.clone())
    }
}

impl<R: Sender, F> TraceSender<R, F> {
    fn new(sender: R, trace: F) -> Self {
        Self { sender, trace }
    }
}

impl<S, F> Sender for TraceSender<S, F>
where
    S: Sender,
    F: Fn(&MsgId, usize) + Send + Sync,
{
    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        if let Ok(id) = <&MsgId>::try_from(msg.as_ref()) {
            (self.trace)(id, msg.len());
        }

        self.sender.feed(msg).await
    }

    async fn send(&self, message: Bytes) -> Result<(), MessageSendError> {
        self.sender.send(message).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.sender.flush().await
    }
}

impl<R: Relay, F> Relay for TraceAsk<R, F>
where
    F: Fn(&MsgId, Duration) + Send + Sync,
{
    async fn next(&mut self) -> Option<BytesMut> {
        self.relay.next().await
    }

    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        self.relay.feed(msg).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.relay.flush().await
    }

    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        (self.trace)(id, ttl);
        self.relay.ask(id, ttl).await
    }
}

impl<R: Relay + SplitSender, F> SplitSender for TraceAsk<R, F>
where
    F: Fn(&MsgId, Duration) + Send + Sync,
{
    fn split_sender(&self) -> impl Sender + 'static {
        self.relay.split_sender()
    }
}
