// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::{future::Future, time::Duration};

pub use bytes::{Bytes, BytesMut};

use crate::message::*;

mod buffered;

#[cfg(feature = "std")]
pub mod adversary;
#[cfg(feature = "std")]
pub mod simple;
#[cfg(feature = "std")]
pub mod stats;
#[cfg(feature = "std")]
pub mod trace;

#[cfg(feature = "mux")]
pub mod mux;

#[cfg(feature = "setup")]
pub use buffered::BufferedError;
pub use buffered::BufferedMsgRelay;
#[cfg(feature = "std")]
pub use simple::SimpleMessageRelay;

#[derive(Debug, Copy, Clone)]
pub struct MessageSendError;

pub trait Sender: Send + Sync {
    /// Prepare a message to output. Possibly putting into an output queue.
    fn feed(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send;

    /// Send the message and flush the output queue, if any.
    fn send(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send {
        async move {
            self.feed(message).await?;
            self.flush().await
        }
    }

    /// Flush all pending/buffered messages.
    fn flush(
        &self,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send {
        async { Ok(()) }
    }
}

pub trait SplitSender {
    fn split_sender(&self) -> impl Sender + 'static;
}

pub trait Relay: Send + Sync {
    /// Send the message and flush the output queue, if any.
    fn send(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send {
        async move {
            self.feed(message).await?;
            self.flush().await
        }
    }

    /// Prepare a message to output. Possibly putting into an output queue.
    fn feed(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send;

    /// Flush all pending/buffered messages.
    fn flush(
        &self,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send {
        async { Ok(()) }
    }

    fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), MessageSendError>> + Send {
        self.feed(allocate_message(id, ttl, 0, &[]))
    }

    /// Receive a message. Returns `None` if the underlying connection is closed.
    fn next(&mut self) -> impl Future<Output = Option<BytesMut>> + Send;
}

pub trait InjectMessage {
    fn inject_message(&self, msg: Bytes);
}

impl<R: Relay> Relay for &mut R {
    fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), MessageSendError>> {
        (**self).ask(id, ttl)
    }

    fn feed(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> {
        (**self).feed(message)
    }

    fn flush(&self) -> impl Future<Output = Result<(), MessageSendError>> {
        (**self).flush()
    }

    fn send(
        &self,
        message: Bytes,
    ) -> impl Future<Output = Result<(), MessageSendError>> {
        (**self).send(message)
    }

    fn next(&mut self) -> impl Future<Output = Option<BytesMut>> {
        (**self).next()
    }
}

pub struct SkipAsk<R> {
    relay: R,
    skip: bool,
}

impl<R: Relay> SkipAsk<R> {
    pub fn new(relay: R) -> Self {
        Self { relay, skip: true }
    }

    pub fn with_ask(self) -> Self {
        let Self { relay, .. } = self;
        Self { relay, skip: false }
    }

    pub fn with_ask_if(self, ask: bool) -> Self {
        let Self { relay, .. } = self;
        Self { relay, skip: !ask }
    }
}

impl<R: Relay> Relay for SkipAsk<R> {
    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        if self.skip {
            Ok(())
        } else {
            self.relay.ask(id, ttl).await
        }
    }

    async fn send(&self, message: Bytes) -> Result<(), MessageSendError> {
        self.relay.send(message).await
    }

    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        self.relay.feed(message).await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.relay.flush().await
    }

    async fn next(&mut self) -> Option<BytesMut> {
        self.relay.next().await
    }
}

impl<R: SplitSender> SplitSender for SkipAsk<R> {
    fn split_sender(&self) -> impl Sender + 'static {
        self.relay.split_sender()
    }
}

pub trait MessageRelayService {
    type MessageRelay: Relay;

    fn connect(&self) -> impl Future<Output = Option<Self::MessageRelay>>;
}
