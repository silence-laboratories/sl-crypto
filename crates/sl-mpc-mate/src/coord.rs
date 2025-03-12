// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub use futures_util::{sink::Feed, Sink, SinkExt, Stream, StreamExt};

use crate::message::*;

mod buffered;

pub mod stats;

#[cfg(feature = "simple-relay")]
pub mod adversary;
#[cfg(feature = "simple-relay")]
pub mod simple;
#[cfg(feature = "simple-relay")]
pub use simple::SimpleMessageRelay;

pub use buffered::BufferedMsgRelay;

#[derive(Debug, Copy, Clone)]
pub struct MessageSendError;

pub struct MaybeFeed<'a, S: ?Sized>(Option<Feed<'a, S, Vec<u8>>>);

impl<'a, Si: Sink<Vec<u8>> + Unpin> MaybeFeed<'a, Si> {
    pub fn new(feed: Feed<'a, Si, Vec<u8>>) -> Self {
        Self(Some(feed))
    }

    pub fn skip() -> Self {
        Self(None)
    }
}

impl<Si: Sink<Vec<u8>> + Unpin> Future for MaybeFeed<'_, Si> {
    type Output = Result<(), Si::Error>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match &mut self.get_mut().0 {
            None => Poll::Ready(Ok(())),
            Some(feed) => Pin::new(feed).poll(cx),
        }
    }
}

pub trait Relay:
    Stream<Item = Vec<u8>> + Sink<Vec<u8>, Error = MessageSendError> + Unpin
{
    fn ask(&mut self, id: &MsgId, ttl: u32) -> MaybeFeed<'_, Self> {
        MaybeFeed(Some(self.feed(AskMsg::allocate(id, ttl))))
    }
}

pub trait MessageRelayService {
    type MessageRelay: Relay;

    fn connect(&self) -> impl Future<Output = Option<Self::MessageRelay>>;
}
