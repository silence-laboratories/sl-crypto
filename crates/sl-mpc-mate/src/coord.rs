// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub use futures_util::{Sink, SinkExt, Stream, StreamExt};

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

pub trait Relay:
    Stream<Item = Vec<u8>>
    + Sink<Vec<u8>, Error = MessageSendError>
    + Unpin
    + 'static
{
}

impl<T> Relay for T
where
    T: Stream<Item = Vec<u8>>,
    T: Sink<Vec<u8>, Error = MessageSendError>,
    T: Unpin,
    T: 'static,
{
}

pub trait MessageRelayService<R: Relay> {
    fn connect(&self) -> R;
}
