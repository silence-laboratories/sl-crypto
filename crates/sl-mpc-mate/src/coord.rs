// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub use futures_util::{Sink, SinkExt, Stream, StreamExt};

use crate::message::*;

mod buffered;

pub mod adversary;
pub mod simple;
pub mod stats;

pub use buffered::BufferedMsgRelay;
pub use simple::SimpleMessageRelay;

pub struct MessageSendError;

pub trait Relay:
    Stream<Item = Vec<u8>>
    + Sink<Vec<u8>, Error = InvalidMessage>
    + Unpin
    + 'static
{
}

impl<T> Relay for T
where
    T: Stream<Item = Vec<u8>>,
    T: Sink<Vec<u8>, Error = InvalidMessage>,
    T: Unpin,
    T: 'static,
{
}

pub trait MessageRelayService<R: Relay> {
    fn connect(&self) -> R;
}
