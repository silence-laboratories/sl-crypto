use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::mpsc::{channel, Receiver};
use tokio_util::sync::PollSender;

use futures_util::{Sink, Stream};

use super::MessageSendError;

/// Simple two party message relay
pub struct SimplePair {
    out: PollSender<Vec<u8>>,
    inq: Receiver<Vec<u8>>,
}

impl SimplePair {
    /// Create a connected pair of message relays
    pub fn connect() -> (SimplePair, SimplePair) {
        let (out_tx, out_rx) = channel(1);
        let (in_tx, in_rx) = channel(1);

        let client = SimplePair {
            out: PollSender::new(out_tx),
            inq: in_rx,
        };

        let server = SimplePair {
            out: PollSender::new(in_tx),
            inq: out_rx,
        };

        (client, server)
    }
}

impl Stream for SimplePair {
    type Item = Vec<u8>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.get_mut().inq.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for SimplePair {
    type Error = MessageSendError;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .out
            .poll_reserve(cx)
            .map_err(|_| MessageSendError)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.get_mut()
            .out
            .send_item(item)
            .map_err(|_| MessageSendError)
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
        self.get_mut().out.close();

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use futures_util::{SinkExt, StreamExt};

    #[tokio::test]
    async fn pair() {
        let (mut p1, mut p2) = SimplePair::connect();

        p1.send(vec![1, 2]).await.unwrap();

        let m = p2.next().await.unwrap();
        assert_eq!(&m, &[1, 2]);

        p2.send(vec![3, 4]).await.unwrap();

        let m = p1.next().await.unwrap();
        assert_eq!(&m, &[3, 4]);
    }
}
