// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use bytes::{Bytes, BytesMut};
use fastwebsockets::{
    FragmentCollectorRead, Frame, OpCode, Payload, WebSocket, WebSocketError,
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::relay::{MessageSendError, Relay, Sender, SplitSender};

enum Output {
    Msg(Bytes),
    Frame(Frame<'static>),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
struct FastSender {
    tx: mpsc::Sender<Output>,
}

pub struct FastRelay {
    tx: FastSender,
    rx: mpsc::Receiver<BytesMut>,
}

impl FastRelay {
    pub fn new<S>(socket: WebSocket<S>, output_buffer: usize) -> Self
    where
        S: AsyncWrite + AsyncRead + Unpin + Send + 'static,
    {
        let (rs, mut wr) = socket.split(io::split);

        let tx = {
            let (tx, mut rx) = mpsc::channel::<Output>(output_buffer);

            tokio::spawn(async move {
                while let Some(output) = rx.recv().await {
                    match output {
                        Output::Msg(msg) => {
                            let frame =
                                Frame::binary(Payload::Borrowed(&msg));
                            if let Err(_err) = wr.write_frame(frame).await {
                                // TODO log error
                                return;
                            }
                        }

                        Output::Frame(frame) => {
                            if let Err(_err) = wr.write_frame(frame).await {
                                // TODO log error
                                return;
                            }
                        }

                        Output::Flush(notify) => {
                            if let Err(_err) = wr.flush().await {
                                // TODO log error
                                return;
                            }

                            // Unsuccessful call send here means that
                            // corresponding receiver was dropped and
                            // there is no task to notify about
                            // completion of flush operation.
                            let _ = notify.send(());
                        }
                    }
                }
            });

            tx
        };

        let rx = {
            let send_tx = tx.clone();

            let mut rs = FragmentCollectorRead::new(rs);

            let (tx, rx) = mpsc::channel::<BytesMut>(1);

            tokio::spawn(async move {
                let mut sender = |f| async {
                    let _ = send_tx.send(Output::Frame(f)).await;

                    Ok::<_, WebSocketError>(())
                };

                let _rs = loop {
                    let frame = tokio::select! {
                        frame = rs.read_frame(&mut sender) => {
                            if let Ok(frame) = frame {
                                frame
                            } else {
                                break rs;
                            }
                        }

                        _ = tx.closed() => {
                            break rs;
                        }
                    };

                    if frame.opcode != OpCode::Binary {
                        break rs;
                    }

                    let msg = match frame.payload {
                        Payload::Bytes(msg) => msg,

                        Payload::Owned(vec) => {
                            // There is no direct way to build
                            // BytesMut from Vec<u8>.  But we can
                            // create Bytes::from(vec)
                            let bytes = Bytes::from(vec);

                            // and then convert Bytes to BytesMut
                            bytes.try_into_mut().unwrap()
                        }

                        payload => BytesMut::from(&*payload),
                    };

                    if tx.send(msg).await.is_err() {
                        // FastRelay was dropped, so `rx` was dropped
                        // too.
                        break rs;
                    }
                };

                // TODO: use `_rs` to recombine it with write side to
                // get initial WebSocket.
            });

            rx
        };

        Self {
            tx: FastSender { tx },
            rx,
        }
    }

    pub async fn close(&self) {
        todo!()
    }

    pub async fn text(
        &mut self,
        message: &str,
    ) -> Result<(), MessageSendError> {
        self.tx.text(message).await
    }
}

impl Relay for FastRelay {
    async fn next(&mut self) -> Option<BytesMut> {
        self.rx.recv().await
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        self.tx.flush().await
    }

    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        self.tx.feed(message).await
    }
}

impl SplitSender for FastRelay {
    fn split_sender(&self) -> impl Sender + 'static {
        self.tx.clone()
    }
}

impl Sender for FastSender {
    async fn flush(&self) -> Result<(), MessageSendError> {
        let (tx, rx) = oneshot::channel();

        self.tx
            .send(Output::Flush(tx))
            .await
            .map_err(|_| MessageSendError)?;

        rx.await.map_err(|_| MessageSendError)
    }

    async fn feed(&self, message: Bytes) -> Result<(), MessageSendError> {
        self.tx
            .send(Output::Msg(message))
            .await
            .map_err(|_| MessageSendError)
    }
}

impl FastSender {
    async fn text(&self, message: &str) -> Result<(), MessageSendError> {
        let frame = Frame::text(Payload::Owned(message.as_bytes().to_vec()));
        self.tx
            .send(Output::Frame(frame))
            .await
            .map_err(|_| MessageSendError)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use fastwebsockets::Role;
    use tokio::net::UnixStream;

    use super::*;

    use crate::message::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn ws() -> io::Result<()> {
        let (tx, rx) = UnixStream::pair()?;

        let mut ws1 = WebSocket::after_handshake(tx, Role::Client);
        let ws2 = WebSocket::after_handshake(rx, Role::Server);

        ws1.write_frame(Frame::new(
            true,
            OpCode::Ping,
            None,
            Payload::Borrowed(&[]),
        ))
        .await
        .unwrap();

        let r1 = FastRelay::new(ws1, 1);
        let mut r2 = FastRelay::new(ws2, 1);

        let inst = InstanceId::new([1; 32]);
        let id = MsgId::new(&inst, &[1], None, MessageTag::tag(1));

        r1.ask(&id, Duration::from_secs(10)).await.unwrap();

        let msg1 = r2.next().await.unwrap();

        assert_eq!(msg1.len(), MESSAGE_HEADER_SIZE);

        let hdr1 = <&MsgHdr>::try_from(msg1.as_ref()).unwrap();

        assert_eq!(&id, hdr1.id());

        assert_eq!(hdr1.ttl(), Duration::from_secs(10));

        Ok(())
    }
}
