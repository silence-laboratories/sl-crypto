// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    collections::HashMap,
    future::poll_fn,
    mem,
    sync::{Arc, Mutex},
};

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    message::*,
    relay::{
        MessageRelayService, MessageSendError, Relay, Sender, SplitSender,
        simple::MessageQueueHandle,
    },
};

enum Output {
    Msg(Bytes),
    Ask(Bytes, MessageQueueHandle<Vec<BytesMut>>),
    Flush(oneshot::Sender<()>),
}

/// Relay multiplexer.
///
/// It multiplexes messages between one external connection and a set of
/// internal connections.
///
/// When one of the internal connections sends (publishes) a message,
/// it is transmitted directly to the external connection.
///
/// A table mapping message IDs and destination internal connections
/// is maintained to handle ASK messages.
///
/// ASK messages from the external connection is broadcasted to all
/// internal collections.
///
///
pub struct MsgRelayMux {
    tx: mpsc::Sender<Output>,
    br: broadcast::Sender<Bytes>,
}

pub struct InternalConnection {
    tx: mpsc::Sender<Output>,
    input: MessageQueueHandle<Vec<BytesMut>>,
    br: broadcast::Receiver<Bytes>,
}

impl MsgRelayMux {
    /// Creates a new instance with the given relay and buffer sizes.
    ///
    /// # Parameters
    /// - `relay`: relay object of an external connection.
    ///
    /// - `output_buffer`: buffer size for outgoing messages.
    ///
    /// - `input_ask_buffer`: buffer size for ASK messages from
    ///   internal connections.
    ///
    pub fn new<R>(
        mut relay: R,
        output_buffer: usize,
        input_ask_buffer: usize,
    ) -> Self
    where
        R: Relay + SplitSender + Send + 'static,
    {
        let asks = Arc::new(Mutex::new(HashMap::new()));

        let tx = {
            let (tx, mut rx) = mpsc::channel::<Output>(output_buffer);

            let sender = relay.split_sender();

            tokio::spawn({
                let asks = asks.clone();
                async move {
                    while let Some(output) = rx.recv().await {
                        match output {
                            Output::Msg(msg) => {
                                if sender.feed(msg).await.is_err() {
                                    break;
                                }
                            }

                            Output::Flush(notify) => {
                                if sender.flush().await.is_err() {
                                    break;
                                }

                                // Unsuccessful call to send() here
                                // means that corresponding receiver
                                // was dropped and there is no task to
                                // notify about completion of flush
                                // operation.
                                let _ = notify.send(());
                            }

                            Output::Ask(msg, q) => {
                                if let Ok(id) = MsgId::try_from(msg.as_ref())
                                {
                                    asks.lock().unwrap().insert(id, q);
                                }

                                if sender.feed(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }

                    rx.close();

                    let asks = mem::take(&mut *asks.lock().unwrap());

                    for q in asks.into_values() {
                        q.close();
                    }
                }
            });

            tx
        };

        let (br, _) = broadcast::channel(input_ask_buffer);

        let input_asks = br.clone();

        tokio::spawn(async move {
            while let Some(msg) = relay.next().await {
                if msg.len() == MESSAGE_HEADER_SIZE {
                    // broadcast ASK message to all internal
                    // connections.
                    let _ = input_asks.send(msg.into());
                } else {
                    if let Some(q) = <&MsgId>::try_from(msg.as_ref())
                        .ok()
                        .and_then(|id| asks.lock().unwrap().remove(id))
                    {
                        q.push(msg);
                    }
                }
            }
        });

        Self { tx, br }
    }
}

impl MessageRelayService for MsgRelayMux {
    type MessageRelay = InternalConnection;

    async fn connect(&self) -> Option<Self::MessageRelay> {
        Some(InternalConnection {
            tx: self.tx.clone(),
            input: MessageQueueHandle::default(),
            br: self.br.subscribe(),
        })
    }
}

impl Relay for InternalConnection {
    async fn next(&mut self) -> Option<BytesMut> {
        loop {
            tokio::select!(
                msg = poll_fn(|cx| self.input.poll_recv(cx)) => return msg,
                ask = self.br.recv() => {
                    // recv() can't fail because there are at least
                    // two Senders: MsgRelayMux.br and and
                    // `input_asks` inside task handling input
                    // messages from external connection.
                    if let Ok(bytes) = ask {
                        return Some(bytes.into());
                    }
                }
            )
        }
    }

    async fn feed(&self, msg: Bytes) -> Result<(), MessageSendError> {
        let output = if msg.len() == MESSAGE_HEADER_SIZE {
            Output::Ask(msg, self.input.clone())
        } else {
            Output::Msg(msg)
        };

        self.tx.send(output).await.map_err(|_| MessageSendError)
    }

    async fn flush(&self) -> Result<(), MessageSendError> {
        let (tx, rx) = oneshot::channel();

        self.tx
            .send(Output::Flush(tx))
            .await
            .map_err(|_| MessageSendError)?;

        rx.await.map_err(|_| MessageSendError)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::{
        message::{InstanceId, MessageTag, MsgId, allocate_message},
        relay::SimpleMessageRelay,
    };

    use super::*;

    fn mk_msg(id: &MsgId) -> Bytes {
        allocate_message(id, Duration::from_secs(10), 0, &[0, 255])
    }

    //
    // c1 -+                       +- m1
    //      \                     /
    //       +-- S <-ext-> Mux --+
    //      /                     \
    // c2 -+                       +- m2
    //
    // If we send an ASK on either c1 or c2, if should be broadcasted
    // to m1 and m2.
    //
    //
    #[tokio::test(flavor = "multi_thread")]
    async fn mux() {
        let sk = &[1];
        let instance = InstanceId::from([1u8; 32]);

        let s = SimpleMessageRelay::new();

        let _c1 = s.connect();
        let mut c2 = s.connect();

        let mux = MsgRelayMux::new(s.connection(true), 1, 1);

        let mut m1 = mux.connect().await.unwrap();
        let mut m2 = mux.connect().await.unwrap();

        let msg_0_id = MsgId::new(&instance, sk, None, MessageTag::tag(0));
        let msg_0 = mk_msg(&msg_0_id);

        // request a msg_0 on m1
        m1.ask(&msg_0_id, Duration::from_secs(10)).await.unwrap();

        // c2 -> s -> c1 -> m1
        c2.send(msg_0.clone()).await.unwrap();

        let msg_0_in = m1.next().await.unwrap();

        assert_eq!(msg_0, msg_0_in);

        let msg_1_id = MsgId::new(&instance, sk, None, MessageTag::tag(1));
        let msg_1 = mk_msg(&msg_1_id);

        // m2 -> ext -> s -> c2
        m2.send(msg_1.clone()).await.unwrap();

        // request msg_1
        c2.ask(&msg_1_id, Duration::from_secs(10)).await.unwrap();

        // recv msg_1
        let msg_1_in = c2.next().await.unwrap();

        assert_eq!(msg_1, msg_1_in);

        let msg_2_id = MsgId::new(&instance, sk, None, MessageTag::tag(2));
        c2.ask(&msg_2_id, Duration::from_secs(10)).await.unwrap();

        let ask_m1 = m1.next().await.unwrap();
        let ask_m2 = m2.next().await.unwrap();

        assert_eq!(ask_m1, ask_m2);

        assert_eq!(MsgId::try_from(ask_m1.as_ref()).unwrap(), msg_2_id);
    }
}
