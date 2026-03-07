// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{sync::Mutex, time::Duration};

use crate::{
    message::{InstanceId, MsgId},
    relay::{Bytes, BytesMut, MessageSendError, Relay},
    setup::{
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        ProtocolParticipant,
    },
};

pub(super) const TEST_TIMEOUT: Duration = Duration::from_millis(250);

pub(super) struct TestParticipant {
    me: usize,
    verifiers: Vec<NoVerifyingKey>,
    signer: NoSigningKey,
    instance: InstanceId,
}

impl TestParticipant {
    pub(super) fn new(total: usize, me: usize) -> Self {
        Self {
            me,
            verifiers: (0..total).map(NoVerifyingKey::new).collect(),
            signer: NoSigningKey,
            instance: InstanceId::from([7u8; 32]),
        }
    }
}

impl ProtocolParticipant for TestParticipant {
    type MessageSignature = NoSignature;
    type MessageSigner = NoSigningKey;
    type MessageVerifier = NoVerifyingKey;

    fn total_participants(&self) -> usize {
        self.verifiers.len()
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.verifiers[index]
    }

    fn signer(&self) -> &Self::MessageSigner {
        &self.signer
    }

    fn participant_index(&self) -> usize {
        self.me
    }

    fn instance_id(&self) -> &InstanceId {
        &self.instance
    }

    fn message_ttl(&self) -> Duration {
        Duration::from_secs(10)
    }
}

#[derive(Default)]
pub(super) struct AskRecorderRelay {
    asks: Mutex<Vec<(MsgId, Duration)>>,
}

impl AskRecorderRelay {
    pub(super) fn asks(&self) -> Vec<(MsgId, Duration)> {
        self.asks.lock().unwrap().clone()
    }
}

impl Relay for AskRecorderRelay {
    async fn ask(
        &self,
        id: &MsgId,
        ttl: Duration,
    ) -> Result<(), MessageSendError> {
        self.asks.lock().unwrap().push((*id, ttl));
        Ok(())
    }

    async fn feed(&self, _message: Bytes) -> Result<(), MessageSendError> {
        Ok(())
    }

    async fn next(&mut self) -> Option<BytesMut> {
        None
    }
}
