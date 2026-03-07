// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Setup message implementation for signing protocols.
//!
//! The [`SetupMessage`] type implements both
//! [`crate::setup::PreSignSetupMessage`] and
//! [`crate::setup::SignSetupMessage`].

use std::{marker::PhantomData, str::FromStr, sync::Arc, time::Duration};

use derivation_path::DerivationPath;
use signature::{SignatureEncoding, Signer, Verifier};

use crate::{
    message::InstanceId,
    setup::{
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        PreSignSetupMessage, ProtocolParticipant, SignSetupMessage,
    },
};

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// Default message hash used by [`SetupMessage`] when one is not provided.
pub const DEFAULT_MSG_HASH: [u8; 32] = [1; 32];

/// Concrete setup context for pre-sign and sign rounds.
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
    KS = (),
> {
    party_idx: usize,
    sk: SK,
    vk: Vec<VK>,
    instance: InstanceId,
    keyshare: Arc<KS>,
    chain_path: DerivationPath,
    ttl: Duration,
    hash: [u8; 32],
    marker: PhantomData<MS>,
}

impl<SK, VK, MS, KS> SetupMessage<SK, VK, MS, KS> {
    /// Creates a sign setup message.
    pub fn new(
        instance: InstanceId,
        sk: SK,
        party_idx: usize,
        vk: Vec<VK>,
        keyshare: Arc<KS>,
    ) -> Self {
        Self {
            party_idx,
            sk,
            vk,
            instance,
            keyshare,
            ttl: Duration::from_secs(DEFAULT_TTL),
            chain_path: DerivationPath::from_str("m").unwrap(),
            hash: DEFAULT_MSG_HASH,
            marker: PhantomData,
        }
    }

    /// Sets the derivation path used by this signing session.
    pub fn with_chain_path(mut self, chain_path: DerivationPath) -> Self {
        self.chain_path = chain_path;
        self
    }

    /// Sets the hash used by [`SignSetupMessage::message_hash`].
    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = hash;
        self
    }

    /// Sets the hash only when `Some`.
    pub fn with_hash_opt(mut self, hash: Option<[u8; 32]>) -> Self {
        if let Some(hash) = hash {
            self.hash = hash;
        }
        self
    }

    /// Overrides default message TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Clones and returns the keyshare handle.
    pub fn clone_keyshare(&self) -> Arc<KS> {
        self.keyshare.clone()
    }

    /// Returns the configured derivation path.
    pub fn chain_path(&self) -> &DerivationPath {
        &self.chain_path
    }
}

impl<SK, VK, MS, KS> ProtocolParticipant for SetupMessage<SK, VK, MS, KS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    fn instance_id(&self) -> &InstanceId {
        &self.instance
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn participant_index(&self) -> usize {
        self.party_idx
    }

    fn total_participants(&self) -> usize {
        self.vk.len()
    }
}

impl<SK, VK, MS, KS> PreSignSetupMessage<KS> for SetupMessage<SK, VK, MS, KS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn chain_path(&self) -> &DerivationPath {
        &self.chain_path
    }

    fn keyshare(&self) -> &KS {
        &self.keyshare
    }
}

impl<SK, VK, MS, KS> SignSetupMessage<KS> for SetupMessage<SK, VK, MS, KS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn message_hash(&self) -> [u8; 32] {
        self.hash
    }
}
