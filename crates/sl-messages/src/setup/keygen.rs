// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Setup message implementation for key generation protocols.
//!
//! The [`SetupMessage`] type provides a concrete implementation of
//! [`crate::setup::KeygenSetupMessage`] and [`crate::setup::ProtocolParticipant`]
//! using signer/verifier generics.

use std::{marker::PhantomData, time::Duration};

use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};

use crate::message::InstanceId;

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

use crate::setup::{
    keys::{NoSignature, NoSigningKey, NoVerifyingKey},
    KeygenSetupMessage, ProtocolParticipant, WeightedKeygenSetupMessage,
};

/// Concrete setup context for key-generation rounds.
pub struct SetupMessage<
    SK = NoSigningKey,
    VK = NoVerifyingKey,
    MS = NoSignature,
> {
    total_parties: usize,
    threshold: usize,
    party_id: usize,
    ranks: Vec<u8>,
    sk: SK,
    vk: Vec<VK>,
    key_id: Option<[u8; 32]>,
    instance_id: InstanceId,
    ttl: Duration,
    weights: Vec<u16>,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
    /// Creates a key-generation setup message.
    ///
    /// `ranks` should contain one rank per participant in `vk`.
    pub fn new(
        instance_id: InstanceId,
        sk: SK,
        party_id: usize,
        vk: Vec<VK>,
        ranks: &[u8],
        threshold: usize,
    ) -> Self {
        Self {
            total_parties: vk.len(),
            threshold,
            party_id,
            sk,
            vk,
            instance_id,
            key_id: None,
            ttl: Duration::from_secs(DEFAULT_TTL),
            ranks: ranks.to_vec(),
            weights: vec![],
            marker: PhantomData,
        }
    }

    /// Overrides default message TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets an explicit key identifier to return from
    /// [`KeygenSetupMessage::derive_key_id`].
    pub fn with_key_id(mut self, key_id: Option<[u8; 32]>) -> Self {
        self.key_id = key_id;
        self
    }

    /// Configures optional participant weights.
    ///
    /// These weights are stored for compatibility with weighted keygen flows.
    pub fn with_weights(mut self, weights: &[u16]) -> Self {
        self.weights = weights.to_vec();
        self
    }

    /// Returns explicitly configured key ID bytes, if present.
    pub fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_ref().map(AsRef::as_ref)
    }
}

impl<SK, VK, MS> ProtocolParticipant for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    fn total_participants(&self) -> usize {
        self.total_parties
    }

    fn participant_index(&self) -> usize {
        self.party_id
    }

    fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }
}

impl<SK, VK, MS> KeygenSetupMessage for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn threshold(&self) -> u8 {
        self.threshold as u8
    }

    fn participant_rank(&self, index: usize) -> u8 {
        self.ranks[index]
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        self.key_id
            .unwrap_or_else(|| Sha256::digest(public_key).into())
    }
}

impl<SK, VK, MS> WeightedKeygenSetupMessage for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    fn participant_weight(&self, index: usize) -> u16 {
        self.weights.get(index).cloned().unwrap_or(1)
    }

    fn weighted_threshold(&self) -> u16 {
        self.threshold as u16
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        self.key_id
            .unwrap_or_else(|| Sha256::digest(public_key).into())
    }
}
