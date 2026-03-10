// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::time::Duration;

use derivation_path::DerivationPath;
use signature::{SignatureEncoding, Signer, Verifier};

use crate::message::{InstanceId, MessageTag, MsgId};

/// An iterator for parties in range 0..total except me.
pub struct AllOtherParties {
    total: usize,
    me: usize,
    curr: usize,
}

impl Iterator for AllOtherParties {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let val = self.curr;

            if val >= self.total {
                return None;
            }

            self.curr += 1;

            if val != self.me {
                return Some(val);
            }
        }
    }
}

impl ExactSizeIterator for AllOtherParties {
    fn len(&self) -> usize {
        self.total - 1
    }
}

/// A type that provides protocol participant details.
///
/// Construction of a value of this type should carefully validate the
/// verifying keys of all parties. It is crucial to recognize the keys
/// of all participants using either a database of known keys or X.509
/// certificates.
///
/// The type defines how messages will be signed and how to verify the
/// signatures.
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of a SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type used to verify signed messages, a verifying key. `AsRef<[u8]>` is
    /// used to get external representation of the key to derive message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Returns total number of participants of a distributed protocol.
    fn total_participants(&self) -> usize;

    /// Returns the verifying key for messages from a participant with
    /// the given index.
    fn verifier(&self, index: usize) -> &Self::MessageVerifier;

    /// Returns a signer to sign messages from the participant.
    fn signer(&self) -> &Self::MessageSigner;

    /// Returns an index of the participant in a protocol.
    /// This is a value in range 0..self.total_participants()
    fn participant_index(&self) -> usize;

    /// Returns the protocol's execution instance ID.
    ///
    /// Each execution of a distributed protocol requires a unique
    /// instance ID to derive the IDs of all messages within that
    /// execution.
    fn instance_id(&self) -> &InstanceId;

    /// Returns the message time-to-live.
    fn message_ttl(&self) -> Duration;

    /// Returns a reference to the participant's own verifier.
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Returns an iterator of all participants except self.
    fn all_other_parties(&self) -> AllOtherParties {
        AllOtherParties {
            curr: 0,
            total: self.total_participants(),
            me: self.participant_index(),
        }
    }

    /// Generates an ID for a message from this party to another party,
    /// or for a broadcast message if the receiver is `None`.
    fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        self.msg_id_from(self.participant_index(), receiver, tag)
    }

    /// Generates an ID for a message from a given sender to a given receiver.
    /// The receiver is identified by its index and is `None` for a broadcast
    /// message.
    fn msg_id_from(
        &self,
        sender: usize,
        receiver: Option<usize>,
        tag: MessageTag,
    ) -> MsgId {
        let receiver = receiver
            .map(|p| self.verifier(p))
            .map(AsRef::<[u8]>::as_ref);

        MsgId::new(
            self.instance_id(),
            self.verifier(sender).as_ref(),
            receiver.as_ref().map(AsRef::as_ref),
            tag,
        )
    }

    /// Hash of the setup message received from the initiator that
    /// starts the protocol execution.
    fn setup_hash(&self) -> &[u8] {
        &[]
    }
}

impl<M: ProtocolParticipant> ProtocolParticipant for &M {
    type MessageSignature = M::MessageSignature;
    type MessageSigner = M::MessageSigner;
    type MessageVerifier = M::MessageVerifier;

    fn total_participants(&self) -> usize {
        (**self).total_participants()
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        (**self).verifier(index)
    }

    fn signer(&self) -> &Self::MessageSigner {
        (**self).signer()
    }

    fn participant_index(&self) -> usize {
        (**self).participant_index()
    }

    fn participant_verifier(&self) -> &Self::MessageVerifier {
        (**self).participant_verifier()
    }

    fn instance_id(&self) -> &InstanceId {
        (**self).instance_id()
    }

    fn message_ttl(&self) -> Duration {
        (**self).message_ttl()
    }

    fn setup_hash(&self) -> &[u8] {
        (**self).setup_hash()
    }
}

/// A type that provides details for key generation protocols.
///
/// Construction of a value of this type is an approval to execute a
/// key generation protocol. An application should carefully validate
/// the source data, usually a setup message received from an
/// initiator of protocol execution.
///
pub trait KeygenSetupMessage: ProtocolParticipant {
    /// Threshold parameter.
    fn threshold(&self) -> u8;

    /// Returns rank of a participant with the given index.
    /// May panic if index is out of range.
    fn participant_rank(&self, _party_index: usize) -> u8 {
        0
    }

    /// Returns the `key_id` of the newly generated key share using
    /// the public key of the generated distributed key.
    ///
    /// The implementation might return `hash(public_key)`.
    ///
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32];

    /// Additional data to incorporate into the resulting KeyShare.
    ///
    /// This mechanism allows incorporating application-specific data
    /// into the key share. Later, during signature generation, an
    /// application may use this data to execute access control
    /// policies.
    fn keyshare_extra(&self) -> &[u8] {
        &[]
    }
}

impl<M: KeygenSetupMessage> KeygenSetupMessage for &M {
    fn threshold(&self) -> u8 {
        (**self).threshold()
    }

    fn participant_rank(&self, party_index: usize) -> u8 {
        (**self).participant_rank(party_index)
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        (**self).derive_key_id(public_key)
    }

    fn keyshare_extra(&self) -> &[u8] {
        (**self).keyshare_extra()
    }
}

/// A type that provides details for pre-signature generation protocols.
///
/// Construction of a value of this type constitutes approval to
/// execute a pre-signature protocol. An application must carefully
/// validate the source data, usually a setup message received from an
/// initiator of signature generation. In particular, the setup
/// message must contain the `key_id` of the key share. Usually, an
/// application executes some access control policy to decide whether
/// the initiator has the right to access the key share.
///
/// An application is responsible for loading the key share and may
/// use `keyshare_extra()` as input for the access control policy.
///
pub trait PreSignSetupMessage<KS>: ProtocolParticipant {
    /// A shared reference to a key share.
    fn keyshare(&self) -> &KS;

    /// Returns the key chain path for this signature.
    fn chain_path(&self) -> &DerivationPath;

    /// Additional data to incorporate into the resulting pre-signature.
    fn presignature_extra(&self) -> &[u8] {
        &[]
    }

    /// Returns the list of banned parties.
    fn banned_parties(&self) -> &[u8] {
        &[]
    }
}

/// A type that provides details for finalizing signature generation
/// from a pre-calculated pre-signature object within the protocol.
///
/// Construction of a value of this type constitutes approval to
/// execute the protocol. An application must carefully validate the
/// source data, usually a setup message received from an initiator of
/// signature generation.
///
/// **Critical Security Warning:** Pay extra attention to the
/// implementation of the `message_hash()` method.
///
/// Always send the full raw message to be signed in the setup message
/// and always calculate the hash function independently by each
/// participant.
///
/// Using a message hash from the setup message received over the
/// network is *strongly discouraged* and can lead to severe security
/// vulnerabilities.
///
pub trait FinalSignSetupMessage<PS>: ProtocolParticipant {
    /// Returns the pre-signature created by `sign::pre_signature()`.
    fn pre_signature(&self) -> &PS;

    /// Computes hash of a message to sign.
    fn message_hash(&self) -> [u8; 32];
}

/// A setup message for `sign::run()`.
pub trait SignSetupMessage<KS>: PreSignSetupMessage<KS> {
    /// Hash of a message to sign.
    fn message_hash(&self) -> [u8; 32];
}

/// A setup message for key export.
pub trait KeyExporterSetupMessage<PK, KS>: ProtocolParticipant {
    /// Returns the public key of the receiving party.
    fn receiver_public_key(&self) -> &PK;

    /// A shared reference to a key share.
    fn keyshare(&self) -> &KS;
}

/// A setup message for a receiver of an exported key.
pub trait KeyExportReceiverSetupMessage<KS, SK>: ProtocolParticipant {
    /// Private key to decrypt P2P messages.
    fn receiver_private_key(&self) -> &SK;

    /// A shared reference to a key share.
    fn keyshare(&self) -> &KS;
}

/// A setup message for quorum_change::run()
pub trait QuorumChangeSetupMessage<KS, PK>: ProtocolParticipant {
    /// A shared reference to a key share.
    fn old_keyshare(&self) -> Option<&KS>;

    /// New threshold parameter.
    fn new_threshold(&self) -> u8;

    /// New participant rank. Panics if `party_id` is out of range.
    fn new_participant_rank(&self, _party_id: u8) -> u8 {
        0
    }

    /// Expected public key.
    fn expected_public_key(&self) -> &PK;

    /// Returns `new_party_id` for `party_index`.
    fn new_party_id(&self, index: usize) -> Option<u8> {
        self.new_party_indices()
            .iter()
            .position(|p| p == &index)
            .map(|p| p as u8)
    }

    /// List of old party indices.
    fn old_party_indices(&self) -> &[usize];

    /// List of indices of new parties in a list of protocol
    /// participants. Order of indices defines assignment of party-id
    /// to new key shares.
    fn new_party_indices(&self) -> &[usize];

    /// Additional data to incorporate into the resulting key share.
    fn keyshare_extra(&self) -> &[u8] {
        &[]
    }

    /// Derives a `key_id` from a public key.
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32];
}

impl<KS, PK, M: QuorumChangeSetupMessage<KS, PK>>
    QuorumChangeSetupMessage<KS, PK> for &M
{
    fn old_keyshare(&self) -> Option<&KS> {
        (**self).old_keyshare()
    }

    fn new_threshold(&self) -> u8 {
        (**self).new_threshold()
    }

    fn expected_public_key(&self) -> &PK {
        (**self).expected_public_key()
    }

    fn old_party_indices(&self) -> &[usize] {
        (**self).old_party_indices()
    }

    fn new_party_indices(&self) -> &[usize] {
        (**self).new_party_indices()
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        (**self).derive_key_id(public_key)
    }
}

/// A setup message for WTSS DKG.
pub trait WeightedKeygenSetupMessage: ProtocolParticipant {
    /// Returns rank of a participant with the given index.
    /// May panic if index is out of range.
    fn participant_weight(&self, _party_index: usize) -> u16 {
        1
    }

    /// Threshold parameter for weighted TSS.
    fn weighted_threshold(&self) -> u16;

    /// Returns the `key_id` of the newly generated key share using
    /// the public key of the generated distributed key.
    ///
    /// The implementation might return `hash(public_key)`.
    ///
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32];

    /// Additional data to incorporate into the resulting KeyShare.
    ///
    /// This mechanism allows incorporating application-specific data
    /// into the key share. Later, during signature generation, an
    /// application may use this data to execute access control
    /// policies.
    fn keyshare_extra(&self) -> &[u8] {
        &[]
    }
}

/// A setup message for WTSS QC.
pub trait WeightedQuorumChangeSetupMessage<KS, PK>:
    QuorumChangeSetupMessage<KS, PK>
{
    /// New participant weight.
    fn new_participant_weight(&self, party_id: usize) -> u16;
}
