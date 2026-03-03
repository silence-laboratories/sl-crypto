// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//!
//! Protocol setup support.
//!

use std::time::Duration;

pub use signature::{SignatureEncoding, Signer, Verifier};

use crate::message::{InstanceId, MessageTag, MsgId};

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

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
///
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of a SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type to verify signed message, a verifying key. `AsRef<[u8]>` is
    /// used to get external representation of the key to derive
    /// message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Returns total number of participants of a distributed
    /// protocol.
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

    /// Returns message Time To Live.
    fn message_ttl(&self) -> Duration;

    /// Returns a reference to participant's own verifier.
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Returns an iterator of all participant's indexes except own one.
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

    /// Generates an ID for a message from a given sender to a given
    /// receiver. The receiver is identified by its index and is
    /// `None` for a broadcast message.
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
