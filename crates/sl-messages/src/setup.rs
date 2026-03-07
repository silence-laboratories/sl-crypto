// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Protocol setup primitives for participant identity and round tracking.
//!
//! This module defines the shared context required to run a protocol
//! execution (`ProtocolParticipant`), including party keys, local party
//! index, instance ID, and message TTL.
//!
//! It also provides helpers for message-flow coordination:
//! - `AllOtherParties` to iterate peers except self.
//! - `RoundMode` and `MessageRound` to derive and track expected message IDs
//!   (broadcast or p2p), mark arrivals, and request pending messages.
//! - `validate_abort_message()` to validate a candidate abort message signature
//!   for a specific party (callers must pre-filter by abort message ID/tag).
//! - `keys` module with no-op signing/verifying key types for trusted transport
//!   or test-only message authentication.
//!
//! Use these types to keep message acceptance deterministic and tied to one
//! protocol instance.

mod abort;
mod round;
mod tags;
mod traits;

pub mod finish;
pub mod key_export;
pub mod keygen;
pub mod keys;
pub mod quorum_change;
pub mod sign;

pub use signature::{SignatureEncoding, Signer, Verifier};

pub use abort::{create_abort_message, validate_abort_message};
pub use round::{MessageRound, RoundMode};
pub use tags::{ABORT_MESSAGE_TAG, SETUP_MESSAGE_TAG};
pub use traits::{
    AllOtherParties, FinalSignSetupMessage, KeyExportReceiverSetupMessage,
    KeyExporterSetupMessage, KeygenSetupMessage, PreSignSetupMessage,
    ProtocolParticipant, QuorumChangeSetupMessage, SignSetupMessage,
    WeightedKeygenSetupMessage, WeightedQuorumChangeSetupMessage,
};

#[cfg(test)]
mod tests;
