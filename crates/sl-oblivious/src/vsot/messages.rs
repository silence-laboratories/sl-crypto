use k256::ProjectivePoint;
use sl_mpc_mate::message::*;

use crate::zkproofs::DLogProof;

use super::{sender::ChallengeOpening, BATCH_SIZE};

/// VSOT Message 1

#[derive(bincode::Encode, bincode::Decode)]
pub struct VSOTMsg1 {
    /// Discrete log proof
    pub proof: DLogProof,

    /// Sender public key
    pub public_key: Opaque<ProjectivePoint, GR>,
}

/// VSOT Message 2
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct VSOTMsg2 {
    /// Encoded choice bits
    pub encoded_choice_bits: Vec<Opaque<ProjectivePoint, GR>>,
}

/// VSOT Message 3
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct VSOTMsg3 {
    ///  Challenges
    pub challenges: [[u8; 32]; BATCH_SIZE],
}

/// VSOT Message 4
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct VSOTMsg4 {
    ///  Challenge responses from the receiver
    pub challenge_responses: [[u8; 32]; BATCH_SIZE],
}

/// VSOT Message 5
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct VSOTMsg5 {
    ///  Challenge responses from the receiver
    pub challenge_openings: [ChallengeOpening; BATCH_SIZE],
}
