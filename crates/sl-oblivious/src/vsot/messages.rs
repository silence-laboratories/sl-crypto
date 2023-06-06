use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use sl_mpc_mate::traits::PersistentObject;

use crate::{
    serialization::{serde_projective_point, serde_projective_point_vec},
    zkproofs::DLogProof,
};

use super::sender::ChallengeOpening;

/// VSOT Message 1
#[derive(Serialize, Deserialize, Clone)]
pub struct VSOTMsg1 {
    /// Discrete log proof
    pub proof: DLogProof,
    #[serde(with = "serde_projective_point")]
    /// Sender public key
    pub public_key: ProjectivePoint,
}

/// VSOT Message 2
#[derive(Serialize, Deserialize)]
pub struct VSOTMsg2 {
    /// Encoded choice bits
    #[serde(with = "serde_projective_point_vec")]
    pub encoded_choice_bits: Vec<ProjectivePoint>,
}

/// VSOT Message 3
#[derive(Serialize, Deserialize)]
pub struct VSOTMsg3 {
    ///  Challenges
    pub challenges: Vec<[u8; 32]>,
}

/// VSOT Message 4
#[derive(Serialize, Deserialize)]
pub struct VSOTMsg4 {
    ///  Challenge responses from the receiver
    pub challenge_responses: Vec<[u8; 32]>,
}

/// VSOT Message 5
#[derive(Serialize, Deserialize)]
pub struct VSOTMsg5 {
    ///  Challenge responses from the receiver
    pub challenge_openings: Vec<ChallengeOpening>,
}

impl PersistentObject for VSOTMsg1 {}
impl PersistentObject for VSOTMsg2 {}
impl PersistentObject for VSOTMsg3 {}
impl PersistentObject for VSOTMsg4 {}
impl PersistentObject for VSOTMsg5 {}
