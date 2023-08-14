// use elliptic_curve::{
//     group::GroupEncoding,
//     subtle::ConstantTimeEq,
//     Field, PrimeField,
// };

use elliptic_curve::group::GroupEncoding;
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{
    bincode::{
        de::Decoder,
        enc::Encoder,
        error::{DecodeError, EncodeError},
        Decode, Encode,
    },
    message::*,
//    traits::PersistentObject,
};

use crate::{
    serialization::{
        serde_projective_point, // serde_projective_point_vec,
    },
    zkproofs::DLogProof,
};

use super::{sender::ChallengeOpening, BATCH_SIZE};

/// VSOT Message 1
#[derive(Serialize, Deserialize, Clone)]
pub struct VSOTMsg1 {
    /// Discrete log proof
    pub proof: DLogProof,

    #[serde(with = "serde_projective_point")]
    /// Sender public key
    pub public_key: ProjectivePoint,
}

impl Encode for VSOTMsg1 {
    fn encode<E: Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), EncodeError> {
        self.proof.encode(encoder)?;
        FixedArray(self.public_key.to_bytes()).encode(encoder)?;

        Ok(())
    }
}

impl Decode for VSOTMsg1 {
    fn decode<D: Decoder>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let proof = DLogProof::decode(decoder)?;
        let pkey =
            ProjectivePoint::from_bytes(&FixedArray::decode(decoder)?)
                .unwrap();
                // .map(|p| Ok::<_, DecodeError>(p))
                // .unwrap_or(Err(DecodeError::Other("invalid point")))?;

        Ok(VSOTMsg1 {
            proof,
            public_key: pkey,
        })
    }
}

/// VSOT Message 2
// #[derive(Serialize, Deserialize)]
pub struct VSOTMsg2 {
    /// Encoded choice bits
//    #[serde(with = "serde_projective_point_vec")]
    pub encoded_choice_bits: [ProjectivePoint; BATCH_SIZE],
}

// impl Encode for VSOTMsg2 {
//     fn encode(&self, msg: &mut [u8]) -> Result<usize, InvalidMessage> {
//     }
// }

// impl Decode for VSOTMsg2 {
//     fn decode(bytes: &[u8]) -> Result<(usize, Self), InvalidMessage> {
//         let mut sub = SubDecoder::new(bytes);

//         let result = VSOTMsg2 {
//             encoded_choice_bits: sub.decode_slice_with(|decoder| {
//                 Ok(ProjectivePoint::from_bytes(&decoder.decode()?)
//                     .unwrap())
//             })?,
//         };

//         sub.ok(result)
//     }
// }

/// VSOT Message 3
//#[derive(Serialize, Deserialize)]
pub struct VSOTMsg3 {
    ///  Challenges
    pub challenges: [[u8; 32]; BATCH_SIZE],
}

/// VSOT Message 4
//#[derive(Serialize, Deserialize)]
pub struct VSOTMsg4 {
    ///  Challenge responses from the receiver
    pub challenge_responses: [[u8; 32]; BATCH_SIZE],
}

/// VSOT Message 5
//#[derive(Serialize, Deserialize)]
pub struct VSOTMsg5 {
    ///  Challenge responses from the receiver
    pub challenge_openings: [ChallengeOpening; BATCH_SIZE],
}

// impl PersistentObject for VSOTMsg1 {}
// impl PersistentObject for VSOTMsg2 {}
// impl PersistentObject for VSOTMsg3 {}
// impl PersistentObject for VSOTMsg4 {}
// impl PersistentObject for VSOTMsg5 {}
