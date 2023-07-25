use elliptic_curve::{
    sec1::ToEncodedPoint,
    subtle::{Choice, ConditionallySelectable},
};
use k256::{ProjectivePoint, Scalar};
use merlin::Transcript;
use rand::Rng;
// use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{traits::Round, xor_byte_arrays, CryptoRng, HashBytes, RngCore, SessionId};

use crate::{
    utils::{double_blake_hash_inter, ExtractBit},
    vsot::{VSOTMsg2, VSOTMsg4},
};

use super::{VSOTError, VSOTMsg1, VSOTMsg3, VSOTMsg5};

/// VSOTReceiver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSOTReceiver<T> {
    session_id: SessionId,
    batch_size: u32,
    state: T,
}

/// Initial state of a party.
pub struct InitRec {
    // TODO: Const generics?
    a_vec: Vec<Scalar>,
    packed_choice_bits: Vec<u8>,
}

// TODO: Zeroize state after protocol execution

/// State of Receiver after processing Message 1.
pub struct RecR1 {
    rho_w_vec: Vec<[u8; 32]>,
    packed_choice_bits: Vec<u8>,
}

/// State of Receiver after processing Message 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecR2 {
    rho_w_hashes: Vec<[u8; 32]>,
    rho_w_vec: Vec<[u8; 32]>,
    packed_choice_bits: Vec<u8>,
}

impl VSOTReceiver<InitRec> {
    /// Create a new instance of the VSOT receiver.
    pub fn new<R: CryptoRng + RngCore>(
        session_id: SessionId,
        batch_size: u32,
        rng: &mut R,
    ) -> Result<Self, VSOTError> {
        if batch_size % 8 != 0 {
            return Err(VSOTError::InvalidBatchSize);
        }
        let a_vec = (0..batch_size)
            .map(|_| Scalar::generate_biased(rng))
            .collect();

        // divide batch_size by 8 to get the number of bytes
        let batch_size_bytes = batch_size >> 3;

        let packed_choice_bits = (0..batch_size_bytes)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>();

        let state = InitRec {
            a_vec,
            packed_choice_bits,
        };

        Ok(Self {
            session_id,
            batch_size,
            state,
        })
    }
}

/// Step 3 of the VSOT (protocol 7 DKLs18).
impl Round for VSOTReceiver<InitRec> {
    type Input = VSOTMsg1;

    type Output = Result<(VSOTReceiver<RecR1>, VSOTMsg2), VSOTError>;

    fn process(self, msg1: Self::Input) -> Self::Output {
        let mut transcript = Transcript::new(b"SL-VSOT");

        transcript.append_message(b"session_id", self.session_id.as_ref());

        msg1.proof
            .verify(
                &msg1.public_key,
                ProjectivePoint::GENERATOR,
                &mut transcript,
            )
            .then_some(())
            .ok_or(VSOTError::InvalidDLogProof)?;

        let sender_pubkey = msg1.public_key;

        let mut hasher = blake3::Hasher::new();

        hasher.update(b"SL-Seed-VSOT");
        hasher.update(self.session_id.as_ref());
        hasher.update(b"Random-Oracle-Salt");

        let session_id: SessionId = hasher.finalize().as_bytes().to_owned().into();

        let (encoded_choice_bits, rho_w_vec): (Vec<ProjectivePoint>, Vec<[u8; 32]>) = self
            .state
            .a_vec
            .iter()
            .enumerate()
            .map(|(idx, a)| {
                let option_0 = ProjectivePoint::GENERATOR * a;
                let option_1 = option_0 + sender_pubkey;

                let random_choice_bit = self.state.packed_choice_bits.extract_bit(idx);

                let rho_w_prehash = sender_pubkey * a;

                let mut hasher = blake3::Hasher::new();
                hasher.update(b"SL-Seed-VSOT");
                hasher.update(session_id.as_ref());
                hasher.update((idx as u64).to_be_bytes().as_slice());
                hasher.update(rho_w_prehash.to_encoded_point(true).as_bytes());

                let rho_w: [u8; 32] = hasher.finalize().into();

                let final_option = ProjectivePoint::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(random_choice_bit as u8),
                );

                (final_option, rho_w)
            })
            .unzip();

        let msg2 = VSOTMsg2 {
            encoded_choice_bits,
        };

        let state = RecR1 {
            rho_w_vec,
            packed_choice_bits: self.state.packed_choice_bits,
        };

        Ok((
            VSOTReceiver {
                batch_size: self.batch_size,
                session_id,
                state,
            },
            msg2,
        ))
    }
}

impl Round for VSOTReceiver<RecR1> {
    type Input = VSOTMsg3;

    type Output = Result<(VSOTReceiver<RecR2>, VSOTMsg4), VSOTError>;

    /// Step 6 of the VSOT (protocol 7 DKLs18).
    fn process(self, msg3: Self::Input) -> Self::Output {
        if msg3.challenges.len() != self.batch_size as usize {
            return Err(VSOTError::InvalidDataCount);
        }

        let (responses, rho_w_hashes): (Vec<[u8; 32]>, Vec<[u8; 32]>) = self
            .state
            .rho_w_vec
            .iter()
            .zip(msg3.challenges)
            .enumerate()
            .map(|(idx, (rho_w, challenge))| {
                // Reusing rho_w hashes to reduce the number of hashes
                let (rho_w_hash, option_0) = double_blake_hash_inter(rho_w);
                let option_1 = xor_byte_arrays(option_0, challenge);
                let random_choice_bit = self.state.packed_choice_bits.extract_bit(idx);

                let final_option = HashBytes::conditional_select(
                    &HashBytes(option_0),
                    &HashBytes(option_1),
                    (random_choice_bit as u8).into(),
                );

                (final_option.0, rho_w_hash)
            })
            .unzip();

        let next_msg = VSOTMsg4 {
            challenge_responses: responses,
        };

        let next_state = RecR2 {
            rho_w_hashes,
            rho_w_vec: self.state.rho_w_vec,
            packed_choice_bits: self.state.packed_choice_bits,
        };

        Ok((
            VSOTReceiver {
                session_id: self.session_id,
                batch_size: self.batch_size,
                state: next_state,
            },
            next_msg,
        ))
    }
}

impl Round for VSOTReceiver<RecR2> {
    type Input = VSOTMsg5;

    type Output = Result<ReceiverOutput, VSOTError>;

    fn process(self, msg5: Self::Input) -> Self::Output {
        if msg5.challenge_openings.len() != self.batch_size as usize {
            return Err(VSOTError::InvalidDataCount);
        }

        msg5.challenge_openings
            .iter()
            .enumerate()
            .map(|(idx, opening)| {
                let rho_w_hash = self.state.rho_w_hashes[idx];
                let random_bit_choice = self.state.packed_choice_bits.extract_bit(idx);

                let final_option = HashBytes::conditional_select(
                    &HashBytes(opening.rho_0_hash),
                    &HashBytes(opening.rho_1_hash),
                    (random_bit_choice as u8).into(),
                );

                (final_option.0 == rho_w_hash)
                    .then_some(())
                    .ok_or(VSOTError::InvalidRhoHash)
            })
            .collect::<Result<Vec<_>, VSOTError>>()?;
        Ok(ReceiverOutput::new(
            self.state.packed_choice_bits,
            self.state.rho_w_vec,
        ))
    }
}

/// The output of the VSOT receiver.

#[derive(Clone, Debug, Default)]
pub struct ReceiverOutput {
    pub(crate) packed_random_choice_bits: Vec<u8>,
    pub(crate) one_time_pad_decryption_keys: Vec<[u8; 32]>,
}

impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        packed_random_choice_bits: Vec<u8>,
        one_time_pad_decryption_keys: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            packed_random_choice_bits,
            one_time_pad_decryption_keys,
        }
    }
}
