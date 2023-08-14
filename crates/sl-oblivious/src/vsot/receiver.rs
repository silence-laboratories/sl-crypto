use std::array;

use elliptic_curve::{
    sec1::ToEncodedPoint,
    subtle::{Choice, ConditionallySelectable},
};
use k256::{ProjectivePoint, Scalar};
use merlin::Transcript;
use rand::Rng;
// use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{
    xor_byte_arrays, CryptoRng, HashBytes, RngCore, SessionId,
};

use crate::{
    utils::{double_blake_hash_inter, ExtractBit},
    vsot::{VSOTMsg2, VSOTMsg4, BATCH_SIZE, BATCH_SIZE_BITS},
};

use super::{VSOTError, VSOTMsg1, VSOTMsg3, VSOTMsg5};

/// VSOTReceiver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSOTReceiver<T> {
    session_id: SessionId,
    state: T,
}

/// Initial state of a party.
pub struct InitRec {
    // TODO: Const generics?
    a_vec: [Scalar; BATCH_SIZE],
    packed_choice_bits: [u8; BATCH_SIZE_BITS],
}

// TODO: Zeroize state after protocol execution

/// State of Receiver after processing Message 1.
pub struct RecR1 {
    rho_w_vec: [[u8; 32]; BATCH_SIZE],
    packed_choice_bits: [u8; BATCH_SIZE_BITS],
}

/// State of Receiver after processing Message 3.
#[derive(Debug, Clone)]
pub struct RecR2 {
    rho_w_hashes: [[u8; 32]; BATCH_SIZE],
    rho_w_vec: [[u8; 32]; BATCH_SIZE],
    packed_choice_bits: [u8; BATCH_SIZE_BITS],
}

impl VSOTReceiver<InitRec> {
    /// Create a new instance of the VSOT receiver.
    pub fn new<R: CryptoRng + RngCore>(
        session_id: SessionId,
        rng: &mut R,
    ) -> Self {
        Self {
            session_id,
            state: InitRec {
                a_vec: array::from_fn(|_| Scalar::generate_biased(rng)),
                packed_choice_bits: rng.gen(),
            },
        }
    }
}

/// Step 3 of the VSOT (protocol 7 DKLs18).
impl VSOTReceiver<InitRec> {
    pub fn process(
        self,
        msg1: VSOTMsg1,
    ) -> Result<(VSOTReceiver<RecR1>, VSOTMsg2), VSOTError> {
        let mut transcript = Transcript::new(b"SL-VSOT");

        transcript
            .append_message(b"session_id", self.session_id.as_ref());

        msg1.proof
            .verify(
                &msg1.public_key,
                ProjectivePoint::GENERATOR,
                &mut transcript,
            )
            .then_some(())
            .ok_or(VSOTError::InvalidDLogProof)?;

        let sender_pubkey = &msg1.public_key;

        let mut hasher = blake3::Hasher::new();

        hasher.update(b"SL-Seed-VSOT");
        hasher.update(self.session_id.as_ref());
        hasher.update(b"Random-Oracle-Salt");

        let session_id: SessionId =
            hasher.finalize().as_bytes().to_owned().into();

        let mut encoded_choice_bits =
            [ProjectivePoint::IDENTITY; BATCH_SIZE];

        let mut rho_w_vec = [[0u8; 32]; BATCH_SIZE];

        self.state.a_vec.iter().enumerate().for_each(|(idx, a)| {
            let option_0 = ProjectivePoint::GENERATOR * a;
            let option_1 = option_0 + sender_pubkey;

            let random_choice_bit =
                self.state.packed_choice_bits.extract_bit(idx);

            let rho_w_prehash = sender_pubkey * a;

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"SL-Seed-VSOT");
            hasher.update(session_id.as_ref());
            hasher.update((idx as u64).to_be_bytes().as_slice());
            hasher.update(
                rho_w_prehash.to_encoded_point(true).as_bytes(),
            );

            rho_w_vec[idx] = hasher.finalize().into();

            encoded_choice_bits[idx] =
                ProjectivePoint::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(random_choice_bit as u8),
                );
        });

        let msg2 = VSOTMsg2 {
            encoded_choice_bits,
        };

        let state = RecR1 {
            rho_w_vec,
            packed_choice_bits: self.state.packed_choice_bits,
        };

        Ok((VSOTReceiver { session_id, state }, msg2))
    }
}

impl VSOTReceiver<RecR1> {
    /// Step 6 of the VSOT (protocol 7 DKLs18).
    pub fn process(
        self,
        msg3: VSOTMsg3,
    ) -> Result<(VSOTReceiver<RecR2>, VSOTMsg4), VSOTError> {
        let mut responses = [[0; 32]; BATCH_SIZE];
        let mut rho_w_hashes = [[0; 32]; BATCH_SIZE];

        self.state
            .rho_w_vec
            .iter()
            .zip(msg3.challenges)
            .enumerate()
            .for_each(|(idx, (rho_w, challenge))| {
                // Reusing rho_w hashes to reduce the number of hashes
                let (rho_w_hashe, option_0) =
                    double_blake_hash_inter(rho_w);

                rho_w_hashes[idx] = rho_w_hashe;

                let option_1 = xor_byte_arrays(&option_0, &challenge);
                let random_choice_bit =
                    self.state.packed_choice_bits.extract_bit(idx);

                responses[idx] = HashBytes::conditional_select(
                    &HashBytes(option_0),
                    &HashBytes(option_1),
                    (random_choice_bit as u8).into(),
                )
                .0;
            });

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
                state: next_state,
            },
            next_msg,
        ))
    }
}

impl VSOTReceiver<RecR2> {
    pub fn process(self, msg5: VSOTMsg5) -> Result<ReceiverOutput, VSOTError> {
        msg5.challenge_openings
            .iter()
            .enumerate()
            .map(|(idx, opening)| {
                let rho_w_hash = &self.state.rho_w_hashes[idx];
                let random_bit_choice =
                    self.state.packed_choice_bits.extract_bit(idx);

                let final_option = HashBytes::conditional_select(
                    &HashBytes(opening.rho_0_hash),
                    &HashBytes(opening.rho_1_hash),
                    (random_bit_choice as u8).into(),
                );

                (&final_option.0 == rho_w_hash)
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

#[derive(Clone, Debug)]
pub struct ReceiverOutput {
    pub(crate) packed_random_choice_bits: [u8; BATCH_SIZE_BITS], // batch_size bits
    pub(crate) one_time_pad_decryption_keys: [[u8; 32]; BATCH_SIZE], // batch_size X 32 bytes
}

impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        packed_random_choice_bits: [u8; BATCH_SIZE_BITS],
        one_time_pad_decryption_keys: [[u8; 32]; BATCH_SIZE],
    ) -> Self {
        Self {
            packed_random_choice_bits,
            one_time_pad_decryption_keys,
        }
    }
}
