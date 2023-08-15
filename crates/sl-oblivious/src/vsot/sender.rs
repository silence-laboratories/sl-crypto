use elliptic_curve::{sec1::ToEncodedPoint, subtle::ConstantTimeEq};
use k256::{ProjectivePoint, Scalar};
use merlin::Transcript;
// use rayon::prelude::*;
use sl_mpc_mate::{xor_byte_arrays, CryptoRng, RngCore, SessionId};

use crate::{
    vsot::{
        VSOTError, VSOTMsg1, VSOTMsg2, VSOTMsg3, VSOTMsg4, VSOTMsg5,
        BATCH_SIZE,
    },
    zkproofs::DLogProof,
};

/// Sender of the VSOT protocol.
pub struct VSOTSender<T> {
    session_id: SessionId,
    secret_key: Scalar,
    /// Public key of the sender.
    public_key: ProjectivePoint,
    state: T,
}

/// State of the sender after generating Message 1.
pub struct SendR1;

/// State of the sender after processing Message 2.
pub struct SendR2 {
    /// One time pad encryption keys
    pad_enc_keys: [OneTimePadEncryptionKeys; BATCH_SIZE],
}

impl VSOTSender<SendR1> {
    /// Create a new instance of the VSOT sender.
    // TODO: u64 for batch size?
    pub fn new<R: CryptoRng + RngCore>(
        session_id: SessionId,
        rng: &mut R,
    ) -> (Self, VSOTMsg1) {
        let secret_key = Scalar::generate_biased(rng);
        let mut transcript = Transcript::new(b"SL-VSOT");
        transcript.append_message(b"session_id", session_id.as_ref());

        let dlog_proof = DLogProof::prove(
            &secret_key,
            ProjectivePoint::GENERATOR,
            &mut transcript,
            rng,
        );

        let public_key = ProjectivePoint::GENERATOR * secret_key;

        let msg = VSOTMsg1 {
            proof: dlog_proof,
            public_key,
        };

        let next_state = VSOTSender {
            session_id,
            secret_key,
            public_key,
            state: SendR1,
        };

        (next_state, msg)
    }
}

impl VSOTSender<SendR1> {
    /// Steps 4 and 5 of VSOT (protocol 7 DKLs18)
    pub fn process(
        self,
        msg2: VSOTMsg2,
    ) -> Result<(VSOTSender<SendR2>, VSOTMsg3), VSOTError> {
        let mut hasher = blake3::Hasher::new();

        hasher.update(b"SL-Seed-VSOT");
        hasher.update(self.session_id.as_ref());
        hasher.update(b"Random-Oracle-Salt");
        let session_id: SessionId =
            hasher.finalize().as_bytes().to_owned().into();

        let mut challenges = [[0; 32]; BATCH_SIZE];
        let mut pad_enc_keys: [OneTimePadEncryptionKeys; BATCH_SIZE] =
            [OneTimePadEncryptionKeys {
                rho_0: [0; 32],
                rho_1: [0; 32],
            }; BATCH_SIZE];

        msg2.encoded_choice_bits.iter().enumerate().for_each(
            |(idx, encoded_choice)| {
                let rho_0_prehash = encoded_choice * &self.secret_key;
                let rho_1_prehash = (encoded_choice - &self.public_key)
                    * &self.secret_key;
                let mut hasher = blake3::Hasher::new();

                hasher.update(b"SL-Seed-VSOT");
                hasher.update(session_id.as_ref());
                hasher.update((idx as u64).to_be_bytes().as_ref());
                hasher.update(
                    rho_0_prehash.to_encoded_point(true).as_bytes(),
                );
                let rho_0: [u8; 32] = hasher.finalize().into();

                hasher.reset().update(b"SL-Seed-VSOT");
                hasher.update(session_id.as_ref());
                hasher.update((idx as u64).to_be_bytes().as_ref());
                hasher.update(
                    rho_1_prehash.to_encoded_point(true).as_bytes(),
                );

                let rho_1: [u8; 32] = hasher.finalize().into();

                // H(H(rho_0)
                let rho_0_hash =
                    hasher.reset().update(rho_0.as_ref()).finalize();
                let rho_0_double_hash: [u8; 32] = hasher
                    .reset()
                    .update(rho_0_hash.as_bytes())
                    .finalize()
                    .into();

                // H(H(rho_1)
                let rho_1_hash =
                    hasher.reset().update(rho_1.as_ref()).finalize();
                let rho_1_double_hash: [u8; 32] = hasher
                    .reset()
                    .update(rho_1_hash.as_bytes())
                    .finalize()
                    .into();

                challenges[idx] = xor_byte_arrays(
                    &rho_0_double_hash,
                    &rho_1_double_hash,
                );

                pad_enc_keys[idx] =
                    OneTimePadEncryptionKeys { rho_0, rho_1 };
            },
        );

        let next_state = VSOTSender {
            session_id,
            secret_key: self.secret_key,
            public_key: self.public_key,
            state: SendR2 { pad_enc_keys },
        };

        let msg3 = VSOTMsg3 { challenges };

        Ok((next_state, msg3))
    }
}

impl VSOTSender<SendR2> {
    /// Step 7 of VSOT (protocol 7 DKLs18)
    pub fn process(
        self,
        msg4: VSOTMsg4,
    ) -> Result<(SenderOutput, VSOTMsg5), VSOTError> {
        let mut challenge_openings =
            [ChallengeOpening::default(); BATCH_SIZE];

        // TODO: Will this be constant time?
        for (idx, (challenge_response, pad_end_key)) in msg4
            .challenge_responses
            .iter()
            .zip(&self.state.pad_enc_keys)
            .enumerate()
        {
            let rho_0_hash: [u8; 32] =
                blake3::hash(pad_end_key.rho_0.as_ref()).into();
            let rho_0_double_hash: [u8; 32] =
                blake3::hash(&rho_0_hash).into();
            (bool::from(challenge_response.ct_eq(&rho_0_double_hash)))
                .then_some(())
                .ok_or(VSOTError::InvalidChallegeResponse)?;

            let rho_1_hash =
                blake3::hash(pad_end_key.rho_1.as_ref()).into();

            challenge_openings[idx] = ChallengeOpening {
                rho_0_hash,
                rho_1_hash,
            };
        }

        Ok((
            SenderOutput::new(self.state.pad_enc_keys),
            VSOTMsg5 { challenge_openings },
        ))
    }
}

/// Challenge opening for a single choice.
#[derive(Default, Copy, Clone)]
pub struct ChallengeOpening {
    /// H(rho_0)
    pub rho_0_hash: [u8; 32],
    /// H(rho_1)
    pub rho_1_hash: [u8; 32],
}

/// The one time pad encryption keys for a single choice.
#[derive(Default, Clone, Copy)]
pub struct OneTimePadEncryptionKeys {
    pub rho_0: [u8; 32],
    pub rho_1: [u8; 32],
}

/// The output of the VSOT receiver.
#[derive(Clone, Copy)]
pub struct SenderOutput {
    pub one_time_pad_enc_keys: [OneTimePadEncryptionKeys; BATCH_SIZE],
}

impl SenderOutput {
    /// Create a new `SenderOutput`.
    pub fn new(
        one_time_pad_enc_keys: [OneTimePadEncryptionKeys; BATCH_SIZE],
    ) -> Self {
        Self {
            one_time_pad_enc_keys,
        }
    }
}
