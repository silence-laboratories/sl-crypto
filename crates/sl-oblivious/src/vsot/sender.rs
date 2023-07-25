use elliptic_curve::{sec1::ToEncodedPoint, subtle::ConstantTimeEq};
use k256::{ProjectivePoint, Scalar};
use merlin::Transcript;
// use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sl_mpc_mate::{traits::Round, xor_byte_arrays, CryptoRng, RngCore, SessionId};

use crate::{
    vsot::{VSOTMsg3, VSOTMsg5},
    zkproofs::DLogProof,
};

use super::{VSOTError, VSOTMsg1, VSOTMsg2, VSOTMsg4};

/// Sender of the VSOT protocol.
pub struct VSOTSender<T> {
    session_id: SessionId,
    batch_size: u32,
    secret_key: Scalar,
    /// Public key of the sender.
    pub public_key: ProjectivePoint,
    state: T,
}

/// Initial state of the sender.
pub struct InitSender {
    dlog_proof: DLogProof,
}
/// State of the sender after generating Message 1.
pub struct SendR1 {}

/// State of the sender after processing Message 2.
pub struct SendR2 {
    /// One time pad encryption keys
    pad_enc_keys: Vec<OneTimePadEncryptionKeys>,
}

impl VSOTSender<InitSender> {
    /// Create a new instance of the VSOT sender.
    // TODO: u64 for batch size?
    pub fn new<R: CryptoRng + RngCore>(
        session_id: SessionId,
        batch_size: u32,
        rng: &mut R,
    ) -> Result<Self, VSOTError> {
        if batch_size % 8 != 0 {
            return Err(VSOTError::InvalidBatchSize);
        }

        let secret_key = Scalar::generate_biased(rng);
        let mut transcript = Transcript::new(b"SL-VSOT");
        transcript.append_message(b"session_id", session_id.as_ref());

        let dlog_proof = DLogProof::prove(
            &secret_key,
            ProjectivePoint::GENERATOR,
            &mut transcript,
            rng,
        );
        VSOTSender::new_with_context(session_id, batch_size, secret_key, dlog_proof)
    }

    pub(crate) fn new_with_context(
        session_id: SessionId,
        batch_size: u32,
        secret_key: Scalar,
        dlog_proof: DLogProof,
    ) -> Result<Self, VSOTError> {
        let public_key = ProjectivePoint::GENERATOR * secret_key;

        Ok(VSOTSender {
            session_id,
            batch_size,
            secret_key,
            public_key,
            state: InitSender { dlog_proof },
        })
    }
}

impl Round for VSOTSender<InitSender> {
    type Input = ();
    type Output = (VSOTSender<SendR1>, VSOTMsg1);

    /// Generate the 1st message of the protocol.
    /// Accepts unit type as input.
    fn process(self, _: Self::Input) -> Self::Output {
        let msg = VSOTMsg1 {
            proof: self.state.dlog_proof,
            public_key: self.public_key,
        };
        let next_state = VSOTSender {
            session_id: self.session_id,
            batch_size: self.batch_size,
            secret_key: self.secret_key,
            public_key: self.public_key,
            state: SendR1 {},
        };
        (next_state, msg)
    }
}

impl Round for VSOTSender<SendR1> {
    type Input = VSOTMsg2;

    type Output = Result<(VSOTSender<SendR2>, VSOTMsg3), VSOTError>;

    /// Steps 4 and 5 of VSOT (protocol 7 DKLs18)
    fn process(self, msg2: Self::Input) -> Self::Output {
        if msg2.encoded_choice_bits.len() != self.batch_size as usize {
            return Err(VSOTError::InvalidDataCount);
        }

        let mut hasher = blake3::Hasher::new();

        hasher.update(b"SL-Seed-VSOT");
        hasher.update(self.session_id.as_ref());
        hasher.update(b"Random-Oracle-Salt");
        let session_id: SessionId = hasher.finalize().as_bytes().to_owned().into();

        let (challenges, pad_enc_keys): (Vec<[u8; 32]>, Vec<OneTimePadEncryptionKeys>) = msg2
            .encoded_choice_bits
            .iter()
            .enumerate()
            .map(|(idx, encoded_choice)| {
                let rho_0_prehash = encoded_choice * &self.secret_key;
                let rho_1_prehash = (encoded_choice - &self.public_key) * self.secret_key;
                let mut hasher = blake3::Hasher::new();

                hasher.update(b"SL-Seed-VSOT");
                hasher.update(session_id.as_ref());
                hasher.update((idx as u64).to_be_bytes().as_ref());
                hasher.update(rho_0_prehash.to_encoded_point(true).as_bytes());
                let rho_0: [u8; 32] = hasher.finalize().into();

                hasher.reset().update(b"SL-Seed-VSOT");
                hasher.update(session_id.as_ref());
                hasher.update((idx as u64).to_be_bytes().as_ref());
                hasher.update(rho_1_prehash.to_encoded_point(true).as_bytes());

                let rho_1: [u8; 32] = hasher.finalize().into();

                // H(H(rho_0)
                let rho_0_hash = hasher.reset().update(rho_0.as_ref()).finalize();
                let rho_0_double_hash: [u8; 32] = hasher
                    .reset()
                    .update(rho_0_hash.as_bytes())
                    .finalize()
                    .into();

                // H(H(rho_1)
                let rho_1_hash = hasher.reset().update(rho_1.as_ref()).finalize();
                let rho_1_double_hash: [u8; 32] = hasher
                    .reset()
                    .update(rho_1_hash.as_bytes())
                    .finalize()
                    .into();

                let challenge = xor_byte_arrays(rho_0_double_hash, rho_1_double_hash);

                let pad_enc_keys = OneTimePadEncryptionKeys { rho_0, rho_1 };

                (challenge, pad_enc_keys)
            })
            .unzip();

        let next_state = VSOTSender {
            session_id,
            batch_size: self.batch_size,
            secret_key: self.secret_key,
            public_key: self.public_key,
            state: SendR2 { pad_enc_keys },
        };
        let msg3 = VSOTMsg3 { challenges };

        Ok((next_state, msg3))
    }
}

impl Round for VSOTSender<SendR2> {
    type Input = VSOTMsg4;

    type Output = Result<(SenderOutput, VSOTMsg5), VSOTError>;

    /// Step 7 of VSOT (protocol 7 DKLs18)
    fn process(self, msg4: Self::Input) -> Self::Output {
        if msg4.challenge_responses.len() != self.state.pad_enc_keys.len() {
            return Err(VSOTError::InvalidDataCount);
        }

        // TODO: Will this be constant time?
        let challenge_openings = msg4
            .challenge_responses
            .iter()
            .zip(&self.state.pad_enc_keys)
            .map(|(challenge_response, pad_end_key)| {
                let rho_0_hash: [u8; 32] = blake3::hash(pad_end_key.rho_0.as_ref()).into();
                let rho_0_double_hash: [u8; 32] = blake3::hash(&rho_0_hash).into();
                (bool::from(challenge_response.ct_eq(&rho_0_double_hash)))
                    .then_some(())
                    .ok_or(VSOTError::InvalidChallegeResponse)?;

                let rho_1_hash = blake3::hash(pad_end_key.rho_1.as_ref()).into();

                Ok(ChallengeOpening {
                    rho_0_hash,
                    rho_1_hash,
                })
            })
            .collect::<Result<Vec<_>, VSOTError>>()?;

        Ok((
            SenderOutput::new(self.state.pad_enc_keys),
            VSOTMsg5 { challenge_openings },
        ))
    }
}

/// Challenge opening for a single choice.
#[derive(Serialize, Deserialize)]
pub struct ChallengeOpening {
    /// H(rho_0)
    pub rho_0_hash: [u8; 32],
    /// H(rho_1)
    pub rho_1_hash: [u8; 32],
}

/// The one time pad encryption keys for a single choice.
#[derive(Serialize, Deserialize, Default)]
pub struct OneTimePadEncryptionKeys {
    pub rho_0: [u8; 32],
    pub rho_1: [u8; 32],
}

/// The output of the VSOT receiver.
#[derive(Serialize, Deserialize, Default)]
pub struct SenderOutput {
    pub one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>,
}

impl SenderOutput {
    /// Create a new `SenderOutput`.
    pub fn new(one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>) -> Self {
        Self {
            one_time_pad_enc_keys,
        }
    }
}
