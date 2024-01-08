use std::array;

use rand::prelude::*;
use rayon::prelude::*;
use x25519_dalek::{PublicKey, ReusableSecret};

use sl_mpc_mate::{xor_byte_arrays, SessionId};

use crate::{
    constants::ENDEMIC_OT_LABEL,
    endemic_ot::{
        EndemicOTMsg1, EndemicOTMsg2, BATCH_SIZE, BATCH_SIZE_BYTES,
    },
    utils::ExtractBit,
};

// RO for EndemicOT
fn h_function(
    index: usize,
    session_id: &SessionId,
    pk: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&ENDEMIC_OT_LABEL);
    hasher.update(session_id);
    hasher.update(&(index as u16).to_be_bytes());
    hasher.update(pk);

    hasher.finalize().into()
}

/// Sender of the Endemic OT protocol.
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
pub struct EndemicOTSender {
    session_id: SessionId,
    t_b_0_list: [ReusableSecret; BATCH_SIZE],
    t_b_1_list: [ReusableSecret; BATCH_SIZE],
}

impl EndemicOTSender {
    /// Create a new instance of the EndemicOT sender.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: SessionId,
        rng: &mut R,
    ) -> Self {
        EndemicOTSender {
            session_id,
            t_b_0_list: array::from_fn(|_| {
                ReusableSecret::random_from_rng(&mut *rng)
            }),
            t_b_1_list: array::from_fn(|_| {
                ReusableSecret::random_from_rng(&mut *rng)
            }),
        }
    }

    /// Process EndemicOTMsg1 from OTReceiver
    pub fn process(
        self,
        msg1: EndemicOTMsg1,
    ) -> (SenderOutput, EndemicOTMsg2) {
        let mut m_b_list = vec![];
        let mut pad_enc_keys = vec![];
        msg1.r_list
            .par_iter()
            .enumerate()
            .map(|(idx, r_values)| {
                let r_0 = r_values[0];
                let r_1 = r_values[1];
                let h_r_0 = h_function(idx, &self.session_id, &r_0);
                let h_r_1 = h_function(idx, &self.session_id, &r_1);
                let m_a_0 = PublicKey::from(xor_byte_arrays(&r_0, &h_r_1));
                let m_a_1 = PublicKey::from(xor_byte_arrays(&r_1, &h_r_0));
                let t_b_0 = &self.t_b_0_list[idx];
                let t_b_1 = &self.t_b_1_list[idx];
                let m_b_0 = PublicKey::from(t_b_0).to_bytes();
                let m_b_1 = PublicKey::from(t_b_1).to_bytes();
                // check key generation
                let rho_0 = t_b_0.diffie_hellman(&m_a_0).to_bytes();
                let rho_1 = t_b_1.diffie_hellman(&m_a_1).to_bytes();
                ([m_b_0, m_b_1], OneTimePadEncryptionKeys { rho_0, rho_1 })
            })
            .unzip_into_vecs(&mut m_b_list, &mut pad_enc_keys);

        let msg2 = EndemicOTMsg2 { m_b_list };
        (SenderOutput::new(pad_enc_keys), msg2)
    }
}

/// EndemicOTReceiver
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
pub struct EndemicOTReceiver<T> {
    packed_choice_bits: [u8; BATCH_SIZE_BYTES],
    state: T,
}

/// State of Receiver after creating Message 1.
pub struct RecR1 {
    t_a_list: [ReusableSecret; BATCH_SIZE],
}

impl EndemicOTReceiver<RecR1> {
    /// Create a new instance of the EndemicOT receiver.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: SessionId,
        rng: &mut R,
    ) -> (Self, EndemicOTMsg1) {
        let packed_choice_bits: [u8; BATCH_SIZE_BYTES] = rng.gen();
        let t_a_list: [ReusableSecret; BATCH_SIZE] =
            array::from_fn(|_| ReusableSecret::random_from_rng(&mut *rng));
        let r_other_list: [[u8; 32]; BATCH_SIZE] =
            array::from_fn(|_| rng.gen());
        let mut r_list = vec![];
        t_a_list
            .par_iter()
            .enumerate()
            .map(|(idx, t_a)| {
                let m_a = PublicKey::from(t_a).to_bytes();
                let random_choice_bit = packed_choice_bits.extract_bit(idx);
                let r_other = r_other_list[idx];
                let r_choice = xor_byte_arrays(
                    &m_a,
                    &h_function(idx, &session_id, &r_other),
                );
                let mut r_values: [[u8; 32]; 2] = [[0; 32]; 2];
                r_values[random_choice_bit as usize] = r_choice;
                let index = ((random_choice_bit as usize) + 1) % 2;
                r_values[index] = r_other;
                r_values
            })
            .collect_into_vec(&mut r_list);

        let msg1 = EndemicOTMsg1 { r_list };

        let next_state = Self {
            packed_choice_bits,
            state: RecR1 { t_a_list },
        };

        (next_state, msg1)
    }

    pub fn process(self, msg2: &EndemicOTMsg2) -> ReceiverOutput {
        let mut rho_w_vec = vec![];
        msg2.m_b_list
            .par_iter()
            .enumerate()
            .map(|(idx, m_b_values)| {
                let random_choice_bit =
                    self.packed_choice_bits.extract_bit(idx);
                let m_b_value = m_b_values[random_choice_bit as usize];
                let s_w = self.state.t_a_list[idx]
                    .diffie_hellman(&PublicKey::from(m_b_value));
                s_w.to_bytes()
            })
            .collect_into_vec(&mut rho_w_vec);

        ReceiverOutput::new(self.packed_choice_bits, rho_w_vec)
    }
}

/// The one time pad encryption keys for a single choice.
#[derive(Default, Clone, Copy, bincode::Encode, bincode::Decode)]
pub struct OneTimePadEncryptionKeys {
    pub rho_0: [u8; 32],
    pub rho_1: [u8; 32],
}

/// The output of the OT sender.
#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct SenderOutput {
    pub one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>, // size == BATCH_SIZE
}

impl SenderOutput {
    /// Create a new `SenderOutput`.
    pub fn new(
        one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>, // size == BATCH_SIZE
    ) -> Self {
        Self {
            one_time_pad_enc_keys,
        }
    }
}

/// The output of the OT receiver.
#[derive(Clone, Debug)]
pub struct ReceiverOutput {
    pub(crate) packed_random_choice_bits: [u8; BATCH_SIZE_BYTES], // batch_size bits
    pub(crate) one_time_pad_decryption_keys: Vec<[u8; 32]>, // size == BATCH_SIZE
}

impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        packed_random_choice_bits: [u8; BATCH_SIZE_BYTES],
        one_time_pad_decryption_keys: Vec<[u8; 32]>, // size == BATCH_SIZE
    ) -> Self {
        Self {
            packed_random_choice_bits,
            one_time_pad_decryption_keys,
        }
    }
}
