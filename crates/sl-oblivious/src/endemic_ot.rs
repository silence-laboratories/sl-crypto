use std::array;

use rand::prelude::*;
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::SessionId;

use crate::{constants::ENDEMIC_OT_LABEL, utils::ExtractBit};

// Computational security parameter, fixed to /lambda_c = 256
// 256 OT seeds each 256-bit
pub const LAMBDA_C: usize = 256;

// size of u8 array to hold LAMBDA_C bits.
pub const LAMBDA_C_BYTES: usize = LAMBDA_C / 8;

//
pub const BATCH_SIZE: usize = LAMBDA_C;

/// EndemicOT Message 1
#[derive(
    Debug, Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct EndemicOTMsg1 {
    /// values r_0 and r_1 from OTReceiver to OTSender
    pub r_list: Vec<[[u8; 32]; 2]>, // size == LAMBDA_C
}

/// EndemicOT Message 2
#[derive(
    Debug, Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct EndemicOTMsg2 {
    /// values m_b_0 and m_b_1 from OTSender to OTReceiver
    pub m_b_list: Vec<[[u8; 32]; 2]>, // size == LAMBDA_C
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
    pub one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>, // size == LAMBDA_C
}

/// The output of the OT receiver.
#[derive(Clone, Debug)]
pub struct ReceiverOutput {
    pub(crate) packed_random_choice_bits: [u8; LAMBDA_C_BYTES], // LAMBDA_C bits
    pub(crate) one_time_pad_decryption_keys: Vec<[u8; 32]>, // size == LAMBDA_C
}

// RO for EndemicOT
fn h_function(
    index: usize,
    session_id: &SessionId,
    pk: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    hasher.update(&ENDEMIC_OT_LABEL);
    hasher.update(session_id);
    hasher.update((index as u16).to_be_bytes());
    hasher.update(pk);

    hasher.finalize().into()
}

/// Sender of the Endemic OT protocol.
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
pub struct EndemicOTSender {
    session_id: SessionId,
    t_b_0_list: [ReusableSecret; LAMBDA_C],
    t_b_1_list: [ReusableSecret; LAMBDA_C],
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
                let r_0 = &r_values[0];
                let r_1 = &r_values[1];

                let h_r_0 = h_function(idx, &self.session_id, r_0);
                let h_r_1 = h_function(idx, &self.session_id, r_1);

                let m_a_0 = PublicKey::from(xor_byte_arrays(r_0, &h_r_1));
                let m_a_1 = PublicKey::from(xor_byte_arrays(r_1, &h_r_0));

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
pub struct EndemicOTReceiver {
    packed_choice_bits: [u8; LAMBDA_C_BYTES],
    t_a_list: [ReusableSecret; LAMBDA_C],
}

impl EndemicOTReceiver {
    /// Create a new instance of the EndemicOT receiver.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: SessionId,
        rng: &mut R,
    ) -> (Self, EndemicOTMsg1) {
        let packed_choice_bits: [u8; LAMBDA_C_BYTES] = rng.gen();

        let t_a_list: [ReusableSecret; LAMBDA_C] =
            array::from_fn(|_| ReusableSecret::random_from_rng(&mut *rng));

        let r_other_list: [[u8; 32]; LAMBDA_C] =
            array::from_fn(|_| rng.gen());

        let mut r_list = vec![];

        t_a_list
            .par_iter()
            .zip(&r_other_list)
            .enumerate()
            .map(|(idx, (t_a, r_other))| {
                let r_choice = xor_byte_arrays(
                    &PublicKey::from(t_a).to_bytes(),
                    &h_function(idx, &session_id, r_other),
                );

                let random_choice_bit =
                    packed_choice_bits.extract_bit(idx) as usize;

                let mut r_values: [[u8; 32]; 2] = [[0; 32]; 2];

                r_values[random_choice_bit] = r_choice;
                r_values[random_choice_bit ^ 1] = *r_other;

                r_values
            })
            .collect_into_vec(&mut r_list);

        let msg1 = EndemicOTMsg1 { r_list };

        let next_state = Self {
            packed_choice_bits,
            t_a_list,
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

                self.t_a_list[idx]
                    .diffie_hellman(&PublicKey::from(m_b_value))
                    .to_bytes()
            })
            .collect_into_vec(&mut rho_w_vec);

        ReceiverOutput::new(self.packed_choice_bits, rho_w_vec)
    }
}

impl SenderOutput {
    /// Create a new `SenderOutput`.
    pub fn new(
        one_time_pad_enc_keys: Vec<OneTimePadEncryptionKeys>, // size == LAMBDA_C
    ) -> Self {
        Self {
            one_time_pad_enc_keys,
        }
    }
}

impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        packed_random_choice_bits: [u8; LAMBDA_C_BYTES],
        one_time_pad_decryption_keys: Vec<[u8; 32]>, // size == LAMBDA_CLAMBDA_C
    ) -> Self {
        Self {
            packed_random_choice_bits,
            one_time_pad_decryption_keys,
        }
    }
}

/// XOR two byte arrays.
fn xor_byte_arrays<const T: usize>(a: &[u8; T], b: &[u8; T]) -> [u8; T] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_endemic_ot() {
        let mut rng = rand::thread_rng();
        let session_id = SessionId::random(&mut rng);

        let sender = EndemicOTSender::new(session_id, &mut rng);

        let (receiver, msg1) = EndemicOTReceiver::new(session_id, &mut rng);

        let (sender_output, msg2) = sender.process(msg1);

        let receiver_output = receiver.process(&msg2);

        for i in 0..LAMBDA_C {
            let sender_pad = &sender_output.one_time_pad_enc_keys[i];

            let rec_pad = &receiver_output.one_time_pad_decryption_keys[i];

            let bit =
                receiver_output.packed_random_choice_bits.extract_bit(i);
            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
