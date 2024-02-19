// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::array;

use merlin::Transcript;
use rand::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    constants::ENDEMIC_OT_LABEL, params::consts::*, utils::ExtractBit,
};

/// EndemicOT Message 1
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg1 {
    // values r_0 and r_1 from OTReceiver to OTSender
    r_list: [[[u8; 32]; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg1 {
    fn default() -> Self {
        Self {
            r_list: [[[0u8; 32]; 2]; LAMBDA_C],
        }
    }
}

/// EndemicOT Message 2
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg2 {
    // values m_b_0 and m_b_1 from OTSender to OTReceiver
    m_b_list: [[[u8; 32]; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg2 {
    fn default() -> Self {
        Self {
            m_b_list: [[[0u8; 32]; 2]; LAMBDA_C],
        }
    }
}

/// The one time pad encryption keys for a single choice.
pub(crate) struct OneTimePadEncryptionKeys {
    pub(crate) rho_0: [u8; LAMBDA_C_BYTES],
    pub(crate) rho_1: [u8; LAMBDA_C_BYTES],
}

/// The output of the OT sender.
pub struct SenderOutput {
    pub(crate) otp_enc_keys: [OneTimePadEncryptionKeys; LAMBDA_C],
}

/// The output of the OT receiver.
pub struct ReceiverOutput {
    pub(crate) choice_bits: [u8; LAMBDA_C_BYTES], // LAMBDA_C bits
    pub(crate) otp_dec_keys: [[u8; LAMBDA_C_BYTES]; LAMBDA_C],
}

// RO for EndemicOT
fn h_function(index: usize, session_id: &[u8], pk: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new(&ENDEMIC_OT_LABEL);

    t.append_message(b"session-id", session_id);
    t.append_message(b"index", &(index as u16).to_be_bytes());
    t.append_message(b"pk", pk);

    let mut output = [0u8; 32];
    t.challenge_bytes(b"", &mut output);

    output
}

/// Sender of the Endemic OT protocol.
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
pub struct EndemicOTSender;

impl EndemicOTSender {
    /// Process EndemicOTMsg1 from OTReceiver
    pub fn process<R: RngCore + CryptoRng>(
        session_id: &[u8],
        msg1: &EndemicOTMsg1,
        msg2: &mut EndemicOTMsg2,
        rng: &mut R,
    ) -> SenderOutput {
        SenderOutput {
            otp_enc_keys: array::from_fn(|idx| {
                let [r_0, r_1] = &msg1.r_list[idx];

                let h_r_0 = h_function(idx, session_id, r_0);
                let h_r_1 = h_function(idx, session_id, r_1);

                let m_a_0 = PublicKey::from(xor_byte_arrays(r_0, &h_r_1));
                let m_a_1 = PublicKey::from(xor_byte_arrays(r_1, &h_r_0));

                let t_b_0 = StaticSecret::random_from_rng(&mut *rng);
                let t_b_1 = StaticSecret::random_from_rng(&mut *rng);

                let m_b_0 = PublicKey::from(&t_b_0).to_bytes();
                let m_b_1 = PublicKey::from(&t_b_1).to_bytes();

                msg2.m_b_list[idx] = [m_b_0, m_b_1];

                // check key generation
                let rho_0 = t_b_0.diffie_hellman(&m_a_0).to_bytes()
                    [0..LAMBDA_C_BYTES]
                    .try_into()
                    .unwrap();
                let rho_1 = t_b_1.diffie_hellman(&m_a_1).to_bytes()
                    [0..LAMBDA_C_BYTES]
                    .try_into()
                    .unwrap();

                OneTimePadEncryptionKeys { rho_0, rho_1 }
            }),
        }
    }
}

/// EndemicOTReceiver
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EndemicOTReceiver {
    packed_choice_bits: [u8; LAMBDA_C_BYTES],
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    t_a_list: [StaticSecret; LAMBDA_C],
}

impl EndemicOTReceiver {
    /// Create a new instance of the EndemicOT receiver.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: &[u8],
        msg1: &mut EndemicOTMsg1,
        rng: &mut R,
    ) -> Self {
        let next_state = Self {
            packed_choice_bits: rng.gen(),
            t_a_list: array::from_fn(|_| {
                StaticSecret::random_from_rng(&mut *rng)
            }),
        };

        msg1.r_list
            .iter_mut()
            .enumerate()
            .for_each(|(idx, r_values)| {
                let t_a = &next_state.t_a_list[idx];

                let r_other = rng.gen();
                let r_choice = xor_byte_arrays(
                    &PublicKey::from(t_a).to_bytes(),
                    &h_function(idx, session_id, &r_other),
                );

                let random_choice_bit =
                    next_state.packed_choice_bits.extract_bit(idx) as usize;

                r_values[random_choice_bit] = r_choice;
                r_values[random_choice_bit ^ 1] = r_other;
            });

        next_state
    }

    pub fn process(self, msg2: &EndemicOTMsg2) -> ReceiverOutput {
        let rho_w_vec: [[u8; LAMBDA_C_BYTES]; LAMBDA_C] =
            std::array::from_fn(|idx| {
                let m_b_values = &msg2.m_b_list[idx];
                let random_choice_bit =
                    self.packed_choice_bits.extract_bit(idx);

                let m_b_value = m_b_values[random_choice_bit as usize];

                let res = self.t_a_list[idx]
                    .diffie_hellman(&PublicKey::from(m_b_value))
                    .to_bytes();
                res[0..LAMBDA_C_BYTES].try_into().unwrap()
            });

        ReceiverOutput {
            choice_bits: self.packed_choice_bits,
            otp_dec_keys: rho_w_vec,
        }
    }
}

// FIXME: required only for testing
impl ReceiverOutput {
    /// Create a new `ReceiverOutput`.
    pub fn new(
        choice_bits: [u8; LAMBDA_C_BYTES],
        otp_dec_keys: [[u8; LAMBDA_C_BYTES]; LAMBDA_C],
    ) -> Self {
        Self {
            choice_bits,
            otp_dec_keys,
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
        let session_id: [u8; 32] = rng.gen();

        let mut msg1 = EndemicOTMsg1::default();

        let receiver =
            EndemicOTReceiver::new(&session_id, &mut msg1, &mut rng);

        let mut msg2 = EndemicOTMsg2::default();
        let sender_output =
            EndemicOTSender::process(&session_id, &msg1, &mut msg2, &mut rng);

        let receiver_output = receiver.process(&msg2);

        for i in 0..LAMBDA_C {
            let sender_pad = &sender_output.otp_enc_keys[i];

            let rec_pad = &receiver_output.otp_dec_keys[i];

            let bit = receiver_output.choice_bits.extract_bit(i);

            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
