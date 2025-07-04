// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::array;

use bytemuck::{AnyBitPattern, NoUninit};
use curve25519_dalek::{
    ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use rand::prelude::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256 as Shake,
};

use crate::{
    constants::ENDEMIC_OT_LABEL, params::consts::*, utils::ExtractBit,
};

const POINT_BYTES_SIZE: usize = 32;

/// External representation of a point on a curve
pub type PointBytes = [u8; POINT_BYTES_SIZE];

/// EndemicOT Message 1
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg1 {
    // values r_0 and r_1 from OTReceiver to OTSender
    r_list: [[PointBytes; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg1 {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

/// EndemicOT Message 2
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg2 {
    // values m_b_0 and m_b_1 from OTSender to OTReceiver
    m_b_list: [[PointBytes; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg2 {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

/// The one time pad encryption keys for a single choice.
#[derive(Debug)]
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

fn init_shake(input: &[&[u8]]) -> Shake {
    let mut d = Shake::default();
    for i in input {
        d.update(i)
    }
    d
}

// RO for EndemicOT
fn h_function(
    ro_index: usize,
    batch_index: usize,
    session_id: &[u8],
    pk: &RistrettoPoint,
) -> RistrettoPoint {
    let mut bytes = init_shake(&[
        &ENDEMIC_OT_LABEL,
        b"session-id",
        session_id,
        b"ro-index",
        &(ro_index as u16).to_be_bytes(),
        b"batch-index",
        &(batch_index as u16).to_be_bytes(),
        b"pk",
        pk.compress().as_bytes(),
    ])
    .finalize_xof();

    let mut s = [0u8; 64];
    bytes.read(&mut s);
    RistrettoPoint::from_uniform_bytes(&s)
}

// create LAMBDA_C_BYTES ot seed
fn h_function_2(
    batch_index: usize,
    pk: &RistrettoPoint,
) -> [u8; LAMBDA_C_BYTES] {
    let mut bytes = init_shake(&[
        &ENDEMIC_OT_LABEL,
        b"batch_index",
        &(batch_index as u16).to_be_bytes(),
        b"pk",
        pk.compress().as_bytes(),
    ])
    .finalize_xof();

    let mut out = [0u8; LAMBDA_C_BYTES];
    bytes.read(&mut out);

    return out;
}

fn encode_point(p: &RistrettoPoint) -> PointBytes {
    p.compress().to_bytes()
}

#[inline(always)]
fn decode_point(bytes: &PointBytes) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
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
    ) -> Result<SenderOutput, &'static str> {
        let mut error = 0;

        let otp_enc_keys = array::from_fn(|idx| {
            let [r_0, r_1] = &msg1.r_list[idx];

            let r_0 = decode_point(r_0).unwrap_or_else(|| {
                error += 1;
                RistrettoPoint::default()
            });

            let r_1 = decode_point(r_1).unwrap_or_else(|| {
                error += 1;
                RistrettoPoint::default()
            });

            let m_a_0 = r_0 + h_function(0, idx, session_id, &r_1);
            let m_a_1 = r_1 + h_function(1, idx, session_id, &r_0);

            let t_b_0 = Scalar::random(rng);
            let t_b_1 = Scalar::random(rng);

            let m_b_0 = RistrettoPoint::mul_base(&t_b_0);
            let m_b_1 = RistrettoPoint::mul_base(&t_b_1);

            msg2.m_b_list[idx] = [encode_point(&m_b_0), encode_point(&m_b_1)];

            let rho_0 = h_function_2(idx, &(m_a_0 * t_b_0));
            let rho_1 = h_function_2(idx, &(m_a_1 * t_b_1));

            OneTimePadEncryptionKeys { rho_0, rho_1 }
        });

        if error != 0 {
            return Err("Decode error");
        }

        Ok(SenderOutput { otp_enc_keys })
    }
}

/// EndemicOTReceiver
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(zeroize::Zeroize)]
pub struct EndemicOTReceiver {
    pub(crate) packed_choice_bits: [u8; LAMBDA_C_BYTES],
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    t_a_list: [Scalar; LAMBDA_C],
}

impl EndemicOTReceiver {
    /// Create a new instance of the EndemicOT receiver.
    pub fn new<R: RngCore + CryptoRng>(
        session_id: &[u8],
        msg1: &mut EndemicOTMsg1,
        rng: &mut R,
    ) -> Self {
        let packed_choice_bits: [u8; LAMBDA_C_BYTES] = rng.gen();
        let t_a_list = array::from_fn(|_| Scalar::random(rng));

        msg1.r_list
            .iter_mut()
            .enumerate()
            .for_each(|(idx, r_values)| {
                let choice_bit = packed_choice_bits.extract_bit(idx);

                // random scalar
                let t_a = &t_a_list[idx];

                let r_other = RistrettoPoint::random(rng);

                let h_choice =
                    h_function(choice_bit, idx, session_id, &r_other);

                let r_choice = RistrettoPoint::mul_base(t_a) - h_choice;

                // It is crucial for the security of the protocol that
                // the sender is not able to distinguish between two
                // points. Otherwise, it would be able to guess the
                // receiver's choice bit.
                r_values[choice_bit] = encode_point(&r_choice);
                r_values[choice_bit ^ 1] = encode_point(&r_other);
            });

        Self {
            packed_choice_bits,
            t_a_list,
        }
    }

    pub fn process(
        &self,
        msg2: &EndemicOTMsg2,
    ) -> Result<ReceiverOutput, &'static str> {
        let mut error = 0;
        let rho_w_vec: [[u8; LAMBDA_C_BYTES]; LAMBDA_C] =
            array::from_fn(|idx| {
                let choice_bit = self.packed_choice_bits.extract_bit(idx);

                let m_b_value = decode_point(&msg2.m_b_list[idx][choice_bit])
                    .unwrap_or_else(|| {
                        error += 1;
                        RistrettoPoint::default()
                    });

                let res = m_b_value * self.t_a_list[idx];

                h_function_2(idx, &res)
            });

        if error != 0 {
            return Err("Decode error");
        }

        Ok(ReceiverOutput {
            choice_bits: self.packed_choice_bits,
            otp_dec_keys: rho_w_vec,
        })
    }
}

pub fn generate_seed_ot_for_test() -> (SenderOutput, ReceiverOutput) {
    let mut rng = thread_rng();

    let sender_ot_seed = SenderOutput {
        otp_enc_keys: std::array::from_fn(|_| {
            let rho_0 = rng.gen();
            let rho_1 = rng.gen();

            OneTimePadEncryptionKeys { rho_0, rho_1 }
        }),
    };

    let choice_bits: [u8; LAMBDA_C_BYTES] = rng.gen();

    let otp_dec_keys = std::array::from_fn(|i| {
        let choice = choice_bits.extract_bit(i);

        if choice == 0 {
            sender_ot_seed.otp_enc_keys[i].rho_0
        } else {
            sender_ot_seed.otp_enc_keys[i].rho_1
        }
    });

    let receiver_ot_seed = ReceiverOutput {
        choice_bits,
        otp_dec_keys,
    };

    (sender_ot_seed, receiver_ot_seed)
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
            EndemicOTSender::process(&session_id, &msg1, &mut msg2, &mut rng)
                .unwrap();

        let receiver_output = receiver.process(&msg2).unwrap();

        for i in 0..LAMBDA_C {
            let sender_pad = &sender_output.otp_enc_keys[i];

            let rec_pad = &receiver_output.otp_dec_keys[i];

            let bit = receiver_output.choice_bits.extract_bit(i);

            if bit != 0 {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
