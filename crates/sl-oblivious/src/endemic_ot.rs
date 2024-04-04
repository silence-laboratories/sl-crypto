// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use elliptic_curve::bigint::{Encoding, U256};
use elliptic_curve::ops::Reduce;
use elliptic_curve::{Field, Group};
use std::array;

use merlin::Transcript;
use rand::prelude::*;

use crate::{
    constants::ENDEMIC_OT_LABEL, params::consts::*, utils::ExtractBit,
};
use k256::{
    elliptic_curve::group::GroupEncoding, ProjectivePoint, Scalar, Secp256k1,
};
use std::ops::Neg;

/// EndemicOT Message 1
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg1 {
    // values r_0 and r_1 from OTReceiver to OTSender
    r_list: [[[u8; 33]; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg1 {
    fn default() -> Self {
        Self {
            r_list: [[[0u8; 33]; 2]; LAMBDA_C],
        }
    }
}

/// EndemicOT Message 2
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EndemicOTMsg2 {
    // values m_b_0 and m_b_1 from OTSender to OTReceiver
    m_b_list: [[[u8; 33]; 2]; LAMBDA_C],
}

impl Default for EndemicOTMsg2 {
    fn default() -> Self {
        Self {
            m_b_list: [[[0u8; 33]; 2]; LAMBDA_C],
        }
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

/// RO for EndemicOT
fn h_function(
    ro_index: usize,
    batch_index: usize,
    session_id: &[u8],
    pk: &ProjectivePoint,
) -> ProjectivePoint {
    let mut t = Transcript::new(&ENDEMIC_OT_LABEL);

    t.append_message(b"session-id", session_id);
    t.append_message(b"ro-index", &(ro_index as u16).to_be_bytes());
    t.append_message(b"batch_index", &(batch_index as u16).to_be_bytes());
    t.append_message(b"pk", &pk.to_affine().to_bytes());

    let mut output = [0u8; 32];
    t.challenge_bytes(b"", &mut output);

    let s = elliptic_curve::Scalar::<Secp256k1>::reduce(U256::from_be_bytes(
        output,
    ));

    ProjectivePoint::GENERATOR * s
}

/// create LAMBDA_C_BYTES ot seed
fn h_function_2(
    batch_index: usize,
    pk: &ProjectivePoint,
) -> [u8; LAMBDA_C_BYTES] {
    let mut t = Transcript::new(&ENDEMIC_OT_LABEL);

    t.append_message(b"batch_index", &(batch_index as u16).to_be_bytes());
    t.append_message(b"pk", &pk.to_affine().to_bytes());

    let mut output = [0u8; LAMBDA_C_BYTES];
    t.challenge_bytes(b"ot-seed", &mut output);

    output
}

/// Encode ProjectivePoint
fn encode_point(p: &ProjectivePoint) -> [u8; 33] {
    p.to_affine().to_bytes()[..].try_into().unwrap()
}

/// Decode ProjectivePoint
fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);

    ProjectivePoint::from_bytes(&repr).into()
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
        let mut error = false;
        let otp_enc_keys = array::from_fn(|idx| {
            let [r_0, r_1] = &msg1.r_list[idx];

            let r_0_point = match decode_point(r_0) {
                None => {
                    error = true;
                    ProjectivePoint::IDENTITY
                }
                Some(v) => v,
            };
            let r_1_point = match decode_point(r_1) {
                None => {
                    error = true;
                    ProjectivePoint::IDENTITY
                }
                Some(v) => v,
            };

            let m_a_0 =
                r_0_point + h_function(0, idx, session_id, &r_1_point);
            let m_a_1 =
                r_1_point + h_function(1, idx, session_id, &r_0_point);

            let t_b_0 = Scalar::random(&mut *rng);
            let t_b_1 = Scalar::random(&mut *rng);

            let m_b_0 = ProjectivePoint::GENERATOR * t_b_0;
            let m_b_1 = ProjectivePoint::GENERATOR * t_b_1;

            msg2.m_b_list[idx] = [encode_point(&m_b_0), encode_point(&m_b_1)];

            let rho_0 = h_function_2(idx, &(m_a_0 * t_b_0));
            let rho_1 = h_function_2(idx, &(m_a_1 * t_b_1));

            OneTimePadEncryptionKeys { rho_0, rho_1 }
        });

        if error {
            return Err("Decode error");
        }

        Ok(SenderOutput { otp_enc_keys })
    }
}

/// EndemicOTReceiver
/// 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EndemicOTReceiver {
    packed_choice_bits: [u8; LAMBDA_C_BYTES],
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
        let next_state = Self {
            packed_choice_bits: rng.gen(),
            t_a_list: array::from_fn(|_| Scalar::random(&mut *rng)),
        };

        msg1.r_list
            .iter_mut()
            .enumerate()
            .for_each(|(idx, r_values)| {
                let random_choice_bit =
                    next_state.packed_choice_bits.extract_bit(idx) as usize;

                let t_a = &next_state.t_a_list[idx];

                let r_other = ProjectivePoint::random(&mut *rng);
                let r_choice = ProjectivePoint::GENERATOR * t_a
                    + h_function(
                        random_choice_bit,
                        idx,
                        session_id,
                        &r_other,
                    )
                    .neg();

                r_values[random_choice_bit] = encode_point(&r_choice);
                r_values[random_choice_bit ^ 1] = encode_point(&r_other);
            });

        next_state
    }

    pub fn process(
        self,
        msg2: &EndemicOTMsg2,
    ) -> Result<ReceiverOutput, &'static str> {
        let mut error = false;
        let rho_w_vec: [[u8; LAMBDA_C_BYTES]; LAMBDA_C] =
            array::from_fn(|idx| {
                let m_b_values = &msg2.m_b_list[idx];
                let random_choice_bit =
                    self.packed_choice_bits.extract_bit(idx);

                let m_b_value = m_b_values[random_choice_bit as usize];
                let m_b_value = match decode_point(&m_b_value) {
                    None => {
                        error = true;
                        ProjectivePoint::IDENTITY
                    }
                    Some(v) => v,
                };
                let res = m_b_value * self.t_a_list[idx];
                h_function_2(idx, &res)
            });

        if error {
            return Err("Decode error");
        }

        Ok(ReceiverOutput {
            choice_bits: self.packed_choice_bits,
            otp_dec_keys: rho_w_vec,
        })
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

            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
