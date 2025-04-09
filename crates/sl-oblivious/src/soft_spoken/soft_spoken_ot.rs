// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//!
//!  SoftSpokenOT protocol https://eprint.iacr.org/2022/192.pdf
//!  Instantiation of SoftSpokenOT based on Fig.10 https://eprint.iacr.org/2015/546.pdf
//!  Extends LAMBDA_C all-but-one-ot (each LAMBDA_C-bit) to L 1 out of 2 base OTs (each KAPPA-bit) with OT_WIDTH=3
//!  Satisfies Functionality 5.1 https://eprint.iacr.org/2023/765.pdf ,
//!     where X = Z^{OT_WIDTH}_{q} and l_OT = L
//!  Fiat-Shamir transform applied according to Section 5.1 of https://eprint.iacr.org/2023/765.pdf
//!

use std::array;

use bytemuck::{allocation::zeroed_box, AnyBitPattern, NoUninit, Zeroable};
use elliptic_curve::{rand_core::CryptoRngCore, subtle::ConstantTimeEq};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256 as Shake,
};

use crate::{
    constants::{
        SOFT_SPOKEN_EXPAND_LABEL, SOFT_SPOKEN_LABEL,
        SOFT_SPOKEN_MATRIX_HASH_LABEL, SOFT_SPOKEN_RANDOMIZE_LABEL,
    },
    params::consts::*,
    soft_spoken::{
        mul_poly::binary_field_multiply_gf_2_128, types::SoftSpokenOTError,
    },
    utils::{bit_to_bit_mask, ExtractBit},
};

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct SenderOTSeed {
    pub otp_enc_keys:
        [[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; LAMBDA_C / SOFT_SPOKEN_K],
}

impl Default for SenderOTSeed {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct ReceiverOTSeed {
    pub random_choices: [u8; LAMBDA_C_DIV_SOFT_SPOKEN_K], // FIXME: define range of random_choices[i]
    pub otp_dec_keys:
        [[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; LAMBDA_C / SOFT_SPOKEN_K],
}

impl Default for ReceiverOTSeed {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct Round1Output {
    u: [[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K],
    x: [u8; S_BYTES],
    t: [[u8; S_BYTES]; LAMBDA_C], // U128
}

impl Default for Round1Output {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

/// The extended output of the OT sender.
#[derive(Zeroable)]
pub struct SenderExtendedOutput {
    pub v_0: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
    pub v_1: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

impl SenderExtendedOutput {
    pub fn new() -> Box<Self> {
        zeroed_box::<Self>()
    }
}

/// The extended output of the OT receiver.
#[derive(Zeroable)]
pub struct ReceiverExtendedOutput {
    pub choices: [u8; L_BYTES], // L bits
    pub v_x: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

impl Default for ReceiverExtendedOutput {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

pub struct SoftSpokenOTReceiver;

fn init_shake(input: &[&[u8]]) -> Shake {
    let mut d = Shake::default();
    for i in input {
        d.update(i)
    }
    d
}

impl SoftSpokenOTReceiver {
    #[track_caller]
    pub fn process<R: CryptoRngCore>(
        session_id: &[u8],
        seed_ot_results: &SenderOTSeed,
        output: &mut Round1Output,
        extended_output: &mut ReceiverExtendedOutput,
        rng: &mut R,
    ) {
        let extended_packed_choices = {
            let mut buf = [0u8; L_PRIME_BYTES];
            buf[..L_BYTES].copy_from_slice(&extended_output.choices);
            rng.fill_bytes(&mut buf[L_BYTES..]);
            buf
        };

        let mut rx: [[[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
            SOFT_SPOKEN_Q] = bytemuck::zeroed();

        for (j, rx_j) in rx.iter_mut().enumerate() {
            for (i, rx_j_i) in rx_j.iter_mut().enumerate() {
                init_shake(&[
                    &SOFT_SPOKEN_LABEL,
                    session_id,
                    &seed_ot_results.otp_enc_keys[i][j],
                    &SOFT_SPOKEN_EXPAND_LABEL,
                ])
                .finalize_xof_into(rx_j_i);
            }
        }

        let t = &mut output.t;
        let u = &mut output.u;

        let mut matrix_hasher =
            init_shake(&[&SOFT_SPOKEN_LABEL, b"session_id", session_id]);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for (j, choice) in extended_packed_choices.iter().enumerate() {
                for r_x_k in &rx {
                    u[i][j] ^= r_x_k[i][j];
                }
                u[i][j] ^= choice;
            }

            matrix_hasher.update(&u[i]);
        }

        // matrix V [LAMBDA_C][COT_EXTENDED_BLOCK_SIZE_BYTES] byte
        // set of vectors v, where each v = v_0 + 2*v_1 + .. + 2^{k-1}*v_{k-1}
        // v_i = sum_x x_i*r_x
        let mut v: [[u8; L_PRIME_BYTES]; LAMBDA_C] = bytemuck::zeroed();

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for bit_index in 0..SOFT_SPOKEN_K {
                // This seems more readable in this situation
                #[allow(clippy::needless_range_loop)]
                for j in 0..SOFT_SPOKEN_Q {
                    let bit = ((j >> bit_index) & 0x01) as u8;
                    let x_i_mask = bit_to_bit_mask(bit);
                    for k in 0..L_PRIME_BYTES {
                        v[i * SOFT_SPOKEN_K + bit_index][k] ^=
                            x_i_mask & rx[j][i][k];
                    }
                }
            }
        }

        let mut digest_matrix_u = [0u8; 32];
        matrix_hasher.update(&SOFT_SPOKEN_MATRIX_HASH_LABEL);
        matrix_hasher.finalize_xof_into(&mut digest_matrix_u);

        for j in 0..SOFT_SPOKEN_M {
            let mut chi_j = [0u8; S_BYTES];

            init_shake(&[&(j as u64).to_be_bytes(), &digest_matrix_u])
                .finalize_xof_into(&mut chi_j);

            let x_hat_j = extended_packed_choices[j * S_BYTES..][..S_BYTES]
                .try_into()
                .unwrap();

            let x_hat_j_times_chi_j =
                binary_field_multiply_gf_2_128(x_hat_j, &chi_j);

            for (x_k, x_hat_k) in
                output.x.iter_mut().zip(&x_hat_j_times_chi_j)
            {
                *x_k ^= x_hat_k;
            }

            for (t_i, v_i) in t.iter_mut().zip(&v) {
                let t_hat_j =
                    v_i[j * S_BYTES..][..S_BYTES].try_into().unwrap();

                let t_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(t_hat_j, &chi_j);

                for k in 0..S_BYTES {
                    t_i[k] ^= t_hat_j_times_chi_j[k];
                }
            }
        }

        const FROM_INDEX: usize = SOFT_SPOKEN_M * S_BYTES;

        for (x_i, c) in &mut output
            .x
            .iter_mut()
            .zip(&extended_packed_choices[FROM_INDEX..][..S_BYTES])
        {
            *x_i ^= c;
        }

        for (t_i, v_i) in t.iter_mut().zip(&v) {
            for (t, b) in t_i.iter_mut().zip(&v_i[FROM_INDEX..][..S_BYTES]) {
                *t ^= b;
            }
        }

        let psi = transpose_bool_matrix(&v);

        for (j, v_x_j) in extended_output.v_x.iter_mut().enumerate() {
            let mut bytes = init_shake(&[
                &SOFT_SPOKEN_LABEL,
                b"session-id",
                session_id,
                b"index",
                &(j as u64).to_be_bytes(),
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &psi[j],
            ])
            .finalize_xof();

            for k in v_x_j.iter_mut() {
                bytes.read(k);
            }
        }
    }
}

#[track_caller]
fn transpose_bool_matrix(
    input: &[[u8; L_PRIME_BYTES]; LAMBDA_C],
) -> [[u8; LAMBDA_C_BYTES]; L] {
    // Unit of a column group.
    type Unit = usize;
    const U: usize = core::mem::size_of::<Unit>();

    // A group of 8 columns, in chunks of Unit items. The total size
    // of `columns` is always LAMBDA_C. Each byte contains bits for 8
    // sequential output rows.
    let mut columns = [0; LAMBDA_C / U];

    array::from_fn(|output_row| {
        let column_offset = output_row % 8;

        // load a group of columns
        if column_offset == 0 {
            for (chunk, rows) in input.chunks_exact(U).enumerate() {
                // load U bytes from input matrix
                let b: [u8; U] = array::from_fn(|i| rows[i][output_row / 8]);
                // and convert them into one unit
                columns[chunk] = Unit::from_le_bytes(b);
            }
        }

        // for each byte of a row of the output matrix
        array::from_fn(|row_byte_index| {
            // for eahc bit of a byte
            (0..8)
                .map(|o_bit| {
                    // bit_index is range 0..LAMBDA_C
                    let bit_index = o_bit + row_byte_index * 8;
                    // each unit contains U output bits,
                    // one in each byte of a unit
                    let c_index = bit_index / U;
                    // index of a bit within unit of the column group
                    let c_bit = (bit_index % U) * 8 + column_offset;
                    // mask of the output bit
                    let mask = 1 << o_bit;

                    // extract one bit from column group unit
                    (((columns[c_index] >> c_bit) << o_bit) as u8) & mask
                })
                .sum()
        })
    })
}

pub struct SoftSpokenOTSender;

impl SoftSpokenOTSender {
    #[track_caller]
    pub fn process(
        session_id: &[u8],
        seed_ot_results: &ReceiverOTSeed,
        message: &Round1Output,
    ) -> Result<Box<SenderExtendedOutput>, SoftSpokenOTError> {
        let mut rx: [[[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
            SOFT_SPOKEN_Q] = bytemuck::zeroed();

        for (j, rx_j) in rx.iter_mut().enumerate() {
            for (i, rx_j_i) in rx_j.iter_mut().enumerate() {
                if j != seed_ot_results.random_choices[i] as usize {
                    init_shake(&[
                        &SOFT_SPOKEN_LABEL,
                        session_id,
                        &seed_ot_results.otp_dec_keys[i][j],
                        &SOFT_SPOKEN_EXPAND_LABEL,
                    ])
                    .finalize_xof_into(rx_j_i);
                }
            }
        }

        // 20k
        let mut w_matrix: [[u8; L_PRIME_BYTES]; LAMBDA_C] =
            bytemuck::zeroed();

        let mut matrix_hasher =
            init_shake(&[&SOFT_SPOKEN_LABEL, b"session_id", session_id]);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let delta = seed_ot_results.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                for (j, rx_j) in rx.iter().enumerate() {
                    let delta_minus_x = delta ^ (j as u8);
                    let bit = (delta_minus_x >> bit_index) & 0x01;
                    let x_i = bit_to_bit_mask(bit);
                    for k in 0..L_PRIME_BYTES {
                        w_matrix[i * SOFT_SPOKEN_K + bit_index][k] ^=
                            x_i & rx_j[i][k];
                    }
                }

                let delta_i = (delta >> bit_index) & 0x01;
                let delta_i_mask = bit_to_bit_mask(delta_i);
                for k in 0..L_PRIME_BYTES {
                    w_matrix[i * SOFT_SPOKEN_K + bit_index][k] ^=
                        delta_i_mask & message.u[i][k];
                }
            }

            matrix_hasher.update(&message.u[i]);
        }

        let mut packed_nabla = [0u8; LAMBDA_C_BYTES];

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let delta = seed_ot_results.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                let delta_i = (delta >> bit_index) & 0x01;
                let byte_index = (i * SOFT_SPOKEN_K + bit_index) / 8;
                let bit_index2 = (i * SOFT_SPOKEN_K + bit_index) % 8;
                packed_nabla[byte_index] ^= delta_i << bit_index2;
            }
        }

        let mut digest_matrix_u = [0u8; 32];
        matrix_hasher.update(&SOFT_SPOKEN_MATRIX_HASH_LABEL);
        matrix_hasher.finalize_xof_into(&mut digest_matrix_u);

        let mut chi_matrix = [[0u8; S_BYTES]; SOFT_SPOKEN_M];
        for (j, chi_j) in chi_matrix.iter_mut().enumerate() {
            init_shake(&[&(j as u64).to_be_bytes(), &digest_matrix_u])
                .finalize_xof_into(chi_j);
        }

        const FROM_INDEX: usize = SOFT_SPOKEN_M * S_BYTES;

        for (i, w_matrix_i) in w_matrix.iter().enumerate() {
            let mut q_row = [0u8; S_BYTES];

            for (j, chi_j) in chi_matrix.iter().enumerate() {
                let q_hat_j =
                    w_matrix_i[j * S_BYTES..][..S_BYTES].try_into().unwrap();

                let q_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(q_hat_j, chi_j);

                for k in 0..S_BYTES {
                    q_row[k] ^= q_hat_j_times_chi_j[k];
                }
            }

            q_row
                .iter_mut()
                .zip(&w_matrix_i[FROM_INDEX..])
                .for_each(|(q, w)| *q ^= w);

            // check

            let bit = packed_nabla.extract_bit(i);
            let bit_mask = bit_to_bit_mask(bit as u8);

            let t_i_plus_delta_i_times_x: [u8; S_BYTES] =
                array::from_fn(|k| {
                    message.t[i][k] ^ (bit_mask & message.x[k])
                });

            if q_row.ct_ne(&t_i_plus_delta_i_times_x).into() {
                return Err(SoftSpokenOTError);
            }
        }

        // 20k
        let mut zeta = transpose_bool_matrix(&w_matrix);
        let mut output = SenderExtendedOutput::new();

        let v_0 = &mut output.v_0;
        let v_1 = &mut output.v_1;

        for j in 0..L {
            let mut bytes = init_shake(&[
                &SOFT_SPOKEN_LABEL,
                b"session-id",
                session_id,
                b"index",
                &(j as u64).to_be_bytes(),
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &zeta[j],
            ])
            .finalize_xof();

            for k in &mut v_0[j] {
                bytes.read(k);
            }

            packed_nabla
                .iter()
                .zip(&mut zeta[j])
                .for_each(|(b, z)| *z ^= b);

            let mut bytes = init_shake(&[
                &SOFT_SPOKEN_LABEL,
                b"session-id",
                session_id,
                b"index",
                &(j as u64).to_be_bytes(),
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &zeta[j],
            ])
            .finalize_xof();

            for k in &mut v_1[j] {
                bytes.read(k);
            }
        }

        Ok(output)
    }
}

pub fn generate_all_but_one_seed_ot<R: CryptoRngCore>(
    rng: &mut R,
) -> (SenderOTSeed, ReceiverOTSeed) {
    use rand::Rng;

    let mut sender_ot_seed = SenderOTSeed::default();
    let mut receiver_ot_seed = ReceiverOTSeed::default();

    for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
        let ot_sender_messages: [[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q] =
            array::from_fn(|_| rng.gen());

        sender_ot_seed.otp_enc_keys[i] = ot_sender_messages;
        receiver_ot_seed.otp_dec_keys[i] = ot_sender_messages;
    }

    receiver_ot_seed.random_choices =
        array::from_fn(|_| rng.gen_range(0..=SOFT_SPOKEN_Q - 1) as u8);

    for i in 0..(LAMBDA_C_DIV_SOFT_SPOKEN_K) {
        let choice = receiver_ot_seed.random_choices[i];
        receiver_ot_seed.otp_dec_keys[i][choice as usize].fill(0);
    }

    (sender_ot_seed, receiver_ot_seed)
}

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use crate::{
        params::consts::*,
        soft_spoken::{
            generate_all_but_one_seed_ot, ReceiverExtendedOutput,
            Round1Output, SoftSpokenOTReceiver, SoftSpokenOTSender,
        },
        utils::ExtractBit,
    };

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn soft_spoken() {
        let mut rng = rand::thread_rng();

        let (sender_ot_results, receiver_ot_results) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id: [u8; 32] = rng.gen();
        let mut choices = [0u8; L_BYTES];
        rng.fill_bytes(&mut choices);

        let mut round1 = Round1Output::default();
        let mut receiver_extended_output = ReceiverExtendedOutput::default();
        receiver_extended_output.choices = choices;

        SoftSpokenOTReceiver::process(
            &session_id,
            &sender_ot_results,
            &mut round1,
            &mut receiver_extended_output,
            &mut rng,
        );

        let sender_extended_output = SoftSpokenOTSender::process(
            &session_id,
            &receiver_ot_results,
            &round1,
        )
        .unwrap();

        for i in 0..L {
            let bit = choices.extract_bit(i);
            let receiver_choice_bit =
                receiver_extended_output.choices.extract_bit(i);
            assert_eq!(bit, receiver_choice_bit);

            for k in 0..OT_WIDTH {
                let receiver_value = &receiver_extended_output.v_x[i][k];
                let sender_value = if bit != 0 {
                    &sender_extended_output.v_1[i][k]
                } else {
                    &sender_extended_output.v_0[i][k]
                };
                assert_eq!(sender_value, receiver_value);
            }
        }
    }
}
