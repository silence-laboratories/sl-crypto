///
///  SoftSpokenOT protocol https://eprint.iacr.org/2022/192.pdf
///  Instantiation of SoftSpokenOT based on Fig.10 https://eprint.iacr.org/2015/546.pdf
///  Extends LAMBDA_C all-but-one-ot (each LAMBDA_C-bit) to L 1 out of 2 base OTs (each KAPPA-bit) with OT_WIDTH=3
///  Satisfies Functionality 5.1 https://eprint.iacr.org/2023/765.pdf ,
///     where X = Z^{OT_WIDTH}_{q} and l_OT = L
///  Fiat-Shamir transform applied according to Section 5.1 of https://eprint.iacr.org/2023/765.pdf
///
use std::array;

use elliptic_curve::{rand_core::CryptoRngCore, subtle::ConstantTimeEq};
use merlin::Transcript;
use rand::Rng;

use crate::{
    constants::{
        SOFT_SPOKEN_EXPAND_LABEL, SOFT_SPOKEN_LABEL,
        SOFT_SPOKEN_MATRIX_HASH_LABEL, SOFT_SPOKEN_RANDOMIZE_LABEL,
    },
    params::consts::*,
    soft_spoken::types::SoftSpokenOTError,
    utils::{bit_to_bit_mask, ExtractBit},
};

use super::mul_poly::binary_field_multiply_gf_2_128;

#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct SenderOTSeed {
    pub otp_enc_keys:
        [[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; LAMBDA_C / SOFT_SPOKEN_K],
}

impl Default for SenderOTSeed {
    fn default() -> Self {
        Self {
            otp_enc_keys: [[[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
                LAMBDA_C / SOFT_SPOKEN_K],
        }
    }
}

#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct ReceiverOTSeed {
    pub random_choices: [u8; LAMBDA_C_DIV_SOFT_SPOKEN_K], // FIXME: define range of random_choices[i]
    pub otp_dec_keys:
        [[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; LAMBDA_C / SOFT_SPOKEN_K],
}

impl Default for ReceiverOTSeed {
    fn default() -> Self {
        Self {
            random_choices: [0u8; LAMBDA_C_DIV_SOFT_SPOKEN_K],
            otp_dec_keys: [[[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];
                LAMBDA_C / SOFT_SPOKEN_K],
        }
    }
}

#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct Round1Output {
    u: [[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K],
    x: [u8; S_BYTES],
    t: [[u8; S_BYTES]; LAMBDA_C], // U128
}

impl Default for Round1Output {
    fn default() -> Self {
        Self {
            u: [[0; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K],
            x: [0; S_BYTES],
            t: [[0; S_BYTES]; LAMBDA_C],
        }
    }
}

/// The extended output of the OT sender.
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct SenderExtendedOutput {
    pub v_0: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
    pub v_1: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

impl SenderExtendedOutput {
    pub fn new() -> Box<Self> {
        bytemuck::allocation::zeroed_box::<Self>()
    }
}

/// The extended output of the OT receiver.
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct ReceiverExtendedOutput {
    pub choices: [u8; L_BYTES], // L bits
    pub v_x: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

#[cfg(test)]
impl ReceiverExtendedOutput {
    pub(crate) fn new(choices: &[u8; L_BYTES]) -> Box<Self> {
        let mut this = bytemuck::allocation::zeroed_box::<Self>();
        this.choices = *choices;
        this
    }
}

///
pub struct SoftSpokenOTReceiver;

impl SoftSpokenOTReceiver {
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

        let mut r_x = [[[0u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
            SOFT_SPOKEN_Q];

        let t = &mut output.t;
        let u = &mut output.u;

        let mut matrix_hasher = Transcript::new(&SOFT_SPOKEN_LABEL);
        matrix_hasher.append_message(b"session-id", session_id);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for (j, r_x_j) in r_x.iter_mut().enumerate() {
                let mut ts = Transcript::new(&SOFT_SPOKEN_LABEL);
                ts.append_message(b"", session_id);
                ts.append_message(b"", &seed_ot_results.otp_enc_keys[i][j]);
                ts.challenge_bytes(&SOFT_SPOKEN_EXPAND_LABEL, &mut r_x_j[i]);
            }

            for (j, choice) in extended_packed_choices.iter().enumerate() {
                for r_x_k in &r_x {
                    u[i][j] ^= r_x_k[i][j];
                }
                u[i][j] ^= choice;
            }

            matrix_hasher.append_message(b"", &u[i]);
        }

        // matrix V [LAMBDA_C][COT_EXTENDED_BLOCK_SIZE_BYTES] byte
        // set of vectors v, where each v = v_0 + 2*v_1 + .. + 2^{k-1}*v_{k-1}
        // v_i = sum_x x_i*r_x
        let mut v = [[0u8; L_PRIME_BYTES]; LAMBDA_C];

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for bit_index in 0..SOFT_SPOKEN_K {
                // This seems more readable in this situation
                #[allow(clippy::needless_range_loop)]
                for j in 0..SOFT_SPOKEN_Q {
                    let bit = ((j >> bit_index) & 0x01) as u8;
                    let x_i_mask = bit_to_bit_mask(bit);
                    for k in 0..L_PRIME_BYTES {
                        v[i * SOFT_SPOKEN_K + bit_index][k] ^=
                            x_i_mask & r_x[j][i][k];
                    }
                }
            }
        }

        let mut digest_matrix_u = [0u8; 32];
        matrix_hasher.challenge_bytes(
            &SOFT_SPOKEN_MATRIX_HASH_LABEL,
            &mut digest_matrix_u,
        );

        for j in 0..SOFT_SPOKEN_M {
            let mut ts = Transcript::new(b"");
            ts.append_u64(b"index", j as u64);
            ts.append_message(b"", &digest_matrix_u);

            let mut chi_j = [0u8; S_BYTES];
            ts.challenge_bytes(b"", &mut chi_j);

            let x_hat_j = &extended_packed_choices[j * S_BYTES..][..S_BYTES]
                .try_into()
                .expect("x_hat_j invalid length, must be 16 bytes");

            let x_hat_j_times_chi_j =
                binary_field_multiply_gf_2_128(x_hat_j, &chi_j);

            for (x_k, x_hat_k) in
                output.x.iter_mut().zip(&x_hat_j_times_chi_j)
            {
                *x_k ^= x_hat_k;
            }

            for (t_i, v_i) in t.iter_mut().zip(&v) {
                let t_hat_j = &v_i[j * S_BYTES..][..S_BYTES]
                    .try_into()
                    .expect("t_hat_j invalid length, must be 16 bytes");

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
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &psi[j]);

            for k in v_x_j.iter_mut() {
                t.challenge_bytes(b"", k);
            }
        }
    }
}

fn transpose_bool_matrix(
    input: &[[u8; L_PRIME_BYTES]; LAMBDA_C],
) -> [[u8; LAMBDA_C_BYTES]; L_PRIME] {
    let mut output = [[0u8; LAMBDA_C_BYTES]; L_PRIME];
    for row_byte in 0..LAMBDA_C_BYTES {
        for row_bit_byte in 0..8 {
            for column_byte in 0..L_PRIME_BYTES {
                for column_bit_byte in 0..8 {
                    let row_bit_index = (row_byte << 3) + row_bit_byte;

                    let column_bit_index =
                        (column_byte << 3) + column_bit_byte;

                    let bit_at_input_row_bit_column_bit =
                        input[row_bit_index][column_byte] >> column_bit_byte
                            & 0x01;

                    let shifted_bit =
                        bit_at_input_row_bit_column_bit << row_bit_byte;

                    output[column_bit_index][row_byte] |= shifted_bit;
                }
            }
        }
    }
    output
}

pub struct SoftSpokenOTSender;

impl SoftSpokenOTSender {
    pub fn process(
        session_id: &[u8],
        seed_ot_results: &ReceiverOTSeed,
        message: &Round1Output,
    ) -> Result<Box<SenderExtendedOutput>, SoftSpokenOTError> {
        // let mut r_x = [[[0u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
        //     SOFT_SPOKEN_Q];

        let mut r_x = bytemuck::allocation::zeroed_box::<
            [[[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
                SOFT_SPOKEN_Q],
        >();

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for (j, rx_j) in r_x.iter_mut().enumerate() {
                if j == seed_ot_results.random_choices[i] as usize {
                    rx_j[i].fill(0);
                } else {
                    let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
                    t.append_message(b"", session_id);
                    t.append_message(
                        b"",
                        &seed_ot_results.otp_dec_keys[i][j],
                    );
                    t.challenge_bytes(
                        &SOFT_SPOKEN_EXPAND_LABEL,
                        &mut rx_j[i],
                    );
                }
            }
        }

        // 20k
        let mut w_matrix = [[0u8; L_PRIME_BYTES]; LAMBDA_C];

        let mut hash_matrix_u = Transcript::new(&SOFT_SPOKEN_LABEL);
        hash_matrix_u.append_message(b"session-id", session_id);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let delta = seed_ot_results.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                for (j, rx_j) in r_x.iter().enumerate() {
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

            hash_matrix_u.append_message(b"", &message.u[i]);
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
        hash_matrix_u.challenge_bytes(
            &SOFT_SPOKEN_MATRIX_HASH_LABEL,
            &mut digest_matrix_u,
        );

        let chi_matrix: [[u8; S_BYTES]; SOFT_SPOKEN_M] =
            array::from_fn(|j| {
                let mut ts = Transcript::new(b"");
                ts.append_u64(b"index", j as u64);
                ts.append_message(b"", &digest_matrix_u);

                let mut chi_j = [0u8; S_BYTES];
                ts.challenge_bytes(b"", &mut chi_j);

                chi_j
            });

        let from_index = SOFT_SPOKEN_M * S_BYTES;
        let to_index = (SOFT_SPOKEN_M + 1) * S_BYTES;

        for (i, w_matrix_i) in w_matrix.iter().enumerate() {
            let mut q_row = [0u8; S_BYTES];

            for (j, chi_j) in chi_matrix.iter().enumerate() {
                let q_hat_j = w_matrix_i[j * S_BYTES..(j + 1) * S_BYTES]
                    .try_into()
                    .expect("q_hat_j is not the right length");

                let q_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(&q_hat_j, chi_j);

                for k in 0..S_BYTES {
                    q_row[k] ^= q_hat_j_times_chi_j[k];
                }
            }

            q_row
                .iter_mut()
                .zip(&w_matrix[i][from_index..to_index])
                .for_each(|(q, w)| *q ^= w);

            // check

            let bit = packed_nabla.extract_bit(i);
            let bit_mask = bit_to_bit_mask(bit as u8);

            let t_i_plus_delta_i_times_x: [u8; S_BYTES] =
                array::from_fn(|k| {
                    message.t[i][k] ^ (bit_mask & message.x[k])
                });

            if q_row.ct_ne(&t_i_plus_delta_i_times_x).into() {
                return Err(SoftSpokenOTError::AbortProtocolAndBanReceiver);
            }
        }

        // 20k
        let mut zeta = transpose_bool_matrix(&w_matrix);
        let mut output = SenderExtendedOutput::new();

        let v_0 = &mut output.v_0;
        let v_1 = &mut output.v_1;

        for j in 0..L {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &zeta[j]);

            for k in &mut v_0[j] {
                t.challenge_bytes(b"", k);
            }

            packed_nabla
                .iter()
                .zip(&mut zeta[j])
                .for_each(|(b, z)| *z ^= b);

            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &zeta[j]);

            for k in &mut v_1[j] {
                t.challenge_bytes(b"", k);
            }
        }

        Ok(output)
    }
}

pub fn generate_all_but_one_seed_ot<R: CryptoRngCore>(
    rng: &mut R,
) -> (SenderOTSeed, ReceiverOTSeed) {
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
        receiver_ot_seed.otp_dec_keys[i][choice as usize] =
            [0u8; LAMBDA_C_BYTES];
    }

    (sender_ot_seed, receiver_ot_seed)
}

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use crate::{
        params::consts::*,
        soft_spoken::{
            generate_all_but_one_seed_ot,
            ReceiverExtendedOutput,
            Round1Output,
            SoftSpokenOTReceiver,
            SoftSpokenOTSender, // L, L_BYTES, OT_WIDTH,
        },
        utils::ExtractBit,
    };

    #[test]
    fn soft_spoken() {
        let mut rng = rand::thread_rng();

        let (sender_ot_results, receiver_ot_results) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id: [u8; 32] = rng.gen();
        let mut choices = [0u8; L_BYTES];
        rng.fill_bytes(&mut choices);

        let mut round1 = Round1Output::default();
        let mut receiver_extended_output =
            ReceiverExtendedOutput::new(&choices);

        // let start = std::time::Instant::now();
        SoftSpokenOTReceiver::process(
            &session_id,
            &sender_ot_results,
            &mut round1,
            &mut receiver_extended_output,
            &mut rng,
        );
        // println!("Round1: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let sender_extended_output = SoftSpokenOTSender::process(
            &session_id,
            &receiver_ot_results,
            &round1,
        )
        .unwrap();
        // println!("Round2: {:?}", start.elapsed());

        for i in 0..L {
            let bit = choices.extract_bit(i);
            let receiver_choice_bit =
                receiver_extended_output.choices.extract_bit(i);
            assert_eq!(bit, receiver_choice_bit);

            for k in 0..OT_WIDTH {
                let receiver_value = receiver_extended_output.v_x[i][k];
                let sender_value = match bit {
                    true => sender_extended_output.v_1[i][k],
                    false => sender_extended_output.v_0[i][k],
                };
                assert_eq!(&sender_value, &receiver_value);
            }
        }
    }
}
