///
///  SoftSpokenOT protocol https://eprint.iacr.org/2022/192.pdf
///  Instantiation of SoftSpokenOT based on Fig.10 https://eprint.iacr.org/2015/546.pdf
///  Extends LAMBDA_C all-but-one-ot (each LAMBDA_C-bit) to L 1 out of 2 base OTs (each KAPPA-bit) with OT_WIDTH=3
///  Satisfies Functionality 5.1 https://eprint.iacr.org/2023/765.pdf ,
///     where X = Z^{OT_WIDTH}_{q} and l_OT = L
///  Fiat-Shamir transform applied according to Section 5.1 of https://eprint.iacr.org/2023/765.pdf
///
use std::array;

use elliptic_curve::rand_core::CryptoRngCore;
use merlin::Transcript;
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::{
    bincode::{
        de::{read::Reader, BorrowDecode, BorrowDecoder, Decoder},
        enc::{write::Writer, Encoder},
        error::{DecodeError, EncodeError},
        Decode, Encode,
    },
    SessionId,
};

use crate::{
    constants::{
        SOFT_SPOKEN_EXPAND_LABEL, SOFT_SPOKEN_LABEL,
        SOFT_SPOKEN_MATRIX_HASH_LABEL, SOFT_SPOKEN_RANDOMIZE_LABEL,
    },
    endemic_ot::{LAMBDA_C, LAMBDA_C_BYTES},
    soft_spoken::types::SoftSpokenOTError,
    utils::{bit_to_bit_mask, ExtractBit},
};

use super::mul_poly::binary_field_multiply_gf_2_128;

pub const KAPPA: usize = 256; // Bits on underlying Scalar
pub const KAPPA_BYTES: usize = KAPPA >> 3;

pub const S: usize = 128; // 16 bytes == 128 bits
pub const S_BYTES: usize = S >> 3;

pub const LAMBDA_S: usize = 128;
pub const L: usize = KAPPA + 2 * LAMBDA_S; // L is divisible by S
pub const L_BYTES: usize = L >> 3;

pub const L_PRIME: usize = L + S;
pub const L_PRIME_BYTES: usize = L_PRIME >> 3;

pub const SOFT_SPOKEN_M: usize = L / S;

pub const OT_WIDTH: usize = 3; // === L_BATCH + RHO

pub const SOFT_SPOKEN_K: usize = 4;
pub const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K; // 2usize.pow(SOFT_SPOKEN_K as u32);

pub const LAMBDA_C_DIV_SOFT_SPOKEN_K: usize = LAMBDA_C / SOFT_SPOKEN_K;
pub const RAND_EXTENSION_SIZE: usize = L_PRIME_BYTES - L_BYTES;

#[derive(
    Debug,
    Default,
    Clone,
    bincode::Encode,
    bincode::Decode,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct SenderOTSeed {
    pub one_time_pad_enc_keys: Vec<[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]>, // [LAMBDA_C / SOFT_SPOKEN_K]
}

#[derive(
    Debug, Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct ReceiverOTSeed {
    pub random_choices: [u8; LAMBDA_C_DIV_SOFT_SPOKEN_K], // FIXME: define range of random_choices[i]
    pub one_time_pad_dec_keys: Vec<[[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]>, // [LAMBDA_C / SOFT_SPOKEN_K]
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Round1Output {
    pub u: [[u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K],
    pub x: [u8; S_BYTES],
    pub t: [[u8; S_BYTES]; LAMBDA_C], // U128
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

//
impl Encode for Round1Output {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        for u in &self.u {
            encoder.writer().write(u)?;
        }

        encoder.writer().write(&self.x)?;

        for v in &self.t {
            encoder.writer().write(v)?;
        }

        Ok(())
    }
}

impl Decode for Round1Output {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut r = Round1Output::default();

        for u in &mut r.u {
            decoder.reader().read(u)?;
        }

        decoder.reader().read(&mut r.x)?;

        for v in &mut r.t {
            decoder.reader().read(v)?;
        }

        Ok(r)
    }
}

impl<'de> BorrowDecode<'de> for Round1Output {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

/// The extended output of the OT sender.
pub struct SenderExtendedOutput {
    pub v_0: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
    pub v_1: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

/// The extended output of the OT receiver.
pub struct ReceiverExtendedOutput {
    pub choices: [u8; L_BYTES], // L bits
    pub v_x: [[[u8; KAPPA_BYTES]; OT_WIDTH]; L],
}

///
pub struct SoftSpokenOTReceiver<'a> {
    session_id: &'a SessionId,
    seed_ot_results: &'a SenderOTSeed,
}

impl<'a> SoftSpokenOTReceiver<'a> {
    pub fn new(
        session_id: &'a SessionId,
        seed_ot_results: &'a SenderOTSeed,
    ) -> Self {
        Self {
            session_id,
            seed_ot_results,
        }
    }
}

impl<'a> SoftSpokenOTReceiver<'a> {
    pub fn process<R: CryptoRngCore>(
        self,
        choices: &[u8; L_BYTES],
        rng: &mut R,
    ) -> (Round1Output, Box<ReceiverExtendedOutput>) {
        let extended_packed_choices = {
            let mut buf = [0u8; L_PRIME_BYTES];
            buf[..L_BYTES].copy_from_slice(choices);
            rng.fill_bytes(&mut buf[L_BYTES..]);
            buf
        };

        let mut r_x = [[[0u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
            SOFT_SPOKEN_Q];

        let mut output = Round1Output::default();

        let x = &mut output.x;
        let t = &mut output.t;
        let u = &mut output.u;

        let mut matrix_hasher = Transcript::new(&SOFT_SPOKEN_LABEL);
        matrix_hasher.append_message(b"session-id", self.session_id);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for (j, r_x_j) in r_x.iter_mut().enumerate() {
                let mut ts = Transcript::new(&SOFT_SPOKEN_LABEL);
                ts.append_message(b"", self.session_id);
                ts.append_message(
                    b"",
                    &self.seed_ot_results.one_time_pad_enc_keys[i][j],
                );
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

            let x_hat_j = &extended_packed_choices
                [j * S_BYTES..(j + 1) * S_BYTES]
                .try_into()
                .expect("x_hat_j invalid length, must be 16 bytes");

            let x_hat_j_times_chi_j =
                binary_field_multiply_gf_2_128(x_hat_j, &chi_j);

            for k in 0..S_BYTES {
                x[k] ^= x_hat_j_times_chi_j[k];
            }

            for i in 0..LAMBDA_C {
                let t_hat_j = &v[i][j * S_BYTES..(j + 1) * S_BYTES]
                    .try_into()
                    .expect("t_hat_j invalid length, must be 16 bytes");
                let t_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(t_hat_j, &chi_j);

                (0..S_BYTES).for_each(|k| {
                    t[i][k] ^= t_hat_j_times_chi_j[k];
                })
            }
        }

        let from_index = SOFT_SPOKEN_M * S_BYTES;
        let to_index = (SOFT_SPOKEN_M + 1) * S_BYTES;

        let x_hat_m_plus_1 = &extended_packed_choices[from_index..to_index];

        for k in 0..S_BYTES {
            x[k] ^= x_hat_m_plus_1[k];
        }

        for i in 0..LAMBDA_C {
            let t_i = &mut t[i];

            let t_hat_m_plus_1 = &v[i][from_index..to_index];
            (0..S_BYTES).for_each(|k| {
                t_i[k] ^= t_hat_m_plus_1[k];
            })
        }

        let mut extended_output = Box::new(ReceiverExtendedOutput {
            choices: *choices,
            v_x: [[[0u8; KAPPA_BYTES]; OT_WIDTH]; L],
        });
        let v_x = &mut extended_output.v_x;

        let psi = transpose_bool_matrix(&v);

        for j in 0..L {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", self.session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &psi[j]);

            for k in &mut v_x[j] {
                t.challenge_bytes(b"", k);
            }
        }

        (output, extended_output)
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

pub struct SoftSpokenOTSender<'a> {
    session_id: &'a SessionId,
    seed_ot_results: &'a ReceiverOTSeed,
}

impl<'a> SoftSpokenOTSender<'a> {
    pub fn new(
        session_id: &'a SessionId,
        seed_ot_results: &'a ReceiverOTSeed,
    ) -> Self {
        Self {
            seed_ot_results,
            session_id,
        }
    }
}

impl<'a> SoftSpokenOTSender<'a> {
    pub fn process(
        self,
        message: &Round1Output,
    ) -> Result<Box<SenderExtendedOutput>, SoftSpokenOTError> {
        let mut r_x = [[[0u8; L_PRIME_BYTES]; LAMBDA_C_DIV_SOFT_SPOKEN_K];
            SOFT_SPOKEN_Q];

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            for (j, rx_j) in r_x.iter_mut().enumerate() {
                if j == self.seed_ot_results.random_choices[i] as usize {
                    rx_j[i].fill(0); // = [0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
                } else {
                    let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
                    t.append_message(b"", self.session_id);
                    t.append_message(
                        b"",
                        &self.seed_ot_results.one_time_pad_dec_keys[i][j],
                    );
                    t.challenge_bytes(
                        &SOFT_SPOKEN_EXPAND_LABEL,
                        &mut rx_j[i],
                    );
                }
            }
        }

        let mut w_matrix = [[0u8; L_PRIME_BYTES]; LAMBDA_C];

        let mut hash_matrix_u = Transcript::new(&SOFT_SPOKEN_LABEL);
        hash_matrix_u.append_message(b"session-id", self.session_id);

        for i in 0..LAMBDA_C_DIV_SOFT_SPOKEN_K {
            let delta = self.seed_ot_results.random_choices[i];
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
            let delta = self.seed_ot_results.random_choices[i];
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
            let q_hat_m_plus_1 = &w_matrix[i][from_index..to_index];
            for k in 0..S_BYTES {
                q_row[k] ^= q_hat_m_plus_1[k];
            }

            // check

            let bit = packed_nabla.extract_bit(i);

            let bit_mask = bit_to_bit_mask(bit as u8);

            let t_i_plus_delta_i_times_x: [u8; S_BYTES] =
                array::from_fn(|k| {
                    message.t[i][k] ^ (bit_mask & message.x[k])
                });

            if q_row != t_i_plus_delta_i_times_x {
                return Err(SoftSpokenOTError::AbortProtocolAndBanReceiver);
            }
        }

        let mut zeta = transpose_bool_matrix(&w_matrix);

        let mut extended_output = Box::new(SenderExtendedOutput {
            v_0: [[[0u8; KAPPA_BYTES]; OT_WIDTH]; L],
            v_1: [[[0u8; KAPPA_BYTES]; OT_WIDTH]; L],
        });
        let v_0 = &mut extended_output.v_0;
        let v_1 = &mut extended_output.v_1;

        for j in 0..L {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", self.session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &zeta[j]);

            for k in &mut v_0[j] {
                t.challenge_bytes(b"", k);
            }

            packed_nabla
                .iter()
                .enumerate()
                .for_each(|(i, b)| zeta[j][i] ^= b);

            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", self.session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(&SOFT_SPOKEN_RANDOMIZE_LABEL, &zeta[j]);

            for k in &mut v_1[j] {
                t.challenge_bytes(b"", k);
            }
        }

        Ok(extended_output)
    }
}

pub fn generate_all_but_one_seed_ot<R: CryptoRngCore>(
    rng: &mut R,
) -> (SenderOTSeed, ReceiverOTSeed) {
    let mut one_time_pad_enc_keys = Vec::new();
    let mut one_time_pad_dec_keys = Vec::new();

    for _ in 0..(crate::soft_spoken::LAMBDA_C_DIV_SOFT_SPOKEN_K) {
        let ot_sender_messages: [[u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q] =
            array::from_fn(|_| rng.gen());

        one_time_pad_enc_keys.push(ot_sender_messages);
        one_time_pad_dec_keys.push(ot_sender_messages);
    }

    let random_choices =
        array::from_fn(|_| rng.gen_range(0..=SOFT_SPOKEN_Q - 1) as u8);

    for i in 0..(LAMBDA_C_DIV_SOFT_SPOKEN_K) {
        let choice = random_choices[i];
        one_time_pad_dec_keys[i][choice as usize] = [0u8; LAMBDA_C_BYTES];
    }

    let sender_ot_seed = SenderOTSeed {
        one_time_pad_enc_keys,
    };

    let receiver_ot_seed = ReceiverOTSeed {
        random_choices,
        one_time_pad_dec_keys,
    };

    (sender_ot_seed, receiver_ot_seed)
}

#[cfg(test)]
mod tests {
    use crate::soft_spoken::{
        generate_all_but_one_seed_ot, SoftSpokenOTReceiver,
        SoftSpokenOTSender, L, L_BYTES, OT_WIDTH,
    };
    use rand::RngCore;
    use sl_mpc_mate::SessionId;

    use crate::utils::ExtractBit;

    #[test]
    fn test_soft_spoken() {
        let mut rng = rand::thread_rng();

        let (sender_ot_results, receiver_ot_results) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id = SessionId::random(&mut rng);
        let mut choices = [0u8; L_BYTES];
        rng.fill_bytes(&mut choices);

        let sender =
            SoftSpokenOTSender::new(&session_id, &receiver_ot_results);
        let receiver =
            SoftSpokenOTReceiver::new(&session_id, &sender_ot_results);

        // let start = std::time::Instant::now();
        let (round1, receiver_extended_output) =
            receiver.process(&choices, &mut rng);
        // println!("Round1: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let sender_extended_output = sender.process(&round1).unwrap();
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
