///
///  SoftSpokenOT protocol https://eprint.iacr.org/2022/192.pdf
///  Instantiation of SoftSpokenOT based on Fig.10 https://eprint.iacr.org/2015/546.pdf
///
use std::array;

use elliptic_curve::{
    ops::Reduce,
    rand_core::CryptoRngCore,
    subtle::{Choice, ConditionallySelectable},
};
use k256::{Scalar, U256};
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::{
    bincode::{
        de::{read::Reader, BorrowDecode, BorrowDecoder, Decoder},
        enc::{write::Writer, Encoder},
        error::{DecodeError, EncodeError},
        Decode, Encode,
    },
    message::*,
    random_bytes, SessionId,
};

use crate::soft_spoken::constants::{
    SOFT_SPOKEN_EXPAND_LABEL, SOFT_SPOKEN_LABEL,
    SOFT_SPOKEN_MATRIX_HASH_LABEL, SOFT_SPOKEN_RANDOMIZE_LABEL,
};
use crate::soft_spoken::types::SoftSpokenOTError;
use crate::{
    soft_spoken::DIGEST_SIZE,
    utils::{bit_to_bit_mask, ExtractBit},
};

use super::mul_poly::binary_field_multiply_gf_2_128;

pub const KAPPA: usize = 256;
pub const KAPPA_BYTES: usize = KAPPA >> 3;
pub const S: usize = 128;
pub const L: usize = KAPPA + 2 * S;
pub const ETA: usize = L; // batch l = 1;
pub const COT_BLOCK_SIZE_BYTES: usize = L >> 3;
pub const COT_BATCH_SIZE_BYTES: usize = ETA >> 3;
pub const OT_WIDTH: usize = 3;
pub const SOFT_SPOKEN_S: usize = 128; // should be: L mod SOFT_SPOKEN_S = 0;
pub const SOFT_SPOKEN_S_BYTES: usize = SOFT_SPOKEN_S >> 3;
pub const L_PRIME: usize = ETA + SOFT_SPOKEN_S;
pub const COT_EXTENDED_BLOCK_SIZE_BYTES: usize = L_PRIME >> 3;
pub const SOFT_SPOKEN_K: usize = 4;
pub const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K; // 2usize.pow(SOFT_SPOKEN_K as u32);
pub const SOFT_SPOKEN_M: usize = ETA / SOFT_SPOKEN_S; // SOFT_SPOKEN_S;
pub const KAPPA_DIV_SOFT_SPOKEN_K: usize = KAPPA / SOFT_SPOKEN_K;
pub const RAND_EXTENSION_SIZE: usize =
    COT_EXTENDED_BLOCK_SIZE_BYTES - COT_BATCH_SIZE_BYTES;

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
    pub one_time_pad_enc_keys: Vec<Vec<[u8; DIGEST_SIZE]>>, // [256 / SOFT_SPOKEN_K][SOFT_SPOKEN_Q][DIGEST]
}

#[derive(
    Debug,
    Default,
    Clone,
    bincode::Encode,
    bincode::Decode,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct ReceiverOTSeed {
    pub random_choices: Vec<u8>, // [256 / SOFT_SPOKEN_K]
    pub one_time_pad_dec_keys: Vec<Vec<[u8; DIGEST_SIZE]>>, // [256 / SOFT_SPOKEN_K][SOFT_SPOKEN_Q][DIGEST]
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Round1Output {
    pub u: [[u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K],
    pub w_prime: [u8; SOFT_SPOKEN_S_BYTES],
    pub v_prime: [[u8; SOFT_SPOKEN_S_BYTES]; KAPPA], // U128
}

//
impl Encode for Round1Output {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        for u in &self.u {
            encoder.writer().write(u)?;
        }

        encoder.writer().write(&self.w_prime)?;

        for v in &self.v_prime {
            encoder.writer().write(v)?;
        }

        Ok(())
    }
}

impl Decode for Round1Output {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut r = Round1Output {
            u: [[0; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K],
            w_prime: [0; SOFT_SPOKEN_S_BYTES],
            v_prime: [[0; SOFT_SPOKEN_S_BYTES]; KAPPA],
        };

        for u in &mut r.u {
            decoder.reader().read(u)?;
        }

        decoder.reader().read(&mut r.w_prime)?;

        for v in &mut r.v_prime {
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

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Round2Output {
    pub tau: [[Scalar; OT_WIDTH]; ETA],
}

impl Encode for Round2Output {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        for t in &self.tau {
            for s in t {
                Opaque::<&Scalar, PFR>::from(s).encode(encoder)?;
            }
        }

        Ok(())
    }
}

impl Decode for Round2Output {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut tau = [[Scalar::ZERO; OT_WIDTH]; ETA];

        for t in &mut tau {
            for s in &mut t[..] {
                *s = *Opaque::<Scalar, PF>::decode(decoder)?;
            }
        }

        Ok(Round2Output { tau })
    }
}

impl<'de> BorrowDecode<'de> for Round2Output {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

// TODO: Expose SOFT_SPOKEN_K const as two options (2 and 4) for the user.
pub struct SoftSpokenOTRec<T> {
    session_id: SessionId,
    seed_ot_results: SenderOTSeed,
    state: T,
}

pub struct RecR0 {
    number_random_bytes: [u8; RAND_EXTENSION_SIZE],
}

pub struct RecR1 {
    psi: [[u8; KAPPA_BYTES]; L_PRIME],
    extended_packed_choices: [u8; COT_EXTENDED_BLOCK_SIZE_BYTES],
}

impl SoftSpokenOTRec<RecR0> {
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &SenderOTSeed,
        rng: &mut R,
    ) -> Self {
        let number_random_bytes: [u8; RAND_EXTENSION_SIZE] =
            random_bytes(rng);

        Self {
            session_id,
            seed_ot_results: seed_ot_results.clone(),
            state: RecR0 {
                number_random_bytes,
            },
        }
    }
}

impl SoftSpokenOTRec<RecR0> {
    pub fn process(
        self,
        choices: &[u8; COT_BATCH_SIZE_BYTES],
    ) -> (SoftSpokenOTRec<RecR1>, Round1Output) {
        let extended_packed_choices: [u8; COT_EXTENDED_BLOCK_SIZE_BYTES] =
            [choices, self.state.number_random_bytes.as_slice()]
                .concat()
                .try_into()
                .expect("Invalid length of extended_packed_choices");

        let mut r_x = [[[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
            KAPPA_DIV_SOFT_SPOKEN_K]; SOFT_SPOKEN_Q];

        // let w_prime = [0u8; SOFT_SPOKEN_S_BYTES];
        // let v_prime = [[0u8; SOFT_SPOKEN_S_BYTES]; KAPPA];
        // let u = [[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K];

        let mut output = Round1Output {
            w_prime: [0u8; SOFT_SPOKEN_S_BYTES],
            v_prime: [[0u8; SOFT_SPOKEN_S_BYTES]; KAPPA],
            u: [[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
                KAPPA_DIV_SOFT_SPOKEN_K],
        };

        let w_prime = &mut output.w_prime;
        let v_prime = &mut output.v_prime;
        let u = &mut output.u;

        let mut matrix_hasher = blake3::Hasher::new();
        matrix_hasher.update(SOFT_SPOKEN_LABEL);
        matrix_hasher.update(&self.session_id);

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            for (j, r_x_j) in r_x.iter_mut().enumerate() {
                let mut shake = Shake256::default();
                shake.update(SOFT_SPOKEN_LABEL);
                shake.update(&self.session_id);
                shake.update(
                    &self.seed_ot_results.one_time_pad_enc_keys[i][j],
                );
                shake.update(SOFT_SPOKEN_EXPAND_LABEL);
                shake.finalize_xof().read(&mut r_x_j[i]);
            }

            for (j, choice) in extended_packed_choices.iter().enumerate() {
                for r_x_k in &r_x {
                    u[i][j] ^= r_x_k[i][j];
                }
                u[i][j] ^= choice;
            }

            matrix_hasher.update(u[i].as_ref());
        }

        // matrix V [KAPPA][COT_EXTENDED_BLOCK_SIZE_BYTES] byte
        // set of vectors v, where each v = v_0 + 2*v_1 + .. + 2^{k-1}*v_{k-1}
        // v_i = sum_x x_i*r_x
        let mut v = [[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA];

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            for bit_index in 0..SOFT_SPOKEN_K {
                // This seems more readable in this situation
                #[allow(clippy::needless_range_loop)]
                for j in 0..SOFT_SPOKEN_Q {
                    let bit = ((j >> bit_index) & 0x01) as u8;
                    let x_i_mask = bit_to_bit_mask(bit);
                    for k in 0..COT_EXTENDED_BLOCK_SIZE_BYTES {
                        v[i * SOFT_SPOKEN_K + bit_index][k] ^=
                            x_i_mask & r_x[j][i][k];
                    }
                }
            }
        }

        matrix_hasher.update(SOFT_SPOKEN_MATRIX_HASH_LABEL);
        let digest_matrix_u = matrix_hasher.finalize().as_bytes().to_owned();

        for j in 0..SOFT_SPOKEN_M {
            let mut shake = Shake256::default();

            shake.update(&(j as u16).to_be_bytes());
            shake.update(digest_matrix_u.as_ref());

            let mut chi_j = [0u8; SOFT_SPOKEN_S_BYTES];

            shake.finalize_xof().read(&mut chi_j);

            let x_hat_j = &extended_packed_choices
                [j * SOFT_SPOKEN_S_BYTES..(j + 1) * SOFT_SPOKEN_S_BYTES]
                .try_into()
                .expect("x_hat_j invalid length, must be 16 bytes");

            let x_hat_j_times_chi_j =
                binary_field_multiply_gf_2_128(x_hat_j, &chi_j);

            for k in 0..SOFT_SPOKEN_S_BYTES {
                w_prime[k] ^= x_hat_j_times_chi_j[k];
            }

            for i in 0..KAPPA {
                let t_hat_j = &v[i]
                    [j * SOFT_SPOKEN_S_BYTES..(j + 1) * SOFT_SPOKEN_S_BYTES]
                    .try_into()
                    .expect("t_hat_j invalid length, must be 16 bytes");
                let t_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(t_hat_j, &chi_j);

                (0..SOFT_SPOKEN_S_BYTES).for_each(|k| {
                    v_prime[i][k] ^= t_hat_j_times_chi_j[k];
                })
            }
        }

        let from_index = SOFT_SPOKEN_M * SOFT_SPOKEN_S_BYTES;
        let to_index = (SOFT_SPOKEN_M + 1) * SOFT_SPOKEN_S_BYTES;

        let x_hat_m_plus_1 = &extended_packed_choices[from_index..to_index];

        for k in 0..SOFT_SPOKEN_S_BYTES {
            w_prime[k] ^= x_hat_m_plus_1[k];
        }

        for i in 0..KAPPA {
            let v_prime_i = &mut v_prime[i];

            let t_hat_m_plus_1 = &v[i][from_index..to_index];
            (0..SOFT_SPOKEN_S_BYTES).for_each(|k| {
                v_prime_i[k] ^= t_hat_m_plus_1[k];
            })
        }

        // let output = Round1Output {
        //     w_prime,
        //     v_prime,
        //     u,
        // };

        let state = SoftSpokenOTRec {
            session_id: self.session_id,
            seed_ot_results: self.seed_ot_results,
            state: RecR1 {
                psi: transpose_bool_matrix(&v),
                extended_packed_choices,
            },
        };

        (state, output)
    }
}

impl SoftSpokenOTRec<RecR1> {
    pub fn process(
        self,
        round2_output: &Round2Output,
    ) -> Box<[[Scalar; OT_WIDTH]; ETA]> {
        let mut output_additive_shares =
            Box::new([[Scalar::ZERO; OT_WIDTH]; ETA]);

        output_additive_shares.iter_mut().enumerate().for_each(
            |(j, additive_shares_j)| {
                let mut shake = Shake256::default();
                shake.update(SOFT_SPOKEN_LABEL);
                shake.update(self.session_id.as_ref());
                shake.update(&(j as u16).to_be_bytes());
                shake.update(self.state.psi[j].as_ref());
                shake.update(SOFT_SPOKEN_RANDOMIZE_LABEL);
                let mut column = [0u8; DIGEST_SIZE * OT_WIDTH];
                shake.finalize_xof().read(&mut column);
                let bit = self.state.extended_packed_choices.extract_bit(j);

                let mut k_additive_shares = [Scalar::default(); OT_WIDTH];

                (0..OT_WIDTH).for_each(|k| {
                    let b = &column[k * DIGEST_SIZE..(k + 1) * DIGEST_SIZE];
                    let value = Scalar::reduce(U256::from_be_slice(b));
                    let option_0 = -value;
                    let option_1 = option_0 + round2_output.tau[j][k];

                    k_additive_shares[k] = Scalar::conditional_select(
                        &option_0,
                        &option_1,
                        Choice::from(bit as u8),
                    );
                });

                *additive_shares_j = k_additive_shares;
            },
        );

        output_additive_shares
    }
}

fn transpose_bool_matrix(
    input: &[[u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA],
) -> [[u8; KAPPA_BYTES]; L_PRIME] {
    let mut output = [[0u8; KAPPA_BYTES]; L_PRIME];
    for row_byte in 0..KAPPA_BYTES {
        for row_bit_byte in 0..8 {
            for column_byte in 0..COT_EXTENDED_BLOCK_SIZE_BYTES {
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

pub struct SoftSpokenOTSender {
    session_id: SessionId,
    seed_ot_results: ReceiverOTSeed,
}

impl SoftSpokenOTSender {
    pub fn new(
        session_id: SessionId,
        seed_ot_results: ReceiverOTSeed,
    ) -> Self {
        Self {
            seed_ot_results,
            session_id,
        }
    }
}

pub type SoftSpokenOTSenderResult = Result<
    (Box<[[Scalar; OT_WIDTH]; ETA]>, Box<Round2Output>),
    SoftSpokenOTError,
>;

impl SoftSpokenOTSender {
    pub fn process(
        self,
        message: (&Round1Output, &[[Scalar; OT_WIDTH]; ETA]),
    ) -> SoftSpokenOTSenderResult {
        let mut r_x = [[[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
            KAPPA_DIV_SOFT_SPOKEN_K]; SOFT_SPOKEN_Q];

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            for (j, rx_j) in r_x.iter_mut().enumerate() {
                if j == self.seed_ot_results.random_choices[i] as usize {
                    rx_j[i].fill(0); // = [0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
                } else {
                    let mut shake = Shake256::default();
                    shake.update(SOFT_SPOKEN_LABEL);
                    shake.update(self.session_id.as_ref());
                    shake.update(
                        self.seed_ot_results.one_time_pad_dec_keys[i][j]
                            .as_ref(),
                    );
                    shake.update(SOFT_SPOKEN_EXPAND_LABEL);
                    //let mut r_x_ij = [0u8; COT_EXTENDED_BLOCK_SIZE_BYTES];
                    shake.finalize_xof().read(&mut rx_j[i]);
                    // rx_j[i] = r_x_ij;
                }
            }
        }

        let mut w_matrix = [[0u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA];

        let mut hash_matrix_u = blake3::Hasher::new();
        hash_matrix_u.update(SOFT_SPOKEN_LABEL);
        hash_matrix_u.update(&self.session_id);

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            let delta = self.seed_ot_results.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                for (j, rx_j) in r_x.iter().enumerate() {
                    let delta_minus_x = delta ^ (j as u8);
                    let bit = (delta_minus_x >> bit_index) & 0x01;
                    let x_i = bit_to_bit_mask(bit);
                    for k in 0..COT_EXTENDED_BLOCK_SIZE_BYTES {
                        w_matrix[i * SOFT_SPOKEN_K + bit_index][k] ^=
                            x_i & rx_j[i][k];
                    }
                }

                let delta_i = (delta >> bit_index) & 0x01;
                let delta_i_mask = bit_to_bit_mask(delta_i);
                for k in 0..COT_EXTENDED_BLOCK_SIZE_BYTES {
                    w_matrix[i * SOFT_SPOKEN_K + bit_index][k] ^=
                        delta_i_mask & message.0.u[i][k];
                }
            }

            hash_matrix_u.update(&message.0.u[i]);
        }

        let mut packed_nabla = [0u8; KAPPA_BYTES];

        for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
            let delta = self.seed_ot_results.random_choices[i];
            for bit_index in 0..SOFT_SPOKEN_K {
                let delta_i = (delta >> bit_index) & 0x01;
                let byte_index = (i * SOFT_SPOKEN_K + bit_index) / 8;
                let bit_index2 = (i * SOFT_SPOKEN_K + bit_index) % 8;
                packed_nabla[byte_index] ^= delta_i << bit_index2;
            }
        }

        hash_matrix_u.update(SOFT_SPOKEN_MATRIX_HASH_LABEL);
        let digest_matrix_u = hash_matrix_u.finalize();

        let mut chi_matrix = [[0u8; SOFT_SPOKEN_S_BYTES]; SOFT_SPOKEN_M];

        chi_matrix.iter_mut().enumerate().for_each(|(j, chi_j)| {
            let mut shake = Shake256::default();
            shake.update((j as u16).to_be_bytes().as_ref());
            shake.update(digest_matrix_u.as_bytes());
            shake.finalize_xof().read(chi_j);
        });

        let from_index = SOFT_SPOKEN_M * SOFT_SPOKEN_S_BYTES;
        let to_index = (SOFT_SPOKEN_M + 1) * SOFT_SPOKEN_S_BYTES;

        for (i, w_matrix_i) in w_matrix.iter().enumerate() {
            let mut q_row = [0u8; SOFT_SPOKEN_S_BYTES];
            for (j, chi_j) in chi_matrix.iter().enumerate() {
                let q_hat_j = w_matrix_i
                    [j * SOFT_SPOKEN_S_BYTES..(j + 1) * SOFT_SPOKEN_S_BYTES]
                    .try_into()
                    .expect("q_hat_j is not the right length");
                let q_hat_j_times_chi_j =
                    binary_field_multiply_gf_2_128(&q_hat_j, chi_j);
                for k in 0..SOFT_SPOKEN_S_BYTES {
                    q_row[k] ^= q_hat_j_times_chi_j[k];
                }
            }
            let q_hat_m_plus_1 = &w_matrix[i][from_index..to_index];
            for k in 0..SOFT_SPOKEN_S_BYTES {
                q_row[k] ^= q_hat_m_plus_1[k];
            }

            // check

            let bit = packed_nabla.extract_bit(i);

            let bit_mask = bit_to_bit_mask(bit as u8);

            let t_i_plus_delta_i_times_x: [u8; SOFT_SPOKEN_S_BYTES] =
                array::from_fn(|k| {
                    message.0.v_prime[i][k]
                        ^ (bit_mask & message.0.w_prime[k])
                });

            if q_row != t_i_plus_delta_i_times_x {
                return Err(SoftSpokenOTError::AbortProtocolAndBanReceiver);
            }
        }

        let mut zeta = transpose_bool_matrix(&w_matrix);

        let mut output = Box::new(Round2Output {
            tau: [[Scalar::ZERO; OT_WIDTH]; ETA],
        });

        let tau = &mut output.tau; //[[Scalar::ZERO; OT_WIDTH]; ETA];

        let mut output_additive_shares =
            Box::new([[Scalar::ZERO; OT_WIDTH]; ETA]);

        for j in 0..ETA {
            let mut shake = Shake256::default();
            shake.update(SOFT_SPOKEN_LABEL);
            shake.update(self.session_id.as_ref());
            shake.update(&(j as u16).to_be_bytes());
            shake.update(&zeta[j]);
            shake.update(SOFT_SPOKEN_RANDOMIZE_LABEL);
            let mut column = [0u8; DIGEST_SIZE * OT_WIDTH];
            shake.finalize_xof().read(&mut column);

            let k_additive_shares = &mut output_additive_shares[j]; //[Scalar::ZERO; OT_WIDTH];

            for k in 0..OT_WIDTH {
                let b = &column[k * DIGEST_SIZE..(k + 1) * DIGEST_SIZE];
                let value = Scalar::reduce(U256::from_be_slice(b));
                k_additive_shares[k] = value;
            }

            // output_additive_shares[j] = k_additive_shares;

            packed_nabla
                .iter()
                .enumerate()
                .for_each(|(i, b)| zeta[j][i] ^= b);

            let mut shake = Shake256::default();
            shake.update(SOFT_SPOKEN_LABEL);
            shake.update(&self.session_id);
            shake.update(&(j as u16).to_be_bytes());
            shake.update(&zeta[j]);
            shake.update(SOFT_SPOKEN_RANDOMIZE_LABEL);
            let mut column = [0u8; DIGEST_SIZE * OT_WIDTH];
            shake.finalize_xof().read(&mut column);

            for k in 0..OT_WIDTH {
                let b = &column[k * DIGEST_SIZE..(k + 1) * DIGEST_SIZE];
                let tau_j_k = Scalar::reduce(U256::from_be_slice(b));
                let input = &message.1[j][k];

                tau[j][k] = tau_j_k - k_additive_shares[k] + input;
            }
        }

        Ok((output_additive_shares, output))
    }
}

pub fn generate_all_but_one_seed_ot<R: CryptoRngCore>(
    rng: &mut R,
) -> (SenderOTSeed, ReceiverOTSeed) {
    let mut one_time_pad_enc_keys = Vec::new();
    let mut one_time_pad_dec_keys = Vec::new();

    for _ in 0..(KAPPA_DIV_SOFT_SPOKEN_K) {
        let ot_sender_messages = (0..SOFT_SPOKEN_Q)
            .map(|_| random_bytes(rng))
            .collect::<Vec<_>>();
        one_time_pad_enc_keys.push(ot_sender_messages.clone());
        one_time_pad_dec_keys.push(ot_sender_messages);
    }

    let random_choices = (0..KAPPA_DIV_SOFT_SPOKEN_K)
        .map(|_| rng.gen_range(0..=SOFT_SPOKEN_Q - 1) as u8)
        .collect::<Vec<_>>();

    for i in 0..(KAPPA_DIV_SOFT_SPOKEN_K) {
        let choice = random_choices[i];
        one_time_pad_dec_keys[i][choice as usize] = [0u8; DIGEST_SIZE];
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

    use k256::Scalar;
    use rand::RngCore;
    use sl_mpc_mate::SessionId;

    use crate::utils::ExtractBit;

    use super::{
        generate_all_but_one_seed_ot, SoftSpokenOTRec, SoftSpokenOTSender,
        COT_BATCH_SIZE_BYTES, ETA, OT_WIDTH,
    };

    // #[derive(Debug, Clone, Serialize, Deserialize)]
    // pub struct RandomValues {
    //     ot_sender_msgs: Vec<Vec<[u8; 32]>>,
    //     random_choices: Vec<u8>,
    //     session_id: SessionId,
    //     #[serde(with = "serde_arrays")]
    //     choices: [u8; 64],
    //     input_data: Vec<[Scalar; 3]>,
    //     number_random_bytes: [u8; RAND_EXTENSION_SIZE],
    // }

    #[test]
    fn test_soft_spoken() {
        let mut rng = rand::thread_rng();

        let (sender_ot_results, receiver_ot_results) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id = SessionId::random(&mut rng);
        let mut choices = [0u8; COT_BATCH_SIZE_BYTES];
        rng.fill_bytes(&mut choices);

        let input_data: [[Scalar; OT_WIDTH]; ETA] =
            std::array::from_fn(|_| {
                let scalars = (0..OT_WIDTH)
                    .map(|_| Scalar::generate_biased(&mut rng))
                    .collect::<Vec<_>>();
                scalars.try_into().unwrap()
            });

        let sender = SoftSpokenOTSender::new(session_id, receiver_ot_results);
        let receiver =
            SoftSpokenOTRec::new(session_id, &sender_ot_results, &mut rng);

        // let start = std::time::Instant::now();
        let (receiver, round1) = receiver.process(&choices);
        // println!("Round1: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let (t_a, round2) = sender.process((&round1, &input_data)).unwrap();
        // println!("Round2: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let t_b = receiver.process(&round2);
        // println!("Round3: {:?}", start.elapsed());

        for i in 0..ETA {
            let bit = choices.extract_bit(i);

            for k in 0..OT_WIDTH {
                let a = t_a[i][k];
                let b = t_b[i][k];
                let temp = a + b;
                if bit {
                    assert_eq!(&temp, &input_data[i][k]);
                } else {
                    assert_eq!(temp, Scalar::ZERO);
                }
            }
        }
    }
}
