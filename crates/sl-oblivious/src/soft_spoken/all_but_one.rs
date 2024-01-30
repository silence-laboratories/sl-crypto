use elliptic_curve::subtle::ConstantTimeEq;
use merlin::Transcript;

use crate::{
    constants::*,
    endemic_ot::{ReceiverOutput, SenderOutput},
    params::consts::*,
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    utils::ExtractBit,
};

#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
pub struct PPRF {
    t: [[[u8; LAMBDA_C_BYTES]; 2]; SOFT_SPOKEN_K - 1],
    s_tilda: [u8; LAMBDA_C_BYTES * 2],
    t_tilda: [u8; LAMBDA_C_BYTES * 2],
}

impl Default for PPRF {
    fn default() -> Self {
        Self {
            t: Default::default(),
            s_tilda: [0u8; LAMBDA_C_BYTES * 2],
            t_tilda: [0u8; LAMBDA_C_BYTES * 2],
        }
    }
}

#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct PPRFOutput([PPRF; LAMBDA_C / SOFT_SPOKEN_K]);

impl Default for PPRFOutput {
    fn default() -> Self {
        Self([PPRF::default(); LAMBDA_C / SOFT_SPOKEN_K])
    }
}

/// Implements BuildPPRF and ProvePPRF functionality of
/// Fig.13 and Fig.14 https://eprint.iacr.org/2022/192.pdf
pub fn build_pprf(
    session_id: &[u8],
    sender_ot_seed: &SenderOutput,
    all_but_one_sender_seed: &mut SenderOTSeed,
    PPRFOutput(output): &mut PPRFOutput,
) {
    for (j, (out, s_i)) in output
        .iter_mut()
        .zip(&mut all_but_one_sender_seed.otp_enc_keys)
        .enumerate()
    {
        s_i[0] = sender_ot_seed.otp_enc_keys[j * SOFT_SPOKEN_K].rho_0;
        s_i[1] = sender_ot_seed.otp_enc_keys[j * SOFT_SPOKEN_K].rho_1;

        for i in 1..SOFT_SPOKEN_K {
            let mut s_i_plus_1 = [[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            for y in 0..(1 << i) {
                let mut t = Transcript::new(&ALL_BUT_ONE_LABEL);
                t.append_message(b"session-id", session_id);
                t.append_message(&ALL_BUT_ONE_PPRF_LABEL, &s_i[y]);

                t.challenge_bytes(b"", &mut s_i_plus_1[2 * y]);
                t.challenge_bytes(b"", &mut s_i_plus_1[2 * y + 1]);
            }

            let t_x_i = &mut out.t;

            let big_f_i = &sender_ot_seed.otp_enc_keys[j * SOFT_SPOKEN_K + i];

            t_x_i[i - 1][0] = big_f_i.rho_0;
            t_x_i[i - 1][1] = big_f_i.rho_1;

            for b_i in 0..LAMBDA_C_BYTES {
                for y in 0..(1 << i) {
                    t_x_i[i - 1][0][b_i] ^= s_i_plus_1[2 * y][b_i];
                    t_x_i[i - 1][1][b_i] ^= s_i_plus_1[2 * y + 1][b_i];
                }
            }

            *s_i = s_i_plus_1;
        }

        // Prove
        let mut s_tilda_hash = Transcript::new(&ALL_BUT_ONE_LABEL);
        s_tilda_hash.append_message(b"session-id", session_id);

        for y in s_i.iter() {
            let mut s_tilda_y = [0u8; LAMBDA_C_BYTES * 2];

            let mut t = Transcript::new(&ALL_BUT_ONE_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_message(&ALL_BUT_ONE_PPRF_PROOF_LABEL, y);
            t.challenge_bytes(b"", &mut s_tilda_y);

            out.t_tilda
                .iter_mut()
                .zip(&s_tilda_y)
                .for_each(|(t, s)| *t ^= s);

            s_tilda_hash.append_message(b"", &s_tilda_y);
        }

        s_tilda_hash
            .challenge_bytes(&ALL_BUT_ONE_PPRF_HASH_LABEL, &mut out.s_tilda);
    }
}

pub fn eval_pprf(
    session_id: &[u8],
    receiver_ot_seed: &ReceiverOutput,
    PPRFOutput(output): &PPRFOutput,
    all_but_one_receiver_seed: &mut ReceiverOTSeed,
) -> Result<(), &'static str> {
    for (j, out) in output.iter().enumerate() {
        let x_star_0: u8 =
            receiver_ot_seed.choice_bits.extract_bit(j * SOFT_SPOKEN_K) as u8;

        let mut s_star_i = [[[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; 2];

        s_star_i[0][x_star_0 as usize] =
            receiver_ot_seed.otp_dec_keys[j * SOFT_SPOKEN_K];

        let mut y_star = x_star_0 as usize ^ 1;

        for i in 1..SOFT_SPOKEN_K {
            let mut s_star_i_plus_1 =
                [[[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q]; 2];

            for y in 0..(1 << i) {
                let choice_index = (y == y_star) as usize;

                let mut t = Transcript::new(&ALL_BUT_ONE_LABEL);
                t.append_message(b"session-id", session_id);
                t.append_message(
                    &ALL_BUT_ONE_PPRF_LABEL,
                    &s_star_i[choice_index][y],
                );

                t.challenge_bytes(
                    b"",
                    &mut s_star_i_plus_1[choice_index][2 * y],
                );
                t.challenge_bytes(
                    b"",
                    &mut s_star_i_plus_1[choice_index][2 * y + 1],
                );
            }

            let x_star_i: u8 = 1 ^ receiver_ot_seed
                .choice_bits
                .extract_bit(j * SOFT_SPOKEN_K + i)
                as u8;

            let big_f_i_star =
                &receiver_ot_seed.otp_dec_keys[j * SOFT_SPOKEN_K + i];

            let ct_x = x_star_i as usize ^ 1;

            // TODO: fix clippy
            #[allow(clippy::needless_range_loop)]
            for b_i in 0..LAMBDA_C_BYTES {
                s_star_i_plus_1[0][2 * y_star + ct_x][b_i] =
                    out.t[i - 1][ct_x][b_i] ^ big_f_i_star[b_i];

                for y in 0..2usize.pow(i as u32) {
                    // assume conversion of bool to usize is constant time
                    let choice = (y == y_star) as usize;

                    s_star_i_plus_1[choice][2 * (y_star) + ct_x][b_i] ^=
                        s_star_i_plus_1[choice][2 * y + ct_x][b_i];
                }
            }

            s_star_i = s_star_i_plus_1;

            y_star = y_star * 2 + x_star_i as usize;
        }

        // Verify
        let mut s_tilda_star =
            [[[0u8; LAMBDA_C_BYTES * 2]; SOFT_SPOKEN_Q]; 2];
        let s_tilda_expected = &out.s_tilda;

        let mut s_tilda_hash = Transcript::new(&ALL_BUT_ONE_LABEL);
        s_tilda_hash.append_message(b"session-id", session_id);

        let mut s_tilda_star_y_star =
            [out.t_tilda, [0u8; LAMBDA_C_BYTES * 2]];

        for y in 0..SOFT_SPOKEN_Q {
            let choice_index = (y == y_star) as usize;

            let mut tt = Transcript::new(&ALL_BUT_ONE_LABEL);
            tt.append_message(b"session-id", session_id);
            tt.append_message(
                &ALL_BUT_ONE_PPRF_PROOF_LABEL,
                &s_star_i[choice_index][y],
            );

            tt.challenge_bytes(b"", &mut s_tilda_star[choice_index][y]);

            (0..LAMBDA_C_BYTES * 2).for_each(|b_i| {
                s_tilda_star_y_star[choice_index][b_i] ^=
                    s_tilda_star[choice_index][y][b_i];
            })
        }

        s_tilda_star[0][y_star] = s_tilda_star_y_star[0];

        (0..SOFT_SPOKEN_Q).for_each(|y| {
            s_tilda_hash.append_message(b"", &s_tilda_star[0][y]);
        });

        let mut s_tilda_digest = [0u8; LAMBDA_C_BYTES * 2];
        s_tilda_hash.challenge_bytes(
            &ALL_BUT_ONE_PPRF_HASH_LABEL,
            &mut s_tilda_digest,
        );

        if s_tilda_digest.ct_ne(s_tilda_expected).into() {
            return Err("Invalid proof");
        }

        all_but_one_receiver_seed.random_choices[j] = y_star as u8;
        all_but_one_receiver_seed.otp_dec_keys[j] = s_star_i[0];
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{thread_rng, Rng};

    use crate::endemic_ot::{OneTimePadEncryptionKeys, LAMBDA_C_BYTES};

    fn generate_seed_ot_for_test() -> (SenderOutput, ReceiverOutput) {
        let mut rng = thread_rng();

        let sender_ot_seed = SenderOutput {
            otp_enc_keys: std::array::from_fn(|_| {
                let rho_0 = rng.gen();
                let rho_1 = rng.gen();

                OneTimePadEncryptionKeys { rho_0, rho_1 }
            }),
        };

        let random_choices: [u8; LAMBDA_C_BYTES] = rng.gen();

        let one_time_pad_enc_keys = std::array::from_fn(|i| {
            let choice = random_choices.extract_bit(i);

            if !choice {
                sender_ot_seed.otp_enc_keys[i].rho_0
            } else {
                sender_ot_seed.otp_enc_keys[i].rho_1
            }
        });

        let receiver_ot_seed =
            ReceiverOutput::new(random_choices, one_time_pad_enc_keys);

        (sender_ot_seed, receiver_ot_seed)
    }

    #[test]
    fn pprf() {
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) = generate_seed_ot_for_test();

        let session_id: [u8; 32] = rng.gen();

        let mut _all_but_one_sender_seed2 = SenderOTSeed::default();
        let mut output_2 = PPRFOutput::default();
        build_pprf(
            &session_id,
            &sender_ot_seed,
            &mut _all_but_one_sender_seed2,
            &mut output_2,
        );

        let mut _all_but_one_receiver_seed2 = ReceiverOTSeed::default();

        eval_pprf(
            &session_id,
            &receiver_ot_seed,
            &output_2,
            &mut _all_but_one_receiver_seed2,
        )
        .unwrap();
    }
}
