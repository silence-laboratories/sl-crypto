// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use bytemuck::{AnyBitPattern, NoUninit, Pod, Zeroable};
use elliptic_curve::subtle::{ConditionallySelectable, ConstantTimeEq};
use merlin::Transcript;

use crate::{
    constants::*,
    endemic_ot::{ReceiverOutput, SenderOutput},
    params::consts::*,
    soft_spoken::{ReceiverOTSeed, SenderOTSeed},
    utils::ExtractBit,
};

#[derive(Clone, Copy, Pod, Zeroable)]
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

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
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
        let x_star_0 =
            receiver_ot_seed.choice_bits.extract_bit(j * SOFT_SPOKEN_K);

        let mut s_star_i = [[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

        s_star_i[x_star_0] = receiver_ot_seed.otp_dec_keys[j * SOFT_SPOKEN_K];

        let mut y_star = x_star_0 ^ 1;

        for i in 1..SOFT_SPOKEN_K {
            let mut s_star_i_plus_1 = [[0u8; LAMBDA_C_BYTES]; SOFT_SPOKEN_Q];

            for y in 0..(1 << i) {
                let choice = y.ct_ne(&y_star);

                let mut temp_0 = [0u8; LAMBDA_C_BYTES];
                let mut temp_1 = [0u8; LAMBDA_C_BYTES];

                let mut t = Transcript::new(&ALL_BUT_ONE_LABEL);
                t.append_message(b"session-id", session_id);
                t.append_message(&ALL_BUT_ONE_PPRF_LABEL, &s_star_i[y]);
                t.challenge_bytes(b"", &mut temp_0);
                t.challenge_bytes(b"", &mut temp_1);

                (0..LAMBDA_C_BYTES).for_each(|b_i| {
                    s_star_i_plus_1[2 * y][b_i]
                        .conditional_assign(&temp_0[b_i], choice);
                    s_star_i_plus_1[2 * y + 1][b_i]
                        .conditional_assign(&temp_1[b_i], choice);
                });
            }

            let x_star_i = 1 ^ receiver_ot_seed
                .choice_bits
                .extract_bit(j * SOFT_SPOKEN_K + i);

            let big_f_i_star =
                &receiver_ot_seed.otp_dec_keys[j * SOFT_SPOKEN_K + i];

            let ct_x = x_star_i ^ 1;

            // TODO: fix clippy
            #[allow(clippy::needless_range_loop)]
            for b_i in 0..LAMBDA_C_BYTES {
                s_star_i_plus_1[2 * y_star + ct_x][b_i] =
                    out.t[i - 1][ct_x][b_i] ^ big_f_i_star[b_i];

                for y in 0..2usize.pow(i as u32) {
                    let choice = y.ct_ne(&y_star);
                    let temp_byte = s_star_i_plus_1[2 * y_star + ct_x][b_i]
                        ^ s_star_i_plus_1[2 * y + ct_x][b_i];
                    s_star_i_plus_1[2 * y_star + ct_x][b_i]
                        .conditional_assign(&temp_byte, choice);
                }
            }

            s_star_i = s_star_i_plus_1;

            y_star = y_star * 2 + x_star_i;
        }

        // Verify
        let mut s_tilda_star = [[0u8; LAMBDA_C_BYTES * 2]; SOFT_SPOKEN_Q];
        let s_tilda_expected = &out.s_tilda;

        let mut s_tilda_hash = Transcript::new(&ALL_BUT_ONE_LABEL);
        s_tilda_hash.append_message(b"session-id", session_id);

        let mut s_tilda_star_y_star = out.t_tilda;

        for y in 0..SOFT_SPOKEN_Q {
            let choice = y.ct_ne(&y_star);
            let mut temp = [0u8; LAMBDA_C_BYTES * 2];

            let mut tt = Transcript::new(&ALL_BUT_ONE_LABEL);
            tt.append_message(b"session-id", session_id);
            tt.append_message(&ALL_BUT_ONE_PPRF_PROOF_LABEL, &s_star_i[y]);
            tt.challenge_bytes(b"", &mut temp);

            (0..LAMBDA_C_BYTES * 2).for_each(|b_i| {
                s_tilda_star[y][b_i].conditional_assign(&temp[b_i], choice);
            });

            (0..LAMBDA_C_BYTES * 2).for_each(|b_i| {
                let temp_byte =
                    s_tilda_star_y_star[b_i] ^ s_tilda_star[y][b_i];
                s_tilda_star_y_star[b_i]
                    .conditional_assign(&temp_byte, choice);
            })
        }

        s_tilda_star[y_star] = s_tilda_star_y_star;

        (0..SOFT_SPOKEN_Q).for_each(|y| {
            s_tilda_hash.append_message(b"", &s_tilda_star[y]);
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
        all_but_one_receiver_seed.otp_dec_keys[j] = s_star_i;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::Rng;

    use crate::endemic_ot::generate_seed_ot_for_test;

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
