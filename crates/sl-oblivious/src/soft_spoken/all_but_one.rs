use elliptic_curve::subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::SessionId;

pub const DIGEST_SIZE: usize = 32;

use crate::soft_spoken::constants::{
    ALL_BUT_ONE_LABEL, ALL_BUT_ONE_PPRF_HASH_LABEL, ALL_BUT_ONE_PPRF_LABEL,
    ALL_BUT_ONE_PPRF_PROOF_LABEL,
};
use crate::{
    endemic_ot::{ReceiverOutput, SenderOutput},
    soft_spoken::SenderOTSeed,
    utils::ExtractBit,
};

use super::ReceiverOTSeed;

#[derive(
    Clone, Debug, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct PPRFOutput {
    pub t: Vec<[[u8; DIGEST_SIZE]; 2]>,

    pub s_tilda: [u8; DIGEST_SIZE * 2],

    pub t_tilda: [u8; DIGEST_SIZE * 2],
}

/// Implements BuildPPRF and ProvePPRF functionality of
/// Fig.13 and Fig.14 https://eprint.iacr.org/2022/192.pdf
pub fn build_pprf(
    session_id: &SessionId,
    sender_ot_seed: &SenderOutput,
    batch: usize, // BATCH_SIZE
    k: usize,
) -> (SenderOTSeed, Vec<PPRFOutput>) {
    let mut all_but_one_sender_seed = SenderOTSeed::default();
    let two_power_k = 1_usize << k;
    let mut output = Vec::with_capacity(batch / k);

    for j in 0..(batch / k) {
        let mut t_x_i = vec![[[0u8; DIGEST_SIZE]; 2]; k - 1];

        let mut s_i = vec![[0u8; DIGEST_SIZE]; two_power_k];

        let mut s_i_plus_1 = vec![[0u8; DIGEST_SIZE]; two_power_k];

        s_i[0] = sender_ot_seed.one_time_pad_enc_keys[j * k].rho_0;
        s_i[1] = sender_ot_seed.one_time_pad_enc_keys[j * k].rho_1;

        // for k=1 case
        s_i_plus_1[0] = s_i[0];
        s_i_plus_1[1] = s_i[1];

        for i in 1..k {
            s_i_plus_1 = vec![[0u8; DIGEST_SIZE]; two_power_k];

            for y in 0..(2usize.pow(i as u32)) {
                let mut shake = Shake256::default();
                shake.update(ALL_BUT_ONE_LABEL);
                shake.update(session_id.as_ref());
                shake.update(&s_i[y]);
                shake.update(ALL_BUT_ONE_PPRF_LABEL);
                let mut reader = shake.finalize_xof();
                let mut hash = [0u8; DIGEST_SIZE * 2];
                reader.read(&mut hash);
                s_i_plus_1[2 * y] = hash[..DIGEST_SIZE].try_into().unwrap();
                s_i_plus_1[2 * y + 1] =
                    hash[DIGEST_SIZE..].try_into().unwrap();
            }

            let big_f_i = &sender_ot_seed.one_time_pad_enc_keys[j * k + i];
            let big_f_i_0 = big_f_i.rho_0;
            let big_f_i_1 = big_f_i.rho_1;
            t_x_i[i - 1][0] = big_f_i_0;
            t_x_i[i - 1][1] = big_f_i_1;
            for b_i in 0..DIGEST_SIZE {
                for y in 0..(2usize.pow(i as u32)) {
                    t_x_i[i - 1][0][b_i] ^= s_i_plus_1[2 * y][b_i];
                    t_x_i[i - 1][1][b_i] ^= s_i_plus_1[2 * y + 1][b_i];
                }
            }

            // TODO: Remove
            s_i = s_i_plus_1.clone();
        }

        // Prove
        let mut t_tilda = [0u8; DIGEST_SIZE * 2];
        let mut s_tilda_hash = Shake256::default();
        s_tilda_hash.update(ALL_BUT_ONE_LABEL);
        s_tilda_hash.update(session_id.as_ref());

        for y in s_i_plus_1.iter().take(two_power_k) {
            let mut shake = Shake256::default();
            shake.update(ALL_BUT_ONE_LABEL);
            shake.update(session_id.as_ref());
            shake.update(y);
            shake.update(ALL_BUT_ONE_PPRF_PROOF_LABEL);
            let mut s_tilda_y = [0u8; DIGEST_SIZE * 2];
            shake.finalize_xof().read(&mut s_tilda_y);

            t_tilda
                .iter_mut()
                .zip(s_tilda_y.iter())
                .for_each(|(t, s)| *t ^= s);

            s_tilda_hash.update(&s_tilda_y);
        }

        all_but_one_sender_seed
            .one_time_pad_enc_keys
            .push(s_i_plus_1);

        let mut s_tilda = [0u8; DIGEST_SIZE * 2];
        s_tilda_hash.update(ALL_BUT_ONE_PPRF_HASH_LABEL);
        s_tilda_hash.finalize_xof().read(&mut s_tilda);

        output.push(PPRFOutput {
            t: t_x_i,
            s_tilda,
            t_tilda,
        });
    }

    (all_but_one_sender_seed, output)
}

pub fn eval_pprf(
    session_id: &SessionId,
    receiver_ot_seed: &ReceiverOutput,
    batch: usize,
    k: usize,
    output: &[PPRFOutput],
) -> Result<ReceiverOTSeed, &'static str> {
    let loop_count = batch / k;
    let mut all_but_one_receiver_seed = ReceiverOTSeed::default();
    let two_power_k = 1 << k;

    for (j, out) in output.iter().enumerate().take(loop_count) {
        let t_x_i = &out.t;
        let mut s_star_i = vec![vec![[0u8; DIGEST_SIZE]; two_power_k]; 2];
        let mut x_star_0: u8 = receiver_ot_seed
            .packed_random_choice_bits
            .extract_bit(j * k)
            .into();
        x_star_0 = (x_star_0 + 1) & 0x01;
        let big_f_i_star =
            receiver_ot_seed.one_time_pad_decryption_keys[j * k];

        let selected = u8::conditional_select(&1, &0, Choice::from(x_star_0));
        s_star_i[0][selected as usize] = big_f_i_star;

        let mut y_star = x_star_0;

        for i in 1..k {
            let mut s_star_i_plus_1 =
                vec![vec![[0u8; DIGEST_SIZE]; two_power_k]; 2];
            for y in 0..2usize.pow(i as u32) {
                let choice_index = u8::conditional_select(
                    &0,
                    &1,
                    Choice::from((y == y_star as usize) as u8),
                ) as usize;

                let mut shake = Shake256::default();
                shake.update(ALL_BUT_ONE_LABEL);
                shake.update(session_id.as_ref());
                shake.update(&s_star_i[choice_index][y]);
                shake.update(ALL_BUT_ONE_PPRF_LABEL);
                let mut res = [0u8; DIGEST_SIZE * 2];
                shake.finalize_xof().read(&mut res);
                s_star_i_plus_1[choice_index][2 * y] =
                    res[0..DIGEST_SIZE].try_into().unwrap();
                s_star_i_plus_1[choice_index][2 * y + 1] =
                    res[DIGEST_SIZE..].try_into().unwrap();
            }

            let x_star_i: u8 = receiver_ot_seed
                .packed_random_choice_bits
                .extract_bit(j * k + i)
                .into();

            let x_star_i = (x_star_i + 1) & 0x01;
            let big_f_i_star =
                receiver_ot_seed.one_time_pad_decryption_keys[j * k + i];

            let ct_x = u8::conditional_select(&1, &0, Choice::from(x_star_i))
                as usize;

            // TODO: fix clippy
            #[allow(clippy::needless_range_loop)]
            for b_i in 0..DIGEST_SIZE {
                s_star_i_plus_1[0][2 * y_star as usize + ct_x][b_i] =
                    t_x_i[i - 1][ct_x][b_i] ^ big_f_i_star[b_i];

                for y in 0..2usize.pow(i as u32) {
                    let choice_index = u8::conditional_select(
                        &0,
                        &1,
                        Choice::from((y == y_star as usize) as u8),
                    ) as usize;

                    s_star_i_plus_1[choice_index]
                        [2 * (y_star as usize) + ct_x][b_i] ^=
                        s_star_i_plus_1[choice_index][2 * y + ct_x][b_i];
                }
            }

            s_star_i = s_star_i_plus_1;
            y_star = y_star * 2 + x_star_i;
        }

        // Verify
        let mut s_tilda_star =
            vec![vec![[0u8; DIGEST_SIZE * 2]; two_power_k]; 2];
        let s_tilda_expected = &out.s_tilda;
        let mut s_tilda_hasher = Shake256::default();
        s_tilda_hasher.update(ALL_BUT_ONE_LABEL);
        s_tilda_hasher.update(session_id.as_ref());
        let mut s_tilda_star_y_star = [out.t_tilda, [0u8; 64]];

        for y in 0..two_power_k {
            let choice_index = u8::conditional_select(
                &0,
                &1,
                Choice::from((y == y_star as usize) as u8),
            ) as usize;

            let mut shake = Shake256::default();
            shake.update(ALL_BUT_ONE_LABEL);
            shake.update(session_id.as_ref());
            shake.update(&s_star_i[choice_index][y]);
            let mut res = [0u8; DIGEST_SIZE * 2];
            shake.update(ALL_BUT_ONE_PPRF_PROOF_LABEL);
            shake.finalize_xof().read(&mut res);
            s_tilda_star[choice_index][y] = res;

            (0..DIGEST_SIZE * 2).for_each(|b_i| {
                s_tilda_star_y_star[choice_index][b_i] ^=
                    s_tilda_star[choice_index][y][b_i];
            })
        }

        s_tilda_star[0][y_star as usize] = s_tilda_star_y_star[0];

        (0..two_power_k).for_each(|y| {
            s_tilda_hasher.update(&s_tilda_star[0][y]);
        });

        let mut s_tilda_digest = [0u8; DIGEST_SIZE * 2];
        s_tilda_hasher.update(ALL_BUT_ONE_PPRF_HASH_LABEL);
        s_tilda_hasher.finalize_xof().read(&mut s_tilda_digest);

        let valid: bool = s_tilda_digest.ct_eq(s_tilda_expected).into();

        if !valid {
            return Err("Invalid proof");
        }

        all_but_one_receiver_seed.random_choices.push(y_star);
        all_but_one_receiver_seed
            .one_time_pad_dec_keys
            .push(s_star_i[0].clone());
    }

    Ok(all_but_one_receiver_seed)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::repeat_with;

    use rand::{thread_rng, Rng};

    use crate::endemic_ot::{
        OneTimePadEncryptionKeys, BATCH_SIZE, BATCH_SIZE_BYTES,
    };
    use sl_mpc_mate::{HashBytes, SessionId};

    fn generate_seed_ot_for_test() -> (SenderOutput, ReceiverOutput) {
        let mut rng = thread_rng();

        let sender_ot_seed = SenderOutput {
            one_time_pad_enc_keys: repeat_with(|| {
                let rho_0 = rng.gen();
                let rho_1 = rng.gen();

                OneTimePadEncryptionKeys { rho_0, rho_1 }
            })
            .take(BATCH_SIZE)
            .collect::<Vec<_>>(),
        };

        let random_choices: [u8; BATCH_SIZE_BYTES] = rng.gen();

        let one_time_pad_enc_keys = (0..BATCH_SIZE)
            .map(|i| {
                let choice = random_choices.extract_bit(i);

                let msg = HashBytes::conditional_select(
                    &HashBytes::new(
                        sender_ot_seed.one_time_pad_enc_keys[i].rho_0,
                    ),
                    &HashBytes::new(
                        sender_ot_seed.one_time_pad_enc_keys[i].rho_1,
                    ),
                    Choice::from(choice as u8),
                );

                msg.0
            })
            .collect::<Vec<_>>();

        let receiver_ot_seed =
            ReceiverOutput::new(random_choices, one_time_pad_enc_keys);

        (sender_ot_seed, receiver_ot_seed)
    }

    use super::{build_pprf, eval_pprf}; //, generate_seed_ot_for_test};

    #[test]
    fn test_pprf() {
        let batch_size = 8;
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) = generate_seed_ot_for_test();

        let session_id = SessionId::random(&mut rng);

        let (_all_but_one_sender_seed2, output_2) =
            build_pprf(&session_id, &sender_ot_seed, batch_size, 2);

        let _all_but_one_receiver_seed2 = eval_pprf(
            &session_id,
            &receiver_ot_seed,
            batch_size,
            2,
            &output_2,
        )
        .unwrap();
    }
}
