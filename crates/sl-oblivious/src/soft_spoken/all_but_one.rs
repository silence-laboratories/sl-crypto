use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sl_mpc_mate::{traits::PersistentObject, SessionId};

pub const DIGEST_SIZE: usize = 32;

use crate::{
    soft_spoken::SenderOTSeed,
    utils::ExtractBit,
    vsot::{ReceiverOutput, SenderOutput},
};

use super::ReceiverOTSeed;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PPRFOutput {
    pub t: Vec<[[u8; DIGEST_SIZE]; 2]>,
    #[serde(with = "serde_arrays")]
    pub s_tilda: [u8; DIGEST_SIZE * 2],
    #[serde(with = "serde_arrays")]
    pub t_tilda: [u8; DIGEST_SIZE * 2],
}
impl PersistentObject for PPRFOutput {}
///Implements BuildPPRF and ProvePPRF functionality of
/// https://eprint.iacr.org/2022/192.pdf p.22, fig. 13
pub fn build_pprf(
    session_id: &SessionId,
    sender_ot_seed: &SenderOutput,
    batch: u32,
    k: u8,
) -> (SenderOTSeed, Vec<PPRFOutput>) {
    let k = k as u32;
    let mut all_but_one_sender_seed = SenderOTSeed::default();
    let two_power_k = 2u32.pow(k);
    let mut output = vec![];

    for j in 0..(batch / k) {
        let mut t_x_i = vec![[[0u8; DIGEST_SIZE]; 2]; (k - 1) as usize];

        let mut s_i = vec![[0u8; DIGEST_SIZE]; two_power_k as usize];

        let mut s_i_plus_1 = vec![[0u8; DIGEST_SIZE]; two_power_k as usize];

        s_i[0] = sender_ot_seed.one_time_pad_enc_keys[(j * k) as usize].rho_0;
        s_i[1] = sender_ot_seed.one_time_pad_enc_keys[(j * k) as usize].rho_1;

        // for k=1 case
        s_i_plus_1[0] = s_i[0];
        s_i_plus_1[1] = s_i[1];

        for i in 1..k as usize {
            s_i_plus_1 = vec![[0u8; DIGEST_SIZE]; two_power_k as usize];

            for y in 0..(2usize.pow(i as u32)) {
                let mut shake = Shake256::default();
                shake.update(session_id.as_ref());
                shake.update(b"SL-SOFT-SPOKEN-PPRF");
                shake.update(&s_i[y]);
                let mut reader = shake.finalize_xof();
                let mut hash = [0u8; DIGEST_SIZE * 2];
                reader.read(&mut hash);
                s_i_plus_1[2 * y] = hash[..DIGEST_SIZE].try_into().unwrap();
                s_i_plus_1[2 * y + 1] = hash[DIGEST_SIZE..].try_into().unwrap();
            }

            let big_f_i = &sender_ot_seed.one_time_pad_enc_keys[(j * k) as usize + i];
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
        s_tilda_hash.update(session_id.as_ref());
        s_tilda_hash.update(b"SL-SOFT-SPOKEN-PPRF-HASH");

        for y in 0..two_power_k {
            let mut shake = Shake256::default();
            shake.update(session_id.as_ref());
            shake.update(b"SL-SOFT-SPOKEN-PPRF-PROOF");
            shake.update(&s_i_plus_1[y as usize]);
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
    batch: u32,
    k: u8,
    output: Vec<PPRFOutput>,
) -> Result<ReceiverOTSeed, String> {
    let k = k as usize;
    let loop_count = (batch / k as u32) as usize;
    let mut all_but_one_receiver_seed = ReceiverOTSeed::default();
    let two_power_k = 2usize.pow(k as u32);

    // TODO: fix clippy
    for j in 0..loop_count {
        let t_x_i = &output[j].t;
        let mut s_star_i = vec![[0u8; DIGEST_SIZE]; two_power_k];
        let mut x_star_0: u8 = receiver_ot_seed
            .packed_random_choice_bits
            .extract_bit(j * k)
            .into();
        x_star_0 = (x_star_0 + 1) & 0x01;
        let big_f_i_star = receiver_ot_seed.one_time_pad_decryption_keys[j * k];

        let selected = u8::conditional_select(&1, &0, Choice::from(x_star_0));
        s_star_i[selected as usize] = big_f_i_star;

        let mut y_star = x_star_0;

        for i in 1..k {
            let mut s_star_i_plus_1 = vec![[0u8; DIGEST_SIZE]; two_power_k];
            for y in 0..2usize.pow(i as u32) {
                // TODO: Constant time?
                if y == (y_star as usize) {
                    continue;
                }

                let mut shake = Shake256::default();
                shake.update(session_id.as_ref());
                shake.update(b"SL-SOFT-SPOKEN-PPRF");
                shake.update(&s_star_i[y]);
                let mut res = [0u8; DIGEST_SIZE * 2];
                shake.finalize_xof().read(&mut res);
                s_star_i_plus_1[2 * y] = res[0..DIGEST_SIZE].try_into().unwrap();
                s_star_i_plus_1[2 * y + 1] = res[DIGEST_SIZE..].try_into().unwrap();
            }

            let x_star_i: u8 = receiver_ot_seed
                .packed_random_choice_bits
                .extract_bit(j * k + i)
                .into();

            let x_star_i = (x_star_i + 1) & 0x01;
            let big_f_i_star = receiver_ot_seed.one_time_pad_decryption_keys[j * k + i];

            let ct_x = u8::conditional_select(&1, &0, Choice::from(x_star_i)) as usize;
            // TODO: fix clippy
            for b_i in 0..DIGEST_SIZE {
                s_star_i_plus_1[2 * y_star as usize + ct_x][b_i] =
                    t_x_i[i - 1][ct_x][b_i] ^ big_f_i_star[b_i];

                for y in 0..2usize.pow(i as u32) {
                    if y == y_star as usize {
                        continue;
                    }

                    s_star_i_plus_1[2 * (y_star as usize) + ct_x][b_i] ^=
                        s_star_i_plus_1[2 * y + ct_x][b_i];
                }
            }

            s_star_i = s_star_i_plus_1;
            y_star = y_star * 2 + x_star_i;
        }

        // Verify
        let mut s_tilda_star = vec![[0u8; DIGEST_SIZE * 2]; two_power_k];
        let s_tilda_expected = output[j].s_tilda;
        let mut s_tilda_hasher = Shake256::default();
        s_tilda_hasher.update(session_id.as_ref());
        s_tilda_hasher.update(b"SL-SOFT-SPOKEN-PPRF-HASH");
        let mut s_tilda_star_y_star = output[j].t_tilda;

        for y in 0..two_power_k {
            if y == (y_star as usize) {
                continue;
            }

            let mut shake = Shake256::default();
            shake.update(session_id.as_ref());
            shake.update(b"SL-SOFT-SPOKEN-PPRF-PROOF");
            shake.update(&s_star_i[y]);
            let mut res = [0u8; DIGEST_SIZE * 2];
            shake.finalize_xof().read(&mut res);
            s_tilda_star[y] = res;

            (0..DIGEST_SIZE * 2).for_each(|b_i| {
                s_tilda_star_y_star[b_i] ^= s_tilda_star[y][b_i];
            })
        }

        s_tilda_star[y_star as usize] = s_tilda_star_y_star;

        (0..two_power_k).for_each(|y| {
            s_tilda_hasher.update(&s_tilda_star[y]);
        });

        let mut s_tilda_digest = [0u8; DIGEST_SIZE * 2];
        s_tilda_hasher.finalize_xof().read(&mut s_tilda_digest);

        let valid: bool = s_tilda_digest.ct_eq(&s_tilda_expected).into();

        if !valid {
            return Err("Invalid proof".into());
        }

        all_but_one_receiver_seed.random_choices.push(y_star);
        all_but_one_receiver_seed
            .one_time_pad_dec_keys
            .push(s_star_i);
    }

    Ok(all_but_one_receiver_seed)
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{thread_rng, Rng};

    use crate::vsot::OneTimePadEncryptionKeys;
    use sl_mpc_mate::{random_bytes, HashBytes, SessionId};

    fn generate_seed_ot_for_test(n: usize) -> (SenderOutput, ReceiverOutput) {
        let mut sender_ot_seed = SenderOutput::default();
        let mut rng = thread_rng();

        for _ in 0..n {
            let rho_0 = random_bytes(&mut rng);
            let rho_1 = random_bytes(&mut rng);
            let ot_sender_messages = OneTimePadEncryptionKeys { rho_0, rho_1 };
            sender_ot_seed
                .one_time_pad_enc_keys
                .push(ot_sender_messages);
        }

        let random_choices = (0..n / 8).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let mut receiver_ot_seed = ReceiverOutput::new(random_choices.clone(), vec![]);

        for i in 0..n {
            let choice = random_choices.extract_bit(i);

            let msg = HashBytes::conditional_select(
                &HashBytes(sender_ot_seed.one_time_pad_enc_keys[i].rho_0),
                &HashBytes(sender_ot_seed.one_time_pad_enc_keys[i].rho_1),
                Choice::from(choice as u8),
            );

            receiver_ot_seed.one_time_pad_decryption_keys.push(msg.0);
        }

        (sender_ot_seed, receiver_ot_seed)
    }

    use super::{build_pprf, eval_pprf}; //, generate_seed_ot_for_test};

    #[test]
    fn test_pprf() {
        let batch_size: u32 = 8;
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) = generate_seed_ot_for_test(batch_size as usize);

        let session_id = SessionId::random(&mut rng);

        let (_all_but_one_sender_seed2, output_2) =
            build_pprf(&session_id, &sender_ot_seed, batch_size, 2);

        let _all_but_one_receiver_seed2 =
            eval_pprf(&session_id, &receiver_ot_seed, batch_size, 2, output_2).unwrap();
    }
}
