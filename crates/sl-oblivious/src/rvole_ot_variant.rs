// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Implementation of the protocol 5.2 OT-Based Random Vector OLE
//! https://eprint.iacr.org/2023/765.pdf
//! with OT variant modification
//!
//! xi = kappa + 2 * lambda_s
//! kappa = |q| = 256
//! lambda_s = 128
//! lambda_c = 256
//! l = 2, rho = 1, OT_WIDTH = l + rho = 3

use std::array;

use merlin::Transcript;

use k256::{
    elliptic_curve::{
        bigint::Encoding,
        ops::Reduce,
        rand_core::CryptoRngCore,
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    },
    Scalar, U256,
};

use crate::endemic_ot::{
    EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender,
};
use crate::{
    constants::{
        RANDOM_VOLE_GADGET_VECTOR_LABEL, RANDOM_VOLE_MU_LABEL,
        RANDOM_VOLE_THETA_LABEL,
    },
    params::consts::*,
    utils::ExtractBit,
};

const XI: usize = L; // by definition
const XI_BYTES: usize = XI >> 3;

use crate::constants::{
    RANDOM_VOLE_BASE_OT, SOFT_SPOKEN_LABEL, SOFT_SPOKEN_RANDOMIZE_LABEL,
};
use crate::soft_spoken::SenderExtendedOutput;

fn generate_gadget_vec(session_id: &[u8]) -> impl Iterator<Item = Scalar> {
    let mut t = Transcript::new(&RANDOM_VOLE_GADGET_VECTOR_LABEL);
    t.append_message(b"session-id", session_id);

    (0..XI).map(move |i| {
        t.append_u64(b"index", i as u64);

        let mut repr = [0u8; KAPPA_BYTES];
        t.challenge_bytes(b"next value", &mut repr);

        Scalar::reduce(U256::from_be_bytes(repr))
    })
}

/// Message 1 output in RVOLE protocol
#[derive(
    Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit, Default,
)]
#[repr(C)]
pub struct RVOLEMsg1 {
    ot_msg1_a: EndemicOTMsg1,
    ot_msg1_b: EndemicOTMsg1,
}

/// Message 2 output in RVOLE protocol
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct RVOLEMsg2 {
    ot_msg2_a: EndemicOTMsg2,
    ot_msg2_b: EndemicOTMsg2,
    a_tilde: [[[u8; KAPPA_BYTES]; L_BATCH_PLUS_RHO]; XI],
    eta: [[u8; KAPPA_BYTES]; RHO],
    mu_hash: [u8; 64],
}

impl RVOLEMsg2 {
    fn get_a_tilde(&self, j: usize, i: usize) -> Scalar {
        Scalar::reduce(U256::from_be_bytes(self.a_tilde[j][i]))
    }
}

impl Default for RVOLEMsg2 {
    fn default() -> Self {
        RVOLEMsg2 {
            ot_msg2_a: EndemicOTMsg2::default(),
            ot_msg2_b: EndemicOTMsg2::default(),
            a_tilde: [[[0u8; KAPPA_BYTES]; L_BATCH_PLUS_RHO]; XI],
            eta: [[0u8; KAPPA_BYTES]; RHO],
            mu_hash: [0u8; 64],
        }
    }
}

///
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct RVOLEReceiver {
    session_id: [u8; 32],
    beta: [u8; XI_BYTES],
}

///
impl RVOLEReceiver {
    /// Create a new RVOLE receiver
    pub fn new<R: CryptoRngCore>(
        session_id: [u8; 32],
        rvole_output_1: &mut RVOLEMsg1,
        rng: &mut R,
    ) -> (
        Box<RVOLEReceiver>,
        Box<EndemicOTReceiver>,
        Box<EndemicOTReceiver>,
        Scalar,
    ) {
        let mut t = Transcript::new(&RANDOM_VOLE_BASE_OT);
        t.append_message(b"session-id", &session_id);
        let mut session_id_a = [0u8; 32];
        let mut session_id_b = [0u8; 32];
        t.challenge_bytes(b"session-id-a", &mut session_id_a);
        t.challenge_bytes(b"session-id-b", &mut session_id_b);

        let receiver_a = EndemicOTReceiver::new(
            &session_id_a,
            &mut rvole_output_1.ot_msg1_a,
            rng,
        );

        let receiver_b = EndemicOTReceiver::new(
            &session_id_b,
            &mut rvole_output_1.ot_msg1_b,
            rng,
        );

        let beta_a = receiver_a.packed_choice_bits;
        let beta_b = receiver_b.packed_choice_bits;

        assert_eq!(beta_a.len() + beta_b.len(), XI_BYTES);

        let mut beta: [u8; XI_BYTES] = [0u8; XI_BYTES];
        beta[0..XI_BYTES / 2].copy_from_slice(&beta_a);
        beta[XI_BYTES / 2..XI_BYTES].copy_from_slice(&beta_b);

        // b = <g, /beta>
        let b = generate_gadget_vec(&session_id).enumerate().fold(
            Scalar::ZERO,
            |option_0, (i, gv)| {
                let i_bit = beta.extract_bit(i);
                let option_1 = option_0 + gv;

                Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(i_bit as u8),
                )
            },
        );

        let mut next = bytemuck::allocation::zeroed_box::<RVOLEReceiver>();

        next.session_id = session_id;
        next.beta = beta;

        (next, Box::new(receiver_a), Box::new(receiver_b), b)
    }
}

impl RVOLEReceiver {
    ///
    pub fn process(
        &self,
        rvole_output_2: &RVOLEMsg2,
        receiver_a: Box<EndemicOTReceiver>,
        receiver_b: Box<EndemicOTReceiver>,
    ) -> Result<[Scalar; L_BATCH], &'static str> {
        let receiver_output_a =
            receiver_a.process(&rvole_output_2.ot_msg2_a)?;
        let receiver_output_b =
            receiver_b.process(&rvole_output_2.ot_msg2_b)?;

        assert_eq!(
            receiver_output_a.otp_dec_keys.len()
                + receiver_output_b.otp_dec_keys.len(),
            XI
        );

        let mut v_x = bytemuck::allocation::zeroed_box::<
            [[[u8; KAPPA_BYTES]; OT_WIDTH]; XI],
        >();

        for j in 0..XI / 2 {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", &self.session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &receiver_output_a.otp_dec_keys[j],
            );
            for k in &mut v_x[j] {
                t.challenge_bytes(b"", k);
            }
        }
        for j in XI / 2..XI {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", &self.session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &receiver_output_b.otp_dec_keys[j - XI / 2],
            );
            for k in &mut v_x[j] {
                t.challenge_bytes(b"", k);
            }
        }

        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", &self.session_id);

        for j in 0..XI {
            t.append_u64(b"row of a tilde", j as u64);
            for i in 0..L_BATCH_PLUS_RHO {
                t.append_message(b"", &rvole_output_2.a_tilde[j][i]);
            }
        }

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; KAPPA_BYTES];
                t.challenge_bytes(b"theta", digest.as_mut());
                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        let mut d_dot = [[Scalar::ZERO; L_BATCH]; XI];
        let mut d_hat = [[Scalar::ZERO; RHO]; XI];

        for j in 0..XI {
            let j_bit = self.beta.extract_bit(j);
            for i in 0..L_BATCH {
                let option_0 = Scalar::reduce(U256::from_be_bytes(v_x[j][i]));
                let option_1 = option_0 + rvole_output_2.get_a_tilde(j, i);
                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );
                d_dot[j][i] = chosen
            }
            for k in 0..RHO {
                let option_0 =
                    Scalar::reduce(U256::from_be_bytes(v_x[j][L_BATCH + k]));
                let option_1 =
                    option_0 + rvole_output_2.get_a_tilde(j, L_BATCH + k);
                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );
                d_hat[j][k] = chosen
            }
        }

        // mu_prime hash
        let mut t = Transcript::new(&RANDOM_VOLE_MU_LABEL);
        t.append_message(b"session-id", &self.session_id);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            let j_bit = self.beta.extract_bit(j);

            for k in 0..RHO {
                let mut v = d_hat[j][k];
                for i in 0..L_BATCH {
                    v += theta[k][i] * d_dot[j][i]
                }

                let option_0 = v;
                let option_1 = option_0
                    - Scalar::reduce(U256::from_be_bytes(
                        rvole_output_2.eta[k],
                    ));
                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );
                t.append_message(b"chosen", &chosen.to_bytes());
            }
        }

        let mut mu_prime_hash = [0u8; 64];
        t.challenge_bytes(b"mu-hash", &mut mu_prime_hash);

        if rvole_output_2.mu_hash.ct_ne(&mu_prime_hash).into() {
            return Err("Consistency check failed");
        }

        let mut d = [Scalar::ZERO; L_BATCH];
        #[allow(clippy::needless_range_loop)]
        for i in 0..L_BATCH {
            for (j, gv) in generate_gadget_vec(&self.session_id).enumerate() {
                d[i] += gv * d_dot[j][i];
            }
        }

        Ok(d)
    }
}

///
pub struct RVOLESender;

impl RVOLESender {
    ///
    pub fn process<R: CryptoRngCore>(
        session_id: &[u8],
        a: &[Scalar; L_BATCH],
        rvole_output_1: &RVOLEMsg1,
        output: &mut RVOLEMsg2,
        rng: &mut R,
    ) -> Result<[Scalar; L_BATCH], &'static str> {
        let mut t = Transcript::new(&RANDOM_VOLE_BASE_OT);
        t.append_message(b"session-id", session_id);
        let mut session_id_a = [0u8; 32];
        let mut session_id_b = [0u8; 32];
        t.challenge_bytes(b"session-id-a", &mut session_id_a);
        t.challenge_bytes(b"session-id-b", &mut session_id_b);

        let Ok(sender_ot_output_a) = EndemicOTSender::process(
            &session_id_a,
            &rvole_output_1.ot_msg1_a,
            &mut output.ot_msg2_a,
            rng,
        ) else {
            return Err("Base OT error");
        };
        let Ok(sender_ot_output_b) = EndemicOTSender::process(
            &session_id_b,
            &rvole_output_1.ot_msg1_b,
            &mut output.ot_msg2_b,
            rng,
        ) else {
            return Err("Base OT error");
        };

        assert_eq!(
            sender_ot_output_a.otp_enc_keys.len()
                + sender_ot_output_b.otp_enc_keys.len(),
            XI
        );

        let mut sender_extended_output = SenderExtendedOutput::new();
        let v_0 = &mut sender_extended_output.v_0;
        let v_1 = &mut sender_extended_output.v_1;
        for j in 0..XI / 2 {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &sender_ot_output_a.otp_enc_keys[j].rho_0,
            );
            for k in &mut v_0[j] {
                t.challenge_bytes(b"", k);
            }

            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &sender_ot_output_a.otp_enc_keys[j].rho_1,
            );
            for k in &mut v_1[j] {
                t.challenge_bytes(b"", k);
            }
        }
        for j in XI / 2..XI {
            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &sender_ot_output_b.otp_enc_keys[j - XI / 2].rho_0,
            );
            for k in &mut v_0[j] {
                t.challenge_bytes(b"", k);
            }

            let mut t = Transcript::new(&SOFT_SPOKEN_LABEL);
            t.append_message(b"session-id", session_id);
            t.append_u64(b"index", j as u64);
            t.append_message(
                &SOFT_SPOKEN_RANDOMIZE_LABEL,
                &sender_ot_output_b.otp_enc_keys[j - XI / 2].rho_1,
            );
            for k in &mut v_1[j] {
                t.challenge_bytes(b"", k);
            }
        }

        let alpha_0 = |j: usize, i: usize| {
            Scalar::reduce(U256::from_be_bytes(
                sender_extended_output.v_0[j][i],
            ))
        };

        let alpha_1 = |j: usize, i: usize| {
            Scalar::reduce(U256::from_be_bytes(
                sender_extended_output.v_1[j][i],
            ))
        };

        let c: [Scalar; L_BATCH] = array::from_fn(|i| {
            generate_gadget_vec(session_id)
                .enumerate()
                .map(|(j, gv)| gv * alpha_0(j, i))
                .sum::<Scalar>()
                .negate()
        });

        output.eta.iter_mut().for_each(|eta| {
            *eta = Scalar::generate_biased(rng).to_bytes().into();
        });

        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", session_id);

        for (j, a_tilde_j_ref) in output.a_tilde.iter_mut().enumerate() {
            t.append_u64(b"row of a tilde", j as u64);
            for i in 0..L_BATCH {
                let v = alpha_0(j, i) - alpha_1(j, i) + a[i];
                a_tilde_j_ref[i] = v.to_bytes().into();

                t.append_message(b"", &a_tilde_j_ref[i]);
            }

            for (k, eta) in output.eta.iter().enumerate() {
                let v = alpha_0(j, L_BATCH + k) - alpha_1(j, L_BATCH + k)
                    + Scalar::reduce(U256::from_be_bytes(*eta));
                a_tilde_j_ref[L_BATCH + k] = v.to_bytes().into();

                t.append_message(b"", &a_tilde_j_ref[L_BATCH + k]);
            }
        }

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; 32];
                t.challenge_bytes(b"theta", &mut digest);

                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        for (k, eta) in output.eta.iter_mut().enumerate() {
            let mut s = Scalar::reduce(U256::from_be_bytes(*eta));
            s += theta[k]
                .iter()
                .zip(a)
                .map(|(t_k_i, a_i)| t_k_i * a_i)
                .sum::<Scalar>();
            *eta = s.to_bytes().into();
        }

        let mut t = Transcript::new(&RANDOM_VOLE_MU_LABEL);
        t.append_message(b"session-id", session_id);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            for k in 0..RHO {
                let mut v = alpha_0(j, L_BATCH + k);
                for i in 0..L_BATCH {
                    v += theta[k][i] * alpha_0(j, i)
                }
                t.append_message(b"chosen", &v.to_bytes());
            }
        }

        t.challenge_bytes(b"mu-hash", &mut output.mu_hash);

        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn pairwise_ot_variant() {
        let mut rng = rand::thread_rng();

        let session_id: [u8; 32] = rng.gen();

        let mut round1_output = RVOLEMsg1::default();
        let (receiver, ot_receiver_a, ot_receiver_b, beta) =
            RVOLEReceiver::new(session_id, &mut round1_output, &mut rng);

        let (alpha1, alpha2) = (
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
        );

        let mut round2_output = RVOLEMsg2::default();
        let sender_shares = RVOLESender::process(
            &session_id,
            &[alpha1, alpha2],
            &round1_output,
            &mut round2_output,
            &mut rng,
        )
        .unwrap();

        let receiver_shares = receiver
            .process(&round2_output, ot_receiver_a, ot_receiver_b)
            .unwrap();

        let sum_0 = receiver_shares[0] + sender_shares[0];
        let sum_1 = receiver_shares[1] + sender_shares[1];

        assert_eq!(sum_0, alpha1 * beta);
        assert_eq!(sum_1, alpha2 * beta);
    }
}
