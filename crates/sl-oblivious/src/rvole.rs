// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Implementation of the protocol 5.2 OT-Based Random Vector OLE
//! https://eprint.iacr.org/2023/765.pdf
//!
//! xi = kappa + 2 * lambda_s
//! kappa = |q| = 256
//! lambda_s = 128
//! lambda_c = 256
//! l = 2, rho = 1, OT_WIDTH = l + rho = 3

use std::array;

use bytemuck::{allocation::zeroed_box, AnyBitPattern, NoUninit, Zeroable};
use k256::{
    elliptic_curve::{
        bigint::Encoding,
        ops::Reduce,
        rand_core::CryptoRngCore,
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    },
    Scalar, U256,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256 as Shake,
};

use crate::{
    constants::{
        RANDOM_VOLE_GADGET_VECTOR_LABEL, RANDOM_VOLE_MU_LABEL,
        RANDOM_VOLE_THETA_LABEL,
    },
    params::consts::*,
    soft_spoken::{
        ReceiverExtendedOutput, ReceiverOTSeed, Round1Output, SenderOTSeed,
        SoftSpokenOTError, SoftSpokenOTReceiver, SoftSpokenOTSender,
    },
    utils::ExtractBit,
};

const XI: usize = L; // by definition

fn init_shake(input: &[&[u8]]) -> Shake {
    let mut d = Shake::default();
    for i in input {
        d.update(i)
    }
    d
}

fn generate_gadget_vec(session_id: &[u8]) -> impl Iterator<Item = Scalar> {
    let mut bytes = init_shake(&[
        &RANDOM_VOLE_GADGET_VECTOR_LABEL,
        b"session-id",
        session_id,
    ])
    .finalize_xof();

    (0..XI).map(move |_i| {
        let mut repr = [0u8; KAPPA_BYTES];
        bytes.read(&mut repr);

        Scalar::reduce(U256::from_be_bytes(repr))
    })
}

/// Message output in RVOLE protocol
#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct RVOLEOutput {
    a_tilde: [[[u8; KAPPA_BYTES]; L_BATCH_PLUS_RHO]; XI],
    eta: [[u8; KAPPA_BYTES]; RHO],
    mu_hash: [u8; 2 * LAMBDA_C_BYTES],
}

impl RVOLEOutput {
    fn get_a_tilde(&self, j: usize, i: usize) -> Scalar {
        Scalar::reduce(U256::from_be_slice(&self.a_tilde[j][i]))
    }
}

impl Default for RVOLEOutput {
    fn default() -> Self {
        bytemuck::zeroed()
    }
}

#[derive(Zeroable)]
pub struct RVOLEReceiver {
    session_id: [u8; 32],
    extended_output: ReceiverExtendedOutput,
}

impl RVOLEReceiver {
    /// Create a new RVOLE receiver
    pub fn new<R: CryptoRngCore>(
        session_id: [u8; 32],
        seed_ot_results: &SenderOTSeed,
        round1_output: &mut Round1Output,
        rng: &mut R,
    ) -> (Box<RVOLEReceiver>, Scalar) {
        let mut next = zeroed_box::<RVOLEReceiver>();

        next.session_id = session_id;
        rng.fill_bytes(&mut next.extended_output.choices);

        // b = <g, /beta>
        let b = generate_gadget_vec(&session_id).enumerate().fold(
            Scalar::ZERO,
            |option_0, (i, gv)| {
                let i_bit = next.extended_output.choices.extract_bit(i);
                let option_1 = option_0 + gv;

                Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(i_bit as u8),
                )
            },
        );

        SoftSpokenOTReceiver::process(
            &session_id,
            seed_ot_results,
            round1_output,
            &mut next.extended_output,
            rng,
        );

        (next, b)
    }
}

impl RVOLEReceiver {
    pub fn process(
        &self,
        rvole_output: &RVOLEOutput,
    ) -> Result<[Scalar; L_BATCH], &'static str> {
        let mut t = init_shake(&[
            &RANDOM_VOLE_THETA_LABEL,
            b"session-id",
            &self.session_id,
        ]);

        for j in 0..XI {
            t.update(b"row of a tilde");
            t.update(&(j as u64).to_le_bytes());
            for i in 0..L_BATCH_PLUS_RHO {
                t.update(&rvole_output.a_tilde[j][i]);
            }
        }

        let mut t_bytes = t.finalize_xof();

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                let mut h_init = [0u8; 32];
                t_bytes.read(&mut h_init);

                let mut h = init_shake(&[&h_init]);

                h.update(b"teta k");
                h.update(&(k as u64).to_le_bytes());

                h.update(b"teta i");
                h.update(&(i as u64).to_le_bytes());

                let mut digest = [0u8; KAPPA_BYTES];
                h.finalize_xof_into(&mut digest);

                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        let mut d_dot = [[Scalar::ZERO; L_BATCH]; XI];
        let mut d_hat = [[Scalar::ZERO; RHO]; XI];

        for j in 0..XI {
            let j_bit = self.extended_output.choices.extract_bit(j);
            for i in 0..L_BATCH {
                let option_0 = Scalar::reduce(U256::from_be_slice(
                    &self.extended_output.v_x[j][i],
                ));

                let option_1 = option_0 + rvole_output.get_a_tilde(j, i);

                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );

                d_dot[j][i] = chosen
            }

            for k in 0..RHO {
                let option_0 = Scalar::reduce(U256::from_be_slice(
                    &self.extended_output.v_x[j][L_BATCH + k],
                ));

                let option_1 =
                    option_0 + rvole_output.get_a_tilde(j, L_BATCH + k);

                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );

                d_hat[j][k] = chosen
            }
        }

        // mu_prime hash
        let mut t = init_shake(&[
            &RANDOM_VOLE_MU_LABEL,
            b"session-id",
            &self.session_id,
        ]);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            let j_bit = self.extended_output.choices.extract_bit(j);

            for k in 0..RHO {
                let mut v = d_hat[j][k];
                for i in 0..L_BATCH {
                    v += theta[k][i] * d_dot[j][i]
                }

                let option_0 = v;

                let option_1 = option_0
                    - Scalar::reduce(U256::from_be_slice(
                        &rvole_output.eta[k],
                    ));

                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );

                t.update(b"chosen");
                t.update(chosen.to_bytes().as_slice());
            }
        }

        let mut mu_prime_hash = [0u8; 2 * LAMBDA_C_BYTES];
        t.update(b"mu-hash");
        t.finalize_xof_into(&mut mu_prime_hash);

        if rvole_output.mu_hash.ct_ne(&mu_prime_hash).into() {
            return Err("Consistency check failed");
        }

        let mut d = [Scalar::ZERO; L_BATCH];
        generate_gadget_vec(&self.session_id).enumerate().for_each(
            |(j, gv)| {
                for (i, d) in d.iter_mut().enumerate() {
                    *d += gv * d_dot[j][i];
                }
            },
        );

        Ok(d)
    }
}

pub struct RVOLESender;

impl RVOLESender {
    pub fn process<R: CryptoRngCore>(
        session_id: &[u8],
        seed_ot_results: &ReceiverOTSeed,
        a: &[Scalar; L_BATCH],
        round1_output: &Round1Output,
        output: &mut RVOLEOutput,
        rng: &mut R,
    ) -> Result<[Scalar; L_BATCH], SoftSpokenOTError> {
        let sender_extended_output = SoftSpokenOTSender::process(
            session_id,
            seed_ot_results,
            round1_output,
        )?;

        let alpha_0 = |j: usize, i: usize| {
            Scalar::reduce(U256::from_be_slice(
                &sender_extended_output.v_0[j][i],
            ))
        };

        let alpha_1 = |j: usize, i: usize| {
            Scalar::reduce(U256::from_be_slice(
                &sender_extended_output.v_1[j][i],
            ))
        };

        let eta: [Scalar; RHO] =
            array::from_fn(|_| Scalar::generate_biased(rng));

        let mut t = init_shake(&[
            &RANDOM_VOLE_THETA_LABEL,
            b"session-id",
            session_id,
        ]);

        for (j, a_tilde_j) in output.a_tilde.iter_mut().enumerate() {
            t.update(b"row of a tilde");
            t.update(&(j as u64).to_le_bytes());

            for i in 0..L_BATCH {
                let v = alpha_0(j, i) - alpha_1(j, i) + a[i];
                a_tilde_j[i] = v.to_bytes().into();

                t.update(&a_tilde_j[i]);
            }

            for (k, eta) in eta.iter().enumerate() {
                let v =
                    alpha_0(j, L_BATCH + k) - alpha_1(j, L_BATCH + k) + eta;
                a_tilde_j[L_BATCH + k] = v.to_bytes().into();

                t.update(&a_tilde_j[L_BATCH + k]);
            }
        }

        let mut t_bytes = t.finalize_xof();

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                let mut h_init = [0u8; 32];
                t_bytes.read(&mut h_init);

                let mut h = init_shake(&[&h_init]);

                h.update(b"teta k");
                h.update(&(k as u64).to_le_bytes());

                h.update(b"teta i");
                h.update(&(i as u64).to_le_bytes());

                let mut digest = [0u8; 32];
                h.finalize_xof_into(&mut digest);

                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        for (k, eta) in eta.into_iter().enumerate() {
            let s = eta
                + theta[k]
                    .iter()
                    .zip(a)
                    .map(|(t_k_i, a_i)| t_k_i * a_i)
                    .sum::<Scalar>();
            output.eta[k] = s.to_bytes().into();
        }

        let mut t =
            init_shake(&[&RANDOM_VOLE_MU_LABEL, b"session-id", session_id]);

        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            for k in 0..RHO {
                let mut v = alpha_0(j, L_BATCH + k);
                for i in 0..L_BATCH {
                    v += theta[k][i] * alpha_0(j, i)
                }

                t.update(b"chosen");
                t.update(v.to_bytes().as_slice());
            }
        }

        t.update(b"mu-hash");
        t.finalize_xof_into(&mut output.mu_hash);

        let mut c = [Scalar::ZERO; L_BATCH];
        generate_gadget_vec(session_id)
            .enumerate()
            .for_each(|(j, gv)| {
                for (i, c) in c.iter_mut().enumerate() {
                    *c += gv * alpha_0(j, i);
                }
            });

        Ok(c.map(|v| v.negate()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    use crate::soft_spoken::generate_all_but_one_seed_ot;

    #[test]
    fn pairwise() {
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id: [u8; 32] = rng.gen();

        let mut round1_output = Round1Output::default();

        let (receiver, beta) = RVOLEReceiver::new(
            session_id,
            &sender_ot_seed,
            &mut round1_output,
            &mut rng,
        );

        let (alpha1, alpha2) = (
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
        );

        let mut round2_output = Default::default();

        let sender_shares = RVOLESender::process(
            &session_id,
            &receiver_ot_seed,
            &[alpha1, alpha2],
            &round1_output,
            &mut round2_output,
            &mut rng,
        )
        .unwrap();

        let receiver_shares = receiver.process(&round2_output).unwrap();

        let sum_0 = receiver_shares[0] + sender_shares[0];
        let sum_1 = receiver_shares[1] + sender_shares[1];

        assert_eq!(sum_0, alpha1 * beta);
        assert_eq!(sum_1, alpha2 * beta);
    }
}
