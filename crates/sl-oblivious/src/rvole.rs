//! Implementation of the protocol 5.2 OT-Based Random Vector OLE
//! https://eprint.iacr.org/2023/765.pdf
//!
//! xi = kappa + 2 * lambda_s
//! kappa = |q| = 256
//! lambda_s = 128
//! lambda_c = 256
//! l = 2, rho = 1, OT_WIDTH = l + rho = 3

use std::array;

use bincode::de::read::Reader;
use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::write::Writer;
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{BorrowDecode, Decode, Encode};
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

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    RANDOM_VOLE_GADGET_VECTOR_LABEL, RANDOM_VOLE_MU_LABEL,
    RANDOM_VOLE_THETA_LABEL,
};
use sl_mpc_mate::{message::*, SessionId};

use crate::soft_spoken::{
    ReceiverExtendedOutput, ReceiverOTSeed, Round1Output, SenderOTSeed,
    SoftSpokenOTError, SoftSpokenOTReceiver, SoftSpokenOTSender, L, L_BYTES,
};

use crate::utils::ExtractBit;

pub const XI: usize = L; // by definition
pub const L_BATCH: usize = 2;
pub const RHO: usize = 1; // ===
pub const L_BATCH_PLUS_RHO: usize = L_BATCH + RHO; // should be equal to OT_WIDTH

fn generate_gadget_vec(
    session_id: &SessionId,
) -> impl Iterator<Item = Scalar> {
    let mut t = Transcript::new(&RANDOM_VOLE_GADGET_VECTOR_LABEL);
    t.append_message(b"session-id", session_id);

    (0..XI).map(move |i| {
        t.append_u64(b"index", i as u64);

        let mut repr = <Scalar as Reduce<U256>>::Bytes::default();

        t.challenge_bytes(b"next value", &mut repr);

        Reduce::<U256>::reduce_bytes(&repr)
    })
}

/// Message output in RVOLE protocol
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RVOLEOutput {
    a_tilde: [[Scalar; L_BATCH_PLUS_RHO]; XI],
    eta: [Scalar; RHO],
    mu_hash: [u8; 64],
}

impl Encode for RVOLEOutput {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        for row in &self.a_tilde {
            for s in row {
                Opaque::<&Scalar, PFR>::from(s).encode(encoder)?;
            }
        }

        for s in &self.eta {
            Opaque::<&Scalar, PFR>::from(s).encode(encoder)?;
        }

        encoder.writer().write(&self.mu_hash)?;

        Ok(())
    }
}

impl Decode for RVOLEOutput {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut r = RVOLEOutput {
            a_tilde: [[Scalar::ZERO; L_BATCH_PLUS_RHO]; XI],
            eta: [Scalar::ZERO; RHO],
            mu_hash: [0u8; 64],
        };

        for row in &mut r.a_tilde {
            for s in row {
                *s = *Opaque::<Scalar, PF>::decode(decoder)?;
            }
        }

        for s in &mut r.eta {
            *s = *Opaque::<Scalar, PF>::decode(decoder)?;
        }

        decoder.reader().read(&mut r.mu_hash)?;

        Ok(r)
    }
}

impl<'de> BorrowDecode<'de> for RVOLEOutput {
    fn borrow_decode<D: BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

///
pub struct RVOLEReceiver {
    session_id: SessionId,
    beta: [u8; L_BYTES],
    receiver_extended_output: Box<ReceiverExtendedOutput>,
}

///
impl RVOLEReceiver {
    /// Create a new RVOLE receiver
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &SenderOTSeed,
        rng: &mut R,
    ) -> (RVOLEReceiver, Scalar, Round1Output) {
        let mut beta = [0u8; L_BYTES];
        rng.fill_bytes(&mut beta);

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

        let (round1_output, receiver_extended_output) =
            SoftSpokenOTReceiver::new(session_id, seed_ot_results, rng)
                .process(&beta);

        let next = RVOLEReceiver {
            session_id,
            beta,
            receiver_extended_output,
        };

        (next, b, round1_output)
    }
}

impl RVOLEReceiver {
    ///
    pub fn process(
        self,
        rvole_output: &RVOLEOutput,
    ) -> Result<[Scalar; L_BATCH], &'static str> {
        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", &self.session_id);

        for j in 0..XI {
            t.append_u64(b"row of a tilde", j as u64);
            for i in 0..L_BATCH_PLUS_RHO {
                t.append_message(b"", &rvole_output.a_tilde[j][i].to_bytes());
            }
        }

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; 32];
                t.challenge_bytes(b"theta", digest.as_mut());
                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        let mut d_dot = [[Scalar::ZERO; L_BATCH]; XI];
        let mut d_hat = [[Scalar::ZERO; RHO]; XI];

        for j in 0..XI {
            for i in 0..L_BATCH {
                let j_bit = self.beta.extract_bit(j);
                let option_0 = Scalar::reduce(U256::from_be_bytes(
                    self.receiver_extended_output.v_x[j][i],
                ));
                let option_1 = option_0 + rvole_output.a_tilde[j][i];
                let chosen = Scalar::conditional_select(
                    &option_0,
                    &option_1,
                    Choice::from(j_bit as u8),
                );
                d_dot[j][i] = chosen
            }
            for k in 0..RHO {
                let j_bit = self.beta.extract_bit(j);
                let option_0 = Scalar::reduce(U256::from_be_bytes(
                    self.receiver_extended_output.v_x[j][L_BATCH + k],
                ));
                let option_1 =
                    option_0 + rvole_output.a_tilde[j][L_BATCH + k];
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
            for k in 0..RHO {
                let mut v = d_hat[j][k];
                for i in 0..L_BATCH {
                    v += theta[k][i] * d_dot[j][i]
                }
                let j_bit = self.beta.extract_bit(j);
                let option_0 = v;
                let option_1 = option_0 - rvole_output.eta[k];
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

        if rvole_output.mu_hash.ct_ne(&mu_prime_hash).into() {
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
        session_id: SessionId,
        seed_ot_results: &ReceiverOTSeed,
        a: &[Scalar; L_BATCH],
        round1_output: &Round1Output,
        rng: &mut R,
    ) -> Result<([Scalar; L_BATCH], Box<RVOLEOutput>), SoftSpokenOTError>
    {
        let a_hat: [Scalar; RHO] =
            array::from_fn(|_| Scalar::generate_biased(rng));

        let sender_extended_output =
            SoftSpokenOTSender::new(session_id, seed_ot_results)
                .process(round1_output)?;

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
            generate_gadget_vec(&session_id)
                .enumerate()
                .map(|(j, gv)| gv * alpha_0(j, i))
                .sum::<Scalar>()
                .negate()
        });

        let mut output = Box::new(RVOLEOutput {
            a_tilde: [[Scalar::ZERO; L_BATCH_PLUS_RHO]; XI],
            eta: a_hat,
            mu_hash: [0u8; 64],
        });

        let mut t = Transcript::new(&RANDOM_VOLE_THETA_LABEL);
        t.append_message(b"session-id", &session_id);

        let a_tilde = &mut output.a_tilde;
        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            t.append_u64(b"row of a tilde", j as u64);
            for i in 0..L_BATCH {
                let v = alpha_0(j, i) - alpha_1(j, i) + a[i];

                t.append_message(b"", &v.to_bytes());
                a_tilde[j][i] = v;
            }
            for k in 0..RHO {
                let v = alpha_0(j, L_BATCH + k) - alpha_1(j, L_BATCH + k)
                    + a_hat[k];

                t.append_message(b"", &v.to_bytes());
                a_tilde[j][L_BATCH + k] = v;
            }
        }

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                t.append_u64(b"theta k", k as u64);
                t.append_u64(b"theta i", i as u64);

                let mut digest = [0u8; 32];
                t.challenge_bytes(b"theta", digest.as_mut());
                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        let eta = &mut output.eta;
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                eta[k] += theta[k][i] * a[i];
            }
        }

        let mut t = Transcript::new(&RANDOM_VOLE_MU_LABEL);
        t.append_message(b"session-id", &session_id);

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

        Ok((c, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::soft_spoken::generate_all_but_one_seed_ot;
    use sl_mpc_mate::SessionId;

    use super::{RVOLEReceiver, RVOLESender};

    #[test]
    fn test_pairwise() {
        let mut rng = rand::thread_rng();

        let (sender_ot_seed, receiver_ot_seed) =
            generate_all_but_one_seed_ot(&mut rng);

        let session_id = SessionId::random(&mut rng);

        let (receiver, beta, round1_output) =
            RVOLEReceiver::new(session_id, &sender_ot_seed, &mut rng);

        let (alpha1, alpha2) = (
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
        );

        let (sender_shares, round2_output) = RVOLESender::process(
            session_id,
            &receiver_ot_seed,
            &[alpha1, alpha2],
            &round1_output,
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
