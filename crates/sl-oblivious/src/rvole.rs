//! Implementation of the protocol 5.2 OT-Based Random Vector OLE
//! https://eprint.iacr.org/2023/765.pdf
//!
//! xi = kappa + 2 * lambda_s
//! kappa = |q| = 256
//! lambda_s = 128
//! lambda_c = 256
//! l = 2, rho = 1, OT_WIDTH = l + rho = 3

use bincode::de::read::Reader;
use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::write::Writer;
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{BorrowDecode, Decode, Encode};

use k256::{
    elliptic_curve::{
        bigint::Encoding,
        generic_array::GenericArray,
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

use crate::utils::{ExtractBit, Hasher};

pub const XI: usize = L;
pub const L_BATCH: usize = 2;
pub const RHO: usize = 1;
pub const L_BATCH_PLUS_RHO: usize = L_BATCH + RHO; // should be equal to OT_WIDTH

fn generate_gadget_vec(session_id: &SessionId) -> Vec<Scalar> {
    let mut gadget_vec = vec![Scalar::ZERO; XI];
    let mut h = Hasher::new();
    h.update(&RANDOM_VOLE_GADGET_VECTOR_LABEL);
    h.update(session_id);

    gadget_vec
        .iter_mut()
        .enumerate()
        .take(L)
        .for_each(|(i, g)| {
            h.update((i as u16).to_be_bytes().as_ref());
            let digest = h.finalize();
            let digest = GenericArray::from_slice(digest.as_bytes());
            *g = Reduce::<U256>::reduce_bytes(digest);
        });

    gadget_vec
}

/// Message output in RVOLE protocol
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RVOLEOutput {
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    a_tilde: [[Scalar; L_BATCH_PLUS_RHO]; XI],
    eta: [Scalar; RHO],
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RVOLEReceiver<T> {
    session_id: SessionId,
    gadget_vector: Vec<Scalar>,
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    beta: [u8; L_BYTES],
    state: T,
}

/// Initial state of the RVOLEReceiver
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RVOLEReceiverR0 {
    cot_receiver: SoftSpokenOTReceiver,
}

/// State of RVOLEReceiver after processing Round 1 output
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RVOLEReceiverR1 {
    receiver_extended_output: Box<ReceiverExtendedOutput>,
}

///
impl RVOLEReceiver<RVOLEReceiverR0> {
    /// Create a new RVOLE receiver
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &SenderOTSeed,
        rng: &mut R,
    ) -> Self {
        let cot_receiver =
            SoftSpokenOTReceiver::new(session_id, seed_ot_results, rng);
        let gadget_vector = generate_gadget_vec(&session_id);
        let mut beta = [0u8; L_BYTES];
        rng.fill_bytes(&mut beta);

        Self {
            session_id,
            gadget_vector,
            beta,
            state: RVOLEReceiverR0 { cot_receiver },
        }
    }
}

impl RVOLEReceiver<RVOLEReceiverR0> {
    ///
    pub fn process(
        self,
    ) -> (RVOLEReceiver<RVOLEReceiverR1>, Scalar, Round1Output) {
        // b = <g, /beta>
        let mut b = Scalar::ZERO;
        for i in 0..XI {
            let i_bit = self.beta.extract_bit(i);
            let option_0 = &b;
            let option_1 = option_0 + self.gadget_vector[i];
            let chosen = Scalar::conditional_select(
                option_0,
                &option_1,
                Choice::from(i_bit as u8),
            );
            b = chosen;
        }

        let (round1_output, receiver_extended_output) =
            self.state.cot_receiver.process(&self.beta);

        let next = RVOLEReceiver {
            session_id: self.session_id,
            gadget_vector: self.gadget_vector,
            beta: self.beta,
            state: RVOLEReceiverR1 {
                receiver_extended_output,
            },
        };

        (next, b, round1_output)
    }
}

impl RVOLEReceiver<RVOLEReceiverR1> {
    ///
    pub fn process(
        self,
        rvole_output: &RVOLEOutput,
    ) -> Result<[Scalar; L_BATCH], &'static str> {
        let mut hasher = Hasher::new();
        hasher.update(&RANDOM_VOLE_THETA_LABEL);
        hasher.update(self.session_id.as_ref());
        for j in 0..XI {
            hasher.update(format!("row_{}_of_a_tilde", j).as_bytes());
            for i in 0..L_BATCH_PLUS_RHO {
                hasher.update(rvole_output.a_tilde[j][i].to_bytes().as_ref());
            }
        }
        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                hasher.update(format!("theta_{}_{}", k, i).as_bytes());
                let digest: [u8; 32] = hasher.finalize().into();
                theta[k][i] = Scalar::reduce(U256::from_be_bytes(digest));
            }
        }

        let mut d_dot = [[Scalar::ZERO; L_BATCH]; XI];
        let mut d_hat = [[Scalar::ZERO; RHO]; XI];
        for j in 0..XI {
            for i in 0..L_BATCH {
                let j_bit = self.beta.extract_bit(j);
                let option_0 = Scalar::reduce(U256::from_be_bytes(
                    self.state.receiver_extended_output.v_x[j][i],
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
                    self.state.receiver_extended_output.v_x[j][L_BATCH + k],
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
        let d_dot = d_dot;
        let d_hat = d_hat;

        // mu_prime hash
        let mut hasher = Hasher::new();
        hasher.update(&RANDOM_VOLE_MU_LABEL);
        hasher.update(self.session_id.as_ref());
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
                hasher.update(chosen.to_bytes().as_ref());
            }
        }
        hasher.update(b"p1");
        let mu_prime_hash_1: [u8; 32] = hasher.finalize().into();
        hasher.update(b"p2");
        let mu_prime_hash_2: [u8; 32] = hasher.finalize().into();
        let mu_prime_hash: [u8; 64] =
            [mu_prime_hash_1.as_slice(), mu_prime_hash_2.as_slice()]
                .concat()
                .try_into()
                .expect("Invalid length of mu_prime_hash");

        if rvole_output.mu_hash.ct_ne(&mu_prime_hash).into() {
            return Err("Consistency check failed");
        }

        let mut d = [Scalar::ZERO; L_BATCH];
        #[allow(clippy::needless_range_loop)]
        for i in 0..L_BATCH {
            for j in 0..XI {
                d[i] += self.gadget_vector[j] * d_dot[j][i];
            }
        }

        Ok(d)
    }
}

///
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RVOLESender {
    session_id: SessionId,
    gadget_vector: Vec<Scalar>,
    a_hat: [Scalar; RHO],
    cot_sender: SoftSpokenOTSender,
}

///
impl RVOLESender {
    /// Create a new RVOLE sender
    pub fn new<R: CryptoRngCore>(
        session_id: SessionId,
        seed_ot_results: &ReceiverOTSeed,
        rng: &mut R,
    ) -> Self {
        let cot_sender =
            SoftSpokenOTSender::new(session_id, seed_ot_results.clone());
        let gadget_vector = generate_gadget_vec(&session_id);
        let mut a_hat = [Scalar::ZERO; RHO];
        #[allow(clippy::needless_range_loop)]
        for i in 0..RHO {
            a_hat[i] = Scalar::generate_biased(rng);
        }

        Self {
            session_id,
            gadget_vector,
            a_hat,
            cot_sender,
        }
    }
}

impl RVOLESender {
    ///
    pub fn process(
        self,
        a: [Scalar; L_BATCH],
        round1_output: &Round1Output,
    ) -> Result<([Scalar; L_BATCH], Box<RVOLEOutput>), SoftSpokenOTError>
    {
        let sender_extended_output =
            self.cot_sender.process(round1_output)?;

        let mut alpha_0 = [[Scalar::ZERO; L_BATCH_PLUS_RHO]; XI];
        let mut alpha_1 = [[Scalar::ZERO; L_BATCH_PLUS_RHO]; XI];
        for j in 0..XI {
            for i in 0..L_BATCH_PLUS_RHO {
                alpha_0[j][i] = Scalar::reduce(U256::from_be_bytes(
                    sender_extended_output.v_0[j][i],
                ));
                alpha_1[j][i] = Scalar::reduce(U256::from_be_bytes(
                    sender_extended_output.v_1[j][i],
                ));
            }
        }
        let alpha_0 = alpha_0;
        let alpha_1 = alpha_1;

        let mut c = [Scalar::ZERO; L_BATCH];
        #[allow(clippy::needless_range_loop)]
        for i in 0..L_BATCH {
            for j in 0..XI {
                c[i] += self.gadget_vector[j] * alpha_0[j][i];
            }
            c[i] = c[i].negate();
        }

        let mut output = Box::new(RVOLEOutput {
            a_tilde: [[Scalar::ZERO; L_BATCH_PLUS_RHO]; XI],
            eta: self.a_hat,
            mu_hash: [0u8; 64],
        });

        let mut hasher = Hasher::new();
        hasher.update(&RANDOM_VOLE_THETA_LABEL);
        hasher.update(self.session_id.as_ref());

        let a_tilde = &mut output.a_tilde;
        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            hasher.update(format!("row_{}_of_a_tilde", j).as_bytes());
            for i in 0..L_BATCH {
                let v = alpha_0[j][i] - alpha_1[j][i] + a[i];
                hasher.update(v.to_bytes().as_ref());
                a_tilde[j][i] = v;
            }
            for k in 0..RHO {
                let v = alpha_0[j][L_BATCH + k] - alpha_1[j][L_BATCH + k]
                    + self.a_hat[k];
                hasher.update(v.to_bytes().as_ref());
                a_tilde[j][L_BATCH + k] = v;
            }
        }

        let mut theta = [[Scalar::ZERO; L_BATCH]; RHO];
        #[allow(clippy::needless_range_loop)]
        for k in 0..RHO {
            for i in 0..L_BATCH {
                hasher.update(format!("theta_{}_{}", k, i).as_bytes());
                let digest: [u8; 32] = hasher.finalize().into();
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

        let mut hasher = Hasher::new();
        hasher.update(&RANDOM_VOLE_MU_LABEL);
        hasher.update(self.session_id.as_ref());
        #[allow(clippy::needless_range_loop)]
        for j in 0..XI {
            for k in 0..RHO {
                let mut v = alpha_0[j][L_BATCH + k];
                for i in 0..L_BATCH {
                    v += theta[k][i] * alpha_0[j][i]
                }
                hasher.update(v.to_bytes().as_ref());
            }
        }
        hasher.update(b"p1");
        let mu_hash_1: [u8; 32] = hasher.finalize().into();
        hasher.update(b"p2");
        let mu_hash_2: [u8; 32] = hasher.finalize().into();
        output.mu_hash = [mu_hash_1.as_slice(), mu_hash_2.as_slice()]
            .concat()
            .try_into()
            .expect("Invalid length of mu_hash");

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

        let sender =
            RVOLESender::new(session_id, &receiver_ot_seed, &mut rng);

        let receiver =
            RVOLEReceiver::new(session_id, &sender_ot_seed, &mut rng);

        let (alpha1, alpha2) = (
            Scalar::generate_biased(&mut rng),
            Scalar::generate_biased(&mut rng),
        );

        let (receiver, beta, round1_output) = receiver.process();

        let (sender_shares, round2_output) =
            sender.process([alpha1, alpha2], &round1_output).unwrap();

        let receiver_shares = receiver.process(&round2_output).unwrap();

        let sum_0 = receiver_shares[0] + sender_shares[0];
        let sum_1 = receiver_shares[1] + sender_shares[1];

        assert_eq!(sum_0, alpha1 * beta);
        assert_eq!(sum_1, alpha2 * beta);
    }
}
