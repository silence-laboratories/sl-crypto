// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use elliptic_curve::{
    group::Curve,
    subtle::{Choice, ConstantTimeEq},
    CurveArithmetic, Field,
};
use rand::prelude::*;

use crate::{constants::DLOG_CHALLENGE_LABEL, utils::TranscriptProtocol};

/// Non-interactive Proof of knowledge of discrete logarithm with Fiat-Shamir transform.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DLogProof<C: CurveArithmetic> {
    /// Public point `t`.
    pub t: C::AffinePoint,

    /// Challenge response
    pub s: C::Scalar,
}

impl<C> DLogProof<C>
where
    C: CurveArithmetic,
{
    /// Prove knowledge of discrete logarithm.
    // TODO: Do we need merlin?
    pub fn prove<R: CryptoRng + RngCore>(
        x: &C::Scalar,
        base_point: &C::ProjectivePoint,
        transcript: &mut impl TranscriptProtocol<C>,
        rng: &mut R,
    ) -> Self {
        let r = C::Scalar::random(rng);
        let t = *base_point * r;
        let y = *base_point * x;
        let c = Self::fiat_shamir(&y, &t, base_point, transcript);

        let s = r + c * x;

        Self {
            t: t.to_affine(),
            s,
        }
    }

    /// Verify knowledge of discrete logarithm.
    pub fn verify(
        &self,
        y: &C::ProjectivePoint,
        base_point: &C::ProjectivePoint,
        transcript: &mut impl TranscriptProtocol<C>,
    ) -> Choice {
        let t = C::ProjectivePoint::from(self.t);
        let c = Self::fiat_shamir(y, &t, base_point, transcript);
        let lhs = *base_point * self.s;
        let rhs = t + *y * c;

        lhs.ct_eq(&rhs)
    }

    /// Get fiat-shamir challenge for Discrete log proof.
    pub fn fiat_shamir(
        y: &C::ProjectivePoint,
        t: &C::ProjectivePoint,
        base_point: &C::ProjectivePoint,
        transcript: &mut impl TranscriptProtocol<C>,
    ) -> C::Scalar {
        transcript.append_point(b"y", y);
        transcript.append_point(b"t", t);
        transcript.append_point(b"base-point", base_point);
        transcript.challenge_scalar(&DLOG_CHALLENGE_LABEL)
    }
}

#[cfg(test)]
mod tests {
    use k256::{ProjectivePoint, Scalar, Secp256k1};
    use merlin::Transcript;
    use rand::thread_rng;

    use super::DLogProof;

    #[test]
    pub fn dlog_proof() {
        use k256::{ProjectivePoint, Scalar};
        use merlin::Transcript;
        use rand::thread_rng;

        let mut rng = thread_rng();
        let mut transcript = Transcript::new(b"test-dlog-proof");

        let x = Scalar::generate_biased(&mut rng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::<Secp256k1>::prove(
            &x,
            &base_point,
            &mut transcript,
            &mut rng,
        );

        let mut verify_transcript = Transcript::new(b"test-dlog-proof");

        assert_ne!(
            proof
                .verify(&y, &base_point, &mut verify_transcript)
                .unwrap_u8(),
            0
        );
    }

    #[test]
    pub fn wrong_dlog_proof() {
        let mut rng = thread_rng();
        let mut transcript = Transcript::new(b"test-dlog-proof");

        let x = Scalar::generate_biased(&mut rng);
        let base_point = ProjectivePoint::GENERATOR;
        let wrong_scalar = Scalar::generate_biased(&mut rng);
        let y = base_point * x;

        let proof = DLogProof::<Secp256k1>::prove(
            &wrong_scalar,
            &base_point,
            &mut transcript,
            &mut rng,
        );

        let mut verify_transcript = Transcript::new(b"test-dlog-proof");

        assert_ne!(
            !proof
                .verify(&y, &base_point, &mut verify_transcript)
                .unwrap_u8(),
            0
        );
    }

    #[test]
    pub fn dlog_proof_fiat_shamir() {
        use k256::{ProjectivePoint, Scalar};
        use merlin::Transcript;

        let mut rng = thread_rng();
        let mut transcript = Transcript::new(b"test-dlog-proof");

        let x = Scalar::generate_biased(&mut rng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::<Secp256k1>::prove(
            &x,
            &base_point,
            &mut transcript,
            &mut rng,
        );

        let mut verify_transcript = Transcript::new(b"test-dlog-proof-wrong");

        assert_ne!(
            !proof
                .verify(&y, &base_point, &mut verify_transcript)
                .unwrap_u8(),
            0,
            "Proof should fail with wrong transcript"
        );
    }
}
