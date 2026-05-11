use elliptic_curve::{
    ff::PrimeField,
    ops::Reduce,
    sec1::{ModulusSize, ToEncodedPoint},
    CurveArithmetic, FieldBytes,
};

#[cfg(feature = "merlin")]
pub use merlin_imp::Transcript;

#[cfg(all(not(feature = "merlin"), feature = "shake128"))]
pub use shake128::Transcript;

/// Common transcript interface used by protocol code.
///
/// Implementations provide labeled absorption and challenge generation.
/// The primitive methods are `new`, `append_message`, `append_u64`, and
/// `challenge_bytes`; the curve helpers have default implementations.
pub trait TranscriptProtocol {
    /// Create a new transcript with the given domain-separation label.
    fn new(label: &'static [u8]) -> Self
    where
        Self: Sized;

    /// Absorb an arbitrary byte string under a label.
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);

    /// Absorb a `u64` value under a label.
    fn append_u64(&mut self, label: &'static [u8], value: u64);

    /// Fill `dest` with challenge bytes derived from the transcript state.
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Absorb an elliptic-curve point in compressed form.
    fn append_point<C>(
        &mut self,
        label: &'static [u8],
        point: &C::ProjectivePoint,
    ) where
        C: CurveArithmetic,
        C::FieldBytesSize: ModulusSize,
        C::ProjectivePoint: ToEncodedPoint<C>,
    {
        self.append_message(label, point.to_encoded_point(true).as_ref())
    }

    /// Absorb an elliptic-curve scalar in canonical representation.
    fn append_scalar<C>(&mut self, label: &'static [u8], scalar: &C::Scalar)
    where
        C: CurveArithmetic,
        C::FieldBytesSize: ModulusSize,
        C::ProjectivePoint: ToEncodedPoint<C>,
    {
        let bytes = scalar.to_repr();
        self.append_message(label, bytes.as_ref())
    }

    /// Derive a scalar challenge from the transcript.
    fn challenge_scalar<C>(&mut self, label: &'static [u8]) -> C::Scalar
    where
        C: CurveArithmetic,
        C::FieldBytesSize: ModulusSize,
        C::ProjectivePoint: ToEncodedPoint<C>,
    {
        let mut buf = FieldBytes::<C>::default();
        self.challenge_bytes(label, &mut buf);
        C::Scalar::reduce_bytes(&buf)
    }

    /// Construct the transcript context used by DLog proofs.
    fn new_dlog_proof(
        session_id: &[u8],
        party_id: usize,
        action: &[u8],
        label: &'static [u8],
    ) -> Self
    where
        Self: Sized,
    {
        let mut transcript = Self::new(label);
        transcript.append_message(b"session_id", session_id.as_ref());
        transcript.append_u64(b"party_id", party_id as u64);
        transcript.append_message(b"action", action);
        transcript
    }
}

#[cfg(feature = "merlin")]
mod merlin_imp {
    use super::*;

    pub struct Transcript(merlin::Transcript);

    impl Transcript {
        pub fn new(label: &'static [u8]) -> Self {
            Self(merlin::Transcript::new(label))
        }
    }

    impl TranscriptProtocol for Transcript {
        fn new(label: &'static [u8]) -> Self {
            Self::new(label)
        }

        fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
            self.0.append_message(label, message);
        }

        fn append_u64(&mut self, label: &'static [u8], value: u64) {
            self.0.append_u64(label, value)
        }

        fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
            self.0.challenge_bytes(label, dest);
        }
    }
}

#[cfg(feature = "shake128")]
mod shake128 {
    use super::TranscriptProtocol;

    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };

    pub struct Transcript(Shake128);

    impl Transcript {
        pub fn new(label: &'static [u8]) -> Self {
            let mut t = Shake128::default();
            t.update(&(label.len() as u64).to_le_bytes());
            t.update(label);
            Self(t)
        }
    }

    impl TranscriptProtocol for Transcript {
        fn new(label: &'static [u8]) -> Self {
            Self::new(label)
        }

        fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
            self.0.update(&(label.len() as u64).to_le_bytes());
            self.0.update(label);
            self.0.update(&(message.len() as u64).to_le_bytes());
            self.0.update(message);
        }

        fn append_u64(&mut self, label: &'static [u8], value: u64) {
            self.append_message(label, &value.to_le_bytes());
        }

        fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
            self.0.update(&(label.len() as u32).to_le_bytes());
            self.0.update(label);
            self.0.update(&(dest.len() as u32).to_le_bytes());

            self.0.clone().finalize_xof().read(dest);
        }
    }
}
