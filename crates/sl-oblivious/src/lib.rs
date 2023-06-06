/// Correlated Oblivious Transfer
pub mod cot;

/// Verified Simplest Oblivious Transfer
pub mod vsot;

/// Soft spoken Oblivious Transfer
pub mod soft_spoken;

/// Serialization for ProjectivePoint
// TODO: Can we remove this?
pub mod serialization;

mod zkproofs;

/// Utility functions
pub mod utils {
    use elliptic_curve::{bigint::Encoding, sec1::ToEncodedPoint};
    use k256::{ProjectivePoint, Secp256k1, U256};
    use merlin::Transcript;
    use sl_mpc_mate::{traits::ToScalar, SessionId};

    /// Compute the double blake hash of a byte array.
    pub fn double_blake_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();

        hasher.reset().update(hash.as_bytes()).finalize().into()
    }

    /// Compute the double blake hash of a byte array, and return both the hash and the double hash.
    pub fn double_blake_hash_inter(data: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let double_hash = hasher.reset().update(hash.as_bytes()).finalize();

        (hash.into(), double_hash.into())
    }
    /// Custom extension trait for the merlin transcript.
    pub trait TranscriptProtocol {
        /// Append a point to the transcript.
        fn append_point(&mut self, label: &'static [u8], point: &ProjectivePoint);
        /// Append a scalar to the transcript.
        fn append_scalar(&mut self, label: &'static [u8], scalar: &k256::Scalar);
        /// Get challenge as scalar from the transcript.
        fn challenge_scalar(&mut self, label: &'static [u8]) -> k256::Scalar;
        /// New transcript for DLOG proof
        fn new_dlog_proof(
            session_id: &SessionId,
            party_id: usize,
            action: &[u8],
            label: &'static [u8],
        ) -> Transcript;
    }

    impl TranscriptProtocol for Transcript {
        fn append_point(&mut self, label: &'static [u8], point: &ProjectivePoint) {
            self.append_message(label, point.to_encoded_point(true).as_bytes())
        }

        fn append_scalar(&mut self, label: &'static [u8], scalar: &k256::Scalar) {
            self.append_message(label, scalar.to_bytes().as_slice())
        }

        fn new_dlog_proof(
            session_id: &SessionId,
            party_id: usize,
            action: &[u8],
            label: &'static [u8],
        ) -> Self {
            let mut transcript = Transcript::new(label);
            transcript.append_message(b"session_id", session_id.as_ref());
            transcript.append_u64(b"party_id", party_id as u64);
            transcript.append_message(b"action", action);

            transcript
        }

        fn challenge_scalar(&mut self, label: &'static [u8]) -> k256::Scalar {
            let mut buf = [0u8; 32];
            self.challenge_bytes(label, &mut buf);
            U256::from_be_bytes(buf).to_scalar::<Secp256k1>()
        }
    }

    /// Simple trait to extract a bit from a byte array.
    pub trait ExtractBit {
        /// Extract a bit at given index from a byte array.
        fn extract_bit(&self, idx: usize) -> bool;
    }

    impl ExtractBit for Vec<u8> {
        fn extract_bit(&self, idx: usize) -> bool {
            let byte_idx = idx >> 3;
            let bit_idx = idx & 0x7;
            let byte = self[byte_idx];
            let mask = 1 << (8 - bit_idx - 1);
            (byte & mask) != 0
        }
    }
}
