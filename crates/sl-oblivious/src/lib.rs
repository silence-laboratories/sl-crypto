// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

/// Domain labels
pub mod constants;

/// Soft spoken Oblivious Transfer
pub mod soft_spoken;

/// zkproofs
pub mod zkproofs;

/// Endemic 1 out of 2 Oblivious Transfer
pub mod endemic_ot;

/// Random Vector OLE
pub mod rvole;

/// Utility functions
pub mod utils {
    use std::ops::Index;

    use elliptic_curve::{
        ff::PrimeField,
        ops::Reduce,
        sec1::{ModulusSize, ToEncodedPoint},
        CurveArithmetic, FieldBytes,
    };
    use merlin::Transcript;

    /// Custom extension trait for the merlin transcript.
    pub trait TranscriptProtocol<C: CurveArithmetic> {
        /// Append a point to the transcript.
        fn append_point(
            &mut self,
            label: &'static [u8],
            point: &C::ProjectivePoint,
        );

        /// Append a scalar to the transcript.
        fn append_scalar(&mut self, label: &'static [u8], scalar: &C::Scalar);

        /// Get challenge as scalar from the transcript.
        fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar;

        /// New transcript for DLOG proof
        fn new_dlog_proof(
            session_id: &[u8],
            party_id: usize,
            action: &[u8],
            label: &'static [u8],
        ) -> Transcript;
    }

    impl<C> TranscriptProtocol<C> for Transcript
    where
        C: CurveArithmetic,
        C::FieldBytesSize: ModulusSize,
        C::ProjectivePoint: ToEncodedPoint<C>,
    {
        fn append_point(
            &mut self,
            label: &'static [u8],
            point: &C::ProjectivePoint,
        ) {
            self.append_message(label, point.to_encoded_point(true).as_ref())
        }

        fn append_scalar(
            &mut self,
            label: &'static [u8],
            scalar: &C::Scalar,
        ) {
            let bytes = scalar.to_repr();
            self.append_message(label, bytes.as_ref())
        }

        fn new_dlog_proof(
            session_id: &[u8],
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

        fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar {
            let mut buf = FieldBytes::<C>::default();
            self.challenge_bytes(label, &mut buf);
            C::Scalar::reduce_bytes(&buf)
        }
    }

    /// Simple trait to extract a bit from a byte array.
    pub trait ExtractBit: Index<usize, Output = u8> {
        /// Extract a bit at given index (in little endian order) from a byte array.
        fn extract_bit(&self, idx: usize) -> bool {
            let byte_idx = idx >> 3;
            let bit_idx = idx & 0x7;
            let byte = self[byte_idx];
            let mask = 1 << bit_idx;
            (byte & mask) != 0
        }
    }

    impl ExtractBit for Vec<u8> {}
    impl<const T: usize> ExtractBit for [u8; T] {}

    pub fn bit_to_bit_mask(bit: u8) -> u8 {
        // constant time
        // outputs 0x00 if `bit == 0` and 0xFF if `bit == 1`
        -(bit as i8) as u8
    }
}

pub mod params;

pub mod label;

/// Random Vector OLE (base OT variant)
pub mod rvole_ot_variant;
