// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! No-op key/signature types for trusted transport scenarios.
//!
//! These helpers are useful when message authenticity is already guaranteed
//! by the transport channel (for example, mTLS or authenticated in-process
//! channels) and protocol wiring still requires signing/verifying types.

use signature::{SignatureEncoding, Signer, Verifier};

/// An empty signature type.
///
/// The binary representation is always an empty byte array.
#[derive(Clone)]
pub struct NoSignature;

impl SignatureEncoding for NoSignature {
    type Repr = [u8; 0];
}

impl<'a> TryFrom<&'a [u8]> for NoSignature {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if !value.is_empty() {
            return Err(());
        }
        Ok(NoSignature)
    }
}

impl TryInto<[u8; 0]> for NoSignature {
    type Error = ();

    fn try_into(self) -> Result<[u8; 0], Self::Error> {
        Ok([0; 0])
    }
}

/// A signer that always produces [`NoSignature`].
#[derive(Clone)]
pub struct NoSigningKey;

impl Signer<NoSignature> for NoSigningKey {
    fn try_sign(&self, _msg: &[u8]) -> Result<NoSignature, signature::Error> {
        Ok(NoSignature)
    }
}

/// A verifying key for `NoSignature`. Verification always succeeds.
///
/// In this case, the verifying key is used as an identity ID and
/// communication uses a secure transport, so there is no need to
/// verify message authenticity.
#[derive(Clone)]
pub struct NoVerifyingKey(Vec<u8>);

impl NoVerifyingKey {
    /// Creates a verifier from a numeric identity.
    ///
    /// The identifier is encoded as big-endian `u64` bytes.
    pub fn new(id: usize) -> Self {
        NoVerifyingKey((id as u64).to_be_bytes().into())
    }
}

impl<T: Into<Vec<u8>>> From<T> for NoVerifyingKey {
    fn from(value: T) -> Self {
        NoVerifyingKey(value.into())
    }
}

impl AsRef<[u8]> for NoVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Verifier<NoSignature> for NoVerifyingKey {
    fn verify(
        &self,
        _: &[u8],
        _: &NoSignature,
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}
