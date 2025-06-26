// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{Deref, DerefMut};

use elliptic_curve::subtle::{Choice, ConditionallySelectable};
use rand::prelude::*;

pub mod math;
pub mod matrix;

pub mod bip32;

/// Session ID
pub type SessionId = ByteArray<32>;

pub type HashBytes = ByteArray<32>;

/// Generate a random byte array
pub fn random_bytes<const N: usize, R: CryptoRng + RngCore>(
    rng: &mut R,
) -> [u8; N] {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    buf
}

// TODO Use GenericArray<u8, N> ?

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ByteArray<const T: usize>(pub [u8; T]);

impl<const T: usize> ConditionallySelectable for ByteArray<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[u8; T]>::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const T: usize> AsRef<[u8]> for ByteArray<T> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const T: usize> Deref for ByteArray<T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const T: usize> Default for ByteArray<T> {
    fn default() -> Self {
        Self([0; T])
    }
}

impl<const T: usize> ByteArray<T> {
    pub const fn new(b: [u8; T]) -> Self {
        Self(b)
    }

    /// Function to generate a random session id which is a 32 byte array.
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0; T];
        rng.fill_bytes(&mut bytes);
        ByteArray(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(b: [u8; N]) -> Self {
        ByteArray(b)
    }
}

impl<const N: usize> From<&[u8; N]> for ByteArray<N> {
    fn from(b: &[u8; N]) -> Self {
        ByteArray(*b)
    }
}

impl<const N: usize> From<ByteArray<N>> for [u8; N] {
    fn from(value: ByteArray<N>) -> Self {
        value.0
    }
}
