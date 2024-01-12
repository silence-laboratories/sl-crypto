use std::ops::{Deref, DerefMut};

use elliptic_curve::subtle::{Choice, ConditionallySelectable};
use rand::prelude::*;

pub mod math;
pub mod matrix;

pub mod bip32;
pub mod coord;
pub mod label;
pub mod message;

/// Reexport bincode
pub use bincode;

/// Session ID
pub type SessionId = ByteArray<32>;

pub type HashBytes = ByteArray<32>;

/// XOR two byte arrays.
pub fn xor_byte_arrays<const T: usize>(a: &[u8; T], b: &[u8; T]) -> [u8; T] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

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

#[cfg(feature = "serde")]
pub mod ser {
    use std::marker::PhantomData;
    use std::{array, fmt};

    use super::*;

    impl<const N: usize> serde::Serialize for ByteArray<N> {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> core::result::Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            serializer.serialize_bytes(&self.0)
        }
    }

    pub struct Visitor<const N: usize, const M: usize>(
        PhantomData<[[u8; N]; M]>,
    );

    impl<const N: usize, const M: usize> Visitor<N, M> {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self(PhantomData)
        }
    }

    impl<'de, const N: usize, const M: usize> serde::de::Visitor<'de>
        for Visitor<N, M>
    {
        type Value = [[u8; N]; M];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a {} bytes array", N)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.len() != N * M {
                return Err(serde::de::Error::invalid_length(
                    N * M,
                    &"bytes",
                ));
            }

            Ok(array::from_fn(|i| v[i * N..][..N].try_into().unwrap()))
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_bytes(v.as_ref())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut b = [[0u8; N]; M];

            for r in &mut b {
                for c in r {
                    if let Some(b) = seq.next_element()? {
                        *c = b;
                    } else {
                        return Err(serde::de::Error::invalid_length(
                            N * M,
                            &"bytes",
                        ));
                    }
                }
            }

            Ok(b)
        }
    }

    impl<'de, const N: usize> serde::Deserialize<'de> for ByteArray<N> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            let bytes: [[u8; N]; 1] =
                deserializer.deserialize_bytes(Visitor::new())?;

            Ok(ByteArray::new(bytes[0]))
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod ser_tests {
    use crate::ByteArray;

    #[test]
    fn cbor_bytes() {
        let b = ByteArray::<32>::default();
        let mut w = vec![];

        ciborium::ser::into_writer(&b, &mut w).unwrap();

        let r: ByteArray<32> =
            ciborium::de::from_reader(&w as &[u8]).unwrap();

        assert_eq!(b, r);

        assert!(
            ciborium::de::from_reader::<ByteArray<16>, &[u8]>(&w).is_err()
        );
    }

    #[test]
    fn json_bytes() {
        let b = ByteArray::<32>::default();

        let w = serde_json::to_string(&b).unwrap();

        let r: ByteArray<32> = serde_json::from_str(&w).unwrap();

        assert_eq!(b, r);

        assert!(serde_json::from_str::<ByteArray<16>>(&w).is_err());
    }
}
