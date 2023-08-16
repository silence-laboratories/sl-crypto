use std::ops::Deref;

use elliptic_curve::subtle::{Choice, ConditionallySelectable};
use rand::prelude::*;

pub mod math;
pub mod matrix;
pub mod traits;

pub mod coord;
pub mod message;
pub mod state;

/// Reexport bincode
pub use bincode;

use cooridinator::Coordinator;
use traits::PersistentObject;

#[cfg(feature = "nacl")]
pub mod nacl {
    use crate::traits::PersistentObject;
    use dryoc::classic::crypto_sign;
    pub use dryoc::classic::crypto_sign::crypto_sign_seed_keypair;
    pub use dryoc::classic::crypto_sign::{
        PublicKey as SignPubkey, SecretKey as SignPrivKey,
    };
    pub use dryoc::classic::crypto_sign_ed25519::Signature;
    use dryoc::constants::{
        CRYPTO_BOX_NONCEBYTES, CRYPTO_SIGN_ED25519_BYTES,
    };
    use dryoc::dryocbox::{DryocBox, Nonce, VecBox};
    pub use dryoc::dryocbox::{
        KeyPair, PublicKey as BoxPubkey, SecretKey as BoxPrivKey,
    };
    use dryoc::types::{NewByteArray, StackByteArray};
    pub use dryoc::Error;

    use serde::{Deserialize, Serialize};

    /// Sign a message using the given signing key.
    pub fn sign_message(
        signing_key: &SignPrivKey,
        message: &[u8],
    ) -> Result<Signature, dryoc::Error> {
        let mut signed_message: Signature =
            [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign::crypto_sign_detached(
            &mut signed_message,
            message,
            signing_key,
        )?;
        Ok(signed_message)
    }

    /// Verify signature and check if the signed message is correct
    #[cfg(feature = "nacl")]
    pub fn verify_signature(
        message_hash: &[u8],
        signature: &Signature,
        verify_key: &SignPubkey,
    ) -> Result<(), dryoc::Error> {
        crypto_sign::crypto_sign_verify_detached(
            signature,
            message_hash,
            verify_key,
        )
    }

    /// Encrypt data using the given public key, secret key.
    pub fn encrypt_data<D: AsRef<[u8]>>(
        data: D,
        ek: &BoxPubkey,
        sk: &BoxPrivKey,
        to_party: usize,
        from_party: usize,
    ) -> Result<EncryptedData, dryoc::Error> {
        let nonce = Nonce::gen();
        let enc_data =
            DryocBox::encrypt_to_vecbox(data.as_ref(), &nonce, ek, sk)?;
        let enc_vsot_msg = EncryptedData {
            to_party,
            from_party,
            enc_data,
            nonce,
        };

        Ok(enc_vsot_msg)
    }

    /// Data that was encrypted using authenticated encryption.
    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct EncryptedData {
        // TODO: Should we omit from_party and to_party?
        // We can calculate them from the message pid and the party id list.
        /// The party to which this part is encrypted for.
        pub to_party: usize,
        /// The party who encrypted this part.
        pub from_party: usize,
        /// The encrypted data.
        pub enc_data: VecBox,
        /// The nonce used for encryption
        pub nonce: StackByteArray<CRYPTO_BOX_NONCEBYTES>,
    }

    impl crate::traits::HasFromParty for EncryptedData {
        fn get_pid(&self) -> usize {
            self.from_party
        }
    }

    impl PersistentObject for EncryptedData {}

    /// Message that has a signature
    pub trait HasSignature {
        /// Returns the signature of this message
        fn get_signature(&self) -> &Signature;
    }
}

pub use elliptic_curve::bigint::{
    ArrayDecoding, ArrayEncoding, Encoding, U256,
};
pub use rand_core::{CryptoRng, RngCore};

/// Session ID
pub type SessionId = ByteArray<32>;

pub type HashBytes = ByteArray<32>;

// /// Calculates the final session id from the list of session ids.
// pub fn calculate_final_session_id(
//     party_ids: impl IntoIterator<Item = usize>,
//     sid_i_list: &[SessionId],
// ) -> SessionId {
//     let mut hasher = Sha256::new();

//     party_ids
//         .into_iter()
//         .for_each(|pid| hasher.update((pid as u32).to_be_bytes()));

//     sid_i_list.iter().for_each(|sid| hasher.update(sid));

//     SessionId::new(hasher.finalize().into())
// }

/// XOR two byte arrays.
pub fn xor_byte_arrays<const T: usize>(
    a: &[u8; T],
    b: &[u8; T],
) -> [u8; T] {
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

// Wrapper around a byte array of 32 bytes.

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

impl<const T: usize> ByteArray<T> {
    pub fn new(b: [u8; T]) -> Self {
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

/// Receive a batch broadcast from the coordinator.
/// Only used internally for testing.
pub fn recv_broadcast<M: PersistentObject>(
    coord: &mut Coordinator,
    round: usize,
) -> Vec<M> {
    M::decode_batch(&coord.broadcast(round).unwrap()).unwrap()
}

/// Prepare batch of messages
pub fn encode_batch<T: AsRef<[u8]>>(msgs: &[T]) -> Option<Vec<u8>> {
    let msgs: Vec<&[u8]> = msgs.iter().map(AsRef::as_ref).collect();
    bincode::serde::encode_to_vec(&msgs, bincode::config::legacy()).ok()
}

#[macro_export]
/// Macro to implement the HasFromParty and HasSignature traits for a message types.
macro_rules! impl_basemessage {
    ($($type:ty),*) => {
        $(
            impl $crate::traits::HasFromParty for $type {
                fn get_pid(&self) -> usize {
                    self.from_party
                }
            }

            impl $crate::nacl::HasSignature for $type {
                fn get_signature(&self) -> &Signature {
                    &self.signature
                }
            }
        )*
    }
}

/// Coordinator module
pub mod cooridinator {
    use crate::encode_batch;

    type Msg = Vec<u8>;

    /// Coordinator
    pub struct Coordinator {
        parties: usize,
        rounds: usize,
        store: Vec<Msg>,
    }

    #[derive(Debug)]
    /// Coordinator errors
    pub enum Error {
        /// Some party tries to send more messages then expected
        RoundFinished,

        /// Some party tries to send message after last round is finished
        TooManyRounds,

        /// Not all messages for a given round are received
        InProgress,
    }

    impl Coordinator {
        /// Create new Coordinator.
        pub fn new(parties: usize, rounds: usize) -> Self {
            Coordinator {
                parties,
                rounds,
                store: Vec::with_capacity(parties * rounds),
            }
        }

        /// Get the maximum number of rounds.
        pub fn max_round(&self) -> usize {
            self.rounds
        }

        /// Receive a message from a party for a given round.
        pub fn send(
            &mut self,
            round: usize,
            msg: Msg,
        ) -> Result<usize, Error> {
            let len = self.store.len();

            if len == self.store.capacity() {
                return Err(Error::TooManyRounds);
            }

            if len / self.parties != round {
                return Err(Error::RoundFinished);
            }

            let pid = len % self.parties;

            self.store.push(msg);

            Ok(pid)
        }

        /// Broadcast the messages for a given round.
        pub fn broadcast(&self, round: usize) -> Result<Msg, Error> {
            let start = round * self.parties;
            let end = start + self.parties;

            if self.store.len() < end {
                Err(Error::InProgress)
            } else {
                // TODO: remove unwrap()
                Ok(encode_batch(&self.store[start..end]).unwrap())
            }
        }
    }
}
