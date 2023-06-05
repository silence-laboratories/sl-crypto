use std::ops::Deref;

use cooridinator::Coordinator;
use dryoc::{constants::CRYPTO_BOX_NONCEBYTES, dryocbox::VecBox, types::StackByteArray};
use elliptic_curve::subtle::{Choice, ConditionallySelectable};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use traits::PersistentObject;

mod math;
mod serialization;
mod traits;

/// Session ID
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 32]);

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for SessionId {
    fn from(b: [u8; 32]) -> Self {
        SessionId(b)
    }
}

impl SessionId {
    /// Create a new session id from a byte array.
    pub fn new(b: [u8; 32]) -> Self {
        SessionId(b)
    }

    /// Function to generate a random session id which is a 32 byte array.
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> SessionId {
        SessionId(random_bytes(rng))
    }
}

/// Generate a random byte array
pub fn random_bytes<const N: usize, R: CryptoRng + RngCore>(rng: &mut R) -> [u8; N] {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    buf
}

// Wrapper around a byte array of 32 bytes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashBytes(pub [u8; 32]);

impl ConditionallySelectable for HashBytes {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [0u8; 32];
        res.iter_mut()
            .enumerate()
            .for_each(|(idx, x)| *x = u8::conditional_select(&a.0[idx], &b.0[idx], choice));

        Self(res)
    }
}

impl AsRef<[u8]> for HashBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for HashBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for HashBytes {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

/// Receive a batch broadcast from the coordinator.
/// Only used internally for testing.
pub fn recv_broadcast<M: PersistentObject>(coord: &mut Coordinator, round: usize) -> Vec<M> {
    M::decode_batch(&coord.broadcast(round).unwrap()).unwrap()
}

/// Prepare batch of messages
pub fn encode_batch<T: AsRef<[u8]>>(msgs: &[T]) -> Option<Vec<u8>> {
    let msgs: Vec<&[u8]> = msgs.iter().map(AsRef::as_ref).collect();
    bincode::serialize(&msgs).ok()
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
        pub fn send(&mut self, round: usize, msg: Msg) -> Result<usize, Error> {
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
