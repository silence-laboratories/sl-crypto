use std::ops::Deref;

use cooridinator::Coordinator;
#[cfg(feature = "nacl")]
use dryoc::{
    classic::{crypto_sign, crypto_sign_ed25519::Signature},
    constants::{CRYPTO_BOX_NONCEBYTES, CRYPTO_SIGN_ED25519_BYTES},
    dryocbox::VecBox,
    types::StackByteArray,
};

use elliptic_curve::subtle::{Choice, ConditionallySelectable};
use serde::{Deserialize, Serialize};
use traits::PersistentObject;

pub mod math;
pub mod matrix;
pub mod traits;
pub use rand::{CryptoRng, RngCore};

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
pub fn xor_byte_arrays<const T: usize>(a: [u8; T], b: [u8; T]) -> [u8; T] {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
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

#[macro_export]
/// Macro to implement the HasFromParty and HasSignature traits for a message types.
macro_rules! impl_basemessage {
    ($($type:ty),*) => {
        $(
            impl sl_mpc_mate::traits::HasFromParty for $type {
                fn get_pid(&self) -> usize {
                    self.from_party
                }
            }

            impl sl_mpc_mate::traits::HasSignature for $type {
                fn get_signature(&self) -> &Signature {
                    &self.signature
                }
            }
        )*
    }
}

/// Sign a message using the given signing key.
#[cfg(feature = "nacl")]
pub fn sign_message(
    signing_key: &dryoc::classic::crypto_sign::SecretKey,
    message: &[u8],
) -> Result<Signature, dryoc::Error> {
    let mut signed_message: Signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
    crypto_sign::crypto_sign_detached(&mut signed_message, message, signing_key)?;
    Ok(signed_message)
}

/// Verify signature and check if the signed message is correct
#[cfg(feature = "nacl")]
pub fn verify_signature(
    message_hash: &[u8],
    signature: &Signature,
    verify_key: &crypto_sign::PublicKey,
) -> Result<(), dryoc::Error> {
    crypto_sign::crypto_sign_verify_detached(signature, message_hash, verify_key)
}

/// Data that was encrypted using authenticated encryption.
#[cfg(feature = "nacl")]
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
