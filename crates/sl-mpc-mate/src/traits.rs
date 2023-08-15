use serde::{de::DeserializeOwned, Serialize};

/// Trait that defines an object that can be converted to and from an array of bytes.
pub trait PersistentObject:
    Serialize + DeserializeOwned + Send + 'static
{
    ///  Serialize
    fn to_bytes(&self) -> Option<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::legacy())
            .ok()
    }

    /// Deserialize
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::legacy(),
        )
        .map(|(val, _)| val)
        .ok()
    }

    /// Deserialize batch of messages
    fn decode_batch(_bytes: &[u8]) -> Option<Vec<Self>> {
        todo!()
        // let msgs: Vec<&[u8]> = bincode::serde::decode_from_slice(
        //     bytes,
        //     bincode::config::legacy(),
        // )
        // .map(|(val, _)| val)
        // .ok()?;

        // msgs.into_iter().map(Self::from_bytes).collect()
    }
}

impl PersistentObject for Vec<u8> {}
impl<T: PersistentObject> PersistentObject for Vec<T> {}

/// Trait that defines a state transition for any round based protocol.
pub trait Round {
    /// Input of the state transition.
    type Input;

    /// Output of the state transition.
    type Output;

    /// Transition to the next state.
    fn process(self, messages: Self::Input) -> Self::Output;
}

/// Message that has a from_party field
pub trait HasFromParty {
    /// Get party's ID of a message
    fn get_pid(&self) -> usize;
}

pub trait HasToParty {
    /// Get the receipient of this message
    fn get_receiver(&self) -> usize;
}
