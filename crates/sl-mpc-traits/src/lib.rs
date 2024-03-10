use serde::{de::DeserializeOwned, Serialize};

/// Trait that defines a state transition for any round based protocol.
pub trait Round {
    /// Output of the state transition.
    type Output;
    /// Input of the state transition.
    type Input;
    /// Transition to the next state.
    fn process(self, messages: Self::Input) -> Self::Output;
}

/// Trait that signifies a persistent object.
/// Encoded using bincode.
pub trait PersistentObject:
    Serialize + DeserializeOwned + Send + 'static
{
    /// Serialize the object into bytes.
    fn to_bytes(&self) -> Option<Vec<u8>> {
        bincode::serialize(self).ok()
    }
    /// Deserialize the object from bytes.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}
