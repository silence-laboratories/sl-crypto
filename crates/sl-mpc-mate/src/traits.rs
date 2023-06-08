use std::cmp::Ordering;

use elliptic_curve::{bigint::NonZero, scalar::FromUintUnchecked, Field};
use elliptic_curve::{bigint::U256, CurveArithmetic};

use serde::{de::DeserializeOwned, Serialize};

/// Trait that defines an object that can be converted to and from an array of bytes.
pub trait PersistentObject: Serialize + DeserializeOwned + Send + 'static {
    ///  Serialize
    fn to_bytes(&self) -> Option<Vec<u8>> {
        bincode::serialize(self).ok()
    }

    /// Deserialize
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }

    /// Deserialize batch of messages
    fn decode_batch(bytes: &[u8]) -> Option<Vec<Self>> {
        let msgs: Vec<&[u8]> = bincode::deserialize(bytes).ok()?;

        msgs.into_iter().map(Self::from_bytes).collect()
    }
}

impl PersistentObject for Vec<u8> {}

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
/// Trait that defines a way to convert this type to a [Scalar].
/// Only supports converting to [Scalar] of max size [U256] for now.
pub trait ToScalar {
    /// Convert to [Scalar]
    fn to_scalar<C: CurveArithmetic>(&self) -> C::Scalar
    where
        C: CurveArithmetic<Uint = elliptic_curve::bigint::Uint<4>>;
}

impl ToScalar for U256 {
    fn to_scalar<C: CurveArithmetic>(&self) -> C::Scalar
    where
        C: CurveArithmetic<Uint = elliptic_curve::bigint::Uint<4>>,
    {
        match self.cmp(&C::ORDER) {
            Ordering::Less => C::Scalar::from_uint_unchecked(*self),
            Ordering::Equal => C::Scalar::ZERO,
            Ordering::Greater => {
                // We know order is non zero
                let order = NonZero::new(C::ORDER).unwrap();
                // SAFETY: We know the scalar is less than the order as we do bigint mod order.
                C::Scalar::from_uint_unchecked(self.rem(&order))
            }
        }
    }
}

// Make this part of OT crate
// /// Message that contains an encrypted vsot message
// pub trait HasVsotMsg {
//     /// Returns the VSOT message for a party
//     fn get_vsot_msg(&self, party_id: usize) -> &EncryptedData;
// }
