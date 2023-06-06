mod messages;
/// VSOT Sender
mod sender;

mod receiver;

pub use messages::*;
pub use receiver::*;
pub use sender::*;

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
/// VSOT errors
pub enum VSOTError {
    /// Invalid Batch size
    #[error("Invalid batch size")]
    InvalidBatchSize,
    /// Invalid Dlog proof for message 1
    #[error("Invalid DLog proof for message 1")]
    InvalidDLogProof,
    /// Invalid challenge response by the receiver
    #[error("Invalid challenge response by the receiver")]
    InvalidChallegeResponse,
    /// Invalid data count
    #[error("Invalid data count, must be equal to batch size")]
    InvalidDataCount,
    /// Invalid rho_w hash
    #[error("Invalid rho_w hash")]
    InvalidRhoHash,
}
