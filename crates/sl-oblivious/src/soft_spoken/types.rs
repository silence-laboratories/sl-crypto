use thiserror::Error;

/// SoftSpokenOT errors
#[derive(Error, Debug)]
pub enum SoftSpokenOTError {
    /// Abort the protocol and ban the Receiver
    #[error("Abort the protocol and ban the Receiver")]
    AbortProtocolAndBanReceiver,
}
