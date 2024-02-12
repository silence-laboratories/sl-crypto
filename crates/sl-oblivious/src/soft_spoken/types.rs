// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use thiserror::Error;

/// SoftSpokenOT errors
#[derive(Error, Debug)]
pub enum SoftSpokenOTError {
    /// Abort the protocol and ban the Receiver
    #[error("Abort the protocol and ban the Receiver")]
    AbortProtocolAndBanReceiver,
}
