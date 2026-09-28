// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::{error::Error, fmt};

/// SoftSpokenOT errors
#[derive(Debug)]
pub enum SoftSpokenOTError {
    /// Abort the protocol and ban the Receiver
    AbortProtocolAndBanReceiver,
}

impl fmt::Display for SoftSpokenOTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbortProtocolAndBanReceiver => {
                f.write_str("Abort the protocol and ban the Receiver")
            }
        }
    }
}

impl Error for SoftSpokenOTError {}
