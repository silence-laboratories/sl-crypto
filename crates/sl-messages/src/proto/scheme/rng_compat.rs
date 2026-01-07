// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand_core_09::{TryCryptoRng, TryRngCore};
use rand_core::{CryptoRng as CryptoRng06, RngCore as RngCore06};

/// Wrapper to adapt a rand_core 0.9 RNG to implement rand_core 0.6 traits
pub struct RngCompat09To06<R>(pub R);

impl<R: TryRngCore> RngCore06 for RngCompat09To06<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.try_next_u32().expect("RNG error")
    }

    fn next_u64(&mut self) -> u64 {
        self.0.try_next_u64().expect("RNG error")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.try_fill_bytes(dest).expect("RNG error")
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.0
            .try_fill_bytes(dest)
            .map_err(|_| rand_core::Error::new("RNG error"))
    }
}

impl<R: TryRngCore + TryCryptoRng> CryptoRng06 for RngCompat09To06<R> {}
