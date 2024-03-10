// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand_core::CryptoRngCore;

use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::{Encoding, NonZero, RandomMod, Uint};

pub trait PublicN<const L: usize>
where
    Uint<L>: Encoding,
{
    fn n(&self) -> &NonZero<Uint<L>>;

    fn r(&self, rng: &mut impl CryptoRngCore) -> NonZero<Uint<L>> {
        NonZero::new(Uint::<L>::random_mod(rng, &self.n())).unwrap()
    }
}

pub trait NN<const L: usize>
where
    Uint<L>: Encoding,
{
    fn nn(&self) -> &NonZero<Uint<L>>;
}

pub trait PublicModParams<const L: usize> {
    fn params(&self) -> DynResidueParams<L>;
}
