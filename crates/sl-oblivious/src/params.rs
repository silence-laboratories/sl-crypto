pub mod consts {
    // Bits on underlying Scalar
    pub const KAPPA: usize = 256;

    // Computational security parameter, fixed to /lambda_c = 256
    // 256 OT seeds each 256-bit
    pub const LAMBDA_C: usize = 256;

    pub const LAMBDA_S: usize = 128;

    pub const S: usize = 128; // 16 bytes == 128 bits

    pub const L_BATCH: usize = 2;
    pub const RHO: usize = 1;
    pub const SOFT_SPOKEN_K: usize = 4;

    // size of u8 array to hold LAMBDA_C bits.
    pub const LAMBDA_C_BYTES: usize = LAMBDA_C / 8;

    pub const KAPPA_BYTES: usize = KAPPA >> 3;

    pub const S_BYTES: usize = S >> 3;

    pub const L: usize = KAPPA + 2 * LAMBDA_S; // L is divisible by S
    pub const L_BYTES: usize = L >> 3;

    pub const L_PRIME: usize = L + S;
    pub const L_PRIME_BYTES: usize = L_PRIME >> 3;

    pub const SOFT_SPOKEN_M: usize = L / S;

    pub const L_BATCH_PLUS_RHO: usize = L_BATCH + RHO; // should be equal to OT_WIDTH
    pub const OT_WIDTH: usize = L_BATCH_PLUS_RHO;

    pub const SOFT_SPOKEN_Q: usize = 1 << SOFT_SPOKEN_K;

    pub const LAMBDA_C_DIV_SOFT_SPOKEN_K: usize = LAMBDA_C / SOFT_SPOKEN_K;
}
