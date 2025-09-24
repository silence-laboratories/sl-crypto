mod constants;

use crate::constants::{FIELD_SIZE, FIELD_SIZE_BYTES, FRACTION_LENGTH, N};
use aead::rand_core::SeedableRng;
use crypto_bigint::{Encoding, U64};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::mem;
use std::ops::Index;
pub type FieldElement = U64;
pub type Binary = bool;
pub trait ExtractBit: Index<usize, Output = u8> {
    fn extract_bit(&self, idx: usize) -> bool {
        let byte_idx = idx >> 3;
        let bit_idx = idx & 0x7;
        let byte = self[byte_idx];

        ((byte >> bit_idx) & 1) != 0
    }
}

impl ExtractBit for Vec<u8> {}
impl<const T: usize> ExtractBit for [u8; T] {}

#[derive(Copy, Clone, Default, Debug)]
pub struct BinaryArithmetic {
    pub value: [u8; FIELD_SIZE_BYTES],
}

impl BinaryArithmetic {
    /// ZERO BinaryArithmetic
    pub const ZERO: BinaryArithmetic = BinaryArithmetic {
        value: [0u8; FIELD_SIZE_BYTES],
    };

    pub fn get_external_size(&self) -> usize {
        FIELD_SIZE_BYTES
    }

    pub fn from_binary_string(b: &BinaryString) -> Self {
        let len = b.value.len();
        assert!(len <= FIELD_SIZE_BYTES);

        let mut value = b.value.clone();

        if len != FIELD_SIZE_BYTES {
            let zero_pad = FIELD_SIZE_BYTES - len;
            value.extend(std::iter::repeat(0u8).take(zero_pad));
        }
        BinaryArithmetic {
            value: value.try_into().unwrap(),
        }
    }

    pub fn to_binary_string(&self, len: usize) -> BinaryString {
        let in_bytes = len.div_ceil(8);

        let value = &self.value[0..in_bytes];

        BinaryString {
            length: len as u64,
            value: value.to_vec(),
        }
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut value = self.value;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value[i] ^= other.value[i];
        }
        BinaryArithmetic { value }
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct BinaryArithmeticShare {
    pub value1: [u8; FIELD_SIZE_BYTES],
    pub value2: [u8; FIELD_SIZE_BYTES],
}

impl BinaryArithmeticShare {
    /// ZERO BinaryArithmeticShare
    pub const ZERO: BinaryArithmeticShare = BinaryArithmeticShare {
        value1: [0u8; FIELD_SIZE_BYTES],
        value2: [0u8; FIELD_SIZE_BYTES],
    };

    pub fn new(
        value1: [u8; FIELD_SIZE_BYTES],
        value2: [u8; FIELD_SIZE_BYTES],
    ) -> BinaryArithmeticShare {
        BinaryArithmeticShare { value1, value2 }
    }

    /// Returns party share for constant value
    pub fn from_constant(c: &FieldElement, party_index: usize) -> Self {
        let v = c
            .wrapping_mul(&FieldElement::from(1u64 << FRACTION_LENGTH))
            .to_le_bytes();
        match party_index {
            0 => BinaryArithmeticShare {
                value1: v,
                value2: v,
            },
            1 => BinaryArithmeticShare {
                value1: v,
                value2: [0u8; FIELD_SIZE_BYTES],
            },
            _ => BinaryArithmeticShare::ZERO,
        }
    }

    /// Reconstruct value with value1 from previous party
    pub fn reconstruct(&self, other: &BinaryArithmetic) -> BinaryArithmetic {
        let mut value = self.value2;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value[i] ^= other.value[i];
        }
        BinaryArithmetic { value }
    }

    pub fn from_own_and_other(
        own: &BinaryArithmetic,
        other: &BinaryArithmetic,
    ) -> BinaryArithmeticShare {
        let mut value1 = own.value;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value1[i] ^= other.value[i];
        }
        BinaryArithmeticShare {
            value1,
            value2: own.value,
        }
    }

    /// Create BinaryArithmeticShare from BinaryShare
    pub fn from_binary_share(
        from_share: &BinaryShare,
    ) -> BinaryArithmeticShare {
        // let mut row_id_bool_p: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
        // for _ in 0..FIELD_SIZE {
        //     row_id_bool_p.push(false, false);
        // }
        //
        // row_id_bool_p.set(
        //     FRACTION_LENGTH,
        //     input_table_p.0[i].is_delimiter.value1,
        //     input_table_p.0[i].is_delimiter.value2,
        // );
        let mut share = BinaryArithmeticShare::default();
        let byte_idx = FRACTION_LENGTH >> 3;
        let bit_idx = FRACTION_LENGTH & 0x7;
        if from_share.value1 {
            share.value1[byte_idx] |= 1 << bit_idx;
        }
        if from_share.value2 {
            share.value2[byte_idx] |= 1 << bit_idx;
        }
        share
    }

    pub fn to_binary_string_share(&self) -> BinaryStringShare {
        BinaryStringShare {
            length: FIELD_SIZE as u64,
            value1: self.value1.to_vec(),
            value2: self.value2.to_vec(),
        }
    }

    pub fn from_binary_string_share(
        from_share: &BinaryStringShare,
    ) -> BinaryArithmeticShare {
        assert_eq!(from_share.length, FIELD_SIZE as u64);
        BinaryArithmeticShare {
            value1: from_share.value1.clone().try_into().unwrap(),
            value2: from_share.value2.clone().try_into().unwrap(),
        }
    }

    pub fn from_choice(c: &BinaryShare) -> Self {
        let v1 = c.value1;
        let v2 = c.value2;

        let value1 = match v1 {
            true => [255u8; FIELD_SIZE_BYTES],
            false => [0u8; FIELD_SIZE_BYTES],
        };

        let value2 = match v2 {
            true => [255u8; FIELD_SIZE_BYTES],
            false => [0u8; FIELD_SIZE_BYTES],
        };

        BinaryArithmeticShare { value1, value2 }
    }

    pub fn xor(&self, other: &Self) -> BinaryArithmeticShare {
        let mut value1 = self.value1;
        let mut value2 = self.value2;
        for i in 0..FIELD_SIZE_BYTES {
            value1[i] ^= other.value1[i];
            value2[i] ^= other.value2[i];
        }
        BinaryArithmeticShare { value1, value2 }
    }

    pub fn not(&self) -> Self {
        let mut value2 = self.value2;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value2[i] ^= 0xFF;
        }
        BinaryArithmeticShare {
            value1: self.value1,
            value2,
        }
    }

    pub fn and_bitwise(
        &self,
        other: &Self,
        randomness: &mut CommonRandomness,
    ) -> BinaryArithmetic {
        let mut alpha_bytes = [0u8; FIELD_SIZE_BYTES];
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            let mut alpha_byte = 0u8;
            for j in 0..8 {
                let alpha = randomness.random_zero_bool() as u8;
                alpha_byte |= alpha << j;
            }
            alpha_bytes[i] = alpha_byte
        }
        let mut res = [0u8; FIELD_SIZE_BYTES];
        for i in 0..FIELD_SIZE_BYTES {
            res[i] = (self.value1[i] & other.value1[i])
                ^ (self.value2[i] & other.value2[i])
                ^ alpha_bytes[i];
        }

        BinaryArithmetic { value: res }
    }

    pub fn get_binary_share(&self, index: usize) -> BinaryShare {
        let bit1 = self.value1.extract_bit(index);
        let bit2 = self.value2.extract_bit(index);
        BinaryShare {
            value1: bit1,
            value2: bit2,
        }
    }

    pub fn set_binary_share(&mut self, index: usize, share: BinaryShare) {
        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;

        assert!(
            byte_idx < self.value1.len(),
            "No value assigned to the index yet!! {} {}",
            byte_idx,
            self.value1.len()
        );

        let mask = !(1 << bit_idx);

        self.value1[byte_idx] &= mask;
        self.value1[byte_idx] |= (share.value1 as u8) << bit_idx;

        self.value2[byte_idx] &= mask;
        self.value2[byte_idx] |= (share.value2 as u8) << bit_idx;
    }

    pub fn left_shift(&self, shift: usize) -> BinaryArithmeticShare {
        let v1 = FieldElement::from_le_slice(&self.value1).shl(shift);
        let v2 = FieldElement::from_le_slice(&self.value2).shl(shift);

        BinaryArithmeticShare {
            value1: v1.to_le_bytes(),
            value2: v2.to_le_bytes(),
        }
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct BinaryString {
    pub length: u64,
    pub value: Vec<u8>,
}

impl BinaryString {
    pub fn new() -> Self {
        BinaryString {
            length: 0,
            value: Vec::new(),
        }
    }

    pub fn new_with_zeros(size_in_bits: usize) -> Self {
        let size_in_bytes = (size_in_bits + 7) / 8;
        BinaryString {
            length: size_in_bits as u64,
            value: vec![0u8; size_in_bytes],
        }
    }

    pub fn length_in_bytes(&self) -> usize {
        if (self.length % 8) == 0 {
            (self.length / 8) as usize
        } else {
            (self.length / 8) as usize + 1
        }
    }

    pub fn get_external_size(&self) -> usize {
        mem::size_of::<u64>() + self.length_in_bytes()
    }

    pub fn with_capacity(size: usize) -> Self {
        let num_bytes = (size + 7) / 8;
        BinaryString {
            length: 0_u64,
            value: Vec::with_capacity(num_bytes),
        }
    }

    pub fn get(&self, index: usize) -> bool {
        self.value.extract_bit(index)
    }

    pub fn set(&mut self, index: usize, value: bool) {
        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;

        assert!(
            byte_idx < self.value.len(),
            "No value assigned to the index yet!! {} {}",
            byte_idx,
            self.value.len()
        );

        self.value[byte_idx] &= !(1 << bit_idx);
        self.value[byte_idx] |= (value as u8) << bit_idx;
    }

    pub fn push(&mut self, value: bool) {
        let index = self.length as usize;

        if index >= self.value.len() * 8 {
            self.value.push(0);
        }

        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;
        self.value[byte_idx] |= (value as u8) << bit_idx;

        self.length += 1;
    }

    pub fn reverse(&mut self) {
        let mut newout = Self::with_capacity(self.length as usize);

        for i in (0..self.length as usize).rev() {
            newout.push(self.get(i));
        }

        self.value = newout.value;
    }

    pub fn extend(&mut self, val: &Self) {
        for i in 0..(val.length as usize) {
            self.push(val.get(i));
        }
    }

    pub fn xor(&self, other: &Self) -> BinaryString {
        assert_eq!(
            self.length, other.length,
            "BinaryString instances must have the same length"
        );
        let mut value = Vec::new();
        for i in 0..self.value.len() {
            value.push(self.value[i] ^ other.value[i]);
        }
        BinaryString {
            length: self.length,
            value,
        }
    }

    pub fn and(&self, other: &Self) -> BinaryString {
        assert_eq!(
            self.length, other.length,
            "BinaryString instances must have the same length"
        );
        let mut value = Vec::new();
        for i in 0..self.value.len() {
            value.push(self.value[i] & other.value[i]);
        }
        BinaryString {
            length: self.length,
            value,
        }
    }

    pub fn _slice(&self, start: usize, end: usize) -> BinaryString {
        assert!(start <= end, "Start index cannot be greater than end index");
        assert!(
            end <= self.length as usize,
            "End index exceeds BinaryStringShare length"
        );

        let mut result = BinaryString::with_capacity(end - start);

        for i in start..end {
            result.push(self.get(i));
        }

        result
    }

    pub fn split(&self, index: usize) -> (Self, Self) {
        assert_eq!(self.length % 8, 0);
        assert_eq!(index % 8, 0);
        assert!(
            index <= self.length as usize,
            "End index exceeds BinaryString length"
        );

        let index_in_bytes = index / 8;
        let r1 = BinaryString {
            length: index as u64,
            value: self.value[0..index_in_bytes].to_vec(),
        };

        let r2 = BinaryString {
            length: self.length - index as u64,
            value: self.value[index_in_bytes..].to_vec(),
        };

        (r1, r2)
    }

    /// Use only for unverified_list
    pub fn append_bytes_with_padding(&mut self, other: &[u8]) {
        // pad length
        self.length = (self.length + 7) / 8 * 8;
        self.length += other.len() as u64;
        self.value.extend_from_slice(other);
    }
}
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct BinaryShare {
    pub value1: Binary,
    pub value2: Binary,
}

impl BinaryShare {
    /// ZERO BinaryShare
    pub const ZERO: BinaryShare = BinaryShare {
        value1: false,
        value2: false,
    };

    pub fn from_constant(value: Binary, party_index: usize) -> Self {
        match party_index {
            0 => BinaryShare {
                value1: value,
                value2: value,
            },
            1 => BinaryShare {
                value1: value,
                value2: false,
            },
            _ => BinaryShare::ZERO,
        }
    }

    pub fn not(&self) -> BinaryShare {
        BinaryShare {
            value1: self.value1,
            value2: self.value2 ^ true,
        }
    }

    pub fn xor(&self, other: &BinaryShare) -> BinaryShare {
        BinaryShare {
            value1: self.value1 ^ other.value1,
            value2: self.value2 ^ other.value2,
        }
    }

    pub fn and_bitwise(
        &self,
        other: &BinaryShare,
        randomness: &mut CommonRandomness,
    ) -> Binary {
        let alpha = randomness.random_zero_bool();
        (self.value1 & other.value1) ^ (self.value2 & other.value2) ^ alpha
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct BinaryStringShare {
    pub length: u64,
    pub value1: Vec<u8>,
    pub value2: Vec<u8>,
}

impl BinaryStringShare {
    pub fn new() -> Self {
        BinaryStringShare {
            length: 0,
            value1: Vec::new(),
            value2: Vec::new(),
        }
    }

    pub fn zero(length: usize) -> Self {
        let num_bytes = (length + 7) / 8;
        BinaryStringShare {
            length: length as u64,
            value1: vec![0u8; num_bytes],
            value2: vec![0u8; num_bytes],
        }
    }

    pub fn from_constant(c: &BinaryString, party_index: usize) -> Self {
        match party_index {
            0 => BinaryStringShare {
                length: c.length,
                value1: c.value.clone(),
                value2: c.value.clone(),
            },
            1 => BinaryStringShare {
                length: c.length,
                value1: c.value.clone(),
                value2: vec![0u8; c.value.len()],
            },
            _ => BinaryStringShare {
                length: c.length,
                value1: vec![0u8; c.value.len()],
                value2: vec![0u8; c.value.len()],
            },
        }
    }

    pub fn from_choice(c: &BinaryShare, size: usize) -> Self {
        let v1 = c.value1;
        let v2 = c.value2;
        let mut res = BinaryStringShare::with_capacity(size);
        for _ in 0..size {
            res.push(v1, v2)
        }
        res
    }

    pub fn length_in_bytes(&self) -> usize {
        if (self.length % 8) == 0 {
            (self.length / 8) as usize
        } else {
            (self.length / 8) as usize + 1
        }
    }

    pub fn get_external_size(&self) -> usize {
        mem::size_of::<u64>() + self.length_in_bytes() * 2
    }

    pub fn with_capacity(size: usize) -> Self {
        let num_bytes = (size + 7) / 8;
        BinaryStringShare {
            length: 0_u64,
            value1: Vec::with_capacity(num_bytes),
            value2: Vec::with_capacity(num_bytes),
        }
    }

    pub fn get(&self, index: usize) -> (bool, bool) {
        let bit1 = self.value1.extract_bit(index);
        let bit2 = self.value2.extract_bit(index);
        (bit1, bit2)
    }

    pub fn get_binary_share(&self, index: usize) -> BinaryShare {
        let bit1 = self.value1.extract_bit(index);
        let bit2 = self.value2.extract_bit(index);
        BinaryShare {
            value1: bit1,
            value2: bit2,
        }
    }

    pub fn set(&mut self, index: usize, value1: bool, value2: bool) {
        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;

        assert!(
            byte_idx < self.value1.len(),
            "No value assigned to the index yet!! {} {}",
            byte_idx,
            self.value1.len()
        );

        let mask = !(1 << bit_idx);

        self.value1[byte_idx] &= mask;
        self.value1[byte_idx] |= (value1 as u8) << bit_idx;

        self.value2[byte_idx] &= mask;
        self.value2[byte_idx] |= (value2 as u8) << bit_idx;
    }

    pub fn set_binary_share(&mut self, index: usize, share: &BinaryShare) {
        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;

        assert!(
            byte_idx < self.value1.len(),
            "No value assigned to the index yet!! {} {}",
            byte_idx,
            self.value1.len()
        );

        let mask = !(1 << bit_idx);

        self.value1[byte_idx] &= mask;
        self.value1[byte_idx] |= (share.value1 as u8) << bit_idx;

        self.value2[byte_idx] &= mask;
        self.value2[byte_idx] |= (share.value2 as u8) << bit_idx;
    }

    pub fn push(&mut self, value1: bool, value2: bool) {
        let index = self.length as usize;

        if index >= self.value1.len() * 8 {
            self.value1.push(0);
            self.value2.push(0);
        }

        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;
        self.value1[byte_idx] |= (value1 as u8) << bit_idx;
        self.value2[byte_idx] |= (value2 as u8) << bit_idx;

        self.length += 1;
    }

    pub fn push_binary_share(&mut self, share: BinaryShare) {
        let index = self.length as usize;

        if index >= self.value1.len() * 8 {
            self.value1.push(0);
            self.value2.push(0);
        }

        let byte_idx = index >> 3;
        let bit_idx = index & 0x7;
        self.value1[byte_idx] |= (share.value1 as u8) << bit_idx;
        self.value2[byte_idx] |= (share.value2 as u8) << bit_idx;

        self.length += 1;
    }

    pub fn reverse(&mut self) {
        let mut newout = Self::with_capacity(self.length as usize);

        for i in (0..self.length as usize).rev() {
            newout.push_binary_share(self.get_binary_share(i));
        }

        self.value1 = newout.value1;
        self.value2 = newout.value2;
    }

    pub fn extend(&mut self, val: &Self) {
        for i in 0..(val.length as usize) {
            let tup = val.get(i);
            self.push(tup.0, tup.1);
        }
    }

    pub fn not(&self) -> Self {
        let mut value2 = self.value2.clone();
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.value2.len() {
            value2[i] ^= 0xFF;
        }
        Self {
            length: self.length,
            value1: self.value1.clone(),
            value2,
        }
    }

    pub fn xor(&self, other: &Self) -> BinaryStringShare {
        assert_eq!(
            self.length, other.length,
            "BinaryStringShare instances must have the same length"
        );
        let mut value1 = Vec::new();
        let mut value2 = Vec::new();

        for i in 0..self.value1.len() {
            value1.push(self.value1[i] ^ other.value1[i]);
            value2.push(self.value2[i] ^ other.value2[i]);
        }
        BinaryStringShare {
            length: self.length,
            value1,
            value2,
        }
    }

    pub fn xor_scalar(&self, scalar: &BinaryString) -> BinaryStringShare {
        assert_eq!(
            self.length, scalar.length,
            "BinaryStringShare and BinaryString instances must have the same length"
        );
        let mut value2 = Vec::new();

        for i in 0..self.value2.len() {
            value2.push(self.value2[i] ^ scalar.value[i]);
        }
        BinaryStringShare {
            length: self.length,
            value1: self.value1.clone(),
            value2,
        }
    }

    pub fn and_scalar(&self, scalar: &BinaryString) -> BinaryStringShare {
        assert_eq!(
            self.length, scalar.length,
            "BinaryStringShare and BinaryString instances must have the same length"
        );
        let mut value1 = Vec::new();
        let mut value2 = Vec::new();

        for i in 0..self.value2.len() {
            value1.push(self.value1[i] & scalar.value[i]);
            value2.push(self.value2[i] & scalar.value[i]);
        }
        BinaryStringShare {
            length: self.length,
            value1,
            value2,
        }
    }

    pub fn and_bitwise(
        &self,
        other: &Self,
        randomness: &mut CommonRandomness,
    ) -> BinaryString {
        assert_eq!(self.length, other.length);
        let n = self.length as usize;

        let mut value = Vec::new();
        for _ in 0..self.length_in_bytes() {
            value.push(randomness.random_zero_byte());
        }
        let alpha = BinaryString {
            length: n as u64,
            value,
        };

        let mut res = BinaryString::new_with_zeros(n);
        for i in 0..self.length_in_bytes() {
            res.value[i] = (self.value1[i] & other.value1[i])
                ^ (self.value2[i] & other.value2[i])
                ^ alpha.value[i];
        }
        res
    }

    pub fn _slice(&self, start: usize, end: usize) -> BinaryStringShare {
        assert!(start <= end, "Start index cannot be greater than end index");
        assert!(
            end <= self.length as usize,
            "End index exceeds BinaryStringShare length"
        );

        let mut result = BinaryStringShare::with_capacity(end - start);

        for i in start..end {
            let (bit1, bit2) = self.get(i);
            result.push(bit1, bit2);
        }

        result
    }

    pub fn append(&mut self, other: &Self) {
        assert_eq!(self.length % 8, 0);
        assert_eq!(other.length % 8, 0);
        self.length += other.length;
        self.value1.extend_from_slice(&other.value1);
        self.value2.extend_from_slice(&other.value2);
    }

    pub fn split(&self, index: usize) -> (Self, Self) {
        assert_eq!(self.length % 8, 0);
        assert_eq!(index % 8, 0);
        assert!(
            index <= self.length as usize,
            "End index exceeds BinaryStringShare length"
        );

        let index_in_bytes = index / 8;
        let r1 = BinaryStringShare {
            length: index as u64,
            value1: self.value1[0..index_in_bytes].to_vec(),
            value2: self.value2[0..index_in_bytes].to_vec(),
        };

        let r2 = BinaryStringShare {
            length: self.length - index as u64,
            value1: self.value1[index_in_bytes..].to_vec(),
            value2: self.value2[index_in_bytes..].to_vec(),
        };

        (r1, r2)
    }

    /// Use only for verify mult triples
    pub fn append_with_padding(&mut self, other: &Self) {
        // pad length
        self.length = (self.length + 7) / 8 * 8;
        self.length += (other.value1.len() * 8) as u64;
        self.value1.extend_from_slice(&other.value1);
        self.value2.extend_from_slice(&other.value2);
    }

    /// Use only for verify mult triples
    pub fn append_arith_with_padding(
        &mut self,
        other: &BinaryArithmeticShare,
    ) {
        // pad length
        self.length = (self.length + 7) / 8 * 8;
        self.length += (other.value1.len() * 8) as u64;
        self.value1.extend_from_slice(&other.value1);
        self.value2.extend_from_slice(&other.value2);
    }
}
#[derive(Clone, Debug)]
pub struct CommonRandomness {
    f1: ChaCha20Rng,
    f2: ChaCha20Rng,
}

impl CommonRandomness {
    /// New CommonRandomness
    pub fn new(key_prev: [u8; 32], key_next: [u8; 32]) -> Self {
        CommonRandomness {
            f1: ChaCha20Rng::from_seed(key_prev),
            f2: ChaCha20Rng::from_seed(key_next),
        }
    }

    /// Implementation of the Protocol 2.3.2. RandomZero()
    pub fn random_zero_bool(&mut self) -> bool {
        let rb: bool = self.f2.r#gen();
        let ra: bool = self.f1.r#gen();
        rb ^ ra
    }

    /// Implementation of the Protocol 2.3.3. RandomBit()
    pub fn random_bit(&mut self) -> [bool; 2] {
        let rb: bool = self.f2.r#gen();
        let ra: bool = self.f1.r#gen();
        [ra ^ rb, rb]
    }

    /// RandomZeroByte()
    pub fn random_zero_byte(&mut self) -> u8 {
        let rb: u8 = self.f2.r#gen();
        let ra: u8 = self.f1.r#gen();
        rb ^ ra
    }

    /// RandomByte()
    pub fn random_byte_share(&mut self) -> [u8; 2] {
        let rb: u8 = self.f2.r#gen();
        let ra: u8 = self.f1.r#gen();
        [ra ^ rb, rb]
    }

    /// Returns (random_prev: [u8; 8], random_next: [u8; 8])
    pub fn random_8_bytes(&mut self) -> ([u8; 8], [u8; 8]) {
        let ra: [u8; 8] = self.f1.r#gen();
        let rb: [u8; 8] = self.f2.r#gen();
        (ra, rb)
    }

    /// Returns (random_prev: [u8; 32], random_next: [u8; 32])
    pub fn random_32_bytes(&mut self) -> ([u8; 32], [u8; 32]) {
        let ra: [u8; 32] = self.f1.r#gen();
        let rb: [u8; 32] = self.f2.r#gen();
        (ra, rb)
    }

    pub fn random_binary_string_share(
        &mut self,
        l: usize,
    ) -> BinaryStringShare {
        let size_in_bytes = (l + 7) / 8;
        let mut value1 = Vec::with_capacity(size_in_bytes);
        let mut value2 = Vec::with_capacity(size_in_bytes);
        for _ in 0..size_in_bytes {
            let [v1, v2] = self.random_byte_share();
            value1.push(v1);
            value2.push(v2);
        }
        BinaryStringShare {
            length: l as u64,
            value1,
            value2,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MultTripleStorage {
    pub a: BinaryStringShare,
    pub b: BinaryStringShare,
    pub c: BinaryStringShare,
}

impl MultTripleStorage {
    pub fn new() -> Self {
        MultTripleStorage {
            a: BinaryStringShare::new(),
            b: BinaryStringShare::new(),
            c: BinaryStringShare::new(),
        }
    }

    pub fn push(&mut self, a: BinaryShare, b: BinaryShare) {
        self.a.push_binary_share(a);
        self.b.push_binary_share(b);
    }

    pub fn insert_c(&mut self, c: BinaryShare) {
        self.c.push_binary_share(c);
    }

    pub fn push_a_b_binary_string_share(
        &mut self,
        a: &BinaryStringShare,
        b: &BinaryStringShare,
    ) {
        self.a.append_with_padding(a);
        self.b.append_with_padding(b);
    }

    pub fn insert_c_binary_string_share(&mut self, c: &BinaryStringShare) {
        self.c.append_with_padding(c);
    }

    pub fn push_a_b_binary_arith_shares(
        &mut self,
        a: &BinaryArithmeticShare,
        b: &BinaryArithmeticShare,
    ) {
        self.a.append_arith_with_padding(a);
        self.b.append_arith_with_padding(b);
    }

    pub fn insert_c_binary_arith_share(&mut self, c: &BinaryArithmeticShare) {
        self.c.append_arith_with_padding(c);
    }

    pub fn len(&self) -> usize {
        self.a.length as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug)]
pub struct ServerState {
    pub common_randomness: CommonRandomness,
    pub and_triples: MultTripleStorage,
    pub unverified_list: BinaryString,
    pub ver: (BinaryStringShare, BinaryStringShare, BinaryStringShare),
    pub rep: (BinaryStringShare, BinaryStringShare, BinaryStringShare),
}

impl ServerState {
    pub fn new(common_randomness: CommonRandomness) -> Self {
        ServerState {
            common_randomness,
            and_triples: MultTripleStorage::new(),
            unverified_list: BinaryString::new(),
            ver: (
                BinaryStringShare::with_capacity(N),
                BinaryStringShare::with_capacity(N),
                BinaryStringShare::with_capacity(N),
            ),
            rep: (
                BinaryStringShare::with_capacity(N),
                BinaryStringShare::with_capacity(N),
                BinaryStringShare::with_capacity(N),
            ),
        }
    }
}
pub fn binary_string_to_u8_vec(input: BinaryString) -> Vec<u8> {
    let mut vec_u8 = Vec::new();
    let mut byte = 0u8;

    for i in 0..(input.length as usize) {
        if input.get(i) {
            byte |= 1 << (7 - (i % 8));
        }
        if i % 8 == 7 {
            vec_u8.push(byte);
            byte = 0;
        }
    }
    if input.length % 8 != 0 {
        vec_u8.push(byte);
    }

    vec_u8
}
