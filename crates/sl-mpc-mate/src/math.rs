// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::Deref;

use elliptic_curve::ops::Reduce;

use elliptic_curve::{
    bigint::U256, group::GroupEncoding, rand_core::CryptoRngCore,
    CurveArithmetic, Field, Group, NonZeroScalar,
};

use crate::matrix::matrix_inverse;

/// A polynomial with coefficients of type `Scalar`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Polynomial<G>
where
    G: Group,
    G::Scalar: ser::Serializable,
{
    coeffs: Vec<G::Scalar>,
}

impl<G> Polynomial<G>
where
    G: Group,
    G::Scalar: ser::Serializable,
{
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<G::Scalar>) -> Self {
        Self { coeffs }
    }

    /// Create a new polynomial with random coefficients.
    pub fn random(rng: &mut impl CryptoRngCore, degree: usize) -> Self {
        Self {
            coeffs: (0..=degree)
                .map(|_| G::Scalar::random(&mut *rng))
                .collect(),
        }
    }

    /// Set constant to Scalar::ZERO
    pub fn reset_contant(&mut self) {
        self.coeffs[0] = G::Scalar::ZERO;
    }

    /// Set constant
    pub fn set_constant(&mut self, scalar: G::Scalar) {
        self.coeffs[0] = scalar;
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> &G::Scalar {
        &self.coeffs[0]
    }

    /// Commit to this polynomial by multiplying each coefficient by the generator.
    pub fn commit(&self) -> GroupPolynomial<G>
    where
        G: GroupEncoding,
    {
        GroupPolynomial::new(
            self.coeffs
                .iter()
                .map(|coeff| G::generator() * coeff)
                .collect(),
        )
    }

    /// Computes the n_i derivative of a polynomial with coefficients u_i_k at the point x
    ///
    /// `n`: order of the derivative
    ///
    /// `x`: point at which to compute the derivative.
    /// Arithmetic is done modulo the curve order
    pub fn derivative_at(&self, n: usize, x: &G::Scalar) -> G::Scalar
    where
        G::Scalar: Reduce<U256>,
    {
        self.coeffs
            .iter()
            .enumerate()
            .skip(n)
            .map(|(i, coeff)| {
                // TODO build static table of factorials ??
                //      U256::wrapping_mul if const fn
                let num: U256 = factorial_range(i - n, i); //
                let scalar_num = G::Scalar::reduce(num);
                let result = x.pow_vartime([(i - n) as u64]);

                scalar_num * coeff * result
            })
            .sum()
    }
}

/// A polynomial with coefficients of type `ProjectivePoint`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    pub coeffs: Vec<G>,
}

impl<G> GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<G>) -> Self {
        Self { coeffs }
    }

    pub fn identity(size: usize) -> Self {
        Self {
            coeffs: vec![G::identity(); size],
        }
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> G {
        self.coeffs[0]
    }

    /// Add another polynomial's coefficients element wise to this one inplace.
    /// If the other polynomial has more coefficients than this one, the extra
    /// coefficients are ignored.
    pub fn add_mut(&mut self, other: &Self) {
        self.coeffs
            .iter_mut()
            .zip(&other.coeffs)
            .for_each(|(a, b)| {
                *a += b;
            });
    }

    /// Get the coeffs of the polynomial derivative
    pub fn derivative_coeffs(&self, n: usize) -> impl Iterator<Item = G> + '_
    where
        G: Group,
        G::Scalar: Reduce<U256>,
    {
        let (_, sub_v) = self.coeffs.split_at(n);

        sub_v.iter().enumerate().map(move |(position, u_i)| {
            *u_i * G::Scalar::reduce(factorial_range(position, position + n))
        })
    }

    pub fn points(&self) -> impl Iterator<Item = &'_ G> {
        self.coeffs.iter()
    }

    pub fn get(&self, idx: usize) -> Option<&G> {
        self.coeffs.get(idx)
    }
}

impl<G> Deref for Polynomial<G>
where
    G: Group,
    G::Scalar: ser::Serializable,
{
    type Target = [G::Scalar];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

/// Computes the factorial of a number, n <= 57 (the largest factorial that fits in 256 bits)
/// This is okay for our purposes because we expect threshold values to be less than 57
/// (i.e. we don't expect to have more than 57 participants)
pub fn factorial(n: usize) -> U256 {
    if n > 57 {
        panic!("Factorial of {} is too large to fit in 256 bits", n);
    }

    (1..=n).fold(U256::from(1_u64), |acc, x| {
        acc.wrapping_mul(&U256::from(x as u64))
    })
}

/// Computes the factorial of a range of numbers (start, end], where end <= 57
pub fn factorial_range(start: usize, end: usize) -> U256 {
    // TODO: Confirm max possible sizes for start and end
    if end > 57 {
        panic!("Factorial of {} is too large to fit in 256 bits", end);
    }

    (start + 1..=end).fold(U256::from(1_u64), |acc, x| {
        acc.wrapping_mul(&U256::from(x as u64))
    })
}

/// Feldman verification
pub fn feldman_verify<C: CurveArithmetic>(
    u_i_k: impl Iterator<Item = C::ProjectivePoint>,
    x_i: &NonZeroScalar<C>,
    f_i_value: &C::Scalar,
    g: &C::ProjectivePoint,
) -> bool {
    let point: C::ProjectivePoint = u_i_k
        .enumerate()
        .map(|(i, coeff)| {
            // x_i^i mod p
            let val = x_i.pow([i as u64]);

            // x_i^i * coeff mod p
            coeff * val
        })
        .sum();

    if point.is_identity().into() {
        return false;
    }

    let expected_point = *g * f_i_value;

    point == expected_point
}

/// Get the multipliers for the coefficients of the polynomial,
/// given the x_i (point of evaluation),
/// `n_i` (order of derivative)
/// `n` (degree of polynomial - 1)
/// `p` prime order of field
pub fn polynomial_coeff_multipliers<G: CurveArithmetic>(
    x_i: &NonZeroScalar<G>,
    n_i: usize,
    n: usize,
) -> Vec<G::Scalar>
where
    G: CurveArithmetic<Uint = U256>,
{
    let mut v = vec![G::Scalar::ZERO; n];

    v.iter_mut().enumerate().skip(n_i).for_each(|(idx, vi)| {
        let num = G::Scalar::reduce(factorial_range(idx - n_i, idx));
        let exponent = [(idx - n_i) as u64];
        let result = x_i.pow_vartime(exponent);
        *vi = num * result;
    });

    v
}

/// Get the birkhoff coefficients
pub fn birkhoff_coeffs<G>(
    params: &[(NonZeroScalar<G>, usize)],
) -> Vec<G::Scalar>
where
    G: CurveArithmetic<Uint = U256>,
{
    let n = params.len();

    let matrix: Vec<Vec<G::Scalar>> = params
        .iter()
        .map(|(x_i, n_i)| polynomial_coeff_multipliers(x_i, *n_i, n))
        .collect();

    let mut matrix_inv = matrix_inverse::<G>(matrix, n);

    matrix_inv.swap_remove(0)
}

#[cfg(not(feature = "serde"))]
mod ser {
    pub trait Serializable {}
    impl<T> Serializable for T {}
}

#[cfg(feature = "serde")]
mod ser {
    use elliptic_curve::group::{prime::PrimeCurveAffine, Curve};

    use super::*;

    pub trait Serializable:
        serde::Serialize + serde::de::DeserializeOwned
    {
    }

    impl<T: serde::Serialize + serde::de::DeserializeOwned> Serializable for T {}

    impl<G: CurveArithmetic> serde::Serialize for GroupPolynomial<G>
    where
        G: GroupEncoding,
        G::AffinePoint: Serializable,
    {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> core::result::Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            // Serialize as Vec<G::AffinePoint>
            self.coeffs
                .iter()
                .map(|p| p.to_affine())
                .collect::<Vec<_>>()
                .serialize(serializer)
        }
    }

    impl<'de, G> serde::Deserialize<'de> for GroupPolynomial<G>
    where
        G: CurveArithmetic,
        G: GroupEncoding,
        G::AffinePoint: PrimeCurveAffine<Curve = G> + Serializable,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            let coeffs = <Vec<G::AffinePoint>>::deserialize(deserializer)?
                .into_iter()
                .map(|a| a.to_curve())
                .collect::<Vec<_>>();

            Ok(Self { coeffs })
        }
    }
}
