use std::ops::Deref;

// use k256::elliptic_curve::CurveArithmetic;

use elliptic_curve::{
    bigint::U256, group::Curve, rand_core::CryptoRngCore, CurveArithmetic, Field, Group,
    NonZeroScalar, ProjectivePoint, Scalar,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{matrix::matrix_inverse, traits::ToScalar};

/// A polynomial with coefficients of type `Scalar`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Polynomial<C: CurveArithmetic>
where
    C::Scalar: Serialize + DeserializeOwned,
{
    /// The coefficients of the polynomial.
    pub coeffs: Vec<C::Scalar>,
}

impl<C: CurveArithmetic> Polynomial<C>
where
    C::Scalar: Serialize + DeserializeOwned,
{
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<C::Scalar>) -> Self {
        Self { coeffs }
    }

    /// Create a new polynomial with random coefficients.
    pub fn random(rng: &mut impl CryptoRngCore, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        for _ in 0..=degree {
            // TODO: Is this random constant time?
            coeffs.push(C::Scalar::random(&mut *rng));
        }
        Self { coeffs }
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> C::Scalar {
        self.coeffs[0]
    }

    /// Commit to this polynomial by multiplying each coefficient by the generator.
    pub fn commit(&self) -> GroupPolynomial<C>
    where
        C::AffinePoint: Serialize + DeserializeOwned,
        C::ProjectivePoint: From<C::AffinePoint>,
    {
        let mut points = Vec::with_capacity(self.coeffs.len());
        for coeff in &self.coeffs {
            points.push(C::ProjectivePoint::generator() * coeff);
        }
        GroupPolynomial::new(points)
    }
    /// Computes the n_i derivative of a polynomial with coefficients u_i_k at the point x
    ///
    /// `n`: order of the derivative
    ///
    /// `x`: point at which to compute the derivative.
    /// Arithmetic is done modulo the curve order
    pub fn derivative_at(&self, n: usize, x: &C::Scalar) -> C::Scalar
    where
        C: CurveArithmetic<Uint = U256>,
    {
        (n..self.coeffs.len())
            .map(|i| {
                let num: U256 = factorial_range(i - n, i);
                let scalar_num: C::Scalar = num.to_scalar::<C>();
                let coeff = self.coeffs[i];
                let result = x.pow_vartime([(i - n) as u64]);
                scalar_num * coeff * result
            })
            .fold(C::Scalar::ZERO, |acc, x| acc + x)
    }
}

/// A polynomial with coefficients of type `ProjectivePoint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupPolynomial<C: CurveArithmetic>
where
    C::AffinePoint: Serialize + DeserializeOwned,
    C::ProjectivePoint: From<C::AffinePoint>,
{
    /// The coefficients of the polynomial.
    pub coeffs: Vec<C::ProjectivePoint>,
}

impl<C: CurveArithmetic> Serialize for GroupPolynomial<C>
where
    C::AffinePoint: Serialize + DeserializeOwned,
    C::ProjectivePoint: From<C::AffinePoint>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C::AffinePoint: Serialize + Clone,
    {
        let affine: Vec<C::AffinePoint> = self.iter().map(|p| p.to_affine()).collect();
        affine.serialize(serializer)
    }
}

impl<'de, C: CurveArithmetic> Deserialize<'de> for GroupPolynomial<C>
where
    C::AffinePoint: Serialize + DeserializeOwned,
    C::ProjectivePoint: From<C::AffinePoint>,
{
    fn deserialize<D>(deserializer: D) -> Result<GroupPolynomial<C>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let affine: Vec<C::AffinePoint> = Vec::deserialize(deserializer)?;
        let coeffs: Vec<C::ProjectivePoint> = affine.iter().map(|p| (*p).into()).collect();
        Ok(GroupPolynomial::new(coeffs))
    }
}

impl<C: CurveArithmetic> GroupPolynomial<C>
where
    C::AffinePoint: Serialize + DeserializeOwned,
    C::ProjectivePoint: From<C::AffinePoint>,
{
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<C::ProjectivePoint>) -> Self {
        Self { coeffs }
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> C::ProjectivePoint {
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
    pub fn derivative_coeffs(&self, n: usize) -> Vec<C::ProjectivePoint>
    where
        C: CurveArithmetic<Uint = U256>,
    {
        let (_, sub_v) = self.coeffs.split_at(n);

        sub_v
            .iter()
            .enumerate()
            .map(|(position, u_i)| {
                let num: C::Scalar = factorial_range(position, position + n).to_scalar::<C>();
                *u_i * num
            })
            .collect()
    }
}

impl<C: CurveArithmetic> Deref for Polynomial<C>
where
    C::Scalar: Serialize + DeserializeOwned,
{
    type Target = [C::Scalar];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

impl<C: CurveArithmetic> Deref for GroupPolynomial<C>
where
    C::AffinePoint: Serialize + DeserializeOwned,
    C::ProjectivePoint: From<C::AffinePoint>,
{
    type Target = [C::ProjectivePoint];

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
    //TODO: Confirm max possible sizes for start and end
    if end > 57 {
        panic!("Factorial of {} is too large to fit in 256 bits", end);
    }

    (start + 1..=end).fold(U256::from(1_u64), |acc, x| {
        acc.wrapping_mul(&U256::from(x as u64))
    })
}

/// Feldman verification
pub fn feldman_verify<C: CurveArithmetic>(
    u_i_k: &[ProjectivePoint<C>],
    x_i: &NonZeroScalar<C>,
    f_i_value: &Scalar<C>,
    g: &ProjectivePoint<C>,
) -> Option<bool> {
    if u_i_k.is_empty() {
        return None;
    }

    let mut point = ProjectivePoint::<C>::identity();

    for (i, coeff) in u_i_k.iter().enumerate() {
        // x_i^i mod p
        let val = x_i.pow([i as u64]);

        // x_i^i * coeff mod p
        point += *coeff * val;
    }

    let expected_point = *g * f_i_value;

    Some(point == expected_point)
}

/// Get the multipliers for the coefficients of the polynomial,
/// given the x_i (point of evaluation),
/// `n_i` (order of derivative)
/// `n` (degree of polynomial - 1)
/// `p` prime order of field
pub fn polynomial_coeff_multipliers<C: CurveArithmetic>(
    x_i: &NonZeroScalar<C>,
    n_i: usize,
    n: usize,
) -> Vec<C::Scalar>
where
    C: CurveArithmetic<Uint = U256>,
{
    let mut v = vec![C::Scalar::ZERO; n];
    v.iter_mut()
        .enumerate()
        .take(n)
        .skip(n_i)
        .for_each(|(idx, vi)| {
            let num: C::Scalar = factorial_range(idx - n_i, idx).to_scalar::<C>();
            let exponent = [(idx - n_i) as u64];
            let result = x_i.pow_vartime(exponent);
            *vi = num * result;
        });

    v
}

/// Get the birkhoff coefficients
pub fn birkhoff_coeffs<C: CurveArithmetic>(params: &[(NonZeroScalar<C>, usize)]) -> Vec<C::Scalar>
where
    Vec<Vec<C::Scalar>>:
        std::iter::FromIterator<std::vec::Vec<<C as elliptic_curve::CurveArithmetic>::Scalar>>,
    C: CurveArithmetic<Uint = U256>,
{
    let n = params.len();

    let matrix: Vec<Vec<C::Scalar>> = params
        .iter()
        .map(|(x_i, n_i)| polynomial_coeff_multipliers(x_i, *n_i, n))
        .collect();

    let matrix_inv = matrix_inverse::<C>(matrix, n);

    matrix_inv[0].clone()
}
