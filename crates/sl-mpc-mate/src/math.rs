// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use elliptic_curve::{
    group::GroupEncoding, CurveArithmetic, Field, Group, NonZeroScalar,
    PrimeField,
};
use rand_core::CryptoRngCore;

use crate::matrix::matrix_inverse;

/// A polynomial with coefficients of type `Scalar`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(PartialEq, Eq)]
pub struct Polynomial<G>
where
    G: Group,
    G::Scalar: ser::Serializable,
{
    coeffs: Vec<G::Scalar>,
}

impl<G> Hash for Polynomial<G>
where
    G: Group,
    G::Scalar: Hash + ser::Serializable,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeffs.hash(state);
    }
}

#[cfg(test)]
impl<G> Debug for Polynomial<G>
where
    G: Group,
    G::Scalar: ser::Serializable,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entry(&format!("Polynomial length {}", self.coeffs.len()))
            .finish()
    }
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

    /// Set constant to Scalar::ZERO
    pub fn reset_constant(&mut self) {
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
    pub fn derivative_at(&self, n: usize, x: &G::Scalar) -> G::Scalar {
        self.coeffs
            .iter()
            .enumerate()
            .skip(n)
            .map(|(i, coeff)| {
                let scalar_num: G::Scalar = factorial_range(i - n, i);
                let result = x.pow_vartime([(i - n) as u64]);

                scalar_num * coeff * result
            })
            .sum()
    }

    /// Evaluate the polynomial at the given point.
    /// Arithmetic is done modulo the curve order
    /// # Arguments
    /// `x`: point at which to evaluate the polynomial.
    pub fn evaluate_at(&self, x: &G::Scalar) -> G::Scalar {
        self.coeffs
            .iter()
            .enumerate()
            .map(|(i, coeff)| {
                let result = x.pow_vartime([i as u64]);
                result * coeff
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

impl<G: Group + GroupEncoding> From<GroupPolynomial<G>> for Vec<G> {
    fn from(p: GroupPolynomial<G>) -> Vec<G> {
        p.coeffs
    }
}

impl<G> Deref for GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    type Target = [G];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

impl<G> DerefMut for GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.coeffs
    }
}

impl<G> AsRef<[G]> for GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    fn as_ref(&self) -> &[G] {
        &self.coeffs
    }
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
    pub fn add_mut<T>(&mut self, other: T)
    where
        T: AsRef<[G]>,
    {
        self.coeffs
            .iter_mut()
            .zip(other.as_ref())
            .for_each(|(a, b)| {
                *a += b;
            });
    }

    /// Get the coeffs of the polynomial derivative
    pub fn derivative_coeffs(&self, n: usize) -> impl Iterator<Item = G> + '_
    where
        G: Group,
    {
        self.coeffs[n..]
            .iter()
            .enumerate()
            .map(move |(position, &u_i)| {
                u_i * factorial_range::<G::Scalar>(position, position + n)
            })
    }

    pub fn points(&self) -> impl Iterator<Item = &'_ G> {
        self.coeffs.iter()
    }

    pub fn get(&self, idx: usize) -> Option<&G> {
        self.coeffs.get(idx)
    }

    pub fn evaluate_at(&self, x: &G::Scalar) -> G
    where
        G: Group,
    {
        let init = (G::identity(), G::Scalar::ONE);

        let (p, _) = self.coeffs.iter().fold(init, |(s, x_pow_i), &coeff| {
            (s + coeff * x_pow_i, x_pow_i * x)
        });

        p
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

/// Computes the factorial of a number.
pub fn factorial<S: PrimeField>(n: usize) -> S {
    factorial_range(0, n)
}

const fn small_factorial<const N: usize>() -> [u64; N] {
    let mut a = [1u64; N];

    let mut j = 1;

    while j < N {
        a[j] = j as u64 * a[j - 1];
        j += 1;
    }

    a
}

// FACT[20] == 20! and fits into u64
static FACT: [u64; 21] = small_factorial();

/// Computes the factorial of a range of numbers (start, end]
pub fn factorial_range<S: PrimeField>(start: usize, end: usize) -> S {
    debug_assert!(start <= end);

    if end < FACT.len() {
        return S::from(FACT[end] / FACT[start]);
    }

    (start + 1..=end).fold(S::ONE, |acc, x| acc * S::from(x as u64))
}

/// Feldman verification
pub fn feldman_verify<C: CurveArithmetic>(
    u_i_k: impl Iterator<Item = C::ProjectivePoint>,
    x_i: &NonZeroScalar<C>,
    f_i_value: &C::Scalar,
    g: &C::ProjectivePoint,
) -> bool {
    let x_i = x_i as &C::Scalar;
    let one = C::Scalar::ONE;
    let s = C::ProjectivePoint::identity();

    // sum( coeff_i * (x_i^i mod p) )
    let (point, _) = u_i_k
        .fold((s, one), |(sum, val), coeff| (sum + coeff * val, val * x_i));

    if point.is_identity().into() {
        return false;
    }

    let expected_point = *g * f_i_value;

    point == expected_point
}

pub fn polynomial_coeff_multipliers_iter<C>(
    x_i: &NonZeroScalar<C>,
    n_i: usize,
    n: usize,
) -> impl Iterator<Item = C::Scalar> + '_
where
    C: CurveArithmetic,
{
    (0..n).map(move |idx| {
        if idx < n_i {
            C::Scalar::ZERO
        } else {
            let num: C::Scalar = factorial_range(idx - n_i, idx);
            let exponent = [(idx - n_i) as u64];
            let result = x_i.pow_vartime(exponent);

            num * result
        }
    })
}

/// Get the multipliers for the coefficients of the polynomial,
/// given the `x_i` (point of evaluation),
/// `n_i` (order of derivative)
/// `n` (degree of polynomial - 1)
pub fn polynomial_coeff_multipliers<C>(
    x_i: &NonZeroScalar<C>,
    n_i: usize,
    n: usize,
) -> Vec<C::Scalar>
where
    C: CurveArithmetic,
{
    polynomial_coeff_multipliers_iter(x_i, n_i, n).collect()
}

/// Get the birkhoff coefficients
pub fn birkhoff_coeffs<C>(
    params: &[(NonZeroScalar<C>, usize)],
) -> Vec<C::Scalar>
where
    C: CurveArithmetic,
{
    let n = params.len();

    let matrix: Vec<Vec<C::Scalar>> = params
        .iter()
        .map(|(x_i, n_i)| polynomial_coeff_multipliers(x_i, *n_i, n))
        .collect();
    let inv = matrix_inverse::<C>(matrix, n);
    inv.unwrap().swap_remove(0)
}

#[cfg(not(feature = "serde"))]
mod ser {
    pub trait Serializable {}
    impl<T> Serializable for T {}
}

#[cfg(feature = "serde")]
mod ser {
    use std::mem::size_of;

    use super::*;

    pub trait Serializable:
        serde::Serialize + serde::de::DeserializeOwned
    {
    }

    impl<T: serde::Serialize + serde::de::DeserializeOwned> Serializable for T {}

    impl<G> serde::Serialize for GroupPolynomial<G>
    where
        G: Group + GroupEncoding,
    {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> core::result::Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            use serde::ser::SerializeSeq;

            let mut seq =
                serializer.serialize_seq(Some(self.coeffs.len()))?;
            for coeff in &self.coeffs {
                seq.serialize_element(&coeff.to_bytes().as_ref())?;
            }
            seq.end()
        }
    }

    impl<'de, G> serde::Deserialize<'de> for GroupPolynomial<G>
    where
        G: Group + GroupEncoding,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            let data = <Vec<Vec<u8>>>::deserialize(deserializer)?;
            let mut coeffs = Vec::with_capacity(data.len());

            for coeff_data in &data {
                if coeff_data.len() != size_of::<G::Repr>() {
                    return Err(serde::de::Error::custom(
                        "Invalid group element",
                    ));
                }
                let mut repr = G::Repr::default();
                repr.as_mut().copy_from_slice(coeff_data);
                let opt = G::from_bytes(&repr);

                let point = if opt.is_some().into() {
                    opt.unwrap()
                } else {
                    return Err(serde::de::Error::custom(
                        "Invalid group element",
                    ));
                };
                coeffs.push(point);
            }

            Ok(Self { coeffs })
        }
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::{scalar::FromUintUnchecked, Curve};
    use k256::{ProjectivePoint, Scalar, Secp256k1};

    use super::*;

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use k256::ProjectivePoint;

        let mut rng = rand::thread_rng();
        let poly1 = Polynomial::<ProjectivePoint>::random(&mut rng, 5);
        let bytes = bincode::serialize(&poly1).unwrap();
        let poly2: Polynomial<ProjectivePoint> =
            bincode::deserialize(&bytes).unwrap();

        let g_poly1 = poly1.commit();

        let bytes = bincode::serialize(&g_poly1).unwrap();

        let g_poly2: GroupPolynomial<ProjectivePoint> =
            bincode::deserialize(&bytes).unwrap();

        assert_eq!(poly1, poly2);
        assert_eq!(g_poly1, g_poly2);
    }

    #[test]
    fn fact() {
        // static FACT: [u64; 21] = small_factorial();

        assert_eq!(FACT[19], 121645100408832000);
        assert_eq!(FACT[20], 2432902008176640000); // biggest number fitting into u64
    }

    #[test]
    fn test_derivative_large() {
        // order of the curve
        let order = Secp256k1::ORDER;
        // f(x) = 1 + 2x + (p-1)x^2
        // p is the curve order
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from_uint_unchecked(order.wrapping_sub(&1u64.into())),
        ];

        // f'(x) = 2 + 2(p-1)x
        // f'(2) = (4p-2) mod p => p - 2
        let poly = Polynomial::<ProjectivePoint>::new(u_i_k);
        let n = 1;

        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(
            result,
            Scalar::from_uint_unchecked(order.wrapping_sub(&2u64.into()))
        );
    }

    #[test]
    fn test_derivative_normal() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(4_u64),
        ];

        let poly = Polynomial::<ProjectivePoint>::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        // f''(2) = 6 + 24(2) = 54
        let result = poly.derivative_at(n, &Scalar::from(2_u64));

        assert_eq!(result, Scalar::from(54_u64));
    }

    #[test]
    fn test_derivative_coeffs() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let g = ProjectivePoint::GENERATOR;
        let u_i_k = vec![
            (g * Scalar::from(1_u64)),
            (g * Scalar::from(2_u64)),
            (g * Scalar::from(3_u64)),
            (g * Scalar::from(4_u64)),
        ];

        let poly = GroupPolynomial::<ProjectivePoint>::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        let coeffs = poly.derivative_coeffs(n).collect::<Vec<_>>();

        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], g * Scalar::from(6_u64));
        assert_eq!(coeffs[1], g * Scalar::from(24_u64));

        // f'(x) = 2 + 6x + 12x^2
        let coeffs = poly.derivative_coeffs(1).collect::<Vec<_>>();

        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], g * Scalar::from(2_u64));
        assert_eq!(coeffs[1], g * Scalar::from(6_u64));
        assert_eq!(coeffs[2], g * Scalar::from(12_u64));
    }
}
