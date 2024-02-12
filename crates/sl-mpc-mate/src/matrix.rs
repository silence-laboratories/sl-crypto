// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{MulAssign, Sub};

use elliptic_curve::{CurveArithmetic, Field};
use rayon::prelude::*;

// Compute minor of a matrix.
fn matrix_minor<C: CurveArithmetic>(
    matrix: &[Vec<C::Scalar>],
    i: usize,
    j: usize,
) -> Vec<Vec<C::Scalar>> {
    matrix
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != i)
        .map(|(_, row)| {
            row.iter()
                .enumerate()
                .filter(|(idx, _)| *idx != j)
                .map(|(_, x)| *x)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

// Transpose a matrix
fn transpose<C: CurveArithmetic>(
    mut v: Vec<Vec<C::Scalar>>,
) -> Vec<Vec<C::Scalar>> {
    let len = v[0].len();

    for n in 0..len - 1 {
        for m in n + 1..len {
            let nm = &mut v[n][m] as *mut C::Scalar;
            let mn = &mut v[m][n] as *mut C::Scalar;

            // SAFETY: n != m, so nm and mn always points to separate locations
            unsafe { core::ptr::swap_nonoverlapping(nm, mn, 1) }
        }
    }

    v
}

// Get the matrix determinant
fn mod_bareiss_determinant<C: CurveArithmetic>(
    mut matrix: Vec<Vec<C::Scalar>>,
    rows: usize,
) -> Result<C::Scalar, &'static str> {
    if matrix.len() != rows || matrix[0].len() != rows {
        return Err("Not a square matrix");
    }

    let mut sign = C::Scalar::from(1_u64);

    for i in 0..(rows - 1) {
        // Swap rows if the diagonal element is zero
        if matrix[i][i].is_zero().into() {
            for m in (i + 1)..rows {
                if !bool::from(matrix[m][i].is_zero()) {
                    matrix.swap(i, m);
                    sign = -sign;
                    break;
                }
            }
        }

        // If the diagonal element is still zero then determinant is zero.
        // proof: https://math.stackexchange.com/questions/2799578/pivoting-in-the-bareiss-algorithm
        if matrix[i][i].is_zero().into() {
            return Ok(C::Scalar::ZERO);
        }

        for j in (i + 1)..rows {
            for k in (i + 1)..rows {
                let jki = matrix[j][k] * matrix[i][i];
                let jik = matrix[j][i] * matrix[i][k];
                matrix[j][k] = jki - jik;
                if i != 0 {
                    let inv = matrix[i - 1][i - 1].invert();
                    if inv.is_none().into() {
                        return Err("Modular inverse does not exist while computing determinant, Given ranks setup might not be valid");
                    }
                    matrix[j][k] *= inv.unwrap()
                }
            }
        }
    }

    Ok(matrix[rows - 1][rows - 1] * sign)
}

/// Calculates the modular inverse of a matrix, generic over curves
// TODO: Use result or option instead of panicking
pub fn matrix_inverse<C: CurveArithmetic>(
    matrix: Vec<Vec<C::Scalar>>,
    rows: usize,
) -> Vec<Vec<C::Scalar>> {
    let determinant = mod_bareiss_determinant::<C>(matrix.clone(), rows)
        .expect("Error while finding det");
    let determinant_inv = determinant.invert().unwrap();
    let n = matrix.len();

    let minus_one = C::Scalar::ZERO.sub(&C::Scalar::ONE);
    if n == 2 {
        let a11 = matrix[1][1] * determinant_inv;
        let a12 = minus_one * matrix[0][1] * determinant_inv;
        let a21 = minus_one * matrix[1][0] * determinant_inv;
        let a22 = matrix[0][0] * determinant_inv;

        return vec![vec![a11, a12], vec![a21, a22]];
    }

    let cofactors = matrix
        .par_iter()
        .enumerate()
        .map(|(r, row)| {
            row.par_iter()
                .enumerate()
                .map(|(c, _)| {
                    let minor = matrix_minor::<C>(&matrix, r, c);
                    let minor_rows = minor.len();
                    let exponentiation = minus_one.pow([((r + c) as u64)]);
                    let value: C::Scalar = exponentiation
                        * mod_bareiss_determinant::<C>(minor, minor_rows)
                            .expect("Error while finding det for minor, Given ranks setup might not be valid");
                    value
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut transposed = transpose::<C>(cofactors);

    for row in &mut transposed {
        for x in row {
            x.mul_assign(determinant_inv);
        }
    }

    transposed
}

#[cfg(test)]
mod tests {
    use super::*;

    use elliptic_curve::{bigint::U256, ops::Reduce};
    use k256::Secp256k1;

    type Scalar = elliptic_curve::Scalar<Secp256k1>;

    #[test]
    fn test_minor() {
        let matrix = vec![
            vec![Scalar::from(1_u64), Scalar::from(2_u64)],
            vec![Scalar::from(3_u64), Scalar::from(4_u64)],
        ];
        let minor = matrix_minor::<Secp256k1>(&matrix, 0, 0);
        assert_eq!(minor, vec![vec![Scalar::from(4_u64)]]);
    }

    #[test]
    fn test_determinant() {
        let matrix = vec![
            vec![Scalar::from(1_u64), Scalar::from(2_u64)],
            vec![Scalar::from(3_u64), Scalar::from(4_u64)],
        ];
        let minor = mod_bareiss_determinant::<Secp256k1>(matrix, 2).unwrap();
        assert_eq!(minor, Scalar::ZERO.sub(&Scalar::from(2_u64)));
    }

    #[test]
    fn test_transpose() {
        let matrix = vec![
            vec![Scalar::from(1_u64), Scalar::from(2_u64)],
            vec![Scalar::from(3_u64), Scalar::from(4_u64)],
        ];
        let transposed = transpose::<Secp256k1>(matrix);

        assert_eq!(
            transposed,
            vec![
                vec![Scalar::from(1_u64), Scalar::from(3_u64)],
                vec![Scalar::from(2_u64), Scalar::from(4_u64)],
            ]
        );

        assert_eq!(
            transpose::<Secp256k1>(vec![
                vec![
                    Scalar::from(1_u64),
                    Scalar::from(2_u64),
                    Scalar::from(3_u64)
                ],
                vec![
                    Scalar::from(4_u64),
                    Scalar::from(5_u64),
                    Scalar::from(6_u64)
                ],
                vec![
                    Scalar::from(7_u64),
                    Scalar::from(8_u64),
                    Scalar::from(9_u64)
                ],
            ]),
            vec![
                vec![
                    Scalar::from(1_u64),
                    Scalar::from(4_u64),
                    Scalar::from(7_u64)
                ],
                vec![
                    Scalar::from(2_u64),
                    Scalar::from(5_u64),
                    Scalar::from(8_u64)
                ],
                vec![
                    Scalar::from(3_u64),
                    Scalar::from(6_u64),
                    Scalar::from(9_u64)
                ],
            ]
        );
    }

    #[test]
    fn test_inverse() {
        let matrix = vec![
            vec![
                Scalar::from(1_u64),
                Scalar::from(2_u64),
                Scalar::from(3_u64),
            ],
            vec![
                Scalar::from(4_u64),
                Scalar::from(5_u64),
                Scalar::from(6_u64),
            ],
            vec![
                Scalar::from(7_u64),
                Scalar::from(8_u64),
                Scalar::from(10_u64),
            ],
        ];

        fn reduce<C: CurveArithmetic>(uint: C::Uint) -> C::Scalar {
            <C::Scalar as Reduce<C::Uint>>::reduce(uint)
        }

        let inverse = matrix_inverse::<Secp256k1>(matrix, 3);

        // Known correct value
        let expected: Vec<Vec<Scalar>> = vec![
            vec![
                reduce::<Secp256k1>(U256::from_be_hex(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9D1C9E899CA306AD27FE1945DE0242B80",
                )),
                reduce::<Secp256k1>(U256::from_be_hex(
                    "55555555555555555555555555555554E8E4F44CE51835693FF0CA2EF01215BF",
                )),
                Scalar::ONE,
            ],
            vec![
                reduce::<Secp256k1>(U256::from_be_hex(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9D1C9E899CA306AD27FE1945DE0242B80",
                )),
                reduce::<Secp256k1>(U256::from_be_hex(
                    "55555555555555555555555555555554E8E4F44CE51835693FF0CA2EF01215C4",
                )),
                reduce::<Secp256k1>(U256::from_be_hex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
                ))
            ],
            vec![
                Scalar::ONE,
                reduce::<Secp256k1>(U256::from_be_hex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
                )),
                Scalar::ONE,
            ],
        ];

        assert_eq!(expected, inverse)
    }
}
