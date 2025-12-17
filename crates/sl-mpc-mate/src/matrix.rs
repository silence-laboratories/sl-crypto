// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ops::{MulAssign, Sub};

use elliptic_curve::{CurveArithmetic, Field};
#[cfg(feature = "rayon")]
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
        // n < len-1 => n+1 < len
        let (up, down) = v.split_at_mut(n + 1);

        for m in n + 1..len {
            let nm = &mut up[n][m]; // == &mut v[n][m]
            let mn = &mut down[m - (n + 1)][n]; // == &mut v[m][n]

            core::mem::swap(nm, mn);
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
pub fn matrix_inverse<C: CurveArithmetic>(
    mut matrix: Vec<Vec<C::Scalar>>,
    rows: usize,
) -> Result<Vec<Vec<C::Scalar>>, &'static str> {
    let n = rows;
    if matrix.len() != n || matrix.iter().any(|row| row.len() != n) {
        return Err("Matrix must be square");
    }

    if n == 2 {
        let determinant = mod_bareiss_determinant::<C>(matrix.clone(), n)?;
        let determinant_inv = determinant.invert().expect("Matrix is singular");
        let minus_one = C::Scalar::ZERO.sub(&C::Scalar::ONE);
        let a11 = matrix[1][1] * determinant_inv;
        let a12 = minus_one * matrix[0][1] * determinant_inv;
        let a21 = minus_one * matrix[1][0] * determinant_inv;
        let a22 = matrix[0][0] * determinant_inv;
        return Ok(vec![vec![a11, a12], vec![a21, a22]]);
    }

    let mut inv = vec![vec![C::Scalar::ZERO; n]; n];
    for i in 0..n {
        inv[i][i] = C::Scalar::ONE;
    }

    for i in 0..n {
        let mut pivot = matrix[i][i];
        let mut pivot_row = i;
        for k in (i + 1)..n {
            if bool::from(matrix[k][i].is_zero()) {
                continue;
            }
            if bool::from(pivot.is_zero()) || matrix[k][i] > pivot {
                pivot = matrix[k][i];
                pivot_row = k;
            }
        }

        if bool::from(pivot.is_zero()) {
            return Err("Matrix is singular");
        }

        if pivot_row != i {
            matrix.swap(i, pivot_row);
            inv.swap(i, pivot_row);
        }

        let inv_pivot = pivot.invert().unwrap(); // Safe since pivot != 0
        for j in 0..n {
            matrix[i][j] *= inv_pivot;
            inv[i][j] *= inv_pivot;
        }

        for k in 0..n {
            if k != i {
                let factor = matrix[k][i];
                for j in 0..n {
                    let mij = matrix[i][j]; 
                    let inv_ij = inv[i][j]; 
                    matrix[k][j] -= mij * factor;
                    inv[k][j] -= inv_ij * factor;
                }
            }
        }
    }
    Ok(inv)
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

        assert_eq!(expected, inverse.unwrap())
    }
    

    #[test]
fn test_inverse_large_matrix() {
    use k256::{Scalar, Secp256k1};
    
    const N: usize = 100;

    // Generate a 100x100 diagonal matrix with random non-zero diagonal entries
    let mut rng = rand::thread_rng();
    let mut matrix = vec![vec![Scalar::ZERO; N]; N];
    for i in 0..N {

        for j in 0..N {
            // Random non-zero scalar for the diagonal
            let mut scalar = Scalar::random(&mut rng);
            while bool::from(scalar.is_zero()) {
                scalar = Scalar::random(&mut rng); // Ensure non-zero
            }
            matrix[i][j] = scalar;
        }

    }

    // Compute the inverse using the matrix_inverse function
    let inverse = matrix_inverse::<Secp256k1>(matrix.clone(), N)
        .expect("Diagonal matrix with non-zero entries is invertible");

    // Additional verification: check that matrix * inverse = identity
    let product = multiply_matrices(&matrix, &inverse);
    assert!(is_identity(&product), "Matrix inverse is incorrect");

    // Helper function to multiply two matrices
    fn multiply_matrices(a: &[Vec<Scalar>], b: &[Vec<Scalar>]) -> Vec<Vec<Scalar>> {
        let n = a.len();
        let mut result = vec![vec![Scalar::ZERO; n]; n];
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    result[i][j] += a[i][k] * b[k][j];
                }
            }
        }
        result
    }

    // Helper function to check if a matrix is the identity matrix
    fn is_identity(matrix: &[Vec<Scalar>]) -> bool {
        let n = matrix.len();
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    if matrix[i][j] != Scalar::ONE {
                        return false;
                    }
                } else if matrix[i][j] != Scalar::ZERO {
                    return false;
                }
            }
        }
        true
    }
}
}
