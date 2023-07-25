use std::ops::Sub;

use elliptic_curve::{CurveArithmetic, Field};
// use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// Compute minor of a matrix.
pub fn matrix_minor<C: CurveArithmetic>(
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

/// Transpose a matrix
pub fn transpose<C: CurveArithmetic>(v: Vec<Vec<C::Scalar>>) -> Vec<Vec<C::Scalar>> {
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<C::Scalar>>()
        })
        .collect()
}
/// Get the matrix determinant
pub fn mod_bareiss_determinant<C: CurveArithmetic>(
    matrix: &mut Vec<Vec<C::Scalar>>,
    rows: usize,
) -> Result<C::Scalar, &'static str>
where
{
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
                    matrix[j][k] = matrix[j][k] * matrix[i - 1][i - 1].invert().unwrap()
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
    let determinant =
        mod_bareiss_determinant::<C>(&mut matrix.clone(), rows).expect("Error while finding det");
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
        .iter()
        .enumerate()
        .map(|(r, row)| {
            row.iter()
                .enumerate()
                .map(|(c, _)| {
                    let mut minor = matrix_minor::<C>(&matrix, r, c);
                    let minor_rows = minor.len();
                    let exponentiation = minus_one.pow([((r + c) as u64)]);
                    let value: C::Scalar = exponentiation
                        * mod_bareiss_determinant::<C>(&mut minor, minor_rows)
                            .expect("Error while finding det for minor, Given ranks setup might not be valid");
                    value
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let transposed = transpose::<C>(cofactors);

    transposed
        .into_iter()
        .map(|row| row.into_iter().map(|x| x * determinant_inv).collect())
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {

    use k256::{Scalar, Secp256k1, U256};

    use crate::traits::ToScalar;

    use super::*;

    #[test]
    fn test_minor() {
        let matrix = vec![
            vec![Scalar::from(1_u64), Scalar::from(2_u64)],
            vec![Scalar::from(3_u64), Scalar::from(4_u64)],
        ];
        let minor = matrix_minor::<Secp256k1>(matrix.as_slice(), 0, 0);
        assert_eq!(minor, vec![vec![Scalar::from(4_u64)]]);
    }
    #[test]
    fn test_determinant() {
        let mut matrix = vec![
            vec![Scalar::from(1_u64), Scalar::from(2_u64)],
            vec![Scalar::from(3_u64), Scalar::from(4_u64)],
        ];
        let minor = mod_bareiss_determinant::<Secp256k1>(&mut matrix, 2).unwrap();
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
        let inverse = matrix_inverse::<Secp256k1>(matrix, 3);

        // Known correct value
        let expected = vec![
            vec![
                U256::from_be_hex(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9D1C9E899CA306AD27FE1945DE0242B80",
                )
                .to_scalar::<Secp256k1>(),
                U256::from_be_hex(
                    "55555555555555555555555555555554E8E4F44CE51835693FF0CA2EF01215BF",
                )
                .to_scalar::<Secp256k1>(),
                Scalar::ONE,
            ],
            vec![
                U256::from_be_hex(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9D1C9E899CA306AD27FE1945DE0242B80",
                )
                .to_scalar::<Secp256k1>(),
                U256::from_be_hex(
                    "55555555555555555555555555555554E8E4F44CE51835693FF0CA2EF01215C4",
                )
                .to_scalar::<Secp256k1>(),
                U256::from_be_hex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
                )
                .to_scalar::<Secp256k1>(),
            ],
            vec![
                Scalar::ONE,
                U256::from_be_hex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
                )
                .to_scalar::<Secp256k1>(),
                Scalar::ONE,
            ],
        ];

        assert_eq!(expected, inverse)
    }
}
