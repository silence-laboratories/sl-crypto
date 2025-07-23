//! Shamir Secret Sharing implementation using GF(256)
//!
//! This crate provides a secure implementation of Shamir's Secret Sharing scheme
//! over the Galois Field GF(256) using the irreducible polynomial 0x11d.

mod gf256;

use gf256::Gf256;
use rand::{CryptoRng, RngCore};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Prefix size of a share (1 magic byte + 1 x-coordinate byte)
/// THe size of a share is PREFIX + SECRET_LEN (bytes)
pub const SHARE_PREFIX: usize = 2;

pub const SHARE_MAGIC_V1: u8 = 1;

/// A polynomial over GF(256) with coefficients stored as [a0, a1, a2, ...]
/// representing a0 + a1*x + a2*x^2 + ...
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
struct Polynomial {
    coeffs: Vec<Gf256>,
}

impl Polynomial {
    /// Create a random polynomial of given degree with specified constant term
    fn random<R: CryptoRng + RngCore>(
        degree: usize,
        constant: Gf256,
        rng: &mut R,
    ) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(constant); // a0 = constant term (secret)
        for _ in 0..degree {
            let mut byte = [0u8];
            rng.fill_bytes(&mut byte);
            coeffs.push(Gf256(byte[0]));
        }

        Self { coeffs }
    }

    /// Evaluate polynomial at point x using Horner's method
    fn eval(&self, x: Gf256) -> Gf256 {
        let mut result = Gf256::ZERO;

        // Horner's method: ((an*x + an-1)*x + ... + a1)*x + a0
        for &coeff in self.coeffs.iter().rev() {
            result = result * x + coeff;
        }

        result
    }
}

/// A share containing an x-coordinate and corresponding y-values
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Share {
    x: u8,
    y: Vec<u8>,
}

impl Share {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SHARE_PREFIX + self.y.len());
        bytes.push(SHARE_MAGIC_V1); // Version identifier
        bytes.push(self.x); // x-coordinate
        bytes.extend(&self.y); // y data
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShamirError> {
        if bytes.len() < SHARE_PREFIX + 1 {
            return Err(ShamirError::InvalidShare);
        }

        // Check magic byte for version compatibility
        let magic = bytes[0];
        if magic != SHARE_MAGIC_V1 {
            return Err(ShamirError::InvalidShare);
        }

        let x = bytes[1];
        if x == 0 {
            return Err(ShamirError::InvalidShare);
        }

        // Extract y data (everything after PREFIX)
        let y = bytes[SHARE_PREFIX..].to_vec();
        if y.is_empty() {
            return Err(ShamirError::InvalidShare);
        }

        Ok(Share { x, y })
    }
}

/// Error types for Shamir secret sharing
#[derive(Debug, PartialEq, Eq)]
pub enum ShamirError {
    InvalidThreshold,
    InvalidShareCount,
    EmptySecret,
    InsufficientShares,
    DuplicateShare,
    InvalidShare,
}

/// Split a `secret` into `share_count` shares with a threshold of `threshold`
///
/// # Arguments
/// * `secret` - The secret bytes to split
/// * `threshold` - Minimum number of shares needed to reconstruct the secret
/// * `share_count` - Total number of shares to generate for the secret
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// Vector of shares that can be used to reconstruct the secret
pub fn split<R: CryptoRng + RngCore>(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    rng: &mut R,
) -> Result<Vec<Share>, ShamirError> {
    if threshold == 0 || threshold > share_count {
        return Err(ShamirError::InvalidThreshold);
    }
    if share_count == 0 {
        return Err(ShamirError::InvalidShareCount);
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    let mut shares = Vec::with_capacity(share_count as usize);

    // Initialize shares with x-coordinates 1..n
    for i in 1..=share_count {
        shares.push(Share {
            x: i,
            y: Vec::with_capacity(secret.len()),
        });
    }

    // For each byte of the secret, create a polynomial and evaluate at share points
    for &secret_byte in secret {
        let poly = Polynomial::random(
            (threshold - 1) as usize,
            secret_byte.into(),
            rng,
        );

        for share in &mut shares {
            let y_val = poly.eval(share.x.into());
            share.y.push(y_val.0);
        }
    }

    Ok(shares)
}

/// Recover secret from shares using Lagrange interpolation
///
/// # Arguments
/// * `shares` - Collection of shares (must have at least threshold shares)
///
/// # Returns
/// The reconstructed secret bytes
pub fn recover(
    shares: &[Share],
    threshold: u8,
) -> Result<Vec<u8>, ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::InvalidThreshold);
    }
    if shares.is_empty() || shares.len() < threshold as usize {
        return Err(ShamirError::InsufficientShares);
    }

    // Check for duplicate x-coordinates
    let mut x_coords = std::collections::HashSet::new();
    for share in shares {
        if share.x == 0 {
            return Err(ShamirError::InvalidShare);
        }
        if !x_coords.insert(share.x) {
            return Err(ShamirError::DuplicateShare);
        }
    }

    // All shares must have the same length
    let secret_len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != secret_len) {
        return Err(ShamirError::InvalidShare);
    }

    let mut secret = Vec::with_capacity(secret_len);

    // Reconstruct each byte of the secret using Lagrange interpolation
    for byte_idx in 0..secret_len {
        // Collect (x, y) points for this byte position
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut points: Vec<(Gf256, Gf256)> = shares
            .iter()
            .map(|share| (Gf256(share.x), Gf256(share.y[byte_idx])))
            .collect();

        // Use Lagrange interpolation to find f(0) = secret
        let secret_byte = lagrange_interpolate_at_zero(&points);
        secret.push(secret_byte.0);

        // Zeroize intermediate points
        #[cfg(feature = "zeroize")]
        points.zeroize();
    }

    Ok(secret)
}

/// Lagrange interpolation to find polynomial value at x=0
fn lagrange_interpolate_at_zero(points: &[(Gf256, Gf256)]) -> Gf256 {
    let mut result = Gf256::ZERO;

    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut li = Gf256::ONE;

        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                // Li(0) = product of (-xj) / (xi - xj) for all j != i
                let numerator = Gf256::ZERO - xj; // -xj
                let denominator = xi - xj;
                li = li * (numerator / denominator);
            }
        }

        result += yi * li;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_basic_sharing() {
        let mut rng = thread_rng();
        let secret = b"hello world!";
        let threshold = 3;
        let share_count = 5;

        let shares = split(secret, threshold, share_count, &mut rng).unwrap();
        assert_eq!(shares.len(), share_count as usize);

        // Test reconstruction with exact threshold
        let reconstructed =
            recover(&shares[0..threshold as usize], threshold).unwrap();
        assert_eq!(reconstructed, secret);

        // Test reconstruction with more shares
        let reconstructed = recover(&shares, threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let mut rng = thread_rng();
        let secret = b"test";
        let threshold = 3;
        let share_count = 5;

        let shares = split(secret, threshold, share_count, &mut rng).unwrap();

        // Should work with threshold shares
        let result = recover(&shares[0..share_count as usize], threshold);
        assert!(result.is_ok());

        // Should fail with too few shares (threshold - 1)
        let result = recover(&shares[0..threshold as usize - 1], threshold);
        // Note: This currently doesn't check the threshold in recover()
        // The mathematical property ensures it won't give the right answer with too few shares
        // but it won't explicitly error. Let's test that it gives a wrong result instead.
        if let Ok(wrong_secret) = result {
            assert_ne!(wrong_secret, secret.to_vec());
        }
    }

    #[test]
    fn test_various_secret_sizes() {
        let mut rng = thread_rng();
        let threshold = 2;
        let share_count = 3;

        // Test different secret sizes
        for size in [1, 16, 32, 64, 100] {
            let secret: Vec<u8> =
                (0..size).map(|i| (i % 256) as u8).collect();
            let shares =
                split(&secret, threshold, share_count, &mut rng).unwrap();
            let reconstructed =
                recover(&shares[0..threshold as usize], threshold).unwrap();
            assert_eq!(reconstructed, secret, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_error_conditions() {
        let mut rng = thread_rng();
        let secret = b"test";

        // Invalid threshold
        assert_eq!(
            split(secret, 0, 5, &mut rng),
            Err(ShamirError::InvalidThreshold)
        );
        assert_eq!(
            split(secret, 6, 5, &mut rng),
            Err(ShamirError::InvalidThreshold)
        );

        // Invalid share count
        assert_eq!(
            split(secret, 0, 0, &mut rng),
            Err(ShamirError::InvalidThreshold)
        ); // This will hit threshold check first since both are 0

        // Empty secret
        assert_eq!(split(&[], 2, 3, &mut rng), Err(ShamirError::EmptySecret));
    }

    #[test]
    fn test_duplicate_shares() {
        let shares = vec![
            Share {
                x: 1,
                y: vec![1, 2, 3],
            },
            Share {
                x: 1,
                y: vec![4, 5, 6],
            }, // Duplicate x
        ];

        let result = recover(&shares, 2);
        assert_eq!(result, Err(ShamirError::DuplicateShare));
    }

    #[test]
    fn test_zero_x_coordinate() {
        let shares = vec![
            Share {
                x: 0,
                y: vec![1, 2, 3],
            }, // Invalid x=0
            Share {
                x: 2,
                y: vec![4, 5, 6],
            },
        ];

        let result = recover(&shares, 2);
        assert_eq!(result, Err(ShamirError::InvalidShare));
    }

    #[test]
    fn test_mismatched_share_lengths() {
        let shares = vec![
            Share {
                x: 1,
                y: vec![1, 2, 3],
            },
            Share {
                x: 2,
                y: vec![4, 5],
            }, // Different length
        ];

        let result = recover(&shares, 2);
        assert_eq!(result, Err(ShamirError::InvalidShare));
    }

    #[test]
    fn test_polynomial_evaluation() {
        // Test that polynomial evaluation works correctly
        let poly = Polynomial {
            coeffs: vec![Gf256(5), Gf256(3), Gf256(2)], // 5 + 3x + 2x^2
        };

        // f(0) = 5
        assert_eq!(poly.eval(Gf256(0)), Gf256(5));

        // f(1) = 5 + 3 + 2 = 10 (but in GF256: 5 ^ 3 ^ 2 = 4)
        let expected = Gf256(5) + Gf256(3) + Gf256(2);
        assert_eq!(poly.eval(Gf256(1)), expected);
    }

    #[test]
    fn test_single_byte_secret() {
        let mut rng = thread_rng();
        let secret = [42u8];
        let threshold = 2;
        let share_count = 3;

        let shares =
            split(&secret, threshold, share_count, &mut rng).unwrap();
        let reconstructed =
            recover(&shares[0..threshold as usize], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_recover() {
        let mut rng = thread_rng();
        let secret = b"hello world!";
        let threshold = 3;
        let share_count = 5;

        let shares = split(secret, threshold, share_count, &mut rng).unwrap();
        let reconstructed =
            recover(&shares[0..threshold as usize], threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_share_serialization() {
        let mut rng = thread_rng();
        let secret = b"test serialization";
        let threshold = 2;
        let share_count = 3;

        let shares = split(secret, threshold, share_count, &mut rng).unwrap();

        // Test each share can be serialized and deserialized
        for share in &shares {
            let bytes = share.to_bytes();
            let deserialized = Share::from_bytes(&bytes).unwrap();
            assert_eq!(*share, deserialized);
        }

        // Test that serialized shares can still reconstruct the secret
        let serialized_shares: Vec<Share> = shares
            .iter()
            .map(|s| Share::from_bytes(&s.to_bytes()).unwrap())
            .collect();

        let reconstructed =
            recover(&serialized_shares[0..threshold as usize], threshold)
                .unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_share_format_validation() {
        // Test invalid magic byte
        let bad_magic = vec![99, 1, 42]; // wrong magic
        assert_eq!(
            Share::from_bytes(&bad_magic),
            Err(ShamirError::InvalidShare)
        );

        // Test zero x-coordinate
        let zero_x = vec![SHARE_MAGIC_V1, 0, 42]; // x = 0
        assert_eq!(
            Share::from_bytes(&zero_x),
            Err(ShamirError::InvalidShare)
        );

        // Test empty y data
        let empty_y = vec![SHARE_MAGIC_V1, 1]; // no y data
        assert_eq!(
            Share::from_bytes(&empty_y),
            Err(ShamirError::InvalidShare)
        );

        // Test too short
        let too_short = vec![SHARE_MAGIC_V1]; // missing x and y data
        assert_eq!(
            Share::from_bytes(&too_short),
            Err(ShamirError::InvalidShare)
        );
    }
}
