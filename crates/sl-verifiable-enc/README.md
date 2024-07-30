## `sl-verifiable-enc`: Verifiable encryption library

This library provides a generic implementation of verifiable RSA encryption. It allows for the encryption of scalar values from various elliptic curves while providing proofs of correct encryption. This is particularly useful in cryptographic protocols where you need to prove that an encrypted value corresponds to a public key without revealing the private key.

### Features

- Generic over elliptic curves
- Uses RSA to be HSM-friendly 



## Usage

Here's a basic example of how to use the library with the `secp256k1` curve:

```rust
use k256::{ProjectivePoint, Scalar};
use rand::SeedableRng;
use rsa::RsaPrivateKey;
use sl_verifiable_enc::VerifiableRsaEncryption;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    
    // Generate keys
    let private_key = Scalar::generate_vartime(&mut rng);
    let public_key = ProjectivePoint::GENERATOR * private_key;
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let rsa_public_key = rsa_private_key.to_public_key();
    
    // Encrypt with proof
    let label = b"example-label";
    let verifiable_rsa = 
        VerifiableRsaEncryption::encrypt_with_proof(
            &private_key,
            &rsa_public_key,
            label,
            None,
            &mut rng,
        )?;
    
    // Verify the proof
    verifiable_rsa.verify(&public_key, &rsa_public_key, label)?;
    
    // Decrypt
    let decrypted_key = verifiable_rsa.decrypt(&public_key, &rsa_private_key, label)?;
    assert_eq!(private_key, decrypted_key);
    
    Ok(())
}
```

## Using with Different Curves

The library is generic over the curve type. Here's an example using the `curve25519`:

```rust
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::RsaPrivateKey;
use sl_verifiable_enc::VerifiableRsaEncryption;
use group::Group;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::from_entropy();
    
    // Generate keys
    let private_key = Scalar::random(&mut rng);
    let public_key = EdwardsPoint::generator() * private_key;
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let rsa_public_key = rsa_private_key.to_public_key();
    
    // Encrypt with proof
    let label = b"example-label";
    let verifiable_rsa = 
        VerifiableRsaEncryption::encrypt_with_proof(
            &private_key,
            &rsa_public_key,
            label,
            None,
            &mut rng,
        )?;
    
    // Verify the proof
    verifiable_rsa.verify(&public_key, &rsa_public_key, label)?;
    
    // Decrypt
    let decrypted_key = verifiable_rsa.decrypt(&public_key, &rsa_private_key, label)?;
    assert_eq!(private_key, decrypted_key);
    
    Ok(())
}
```

## Security Considerations

- The library uses constant-time operations where possible to mitigate timing attacks.
- The default security parameter is set to 120, which can be adjusted if needed.
- Always use cryptographically secure random number generators in production environments.

## License

You can find the license [here](/LICENSE.md)

