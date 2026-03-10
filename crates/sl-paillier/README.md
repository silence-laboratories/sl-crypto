# sl-paillier

`sl-paillier` provides a Paillier cryptosystem implementation built on
[`crypto-bigint`](https://docs.rs/crypto-bigint).

The crate currently targets Rust `1.88` and ships a 2048-bit configuration as
its main public API.

## Main types

- `SK2048`: secret key
- `PK2048`: public key
- `RawPlaintext`
- `RawCiphertext`

## Features

- `serde`: enables serialization support for the 2048-bit key and ciphertext
  types, and exposes `MinimalSK2048` / `MinimalPK2048` for compact key
  serialization

## Supported operations

- key generation with `SK2048::gen()` / `SK2048::gen_keys()`
- plaintext construction with `PK2048::message()` and `PK2048::into_message()`
- encryption with `PK2048::encrypt()` or `PK2048::encrypt_with_r()`
- decryption with `SK2048::decrypt()` and CRT-accelerated `SK2048::decrypt_fast()`
- additive homomorphism with `PK2048::add()`
- multiplication by a plaintext scalar with `PK2048::mul()`

`PK2048::mul_vartime()` is also exposed as an explicitly variable-time variant.

## Example

```rust
use rand::thread_rng;
use sl_paillier::SK2048;

let mut rng = thread_rng();
let (sk, pk) = SK2048::gen_keys(&mut rng);

let m1 = pk.message(&[5]).unwrap();
let m2 = pk.message(&[9]).unwrap();

let c1 = pk.encrypt(&m1, &mut rng);
let c2 = pk.encrypt(&m2, &mut rng);

let sum = pk.add(&c1, &c2);
let doubled = pk.mul(&c1, &pk.message(&[2]).unwrap());

assert_eq!(sk.decrypt(&sum), pk.message(&[14]).unwrap());
assert_eq!(sk.decrypt_fast(&sum), pk.message(&[14]).unwrap());
assert_eq!(sk.decrypt_fast(&doubled), pk.message(&[10]).unwrap());
```

## Notes

- `PK2048::message()` interprets input bytes in little-endian order and returns
  `None` if the resulting integer is not smaller than `n`.
- `decrypt_fast()` uses CRT precomputation and is intended to produce the same
  result as `decrypt()`.
- Benchmarks live in [`benches/sl-paillier.rs`](benches/sl-paillier.rs).
