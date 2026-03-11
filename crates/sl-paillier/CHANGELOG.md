# Changelog

All notable changes to `sl-paillier` are documented in this file.

## [1.2.0] - 2026-03-10

### Changed

- Upgraded the crate to `crypto-bigint 0.6` and `crypto-primes 0.6`.
- Migrated modular arithmetic internals from dynamic residues to Montgomery
  forms and parameters.
- Enabled the `alloc` feature on `crypto-bigint` to support generic modular
  inverse handling during key setup.

### Fixed

- Restored compatibility of encryption, decryption, CRT recombination, and
  `extract_n_root` helpers with the current `crypto-bigint` APIs.
- Removed secret-side uses of `_vartime` modular reduction and parameter
  construction in private-key paths.
- Updated Criterion benchmarks and public traits to match the new bigint and
  modular arithmetic APIs.

## [1.1.0] - 2026-01-13

### Added

- Initial published release of `sl-paillier` as a standalone Paillier
  encryption crate.
