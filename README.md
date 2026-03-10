# sl-crypto

`sl-crypto` is a Rust workspace with cryptographic and MPC-related crates used
by Silence Laboratories.

## Workspace crates

- `sl-compute-common`: utilities for secure compute
- `sl-messages`: message exchange and relay components for MPC protocols
- `sl-mpc-mate`: utilities for secure multi-party computation
- `sl-mpc-traits`: small utility traits shared across crates
- `sl-oblivious`: oblivious transfer protocols
- `sl-paillier`: Paillier encryption built on `crypto-bigint`
- `sl-shamir`: Shamir secret sharing
- `sl-verifiable-enc`: verifiable encryption

Additional crate-specific documentation is available in:

- [`crates/sl-messages/README.md`](crates/sl-messages/README.md)
- [`crates/sl-verifiable-enc/README.md`](crates/sl-verifiable-enc/README.md)

## Toolchain

The workspace currently targets Rust `1.88`.

## Development

This repository includes a workspace-local Cargo alias:

```bash
cargo xtask ...
```

The alias expands to:

```bash
cargo run --locked --package xtask -- ...
```

The main helper currently implemented in `xtask` is `feature-matrix`. It runs
`cargo clippy` or `cargo test` for every workspace crate and every explicit
feature combination of that crate.

Examples:

```bash
# Show the test matrix without executing it
cargo xtask feature-matrix test --dry-run

# Run clippy for every crate / feature combination
cargo xtask feature-matrix clippy -- --locked

# Run tests only for sl-messages across its feature combinations
cargo xtask feature-matrix test --package sl-messages -- --locked --release

# Inspect the generated commands for one crate
cargo xtask feature-matrix test --package sl-paillier --dry-run
```

Arguments after `--` are forwarded to the underlying Cargo command. For
example, `--release` and `--locked` are passed through to every generated
`cargo test` invocation.

## CI

GitHub Actions runs the following checks on pushes and pull requests to `main`:

```bash
cargo fmt --all --check
cargo deny --locked --all-features check
cargo run --locked --package xtask -- feature-matrix clippy -- --locked
cargo run --locked --package xtask -- feature-matrix test -- --locked --release
```

Running those commands locally is the closest way to reproduce CI.
