# Changelog

All notable changes to `sl-messages` are documented in this file.

## [1.2.0] - 2026-03-10

### Changed

- Finalized the crate version as `1.2.0`.
- Removed `setup` from the default feature set; consumers that rely on setup
  APIs must now enable the `setup` feature explicitly.
- Removed `fast-ws` and `mux` from the default feature set.

## [1.2.0-pre.3] - 2026-03-07

### Added

- Split `setup` into focused modules for round tracking, abort handling,
  key generation, signing, key export, quorum change, and no-op test keys.
- Added typed setup-message traits for keygen, signing, finish, quorum change,
  key export, and weighted variants.
- Added public no-op key/signature types in `setup::keys` for trusted
  transports and tests.
- Added `BufferedMsgRelay::process_round()` and
  `BufferedMsgRelay::process_signed()` for round-aware setup message handling.
- Added crate-level `README.md` and setup-specific tests for round tracking and
  relay behavior.

### Changed

- Enabled the `setup` feature by default and wired it to the optional
  `derivation-path` dependency.
- Exported `BufferedError` behind the `setup` feature.

### Breaking

- Renamed `setup::check_abort` to `setup::validate_abort_message`.
- Replaced `BufferedMsgRelay::wait_for_bounded()` with
  `BufferedMsgRelay::wait_for_limited()`, which now returns predicate output
  together with the matched message.
- Changed `MessageRound::ask_pending()` to return
  `Result<usize, MessageSendError>`.

## [1.2.0-pre.2] - 2026-03-05

### Added

- Added `MessageRound` and `RoundMode` helpers for broadcast and P2P setup
  rounds, including sender tracking, pending-message checks, and bulk asks.
- Added bounded relay waiting with `BufferedMsgRelay::wait_for_bounded()` and
  `buffered_len()`.
- Added abort-message creation and validation helpers.

### Changed

- Enabled the `setup` feature by default.

## [1.2.0-pre.1] - 2026-03-03

### Added

- Added the feature-gated `setup` module.
- Added the `ProtocolParticipant` trait and `AllOtherParties` iterator for
  deriving setup message IDs from protocol participant metadata.
- Added setup message tags and shared participant helpers such as instance ID,
  participant verifier access, TTL, and `setup_hash()`.

## [1.1.0] - 2026-01-13

### Added

- Initial published release of `sl-messages` as a standalone crate for MPC
  message transport and encoding.
- Core message primitives for deterministic `MsgId`s, message allocation, pair
  metadata, signed message verification, and encrypted message construction.
- Relay implementations for in-memory transport, buffering, tracing,
  statistics, adversarial testing, fan-in/fan-out multiplexing, and optional
  websocket transport.

### Changed

- Redesigned the encryption API around reusable scheme traits and builders,
  including AEAD X25519 and passthrough schemes.
- Finalized the crate metadata and workspace dependency wiring for the 1.1.0
  release on `main`.

### Fixed

- `BufferedMsgRelay::next()` now returns buffered messages before polling the
  wrapped relay, preserving messages previously captured by `wait_for`.
- `RelayStats` now counts `ask()` calls separately instead of treating
  header-only asks as regular sends.
