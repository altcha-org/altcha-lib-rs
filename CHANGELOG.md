# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-04

Brings PoW v2 behavior in line with the JS reference implementation (`altcha-lib`).

### Added

- `CounterMode` (`Uint32`, `String`) and a `counter_mode` field on `CreateChallengeOptions`,
  `SolveChallengeOptions` and `VerifySolutionOptions`, matching JS `counterMode`.
  `String` encodes the counter as a decimal UTF-8 string for v1 compatibility; the default
  `Uint32` is unchanged.

### Changed

- **Breaking:** `expires_at` on `ChallengeParameters` and `CreateChallengeOptions` is now
  `Option<i64>` (was `Option<u64>`). The JSON wire format is unchanged.
- **Breaking:** `CreateChallengeOptions`, `SolveChallengeOptions` and
  `VerifySolutionOptions` have a new `counter_mode` field; struct literals without
  `..Default::default()` / `::new` must set it.
- **Breaking:** a `key_prefix` containing non-hex characters returns
  `Error::InvalidParameters` from `create_challenge`, `solve_challenge` and
  `verify_solution` (re-derivation path), regardless of its length. Previously an
  even-length one returned `Error::Hex` and an odd-length one could never match.
- `create_challenge` stores `key_prefix` lowercase, and solve/verify match it
  case-insensitively.
- `key_prefix_length` is capped at half the derived key length.
- `timeout_ms: 0` in `SolveChallengeOptions` disables the timeout instead of returning
  `None` immediately.
- Empty-string secrets count as absent, as in JS: an empty `hmac_signature_secret` yields an
  unsigned challenge, an empty `hmac_key_signature_secret` adds no key signature, and an
  empty key secret or `key_signature` skips the key-signature verification path.

### Fixed

- `verify_solution` rejected solutions to even-length uppercase key prefixes (e.g. `0A`)
  that `solve_challenge` accepted.
- `verify_solution` returned `Err` for a malformed (non-hex or odd-length) `derived_key` on
  the key-signature path; it now returns `invalid_solution`.
- Expiry was checked with whole seconds, allowing up to 1 s past `expires_at`; it is now
  checked with sub-second precision.
- `expires_at = 0` counted as expired; it now means no expiry. Negative values are always
  expired.
- `solve_challenge` checked the timeout only when `counter % 10 == 0`, so counter sequences
  that never hit a multiple of 10 (e.g. odd counters) never timed out. It now checks every
  10 iterations.
- `create_challenge` panicked when `key_prefix_length` exceeded the derived key length.

## [0.2.0] - 2026-07-27

### Security

- PoW v2 fallback verification (no key signature) now enforces `keyPrefix`. Previously only
  `derivedKey == KDF(counter)` was checked, so any counter verified after a single KDF
  run, without searching for the prefix.

## [0.1.0] - 2026-04-07

Initial release.

[Unreleased]: https://github.com/altcha-org/altcha-lib-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/altcha-org/altcha-lib-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/altcha-org/altcha-lib-rs/releases/tag/v0.1.0
