# Changelog

All notable changes to `algovoi-receipt-verifier` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-15

### Fixed
- **Tests:** the JWS signature-tamper test (`test_rejects_tampered_signature`)
  was non-deterministic. It mutated the trailing base64url character of the
  signature segment, which for a 64-byte Ed25519 signature carries only a few
  significant bits — many single-character edits decode to identical bytes, so
  the signature still verified and the expected rejection did not fire (~1 in 4
  runs). The test now tampers at the byte level (decode, flip the middle byte,
  re-encode) and asserts the decoded bytes actually changed.

### Notes
- The verifier runtime is unchanged from 0.1.0; this is a test-reliability and
  packaging-trail release. Published for version parity across the Python
  (PyPI) and TypeScript (npm) distributions.

## [0.1.0] - 2026-06

### Added
- Initial release: standalone, offline-capable cryptographic verifier for
  AlgoVoi JWS compliance receipts (Ed25519 / EdDSA, RFC 8785 JCS canonical
  payloads). Python and TypeScript implementations.
