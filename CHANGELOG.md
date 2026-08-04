# Changelog

All notable changes to `intyga-verify` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0]

Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no Intyga secret, no network. Standard Rust crypto crates (`p256`, `sha2`, …), no
  bespoke cryptography.
- DEWP Core Profile primitives and §5.2 single-anchor signature verification, pinned by the shared
  cross-language golden vectors. §5.3 anchor-quorum evaluation and evidence-bundle parsing are
  deliberately out of scope — see the README's limits section.
