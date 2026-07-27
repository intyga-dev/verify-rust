# sakra-verify — Offline SÄKRA receipt verification for Rust

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no SÄKRA secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on the standard Rust crypto crates (`p256`, `sha2`, …) — no bespoke cryptography. Its canonicalization is held byte-identical to the TypeScript, Python, and Go verifiers by shared cross-language test vectors.

> Status: **not yet published** to crates.io. Part of the SÄKRA multi-language verifier set.

## Add it

```sh
cargo add sakra-verify
```

## Verify an approval receipt

```rust
use sakra_verify::{verify_approval_receipt_with_options, Expected, VerifyOptions};
use serde_json::json;

// `expected` is what you are ABOUT to execute; `nonce` is the challenge YOU issued.
let expected = Expected {
    nonce: nonce.clone(),
    action_type: "wipe_production".into(),
    params: json!({ "target": "prod-db-1" }),
};
verify_approval_receipt_with_options(&receipt, &expected, &VerifyOptions::default())?;
```

`verify_approval_receipt(&receipt, &expected)` is a shorthand for ES256 receipts. One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```rust
let opts = VerifyOptions {
    expected_origin: Some("https://app.example.com".into()),
    expected_rp_id: Some("app.example.com".into()),
    ..Default::default()
};
verify_approval_receipt_with_options(&receipt, &expected, &opts)?;
```

`require_user_verification` defaults to true (demands the User-Verified flag); set `Some(false)` to accept mere user presence. Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `allow_auto_approved: true`.

## DEWP conformance

This port implements the **DEWP Core primitives** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1):
domain-separated hashing (`0x00`/`0x01`/`0x02`/`0x03`), two-tier Merkle tree construction with
duplicate-last balancing, leaf-to-root inclusion proof verification, the `trust.sakra.audit.v1`
canonical preimage, and the `0x03` anchor digest. Byte parity with the TypeScript reference is locked
by the shared golden vectors in `packages/mcp-schemas/vectors/ledger-vectors.json`.

It does **not** implement, and a caller should not assume:

- **Anchor signature and quorum verification** (§5.3). `AnchorDigest` is provided; verifying an
  anchor's signature and evaluating `requiredAnchors` / issuer trust is not. `anchorVerified` therefore
  cannot be established by this port alone.
- **Proof bundle parsing and the §7.1 verification levels.** This port verifies proofs, not envelopes.
- **Evidence bundles, `tenantSeq` gapless validation, and NDJSON streaming** (§9.2 Extended Profile).

For the Extended Profile — signed multi-anchor quorum, evidence bundles, gapless completeness and the
four-property verification model — use the TypeScript verifier (`@sakra-trust/verify`).

## Also available in
- TypeScript — [`@sakra-trust/verify`](https://github.com/SAKRA-trust/verify)
- Python — [`verify-python`](https://github.com/SAKRA-trust/verify-python)
- Go — [`verify-go`](https://github.com/SAKRA-trust/verify-go)

For a full client that *requests* approvals (not just verifies them), see [`sdk-rust`](https://github.com/SAKRA-trust/sdk-rust) — it bundles this verifier, so you don't need both.

## License

Apache-2.0.
