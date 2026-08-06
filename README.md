# intyga-verify — Offline Intyga receipt verification for Rust

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on the standard Rust crypto crates (`p256`, `sha2`, …) — no bespoke cryptography. Its canonicalization is held byte-identical to the TypeScript, Python, and Go verifiers by shared cross-language test vectors.

> Part of the Intyga multi-language verifier set (TypeScript, Python, Go, Rust).

## Add it

```sh
cargo add intyga-verify
```

## Verify an approval receipt

```rust
use intyga_verify::{verify_approval_receipt_with_options, ApproverTrustAnchor, Expected, VerifyOptions};
use serde_json::json;

// `expected` is what you are ABOUT to execute. `target` is YOUR OWN identifier (Target
// Isolation), `nonce` is the challenge YOU issued, and `approvers` is the key set YOU trust —
// all required, and none of them ever read from the receipt.
let expected = Expected {
    target: "prod-db-cluster-01".into(),
    nonce: nonce.clone(),
    action_type: "wipe_production".into(),
    params: json!({ "target": "prod-db-1" }),
    approvers: ApproverTrustAnchor::PublicKeys(vec![approver_spki_b64]),
};
verify_approval_receipt_with_options(&receipt, &expected, &VerifyOptions::default())?;
```

**One-approver-per-key caveat.** In `PublicKeys` mode the identity IS the key, so an M-of-N quorum counts credentials, not people: one approver whose two registered credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form, which counts distinct approvers (DIV §4.4.6).

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
duplicate-last balancing, leaf-to-root inclusion proof verification, the `trust.intyga.audit.v1`
canonical preimage, the `0x03` anchor digest, and **anchor signature verification (single-anchor,
ES256)** — `verify_anchor_signature`, over the raw 32-byte digest per §5.2. Byte parity with the
TypeScript reference is locked by the shared golden vectors in
`packages/mcp-schemas/vectors/ledger-vectors.json`, including the `signedAnchor` cases.

It does **not** implement, and a caller should not assume:

- **Anchor quorum verification** (§5.3). A single anchor's ES256 signature can be checked with
  `verify_anchor_signature` against a key the caller resolved; evaluating `requiredAnchors` /
  issuer trust across multiple anchors, divergence detection, and non-ES256 anchor algorithms
  (Ed25519, RSA-PSS) are not. `anchorVerified` beyond one ES256 anchor therefore cannot be
  established by this port alone.
- **The §5.4 checkpoint continuity chain** (`0x04` domain tag). TS-only; DEWP §9.1 places it
  outside the Core Profile.
- **Proof bundle parsing and the §7.1 verification levels.** This port verifies proofs, not envelopes.
- **Evidence bundles, `tenantSeq` gapless validation, and NDJSON streaming** (§9.2 Extended Profile).
- **DIV §4.4.4 verification-code derivation** (the `digests` vector section). The short display
  code is a human-factors aid that MUST NOT be treated as authentication, so this port carries
  `verificationCode` as an unvalidated field and deliberately does not assert those vectors
  (TypeScript and Python do).
- **DIV §5b Agent Authority** (`div-agent-authority` payloads and the `agentAuthorityPayloads`
  vector section). TypeScript-only. This port's approval verifier correctly REFUSES the
  payload type — an authority authorizes no action — it just cannot verify one as governance
  evidence.

For the rest of the surface — signed multi-anchor quorum, evidence bundles, gapless `tenantSeq`
completeness over committed events, and the four-property verification model — use the TypeScript
verifier (`@intyga/verify`). Note that no
implementation, the TypeScript one included, currently claims the §9.2 **Extended Profile**: the
profile also requires NDJSON evidence streaming (§6.4), which is specified but not yet implemented
anywhere.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Java — [`verify-java`](https://github.com/intyga-dev/verify-java)

For a full client that *requests* approvals (not just verifies them), see [`sdk-rust`](https://github.com/intyga-dev/sdk-rust) — it bundles this verifier, so you don't need both.

## License

Apache-2.0.
