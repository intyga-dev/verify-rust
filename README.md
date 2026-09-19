# intyga-verify — Offline Intyga receipt verification for Rust

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on the standard Rust crypto crates (`p256`, `sha2`, …) — no bespoke cryptography. Its canonicalization is held byte-identical to the TypeScript, Python, Go, and Java verifiers by shared cross-language test vectors, for portable content (DIV §4.1.1). One known exception inside the portable range: an integer in `(2^53, 1e16)` canonicalizes to its exact digits here, as it does in Java and Python, while a double-based parser (TypeScript, Go) rounds it at parse time — the same document then yields different bytes and the mismatch reads as tampering. Keep integers within `±2^53` or carry larger values as decimal strings.

> Part of the Intyga multi-language verifier set (TypeScript, Python, Go, Rust, Java).

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
// On success you get the DISTINCT approver identities whose signatures verified, sorted — the
// keys themselves in `PublicKeys` mode, the DIDs in identity mode. Empty for an AUTO_APPROVED
// receipt, because no human signed it.
let signers = verify_approval_receipt_with_options(&receipt, &expected, &VerifyOptions::default())?;
```

**One-approver-per-key caveat.** In `PublicKeys` mode the identity IS the key, so an M-of-N quorum counts credentials, not people: one approver whose two registered credentials are both listed satisfies a 2-of-N alone. A signed `requesterCannotApprove` rule requires DID/identity trust; key-only anchors are refused because `signerDid` is unverified in that mode. For `requiredApprovals` > 1, use the DID/identity form, which counts distinct approvers (DIV §4.4.6).

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

## Receipt and audit verification

Use `verify_platform_receipt` and `verify_agent_authority` for the additional DIV receipt types.
`bundle::verify_bundle` verifies single proofs; `bundle::verify_evidence_bundle_with_options`
adds caller-policy anchoring to multi-event exports. The existing `verify_evidence_bundle` entry
point remains available for callers that only pin roots. Supply `EvidenceAnchorSet::ByCheckpoint`
for checkpoint-attributed caller anchors, or `Flat` for a flat candidate list.
`chain::verify_roots_chain` checks continuity; `ledger::verify_signed_anchor` supports all three
anchor signature algorithms, while the existing `verify_anchor_signature` ES256 helper remains.

The five language verifiers support the same receipt and audit verification features, pinned by
`canonical-vectors.json`, `ledger-vectors.json` and `verifier-parity-vectors.json`:

- DIV approval/offline/delegation receipts, agent-authority seals (§5b), and platform receipts (§5c).
  Platform receipts require WebAuthn and caller-pinned digest, RP, nonce, origin and subject keys.
  Authority/delegation verification never substitutes for approval of an action.
- Self-certifying DIDs, with explicit caller key mappings taking precedence.
- DEWP single-event and multi-event proof bundles: inclusion, canonical content/header binding,
  embedded ES256 signatures, tenant identity, sequence gaps/duplicates and claimed range endpoints.
- Checkpoint continuity (§5.4), and anchor quorum (§5.3) under the caller's policy: ES256, Ed25519,
  RSA-PSS and Rekor SET/payload verification under a separately pinned log key.

Trust inputs must come from the caller. A root carried in the bundle proves only internal
consistency; a producer's `externallyAnchored` flag is a claim, not verification. Bundle-carried
anchors can count under caller-trusted keys, but only independently fetched, checkpoint-attributed
anchors may establish divergence. For multi-checkpoint exports, key caller anchors by checkpoint ID
or root; a flat list cannot establish exact attribution across checkpoints.

Limits remain explicit: no NDJSON evidence streaming, no RFC 3161/CMS verification, and no WEBHOOK
anchor verifier. Those anchors do not count toward quorum. No implementation claims the complete
DEWP Extended Profile (§9.2). Embedded WebAuthn material is incomplete in the audit leaf; verify the
full DIV receipt separately. Offline authority verification checks the seal, not subsequent online
revocation. Verification does not consume a nonce or prove execution.

The short DIV display-code derivation and document-signing canonical builder remain outside this
port's API; neither is used to authenticate a receipt. Portable-number limits are unchanged.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Java — [`verify-java`](https://github.com/intyga-dev/verify-java)

For a full client that *requests* approvals (not just verifies them), see [`sdk-rust`](https://github.com/intyga-dev/sdk-rust) — it bundles this verifier, so you don't need both.

## License

Apache-2.0.
