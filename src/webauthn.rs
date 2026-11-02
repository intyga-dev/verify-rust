//! WebAuthn (passkey) receipt verification.
//!
//! Mirrors the TypeScript (`@intyga/verify`) and Python verifiers byte-for-byte: a minimal
//! CBOR reader walks the COSE_Key, the assertion is pinned to the expected origin and RP ID, user
//! presence/verification is enforced, the challenge must equal base64url(canonicalPayload), and the
//! ES256 signature is checked over `authenticatorData ‖ SHA-256(clientDataJSON)`.

use crate::{parse_p256_public_key, ApprovalReceipt, ApprovalWitness, VerifyOptions};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const AUTH_DATA_FLAG_UP: u8 = 0x01; // User Present
const AUTH_DATA_FLAG_UV: u8 = 0x04; // User Verified
const AUTH_DATA_FLAG_BE: u8 = 0x08; // Backup Eligible — the credential may be synced to other devices
const AUTH_DATA_FLAG_BS: u8 = 0x10; // Backup State — the credential is currently backed up

/// Under a signed `require_hardware_key`, a WEBAUTHN witness whose authenticatorData carries the
/// Backup Eligible or Backup State flag cannot count (DIV §4.4.5 rule 6). The flags are covered by the
/// assertion signature, so a relying party can catch an issuer that let a synced passkey sign a
/// hardware-pinned action. BE=0 is the authenticator's own claim, not attestation. Called only for a
/// witness that already verified, so authenticatorData decodes to at least 37 bytes.
pub(crate) fn backup_flags_problem(witness: &ApprovalWitness) -> Option<String> {
    if witness.sig_alg.as_deref() != Some("WEBAUTHN") {
        return None;
    }
    let encoded = witness.authenticator_data.as_deref()?;
    match decode_base64_flexible(encoded) {
        Ok(auth_data) if auth_data.len() >= 37 => {
            if auth_data[32] & (AUTH_DATA_FLAG_BE | AUTH_DATA_FLAG_BS) == 0 {
                None
            } else {
                Some(format!(
                    "signer {} used a backup-eligible (synced) passkey — authenticatorData BE/BS flag set — but the signed policy requires a hardware-backed WebAuthn credential",
                    witness.signer_did.as_deref().unwrap_or("")
                ))
            }
        }
        _ => Some("authenticatorData is unreadable".to_string()),
    }
}

/// Accepts both base64url — the DIV §4.4.2 wire form, which browsers and the gateway emit
/// unpadded — and standard base64 (legacy receipts, older vectors), padded or not. The alphabets
/// differ only in characters 62/63 (`+/` vs `-_`), so normalizing is lossless and cannot make an
/// invalid encoding valid.
pub(crate) fn decode_base64_flexible(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut normalized: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }
    STANDARD.decode(normalized)
}

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Anything outside
// that subset is rejected rather than guessed.

enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    // Text and Array are part of the CBOR grammar we must consume to walk a COSE_Key correctly,
    // but their contents are never read for a P-256 key — only the integer labels and byte-string
    // coordinates matter.
    #[allow(dead_code)]
    Text(String),
    #[allow(dead_code)]
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
}

struct CborReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        CborReader { buf, pos: 0 }
    }

    fn require(&self, n: usize) -> Result<(), String> {
        if self.pos + n > self.buf.len() {
            return Err("invalid COSE public key format: truncated CBOR item".to_string());
        }
        Ok(())
    }

    /// Read a CBOR head, returning (major type, argument value).
    fn read_head(&mut self) -> Result<(u8, u64), String> {
        self.require(1)?;
        let initial = self.buf[self.pos];
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let value = match info {
            0..=23 => info as u64,
            24 => {
                self.require(1)?;
                let v = self.buf[self.pos] as u64;
                self.pos += 1;
                v
            }
            25 => {
                self.require(2)?;
                let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]) as u64;
                self.pos += 2;
                v
            }
            26 => {
                self.require(4)?;
                let v = u32::from_be_bytes([
                    self.buf[self.pos],
                    self.buf[self.pos + 1],
                    self.buf[self.pos + 2],
                    self.buf[self.pos + 3],
                ]) as u64;
                self.pos += 4;
                v
            }
            // 27 = 64-bit, 28-30 reserved, 31 = indefinite. No COSE_Key needs any of them.
            _ => {
                return Err(
                    "invalid COSE public key format: unsupported CBOR length encoding".to_string(),
                )
            }
        };
        Ok((major, value))
    }

    fn decode_item(&mut self) -> Result<Cbor, String> {
        let (major, value) = self.read_head()?;
        match major {
            0 => Ok(Cbor::Int(value as i64)),
            1 => Ok(Cbor::Int(-1 - value as i64)),
            2 => {
                self.require(value as usize)?;
                let b = self.buf[self.pos..self.pos + value as usize].to_vec();
                self.pos += value as usize;
                Ok(Cbor::Bytes(b))
            }
            3 => {
                self.require(value as usize)?;
                let s = String::from_utf8(self.buf[self.pos..self.pos + value as usize].to_vec())
                    .map_err(|_| {
                    "invalid COSE public key format: bad UTF-8 text".to_string()
                })?;
                self.pos += value as usize;
                Ok(Cbor::Text(s))
            }
            4 => {
                let mut items = Vec::with_capacity(value as usize);
                for _ in 0..value {
                    items.push(self.decode_item()?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut pairs = Vec::with_capacity(value as usize);
                for _ in 0..value {
                    let k = self.decode_item()?;
                    let v = self.decode_item()?;
                    pairs.push((k, v));
                }
                Ok(Cbor::Map(pairs))
            }
            _ => Err(format!(
                "invalid COSE public key format: unsupported CBOR major type {}",
                major
            )),
        }
    }
}

/// Extract the P-256 public key from a WebAuthn COSE_Key. Pins kty EC2 (2), crv P-256 (1) and, if
/// present, alg ES256 (-7), so a key for another curve can never be reinterpreted as P-256.
fn parse_cose_p256_key(cose_buf: &[u8]) -> Result<VerifyingKey, String> {
    let item = CborReader::new(cose_buf).decode_item()?;
    let pairs = match item {
        Cbor::Map(pairs) => pairs,
        _ => return Err("invalid COSE public key format: expected a CBOR map".to_string()),
    };

    let get = |label: i64| -> Option<&Cbor> {
        pairs.iter().find_map(|(k, v)| match k {
            Cbor::Int(i) if *i == label => Some(v),
            _ => None,
        })
    };

    match get(1) {
        Some(Cbor::Int(2)) => {}
        _ => return Err("invalid COSE public key format: expected kty EC2 (2)".to_string()),
    }
    match get(-1) {
        Some(Cbor::Int(1)) => {}
        _ => return Err("invalid COSE public key format: expected crv P-256 (1)".to_string()),
    }
    if let Some(alg) = get(3) {
        match alg {
            Cbor::Int(-7) => {}
            _ => return Err("invalid COSE public key format: expected alg ES256 (-7)".to_string()),
        }
    }

    let coord = |label: i64, name: &str| -> Result<Vec<u8>, String> {
        match get(label) {
            Some(Cbor::Bytes(b)) if b.len() == 32 => Ok(b.clone()),
            Some(Cbor::Bytes(b)) => Err(format!(
                "invalid COSE public key format: {} coordinate must be 32 bytes, got {}",
                name,
                b.len()
            )),
            _ => Err(format!(
                "invalid COSE public key format: missing {} coordinate",
                name
            )),
        }
    };
    let x = coord(-2, "x")?;
    let y = coord(-3, "y")?;

    // Build an uncompressed SEC1 point (0x04 ‖ x ‖ y); from_sec1_bytes validates it is on-curve.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    parse_p256_public_key(&sec1)
        .ok_or_else(|| "invalid COSE public key format: point is not a valid P-256 key".to_string())
}

pub(super) fn cose_p256_fingerprint(cose_buf: &[u8]) -> Result<Vec<u8>, String> {
    parse_cose_p256_key(cose_buf).map(|key| key.to_encoded_point(false).as_bytes().to_vec())
}

/// The fields read from clientDataJSON. Each is optional and read loosely (a wrong JSON type reads
/// as absent), so a hostile document is a refusal for the field it breaks, never a parse panic.
#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type", default, deserialize_with = "loose_string")]
    type_: Option<String>,
    #[serde(default, deserialize_with = "loose_string")]
    challenge: Option<String>,
    #[serde(default, deserialize_with = "loose_string")]
    origin: Option<String>,
    /// True when the ceremony ran inside a cross-origin frame. `origin` cannot detect this: an
    /// embedded RP page reports the RP's OWN origin and rpIdHash matches too, so this flag is the
    /// only signal separating "approved on our page" from "approved inside someone else's page"
    /// (W3C WebAuthn L3 §7.2 step 9).
    #[serde(rename = "crossOrigin", default, deserialize_with = "loose_bool")]
    cross_origin: Option<bool>,
    /// WebAuthn L3: the top-level page when the ceremony ran in a frame. Any present value other
    /// than a string equal to `origin` differs from it, as `topOrigin !== origin` does.
    #[serde(rename = "topOrigin", default, deserialize_with = "present_value")]
    top_origin: Option<serde_json::Value>,
}

/// `Some` for any PRESENT value, `null` included (a plain `Option` would read `null` as absent).
fn present_value<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    <serde_json::Value as serde::Deserialize>::deserialize(d).map(Some)
}

fn loose_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
    Ok(v.as_str().map(str::to_owned))
}

fn loose_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
    Ok(v.as_bool())
}

/// Verify one WEBAUTHN witness of a receipt against an already-TRUSTED key (a COSE_Key). Requires
/// `opts.expected_origin` and `opts.expected_rp_id`. The key comes from the caller's trust anchor —
/// never from the receipt.
pub(crate) fn verify_receipt_witness(
    witness: &ApprovalWitness,
    trusted_key: &str,
    receipt: &ApprovalReceipt,
    opts: &VerifyOptions,
) -> Result<(), String> {
    let (Some(authenticator_data), Some(client_data_json)) = (
        witness
            .authenticator_data
            .as_deref()
            .filter(|s| !s.is_empty()),
        witness
            .client_data_json
            .as_deref()
            .filter(|s| !s.is_empty()),
    ) else {
        return Err("WebAuthn witness missing authenticatorData or clientDataJSON".to_string());
    };

    // FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
    let expected_origin = opts.expected_origin.as_deref().filter(|s| !s.is_empty());
    let expected_rp_id = opts.expected_rp_id.as_deref().filter(|s| !s.is_empty());
    let (Some(expected_origin), Some(expected_rp_id)) = (expected_origin, expected_rp_id) else {
        return Err("WebAuthn receipts require expected_origin and expected_rp_id — without them an assertion from any relying party would verify".to_string());
    };
    verify_assertion(
        authenticator_data,
        client_data_json,
        &witness.signature,
        // The COSE key is parsed from the TRUSTED key, not from the receipt's copy.
        trusted_key,
        KeyForm::Cose,
        &receipt.canonical_payload,
        &AssertionExpectation {
            origins: &[expected_origin],
            rp_id: expected_rp_id,
            require_user_verification: opts.require_user_verification.unwrap_or(true),
            allow_cross_origin: opts.allow_cross_origin.unwrap_or(false),
        },
    )
}

/// One WebAuthn assertion and the exact payload it claims to sign — a single stored witness row.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnWitness {
    /// The exact bytes the assertion's challenge commits to (base64url of them is the challenge).
    #[serde(default)]
    pub signed_payload: String,
    /// The credential's P-256 public key, base64: DER SPKI or a COSE_Key. From YOUR trust policy.
    #[serde(default)]
    pub public_key: String,
    /// base64 or base64url, as the browser returned them.
    #[serde(default)]
    pub authenticator_data: String,
    #[serde(default, rename = "clientDataJSON")]
    pub client_data_json: String,
    /// The DER ECDSA assertion signature (a raw r‖s encoding is refused).
    #[serde(default)]
    pub signature: String,
}

/// What a standalone WebAuthn witness must be bound to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebAuthnWitnessExpectation {
    /// The origin(s) the assertion may carry, e.g. `"https://app.example.com"`. Required: at least
    /// one, every one non-empty.
    pub expected_origin: Vec<String>,
    /// The RP ID the authenticatorData must hash to, e.g. `"app.example.com"`. Required.
    pub expected_rp_id: String,
    /// Demand the User-Verified flag. `None` means TRUE; User-Present is always required.
    pub require_user_verification: Option<bool>,
    /// Accept `clientDataJSON.crossOrigin: true` / a differing `topOrigin`. Defaults to false
    /// (DIV §4.4.5 rule 5).
    pub allow_cross_origin: bool,
}

/// Verify ONE WebAuthn assertion on its own — the DIV §4.4.5 checks every receipt verifier here
/// applies to each WEBAUTHN witness, without a receipt around it: one approver of a quorum, a console
/// step-up, a login approval, a row read back out of an audit ledger. Same implementation as the
/// receipt path, not a copy.
///
/// It answers only "did the holder of THIS key sign THIS payload, at THIS relying party, with the
/// user present". It knows nothing of quorum, validity windows, payload type, the signed requirement
/// or who the key belongs to: to verify an approval use `verify_approval_receipt` (or the
/// delegation, agent-authority and platform verifiers), which also enforce those. Never panics on
/// hostile input; every refusal is an `Err` with the reference's reason.
pub fn verify_webauthn_witness(
    witness: &WebAuthnWitness,
    expectation: &WebAuthnWitnessExpectation,
) -> Result<(), String> {
    // Fail closed, as the receipt path does: with nothing pinned, an assertion from any RP verifies.
    if expectation.expected_origin.is_empty()
        || expectation.expected_origin.iter().any(String::is_empty)
        || expectation.expected_rp_id.is_empty()
    {
        return Err("a WebAuthn witness requires expected_origin and expected_rp_id — without them an assertion from any relying party would verify".to_string());
    }
    for (field, value) in [
        ("signedPayload", &witness.signed_payload),
        ("publicKey", &witness.public_key),
        ("authenticatorData", &witness.authenticator_data),
        ("clientDataJSON", &witness.client_data_json),
        ("signature", &witness.signature),
    ] {
        if value.is_empty() {
            return Err(format!("WebAuthn witness missing {field}"));
        }
    }
    let origins: Vec<&str> = expectation
        .expected_origin
        .iter()
        .map(String::as_str)
        .collect();
    verify_assertion(
        &witness.authenticator_data,
        &witness.client_data_json,
        &witness.signature,
        &witness.public_key,
        KeyForm::SpkiOrCose,
        &witness.signed_payload,
        &AssertionExpectation {
            origins: &origins,
            rp_id: &expectation.expected_rp_id,
            require_user_verification: expectation.require_user_verification.unwrap_or(true),
            allow_cross_origin: expectation.allow_cross_origin,
        },
    )
}

/// How the credential key is encoded.
#[derive(Clone, Copy)]
enum KeyForm {
    /// A COSE_Key (the receipt path's trusted keys).
    Cose,
    /// DER SPKI (a SEQUENCE, first byte 0x30) or a COSE_Key (the standalone witness).
    SpkiOrCose,
}

struct AssertionExpectation<'a> {
    origins: &'a [&'a str],
    rp_id: &'a str,
    require_user_verification: bool,
    allow_cross_origin: bool,
}

/// The one WebAuthn assertion check (the reference's `verifyWebAuthnAssertion`). Errors that the
/// reference raises from a decoder or key parser surface as "WebAuthn verification failed: …".
fn verify_assertion(
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
    key: &str,
    form: KeyForm,
    signed_payload: &str,
    expect: &AssertionExpectation<'_>,
) -> Result<(), String> {
    let failed = |why: &str| format!("WebAuthn verification failed: {why}");
    let client_data_buf = decode_base64_flexible(client_data_json)
        .map_err(|_| failed("clientDataJSON is not base64"))?;
    let parsed: serde_json::Value = serde_json::from_slice(&client_data_buf)
        .map_err(|_| failed("clientDataJSON is not valid JSON"))?;
    // `null` has no fields to read (the reference throws reading one); any other non-object simply
    // has no `type`, and is refused as not an assertion.
    if parsed.is_null() {
        return Err(failed("clientDataJSON is null"));
    }
    let client_data: ClientData = if parsed.is_object() {
        serde_json::from_value(parsed).map_err(|_| failed("clientDataJSON is not valid JSON"))?
    } else {
        ClientData {
            type_: None,
            challenge: None,
            origin: None,
            cross_origin: None,
            top_origin: None,
        }
    };

    // An assertion, not a registration: webauthn.create signs a different ceremony over the same
    // challenge bytes and must never be accepted as approval.
    if client_data.type_.as_deref() != Some("webauthn.get") {
        return Err("clientDataJSON is not a webauthn.get assertion".to_string());
    }
    let origin = client_data.origin.as_deref();
    if !origin.is_some_and(|o| expect.origins.contains(&o)) {
        return Err("assertion origin does not match expected_origin".to_string());
    }
    if client_data.cross_origin == Some(true) && !expect.allow_cross_origin {
        return Err(
            "assertion was produced in a cross-origin frame (crossOrigin=true)".to_string(),
        );
    }
    // A topOrigin that differs from origin is the same embedding reported another way, refused
    // exactly like crossOrigin=true (DIV §4.4.5 rule 5) — the gateway refuses it at ingest.
    if client_data
        .top_origin
        .as_ref()
        .is_some_and(|top| top.as_str() != origin)
        && !expect.allow_cross_origin
    {
        return Err(
            "assertion was produced in a frame embedded by another origin (topOrigin differs from origin)"
                .to_string(),
        );
    }
    let Some(challenge) = client_data.challenge.as_deref() else {
        return Err(failed("clientDataJSON challenge is not a string"));
    };
    let expected_challenge = URL_SAFE_NO_PAD.encode(signed_payload.as_bytes());
    let client_challenge: String = challenge
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    if client_challenge != expected_challenge {
        return Err("clientDataJSON challenge does not match canonical payload".to_string());
    }

    let auth_data = decode_base64_flexible(authenticator_data)
        .map_err(|_| failed("authenticatorData is not base64"))?;
    if auth_data.len() < 37 {
        return Err("authenticatorData is too short".to_string());
    }
    let rp_id_hash = Sha256::digest(expect.rp_id.as_bytes());
    // Constant-time compare of the 32-byte rpIdHash.
    if !constant_time_eq(&auth_data[..32], &rp_id_hash) {
        return Err("authenticatorData rpIdHash does not match expected_rp_id".to_string());
    }
    let flags = auth_data[32];
    if flags & AUTH_DATA_FLAG_UP == 0 {
        return Err("authenticatorData user-present flag is not set".to_string());
    }
    if expect.require_user_verification && flags & AUTH_DATA_FLAG_UV == 0 {
        return Err("authenticatorData user-verified flag is not set".to_string());
    }

    let key_buf = decode_base64_flexible(key).map_err(|_| failed("public key is not base64"))?;
    let verifying_key = match form {
        KeyForm::SpkiOrCose if key_buf.first() == Some(&0x30) => spki_p256_key(&key_buf),
        _ => parse_cose_p256_key(&key_buf).map_err(|why| capitalized(&why)),
    }
    .map_err(|why| failed(&why))?;

    let sig_bytes = decode_base64_flexible(signature).unwrap_or_default();
    let client_data_hash = Sha256::digest(&client_data_buf);
    let mut signed_data = auth_data;
    signed_data.extend_from_slice(&client_data_hash);

    // A WebAuthn ES256 assertion signature is ASN.1 DER (WebAuthn §6.5.6); unlike a bare-key ES256
    // witness, a raw r||s encoding is refused, as in every other port.
    let der_only = p256::ecdsa::Signature::from_der(&sig_bytes)
        .ok()
        .map(|sig| {
            use p256::ecdsa::signature::Verifier;
            verifying_key.verify(&signed_data, &sig).is_ok()
        })
        .unwrap_or(false);
    if der_only {
        Ok(())
    } else {
        Err("WebAuthn signature does not verify against the trusted signer key".to_string())
    }
}

/// A DER SPKI credential key, pinned to P-256 (the reference refuses any other key type or curve).
fn spki_p256_key(der: &[u8]) -> Result<VerifyingKey, String> {
    use p256::pkcs8::DecodePublicKey;
    match p256::PublicKey::from_public_key_der(der) {
        Ok(key) => Ok(VerifyingKey::from(&key)),
        // A well-formed SPKI for another algorithm or curve, or not an SPKI at all.
        Err(_) => Err("public key is not a P-256 key".to_string()),
    }
}

/// The reference spells the COSE parser's errors "Invalid COSE public key format: …".
fn capitalized(why: &str) -> String {
    match why.strip_prefix("invalid COSE") {
        Some(rest) => format!("Invalid COSE{rest}"),
        None => why.to_string(),
    }
}

/// Constant-time equality for equal-length byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
