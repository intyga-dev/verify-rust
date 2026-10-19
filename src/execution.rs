//! DEWP §4.7 — execution evidence, mirroring `ledger-execution.ts` in @intyga/verify.
//!
//! A Dispatch Record says the executing party sent an approved action; an Evidence Record carries a
//! statement an independent evidence source signed about whether it took effect. The status derived
//! here reports what a CALLER-TRUSTED source observed, never what physically happened (§4.7.6), and it
//! never changes commitment, content, signature or anchor verification.
//!
//! The executing party writes Dispatch Records, so nothing it writes may decide the verdict on its
//! own: a statement binds to ANY Dispatch Record whose hash matches (an early record with another
//! hash is a reported conflict, not a way to unbind a trusted contradiction), the evidence window is
//! bounded by the caller and never by the dispatch alone, every Approval Record's nonce is reported so
//! a silent approval shows as `not_reported`, and a trusted `contradicted` sampled after the deadline
//! is its own alert rather than a dropped statement.

use crate::bundle::{verify_embedded_signature, AuditSignatureCheck};
use serde::de::Deserializer;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Signed statement `type` (DEWP §4.7.2), distinct from every DIV payload type.
pub const DEWP_EXECUTION_EVIDENCE_TYPE: &str = "dewp-execution-evidence";
pub const EXECUTION_DISPATCHED: &str = "EXECUTION_DISPATCHED";
pub const EXECUTION_CONFIRMED: &str = "EXECUTION_CONFIRMED";
pub const EXECUTION_CONTRADICTED: &str = "EXECUTION_CONTRADICTED";
pub const EXECUTION_UNCONFIRMED: &str = "EXECUTION_UNCONFIRMED";
/// DEWP §4.7.2 rule 10.
pub const MAX_EXECUTION_EVIDENCE_BYTES: usize = 16_384;
/// DEWP §4.7.3 step 6: the default allowance before the dispatch time, caller-overridable. It covers
/// clock error between the source and the producer and nothing else — it also admits a measurement
/// taken just before dispatch, which for an action with no visible change confirms a no-op — so it
/// is small.
pub const DEFAULT_EVIDENCE_SKEW_SECONDS: i64 = 30;
/// DEWP §4.7.3 step 6: the default maximum evidence window, caller-overridable. The executing party
/// chooses `evidenceDeadline`; without this bound a far-out deadline keeps a nonce `pending` forever
/// and `unconfirmed` never fires.
pub const DEFAULT_MAX_EVIDENCE_WINDOW_SECONDS: i64 = 86_400;
const DIV_INTENT_TYPE: &str = "div-intent-verification";
/// DEWP §4.7.7: arrays and objects nest at most this deep, the outermost value counting as 1.
pub const MAX_SIGNED_PAYLOAD_DEPTH: usize = 64;
/// DEWP §4.7.2 rules 8 and 12: every statement number's magnitude is at most 2^53 − 1.
const MAX_STATEMENT_NUMBER: f64 = 9_007_199_254_740_991.0;
const MAX_STATEMENT_INTEGER: u64 = 9_007_199_254_740_991;
const STATEMENT_KEYS: [&str; 9] = [
    "approval",
    "observation",
    "observedAt",
    "sampledAt",
    "sequence",
    "source",
    "type",
    "v",
    "verdict",
];

/// True when `text` nests arrays/objects deeper than `limit`, scanned without parsing.
fn nests_deeper_than(text: &str, limit: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for c in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'[' || c == b'{' {
            depth += 1;
            if depth > limit {
                return true;
            }
        } else if c == b']' || c == b'}' {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

fn every_number(value: &Value, ok: &dyn Fn(&serde_json::Number) -> bool) -> bool {
    match value {
        Value::Number(n) => ok(n),
        Value::Array(a) => a.iter().all(|v| every_number(v, ok)),
        Value::Object(m) => m.values().all(|v| every_number(v, ok)),
        _ => true,
    }
}

fn number_magnitude(n: &serde_json::Number) -> f64 {
    n.as_i64()
        .map(|i| (i as f64).abs())
        .or_else(|| n.as_u64().map(|u| u as f64))
        .or_else(|| n.as_f64().map(f64::abs))
        .unwrap_or(f64::INFINITY)
}

/// DEWP §4.7.7: the one way §4.7 parses a signed payload. serde_json already refuses trailing
/// content, NaN/Infinity literals and numbers outside the double range; the depth bound is scanned
/// first so serde_json's own recursion limit (128) never decides.
pub fn parse_signed_payload(text: &str) -> Option<Value> {
    if nests_deeper_than(text, MAX_SIGNED_PAYLOAD_DEPTH) {
        return None;
    }
    let value: Value = serde_json::from_str(text).ok()?;
    every_number(&value, &|n| number_magnitude(n).is_finite()).then_some(value)
}

/// The object an evidence source signs (DEWP §4.7.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionEvidenceStatement {
    pub nonce: String,
    pub payload_sha256: String,
    pub observation: Map<String, Value>,
    /// When the source produced the statement (rule 6).
    pub observed_at: String,
    /// When the measurement behind `observation` was taken (rule 11); the window is evaluated on it.
    pub sampled_at: String,
    /// The source's own gapless, per-log counter (rule 12): 1..=2^53 − 1.
    pub sequence: u64,
    pub source: String,
    pub verdict: String,
}

/// One caller-trusted key for an evidence source (DEWP §4.7.5): a bare base64 SPKI P-256 key, valid
/// at any time, or the key with a validity interval — each bound a §4.3 timestamp, both inclusive,
/// either optional. A bounded key establishes trust only at the record's ANCHORED time.
///
/// Deserializes from the policy's JSON form: a string, or an object with exactly the members `key`,
/// `notBefore` and `notAfter` (the last two optional). An object entry with any OTHER member, or
/// with a bound that is present but not a string, is kept with its key as
/// [`TrustedSourceKey::Malformed`]: it verifies a signature but never establishes trust — a
/// misspelt `notafter` or a numeric bound fails closed, never reads as "no bound". An entry with no
/// usable string key is [`TrustedSourceKey::Unusable`] and is dropped (not provisioned), as the
/// reference implementation drops it, rather than failing the whole policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedSourceKey {
    Key(String),
    Bounded {
        key: String,
        not_before: Option<String>,
        not_after: Option<String>,
    },
    /// An object entry whose key is usable but whose shape is not (DEWP §4.7.5). `entry` is the
    /// object as given, so the policy serializes back exactly and stays malformed on a round trip.
    Malformed {
        key: String,
        /// Why the entry establishes no trust, naming the member or bound.
        reason: String,
        entry: Map<String, Value>,
    },
    /// No usable string key: nothing can verify under it.
    Unusable,
}

const KEY_ENTRY_MEMBERS: [&str; 3] = ["key", "notBefore", "notAfter"];

impl From<Value> for TrustedSourceKey {
    fn from(v: Value) -> Self {
        match v {
            Value::String(key) => TrustedSourceKey::Key(key),
            Value::Object(m) => {
                let Some(key) = m
                    .get("key")
                    .and_then(Value::as_str)
                    .filter(|k| !k.is_empty())
                    .map(str::to_owned)
                else {
                    return TrustedSourceKey::Unusable;
                };
                let unknown: Vec<&str> = m
                    .keys()
                    .map(String::as_str)
                    .filter(|k| !KEY_ENTRY_MEMBERS.contains(k))
                    .collect();
                let bad_bound = ["notBefore", "notAfter"]
                    .into_iter()
                    .find(|b| m.get(*b).is_some_and(|v| !v.is_string()));
                let reason = if !unknown.is_empty() {
                    Some(format!(
                        "Caller key entry has unexpected member(s) {}; it does not establish trust.",
                        unknown.join(", ")
                    ))
                } else {
                    bad_bound.map(|b| {
                        format!(
                            "Caller key entry's {b} is not a timestamp string; it does not establish trust."
                        )
                    })
                };
                match reason {
                    Some(reason) => TrustedSourceKey::Malformed {
                        key,
                        reason,
                        entry: m,
                    },
                    None => TrustedSourceKey::Bounded {
                        key,
                        not_before: m
                            .get("notBefore")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        not_after: m.get("notAfter").and_then(Value::as_str).map(str::to_owned),
                    },
                }
            }
            _ => TrustedSourceKey::Unusable,
        }
    }
}

impl<'de> Deserialize<'de> for TrustedSourceKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Value::deserialize(d).map(TrustedSourceKey::from)
    }
}

impl Serialize for TrustedSourceKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            TrustedSourceKey::Key(key) => s.serialize_str(key),
            TrustedSourceKey::Bounded {
                key,
                not_before,
                not_after,
            } => {
                let mut m = s.serialize_map(None)?;
                m.serialize_entry("key", key)?;
                if let Some(t) = not_before {
                    m.serialize_entry("notBefore", t)?;
                }
                if let Some(t) = not_after {
                    m.serialize_entry("notAfter", t)?;
                }
                m.end()
            }
            TrustedSourceKey::Malformed { entry, .. } => entry.serialize(s),
            TrustedSourceKey::Unusable => s.serialize_none(),
        }
    }
}

/// Caller-owned evidence-source trust: source → keys, separate from approver trust (§4.7.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionEvidencePolicy {
    pub trusted_sources: BTreeMap<String, Vec<TrustedSourceKey>>,
}

/// DEWP §4.7.3 result for one Evidence Record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionEvidenceCheck {
    pub status: String,
    pub reason: String,
    /// True only when the statement verified under a caller-provisioned key valid for its source.
    pub trusted: bool,
    pub nonce: Option<String>,
    pub verdict: Option<String>,
    /// The statement's `source` and `sequence` once it parsed; None before that.
    pub source: Option<String>,
    pub sequence: Option<u64>,
}

/// DEWP §4.7.4 status of one approval nonce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionNonceStatus {
    pub status: String,
    /// The governing Dispatch Record (DEWP §4.7.3 step 5 / §4.7.4), or None.
    pub dispatch_seq: Option<String>,
    /// Its own `evidenceDeadline`, as written by the executing party.
    pub evidence_deadline: Option<String>,
    /// The deadline the status was evaluated against: `evidence_deadline` cut to the caller's window.
    pub effective_deadline: Option<String>,
    /// True when the record's own deadline lay beyond the caller's maximum window (§4.7.4).
    pub window_capped: bool,
    /// Dispatch Records for this nonce that disagree on `payloadSha256`; empty when they agree.
    pub dispatch_conflict: Vec<String>,
    /// Trusted, bound `contradicted` statements sampled after the effective deadline (§4.7.4).
    pub late_contradiction: Vec<String>,
    /// Bound, in-window or late `contradicted` statements whose signature verified under a caller-provisioned
    /// key that did not establish trust — its validity could not be placed in time, the record lay
    /// outside it, or the entry was malformed (§4.7.4, §4.7.5). They cannot decide the status; they
    /// are never silent.
    pub untrusted_contradiction: Vec<String>,
    pub evidence_seqs: Vec<String>,
}

/// DEWP §4.7.3 "Source continuity": what one source's counter shows inside the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceContinuity {
    /// Smallest and largest `sequence` seen from this source.
    pub first: u64,
    pub last: u64,
    /// Inclusive ranges of counter values between `first` and `last` that no record carries.
    pub gaps: Vec<(u64, u64)>,
    /// Counter values carried by two or more records whose statement bytes differ.
    pub divergent: Vec<u64>,
}

/// DEWP §4.7 over one evidence bundle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecutionVerification {
    /// One check per Evidence Record, in bundle order, with its seq.
    pub checks: Vec<(String, ExecutionEvidenceCheck)>,
    /// DEWP §4.7.4 status per approval nonce named by an Approval, Dispatch or Evidence Record.
    pub by_nonce: BTreeMap<String, ExecutionNonceStatus>,
    pub confirmed: Vec<String>,
    pub contradicted: Vec<String>,
    pub unconfirmed: Vec<String>,
    pub pending: Vec<String>,
    pub not_reported: Vec<String>,
    /// Nonces with a late contradiction — the alert that most needs escalation (§4.7.4).
    pub late_contradicted: Vec<String>,
    /// Nonces with a contradiction under a provisioned key that established no trust (§4.7.4).
    pub untrusted_contradicted: Vec<String>,
    /// Nonces whose Dispatch Records disagree (§4.7.4).
    pub dispatch_conflicts: Vec<String>,
    /// Per-source continuity over the statements whose signature verified (§4.7.3).
    pub sources: BTreeMap<String, SourceContinuity>,
}

/// Caller options for DEWP §4.7 over an evidence bundle.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOptions {
    /// Evidence-source trust, separate from approver trust (§4.7.5).
    pub evidence_policy: Option<ExecutionEvidencePolicy>,
    /// Fail the bundle unless it reports at least one approval nonce and every one is confirmed,
    /// with no dispatch conflict, late contradiction, untrusted contradiction, source gap or
    /// divergence (§4.7.4).
    pub require_execution_confirmed: bool,
    /// The §4.7.4 evaluation time in Unix milliseconds (None: the current time).
    pub now_ms: Option<i64>,
    /// The §4.7.3 allowance before dispatch in seconds (None or negative: 30).
    pub skew_seconds: Option<i64>,
    /// The §4.7.3 maximum evidence window in seconds (None or negative: 86 400).
    pub max_window_seconds: Option<i64>,
}

/// The anchored time of the record at `seq` (Unix ms): the earliest external witness time among
/// anchors that counted toward quorum for a checkpoint covering it — or None when none does (DEWP
/// §4.7.5).
pub type AnchoredTimeFn<'a> = &'a dyn Fn(&str) -> Option<i64>;

/// Options for [`evaluate_execution_evidence_with_options`].
#[derive(Clone, Copy, Default)]
pub struct ExecutionEvaluationOptions<'a> {
    pub policy: Option<&'a ExecutionEvidencePolicy>,
    /// Evaluation time, Unix ms; None: the current time. An input, so a status is reproducible.
    pub now_ms: Option<i64>,
    pub skew_seconds: Option<i64>,
    pub max_window_seconds: Option<i64>,
    /// Only consulted for caller keys that carry a validity interval.
    pub anchored_time: Option<AnchoredTimeFn<'a>>,
}

/// A DEWP §4.3 timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`) naming a real instant, as Unix milliseconds.
pub(crate) fn dewp_timestamp_ms(value: &Value) -> Option<i64> {
    dewp_timestamp_str_ms(value.as_str()?)
}

fn dewp_timestamp_str_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24 || b[19] != b'.' || b[23] != b'Z' || !b[20..23].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let secs = crate::parse_rfc3339_utc_secs(s)?;
    let millis: i64 = s[20..23].parse().ok()?;
    Some(secs * 1000 + millis)
}

/// Unix milliseconds as JavaScript's `Date.prototype.toISOString()` prints them (a year outside
/// 0000–9999 takes the six-digit signed form, as there).
fn iso_from_ms(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        (rem / 60_000) % 60,
        (rem / 1_000) % 60,
        rem % 1_000
    )
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn keys_are(obj: &Map<String, Value>, expected: &[&str]) -> bool {
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    keys.len() == expected.len() && expected.iter().all(|k| keys.contains(k))
}

/// DEWP §4.7.2 rules 1–3 and 5–12. Rule 4 (source equals the record's signer) needs the record.
pub fn parse_execution_evidence_statement(
    bytes: &str,
) -> Result<ExecutionEvidenceStatement, String> {
    if bytes.len() > MAX_EXECUTION_EVIDENCE_BYTES {
        return Err(format!(
            "statement exceeds {MAX_EXECUTION_EVIDENCE_BYTES} bytes"
        ));
    }
    let value = parse_signed_payload(bytes).ok_or("statement does not parse (DEWP §4.7.7)")?;
    // Integers above 2^53 − 1 are exact here but not in a double-based parser (rule 8).
    if !every_number(&value, &|n| {
        n.as_u64().map_or(true, |u| u <= MAX_STATEMENT_INTEGER)
            && n.as_i64()
                .map_or(true, |i| i.unsigned_abs() <= MAX_STATEMENT_INTEGER)
            && number_magnitude(n) <= MAX_STATEMENT_NUMBER
    }) {
        return Err("a statement number exceeds 2^53 - 1".into());
    }
    // Re-serializing must reproduce the bytes: refuses duplicate members, whitespace, non-portable
    // numbers and lone surrogates, so every port reads one statement from one byte string.
    let canonical =
        crate::stable_stringify(&value).map_err(|e| format!("statement is not canonical: {e}"))?;
    if canonical != bytes {
        return Err("statement is not in RFC 8785 canonical form".into());
    }
    let obj = value.as_object().ok_or("statement is not a JSON object")?;
    if !keys_are(obj, &STATEMENT_KEYS) {
        return Err(format!(
            "statement must have exactly the members {}",
            STATEMENT_KEYS.join(", ")
        ));
    }
    if obj["type"].as_str() != Some(DEWP_EXECUTION_EVIDENCE_TYPE) {
        return Err(format!(
            "statement type is not {DEWP_EXECUTION_EVIDENCE_TYPE}"
        ));
    }
    if obj["v"].as_u64() != Some(1) {
        return Err("statement version v must be 1".into());
    }
    let approval = obj["approval"]
        .as_object()
        .ok_or("approval must be an object")?;
    if !keys_are(approval, &["nonce", "payloadSha256"]) {
        return Err("approval must have exactly the members nonce, payloadSha256".into());
    }
    let nonce = approval["nonce"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("approval.nonce must be a non-empty string")?;
    let digest = approval["payloadSha256"]
        .as_str()
        .filter(|s| is_hex64(s))
        .ok_or("approval.payloadSha256 must be 64 lowercase hex characters")?;
    let source = obj["source"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("source must be a non-empty string")?;
    let verdict = obj["verdict"]
        .as_str()
        .filter(|v| *v == "confirmed" || *v == "contradicted")
        .ok_or("verdict must be confirmed or contradicted")?;
    let observed_ms = dewp_timestamp_ms(&obj["observedAt"])
        .ok_or("observedAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")?;
    let sampled_ms = dewp_timestamp_ms(&obj["sampledAt"])
        .ok_or("sampledAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")?;
    if sampled_ms > observed_ms {
        return Err("sampledAt must not be later than observedAt".into());
    }
    // A float spelling (`418.0`) or fraction never reaches here: the canonical check above refuses
    // the former and `as_u64` the latter; the magnitude check bounds it above.
    let sequence = obj["sequence"]
        .as_u64()
        .filter(|n| *n >= 1)
        .ok_or("sequence must be an integer from 1 to 2^53 − 1")?;
    let observation = obj["observation"]
        .as_object()
        .ok_or("observation must be an object")?;
    Ok(ExecutionEvidenceStatement {
        nonce: nonce.into(),
        payload_sha256: digest.into(),
        observation: observation.clone(),
        observed_at: obj["observedAt"].as_str().unwrap_or_default().into(),
        sampled_at: obj["sampledAt"].as_str().unwrap_or_default().into(),
        sequence,
        source: source.into(),
        verdict: verdict.into(),
    })
}

/// Canonical statement bytes an evidence source signs (DEWP §4.7.2). `Err` on input the statement
/// rules refuse, so a source never signs bytes a verifier rejects as malformed.
pub fn canonical_execution_evidence_statement(
    s: &ExecutionEvidenceStatement,
) -> Result<String, String> {
    let bytes = crate::stable_stringify(&serde_json::json!({
        "approval": {"nonce": s.nonce, "payloadSha256": s.payload_sha256},
        "observation": Value::Object(s.observation.clone()),
        "observedAt": s.observed_at,
        "sampledAt": s.sampled_at,
        "sequence": s.sequence,
        "source": s.source,
        "type": DEWP_EXECUTION_EVIDENCE_TYPE,
        "v": 1,
        "verdict": s.verdict,
    }))?;
    parse_execution_evidence_statement(&bytes)?;
    Ok(bytes)
}

/// Lowercase hex SHA-256 of a DIV Intent Payload's UTF-8 bytes — the statement's `payloadSha256`.
pub fn execution_payload_sha256(canonical_payload: &str) -> String {
    Sha256::digest(canonical_payload.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn payload_object(signed_payload: &Value) -> Option<Map<String, Value>> {
    let text = signed_payload.as_str().filter(|s| !s.is_empty())?;
    match parse_signed_payload(text) {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// True when a leaf's signed payload is an Execution Evidence Statement (DEWP §4.7.3).
pub fn is_execution_evidence_payload(signed_payload: &Value) -> bool {
    payload_object(signed_payload).is_some_and(|m| {
        m.get("type").and_then(Value::as_str) == Some(DEWP_EXECUTION_EVIDENCE_TYPE)
    })
}

/// An Evidence Record: its event says so, or its payload is a statement — either suffices, so a record
/// cannot dodge evidence-source trust by mislabelling one side (§4.7.3, §4.7.5).
pub fn is_execution_evidence_leaf(leaf: &Value) -> bool {
    matches!(
        leaf["event"].as_str(),
        Some(EXECUTION_CONFIRMED) | Some(EXECUTION_CONTRADICTED)
    ) || is_execution_evidence_payload(&leaf["signedPayload"])
}

fn sig(status: &str, reason: &str, trusted: bool) -> AuditSignatureCheck {
    AuditSignatureCheck {
        status: status.into(),
        reason: reason.into(),
        trusted,
    }
}

struct NormalizedKey {
    key: String,
    not_before: Option<String>,
    not_after: Option<String>,
    /// Why this entry can verify a signature but never establish trust (§4.7.5), or None.
    malformed: Option<String>,
}

/// The caller's keys for a source as `{key, not_before, not_after, malformed}`. An entry with no
/// usable key is dropped (nothing can verify under it). A [`TrustedSourceKey::Malformed`] entry is
/// kept with its key and its reason: a misspelt `notafter` or a numeric bound must fail closed,
/// never read as "no bound".
fn trusted_keys_for(policy: &ExecutionEvidencePolicy, source: Option<&str>) -> Vec<NormalizedKey> {
    let Some(entries) = source.and_then(|s| policy.trusted_sources.get(s)) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| match entry {
            TrustedSourceKey::Key(key) if !key.is_empty() => Some(NormalizedKey {
                key: key.clone(),
                not_before: None,
                not_after: None,
                malformed: None,
            }),
            TrustedSourceKey::Bounded {
                key,
                not_before,
                not_after,
            } if !key.is_empty() => Some(NormalizedKey {
                key: key.clone(),
                not_before: not_before.clone(),
                not_after: not_after.clone(),
                malformed: None,
            }),
            TrustedSourceKey::Malformed { key, reason, .. } if !key.is_empty() => {
                Some(NormalizedKey {
                    key: key.clone(),
                    not_before: None,
                    not_after: None,
                    malformed: Some(reason.clone()),
                })
            }
            _ => None,
        })
        .collect()
}

/// DEWP §4.7.5: a bounded key establishes trust only at the record's anchored time. `observedAt` and
/// `sampledAt` are the source's own claims and are never used here — a compromised key could place a
/// statement inside the period when it was still valid; a witness cannot be backdated.
fn key_valid_at(k: &NormalizedKey, anchored_time_ms: Option<i64>) -> Result<(), String> {
    if let Some(reason) = &k.malformed {
        return Err(reason.clone());
    }
    if k.not_before.is_none() && k.not_after.is_none() {
        return Ok(());
    }
    let bound = |t: &Option<String>| -> Result<Option<i64>, String> {
        match t {
            None => Ok(None),
            Some(s) => dewp_timestamp_str_ms(s).map(Some).ok_or_else(|| {
                "Caller key carries a malformed validity interval; it does not establish trust."
                    .to_string()
            }),
        }
    };
    let from = bound(&k.not_before)?;
    let to = bound(&k.not_after)?;
    let Some(at) = anchored_time_ms else {
        return Err("Caller key carries a validity interval but no counting anchor covers this record, so the key cannot be placed in time (DEWP §4.7.5); it does not establish trust.".into());
    };
    if from.is_some_and(|f| at < f) || to.is_some_and(|t| at > t) {
        return Err("Caller key was not valid at this record's anchored time (DEWP §4.7.5); it does not establish trust.".into());
    }
    Ok(())
}

/// ES256 under caller-provisioned keys for the statement's source (evidence-source trust only): an
/// approver key never verifies a statement, and an evidence key never verifies an approval (§4.7.5).
/// A bounded key is placed in time by nothing here, so it verifies the signature but establishes no
/// trust; see [`verify_evidence_signature_at`].
pub fn verify_evidence_signature(
    leaf: &Value,
    policy: Option<&ExecutionEvidencePolicy>,
) -> AuditSignatureCheck {
    verify_evidence_signature_at(leaf, policy, None)
}

/// [`verify_evidence_signature`] with the record's anchored time (Unix ms; None when no counting
/// anchor covers it). A key with a validity interval verifies the signature but establishes trust
/// only when the anchored time lies inside the interval (DEWP §4.7.5).
pub fn verify_evidence_signature_at(
    leaf: &Value,
    policy: Option<&ExecutionEvidencePolicy>,
    anchored_time_ms: Option<i64>,
) -> AuditSignatureCheck {
    let Some(policy) = policy else {
        return if verify_embedded_signature(leaf) {
            sig(
                "verified",
                "Signature valid under embedded key; source identity is not established.",
                false,
            )
        } else {
            sig("invalid", "Statement signature does not verify.", false)
        };
    };
    let keys = trusted_keys_for(policy, leaf["signerDid"].as_str());
    if keys.is_empty() {
        return sig(
            "not_checked",
            "No caller-trusted key for this evidence source.",
            false,
        );
    }
    let mut untrusted_reason: Option<String> = None;
    for k in &keys {
        let mut clone = leaf.clone();
        clone["signerPublicKey"] = Value::String(k.key.clone());
        if !verify_embedded_signature(&clone) {
            continue;
        }
        match key_valid_at(k, anchored_time_ms) {
            Ok(()) => {
                return sig(
                    "verified",
                    "Statement valid under caller-trusted source key.",
                    true,
                )
            }
            Err(reason) => {
                untrusted_reason.get_or_insert(reason);
            }
        }
    }
    if let Some(reason) = untrusted_reason {
        return sig("verified", &reason, false);
    }
    sig(
        "invalid",
        "Statement signature does not verify under caller trust.",
        false,
    )
}

fn check(
    status: &str,
    reason: &str,
    s: Option<&ExecutionEvidenceStatement>,
    trusted: bool,
) -> ExecutionEvidenceCheck {
    ExecutionEvidenceCheck {
        status: status.into(),
        reason: reason.into(),
        trusted,
        nonce: s.map(|s| s.nonce.clone()),
        verdict: s.map(|s| s.verdict.clone()),
        source: s.map(|s| s.source.clone()),
        sequence: s.map(|s| s.sequence),
    }
}

fn with_note(reason: &str, note: Option<&str>) -> String {
    match note {
        Some(n) => format!("{reason} {n}"),
        None => reason.to_string(),
    }
}

/// What a leaf established on its own once DEWP §4.7.3 steps 1–4 passed.
struct Passed {
    statement: ExecutionEvidenceStatement,
    trusted: bool,
    /// Why a verified signature under a policy is nonetheless untrusted (a bounded key outside its
    /// interval, or no anchored time); the embedded-key case needs no note, the status says it.
    note: Option<String>,
}

/// DEWP §4.7.3 steps 1–4: a decided check, or the statement and its trust.
// The `Err` is the decided check itself — a result, not a failure path worth boxing.
#[allow(clippy::result_large_err)]
fn check_leaf(
    leaf: &Value,
    policy: Option<&ExecutionEvidencePolicy>,
    anchored_time_ms: Option<i64>,
) -> Result<Passed, ExecutionEvidenceCheck> {
    let present = |k: &str| leaf[k].as_str().is_some_and(|s| !s.is_empty());
    if leaf["sigAlg"].as_str() != Some("ES256")
        || !present("signature")
        || !present("signerPublicKey")
        || !present("signedPayload")
    {
        return Err(check(
            "invalid",
            "Evidence Records must carry an ES256 signature, public key and statement.",
            None,
            false,
        ));
    }
    let s = parse_execution_evidence_statement(leaf["signedPayload"].as_str().unwrap_or_default())
        .map_err(|e| {
            check(
                "invalid",
                &format!("Malformed statement: {e}."),
                None,
                false,
            )
        })?;
    if Some(s.source.as_str()) != leaf["signerDid"].as_str() {
        return Err(check(
            "invalid",
            "Statement source does not match the record's signerDid.",
            Some(&s),
            false,
        ));
    }
    let (event, outcome) = if s.verdict == "confirmed" {
        (EXECUTION_CONFIRMED, "SUCCESS")
    } else {
        (EXECUTION_CONTRADICTED, "FAILURE")
    };
    if leaf["event"].as_str() != Some(event) || leaf["outcome"].as_str() != Some(outcome) {
        return Err(check(
            "invalid",
            "Record event/outcome do not match the signed verdict.",
            Some(&s),
            false,
        ));
    }
    let signature = verify_evidence_signature_at(leaf, policy, anchored_time_ms);
    if signature.status != "verified" {
        return Err(check(&signature.status, &signature.reason, Some(&s), false));
    }
    let note = (policy.is_some() && !signature.trusted).then_some(signature.reason);
    Ok(Passed {
        statement: s,
        trusted: signature.trusted,
        note,
    })
}

/// DEWP §4.7.3 for a leaf seen alone (a single proof): never verified, at best unbound.
pub fn check_execution_evidence_leaf(
    leaf: &Value,
    policy: Option<&ExecutionEvidencePolicy>,
) -> ExecutionEvidenceCheck {
    check_execution_evidence_leaf_at(leaf, policy, None)
}

/// [`check_execution_evidence_leaf`] with the record's anchored time (DEWP §4.7.5): the earliest
/// external witness time among the anchors that counted toward quorum over the proof's root, or
/// None when none did. Only a caller key with a validity interval consults it.
pub fn check_execution_evidence_leaf_at(
    leaf: &Value,
    policy: Option<&ExecutionEvidencePolicy>,
    anchored_time_ms: Option<i64>,
) -> ExecutionEvidenceCheck {
    match check_leaf(leaf, policy, anchored_time_ms) {
        Err(decided) => decided,
        Ok(p) => check(
            "unbound",
            &with_note(
                "A single proof cannot bind a statement to its dispatch and approval records.",
                p.note.as_deref(),
            ),
            Some(&p.statement),
            p.trusted,
        ),
    }
}

#[derive(Clone)]
struct Dispatch {
    seq: String,
    created_at_ms: i64,
    deadline: String,
    deadline_ms: i64,
    payload_sha256: String,
}

/// A valid Dispatch Record's governing fields, or None when the record does not qualify.
fn dispatch_of(leaf: &Value) -> Option<(String, Dispatch)> {
    if leaf["event"].as_str() != Some(EXECUTION_DISPATCHED) {
        return None;
    }
    let m = leaf["metadata"].as_object()?;
    let nonce = m.get("nonce")?.as_str().filter(|s| !s.is_empty())?;
    let digest = m.get("payloadSha256")?.as_str().filter(|s| is_hex64(s))?;
    let deadline_value = m.get("evidenceDeadline")?;
    let deadline_ms = dewp_timestamp_ms(deadline_value)?;
    let created_at_ms = dewp_timestamp_ms(&leaf["createdAt"])?;
    Some((
        nonce.into(),
        Dispatch {
            seq: leaf["seq"].as_str().unwrap_or_default().into(),
            created_at_ms,
            deadline: deadline_value.as_str().unwrap_or_default().into(),
            deadline_ms,
            payload_sha256: digest.into(),
        },
    ))
}

/// Numeric seq order; a non-numeric seq (which a verified entry cannot have) sorts last.
fn seq_key(seq: &str) -> (u8, u128) {
    if !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = seq.parse::<u128>() {
            return (0, n);
        }
    }
    (1, 0)
}

fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// The deadline a status is evaluated against: the record's own, cut to the caller's window.
fn effective_deadline_of(d: &Dispatch, max_window_ms: i64) -> (i64, bool) {
    let bound = d.created_at_ms.saturating_add(max_window_ms);
    if d.deadline_ms > bound {
        (bound, true)
    } else {
        (d.deadline_ms, false)
    }
}

/// DEWP §4.7.3 "Source continuity" over the records that passed step 4.
fn continuity(
    records: &BTreeMap<String, Vec<(u64, String)>>,
) -> BTreeMap<String, SourceContinuity> {
    let mut out = BTreeMap::new();
    for (source, list) in records {
        let mut by_sequence: BTreeMap<u64, HashSet<&str>> = BTreeMap::new();
        for (sequence, bytes) in list {
            by_sequence
                .entry(*sequence)
                .or_default()
                .insert(bytes.as_str());
        }
        let seen: Vec<u64> = by_sequence.keys().copied().collect();
        let (Some(&first), Some(&last)) = (seen.first(), seen.last()) else {
            continue;
        };
        // Gaps as ranges: a source that signed 1 and 2^53 − 1 must not make the verifier enumerate
        // the numbers in between.
        let gaps = seen
            .windows(2)
            .filter(|w| w[1] - w[0] > 1)
            .map(|w| (w[0] + 1, w[1] - 1))
            .collect();
        let divergent = seen
            .iter()
            .copied()
            .filter(|s| by_sequence.get(s).is_some_and(|set| set.len() > 1))
            .collect();
        out.insert(
            source.clone(),
            SourceContinuity {
                first,
                last,
                gaps,
                divergent,
            },
        );
    }
    out
}

/// DEWP §4.7.3–§4.7.4 over the CONTENT-VERIFIED entries (`(seq, leaf)`) of one evidence bundle,
/// with the default evidence window and no anchored time (every bounded key is then untrusted).
pub fn evaluate_execution_evidence(
    entries: &[(String, Value)],
    policy: Option<&ExecutionEvidencePolicy>,
    now_ms: Option<i64>,
    skew_seconds: Option<i64>,
) -> ExecutionVerification {
    evaluate_execution_evidence_with_options(
        entries,
        &ExecutionEvaluationOptions {
            policy,
            now_ms,
            skew_seconds,
            max_window_seconds: None,
            anchored_time: None,
        },
    )
}

/// A caller bound in seconds, or the default: a value that is not a non-negative number is no bound
/// at all, so it falls back rather than removing the window cap or the early-sample limit.
fn bounded_seconds(value: Option<i64>, fallback: i64) -> i64 {
    value.filter(|v| *v >= 0).unwrap_or(fallback)
}

/// DEWP §4.7.3–§4.7.4 over the CONTENT-VERIFIED entries (`(seq, leaf)`) of one evidence bundle.
/// `now_ms` is the evaluation time and is an input so a status is reproducible.
pub fn evaluate_execution_evidence_with_options(
    entries: &[(String, Value)],
    opts: &ExecutionEvaluationOptions<'_>,
) -> ExecutionVerification {
    let now_ms = opts.now_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(i64::MAX)
    });
    let skew_ms =
        bounded_seconds(opts.skew_seconds, DEFAULT_EVIDENCE_SKEW_SECONDS).saturating_mul(1000);
    let max_window_ms =
        bounded_seconds(opts.max_window_seconds, DEFAULT_MAX_EVIDENCE_WINDOW_SECONDS)
            .saturating_mul(1000);
    let policy = opts.policy;
    let anchored_time = |seq: &str| opts.anchored_time.and_then(|f| f(seq));
    let mut ordered: Vec<&(String, Value)> = entries.iter().collect();
    ordered.sort_by_key(|(seq, _)| seq_key(seq));
    // Every valid Dispatch Record per nonce, in seq order.
    let mut dispatches: HashMap<String, Vec<Dispatch>> = HashMap::new();
    let mut approval_hashes: HashMap<String, HashSet<String>> = HashMap::new();
    for (_, leaf) in &ordered {
        if let Some((nonce, d)) = dispatch_of(leaf) {
            dispatches.entry(nonce).or_default().push(d);
        }
        if let Some(p) = payload_object(&leaf["signedPayload"]) {
            if p.get("type").and_then(Value::as_str) == Some(DIV_INTENT_TYPE) {
                if let (Some(nonce), Some(payload)) = (
                    p.get("nonce").and_then(Value::as_str),
                    leaf["signedPayload"].as_str(),
                ) {
                    approval_hashes
                        .entry(nonce.into())
                        .or_default()
                        .insert(execution_payload_sha256(payload));
                }
            }
        }
    }

    let mut result = ExecutionVerification::default();
    let mut evidence_seqs: HashMap<String, Vec<String>> = HashMap::new();
    // Per nonce: the governing Dispatch Record of its bound statements (first seen).
    let mut governing_by_nonce: HashMap<String, Dispatch> = HashMap::new();
    let mut late_contradictions: HashMap<String, Vec<String>> = HashMap::new();
    let mut untrusted_contradictions: HashMap<String, Vec<String>> = HashMap::new();
    let mut continuity_records: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    for (seq, leaf) in entries {
        if !is_execution_evidence_leaf(leaf) {
            continue;
        }
        let c = match check_leaf(leaf, policy, anchored_time(seq)) {
            Err(decided) => decided,
            Ok(Passed {
                statement: s,
                trusted,
                note,
            }) => {
                continuity_records
                    .entry(s.source.clone())
                    .or_default()
                    .push((
                        s.sequence,
                        leaf["signedPayload"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    ));
                let note = note.as_deref();
                let all = dispatches.get(&s.nonce).map(Vec::as_slice).unwrap_or(&[]);
                let governing = all.iter().find(|d| d.payload_sha256 == s.payload_sha256);
                match governing {
                    None => check(
                        "unbound",
                        &with_note(
                            if all.is_empty() {
                                "No Dispatch Record for this approval nonce."
                            } else {
                                "No Dispatch Record for this nonce carries the statement's payload hash."
                            },
                            note,
                        ),
                        Some(&s),
                        trusted,
                    ),
                    Some(_)
                        if !approval_hashes
                            .get(&s.nonce)
                            .is_some_and(|h| h.contains(&s.payload_sha256)) =>
                    {
                        check(
                            "unbound",
                            &with_note(
                                "No Approval Record with this nonce and payload hash.",
                                note,
                            ),
                            Some(&s),
                            trusted,
                        )
                    }
                    Some(d) => {
                        governing_by_nonce
                            .entry(s.nonce.clone())
                            .or_insert_with(|| d.clone());
                        let sampled = dewp_timestamp_str_ms(&s.sampled_at).unwrap_or(i64::MIN);
                        let (deadline_ms, _) = effective_deadline_of(d, max_window_ms);
                        // A provisioned key signed this contradiction but established no trust
                        // (`note` is set only then). In-window or late, it cannot decide the status
                        // and must not be silent (§4.7.4).
                        if sampled >= d.created_at_ms.saturating_sub(skew_ms)
                            && !trusted
                            && note.is_some()
                            && s.verdict == "contradicted"
                        {
                            untrusted_contradictions
                                .entry(s.nonce.clone())
                                .or_default()
                                .push(seq.clone());
                        }
                        if sampled < d.created_at_ms.saturating_sub(skew_ms) {
                            check(
                                "stale",
                                &with_note(
                                    "Sampled before the dispatch evidence window (early).",
                                    note,
                                ),
                                Some(&s),
                                trusted,
                            )
                        } else if sampled > deadline_ms {
                            if trusted && s.verdict == "contradicted" {
                                late_contradictions
                                    .entry(s.nonce.clone())
                                    .or_default()
                                    .push(seq.clone());
                            }
                            check(
                                "stale",
                                &with_note(
                                    "Sampled after the dispatch evidence window (late).",
                                    note,
                                ),
                                Some(&s),
                                trusted,
                            )
                        } else {
                            check(
                                "verified",
                                &with_note(
                                    "Statement verified and bound to its dispatch and approval.",
                                    note,
                                ),
                                Some(&s),
                                trusted,
                            )
                        }
                    }
                }
            }
        };
        if let Some(n) = &c.nonce {
            evidence_seqs
                .entry(n.clone())
                .or_default()
                .push(seq.clone());
        }
        result.checks.push((seq.clone(), c));
    }
    result.sources = continuity(&continuity_records);

    let mut nonces: Vec<String> = approval_hashes
        .keys()
        .chain(dispatches.keys())
        .chain(evidence_seqs.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    nonces.sort_by_key(|n| utf16_key(n));
    for nonce in nonces {
        let counted = result.checks.iter().filter(|(_, c)| {
            c.nonce.as_deref() == Some(nonce.as_str()) && c.status == "verified" && c.trusted
        });
        let (mut confirmed, mut contradicted) = (false, false);
        for (_, c) in counted {
            confirmed |= c.verdict.as_deref() == Some("confirmed");
            contradicted |= c.verdict.as_deref() == Some("contradicted");
        }
        let all = dispatches.get(&nonce).map(Vec::as_slice).unwrap_or(&[]);
        // The governing record: the one the nonce's bound statements bound to, else the first that
        // names it.
        let d = governing_by_nonce.get(&nonce).or_else(|| all.first());
        let deadline = d.map(|d| effective_deadline_of(d, max_window_ms));
        let status = if contradicted {
            "contradicted"
        } else if confirmed {
            "confirmed"
        } else if let Some((deadline_ms, _)) = deadline {
            if deadline_ms < now_ms {
                "unconfirmed"
            } else {
                "pending"
            }
        } else {
            "not_reported"
        };
        let distinct_hashes: HashSet<&str> =
            all.iter().map(|d| d.payload_sha256.as_str()).collect();
        let conflict: Vec<String> = if distinct_hashes.len() > 1 {
            all.iter().map(|d| d.seq.clone()).collect()
        } else {
            Vec::new()
        };
        let late = late_contradictions.get(&nonce).cloned().unwrap_or_default();
        let untrusted = untrusted_contradictions
            .get(&nonce)
            .cloned()
            .unwrap_or_default();
        match status {
            "contradicted" => result.contradicted.push(nonce.clone()),
            "confirmed" => result.confirmed.push(nonce.clone()),
            "unconfirmed" => result.unconfirmed.push(nonce.clone()),
            "pending" => result.pending.push(nonce.clone()),
            _ => result.not_reported.push(nonce.clone()),
        }
        if !conflict.is_empty() {
            result.dispatch_conflicts.push(nonce.clone());
        }
        if !untrusted.is_empty() {
            result.untrusted_contradicted.push(nonce.clone());
        }
        if !late.is_empty() {
            result.late_contradicted.push(nonce.clone());
        }
        result.by_nonce.insert(
            nonce.clone(),
            ExecutionNonceStatus {
                status: status.into(),
                dispatch_seq: d.map(|d| d.seq.clone()),
                evidence_deadline: d.map(|d| d.deadline.clone()),
                effective_deadline: deadline.map(|(ms, _)| iso_from_ms(ms)),
                window_capped: deadline.is_some_and(|(_, capped)| capped),
                dispatch_conflict: conflict,
                late_contradiction: late,
                untrusted_contradiction: untrusted,
                evidence_seqs: evidence_seqs.get(&nonce).cloned().unwrap_or_default(),
            },
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NONCE: &str = "4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d";
    const HASH: &str = "c5ddc97ca4507d1681efb34b83cb25c43a631e4a10931eb51424258b0ba49682";

    fn statement() -> ExecutionEvidenceStatement {
        ExecutionEvidenceStatement {
            nonce: NONCE.into(),
            payload_sha256: HASH.into(),
            observation: Map::new(),
            observed_at: "2026-10-05T14:02:11.000Z".into(),
            sampled_at: "2026-10-05T14:02:09.500Z".into(),
            sequence: 418,
            source: "did:example:relay-7".into(),
            verdict: "confirmed".into(),
        }
    }

    #[test]
    fn builder_refuses_what_the_parser_refuses() {
        assert!(canonical_execution_evidence_statement(&statement()).is_ok());
        let mut s = statement();
        s.sequence = 0;
        assert!(canonical_execution_evidence_statement(&s).is_err());
        let mut s = statement();
        s.sampled_at = "2026-10-05T14:02:11.001Z".into();
        assert!(canonical_execution_evidence_statement(&s).is_err());
        let mut s = statement();
        s.sequence = MAX_STATEMENT_INTEGER + 1;
        assert!(canonical_execution_evidence_statement(&s).is_err());
        let mut s = statement();
        s.verdict = "unsure".into();
        assert!(canonical_execution_evidence_statement(&s).is_err());
    }

    #[test]
    fn sequence_spellings() {
        let bytes = canonical_execution_evidence_statement(&statement()).unwrap();
        let parsed = parse_execution_evidence_statement(&bytes).unwrap();
        assert_eq!(parsed.sequence, 418);
        assert_eq!(parsed.sampled_at, "2026-10-05T14:02:09.500Z");
        for bad in ["418.0", "418.5", "\"418\"", "-1", "9007199254740992"] {
            let text = bytes.replace("\"sequence\":418", &format!("\"sequence\":{bad}"));
            assert!(
                parse_execution_evidence_statement(&text).is_err(),
                "sequence {bad} must be malformed"
            );
        }
    }

    #[test]
    fn trusted_source_key_reads_both_shapes_and_fails_closed_on_the_rest() {
        let policy: ExecutionEvidencePolicy = serde_json::from_value(json!({
            "trustedSources": {
                "did:example:relay-7": [
                    "AAAA",
                    {"key": "BBBB", "notAfter": "2026-10-07T00:00:00.000Z"},
                    {"notBefore": "2026-10-01T00:00:00.000Z"},
                    7,
                    "",
                    {"key": "", "notAfter": "2026-10-07T00:00:00.000Z"},
                    {"key": "CCCC", "notBefore": 5},
                    {"key": "DDDD", "notafter": "2026-10-07T00:00:00.000Z"},
                    {"key": "EEEE", "notAfter": null},
                    {"key": "FFFF", "extra": 1, "notBefore": 5}
                ]
            }
        }))
        .unwrap();
        let keys = trusted_keys_for(&policy, Some("did:example:relay-7"));
        let names: Vec<&str> = keys.iter().map(|k| k.key.as_str()).collect();
        // No usable key: dropped. A usable key with the wrong shape: kept, marked malformed.
        assert_eq!(names, ["AAAA", "BBBB", "CCCC", "DDDD", "EEEE", "FFFF"]);
        assert_eq!(
            keys[1].not_after.as_deref(),
            Some("2026-10-07T00:00:00.000Z")
        );
        assert!(keys[0].malformed.is_none() && keys[1].malformed.is_none());
        let reason = |i: usize| keys[i].malformed.clone().expect("malformed");
        assert!(reason(2).contains("notBefore is not a timestamp string"));
        assert!(reason(3).contains("unexpected member(s) notafter"));
        assert!(reason(4).contains("notAfter is not a timestamp string"));
        // An unknown member is named before a bad bound.
        assert!(reason(5).contains("unexpected member(s) extra"));
        assert!(trusted_keys_for(&policy, Some("did:example:other")).is_empty());
        assert!(trusted_keys_for(&policy, None).is_empty());
        // Round-trips through serde in the policy's JSON form — and a malformed entry serializes as
        // given, so it stays malformed (never a bare, trusted key) on the way back.
        let entries = &policy.trusted_sources["did:example:relay-7"];
        assert_eq!(
            serde_json::to_string(&entries[1]).unwrap(),
            r#"{"key":"BBBB","notAfter":"2026-10-07T00:00:00.000Z"}"#
        );
        let text = serde_json::to_string(&entries[7]).unwrap();
        assert_eq!(
            text,
            r#"{"key":"DDDD","notafter":"2026-10-07T00:00:00.000Z"}"#
        );
        assert_eq!(
            serde_json::from_str::<TrustedSourceKey>(&text).unwrap(),
            entries[7]
        );
        assert!(matches!(entries[2], TrustedSourceKey::Unusable));
        assert_eq!(serde_json::to_string(&entries[2]).unwrap(), "null");
    }

    #[test]
    fn bounded_key_needs_an_anchored_time_inside_its_interval() {
        let k = |nb: Option<&str>, na: Option<&str>| NormalizedKey {
            key: "K".into(),
            not_before: nb.map(str::to_owned),
            not_after: na.map(str::to_owned),
            malformed: None,
        };
        let t = |s: &str| dewp_timestamp_str_ms(s);
        assert!(key_valid_at(&k(None, None), None).is_ok());
        // A malformed entry establishes nothing, anchored time or not.
        let malformed = NormalizedKey {
            malformed: Some(
                "Caller key entry has unexpected member(s) notafter; it does not establish trust."
                    .into(),
            ),
            ..k(None, None)
        };
        assert!(key_valid_at(&malformed, None)
            .unwrap_err()
            .contains("unexpected member(s) notafter"));
        assert!(key_valid_at(&malformed, t("2026-10-05T12:00:00.000Z")).is_err());
        let bounded = k(
            Some("2026-10-01T00:00:00.000Z"),
            Some("2026-10-07T00:00:00.000Z"),
        );
        assert!(key_valid_at(&bounded, None)
            .unwrap_err()
            .contains("no counting anchor"));
        assert!(key_valid_at(&bounded, t("2026-10-05T12:00:00.000Z")).is_ok());
        assert!(key_valid_at(&bounded, t("2026-10-01T00:00:00.000Z")).is_ok());
        assert!(key_valid_at(&bounded, t("2026-10-07T00:00:00.000Z")).is_ok());
        assert!(key_valid_at(&bounded, t("2026-10-07T00:00:00.001Z"))
            .unwrap_err()
            .contains("not valid at"));
        assert!(key_valid_at(&bounded, t("2026-09-30T23:59:59.999Z")).is_err());
        assert!(
            key_valid_at(&k(Some("2026-10-01"), None), t("2026-10-05T12:00:00.000Z"))
                .unwrap_err()
                .contains("malformed validity interval")
        );
    }

    #[test]
    fn iso_from_ms_matches_to_iso_string() {
        assert_eq!(iso_from_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_from_ms(dewp_timestamp_str_ms("2026-10-06T14:00:00.001Z").unwrap()),
            "2026-10-06T14:00:00.001Z"
        );
        assert_eq!(
            iso_from_ms(dewp_timestamp_str_ms("0000-01-01T00:00:00.000Z").unwrap()),
            "0000-01-01T00:00:00.000Z"
        );
        assert_eq!(iso_from_ms(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(
            iso_from_ms(253_402_300_800_000),
            "+010000-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn continuity_reports_ranges_and_divergence() {
        let mut records = BTreeMap::new();
        records.insert(
            "s".to_string(),
            vec![
                (2, "a".to_string()),
                (6, "b".to_string()),
                (6, "b".to_string()),
                (9, "c".to_string()),
                (9, "d".to_string()),
            ],
        );
        let out = continuity(&records);
        assert_eq!(
            out["s"],
            SourceContinuity {
                first: 2,
                last: 9,
                gaps: vec![(3, 5), (7, 8)],
                divergent: vec![9],
            }
        );
    }

    #[test]
    fn effective_deadline_is_cut_to_the_window() {
        let d = Dispatch {
            seq: "1".into(),
            created_at_ms: 1_000,
            deadline: String::new(),
            deadline_ms: 5_000,
            payload_sha256: HASH.into(),
        };
        assert_eq!(effective_deadline_of(&d, 10_000), (5_000, false));
        assert_eq!(effective_deadline_of(&d, 4_000), (5_000, false));
        assert_eq!(effective_deadline_of(&d, 3_999), (4_999, true));
    }

    #[test]
    fn a_negative_bound_is_no_bound_and_falls_back_to_the_default() {
        assert_eq!(bounded_seconds(None, 30), 30);
        assert_eq!(bounded_seconds(Some(0), 30), 0);
        assert_eq!(bounded_seconds(Some(10), 30), 10);
        assert_eq!(bounded_seconds(Some(-1), 30), 30);
        assert_eq!(bounded_seconds(Some(i64::MIN), 86_400), 86_400);
    }

    // One approval, one dispatch and one statement signed by a real P-256 key, so the finding and
    // the option sanitising are exercised end to end rather than on hand-built checks.
    mod signed {
        use super::*;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ecdsa::signature::Signer;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePublicKey;

        const SOURCE: &str = "did:example:relay-7";
        const T_DISPATCH: &str = "2026-10-05T14:00:00.000Z";
        const T_DEADLINE: &str = "2026-10-05T14:10:00.000Z";
        const T_OBSERVED: &str = "2026-10-05T14:02:11.000Z";
        const T_SAMPLED: &str = "2026-10-05T14:02:09.500Z";
        const NOW_AFTER: &str = "2026-10-05T14:30:00.000Z";

        fn source_key() -> SigningKey {
            SigningKey::from_slice(&[0x22u8; 32]).expect("valid P-256 scalar")
        }

        fn spki() -> String {
            STANDARD.encode(
                source_key()
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes(),
            )
        }

        fn approval_payload() -> String {
            crate::stable_stringify(&json!({
                "type": DIV_INTENT_TYPE, "nonce": NONCE, "target": "breaker-7", "actionType": "open"
            }))
            .unwrap()
        }

        fn evidence_leaf(verdict: &str, sampled_at: &str) -> Value {
            let observed_at = if sampled_at > T_OBSERVED {
                sampled_at
            } else {
                T_OBSERVED
            };
            let bytes = canonical_execution_evidence_statement(&ExecutionEvidenceStatement {
                nonce: NONCE.into(),
                payload_sha256: execution_payload_sha256(&approval_payload()),
                observation: Map::new(),
                observed_at: observed_at.into(),
                sampled_at: sampled_at.into(),
                sequence: 1,
                source: SOURCE.into(),
                verdict: verdict.into(),
            })
            .unwrap();
            let signature: p256::ecdsa::Signature = source_key().sign(bytes.as_bytes());
            let (event, outcome) = if verdict == "confirmed" {
                (EXECUTION_CONFIRMED, "SUCCESS")
            } else {
                (EXECUTION_CONTRADICTED, "FAILURE")
            };
            json!({
                "seq": "102", "event": event, "outcome": outcome, "createdAt": observed_at,
                "signerDid": SOURCE, "sigAlg": "ES256", "signerPublicKey": spki(),
                "signature": STANDARD.encode(signature.to_bytes()), "signedPayload": bytes,
            })
        }

        fn entries(verdict: &str, sampled_at: &str) -> Vec<(String, Value)> {
            let approval = json!({
                "seq": "100", "event": "AUTHZ_APPROVED", "outcome": "SUCCESS",
                "createdAt": "2026-10-05T13:59:00.000Z", "signedPayload": approval_payload(),
            });
            let dispatch = json!({
                "seq": "101", "event": EXECUTION_DISPATCHED, "outcome": "SUCCESS",
                "createdAt": T_DISPATCH,
                "metadata": {
                    "nonce": NONCE,
                    "payloadSha256": execution_payload_sha256(&approval_payload()),
                    "evidenceDeadline": T_DEADLINE,
                },
            });
            vec![
                ("100".into(), approval),
                ("101".into(), dispatch),
                ("102".into(), evidence_leaf(verdict, sampled_at)),
            ]
        }

        fn policy(entry: Value) -> ExecutionEvidencePolicy {
            serde_json::from_value(json!({ "trustedSources": { SOURCE: [entry] } })).unwrap()
        }

        fn evaluate(
            entries: &[(String, Value)],
            policy: Option<&ExecutionEvidencePolicy>,
            skew_seconds: Option<i64>,
            max_window_seconds: Option<i64>,
        ) -> ExecutionVerification {
            evaluate_execution_evidence_with_options(
                entries,
                &ExecutionEvaluationOptions {
                    policy,
                    now_ms: dewp_timestamp_str_ms(NOW_AFTER),
                    skew_seconds,
                    max_window_seconds,
                    anchored_time: None,
                },
            )
        }

        fn summary(r: &ExecutionVerification) -> (String, String, bool, Vec<String>) {
            let (_, check) = &r.checks[0];
            (
                r.by_nonce[NONCE].status.clone(),
                check.status.clone(),
                check.trusted,
                r.untrusted_contradicted.clone(),
            )
        }

        #[test]
        fn a_contradiction_under_a_provisioned_key_that_established_no_trust_is_a_finding() {
            let rows = entries("contradicted", T_SAMPLED);
            // A bounded key with no anchored time cannot be placed in time: verified, untrusted,
            // and the contradiction is reported rather than dropped.
            let bounded = policy(json!({"key": spki(), "notAfter": "2026-10-07T00:00:00.000Z"}));
            let r = evaluate(&rows, Some(&bounded), None, None);
            assert_eq!(
                summary(&r),
                (
                    "unconfirmed".into(),
                    "verified".into(),
                    false,
                    vec![NONCE.to_string()]
                )
            );
            assert_eq!(r.by_nonce[NONCE].untrusted_contradiction, ["102"]);
            assert!(r.checks[0].1.reason.contains("no counting anchor"));
            assert!(r.late_contradicted.is_empty());
            // A malformed entry (a misspelt bound) is the same finding, with its reason.
            let misspelt = policy(json!({"key": spki(), "notafter": "2026-10-07T00:00:00.000Z"}));
            let r = evaluate(&rows, Some(&misspelt), None, None);
            assert_eq!(
                summary(&r),
                (
                    "unconfirmed".into(),
                    "verified".into(),
                    false,
                    vec![NONCE.to_string()]
                )
            );
            assert!(r.checks[0]
                .1
                .reason
                .contains("unexpected member(s) notafter"));
            // A numeric bound likewise.
            let numeric = policy(json!({"key": spki(), "notAfter": 1_754_006_400_000_i64}));
            let r = evaluate(&rows, Some(&numeric), None, None);
            assert_eq!(summary(&r).3, [NONCE.to_string()]);
            assert!(r.checks[0]
                .1
                .reason
                .contains("notAfter is not a timestamp string"));
        }

        #[test]
        fn the_finding_needs_a_provisioned_key_and_a_contradiction() {
            // No policy: the embedded key verifies the bytes but no key was provisioned.
            let r = evaluate(&entries("contradicted", T_SAMPLED), None, None, None);
            assert_eq!(
                summary(&r),
                ("unconfirmed".into(), "verified".into(), false, Vec::new())
            );
            // A bare key is trusted: the status is contradicted and nothing is untrusted.
            let bare = policy(json!(spki()));
            let r = evaluate(&entries("contradicted", T_SAMPLED), Some(&bare), None, None);
            assert_eq!(
                summary(&r),
                ("contradicted".into(), "verified".into(), true, Vec::new())
            );
            // An untrusted CONFIRMED is not the finding.
            let bounded = policy(json!({"key": spki(), "notAfter": "2026-10-07T00:00:00.000Z"}));
            let r = evaluate(&entries("confirmed", T_SAMPLED), Some(&bounded), None, None);
            assert_eq!(
                summary(&r),
                ("unconfirmed".into(), "verified".into(), false, Vec::new())
            );
            // A trusted late one is the late finding, not this one.
            let r = evaluate(
                &entries("contradicted", "2026-10-05T14:20:00.000Z"),
                Some(&bare),
                None,
                None,
            );
            assert_eq!(summary(&r).1, "stale");
            assert_eq!(r.late_contradicted, [NONCE.to_string()]);
            assert!(r.untrusted_contradicted.is_empty());
            // Without established key trust, lateness must still leave an untrusted finding.
            let r = evaluate(
                &entries("contradicted", "2026-10-05T14:20:00.000Z"),
                Some(&bounded),
                None,
                None,
            );
            assert_eq!(summary(&r).1, "stale");
            assert!(!r.checks[0].1.trusted);
            assert_eq!(r.untrusted_contradicted, [NONCE.to_string()]);
            assert_eq!(r.by_nonce[NONCE].untrusted_contradiction, ["102"]);
            assert!(r.late_contradicted.is_empty());
        }

        #[test]
        fn a_negative_skew_or_window_falls_back_to_the_default() {
            let bare = policy(json!(spki()));
            // Sampled 20 s before dispatch: inside the default 30 s allowance …
            let early = entries("confirmed", "2026-10-05T13:59:40.000Z");
            assert_eq!(
                summary(&evaluate(&early, Some(&bare), None, None)).0,
                "confirmed"
            );
            // … outside a caller's 10 s …
            assert_eq!(
                summary(&evaluate(&early, Some(&bare), Some(10), None)).0,
                "unconfirmed"
            );
            // … and a negative allowance is no allowance at all, so the default stands.
            assert_eq!(
                summary(&evaluate(&early, Some(&bare), Some(-1), None)).0,
                "confirmed"
            );
            // A negative window likewise: it must not cut the deadline to the dispatch time.
            let inside = entries("confirmed", T_SAMPLED);
            let r = evaluate(&inside, Some(&bare), None, Some(-5));
            assert_eq!(summary(&r).0, "confirmed");
            assert!(!r.by_nonce[NONCE].window_capped);
            assert_eq!(
                summary(&evaluate(&inside, Some(&bare), None, Some(60))).0,
                "unconfirmed"
            );
        }
    }
}
