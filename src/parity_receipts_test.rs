use super::*;
use serde_json::json;
use std::collections::BTreeMap;

fn merged(base: &Value, overrides: &Value) -> Value {
    let mut result = base.clone();
    if let Some(fields) = overrides.as_object() {
        result.as_object_mut().unwrap().extend(fields.clone());
    }
    result
}

/// A case's optional relying-party requirement floor (DIV §5 step 3d).
fn floor(raw: &Value) -> Option<RequirementFloor> {
    if raw.is_null() {
        return None;
    }
    Some(serde_json::from_value(raw.clone()).unwrap())
}

/// A floor whose flags are not booleans (`enrolled-device-floor-malformed-refused`:
/// `requireEnrolledDevice: "yes"`) cannot reach the API at all: `RequirementFloor`'s flags are
/// `bool`, so the type boundary is this port's refusal. Such a case must be one the reference
/// refuses as a malformed floor; anything else unparseable is a harness bug and fails loudly.
/// Returns true when the case was settled here.
fn floor_refused_by_type(case: &Value, e: &Value) -> bool {
    let raw = &e["requirement"];
    if raw.is_null() || serde_json::from_value::<RequirementFloor>(raw.clone()).is_ok() {
        return false;
    }
    let want = "expected.requirement is malformed";
    assert_eq!(case["ok"].as_bool(), Some(false), "{}", case["name"]);
    assert!(
        case["reasonIncludes"]
            .as_str()
            .or(case["reason"].as_str())
            .is_some_and(|reason| reason.starts_with(want)),
        "{}: an unrepresentable floor must be a malformed-floor refusal",
        case["name"]
    );
    true
}

/// `expected.enrolledDeviceKeys` for an approval case (DIV §4.3.2): `enrolledDeviceKeyIds` map
/// through the section's keys to SPKI; a literal `enrolledDeviceKeys` is passed verbatim; absent
/// means `None`, exactly as the reference spreads `expected`.
fn enrolled_device_keys(e: &Value, keys: &BTreeMap<String, Value>) -> Option<Vec<String>> {
    if let Some(ids) = e["enrolledDeviceKeyIds"].as_array() {
        return Some(
            ids.iter()
                .map(|id| {
                    keys[id.as_str().unwrap()]["spkiB64"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect(),
        );
    }
    e.get("enrolledDeviceKeys").map(|literal| {
        literal
            .as_array()
            .expect("a literal enrolledDeviceKeys is an array")
            .iter()
            .map(|key| key.as_str().expect("of strings").to_owned())
            .collect()
    })
}

fn options(raw: &Value) -> VerifyOptions {
    VerifyOptions {
        expected_origin: raw["expectedOrigin"].as_str().map(str::to_owned),
        expected_rp_id: raw["expectedRpId"].as_str().map(str::to_owned),
        as_of_unix_secs: raw["asOf"]
            .as_str()
            .map(|s| parse_rfc3339_utc_secs(s).unwrap()),
        clock_skew_seconds: raw["clockSkewSeconds"].as_i64(),
        allow_offline: raw["allowOffline"].as_bool().unwrap_or(false),
        require_user_verification: raw["requireUserVerification"].as_bool(),
        ..Default::default()
    }
}

#[test]
fn shared_platform_and_authority_receipts() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let keys = key_table(&vectors["keys"]);
    run_approval_cases(&vectors["approvals"], &keys);
    run_platform_cases(&vectors["platform"], &keys);
    run_authority_cases(&vectors["agentAuthority"], &keys);
}

/// The `verifierInputHardening` section (2026-09-27 review L15-L18, I7): its own keys, the same
/// harness as the top-level sections of the same names. Its `bundles` run in bundle.rs.
#[test]
fn shared_verifier_input_hardening_receipts() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let section = &vectors["verifierInputHardening"];
    let keys = key_table(&section["keys"]);
    for part in ["approvals", "platform", "agentAuthority"] {
        assert!(
            !section[part]["cases"].as_array().unwrap().is_empty(),
            "{part}"
        );
    }
    run_approval_cases(&section["approvals"], &keys);
    run_platform_cases(&section["platform"], &keys);
    run_authority_cases(&section["agentAuthority"], &keys);
}

/// The vectors' reasons name TypeScript APIs; rewrite them to this port's own names
/// (packages/mcp-schemas/vectors/api-name-hints.json): every token, longest first, becomes a
/// placeholder, then every placeholder becomes the Rust spelling — one pass, never rescanned.
pub(crate) fn localized(text: &str) -> String {
    let hints: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/api-name-hints.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let tokens: Vec<&str> = hints["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    let map = hints["rust"].as_object().unwrap();
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    let mut want = tokens.clone();
    keys.sort_unstable();
    want.sort_unstable();
    assert_eq!(
        keys, want,
        "the Rust api-name map must name exactly the shared tokens"
    );
    let mut order = tokens.clone();
    order.sort_by(|a, b| b.len().cmp(&a.len()));
    let mut out = text.to_string();
    for (i, token) in order.iter().enumerate() {
        out = out.replace(token, &format!("\u{0}{i}\u{0}"));
    }
    for (i, token) in order.iter().enumerate() {
        out = out.replace(&format!("\u{0}{i}\u{0}"), map[*token].as_str().unwrap());
    }
    out
}

/// `reasonIncludes` (substring) and `reason` (exact reference text), whenever a case carries them,
/// after rewriting the TypeScript API names to Rust's.
fn assert_reason_fields<T: std::fmt::Debug>(case: &Value, result: &Result<T, String>) {
    let reason = result.as_ref().err().map(String::as_str);
    if let Some(fragment) = case["reasonIncludes"].as_str() {
        let fragment = localized(fragment);
        assert!(
            reason.is_some_and(|r| r.contains(&fragment)),
            "{}: reason {reason:?} does not contain {fragment:?}",
            case["name"]
        );
    }
    if let Some(exact) = case["reason"].as_str() {
        assert_eq!(
            reason,
            Some(localized(exact).as_str()),
            "{}: exact reason",
            case["name"]
        );
    }
}

/// A resolver-less DID anchor (`resolverOmitted`) is not expressible in Rust: both DID-mode
/// variants carry a resolver by type. The harness uses the closest equivalent, a resolver that knows
/// no keys, and expects what the reference reports for THAT anchor: the "provides no resolver" clause
/// becomes "no trusted key could be resolved for <did>". Everything else in the reason is compared
/// exactly.
const RESOLVER_OMITTED: &str =
    " is not self-certifying (did:intyga:key:…) and the trust anchor provides no resolveKey";

fn assert_resolver_omitted<T: std::fmt::Debug>(case: &Value, result: &Result<T, String>) {
    let exact = case["reason"]
        .as_str()
        .expect("a resolverOmitted case pins its exact reason");
    let at = exact
        .find(RESOLVER_OMITTED)
        .expect("a resolverOmitted reason names the missing resolver");
    let did_start = exact[..at].rfind(['(', ' ']).map_or(0, |i| i + 1);
    let did = &exact[did_start..at];
    let rewritten = format!(
        "{}no trusted key could be resolved for {did}{}",
        &exact[..did_start],
        &exact[at + RESOLVER_OMITTED.len()..]
    );
    assert_eq!(
        result.as_ref().err().map(String::as_str),
        Some(localized(&rewritten).as_str()),
        "{}: exact reason (resolver-less anchor emulated)",
        case["name"]
    );
}

fn key_table(raw: &Value) -> BTreeMap<String, Value> {
    raw.as_array()
        .unwrap()
        .iter()
        .map(|key| (key["id"].as_str().unwrap().to_owned(), key.clone()))
        .collect()
}

fn run_approval_cases(section: &Value, keys: &BTreeMap<String, Value>) {
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        if floor_refused_by_type(case, &e) {
            continue;
        }
        // A WEBAUTHN witness verifies under the credential's COSE_Key; such cases say so explicitly.
        let encoding = if case["approverKeyEncoding"].as_str() == Some("cose") {
            "coseB64"
        } else {
            "spkiB64"
        };
        let approvers = if let Some(table) = e["approverDids"].as_object() {
            let cose_dids = e["approverCoseDids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<std::collections::HashSet<_>>();
            let resolved = table
                .iter()
                .map(|(did, ids)| {
                    let encoding = if cose_dids.contains(did) {
                        "coseB64"
                    } else {
                        "spkiB64"
                    };
                    let values = ids
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()][encoding]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect::<Vec<_>>();
                    (did.clone(), values)
                })
                .collect::<BTreeMap<_, _>>();
            let dids = resolved.keys().cloned().collect::<Vec<_>>();
            // Harness instruction: the resolver panics (the Rust analogue of throwing) for these.
            let throws_for = e["resolverThrowsFor"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<std::collections::HashSet<_>>();
            if e["resolverOmitted"].as_bool() == Some(true) {
                // Rust has no resolver-less DID anchor; the closest equivalent is a DID-mode
                // anchor whose resolver knows no keys (see `RESOLVER_OMITTED` below).
                ApproverTrustAnchor::DidsMultiKey {
                    dids,
                    resolve: Box::new(|_| Vec::new()),
                }
            } else {
                ApproverTrustAnchor::DidsMultiKey {
                    dids,
                    resolve: Box::new(move |did| {
                        if throws_for.contains(did) {
                            panic!("resolver unavailable for {did}");
                        }
                        resolved.get(did).cloned().unwrap_or_default()
                    }),
                }
            }
        } else {
            ApproverTrustAnchor::PublicKeys(
                e["approverKeyIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        keys[id.as_str().unwrap()][encoding]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect(),
            )
        };
        let expected = Expected {
            // DIV §5 step 3d: an optional relying-party requirement floor.
            requirement: floor(&e["requirement"]),
            target: e["target"].as_str().unwrap().into(),
            nonce: e["nonce"].as_str().unwrap().into(),
            action_type: e["actionType"].as_str().unwrap().into(),
            params: e["params"].clone(),
            requester_did: e["requesterDid"].as_str().map(str::to_owned),
            approvers,
            // Absent means omitted, exactly as the reference spreads `expected`.
            tenant_id: e["tenantId"].as_str().map(str::to_owned),
            enrolled_device_keys: enrolled_device_keys(&e, keys),
        };
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let opts = options(&merged(&section["options"], &case["options"]));
        let result = if e.get("agentContext").is_some() {
            verify_agent_approval_receipt(&receipt, &expected, &e["agentContext"], &opts)
        } else {
            verify_approval_receipt_with_options(&receipt, &expected, &opts)
        };
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        // A refusal that lands for the wrong reason, or an acceptance crediting the wrong
        // identities, is the divergence these fixtures exist to catch.
        if e["resolverOmitted"].as_bool() == Some(true) {
            assert_resolver_omitted(case, &result);
        } else {
            assert_reason_fields(case, &result);
        }
        if let Some(signers) = case.get("signers") {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                *signers,
                "{}",
                case["name"]
            );
        }
    }
}

fn run_platform_cases(section: &Value, keys: &BTreeMap<String, Value>) {
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        let expected = PlatformReceiptExpectation {
            approvers: ApproverTrustAnchor::PublicKeys(
                e["approverKeyIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        keys[id.as_str().unwrap()]["coseB64"]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect(),
            ),
            payload_hash: e["payloadHash"].as_str().unwrap().into(),
            rp_id: e["rpId"].as_str().unwrap().into(),
            nonce: e["nonce"].as_str().unwrap().into(),
            subject_external_id: e["subjectExternalId"].as_str().map(str::to_owned),
            tenant_id: e["tenantId"].as_str().map(str::to_owned),
        };
        let receipt: PlatformReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_platform_receipt(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        assert_reason_fields(case, &result);
        if let Some(signers) = case.get("signers") {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                *signers,
                "{}",
                case["name"]
            );
        }
    }
}

fn run_authority_cases(section: &Value, keys: &BTreeMap<String, Value>) {
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        if floor_refused_by_type(case, &e) {
            continue;
        }
        let mappings: BTreeMap<String, Vec<String>> = e["approverDids"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(did, ids)| {
                (
                    did.clone(),
                    ids.as_array()
                        .unwrap()
                        .iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            })
            .collect();
        let expected = AgentAuthorityExpectation {
            approvers: if let Some(ids) = e["approverKeyIds"].as_array() {
                ApproverTrustAnchor::PublicKeys(
                    ids.iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            } else {
                ApproverTrustAnchor::DidsMultiKey {
                    dids: mappings.keys().cloned().collect(),
                    resolve: Box::new(move |did| mappings.get(did).cloned().unwrap_or_default()),
                }
            },
            target: e["target"].as_str().unwrap().into(),
            agent_did: e["agentDid"].as_str().unwrap().into(),
            requirement: floor(&e["requirement"]),
            tenant_id: e["tenantId"].as_str().map(str::to_owned),
        };
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_agent_authority(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        assert_reason_fields(case, &result);
        if let Ok(authority) = result {
            if let Some(signers) = case.get("signers") {
                assert_eq!(
                    serde_json::to_value(authority.signers).unwrap(),
                    *signers,
                    "{}",
                    case["name"]
                );
            }
            if let Some(patterns) = case.get("actionPatterns") {
                assert_eq!(
                    serde_json::to_value(authority.action_patterns).unwrap(),
                    *patterns,
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

fn tenant_expected(
    raw: &Value,
    keys: &BTreeMap<String, Value>,
    tenant_id: Option<&str>,
) -> Expected {
    let anchor = if let Some(ids) = raw["approverKeyIds"].as_array() {
        ApproverTrustAnchor::PublicKeys(
            ids.iter()
                .map(|id| {
                    keys[id.as_str().unwrap()]["spkiB64"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect(),
        )
    } else {
        let mappings: BTreeMap<String, Vec<String>> = raw["approverDids"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(did, ids)| {
                (
                    did.clone(),
                    ids.as_array()
                        .unwrap()
                        .iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            })
            .collect();
        ApproverTrustAnchor::DidsMultiKey {
            dids: mappings.keys().cloned().collect(),
            resolve: Box::new(move |did| mappings.get(did).cloned().unwrap_or_default()),
        }
    };
    Expected {
        target: raw["target"].as_str().unwrap_or_default().into(),
        nonce: raw["nonce"].as_str().unwrap_or_default().into(),
        action_type: raw["actionType"].as_str().unwrap_or_default().into(),
        params: raw.get("params").cloned().unwrap_or(Value::Null),
        requester_did: raw["requesterDid"].as_str().map(str::to_owned),
        approvers: anchor,
        requirement: floor(&raw["requirement"]),
        tenant_id: tenant_id.map(str::to_owned),
        enrolled_device_keys: enrolled_device_keys(raw, keys),
    }
}

fn tenant_authority_expected(
    raw: &Value,
    keys: &BTreeMap<String, Value>,
    tenant_id: Option<&str>,
) -> AgentAuthorityExpectation {
    let expected = tenant_expected(raw, keys, tenant_id);
    AgentAuthorityExpectation {
        approvers: expected.approvers,
        target: expected.target,
        agent_did: raw["agentDid"].as_str().unwrap_or_default().into(),
        requirement: expected.requirement,
        tenant_id: expected.tenant_id,
    }
}

#[test]
fn shared_tenant_binding_verifier_vectors() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/tenant-binding-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let keys = key_table(&vectors["keys"]);
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let verifier = case["verifier"].as_str().unwrap();
        let mut opts = options(&case["options"]);
        let tenant = case["expectedTenantId"].as_str();
        let result = match verifier {
            "approval" => {
                if let Some(links) = case["chain"].as_array() {
                    let chain: Vec<AgentAuthorityChainLink> = links
                        .iter()
                        .map(|link| AgentAuthorityChainLink {
                            receipt: serde_json::from_value(link["receipt"].clone()).unwrap(),
                            expected: tenant_authority_expected(
                                &link["expected"],
                                &keys,
                                link["expectedTenantId"].as_str(),
                            ),
                        })
                        .collect();
                    opts.agent_authority_chain = Some(std::sync::Arc::new(chain));
                }
                let receipt: ApprovalReceipt =
                    serde_json::from_value(case["receipt"].clone()).unwrap();
                let expected = tenant_expected(&case["expected"], &keys, tenant);
                if let Some(agent_context) = case["expected"].get("agentContext") {
                    verify_agent_approval_receipt(&receipt, &expected, agent_context, &opts)
                        .map(|_| ())
                } else {
                    verify_approval_receipt_with_options(&receipt, &expected, &opts).map(|_| ())
                }
            }
            "delegation" => {
                let receipt: ApprovalReceipt =
                    serde_json::from_value(case["receipt"].clone()).unwrap();
                verify_delegation(
                    &receipt,
                    &tenant_expected(&case["expected"], &keys, tenant),
                    &opts,
                )
                .map(|_| ())
            }
            "authority" => {
                let receipt: ApprovalReceipt =
                    serde_json::from_value(case["receipt"].clone()).unwrap();
                let expected = tenant_expected(&case["expected"], &keys, tenant);
                let authority_expected = AgentAuthorityExpectation {
                    approvers: expected.approvers,
                    target: expected.target,
                    agent_did: case["expected"]["agentDid"].as_str().unwrap().into(),
                    requirement: expected.requirement,
                    tenant_id: expected.tenant_id,
                };
                verify_agent_authority(&receipt, &authority_expected, &opts).map(|_| ())
            }
            "platform" => {
                let e = &case["expected"];
                let expected = PlatformReceiptExpectation {
                    approvers: ApproverTrustAnchor::PublicKeys(
                        e["approverKeyIds"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|id| {
                                keys[id.as_str().unwrap()]["coseB64"]
                                    .as_str()
                                    .unwrap()
                                    .to_owned()
                            })
                            .collect(),
                    ),
                    payload_hash: e["payloadHash"].as_str().unwrap().into(),
                    rp_id: e["rpId"].as_str().unwrap().into(),
                    nonce: e["nonce"].as_str().unwrap().into(),
                    subject_external_id: e["subjectExternalId"].as_str().map(str::to_owned),
                    tenant_id: tenant.map(str::to_owned),
                };
                let receipt: PlatformReceipt =
                    serde_json::from_value(case["receipt"].clone()).unwrap();
                verify_platform_receipt(&receipt, &expected, &opts).map(|_| ())
            }
            "approval-with-delegation" => {
                let delegation: ApprovalReceipt =
                    serde_json::from_value(case["delegationReceipt"].clone()).unwrap();
                let seal_expected = tenant_expected(
                    &case["delegationExpected"],
                    &keys,
                    case["delegationExpectedTenantId"].as_str(),
                );
                match verify_delegation(&delegation, &seal_expected, &opts) {
                    Ok(delegation) => {
                        let receipt: ApprovalReceipt =
                            serde_json::from_value(case["receipt"].clone()).unwrap();
                        let mut opts = opts;
                        opts.delegation = Some(delegation);
                        verify_approval_receipt_with_options(
                            &receipt,
                            &tenant_expected(&case["expected"], &keys, tenant),
                            &opts,
                        )
                        .map(|_| ())
                    }
                    Err(reason) => Err(reason),
                }
            }
            "authority-chain" => {
                let chain: Vec<AgentAuthorityChainLink> = case["chain"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|link| AgentAuthorityChainLink {
                        receipt: serde_json::from_value(link["receipt"].clone()).unwrap(),
                        expected: tenant_authority_expected(
                            &link["expected"],
                            &keys,
                            link["expectedTenantId"].as_str(),
                        ),
                    })
                    .collect();
                let action: AgentDelegatedAction =
                    serde_json::from_value(case["action"].clone()).unwrap();
                verify_agent_delegation_chain(&chain, &action, &opts).map(|_| ())
            }
            other => panic!("unknown tenant verifier {other}"),
        };
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn shared_agent_receipt_digest_signer_did_projections() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/tenant-binding-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for case in vectors["agentReceiptDigestCases"].as_array().unwrap() {
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        assert_eq!(
            agent_receipt_digest(&receipt).unwrap(),
            case["expected"].as_str().unwrap(),
            "{}",
            case["name"].as_str().unwrap()
        );
    }
}

#[test]
fn shared_canonical_authority_and_platform_builders() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/canonical-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for item in v["agentAuthorityPayloads"].as_array().unwrap() {
        let i = &item["input"];
        let requester: RequesterIdentity = serde_json::from_value(i["requester"].clone()).unwrap();
        let requirement: ApprovalRequirement =
            serde_json::from_value(i["requirement"].clone()).unwrap();
        let patterns: Vec<String> = serde_json::from_value(i["actionPatterns"].clone()).unwrap();
        let got = canonical_agent_authority_payload_with_parent(
            i["target"].as_str().unwrap(),
            &patterns,
            i["actionDescription"].as_str().unwrap(),
            i["agentDid"].as_str().unwrap(),
            &requester,
            &requirement,
            i["nonce"].as_str().unwrap(),
            i["sealedAt"].as_str().unwrap(),
            i["expiresAt"].as_str().unwrap(),
            i["parentReceiptHash"].as_str(),
        )
        .unwrap();
        assert_eq!(got, item["expected"].as_str().unwrap());
    }
    for item in v["agentIntentPayloads"].as_array().unwrap() {
        let i = &item["input"];
        let requester: RequesterIdentity = serde_json::from_value(i["requester"].clone()).unwrap();
        let requirement: ApprovalRequirement =
            serde_json::from_value(i["requirement"].clone()).unwrap();
        let got = canonical_agent_intent_payload(
            i["target"].as_str().unwrap(),
            i["actionType"].as_str().unwrap(),
            i["actionDescription"].as_str().unwrap(),
            &i["params"],
            &requester,
            &requirement,
            i["nonce"].as_str().unwrap(),
            i["expiresAt"].as_str().unwrap(),
            &i["agentContext"],
        )
        .unwrap();
        assert_eq!(got, item["expected"].as_str().unwrap());
    }
    for item in v["platformIntentPayloads"]["cases"].as_array().unwrap() {
        let i = &item["input"];
        let got = canonical_platform_intent_payload(
            i["payloadHash"].as_str().unwrap(),
            i["rpId"].as_str().unwrap(),
            i["subjectExternalId"].as_str().unwrap(),
            i["signedAt"].as_str().unwrap(),
            i["expiresAt"].as_str().unwrap(),
            i["nonce"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(got, item["expected"].as_str().unwrap());
    }
}

/// DEWP §4.7 (version 1.1): the shared `executionEvidence` section, run exactly as TS runs it.
#[test]
fn shared_execution_evidence_vectors() {
    use crate::bundle::{
        verify_bundle_with_evidence, verify_evidence_bundle_with_execution, BundleVerifyOptions,
        EvidenceBundle, EvidenceVerifyOptions, ProofBundle,
    };
    use crate::execution::{
        canonical_execution_evidence_statement, parse_execution_evidence_statement,
        ExecutionEvidencePolicy, ExecutionEvidenceStatement, ExecutionOptions, SourceContinuity,
    };
    use crate::ledger::{AnchorPolicy, AnchorQuorum, ExternalAnchorKeys, SignedAnchor};
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let section = &vectors["executionEvidence"];
    let rows = |v: &Value| -> Vec<(String, String, bool)> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["seq"].as_str().unwrap().into(),
                    r["status"].as_str().unwrap().into(),
                    r["trusted"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let no_resolver = |_: &SignedAnchor| -> Option<String> { None };
    let cases = section["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let o = &c["options"];
        let bundle: EvidenceBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
        let roots: Vec<String> = serde_json::from_value(o["trustedRoots"].clone()).unwrap();
        let eo = EvidenceVerifyOptions {
            signature_policy: if o["signaturePolicy"].is_null() {
                None
            } else {
                Some(serde_json::from_value(o["signaturePolicy"].clone()).unwrap())
            },
            require_signatures: false,
            trusted_roots: Some(&roots),
            anchors: None,
            // The anchored-time cases (DEWP §4.7.5) carry a Rekor-witnessed anchor in the bundle's
            // checkpoint and pin the log key inline: the section stays self-contained.
            anchor_policy: c
                .get("policy")
                .filter(|p| !p.is_null())
                .map(|p| AnchorPolicy {
                    required_anchors: p["requiredAnchors"].as_u64().unwrap() as usize,
                    trusted_issuers: serde_json::from_value(p["trustedIssuers"].clone()).unwrap(),
                    quorum: if p["quorum"] == "ALL_MUST_AGREE" {
                        AnchorQuorum::AllMustAgree
                    } else {
                        AnchorQuorum::NOfM
                    },
                    max_anchor_lag_seconds: p["maxAnchorLagSeconds"].as_i64(),
                }),
            resolve_anchor_key: Some(&no_resolver),
            external_keys: ExternalAnchorKeys {
                rekor: o["rekorSpki"].as_str().map(str::to_owned),
                ..Default::default()
            },
            trusted_checkpoints: None,
        };
        let x = ExecutionOptions {
            evidence_policy: if o["evidencePolicy"].is_null() {
                None
            } else {
                Some(
                    serde_json::from_value::<ExecutionEvidencePolicy>(o["evidencePolicy"].clone())
                        .unwrap(),
                )
            },
            require_execution_confirmed: o["requireExecutionConfirmed"].as_bool().unwrap_or(false),
            now_ms: Some(crate::execution::dewp_timestamp_ms(&o["now"]).unwrap()),
            skew_seconds: o["skewSeconds"].as_i64(),
            max_window_seconds: o["maxWindowSeconds"].as_i64(),
        };
        let r = verify_evidence_bundle_with_execution(&bundle, &eo, &x);
        assert_eq!(r.ok, c["ok"].as_bool().unwrap(), "{name}: {:?}", r.failed);
        if let Some(n) = c.get("contentVerified").and_then(Value::as_u64) {
            assert_eq!(r.content_verified, n as usize, "{name}: contentVerified");
        }
        if let Some(n) = c.get("commitmentOnly").and_then(Value::as_u64) {
            assert_eq!(r.commitment_only, n as usize, "{name}: commitmentOnly");
        }
        let by_nonce: BTreeMap<String, String> = r
            .execution
            .by_nonce
            .iter()
            .map(|(n, v)| (n.clone(), v.status.clone()))
            .collect();
        let want: BTreeMap<String, String> =
            serde_json::from_value(c["execution"]["byNonce"].clone()).unwrap();
        assert_eq!(by_nonce, want, "{name}: byNonce");
        let got: Vec<(String, String, bool)> = r
            .execution
            .checks
            .iter()
            .map(|(s, k)| (s.clone(), k.status.clone(), k.trusted))
            .collect();
        assert_eq!(
            got,
            rows(&c["execution"]["checks"]),
            "{name}: checks {:?}",
            r.execution.checks
        );
        // Every §4.7.4 finding the case pins: late and untrusted contradictions, dispatch conflicts,
        // the window cap per nonce and per-source continuity.
        let f = &c["execution"]["findings"];
        if let Some(want) = f.get("lateContradicted") {
            let want: Vec<String> = serde_json::from_value(want.clone()).unwrap();
            assert_eq!(r.execution.late_contradicted, want, "{name}: late");
        }
        if let Some(want) = f.get("untrustedContradicted") {
            let want: Vec<String> = serde_json::from_value(want.clone()).unwrap();
            assert_eq!(
                r.execution.untrusted_contradicted, want,
                "{name}: untrusted"
            );
        }
        if let Some(want) = f.get("dispatchConflicts") {
            let want: Vec<String> = serde_json::from_value(want.clone()).unwrap();
            assert_eq!(r.execution.dispatch_conflicts, want, "{name}: conflicts");
        }
        if let Some(want) = f.get("windowCapped") {
            let want: BTreeMap<String, bool> = serde_json::from_value(want.clone()).unwrap();
            let got: BTreeMap<String, bool> = r
                .execution
                .by_nonce
                .iter()
                .map(|(n, v)| (n.clone(), v.window_capped))
                .collect();
            assert_eq!(got, want, "{name}: windowCapped");
        }
        if let Some(want) = f.get("sources") {
            let want: BTreeMap<String, SourceContinuity> =
                serde_json::from_value(want.clone()).unwrap();
            assert_eq!(r.execution.sources, want, "{name}: sources");
        }
        // The per-nonce report and each check agree with the lists they are summarized into.
        for (nonce, item) in &r.execution.by_nonce {
            assert_eq!(
                !item.dispatch_conflict.is_empty(),
                r.execution.dispatch_conflicts.contains(nonce),
                "{name}: {nonce} conflict"
            );
            assert_eq!(
                !item.late_contradiction.is_empty(),
                r.execution.late_contradicted.contains(nonce),
                "{name}: {nonce} late"
            );
            assert_eq!(
                !item.untrusted_contradiction.is_empty(),
                r.execution.untrusted_contradicted.contains(nonce),
                "{name}: {nonce} untrusted"
            );
            assert_eq!(
                item.effective_deadline.is_some(),
                item.dispatch_seq.is_some(),
                "{name}: {nonce} deadline"
            );
        }
        for (seq, k) in &r.execution.checks {
            assert_eq!(
                k.source.is_some(),
                k.sequence.is_some(),
                "{name}: seq {seq} source/sequence"
            );
            assert_eq!(
                k.nonce.is_some(),
                k.sequence.is_some(),
                "{name}: seq {seq} nonce/sequence"
            );
        }
        if !c["signatures"].is_null() {
            let sigs: Vec<(String, String, bool)> = r
                .signatures
                .checks
                .iter()
                .map(|(s, k)| (s.clone(), k.status.clone(), k.trusted))
                .collect();
            assert_eq!(sigs, rows(&c["signatures"]), "{name}: signatures");
        }
    }
    for c in section["proofs"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let o = &c["options"];
        let bundle: ProofBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
        let bo: BundleVerifyOptions<_> = BundleVerifyOptions {
            trusted_root: o["trustedRoot"].as_str().map(str::to_owned),
            resolve_anchor_key: Some(&no_resolver),
            ..Default::default()
        };
        let policy: Option<ExecutionEvidencePolicy> = if o["evidencePolicy"].is_null() {
            None
        } else {
            Some(serde_json::from_value(o["evidencePolicy"].clone()).unwrap())
        };
        let r = verify_bundle_with_evidence(&bundle, &bo, policy.as_ref());
        assert!(r.properties.content_verified, "{name}");
        let got = r.execution.map(|e| (e.status, e.trusted));
        let want = if c["execution"].is_null() {
            None
        } else {
            Some((
                c["execution"]["status"].as_str().unwrap().to_string(),
                c["execution"]["trusted"].as_bool().unwrap(),
            ))
        };
        assert_eq!(got, want, "{name}");
    }
    for c in section["statements"].as_array().unwrap() {
        let ok = parse_execution_evidence_statement(c["bytes"].as_str().unwrap()).is_ok();
        assert_eq!(ok, c["ok"].as_bool().unwrap(), "statement {}", c["name"]);
    }
    for c in section["builder"].as_array().unwrap() {
        let i = &c["input"];
        let bytes = canonical_execution_evidence_statement(&ExecutionEvidenceStatement {
            nonce: i["nonce"].as_str().unwrap().into(),
            payload_sha256: i["payloadSha256"].as_str().unwrap().into(),
            observation: i["observation"].as_object().unwrap().clone(),
            observed_at: i["observedAt"].as_str().unwrap().into(),
            sampled_at: i["sampledAt"].as_str().unwrap().into(),
            sequence: i["sequence"].as_u64().unwrap(),
            source: i["source"].as_str().unwrap().into(),
            verdict: i["verdict"].as_str().unwrap().into(),
        })
        .unwrap();
        assert_eq!(bytes, c["bytes"].as_str().unwrap(), "builder {}", c["name"]);
    }
}

/// The `delegation` section: a seal verified with `verify_delegation` against a DID-mode anchor.
#[test]
fn shared_delegation_seals() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    run_delegation_cases(&vectors["delegation"], &key_table(&vectors["keys"]));
}

/// The `enrolledDevice` section (DIV §4.3.2 enrolled approver devices): its own keys; approvals
/// through the approval harness (with `expected.enrolled_device_keys`), and the delegation and
/// agent-authority kinds, which can never carry the field.
#[test]
fn shared_enrolled_device_vectors() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let section = &vectors["enrolledDevice"];
    let keys = key_table(&section["keys"]);
    for part in ["approvals", "delegation", "agentAuthority"] {
        assert!(
            !section[part]["cases"].as_array().unwrap().is_empty(),
            "{part}"
        );
    }
    run_approval_cases(&section["approvals"], &keys);
    run_delegation_cases(&section["delegation"], &keys);
    run_authority_cases(&section["agentAuthority"], &keys);
}

fn run_delegation_cases(section: &Value, keys: &BTreeMap<String, Value>) {
    let cases = section["cases"].as_array().expect("a delegation section");
    assert!(!cases.is_empty());
    for case in cases {
        let e = merged(&section["expected"], &case["expected"]);
        if floor_refused_by_type(case, &e) {
            continue;
        }
        let mappings: BTreeMap<String, Vec<String>> = e["approverDids"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(did, ids)| {
                (
                    did.clone(),
                    ids.as_array()
                        .unwrap()
                        .iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            })
            .collect();
        let expected = Expected {
            target: e["target"].as_str().unwrap().into(),
            nonce: String::new(),
            action_type: e["actionType"].as_str().unwrap().into(),
            params: e["params"].clone(),
            requester_did: e["requesterDid"].as_str().map(str::to_owned),
            approvers: ApproverTrustAnchor::DidsMultiKey {
                dids: mappings.keys().cloned().collect(),
                resolve: Box::new(move |did| mappings.get(did).cloned().unwrap_or_default()),
            },
            requirement: floor(&e["requirement"]),
            tenant_id: e["tenantId"].as_str().map(str::to_owned),
            enrolled_device_keys: None,
        };
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_delegation(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        assert_reason_fields(case, &result);
        if let Ok(d) = result {
            if let Some(signers) = case.get("signers") {
                assert_eq!(json!(d.signers), *signers, "{}", case["name"]);
            }
            if let Some(to) = case.get("delegatedTo") {
                assert_eq!(json!(d.delegated_to), *to, "{}", case["name"]);
            }
            if let Some(q) = case.get("delegatedQuorum") {
                assert_eq!(json!(d.delegated_quorum), *q, "{}", case["name"]);
            }
        }
    }
}
