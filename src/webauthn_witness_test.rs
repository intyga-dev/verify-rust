//! `verify_webauthn_witness` against the shared golden assertion (webauthn-vector.json) and the shared
//! `webauthnWitness` parity cases, mirroring packages/verify/src/webauthn-vector.test.ts and Go's
//! webauthn_witness_test.go.

use super::*;
use base64::engine::general_purpose::STANDARD as B64;

struct Golden {
    origin: String,
    rp_id: String,
    witness: WebAuthnWitness,
    receipt: ApprovalReceipt,
    expected: Expected,
}

fn golden() -> Golden {
    let doc: Value = serde_json::from_str(include_str!(
        "../vectors/webauthn-vector.json"
    ))
    .unwrap();
    let r = &doc["receipt"];
    let s = |k: &str| r[k].as_str().unwrap().to_string();
    let receipt: ApprovalReceipt = serde_json::from_value(r.clone()).unwrap();
    Golden {
        origin: doc["origin"].as_str().unwrap().into(),
        rp_id: doc["rpId"].as_str().unwrap().into(),
        witness: WebAuthnWitness {
            signed_payload: s("canonicalPayload"),
            public_key: s("signerPublicKey"),
            authenticator_data: s("authenticatorData"),
            client_data_json: s("clientDataJSON"),
            signature: s("signature"),
        },
        expected: Expected {
            requirement: None,
            target: doc["expected"]["target"].as_str().unwrap().into(),
            nonce: doc["expected"]["nonce"].as_str().unwrap().into(),
            action_type: doc["expected"]["actionType"].as_str().unwrap().into(),
            params: doc["expected"]["params"].clone(),
            requester_did: None,
            approvers: ApproverTrustAnchor::PublicKeys(vec![s("signerPublicKey")]),
            tenant_id: None,
            enrolled_device_keys: None,
        },
        receipt,
    }
}

fn expectation(g: &Golden) -> WebAuthnWitnessExpectation {
    WebAuthnWitnessExpectation {
        expected_origin: vec![g.origin.clone()],
        expected_rp_id: g.rp_id.clone(),
        ..Default::default()
    }
}

fn spki_from_cose(cose_b64: &str) -> String {
    use p256::pkcs8::EncodePublicKey;
    let cose = webauthn::decode_base64_flexible(cose_b64).unwrap();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&cose[10..42]);
    sec1.extend_from_slice(&cose[45..77]);
    let key = PublicKey::from_sec1_bytes(&sec1).unwrap();
    B64.encode(key.to_public_key_der().unwrap().as_bytes())
}

#[test]
fn golden_verifies_under_cose_or_spki_and_an_origin_list() {
    let g = golden();
    let exp = expectation(&g);
    assert_eq!(verify_webauthn_witness(&g.witness, &exp), Ok(()));
    let mut spki = g.witness.clone();
    spki.public_key = spki_from_cose(&g.witness.public_key);
    assert_eq!(verify_webauthn_witness(&spki, &exp), Ok(()));
    let multi = WebAuthnWitnessExpectation {
        expected_origin: vec!["https://other.example".into(), g.origin.clone()],
        ..exp.clone()
    };
    assert_eq!(verify_webauthn_witness(&g.witness, &multi), Ok(()));
    let cross = WebAuthnWitnessExpectation {
        allow_cross_origin: true,
        ..exp
    };
    assert_eq!(verify_webauthn_witness(&g.witness, &cross), Ok(()));
}

#[test]
fn binds_payload_key_origin_rp_and_signature() {
    use p256::pkcs8::EncodePublicKey;
    let g = golden();
    let exp = expectation(&g);
    let refused = |w: &WebAuthnWitness, e: &WebAuthnWitnessExpectation, want: &str| {
        let got = verify_webauthn_witness(w, e).expect_err("must refuse");
        assert_eq!(got, want);
    };
    let mut w = g.witness.clone();
    w.signed_payload.push(' ');
    refused(
        &w,
        &exp,
        "clientDataJSON challenge does not match canonical payload",
    );

    let other = p256::SecretKey::from_slice(&[7u8; 32])
        .unwrap()
        .public_key();
    let mut w = g.witness.clone();
    w.public_key = B64.encode(other.to_public_key_der().unwrap().as_bytes());
    refused(
        &w,
        &exp,
        "WebAuthn signature does not verify against the trusted signer key",
    );

    // A well-formed SPKI that is not P-256 (Ed25519).
    let mut w = g.witness.clone();
    w.public_key = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=".into();
    refused(
        &w,
        &exp,
        "WebAuthn verification failed: public key is not a P-256 key",
    );

    let evil_origin = WebAuthnWitnessExpectation {
        expected_origin: vec!["https://evil.example.com".into()],
        ..exp.clone()
    };
    refused(
        &g.witness,
        &evil_origin,
        "assertion origin does not match expected_origin",
    );
    let evil_rp = WebAuthnWitnessExpectation {
        expected_rp_id: "evil.example.com".into(),
        ..exp.clone()
    };
    refused(
        &g.witness,
        &evil_rp,
        "authenticatorData rpIdHash does not match expected_rp_id",
    );

    let mut sig = webauthn::decode_base64_flexible(&g.witness.signature).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    let mut w = g.witness.clone();
    w.signature = B64.encode(sig);
    assert!(
        verify_webauthn_witness(&w, &exp).is_err(),
        "tampered signature accepted"
    );
}

#[test]
fn fails_closed_and_never_panics() {
    let g = golden();
    const NEED: &str = "a WebAuthn witness requires expected_origin and expected_rp_id — without them an assertion from any relying party would verify";
    for e in [
        WebAuthnWitnessExpectation {
            expected_origin: vec![String::new()],
            expected_rp_id: g.rp_id.clone(),
            ..Default::default()
        },
        WebAuthnWitnessExpectation {
            expected_origin: vec![],
            expected_rp_id: g.rp_id.clone(),
            ..Default::default()
        },
        WebAuthnWitnessExpectation {
            expected_origin: vec![g.origin.clone()],
            ..Default::default()
        },
        WebAuthnWitnessExpectation::default(),
    ] {
        assert_eq!(
            verify_webauthn_witness(&g.witness, &e),
            Err(NEED.to_string())
        );
    }
    let exp = expectation(&g);
    for field in [
        "signedPayload",
        "publicKey",
        "authenticatorData",
        "clientDataJSON",
        "signature",
    ] {
        let mut w = g.witness.clone();
        match field {
            "signedPayload" => w.signed_payload.clear(),
            "publicKey" => w.public_key.clear(),
            "authenticatorData" => w.authenticator_data.clear(),
            "clientDataJSON" => w.client_data_json.clear(),
            _ => w.signature.clear(),
        }
        assert_eq!(
            verify_webauthn_witness(&w, &exp),
            Err(format!("WebAuthn witness missing {field}"))
        );
    }
    // Garbage in every field is a verdict, never a panic.
    for (key, auth, client) in [
        ("AAAA", "AAAA", "e30="),
        ("%%%", "%%%", "%%%"),
        ("oA==", "AAAA", B64.encode("null").as_str()),
        ("oA==", "AAAA", B64.encode("[1,2]").as_str()),
        (
            "oA==",
            "AAAA",
            B64.encode(r#"{"type":"webauthn.get","origin":5}"#).as_str(),
        ),
    ] {
        let w = WebAuthnWitness {
            public_key: key.into(),
            authenticator_data: auth.into(),
            client_data_json: client.into(),
            ..g.witness.clone()
        };
        assert!(verify_webauthn_witness(&w, &exp).is_err());
    }
}

/// The golden signature re-encoded as raw r‖s (IEEE P1363) is refused on both the standalone and
/// the receipt path, with the reference's text.
#[test]
fn webauthn_signature_is_der_only() {
    let g = golden();
    let der = webauthn::decode_base64_flexible(&g.witness.signature).unwrap();
    let raw = B64.encode(Signature::from_der(&der).unwrap().to_bytes());
    const WANT: &str = "WebAuthn signature does not verify against the trusted signer key";
    let w = WebAuthnWitness {
        signature: raw.clone(),
        ..g.witness.clone()
    };
    assert_eq!(
        verify_webauthn_witness(&w, &expectation(&g)),
        Err(WANT.into())
    );
    let mut receipt = g.receipt.clone();
    receipt.signature = Some(raw);
    let got = verify_approval_receipt_with_options(
        &receipt,
        &g.expected,
        &VerifyOptions {
            expected_origin: Some(g.origin.clone()),
            expected_rp_id: Some(g.rp_id.clone()),
            ..Default::default()
        },
    );
    assert_eq!(
        got,
        Err(format!(
            "quorum not met: 0 of 1 required approver signatures verified ({WANT})"
        ))
    );
}

/// The shared `webauthnWitness` section of verifier-parity-vectors.json.
#[test]
fn shared_webauthn_witness_cases() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let cases = vectors["webauthnWitness"]["cases"]
        .as_array()
        .expect("a webauthnWitness section");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap_or("(unnamed)");
        // Absent or non-string fields read as empty, i.e. missing, as the reference treats them.
        let field = |k: &str| case["witness"][k].as_str().unwrap_or_default().to_string();
        let witness = WebAuthnWitness {
            signed_payload: field("signedPayload"),
            public_key: field("publicKey"),
            authenticator_data: field("authenticatorData"),
            client_data_json: field("clientDataJSON"),
            signature: field("signature"),
        };
        let e = &case["expectation"];
        let expectation = WebAuthnWitnessExpectation {
            expected_origin: match &e["expectedOrigin"] {
                Value::String(o) => vec![o.clone()],
                Value::Array(list) => list
                    .iter()
                    .map(|o| o.as_str().unwrap_or_default().to_owned())
                    .collect(),
                _ => Vec::new(),
            },
            expected_rp_id: e["expectedRpId"].as_str().unwrap_or_default().into(),
            require_user_verification: e["requireUserVerification"].as_bool(),
            allow_cross_origin: e["allowCrossOrigin"].as_bool().unwrap_or(false),
        };
        let got = verify_webauthn_witness(&witness, &expectation);
        assert_eq!(
            got.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{name}: {got:?}"
        );
        let reason = got.as_ref().err().map(String::as_str);
        if let Some(exact) = case["reason"].as_str() {
            let want = parity_receipts_test::localized(exact);
            assert_eq!(reason, Some(want.as_str()), "{name}: exact reason");
        }
        if let Some(prefix) = case["reasonPrefix"].as_str() {
            let want = parity_receipts_test::localized(prefix);
            assert!(
                reason.is_some_and(|r| r.starts_with(&want)),
                "{name}: reason {reason:?} lacks prefix {want:?}"
            );
        }
    }
}
