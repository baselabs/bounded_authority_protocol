use bounded_authority_protocol::facts::{NotEvaluated, SignatureAndWindow};
use bounded_authority_protocol::types::{
    HistoricalPublicKey, SigningInput, SigningKind, ValidityUpperBound,
};
use bounded_authority_protocol::{
    assemble_content_assertion_compact, assertion_digest, assertion_signing_input, content_digest,
    decode_content_assertion, verify_content_assertion, verify_content_assertion_successor, Bounds,
    ContentAssertionFacts, ContentAssertionInput, ExpectedContentAssertion, Invalid,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTENT_CORPUS_INDEX_SHA256: &str =
    "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876";

fn ephemeral_signing_key(label: &[u8]) -> SigningKey {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut h = Sha256::new();
    h.update(label);
    h.update(now.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn fixture(
    key_id: &str,
    generation: i64,
    previous: [u8; 32],
    iat: i64,
    nbf: i64,
    exp: i64,
) -> (ContentAssertionInput, ExpectedContentAssertion, SigningKey) {
    let signing_key = ephemeral_signing_key(key_id.as_bytes());
    let profile_digest: [u8; 32] = Sha256::digest(b"content-profile-v1").into();
    let content = content_digest(br#"{"value":"one"}"#, &Bounds::maximum()).unwrap();
    let input = ContentAssertionInput {
        attestor_key_id: key_id.to_string(),
        jti: format!("urn:assertion:{key_id}"),
        iss: "https://issuer.example".to_string(),
        aud: "urn:example:audience:1".to_string(),
        sub: "urn:lineage:installation-1".to_string(),
        profile: "urn:example:content-profile:1".to_string(),
        profile_digest,
        content_digest: content,
        generation,
        previous,
        issued_at: iat,
        not_before: nbf,
        expires_at: exp,
    };
    let expected = ExpectedContentAssertion {
        attestor: HistoricalPublicKey {
            key_id: key_id.to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
            valid_from: iat - 10,
            valid_before: ValidityUpperBound::Bounded(exp + 10),
        },
        issuer: input.iss.clone(),
        audience: input.aud.clone(),
        subject: input.sub.clone(),
        profile: input.profile.clone(),
        profile_digest,
        content_digest: content,
        now: nbf,
        bounds: Bounds::maximum(),
    };
    (input, expected, signing_key)
}

fn sign(input: &ContentAssertionInput, key: &SigningKey, bounds: &Bounds) -> Vec<u8> {
    let produced = assertion_signing_input(input, bounds).unwrap();
    let signature = key.sign(&produced.message).to_bytes();
    let signing_input = SigningInput {
        kind: SigningKind::ContentAssertion,
        protected_segment: produced.protected_segment,
        payload_segment: produced.payload_segment,
    };
    assemble_content_assertion_compact(&signing_input, &signature, Some(bounds)).unwrap()
}

#[test]
fn content_digest_uses_exact_domain_and_enforces_bound() {
    let content = b"exact content bytes";
    let mut h = Sha256::new();
    h.update(b"BAP1-CONTENT\0");
    h.update(content);
    let want: [u8; 32] = h.finalize().into();
    assert_eq!(content_digest(content, &Bounds::maximum()), Ok(want));
    assert_eq!(content_digest(b"", &Bounds::maximum()), Err(Invalid));
    assert!(content_digest(&vec![0u8; 65_536], &Bounds::maximum()).is_ok());
    assert_eq!(
        content_digest(&vec![0u8; 65_537], &Bounds::maximum()),
        Err(Invalid)
    );
    let overrides =
        bounded_authority_protocol::json_decode(br#"{"content_bytes":3}"#, &Bounds::maximum())
            .unwrap();
    let tight = Bounds::new(Some(&overrides)).unwrap();
    assert_eq!(content_digest(b"four", &tight), Err(Invalid));
}

#[test]
fn producer_decode_verify_digest_and_signature_tamper() {
    let bounds = Bounds::maximum();
    let (input, expected, key) = fixture("attestor-1", 1, [0u8; 32], 100, 110, 200);
    let compact = sign(&input, &key, &bounds);
    let decoded = decode_content_assertion(&compact, &bounds).unwrap();
    assert_eq!(decoded.verification, NotEvaluated);
    assert_eq!(decoded.content_digest, input.content_digest);
    let facts = verify_content_assertion(&compact, &expected).unwrap();
    let want: [u8; 32] = Sha256::digest(&compact).into();
    assert_eq!(facts.digest, want);
    assert_eq!(facts.verification, SignatureAndWindow);
    assert_eq!(facts.trust, NotEvaluated);
    assert_eq!(assertion_digest(&compact, &bounds), Ok(want));
    let mut wrong = expected.clone();
    wrong.content_digest[0] ^= 1;
    assert_eq!(verify_content_assertion(&compact, &wrong), Err(Invalid));
    let mut tampered = compact.clone();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(verify_content_assertion(&tampered, &expected), Err(Invalid));
}

#[test]
fn producer_rejects_genesis_and_time_defects() {
    let bounds = Bounds::maximum();
    let (input, _, _) = fixture("attestor-1", 1, [0u8; 32], 100, 110, 200);
    let mut bad = input.clone();
    bad.generation = 2;
    assert_eq!(assertion_signing_input(&bad, &bounds), Err(Invalid));
    bad = input.clone();
    bad.previous[0] = 1;
    assert_eq!(assertion_signing_input(&bad, &bounds), Err(Invalid));
    bad = input.clone();
    bad.issued_at = bad.not_before + 1;
    assert_eq!(assertion_signing_input(&bad, &bounds), Err(Invalid));
    bad = input;
    bad.not_before = bad.expires_at;
    assert_eq!(assertion_signing_input(&bad, &bounds), Err(Invalid));
}

#[test]
fn successor_allows_rotation_and_expired_predecessor() {
    let bounds = Bounds::maximum();
    let (pred_input, pred_expected, pred_key) =
        fixture("attestor-old", 1, [0u8; 32], 100, 110, 120);
    let pred_compact = sign(&pred_input, &pred_key, &bounds);
    let pred = verify_content_assertion(&pred_compact, &pred_expected).unwrap();
    let (mut succ_input, mut succ_expected, succ_key) =
        fixture("attestor-new", 2, pred.digest, 200, 210, 300);
    succ_input.iss = pred.iss.clone();
    succ_input.aud = pred.aud.clone();
    succ_input.sub = pred.sub.clone();
    succ_input.profile = pred.profile.clone();
    succ_input.profile_digest = pred.profile_digest;
    succ_expected.issuer = succ_input.iss.clone();
    succ_expected.audience = succ_input.aud.clone();
    succ_expected.subject = succ_input.sub.clone();
    succ_expected.profile = succ_input.profile.clone();
    succ_expected.profile_digest = succ_input.profile_digest;
    let succ_compact = sign(&succ_input, &succ_key, &bounds);
    let succ = verify_content_assertion(&succ_compact, &succ_expected).unwrap();
    assert_eq!(
        verify_content_assertion_successor(&pred, &succ, &bounds),
        Ok(())
    );
    assert_ne!(pred.attestor_key_fingerprint, succ.attestor_key_fingerprint);
    let mut bad = succ.clone();
    bad.jti = pred.jti.clone();
    assert_eq!(
        verify_content_assertion_successor(&pred, &bad, &bounds),
        Err(Invalid)
    );
    let malformed = ContentAssertionFacts {
        verification: SignatureAndWindow,
        trust: NotEvaluated,
        version: 0,
        ..succ
    };
    assert_eq!(
        verify_content_assertion_successor(&pred, &malformed, &bounds),
        Err(Invalid)
    );
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../priv/conformance/attestation-profiles/content-assertion/v1")
}

fn corpus_bytes(name: &str) -> Vec<u8> {
    fs::read(corpus_root().join(name)).unwrap()
}

fn corpus_json(name: &str) -> Value {
    serde_json::from_slice(&corpus_bytes(name)).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn corpus_fixed_digest(value: &str) -> Result<[u8; 32], Invalid> {
    bounded_authority_protocol::base64url_decode(value.as_bytes())
        .and_then(|bytes| bytes.as_slice().try_into().map_err(|_| Invalid))
}

fn corpus_bounds(value: Option<&Value>) -> Result<Bounds, Invalid> {
    match value {
        Some(bounds) => {
            let encoded = serde_json::to_vec(bounds).map_err(|_| Invalid)?;
            let decoded = bounded_authority_protocol::json_decode(&encoded, &Bounds::maximum())?;
            Bounds::new(Some(&decoded))
        }
        None => Ok(Bounds::maximum()),
    }
}

fn corpus_expected(
    profile: &Value,
    attestor_name: Option<&str>,
    overrides: Option<&Value>,
    bounds: Bounds,
) -> Result<ExpectedContentAssertion, Invalid> {
    let base = &profile["expected"];
    let override_value = overrides.unwrap_or(&Value::Null);
    let pick_string = |key: &str| -> Result<String, Invalid> {
        override_value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| base.get(key).and_then(Value::as_str).map(str::to_owned))
            .ok_or(Invalid)
    };
    let attestor = &profile["attestors"][attestor_name.unwrap_or("primary")];
    let key_id = override_value
        .get("attestor_key_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| attestor["key_id"].as_str().unwrap());
    let public_key = override_value
        .get("attestor_public_key")
        .and_then(Value::as_str)
        .unwrap_or_else(|| attestor["public_key"].as_str().unwrap());
    let valid_from = override_value
        .get("attestor_valid_from")
        .and_then(Value::as_i64)
        .or_else(|| attestor["valid_from"].as_i64())
        .ok_or(Invalid)?;
    let valid_before = override_value
        .get("attestor_valid_before")
        .and_then(Value::as_i64)
        .or_else(|| attestor["valid_before"].as_i64())
        .ok_or(Invalid)?;
    Ok(ExpectedContentAssertion {
        attestor: HistoricalPublicKey {
            key_id: key_id.to_owned(),
            public_key: corpus_fixed_digest(public_key)?,
            valid_from,
            valid_before: ValidityUpperBound::Bounded(valid_before),
        },
        issuer: pick_string("issuer")?,
        audience: pick_string("audience")?,
        subject: pick_string("subject")?,
        profile: pick_string("profile")?,
        profile_digest: corpus_fixed_digest(&pick_string("profile_digest")?)?,
        content_digest: corpus_fixed_digest(&pick_string("content_digest")?)?,
        now: override_value
            .get("now")
            .and_then(Value::as_i64)
            .or_else(|| base["now"].as_i64())
            .ok_or(Invalid)?,
        bounds,
    })
}

fn facts_input(
    decoded: &bounded_authority_protocol::DecodedContentAssertion,
) -> ContentAssertionInput {
    ContentAssertionInput {
        attestor_key_id: decoded.attestor_key_id.clone(),
        jti: decoded.jti.clone(),
        iss: decoded.iss.clone(),
        aud: decoded.aud.clone(),
        sub: decoded.sub.clone(),
        profile: decoded.profile.clone(),
        profile_digest: decoded.profile_digest,
        content_digest: decoded.content_digest,
        generation: decoded.generation,
        previous: decoded.previous,
        issued_at: decoded.issued_at,
        not_before: decoded.not_before,
        expires_at: decoded.expires_at,
    }
}

#[test]
fn certified_content_assertion_corpus_integrity_and_verdicts() {
    let index_bytes = corpus_bytes("index.json");
    assert_eq!(sha256_hex(&index_bytes), CONTENT_CORPUS_INDEX_SHA256);
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["profile"], "bap-content-assertion/1");
    assert_eq!(index["revision"], 1);
    assert_eq!(index["private_material_tracked"], false);
    for file in index["files"].as_array().unwrap() {
        let path = file["path"].as_str().unwrap();
        assert_eq!(
            sha256_hex(&corpus_bytes(path)),
            file["sha256"].as_str().unwrap()
        );
    }

    let digest_cases = corpus_json("digest-cases.json");
    assert_eq!(
        digest_cases.as_array().unwrap().len() as i64,
        index["digest_cases"]
    );
    for case in digest_cases.as_array().unwrap() {
        let input = &case["input"];
        let content = match input.get("content_file").and_then(Value::as_str) {
            Some(path) => Ok(corpus_bytes(path)),
            None => input
                .get("content_base64url")
                .and_then(Value::as_str)
                .ok_or(Invalid)
                .and_then(|encoded| {
                    bounded_authority_protocol::base64url_decode(encoded.as_bytes())
                }),
        };
        let result = corpus_bounds(input.get("bounds"))
            .and_then(|bounds| content.and_then(|bytes| content_digest(&bytes, &bounds)));
        let valid = case["expected"]["verdict"] == "valid";
        assert_eq!(result.is_ok(), valid, "{}", case["id"]);
        if let Ok(actual) = result {
            assert_eq!(
                actual,
                corpus_fixed_digest(case["expected"]["digest"].as_str().unwrap()).unwrap()
            );
        }
    }

    let profile = corpus_json("profile.json");
    let mut assertion_count = 0usize;
    let mut producer_count = 0usize;
    for name in [
        "assertion-structure-cases.json",
        "assertion-verification-cases.json",
    ] {
        let cases = corpus_json(name);
        assertion_count += cases.as_array().unwrap().len();
        for case in cases.as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let compact = case["compact"].as_str().unwrap().as_bytes();
            let bounds = corpus_bounds(case.get("bounds"));
            let decoded = bounds
                .as_ref()
                .map_err(|_| Invalid)
                .and_then(|bounds| decode_content_assertion(compact, bounds));
            assert_eq!(
                decoded.is_ok(),
                case["expected"]["decode"] == "valid",
                "{id}"
            );
            if let Ok(decoded) = &decoded {
                producer_count += 1;
                let produced =
                    assertion_signing_input(&facts_input(decoded), bounds.as_ref().unwrap())
                        .unwrap();
                let segments: Vec<&[u8]> = compact.split(|byte| *byte == b'.').collect();
                assert_eq!(produced.protected_segment, segments[0], "{id}");
                assert_eq!(produced.payload_segment, segments[1], "{id}");
                assert_eq!(
                    assertion_digest(compact, bounds.as_ref().unwrap()),
                    Ok(Sha256::digest(compact).into()),
                    "{id}"
                );
            }
            let verified = bounds.and_then(|bounds| {
                corpus_expected(
                    &profile,
                    case.get("attestor").and_then(Value::as_str),
                    case.get("expected_overrides"),
                    bounds,
                )
                .and_then(|expected| verify_content_assertion(compact, &expected))
            });
            assert_eq!(
                verified.is_ok(),
                case["expected"]["verify"] == "valid",
                "{id}"
            );
        }
    }
    assert_eq!(assertion_count as i64, index["assertion_cases"]);
    assert_eq!(producer_count, 38);
}

fn verify_corpus_artifact(
    profile: &Value,
    artifact: &Value,
) -> Result<ContentAssertionFacts, Invalid> {
    corpus_expected(
        profile,
        artifact.get("attestor").and_then(Value::as_str),
        artifact.get("expected_overrides"),
        Bounds::maximum(),
    )
    .and_then(|expected| {
        verify_content_assertion(
            artifact["compact"].as_str().ok_or(Invalid)?.as_bytes(),
            &expected,
        )
    })
}

fn apply_facts_overrides(
    mut facts: ContentAssertionFacts,
    overrides: Option<&Value>,
) -> Result<ContentAssertionFacts, Invalid> {
    let Some(overrides) = overrides.and_then(Value::as_object) else {
        return Ok(facts);
    };
    for (key, value) in overrides {
        match key.as_str() {
            "digest" => facts.digest = corpus_fixed_digest(value.as_str().ok_or(Invalid)?)?,
            "verification" | "trust" => return Err(Invalid),
            _ => return Err(Invalid),
        }
    }
    Ok(facts)
}

#[test]
fn certified_content_assertion_successor_corpus_verdicts() {
    let index = corpus_json("index.json");
    let profile = corpus_json("profile.json");
    let cases = corpus_json("successor-cases.json");
    assert_eq!(
        cases.as_array().unwrap().len() as i64,
        index["successor_cases"]
    );
    for case in cases.as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let predecessor = verify_corpus_artifact(&profile, &case["predecessor"]);
        let successor = verify_corpus_artifact(&profile, &case["successor"]);
        assert_eq!(
            predecessor.is_ok(),
            case["expected"]["predecessor"] == "valid",
            "{id}"
        );
        assert_eq!(
            successor.is_ok(),
            case["expected"]["successor"] == "valid",
            "{id}"
        );
        if case["expected"]["relation"] == "not_run" {
            continue;
        }
        let relation = predecessor
            .and_then(|facts| {
                apply_facts_overrides(facts, case["predecessor"].get("facts_overrides"))
            })
            .and_then(|predecessor| {
                successor
                    .and_then(|facts| {
                        apply_facts_overrides(facts, case["successor"].get("facts_overrides"))
                    })
                    .and_then(|successor| {
                        verify_content_assertion_successor(
                            &predecessor,
                            &successor,
                            &Bounds::maximum(),
                        )
                    })
            });
        assert_eq!(
            relation.is_ok(),
            case["expected"]["relation"] == "valid",
            "{id}"
        );
    }
}

#[test]
fn content_assertion_is_rejected_by_legacy_decoders_and_assembler() {
    let cases = corpus_json("assertion-structure-cases.json");
    let compact = cases[0]["compact"].as_str().unwrap().as_bytes();
    let bounds = Bounds::maximum();
    assert!(bounded_authority_protocol::decode_grant(compact, &bounds).is_err());
    assert!(bounded_authority_protocol::decode_proof(compact, &bounds).is_err());
    assert!(
        bounded_authority_protocol::decode_local_loopback_http_proof(compact, &bounds).is_err()
    );
    assert!(bounded_authority_protocol::decode_attestation(compact, &bounds).is_err());
    assert!(bounded_authority_protocol::v2::decode_grant(compact, &bounds).is_err());
    assert!(bounded_authority_protocol::v2::decode_proof(compact, &bounds).is_err());
    assert!(bounded_authority_protocol::v3::decode_grant(compact, &bounds).is_err());
    assert!(bounded_authority_protocol::v3::decode_proof(compact, &bounds).is_err());
    let input = SigningInput {
        kind: SigningKind::ContentAssertion,
        protected_segment: b"{}".to_vec(),
        payload_segment: b"{}".to_vec(),
    };
    assert!(bounded_authority_protocol::assemble_compact(&input, &[0u8; 64], None).is_err());
    assert!(bounded_authority_protocol::v2::assemble_compact(&input, &[0u8; 64], None).is_err());
    assert!(bounded_authority_protocol::v3::assemble_compact(&input, &[0u8; 64], None).is_err());
}
