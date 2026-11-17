//! The strict-Ed25519 conformance runner (profile `bap-strict-ed25519/1`).
//!
//! An integration test living OUTSIDE `src/` so it calls ONLY the crate's public surface. It:
//!
//! 1. **SHA-binds** the vendored snapshot: hashes `conformance/priv/conformance/strict-ed25519/index.json` at
//!    startup and fails closed on mismatch with the certified SHA-256, then verifies every listed
//!    file against the index's per-file SHA-256 and case count.
//! 2. **Recomputes every verdict** for all cases through the public façades: the primitive and
//!    key-acceptance helpers, the v1 and v2 façades (selected per case by `major`), the JWK and
//!    thumbprint family, and the loopback, role-attestation and content-assertion profiles.
//! 3. Requires `agreed == total_cases` and `disagreed == 0`.
//!
//! The snapshot is a byte-identical copy of `priv/conformance/strict-ed25519/`; earlier corpora
//! stay byte identical and keep their own runners.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol as bap;
use bounded_authority_protocol::types::*;
use bounded_authority_protocol::v2;
use bounded_authority_protocol::{Bounds, Invalid, JsonValue};
mod support;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CERTIFIED_INDEX_SHA: &str =
    "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9";
const PROFILE: &str = "bap-strict-ed25519/1";
const TOTAL_CASES: usize = 2410;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance/priv/conformance/strict-ed25519")
}

fn max() -> Bounds {
    Bounds::maximum()
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut acc, b| {
            write!(acc, "{b:02x}").unwrap();
            acc
        })
}

// ---- corpus value helpers ---------------------------------------------------------------------

fn b64(field: &Value) -> Vec<u8> {
    bap::base64url_decode(field.as_str().expect("base64url string").as_bytes())
        .expect("base64url decodes")
}

fn b64_32(field: &Value) -> [u8; 32] {
    let raw = b64(field);
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

/// `None` for a wrong-width value (rejected at the `[u8; 32]` import boundary).
fn try_b64_32(field: &Value) -> Option<[u8; 32]> {
    let raw = bap::base64url_decode(field.as_str()?.as_bytes()).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

fn serde_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Bool(b) => JsonValue::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => JsonValue::Int(i),
            None => JsonValue::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        Value::String(s) => JsonValue::String(s.clone()),
        Value::Array(a) => JsonValue::Array(a.iter().map(serde_to_json).collect()),
        Value::Object(o) => JsonValue::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), serde_to_json(v)))
                .collect(),
        ),
    }
}

fn s(v: &Value) -> String {
    v.as_str().expect("string").to_string()
}

fn historical_key(v: &Value) -> Option<HistoricalPublicKey> {
    Some(HistoricalPublicKey {
        key_id: s(&v["key_id"]),
        public_key: try_b64_32(&v["public_key"])?,
        valid_from: v["valid_from"].as_i64().unwrap(),
        valid_before: match v["valid_before"].as_i64() {
            Some(n) => ValidityUpperBound::Bounded(n),
            None => ValidityUpperBound::Unbounded,
        },
    })
}

fn expected_anchor(v: &Value) -> ExpectedAnchor {
    ExpectedAnchor {
        anchor_id: s(&v["anchor_id"]),
        anchored_at: v["anchored_at"].as_i64().unwrap(),
        chain_hash: b64_32(&v["chain_hash"]),
        chain_id: s(&v["chain_id"]),
        key_fingerprint: b64_32(&v["key_fingerprint"]),
        key_id: s(&v["key_id"]),
        sequence: v["sequence"].as_i64().unwrap(),
        bounds: None,
    }
}

fn expected_transition(v: &Value) -> ExpectedKeyTransition {
    ExpectedKeyTransition {
        chain_id: s(&v["chain_id"]),
        current_key_fingerprint: b64_32(&v["current_key_fingerprint"]),
        current_key_id: s(&v["current_key_id"]),
        effective_at: v["effective_at"].as_i64().unwrap(),
        next_key_fingerprint: b64_32(&v["next_key_fingerprint"]),
        next_key_id: s(&v["next_key_id"]),
        transition_id: s(&v["transition_id"]),
        bounds: None,
    }
}

fn expected_chain(v: &Value) -> ExpectedChain {
    ExpectedChain {
        chain_id: s(&v["chain_id"]),
        first_sequence: v["first_sequence"].as_i64().unwrap(),
        last_sequence: v["last_sequence"].as_i64().unwrap(),
        row_count: v["row_count"].as_i64().unwrap(),
        previous_hash: b64_32(&v["previous_hash"]),
        head_hash: b64_32(&v["last_hash"]),
        bounds: None,
    }
}

fn expected_export(e: &Value) -> ExpectedAnchoredExport {
    ExpectedAnchoredExport {
        chain: expected_chain(&e["chain"]),
        digest: b64_32(&e["digest"]),
        start_anchor: expected_anchor(&e["start_anchor"]),
        end_anchor: expected_anchor(&e["end_anchor"]),
        transitions: e["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(expected_transition)
            .collect(),
        object_version: s(&e["object_version"]),
        bounds: None,
    }
}

fn nonce_mode(exp: &Value) -> NonceMode {
    match exp.get("nonce") {
        None => NonceMode::NotRequired,
        Some(n) => NonceMode::Required(s(&n["required"])),
    }
}

fn expected_request(exp: &Value, trusted: TrustedIssuer) -> ExpectedRequest {
    ExpectedRequest {
        issuer: s(&exp["issuer"]),
        audience: s(&exp["audience"]),
        evaluation_time: exp["evaluation_time"].as_i64().unwrap(),
        skew: exp["clock_skew"].as_u64().unwrap(),
        bounds: max(),
        method: s(&exp["method"]),
        target_uri: s(&exp["target_uri"]),
        invocation_id: s(&exp["invocation_id"]),
        operation: s(&exp["operation"]),
        cast_arguments: serde_to_json(&exp["cast_arguments"]),
        proof_max_age: exp["proof_max_age"].as_u64().unwrap(),
        nonce_mode: nonce_mode(exp),
        trusted_issuer: trusted,
    }
}

fn verdict(accepted: bool) -> Value {
    json!({"verdict":if accepted {"valid"}else{"invalid"}})
}
fn result_value(result: Result<Value, Invalid>) -> Value {
    match result {
        Ok(mut v) => {
            v.as_object_mut()
                .unwrap()
                .insert("verdict".into(), json!("valid"));
            v
        }
        Err(Invalid) => verdict(false),
    }
}

// ---- dispatch ---------------------------------------------------------------------------------

fn run_primitive(case: &Value) -> Value {
    let input = &case["input"];
    let accepted = match case["surface"].as_str().unwrap() {
        "ed25519.verify_strict" => {
            let message = if input["message"].as_str().unwrap().is_empty() {
                Vec::new()
            } else {
                b64(&input["message"])
            };
            bap::verify_strict(
                &message,
                &b64(&input["signature"]),
                &b64(&input["public_key"]),
            )
        }
        "ed25519.acceptable_public_key" => bap::acceptable_public_key(&b64(&input["public_key"])),
        "ed25519.torsion_free" => bap::torsion_free(&b64(&input["public_key"])),
        other => panic!("unknown primitive surface {other}"),
    };
    verdict(accepted)
}

fn jwk_x(text: &str) -> Option<[u8; 32]> {
    // The raw key behind a JWK text, WITHOUT key acceptance, so the fallible thumbprint family is
    // exercised on weak keys directly.
    let value = bap::json_decode(text.as_bytes(), &max()).ok()?;
    let JsonValue::Object(members) = value else {
        return None;
    };
    let x = members.iter().find(|(k, _)| k == "x")?;
    let JsonValue::String(x) = &x.1 else {
        return None;
    };
    let raw = bap::base64url_decode(x.as_bytes()).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

fn run_jwk(case: &Value) -> Value {
    let surface = case["surface"].as_str().unwrap();
    let input = &case["input"];
    let result = (|| {
        let key = if surface == "jwk.encode_public" || surface == "jwk.public_key_thumbprint_raw" {
            try_b64_32(&input["public_key"]).ok_or(Invalid)?
        } else if surface == "jwk.decode_public" {
            bap::jwk_decode_public(input["text"].as_str().unwrap().as_bytes())?
        } else {
            jwk_x(input["text"].as_str().unwrap()).ok_or(Invalid)?
        };
        Ok(match surface {
            "jwk.encode_public" => {
                json!({"encoded":String::from_utf8(bap::jwk_encode_public(&key)?).unwrap()})
            }
            "jwk.decode_public" => {
                json!({"public_key":String::from_utf8(bap::base64url_encode(&key)).unwrap()})
            }
            "jwk.thumbprint" => {
                json!({"thumbprint":String::from_utf8(bap::thumbprint(&key)?).unwrap()})
            }
            "jwk.thumbprint_preimage" => {
                json!({"preimage":String::from_utf8(bap::thumbprint_preimage(&key)?).unwrap()})
            }
            "jwk.thumbprint_raw" => {
                json!({"thumbprint_raw":String::from_utf8(bap::base64url_encode(&bap::thumbprint_raw(&key)?)).unwrap()})
            }
            "jwk.public_key_thumbprint_raw" => {
                json!({"thumbprint_raw":String::from_utf8(bap::base64url_encode(&bap::public_key_thumbprint_raw(&key)?)).unwrap()})
            }
            _ => panic!("unknown JWK surface"),
        })
    })();
    result_value(result)
}

fn json_input_bytes(input: &Value) -> Vec<u8> {
    match input.get("base64url") {
        Some(b) => bap::base64url_decode(b.as_str().unwrap().as_bytes()).unwrap(),
        None => input["text"].as_str().unwrap().as_bytes().to_vec(),
    }
}

fn json_value(value: &JsonValue) -> serde_json::Value {
    match value {
        JsonValue::Null => serde_json::Value::Null,
        JsonValue::Bool(b) => json!(b),
        JsonValue::Int(n) => json!(n),
        JsonValue::Float(n) => json!(n),
        JsonValue::String(s) => json!(s),
        JsonValue::Array(a) => json!(a.iter().map(json_value).collect::<Vec<_>>()),
        JsonValue::Object(o) => {
            serde_json::Value::Object(o.iter().map(|(k, v)| (k.clone(), json_value(v))).collect())
        }
    }
}

fn run_shaped(case: &Value, major: i64) -> Value {
    let input = &case["input"];
    let second_major = major == 2;
    match case["surface"].as_str().unwrap() {
        "json.decode" => result_value(
            bap::json_decode(&json_input_bytes(input), &max())
                .map(|v| json!({"value":json_value(&v)})),
        ),
        "jcs.encode" => result_value(
            bap::json_decode(&json_input_bytes(input), &max())
                .and_then(|v| bap::jcs_encode(&v, &max()))
                .map(|b| json!({"encoded":String::from_utf8(b).unwrap()})),
        ),
        "request_digest" => {
            let operation = input["operation"].as_str().unwrap();
            let args = serde_to_json(&input["cast_arguments"]);
            let result = if second_major {
                v2::request_digest(operation, &args, &max())
            } else {
                bap::request_digest(operation, &args, &max())
            };
            result_value(result.map(|d| json!({"digest":String::from_utf8(d).unwrap()})))
        }
        surface if surface.starts_with("jwk.") => run_jwk(case),
        "verify_grant" => {
            let Some(public_key) = try_b64_32(&input["public_key"]) else {
                return verdict(false);
            };
            let issuer = TrustedIssuer {
                key_id: s(&input["key_id"]),
                public_key,
            };
            let expected = ExpectedGrant {
                issuer: s(&input["issuer"]),
                audience: s(&input["audience"]),
                evaluation_time: input["evaluation_time"].as_i64().unwrap(),
                skew: input["clock_skew"].as_u64().unwrap(),
                bounds: max(),
            };
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let result = if second_major {
                v2::verify_grant(compact, &issuer, &expected)
            } else {
                bap::verify_grant(compact, &issuer, &expected)
            };
            result_value(result.map(|facts| {
                assert_eq!(facts.version, major, "verify_grant: version fact");
                assert_eq!(
                    facts.authorization,
                    bap::facts::NotEvaluated,
                    "authorization fact"
                );
                json!({"grant_id":facts.grant_id,"issuer":facts.issuer})
            }))
        }
        "check_envelope" => {
            let exp = &input["expected"];
            let Some(public_key) = try_b64_32(&exp["trusted_issuer"]["public_key"]) else {
                return verdict(false);
            };
            let trusted = TrustedIssuer {
                key_id: s(&exp["trusted_issuer"]["key_id"]),
                public_key,
            };
            let expected = expected_request(exp, trusted);
            let creds = Credentials {
                grant: input["grant"].as_str().unwrap().as_bytes().to_vec(),
                proof: input["proof"].as_str().unwrap().as_bytes().to_vec(),
            };
            let result = if second_major {
                v2::check_envelope(&creds, &expected)
            } else {
                bap::check_envelope(&creds, &expected)
            };
            result_value(result.map(|facts| {
                assert_eq!(facts.grant.version, major, "check_envelope: version fact");
                assert_eq!(
                    facts.authorization,
                    bap::facts::NotEvaluated,
                    "authorization fact"
                );
                json!({})
            }))
        }
        "verify_historical_anchor" => {
            let Some(key) = historical_key(&input["key"]) else {
                return verdict(false);
            };
            let expected = expected_anchor(&input["expected"]);
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let result = if second_major {
                v2::verify_historical_anchor(compact, &key, &expected)
            } else {
                bap::verify_historical_anchor(compact, &key, &expected)
            };
            result_value(result.map(|facts| {
                assert_eq!(
                    facts.anchor_id, expected.anchor_id,
                    "anchor: anchor_id fact"
                );
                assert_eq!(facts.sequence, expected.sequence, "anchor: sequence fact");
                assert_eq!(
                    facts.chain_hash, expected.chain_hash,
                    "anchor: chain_hash fact"
                );
                assert_eq!(
                    facts.key_fingerprint, expected.key_fingerprint,
                    "anchor: key_fingerprint fact"
                );
                assert_eq!(facts.trust, bap::facts::NotEvaluated, "trust fact");
                json!({"anchor_id":facts.anchor_id})
            }))
        }
        "verify_key_transition" => {
            let (Some(current), Some(next)) = (
                historical_key(&input["current_key"]),
                historical_key(&input["next_key"]),
            ) else {
                return verdict(false);
            };
            let expected = expected_transition(&input["expected"]);
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let result = if second_major {
                v2::verify_key_transition(compact, &current, &next, &expected)
            } else {
                bap::verify_key_transition(compact, &current, &next, &expected)
            };
            result_value(result.map(|facts| {
                assert_eq!(
                    facts.transition_id, expected.transition_id,
                    "transition: transition_id fact"
                );
                assert_eq!(
                    facts.current_key_fingerprint, expected.current_key_fingerprint,
                    "transition: current fingerprint fact"
                );
                assert_eq!(
                    facts.next_key_fingerprint, expected.next_key_fingerprint,
                    "transition: next fingerprint fact"
                );
                assert_eq!(facts.trust, bap::facts::NotEvaluated, "trust fact");
                json!({"transition_id":facts.transition_id})
            }))
        }
        "verify_anchored_export" => {
            let chunks: Vec<Vec<u8>> = input["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| bap::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
                .collect();
            let obj = ArchivedObject {
                chunks,
                version: s(&input["version"]),
            };
            let keys: Option<Vec<HistoricalPublicKey>> = input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key)
                .collect();
            let Some(keys) = keys else {
                return verdict(false);
            };
            let keys = HistoricalKeyChain { keys };
            let expected = expected_export(&input["expected"]);
            let result = if second_major {
                v2::verify_anchored_export(&obj, &keys, &expected)
            } else {
                bap::verify_anchored_export(&obj, &keys, &expected)
            };
            result_value(result.map(|facts| {
                assert_eq!(
                    facts.chain_id, expected.chain.chain_id,
                    "export: chain_id fact"
                );
                assert_eq!(
                    facts.row_count, expected.chain.row_count,
                    "export: row_count fact"
                );
                assert_eq!(facts.trust, bap::facts::NotEvaluated, "trust fact");
                assert_eq!(
                    facts.authorization,
                    bap::facts::NotEvaluated,
                    "authorization fact"
                );
                json!({"chain_id":facts.chain_id})
            }))
        }
        other => panic!("case {}: unknown strict surface {other}", case["id"]),
    }
}

fn run_loopback(case: &Value) -> Value {
    let issuer = &case["issuer"];
    let request = &case["request"];
    let trusted = TrustedIssuer {
        key_id: s(&issuer["key_id"]),
        public_key: b64_32(&issuer["public_key"]),
    };
    let expected = ExpectedRequest {
        issuer: s(&issuer["issuer"]),
        audience: s(&issuer["audience"]),
        evaluation_time: request["evaluation_time"].as_i64().unwrap(),
        skew: request["clock_skew"].as_u64().unwrap(),
        bounds: max(),
        method: s(&request["method"]),
        target_uri: s(&case["target_uri"]),
        invocation_id: s(&request["invocation_id"]),
        operation: s(&request["operation"]),
        cast_arguments: serde_to_json(&request["cast_arguments"]),
        proof_max_age: request["proof_max_age"].as_u64().unwrap(),
        nonce_mode: NonceMode::Required(s(&case["nonce"])),
        trusted_issuer: trusted,
    };
    let compact = case["compact"].as_str().unwrap().as_bytes();
    let creds = Credentials {
        grant: case["grant"].as_str().unwrap().as_bytes().to_vec(),
        proof: compact.to_vec(),
    };
    json!({"decode_local":bap::decode_local_loopback_http_proof(compact,&max()).is_ok(),"decode_standard":bap::decode_proof(compact,&max()).is_ok(),"envelope_local":bap::check_local_loopback_http_envelope(&creds,&expected).is_ok()})
}

fn run_role_attestation(case: &Value) -> Value {
    let expected = ExpectedAttestation {
        attestor: historical_key(&case["attestor"]).expect("32-byte attestor key"),
        subject_key_id: s(&case["subject"]["key_id"]),
        subject_public_key: b64_32(&case["subject"]["public_key"]),
        now: case["now"].as_i64().unwrap(),
        bounds: max(),
    };
    let compact = case["compact"].as_str().unwrap().as_bytes();
    json!({"decode":bap::decode_attestation(compact,&max()).is_ok(),"verify":bap::verify_attestation(compact,&expected).is_ok()})
}

fn run_content_assertion(case: &Value) -> Value {
    let context = &case["expected_context"];
    let expected = bap::ExpectedContentAssertion {
        attestor: historical_key(&case["attestor"]).expect("32-byte attestor key"),
        issuer: s(&context["issuer"]),
        audience: s(&context["audience"]),
        subject: s(&context["subject"]),
        profile: s(&context["profile"]),
        profile_digest: b64_32(&context["profile_digest"]),
        content_digest: b64_32(&context["content_digest"]),
        now: context["now"].as_i64().unwrap(),
        bounds: max(),
    };
    let compact = case["compact"].as_str().unwrap().as_bytes();
    json!({"decode":if bap::decode_content_assertion(compact,&max()).is_ok(){"valid"}else{"invalid"},"verify":if bap::verify_content_assertion(compact,&expected).is_ok(){"valid"}else{"invalid"}})
}

fn run_case(case: &Value) -> Value {
    match case["surface"].as_str().unwrap() {
        "ed25519.verify_strict" | "ed25519.acceptable_public_key" | "ed25519.torsion_free" => {
            run_primitive(case)
        }
        "local_loopback_http" => run_loopback(case),
        "role_attestation" => run_role_attestation(case),
        "content_assertion" => run_content_assertion(case),
        _ => run_shaped(case, case["major"].as_i64().unwrap_or(1)),
    }
}

#[test]
fn strict_ed25519_corpus_all_cases_agree() {
    let root = corpus_root();
    let mut execution = support::Run::new(&root, CERTIFIED_INDEX_SHA);
    let index_bytes = fs::read(root.join("index.json")).expect("vendored index.json");
    let actual = hex_sha256(&index_bytes);
    assert_eq!(
        actual, CERTIFIED_INDEX_SHA,
        "index.json SHA mismatch — corpus drift (expected {CERTIFIED_INDEX_SHA}, got {actual})"
    );
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["profile"], PROFILE);
    assert_eq!(index["revision"], 1);
    assert_eq!(index["total_cases"], TOTAL_CASES);

    let mut families: BTreeMap<String, usize> = BTreeMap::new();
    let mut cases: Vec<Value> = Vec::new();
    for entry in index["files"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let body = fs::read(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            hex_sha256(&body),
            entry["sha256"].as_str().unwrap(),
            "{path}: file SHA"
        );
        if path == "profile.json" || path == "revision.json" {
            assert_eq!(entry["cases"], 0, "{path} declares cases");
            continue;
        }
        let file: Value = serde_json::from_slice(&body).unwrap();
        let file_cases = file["cases"].as_array().unwrap();
        assert_eq!(
            file_cases.len() as u64,
            entry["cases"].as_u64().unwrap(),
            "{path}: case count"
        );
        *families.entry(s(&file["family"])).or_default() += file_cases.len();
        cases.extend(file_cases.iter().cloned().map(|mut c| {
            c["_file"] = serde_json::json!(path);
            c
        }));
    }
    let declared: BTreeMap<String, usize> = index["families"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap() as usize))
        .collect();
    assert_eq!(families, declared, "family counts differ from the index");
    assert_eq!(cases.len(), TOTAL_CASES);
    let mut ids: Vec<&str> = cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), TOTAL_CASES, "duplicate case ids");

    let mut failures = Vec::new();
    for case in &cases {
        let actual = run_case(case);
        execution.record(
            case["id"].as_str().unwrap(),
            case["_file"].as_str().unwrap(),
            actual.clone(),
        );
        let expected = support::outcome(case);
        let projected = Value::Object(
            expected
                .as_object()
                .unwrap()
                .keys()
                .filter_map(|k| actual.get(k).map(|v| (k.clone(), v.clone())))
                .collect(),
        );
        if projected != expected {
            failures.push(s(&case["id"]));
        }
    }
    execution.finish();
    assert!(
        failures.is_empty(),
        "{} of {} strict cases disagree: {:?}",
        failures.len(),
        cases.len(),
        &failures[..failures.len().min(20)]
    );
}
