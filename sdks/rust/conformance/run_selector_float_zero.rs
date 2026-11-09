//! The selector float-zero runner (profile `bap-selector-float-zero/1`, erratum 6): it executes
//! the vendored additive corpus (corpus-selector-float-zero, a byte-identical snapshot of
//! priv/conformance/selector-float-zero/) against grant decode, the grant signing-input producer
//! and envelope checking for contract-majors 1, 2 and 3. It SHA-binds the vendored index.json
//! before any case runs, verifies every listed file against the index's per-file SHA-256 and
//! case counts, and requires every case to agree.
//!
//! Typed values travel as JSON text (`input.operations_json`, `input.expected.
//! cast_arguments_json`) so the float/integer tag survives; the runner decodes them with the
//! crate's own tag-preserving `json_decode`, never through serde_json.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol as bap;
use bounded_authority_protocol::facts::NotEvaluated;
use bounded_authority_protocol::types::*;
use bounded_authority_protocol::{v2, v3, Bounds, Invalid, JsonValue};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CERTIFIED_INDEX_SHA: &str =
    "97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003";
const PROFILE: &str = "bap-selector-float-zero/1";
const REVISION: u64 = 1;
const TOTAL_CASES: usize = 161;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance")
        .join("corpus-selector-float-zero")
}

fn max() -> Bounds {
    Bounds::maximum()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    out.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        write!(acc, "{b:02x}").unwrap();
        acc
    })
}

fn load_cases() -> Vec<Value> {
    let index_bytes = fs::read(corpus_root().join("index.json")).expect("read index.json");
    assert_eq!(
        sha256_hex(&index_bytes),
        CERTIFIED_INDEX_SHA,
        "corpus index.json SHA-256 mismatch — silent drift is impossible"
    );
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["profile"].as_str().unwrap(), PROFILE);
    assert_eq!(index["revision"].as_u64().unwrap(), REVISION);
    assert_eq!(index["total_cases"].as_u64().unwrap() as usize, TOTAL_CASES);
    let mut cases = Vec::new();
    let mut counted = 0usize;
    for file in index["files"].as_array().unwrap() {
        let raw = fs::read(corpus_root().join(file["path"].as_str().unwrap())).unwrap();
        assert_eq!(
            sha256_hex(&raw),
            file["sha256"].as_str().unwrap(),
            "corpus file {} SHA-256 mismatch",
            file["path"]
        );
        if file["cases"].as_u64().unwrap() == 0 {
            continue; // profile.json / revision.json: integrity-checked, no cases
        }
        let doc: Value = serde_json::from_slice(&raw).unwrap();
        let doc_cases = doc["cases"].as_array().unwrap();
        assert_eq!(doc_cases.len(), file["cases"].as_u64().unwrap() as usize);
        counted += doc_cases.len();
        cases.extend(doc_cases.iter().cloned());
    }
    assert_eq!(counted, TOTAL_CASES);
    cases
}

/// Decodes JSON text with the crate's tag-preserving decoder (`0.0` stays Float, `0` Int).
fn typed(text: &Value) -> JsonValue {
    bap::json_decode(text.as_str().unwrap().as_bytes(), &max()).expect("corpus typed JSON text")
}

fn b64_fixed<const N: usize>(field: &Value) -> [u8; N] {
    bap::base64url_decode(field.as_str().unwrap().as_bytes())
        .expect("corpus base64url")
        .try_into()
        .expect("corpus fixed-width field")
}

fn member<'a>(object: &'a JsonValue, name: &str) -> &'a JsonValue {
    match object {
        JsonValue::Object(members) => {
            &members
                .iter()
                .find(|(k, _)| k == name)
                .expect("operation member")
                .1
        }
        _ => panic!("operation is not an object"),
    }
}

fn grant_input(input: &Value) -> GrantInput {
    let operations = match typed(&input["operations_json"]) {
        JsonValue::Array(ops) => ops
            .iter()
            .map(|op| GrantOperation {
                name: match member(op, "name") {
                    JsonValue::String(s) => s.clone(),
                    _ => panic!("operation name"),
                },
                selectors: match member(op, "selectors") {
                    JsonValue::Array(selectors) => selectors.clone(),
                    _ => panic!("operation selectors"),
                },
            })
            .collect(),
        _ => panic!("operations_json is not an array"),
    };
    GrantInput {
        issuer: input["issuer"].as_str().unwrap().to_string(),
        grant_id: input["grant_id"].as_str().unwrap().to_string(),
        key_id: input["key_id"].as_str().unwrap().to_string(),
        holder_thumbprint: b64_fixed::<32>(&input["holder_thumbprint"]),
        issued_at: input["issued_at"].as_i64().unwrap(),
        not_before: input["not_before"].as_i64().unwrap(),
        expires_at: input["expires_at"].as_i64().unwrap(),
        audiences: input["audiences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
        operations,
    }
}

fn run_decode(case: &Value) -> bool {
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    let key_id = match case["major"].as_u64().unwrap() {
        1 => bap::decode_grant(compact, &max()).map(|d| d.key_id),
        2 => v2::decode_grant(compact, &max()).map(|d| d.key_id),
        3 => v3::decode_grant(compact, &max()).map(|d| d.key_id),
        m => panic!("major {m}"),
    };
    match (key_id, case["expected"]["verdict"].as_str().unwrap()) {
        (Ok(k), "valid") => k == case["expected"]["key_id"].as_str().unwrap(),
        (Err(Invalid), "invalid") => true,
        _ => false,
    }
}

fn run_signing_input(case: &Value) -> bool {
    let grant = grant_input(&case["input"]);
    let produced = match case["major"].as_u64().unwrap() {
        1 => bap::grant_signing_input(&grant, &max()),
        2 => v2::grant_signing_input(&grant, &max()),
        3 => v3::grant_signing_input(&grant, &max()),
        m => panic!("major {m}"),
    };
    let exp = &case["expected"];
    match (produced, exp["verdict"].as_str().unwrap()) {
        (Ok(p), "valid") => {
            p.protected_segment == exp["protected_segment"].as_str().unwrap().as_bytes()
                && p.payload_segment == exp["payload_segment"].as_str().unwrap().as_bytes()
                && p.message == exp["message"].as_str().unwrap().as_bytes()
        }
        (Err(Invalid), "invalid") => true,
        _ => false,
    }
}

fn nonce_mode(exp: &Value) -> NonceMode {
    match exp.get("nonce") {
        None => NonceMode::NotRequired,
        Some(n) => NonceMode::Required(n["required"].as_str().unwrap().to_string()),
    }
}

fn run_envelope(case: &Value) -> bool {
    let input = &case["input"];
    let exp = &input["expected"];
    let credentials = Credentials {
        grant: input["grant"].as_str().unwrap().as_bytes().to_vec(),
        proof: input["proof"].as_str().unwrap().as_bytes().to_vec(),
    };
    let key_id = exp["trusted_issuer"]["key_id"]
        .as_str()
        .unwrap()
        .to_string();
    let major = case["major"].as_u64().unwrap();
    let result = if major == 3 {
        let expected = v3::ExpectedRequest {
            issuer: exp["issuer"].as_str().unwrap().to_string(),
            audience: exp["audience"].as_str().unwrap().to_string(),
            evaluation_time: exp["evaluation_time"].as_i64().unwrap(),
            skew: exp["clock_skew"].as_u64().unwrap(),
            bounds: max(),
            method: exp["method"].as_str().unwrap().to_string(),
            target_uri: exp["target_uri"].as_str().unwrap().to_string(),
            invocation_id: exp["invocation_id"].as_str().unwrap().to_string(),
            operation: exp["operation"].as_str().unwrap().to_string(),
            cast_arguments: typed(&exp["cast_arguments_json"]),
            proof_max_age: exp["proof_max_age"].as_u64().unwrap(),
            nonce_mode: nonce_mode(exp),
            trusted_issuer: v3::TrustedIssuer {
                key_id,
                public_key: b64_fixed::<65>(&exp["trusted_issuer"]["public_key"]),
            },
        };
        v3::check_envelope(&credentials, &expected).map(|f| (f.authorization, f.grant.version))
    } else {
        let expected = ExpectedRequest {
            issuer: exp["issuer"].as_str().unwrap().to_string(),
            audience: exp["audience"].as_str().unwrap().to_string(),
            evaluation_time: exp["evaluation_time"].as_i64().unwrap(),
            skew: exp["clock_skew"].as_u64().unwrap(),
            bounds: max(),
            method: exp["method"].as_str().unwrap().to_string(),
            target_uri: exp["target_uri"].as_str().unwrap().to_string(),
            invocation_id: exp["invocation_id"].as_str().unwrap().to_string(),
            operation: exp["operation"].as_str().unwrap().to_string(),
            cast_arguments: typed(&exp["cast_arguments_json"]),
            proof_max_age: exp["proof_max_age"].as_u64().unwrap(),
            nonce_mode: nonce_mode(exp),
            trusted_issuer: TrustedIssuer {
                key_id,
                public_key: b64_fixed::<32>(&exp["trusted_issuer"]["public_key"]),
            },
        };
        if major == 1 {
            bap::check_envelope(&credentials, &expected).map(|f| (f.authorization, f.grant.version))
        } else {
            v2::check_envelope(&credentials, &expected).map(|f| (f.authorization, f.grant.version))
        }
    };
    match (result, case["expected"]["verdict"].as_str().unwrap()) {
        (Ok((authorization, version)), "valid") => {
            authorization == NotEvaluated && u64::try_from(version) == Ok(major)
        }
        (Err(Invalid), "invalid") => true,
        _ => false,
    }
}

#[test]
fn selector_float_zero_corpus_all_cases_agree() {
    let cases = load_cases();
    let mut seen = BTreeSet::new();
    let mut disagreed = Vec::new();
    let (mut invalid, mut valid) = (0usize, 0usize);
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        assert!(seen.insert(id.to_string()), "duplicate case id {id}");
        let agrees = match case["surface"].as_str().unwrap() {
            "decode_grant" => run_decode(case),
            "grant_signing_input" => run_signing_input(case),
            "check_envelope" => run_envelope(case),
            s => panic!("unknown surface {s}"),
        };
        if !agrees {
            disagreed.push(format!(
                "{id} ({}): {}",
                case["construction"].as_str().unwrap(),
                case["expected"]["verdict"].as_str().unwrap()
            ));
        }
        match case["expected"]["verdict"].as_str().unwrap() {
            "valid" => valid += 1,
            _ => invalid += 1,
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of {TOTAL_CASES} cases disagree:\n{}",
        disagreed.len(),
        disagreed.join("\n")
    );
    assert_eq!(seen.len(), TOTAL_CASES);
    assert_eq!((invalid, valid), (98, 63));
}
