//! The producer-canonicality runner (profile `bap-producer-canonicality/1`, erratum 3): it
//! executes the vendored additive corpus (corpus-producer-canonicality, a byte-identical
//! snapshot of priv/conformance/producer-canonicality/) against the crate's PRODUCER surfaces
//! only — compact assembly for contract-majors 1, 2 and 3 and the three sibling profiles,
//! anchored-export encoding for all three majors — SHA-binds the vendored index.json at
//! startup, verifies every listed file against the index's per-file SHA-256 and case counts,
//! and requires every case to agree: a refused signature is the closed error; an accepted
//! signature's bytes are emitted unchanged (byte-equality against the certified compact).
//!
//! No verification verdict changes anywhere: every BAP verifier already rejects these
//! signatures.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol::types::*;
use bounded_authority_protocol::v2;
use bounded_authority_protocol::v3;
use bounded_authority_protocol::{content_assertion, role_attestation, v1, Invalid};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CERTIFIED_INDEX_SHA: &str =
    "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601";
const PROFILE: &str = "bap-producer-canonicality/1";
const REVISION: u64 = 1;
const TOTAL_CASES: usize = 75;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance")
        .join("corpus-producer-canonicality")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
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

fn b64_decode(s: &str) -> Vec<u8> {
    bap_b64(s)
}

fn bap_b64(s: &str) -> Vec<u8> {
    // base64url decode through the crate's own decoder (no padding, strict).
    use bounded_authority_protocol::base64url::base64url_decode;
    base64url_decode(s.as_bytes()).expect("corpus base64url")
}

fn sig64(s: &str) -> [u8; 64] {
    b64_decode(s).try_into().expect("64-byte signature")
}

fn signing_input(kind: SigningKind, protected: &str, payload: &str) -> SigningInput {
    // The segments are base64url TEXT (the composer frames them as given).
    SigningInput {
        kind,
        protected_segment: protected.as_bytes().to_vec(),
        payload_segment: payload.as_bytes().to_vec(),
    }
}

fn wire_kind(kind: &str) -> SigningKind {
    match kind {
        "grant" => SigningKind::Grant,
        "proof" => SigningKind::Proof,
        "local_loopback_http_proof" => SigningKind::LocalLoopbackHttpProof,
        "boundary_anchor" => SigningKind::ChainAnchor,
        "key_transition" => SigningKind::KeyTransition,
        "role_attestation" => SigningKind::RoleAttestation,
        "content_assertion" => SigningKind::ContentAssertion,
        _ => panic!("unknown kind {kind}"),
    }
}

fn run_assemble(case: &Value) -> bool {
    let input = &case["input"];
    let signature = sig64(input["signature"].as_str().unwrap());
    let major = case.get("major").and_then(Value::as_u64);
    let profile = case["profile"].as_str();
    let kind = match (major, profile) {
        (_, Some("bap-application-proof/local-loopback-http/1")) => SigningKind::LocalLoopbackHttpProof,
        (_, Some("bap-role-attestation/1")) => SigningKind::RoleAttestation,
        (_, Some("bap-content-assertion/1")) => SigningKind::ContentAssertion,
        (Some(1), _) | (None, _) => wire_kind(input["kind"].as_str().unwrap_or("grant")),
        _ => wire_kind(input["kind"].as_str().unwrap_or("grant")),
    };
    let si = signing_input(
        kind,
        input["protected_segment"].as_str().unwrap(),
        input["payload_segment"].as_str().unwrap(),
    );
    let result: Result<Vec<u8>, Invalid> = match major {
        Some(1) => v1::assemble_compact(&si, &signature, None),
        Some(2) => v2::assemble_compact(&si, &signature, None),
        Some(3) => v3::assemble_compact(&si, &signature, None),
        _ => match profile {
            Some("bap-application-proof/local-loopback-http/1") => {
                v1::assemble_local_loopback_http_compact(&si, &signature, None)
            }
            Some("bap-role-attestation/1") => {
                role_attestation::assemble_attestation_compact(&si, &signature, None)
            }
            Some("bap-content-assertion/1") => {
                content_assertion::assemble_content_assertion_compact(&si, &signature, None)
            }
            _ => panic!("unknown profile {profile:?}"),
        },
    };
    match result {
        Ok(compact) => {
            assert_eq!(
                compact,
                case["expected"]["compact"].as_str().unwrap().as_bytes(),
                "accepted bytes emitted unchanged"
            );
            true
        }
        Err(_) => false,
    }
}

fn digest32(s: &str) -> [u8; 32] {
    b64_decode(s).try_into().expect("32-byte digest")
}

fn expected_export(case: &Value) -> (AnchoredExportInput, ExpectedExport) {
    let input = &case["input"];
    let e = &input["expected"];

    let chain_json = &e["chain"];
    let chain = ExpectedChain {
        chain_id: chain_json["chain_id"].as_str().unwrap().to_string(),
        first_sequence: chain_json["first_sequence"].as_i64().unwrap(),
        last_sequence: chain_json["last_sequence"].as_i64().unwrap(),
        row_count: chain_json["row_count"].as_i64().unwrap(),
        previous_hash: digest32(chain_json["previous_hash"].as_str().unwrap()),
        head_hash: digest32(chain_json["last_hash"].as_str().unwrap()),
        bounds: None,
    };
    let anchor = |a: &Value| ExpectedAnchor {
        anchor_id: a["anchor_id"].as_str().unwrap().to_string(),
        chain_id: a["chain_id"].as_str().unwrap().to_string(),
        key_id: a["key_id"].as_str().unwrap().to_string(),
        sequence: a["sequence"].as_i64().unwrap(),
        anchored_at: a["anchored_at"].as_i64().unwrap(),
        chain_hash: digest32(a["chain_hash"].as_str().unwrap()),
        key_fingerprint: digest32(a["key_fingerprint"].as_str().unwrap()),
        bounds: None,
    };
    let transitions = e["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| ExpectedKeyTransition {
            transition_id: t["transition_id"].as_str().unwrap().to_string(),
            chain_id: t["chain_id"].as_str().unwrap().to_string(),
            current_key_id: t["current_key_id"].as_str().unwrap().to_string(),
            next_key_id: t["next_key_id"].as_str().unwrap().to_string(),
            effective_at: t["effective_at"].as_i64().unwrap(),
            current_key_fingerprint: digest32(t["current_key_fingerprint"].as_str().unwrap()),
            next_key_fingerprint: digest32(t["next_key_fingerprint"].as_str().unwrap()),
            bounds: None,
        })
        .collect::<Vec<_>>();
    let digest = e
        .get("digest")
        .and_then(Value::as_str)
        .map(|s| digest32(s))
        .unwrap_or([0u8; 32]);
    let version = e
        .get("object_version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("v{}", case["major"].as_u64().unwrap()));

    let input_struct = AnchoredExportInput {
        start_anchor: input["start_anchor"].as_str().unwrap().as_bytes().to_vec(),
        end_anchor: input["end_anchor"].as_str().unwrap().as_bytes().to_vec(),
        transitions: input["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().as_bytes().to_vec())
            .collect(),
        rows: input["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| b64_decode(r.as_str().unwrap()))
            .collect(),
    };
    let expected = ExpectedExport {
        chain,
        digest,
        start_anchor: anchor(&e["start_anchor"]),
        end_anchor: anchor(&e["end_anchor"]),
        transitions,
        object_version: version,
        bounds: None,
    };
    (input_struct, expected)
}

fn run_encode(case: &Value) -> bool {
    let (input, expected) = expected_export(case);
    match case["major"].as_u64().unwrap() {
        1 => v1::encode_anchored_export(&input, &expected).is_ok(),
        2 => v2::encode_anchored_export(&input, &expected).is_ok(),
        3 => v3::encode_anchored_export(&input, &expected).is_ok(),
        m => panic!("major {m}"),
    }
}

#[test]
fn producer_canonicality_corpus_all_cases_agree() {
    let cases = load_cases();
    let mut refused = 0usize;
    let mut accepted = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        assert!(seen.insert(id.to_string()), "duplicate case id {id}");
        let want_valid = case["expected"]["verdict"].as_str().unwrap() == "valid";
        let ok = if case["surface"].as_str().unwrap() == "assemble_compact" {
            run_assemble(case)
        } else {
            run_encode(case)
        };
        assert_eq!(
            ok, want_valid,
            "{id} ({}): expected verdict {}, got ok={ok}",
            case["class"].as_str().unwrap(),
            case["expected"]["verdict"].as_str().unwrap()
        );
        if want_valid {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert_eq!(seen.len(), TOTAL_CASES);
    assert_eq!((refused, accepted), (60, 15));
}
