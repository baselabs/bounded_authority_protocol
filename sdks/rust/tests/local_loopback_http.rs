use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol::types::{
    Credentials, ExpectedRequest, LocalLoopbackHttpProofInput, NonceMode, ProofInput, SigningInput,
    SigningKind, TrustedIssuer,
};
use bounded_authority_protocol::{
    assemble_compact, assemble_local_loopback_http_compact, base64url_decode,
    check_local_loopback_http_envelope, decode_local_loopback_http_proof, decode_proof,
    local_loopback_http_proof_signing_input, local_loopback_http_uri_normalize,
    proof_signing_input, Bounds, JsonValue,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CERTIFIED_INDEX_SHA256: &str =
    "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4";

#[test]
fn local_loopback_http_uri_profile_accepts_only_exact_loopback_literals() {
    let bounds = Bounds::maximum();

    for (source, expected) in [
        ("HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"),
        (
            "http://127.0.0.1:4000/invoke",
            "http://127.0.0.1:4000/invoke",
        ),
        ("HTTP://[::1]:80/invoke", "http://[::1]/invoke"),
        ("http://127.0.0.1:443/invoke", "http://127.0.0.1:443/invoke"),
    ] {
        assert_eq!(
            local_loopback_http_uri_normalize(source, &bounds).unwrap(),
            expected
        );
    }

    for invalid in [
        "https://127.0.0.1/invoke",
        "http://localhost/invoke",
        "http://127.0.0.2/invoke",
        "http://127.1/invoke",
        "http://2130706433/invoke",
        "http://[::ffff:127.0.0.1]/invoke",
        "http://[::1%25lo0]/invoke",
        "http://user@127.0.0.1/invoke",
        "http://127.0.0.1/invoke?query=true",
        "http://127.0.0.1/invoke#fragment",
        "http://127.0.0.1/[]",
    ] {
        assert!(
            local_loopback_http_uri_normalize(invalid, &bounds).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn certified_local_loopback_corpus_drives_rust_verdicts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../priv/conformance/application-profiles/local-loopback-http/v1");
    let read_json = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
    };
    let index_bytes = fs::read(root.join("index.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&index_bytes)),
        CERTIFIED_INDEX_SHA256
    );
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(
        index["profile"],
        "bap-application-proof/local-loopback-http/1"
    );
    assert_eq!(index["revision"], 1);
    assert_eq!(index["proof_cases"], 8);
    assert_eq!(index["uri_cases"], 36);
    assert_eq!(
        index["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["profile.json", "proof-cases.json"]
    );
    for file in index["files"].as_array().unwrap() {
        let path = file["path"].as_str().unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(root.join(path)).unwrap()));
        assert_eq!(digest, file["sha256"].as_str().unwrap(), "{path}");
    }

    let profile = read_json("profile.json");
    assert_eq!(
        profile["uri_cases"].as_array().unwrap().len(),
        index["uri_cases"].as_u64().unwrap() as usize
    );
    let bounds = Bounds::maximum();
    for uri_case in profile["uri_cases"].as_array().unwrap() {
        let id = uri_case["id"].as_str().unwrap();
        let result =
            local_loopback_http_uri_normalize(uri_case["input"].as_str().unwrap(), &bounds);
        assert_eq!(result.is_ok(), uri_case["valid"].as_bool().unwrap(), "{id}");
        if let Ok(normalized) = result {
            assert_eq!(normalized, uri_case["normalized"].as_str().unwrap(), "{id}");
        }
    }

    let issuer_key =
        base64url_decode(profile["issuer"]["public_key"].as_str().unwrap().as_bytes()).unwrap();
    let mut issuer_public_key = [0u8; 32];
    issuer_public_key.copy_from_slice(&issuer_key);
    let holder_key =
        base64url_decode(profile["holder_public_key"].as_str().unwrap().as_bytes()).unwrap();
    let mut holder_public_key = [0u8; 32];
    holder_public_key.copy_from_slice(&holder_key);

    let valid_compact = profile["proofs"]["ipv4"]["compact"].as_str().unwrap();
    let segments: Vec<&str> = valid_compact.split('.').collect();
    let producer = LocalLoopbackHttpProofInput {
        proof_id: profile["proofs"]["ipv4"]["proof_id"]
            .as_str()
            .unwrap()
            .to_string(),
        method: profile["request"]["method"].as_str().unwrap().to_string(),
        target_uri: profile["proofs"]["ipv4"]["target_uri"]
            .as_str()
            .unwrap()
            .to_string(),
        invocation_id: profile["request"]["invocation_id"]
            .as_str()
            .unwrap()
            .to_string(),
        operation: profile["request"]["operation"]
            .as_str()
            .unwrap()
            .to_string(),
        cast_arguments: JsonValue::Object(vec![(
            "record_id".to_string(),
            JsonValue::String("record-1".to_string()),
        )]),
        grant_compact: profile["grant_compact"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        holder_public_key,
        issued_at: profile["request"]["evaluation_time"].as_i64().unwrap(),
        nonce: profile["proofs"]["ipv4"]["nonce"]
            .as_str()
            .unwrap()
            .to_string(),
    };
    let produced = local_loopback_http_proof_signing_input(&producer, &bounds).unwrap();
    assert_eq!(produced.protected_segment, segments[0].as_bytes());
    assert_eq!(produced.payload_segment, segments[1].as_bytes());
    let signature = base64url_decode(segments[2].as_bytes()).unwrap();
    let mut signature64 = [0u8; 64];
    signature64.copy_from_slice(&signature);
    let input = SigningInput {
        kind: SigningKind::LocalLoopbackHttpProof,
        protected_segment: produced.protected_segment,
        payload_segment: produced.payload_segment,
    };
    assert_eq!(
        assemble_local_loopback_http_compact(&input, &signature64, Some(&bounds)).unwrap(),
        valid_compact.as_bytes()
    );
    assert!(assemble_compact(&input, &signature64, Some(&bounds)).is_err());
    let wrong_kind = SigningInput {
        kind: SigningKind::Grant,
        protected_segment: input.protected_segment.clone(),
        payload_segment: input.payload_segment.clone(),
    };
    assert!(
        assemble_local_loopback_http_compact(&wrong_kind, &signature64, Some(&bounds)).is_err()
    );
    let standard_input = ProofInput {
        proof_id: producer.proof_id.clone(),
        method: producer.method.clone(),
        target_uri: producer.target_uri.clone(),
        invocation_id: producer.invocation_id.clone(),
        operation: producer.operation.clone(),
        cast_arguments: producer.cast_arguments.clone(),
        grant_compact: producer.grant_compact.clone(),
        holder_public_key,
        issued_at: producer.issued_at,
    };
    assert!(proof_signing_input(&standard_input, &bounds).is_err());
    let expected = ExpectedRequest {
        issuer: profile["issuer"]["issuer"].as_str().unwrap().to_string(),
        audience: profile["issuer"]["audience"].as_str().unwrap().to_string(),
        evaluation_time: profile["request"]["evaluation_time"].as_i64().unwrap(),
        skew: profile["request"]["clock_skew"].as_u64().unwrap(),
        bounds,
        method: profile["request"]["method"].as_str().unwrap().to_string(),
        target_uri: profile["proofs"]["ipv4"]["target_uri"]
            .as_str()
            .unwrap()
            .to_string(),
        invocation_id: profile["request"]["invocation_id"]
            .as_str()
            .unwrap()
            .to_string(),
        operation: profile["request"]["operation"]
            .as_str()
            .unwrap()
            .to_string(),
        cast_arguments: JsonValue::Object(vec![(
            "record_id".to_string(),
            JsonValue::String("record-1".to_string()),
        )]),
        proof_max_age: profile["request"]["proof_max_age"].as_u64().unwrap(),
        nonce_mode: NonceMode::Required(
            profile["proofs"]["ipv4"]["nonce"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        trusted_issuer: TrustedIssuer {
            key_id: profile["issuer"]["key_id"].as_str().unwrap().to_string(),
            public_key: issuer_public_key,
        },
    };
    let grant = profile["grant_compact"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();

    let ipv6 = &profile["proofs"]["ipv6"];
    let mut ipv6_producer = producer.clone();
    ipv6_producer.proof_id = ipv6["proof_id"].as_str().unwrap().to_string();
    ipv6_producer.target_uri = ipv6["target_uri"].as_str().unwrap().to_string();
    ipv6_producer.nonce = ipv6["nonce"].as_str().unwrap().to_string();
    let ipv6_produced = local_loopback_http_proof_signing_input(&ipv6_producer, &bounds).unwrap();
    let ipv6_compact = ipv6["compact"].as_str().unwrap();
    let ipv6_segments: Vec<&str> = ipv6_compact.split('.').collect();
    assert_eq!(ipv6_produced.protected_segment, ipv6_segments[0].as_bytes());
    assert_eq!(ipv6_produced.payload_segment, ipv6_segments[1].as_bytes());
    let ipv6_signature = base64url_decode(ipv6_segments[2].as_bytes()).unwrap();
    let mut ipv6_signature64 = [0u8; 64];
    ipv6_signature64.copy_from_slice(&ipv6_signature);
    let ipv6_input = SigningInput {
        kind: SigningKind::LocalLoopbackHttpProof,
        protected_segment: ipv6_produced.protected_segment,
        payload_segment: ipv6_produced.payload_segment,
    };
    let ipv6_assembled =
        assemble_local_loopback_http_compact(&ipv6_input, &ipv6_signature64, Some(&bounds))
            .unwrap();
    assert_eq!(ipv6_assembled, ipv6_compact.as_bytes());
    assert!(decode_local_loopback_http_proof(&ipv6_assembled, &bounds).is_ok());
    let mut ipv6_expected = expected.clone();
    ipv6_expected.target_uri = ipv6["target_uri"].as_str().unwrap().to_string();
    ipv6_expected.nonce_mode = NonceMode::Required(ipv6["nonce"].as_str().unwrap().to_string());
    assert!(check_local_loopback_http_envelope(
        &Credentials {
            grant: grant.clone(),
            proof: ipv6_assembled,
        },
        &ipv6_expected,
    )
    .is_ok());

    let proof_cases = read_json("proof-cases.json");
    assert_eq!(
        proof_cases.as_array().unwrap().len(),
        index["proof_cases"].as_u64().unwrap() as usize
    );
    for proof_case in proof_cases.as_array().unwrap() {
        let id = proof_case["id"].as_str().unwrap();
        let compact = proof_case["compact"].as_str().unwrap().as_bytes().to_vec();
        let mut case_expected = expected.clone();
        if let Some(overrides) = proof_case.get("expected_overrides") {
            let overrides = overrides.as_object().unwrap();
            assert!(overrides.len() <= 1, "{id}: ambiguous expected override");
            if let Some(encoded) = overrides.get("trusted_issuer_public_key") {
                let public_key = base64url_decode(encoded.as_str().unwrap().as_bytes()).unwrap();
                assert_eq!(
                    public_key.len(),
                    32,
                    "{id}: invalid trusted issuer override"
                );
                case_expected
                    .trusted_issuer
                    .public_key
                    .copy_from_slice(&public_key);
            } else if let Some(invocation_id) = overrides.get("invocation_id") {
                case_expected.invocation_id = invocation_id.as_str().unwrap().to_string();
            } else {
                panic!("{id}: unsupported expected override");
            }
        }
        assert_eq!(
            decode_local_loopback_http_proof(&compact, &bounds).is_ok(),
            proof_case["decode_local"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            decode_proof(&compact, &bounds).is_ok(),
            proof_case["decode_standard"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            check_local_loopback_http_envelope(
                &Credentials {
                    grant: grant.clone(),
                    proof: compact
                },
                &case_expected,
            )
            .is_ok(),
            proof_case["envelope_local"].as_bool().unwrap(),
            "{id}"
        );
    }

    let mut wrong_nonce = expected.clone();
    wrong_nonce.nonce_mode = NonceMode::Required("wrong-nonce".to_string());
    assert!(check_local_loopback_http_envelope(
        &Credentials {
            grant,
            proof: valid_compact.as_bytes().to_vec(),
        },
        &wrong_nonce,
    )
    .is_err());

    let mut wrong_trust = expected.clone();
    wrong_trust.trusted_issuer.public_key[0] ^= 1;
    assert!(check_local_loopback_http_envelope(
        &Credentials {
            grant: profile["grant_compact"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            proof: valid_compact.as_bytes().to_vec(),
        },
        &wrong_trust,
    )
    .is_err());

    let mut wrong_binding = expected;
    wrong_binding.invocation_id = "550e8400-e29b-41d4-a716-446655440001".to_string();
    assert!(check_local_loopback_http_envelope(
        &Credentials {
            grant: profile["grant_compact"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            proof: valid_compact.as_bytes().to_vec(),
        },
        &wrong_binding,
    )
    .is_err());
}
