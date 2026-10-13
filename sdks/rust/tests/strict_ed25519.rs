//! End-to-end strict-Ed25519 tests (public crate surface only).
//!
//! A small-order public key (the identity point, `01 00..00`) lets anyone forge an Ed25519
//! signature without a private key: R = identity, S = 0 satisfies the cofactorless equation for
//! every message. These tests forge a real grant from the vendored strict corpus's honest grant
//! (same protected header and payload, forged signature, identity issuer key), so a rejection can
//! only come from the verifier. Each forged test carries a positive control (the honest grant
//! verifies in the same test), so a failure to build the artifact cannot masquerade as a rejection.

use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol::types::{ExpectedGrant, TrustedIssuer};
use bounded_authority_protocol::{base64url_decode, base64url_encode, v2, Bounds, Invalid};
use serde_json::Value;

const IDENTITY_KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

fn corpus_case(family_file: &str, id: &str) -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "conformance",
        "corpus-strict",
        "cases",
        family_file,
    ]
    .iter()
    .collect();
    let file: Value = serde_json::from_slice(&fs::read(path).expect("corpus file")).unwrap();
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("corpus case {id}"))
        .clone()
}

fn to_32(v: &Value) -> [u8; 32] {
    let raw = base64url_decode(v.as_str().unwrap().as_bytes()).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

struct HonestGrant {
    compact: Vec<u8>,
    issuer: TrustedIssuer,
    expected: ExpectedGrant,
}

fn honest_grant(id: &str) -> HonestGrant {
    let case = corpus_case("grant-verify/grant-verify-01.json", id);
    let input = &case["input"];
    HonestGrant {
        compact: input["compact"].as_str().unwrap().as_bytes().to_vec(),
        issuer: TrustedIssuer {
            key_id: input["key_id"].as_str().unwrap().to_string(),
            public_key: to_32(&input["public_key"]),
        },
        expected: ExpectedGrant {
            issuer: input["issuer"].as_str().unwrap().to_string(),
            audience: input["audience"].as_str().unwrap().to_string(),
            evaluation_time: input["evaluation_time"].as_i64().unwrap(),
            skew: input["clock_skew"].as_u64().unwrap(),
            bounds: Bounds::maximum(),
        },
    }
}

/// The honest grant's protected header and payload with the forged signature (R = identity,
/// S = 0) swapped in.
fn forged_compact(honest: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(honest).unwrap();
    let mut parts = text.split('.');
    let (protected, payload) = (parts.next().unwrap(), parts.next().unwrap());
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&IDENTITY_KEY);
    let mut out = format!("{protected}.{payload}.").into_bytes();
    out.extend_from_slice(&base64url_encode(&signature));
    out
}

#[test]
fn verify_grant_rejects_identity_key_forgery_with_positive_control() {
    let honest = honest_grant("grant-verify-v1-issuer-honest");
    assert!(
        bounded_authority_protocol::verify_grant(&honest.compact, &honest.issuer, &honest.expected)
            .is_ok(),
        "positive control: the honest grant must verify"
    );
    let forged = forged_compact(&honest.compact);
    let issuer = TrustedIssuer {
        key_id: honest.issuer.key_id.clone(),
        public_key: IDENTITY_KEY,
    };
    assert_eq!(
        bounded_authority_protocol::verify_grant(&forged, &issuer, &honest.expected).map(|_| ()),
        Err(Invalid),
        "a grant forged under the identity issuer key must be rejected"
    );
}

#[test]
fn verify_grant_rejects_identity_key_forgery_second_major_with_positive_control() {
    let honest = honest_grant("grant-verify-v2-issuer-honest");
    assert!(
        v2::verify_grant(&honest.compact, &honest.issuer, &honest.expected).is_ok(),
        "positive control: the honest v2 grant must verify"
    );
    let forged = forged_compact(&honest.compact);
    let issuer = TrustedIssuer {
        key_id: honest.issuer.key_id.clone(),
        public_key: IDENTITY_KEY,
    };
    assert_eq!(
        v2::verify_grant(&forged, &issuer, &honest.expected).map(|_| ()),
        Err(Invalid),
        "a v2 grant forged under the identity issuer key must be rejected"
    );
}

// ---- the fallible key family, and the producers ----------------------------------------------

use bounded_authority_protocol::types::{AttestationInput, ProofInput, Role};
use bounded_authority_protocol::{
    attestation_signing_input, jwk_decode_public, jwk_encode_public, proof_signing_input,
    public_key_thumbprint_raw, thumbprint, thumbprint_preimage, thumbprint_raw, JsonValue,
};

/// Every 32-byte key the strict corpus labels acceptable or not, from the key-acceptance family.
fn corpus_keys() -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "conformance",
        "corpus-strict",
        "cases",
        "key-acceptance",
        "acceptable-public-key.json",
    ]
    .iter()
    .collect();
    let file: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let (mut good, mut weak) = (Vec::new(), Vec::new());
    for case in file["cases"].as_array().unwrap() {
        let raw =
            base64url_decode(case["input"]["public_key"].as_str().unwrap().as_bytes()).unwrap();
        let Ok(key) = <[u8; 32]>::try_from(raw.as_slice()) else {
            continue;
        };
        if case["expected"]["verdict"] == "valid" {
            good.push(key);
        } else {
            weak.push(key);
        }
    }
    (good, weak)
}

fn jwk_text(key: &[u8; 32]) -> Vec<u8> {
    let mut out = br#"{"crv":"Ed25519","kty":"OKP","x":""#.to_vec();
    out.extend_from_slice(&base64url_encode(key));
    out.extend_from_slice(b"\"}");
    out
}

#[test]
fn every_key_function_refuses_weak_keys_and_accepts_the_acceptable_ones() {
    let (good, weak) = corpus_keys();
    assert!(
        good.len() >= 20,
        "the corpus labels honest and torsion-variant keys acceptable"
    );
    assert!(
        weak.len() >= 40,
        "the corpus labels the weak encodings (small-order, aliases, off-curve)"
    );
    for key in &good {
        // Positive controls: every function works on every acceptable key.
        assert!(jwk_encode_public(key).is_ok());
        assert_eq!(jwk_decode_public(&jwk_text(key)), Ok(*key));
        assert!(thumbprint_preimage(key).is_ok());
        assert!(thumbprint(key).is_ok());
        assert!(thumbprint_raw(key).is_ok());
        assert!(public_key_thumbprint_raw(key).is_ok());
    }
    for key in &weak {
        assert_eq!(jwk_encode_public(key), Err(Invalid), "{key:02x?}");
        assert_eq!(
            jwk_decode_public(&jwk_text(key)),
            Err(Invalid),
            "{key:02x?}"
        );
        assert_eq!(thumbprint_preimage(key), Err(Invalid), "{key:02x?}");
        assert_eq!(thumbprint(key), Err(Invalid), "{key:02x?}");
        assert_eq!(thumbprint_raw(key), Err(Invalid), "{key:02x?}");
        assert_eq!(public_key_thumbprint_raw(key), Err(Invalid), "{key:02x?}");
    }
}

#[test]
fn producers_refuse_a_weak_key_and_accept_a_real_one() {
    let (good, weak) = corpus_keys();
    let honest = good[0];
    let grant = honest_grant("grant-verify-v1-issuer-honest");
    let proof = |holder: [u8; 32]| ProofInput {
        proof_id: "urn:example:proof:1".to_string(),
        method: "POST".to_string(),
        target_uri: "https://resource.example.test/invoke".to_string(),
        invocation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        operation: "read".to_string(),
        cast_arguments: JsonValue::Null,
        grant_compact: grant.compact.clone(),
        holder_public_key: holder,
        issued_at: 1400,
    };
    let attestation = |subject: [u8; 32]| AttestationInput {
        attestor_key_id: "attestor-ra-1".to_string(),
        jti: "urn:example:attestation:ra-1".to_string(),
        key_id: "subject-key-1".to_string(),
        public_key: subject,
        role: Role::Issuer,
        nbf: 1_735_689_600,
        exp: 1_735_693_200,
    };
    let bounds = Bounds::maximum();
    assert!(
        proof_signing_input(&proof(honest), &bounds).is_ok(),
        "control: v1 proof producer"
    );
    assert!(
        v2::proof_signing_input(&proof(honest), &bounds).is_ok(),
        "control: v2 proof producer"
    );
    assert!(
        attestation_signing_input(&attestation(honest), &bounds).is_ok(),
        "control: attestation"
    );
    for key in &weak {
        assert!(
            proof_signing_input(&proof(*key), &bounds).is_err(),
            "{key:02x?}"
        );
        assert!(
            v2::proof_signing_input(&proof(*key), &bounds).is_err(),
            "{key:02x?}"
        );
        assert!(
            attestation_signing_input(&attestation(*key), &bounds).is_err(),
            "{key:02x?}"
        );
    }
}

#[test]
fn the_unchecked_thumbprint_is_private_to_the_jwk_module() {
    // Finding 10a: the raw hash-only path is for censuses and generators only. It is a private
    // function of jwk.rs, so no verify or key-import path can reach it; this pins both facts.
    let src: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src"].iter().collect();
    for entry in fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        let mentions = text.contains("thumbprint_digest_unchecked");
        if path.file_name().unwrap() == "jwk.rs" {
            assert!(mentions, "jwk.rs defines the raw path");
            assert!(
                !text.contains("pub fn thumbprint_digest_unchecked")
                    && !text.contains("pub(crate) fn thumbprint_digest_unchecked"),
                "the raw path must stay private to jwk.rs"
            );
        } else {
            assert!(
                !mentions,
                "{} references the raw thumbprint path",
                path.display()
            );
        }
    }
}
