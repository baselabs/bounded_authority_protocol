use std::fs;
use std::path::PathBuf;

use bounded_authority_protocol::facts::{AttestationFacts, NotEvaluated, SignatureAndWindow};
use bounded_authority_protocol::types::{
    AttestationDecoded, AttestationInput, ExpectedAttestation, HistoricalPublicKey, Role,
    SigningInput, SigningKind, ValidityUpperBound,
};
use bounded_authority_protocol::{
    assemble_attestation_compact, assemble_compact, attestation_signing_input, base64url_decode,
    base64url_encode, decode_attestation, decode_grant, public_key_thumbprint_raw, thumbprint_raw,
    verify_attestation, Bounds,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CERTIFIED_INDEX_SHA256: &str =
    "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a";

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../priv/conformance/attestation-profiles/role-attestation/v1")
}

fn read_json(name: &str) -> Value {
    let root = corpus_root();
    serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap()
}

fn to_arr_32(v: Vec<u8>) -> [u8; 32] {
    assert_eq!(v.len(), 32, "expected 32 bytes");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn base_expected() -> (ExpectedAttestation, [u8; 32]) {
    let profile = read_json("profile.json");
    let attestor_public_key = to_arr_32(
        base64url_decode(
            profile["attestor"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
    );
    let subject_public_key = to_arr_32(
        base64url_decode(
            profile["subject"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
    );
    let expected = ExpectedAttestation {
        attestor: HistoricalPublicKey {
            key_id: profile["attestor"]["key_id"].as_str().unwrap().to_string(),
            public_key: attestor_public_key,
            valid_from: profile["attestor"]["valid_from"].as_i64().unwrap(),
            valid_before: ValidityUpperBound::Bounded(
                profile["attestor"]["valid_before"].as_i64().unwrap(),
            ),
        },
        subject_key_id: profile["subject"]["key_id"].as_str().unwrap().to_string(),
        subject_public_key,
        now: profile["now"].as_i64().unwrap(),
        bounds: Bounds::maximum(),
    };
    (expected, subject_public_key)
}

#[test]
fn tightened_size_bounds_cover_every_attestation_surface() {
    use bounded_authority_protocol::json::JsonValue;

    let cases = read_json("attestation-cases.json");
    let compact = cases
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "issuer-valid")
        .unwrap()["compact"]
        .as_str()
        .unwrap()
        .as_bytes();
    let segments: Vec<&[u8]> = compact.split(|byte| *byte == b'.').collect();
    let claims: Value = serde_json::from_slice(&base64url_decode(segments[1]).unwrap()).unwrap();
    let (mut expected, public_key) = base_expected();
    let producer = AttestationInput {
        attestor_key_id: expected.attestor.key_id.clone(),
        jti: claims["jti"].as_str().unwrap().to_string(),
        key_id: expected.subject_key_id.clone(),
        public_key,
        role: Role::Issuer,
        nbf: claims["nbf"].as_i64().unwrap(),
        exp: claims["exp"].as_i64().unwrap(),
    };
    let signing_input = SigningInput {
        kind: SigningKind::RoleAttestation,
        protected_segment: segments[0].to_vec(),
        payload_segment: segments[1].to_vec(),
    };
    let signature: [u8; 64] = base64url_decode(segments[2]).unwrap().try_into().unwrap();
    let produced = attestation_signing_input(&producer, &Bounds::maximum()).unwrap();
    assert_eq!(produced.protected_segment, segments[0]);
    assert_eq!(produced.payload_segment, segments[1]);
    let mut failures = Vec::new();
    let decoded_segments = [
        base64url_decode(segments[0]).unwrap(),
        base64url_decode(segments[1]).unwrap(),
    ];
    let largest_decoded_segment = decoded_segments.iter().map(Vec::len).max().unwrap();
    let largest_number_lexeme = ["exp", "nbf", "v"]
        .iter()
        .map(|name| claims[name].as_i64().unwrap().to_string().len())
        .max()
        .unwrap();
    for (ceiling, size) in [
        ("anchor_bytes", compact.len()),
        ("compact_bytes", compact.len()),
        (
            "encoded_segment_bytes",
            segments.iter().map(|segment| segment.len()).max().unwrap(),
        ),
        ("decoded_segment_bytes", largest_decoded_segment),
        ("json_bytes", largest_decoded_segment),
        ("number_lexeme_bytes", largest_number_lexeme),
    ] {
        for (limit, accepted) in [(size, true), (size - 1, false), (1, false)] {
            let bounds = Bounds::new(Some(&JsonValue::Object(vec![(
                ceiling.to_string(),
                JsonValue::Int(limit as i64),
            )])))
            .unwrap();
            expected.bounds = bounds;
            for (surface, actual) in [
                (
                    "produce",
                    attestation_signing_input(&producer, &bounds).is_ok(),
                ),
                (
                    "assemble",
                    assemble_attestation_compact(&signing_input, &signature, Some(&bounds)).is_ok(),
                ),
                ("decode", decode_attestation(compact, &bounds).is_ok()),
                ("verify", verify_attestation(compact, &expected).is_ok()),
            ] {
                if actual != accepted {
                    failures.push(format!(
                        "{surface} {ceiling}={limit}: accepted={actual}, want={accepted}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn string_or_uri_rules_are_symmetric_across_every_attestation_surface() {
    let profile = read_json("profile.json");
    let bounds = Bounds::maximum();
    let subject_public_key = to_arr_32(
        base64url_decode(
            profile["subject"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
    );
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let attestor_public_key = signing_key.verifying_key().to_bytes();
    let attestor_key_id = profile["attestor"]["key_id"].as_str().unwrap();
    let subject_key_id = profile["subject"]["key_id"].as_str().unwrap();
    let subject_x = profile["subject"]["public_key"].as_str().unwrap();
    let expected = ExpectedAttestation {
        attestor: HistoricalPublicKey {
            key_id: attestor_key_id.to_string(),
            public_key: attestor_public_key,
            valid_from: profile["attestor"]["valid_from"].as_i64().unwrap(),
            valid_before: ValidityUpperBound::Bounded(
                profile["attestor"]["valid_before"].as_i64().unwrap(),
            ),
        },
        subject_key_id: subject_key_id.to_string(),
        subject_public_key,
        now: profile["now"].as_i64().unwrap(),
        bounds,
    };

    let mut failures = Vec::new();
    for (label, jti, accepted) in [
        ("userinfo", "https://user:pass@example.com", true),
        ("empty authority", "file:///tmp", true),
        ("empty host with port", "https://:80", true),
        ("empty host after userinfo", "https://user@", true),
        (
            "opaque later slash pair with colon",
            "urn:example://foo:abc",
            true,
        ),
        ("IPv6 with numeric port", "https://[::1]:443", true),
        ("malformed IPv6", "https://[bad]", false),
        ("IPv6 with nonnumeric port", "https://[::1]:abc", false),
        ("unterminated IPv6", "https://[::1", false),
        ("stray closing bracket", "https://example.com]", false),
        (
            "bracket in userinfo",
            "https://user[bad]@example.com",
            false,
        ),
        (
            "bracket in authority path",
            "https://user:pass@example.com/[bad]",
            false,
        ),
        ("bracket in query", "https://example.com/path?[bad]", false),
        (
            "bracket in fragment",
            "https://example.com/path#[bad]",
            false,
        ),
        (
            "percent-encoded brackets",
            "https://example.com/%5Bbad%5D",
            true,
        ),
        ("plain brackets", "plain[bad]", true),
        ("multiple fragment delimiters", "https://host/#a#b", false),
        ("opaque multiple fragments", "urn:a#b#c", false),
        ("multiple query delimiters", "https://host/?a?b", true),
        ("opaque malformed percent escape", "urn:example:%", false),
        ("opaque percent escape", "urn:example:%20", true),
    ] {
        let input = AttestationInput {
            attestor_key_id: attestor_key_id.to_string(),
            jti: jti.to_string(),
            key_id: subject_key_id.to_string(),
            public_key: subject_public_key,
            role: Role::Issuer,
            nbf: 1735689600,
            exp: 1735693200,
        };
        let header = format!(
            "{{\"alg\":\"EdDSA\",\"kid\":\"{attestor_key_id}\",\"typ\":\"ba+role-attestation\"}}"
        );
        let payload = format!(
            "{{\"exp\":1735693200,\"jti\":\"{jti}\",\"key_id\":\"{subject_key_id}\",\
             \"nbf\":1735689600,\"public_key\":\"{subject_x}\",\"role\":\"issuer\",\"v\":1}}"
        );
        let protected_segment = base64url_encode(header.as_bytes());
        let payload_segment = base64url_encode(payload.as_bytes());
        let mut message = protected_segment.clone();
        message.push(b'.');
        message.extend_from_slice(&payload_segment);
        let signature = signing_key.sign(&message).to_bytes();
        let signing_input = SigningInput {
            kind: SigningKind::RoleAttestation,
            protected_segment,
            payload_segment,
        };
        let mut compact = message;
        compact.push(b'.');
        compact.extend_from_slice(&base64url_encode(&signature));

        for (surface, actual) in [
            (
                "produce",
                attestation_signing_input(&input, &bounds).is_ok(),
            ),
            (
                "assemble",
                assemble_attestation_compact(&signing_input, &signature, Some(&bounds)).is_ok(),
            ),
            ("decode", decode_attestation(&compact, &bounds).is_ok()),
            ("verify", verify_attestation(&compact, &expected).is_ok()),
        ] {
            if actual != accepted {
                failures.push(format!(
                    "{label} {surface}: accepted={actual}, want={accepted}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn certified_role_attestation_corpus_drives_rust_verdicts() {
    let root = corpus_root();
    let read_file = |name: &str| fs::read(root.join(name)).unwrap();

    // REQ-RA1-CONFORMANCE-certified-pin: pin the certified index digest
    // independently, then require profile identity, revision, case count, and
    // the exact two-file set BEFORE trusting the per-file digests.
    let index_bytes = read_file("index.json");
    assert_eq!(
        format!("{:x}", Sha256::digest(&index_bytes)),
        CERTIFIED_INDEX_SHA256
    );
    let index: Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["profile"], "bap-role-attestation/1");
    assert_eq!(index["revision"], 1);
    assert_eq!(index["attestation_cases"], 40);
    assert_eq!(
        index["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["profile.json", "attestation-cases.json"]
    );
    for file in index["files"].as_array().unwrap() {
        let path = file["path"].as_str().unwrap();
        let digest = format!("{:x}", Sha256::digest(read_file(path)));
        assert_eq!(digest, file["sha256"].as_str().unwrap(), "{path}");
    }

    // The profile carries its own identity + revision echo of the index.
    let profile = read_json("profile.json");
    assert_eq!(profile["profile"], "bap-role-attestation/1");
    assert_eq!(profile["revision"], 1);

    let (base, _subject_key) = base_expected();
    let bounds = base.bounds;

    // All 40 cases: decode verdict, verify verdict (applying the certified
    // expected_overrides), and cross-profile rejection in BOTH directions.
    let cases = read_json("attestation-cases.json");
    let all_cases = cases.as_array().unwrap();
    assert_eq!(
        all_cases.len(),
        index["attestation_cases"].as_u64().unwrap() as usize
    );
    for case in all_cases {
        let id = case["id"].as_str().unwrap();
        let compact = case["compact"].as_str().unwrap().as_bytes().to_vec();

        let mut case_expected = base.clone();
        if let Some(overrides) = case.get("expected_overrides") {
            let overrides = overrides.as_object().unwrap();
            // The certified override set: the four singleton forms plus the
            // one combined form the corpus carries (both subject-binding
            // members together — the self-attestation-same-material case).
            // An unknown key, or any OTHER combination, is rejected here
            // rather than silently applied.
            let known = [
                "now",
                "subject_public_key",
                "subject_key_id",
                "attestor_public_key",
            ];
            let combined_subject_form = overrides.len() == 2
                && overrides.contains_key("subject_key_id")
                && overrides.contains_key("subject_public_key");
            assert!(
                overrides.len() == 1 || combined_subject_form,
                "{id}: ambiguous expected override"
            );
            for key in overrides.keys() {
                assert!(
                    known.contains(&key.as_str()),
                    "{id}: unsupported expected override {key}"
                );
            }
            if let Some(now) = overrides.get("now") {
                case_expected.now = now.as_i64().unwrap();
            }
            if let Some(encoded) = overrides.get("subject_public_key") {
                case_expected.subject_public_key =
                    to_arr_32(base64url_decode(encoded.as_str().unwrap().as_bytes()).unwrap());
            }
            if let Some(key_id) = overrides.get("subject_key_id") {
                case_expected.subject_key_id = key_id.as_str().unwrap().to_string();
            }
            if let Some(encoded) = overrides.get("attestor_public_key") {
                case_expected.attestor.public_key =
                    to_arr_32(base64url_decode(encoded.as_str().unwrap().as_bytes()).unwrap());
            }
        }

        assert_eq!(
            decode_attestation(&compact, &bounds).is_ok(),
            case["decode"].as_bool().unwrap(),
            "{id}: decode"
        );
        assert_eq!(
            verify_attestation(&compact, &case_expected).is_ok(),
            case["verify"].as_bool().unwrap(),
            "{id}: verify"
        );

        // REQ-RA1-CORE-cross-profile-reject: the v1 grant decoder accepts a
        // case ONLY when the corpus marks it a genuine v1 grant
        // (`v1_grant: true`); every role-attestation byte is rejected by the
        // contract-major decoder.
        let standard_expected = case
            .get("v1_grant")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assert_eq!(
            decode_grant(&compact, &bounds).is_ok(),
            standard_expected,
            "{id}: v1 grant cross-profile rejection"
        );
    }
}

#[test]
fn producer_and_assembly_round_trip_both_roles_from_profile_material() {
    let profile = read_json("profile.json");
    let bounds = Bounds::maximum();
    let subject_public_key = to_arr_32(
        base64url_decode(
            profile["subject"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
    );
    // The library accepts only external signature bytes: the TEST generates
    // the attestor signing key (a fixed deterministic seed — no library RNG),
    // and the trusted attestor context carries its public half.
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let attestor_public_key = signing_key.verifying_key().to_bytes();
    let attestor_key_id = profile["attestor"]["key_id"].as_str().unwrap().to_string();

    let expected = ExpectedAttestation {
        attestor: HistoricalPublicKey {
            key_id: attestor_key_id.clone(),
            public_key: attestor_public_key,
            valid_from: profile["attestor"]["valid_from"].as_i64().unwrap(),
            valid_before: ValidityUpperBound::Bounded(
                profile["attestor"]["valid_before"].as_i64().unwrap(),
            ),
        },
        subject_key_id: profile["subject"]["key_id"].as_str().unwrap().to_string(),
        subject_public_key,
        now: profile["now"].as_i64().unwrap(),
        bounds,
    };

    for role in [Role::Issuer, Role::Holder] {
        let input = AttestationInput {
            attestor_key_id: attestor_key_id.clone(),
            jti: "urn:example:attestation:ra-rust-producer".to_string(),
            key_id: profile["subject"]["key_id"].as_str().unwrap().to_string(),
            public_key: subject_public_key,
            role,
            nbf: 1735689600,
            exp: 1735693200,
        };
        let produced = attestation_signing_input(&input, &bounds).unwrap();

        // Exact closed sets, byte-exact: the JCS header is exactly
        // {alg, kid, typ} and the JCS payload exactly the seven members.
        let expected_header = format!(
            "{{\"alg\":\"EdDSA\",\"kid\":\"{attestor_key_id}\",\"typ\":\"ba+role-attestation\"}}"
        );
        let subject_x = profile["subject"]["public_key"].as_str().unwrap();
        let expected_payload = format!(
            "{{\"exp\":1735693200,\"jti\":\"urn:example:attestation:ra-rust-producer\",\
             \"key_id\":\"{}\",\"nbf\":1735689600,\"public_key\":\"{subject_x}\",\"role\":\"{}\",\
             \"v\":1}}",
            profile["subject"]["key_id"].as_str().unwrap(),
            role.as_str(),
        );
        assert_eq!(
            base64url_decode(&produced.protected_segment).unwrap(),
            expected_header.as_bytes(),
            "{role:?}: header closed set"
        );
        assert_eq!(
            base64url_decode(&produced.payload_segment).unwrap(),
            expected_payload.as_bytes(),
            "{role:?}: payload closed set"
        );
        let mut message = produced.protected_segment.clone();
        message.push(b'.');
        message.extend_from_slice(&produced.payload_segment);
        assert_eq!(produced.message, message);

        // External signature bytes only — the library never signs.
        let signature = signing_key.sign(&produced.message);
        let mut signature64 = [0u8; 64];
        signature64.copy_from_slice(&signature.to_bytes());
        let signing_input = SigningInput {
            kind: SigningKind::RoleAttestation,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: produced.payload_segment.clone(),
        };
        let compact = assemble_attestation_compact(&signing_input, &signature64, Some(&bounds))
            .expect("valid attestation assembles");

        // REQ-RA1-CORE-cross-profile-reject: the contract-major assembler and
        // decoder reject these bytes; the wrong kind never assembles here.
        assert!(assemble_compact(&signing_input, &signature64, Some(&bounds)).is_err());
        let wrong_kind = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: signing_input.protected_segment.clone(),
            payload_segment: signing_input.payload_segment.clone(),
        };
        assert!(assemble_attestation_compact(&wrong_kind, &signature64, Some(&bounds)).is_err());
        assert!(decode_grant(&compact, &bounds).is_err());

        // Decode view: the decoded claims + the not-evaluated marker.
        let decoded = decode_attestation(&compact, &bounds).unwrap();
        assert_eq!(
            decoded,
            AttestationDecoded {
                attestor_key_id: attestor_key_id.clone(),
                jti: input.jti.clone(),
                key_id: input.key_id.clone(),
                public_key: subject_public_key,
                role,
                nbf: 1735689600,
                exp: 1735693200,
                verification: NotEvaluated,
            }
        );

        // Verified facts: redacted (thumbprints, never raw keys) with the
        // signature-and-window + not-evaluated markers.
        let facts = verify_attestation(&compact, &expected).unwrap();
        assert_eq!(
            facts,
            AttestationFacts {
                attestor_key_id: attestor_key_id.clone(),
                attestor_key_fingerprint: public_key_thumbprint_raw(&attestor_public_key),
                subject_key_id: input.key_id.clone(),
                subject_key_fingerprint: thumbprint_raw(&subject_public_key),
                role,
                jti: input.jti.clone(),
                nbf: 1735689600,
                exp: 1735693200,
                verification: SignatureAndWindow,
                trust: NotEvaluated,
            }
        );

        // The unbounded attestor window admits the same window (no upper
        // containment bound to violate).
        let mut unbounded = expected.clone();
        unbounded.attestor.valid_before = ValidityUpperBound::Unbounded;
        assert!(verify_attestation(&compact, &unbounded).is_ok());
    }
}

#[test]
fn producer_matrix_and_assembly_defects_fail_closed() {
    let profile = read_json("profile.json");
    let bounds = Bounds::maximum();
    let subject_public_key = to_arr_32(
        base64url_decode(
            profile["subject"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
    );
    let subject_x = profile["subject"]["public_key"]
        .as_str()
        .unwrap()
        .to_string();
    let attestor_key_id = profile["attestor"]["key_id"].as_str().unwrap().to_string();
    let subject_key_id = profile["subject"]["key_id"].as_str().unwrap().to_string();
    let valid = AttestationInput {
        attestor_key_id: attestor_key_id.clone(),
        jti: "urn:example:attestation:ra-1".to_string(),
        key_id: subject_key_id.clone(),
        public_key: subject_public_key,
        role: Role::Issuer,
        nbf: 1735689600,
        exp: 1735693200,
    };

    // --- Producer fail-closed matrix (empty ids, malformed kid bytes,
    // nbf >= exp in both directions). ---
    for (label, mutate) in [
        ("empty attestor key id", 0usize),
        ("bad attestor kid byte", 1),
        ("empty jti", 2),
        ("empty subject key id", 3),
        ("nbf equals exp", 4),
        ("nbf after exp", 5),
    ] {
        let mut bad = valid.clone();
        match mutate {
            0 => bad.attestor_key_id = String::new(),
            1 => bad.attestor_key_id = "attestor ra!".to_string(),
            2 => bad.jti = String::new(),
            3 => bad.key_id = String::new(),
            4 => bad.exp = bad.nbf,
            _ => bad.exp = bad.nbf - 1,
        }
        assert!(
            attestation_signing_input(&bad, &bounds).is_err(),
            "{label}: producer must fail closed"
        );
    }
    assert!(attestation_signing_input(&valid, &bounds).is_ok());

    // --- Assembly/decode defect matrix: every crafted payload segment (or
    // signature width) fails BOTH the assembly revalidation and the decode. ---
    let produced = attestation_signing_input(&valid, &bounds).unwrap();
    let signature = [0u8; 64];
    let base_payload = format!(
        "{{\"exp\":1735693200,\"jti\":\"urn:example:attestation:ra-1\",\
         \"key_id\":\"{subject_key_id}\",\"nbf\":1735689600,\"public_key\":\"{subject_x}\",\
         \"role\":\"issuer\",\"v\":1}}"
    );
    let short_key = String::from_utf8(base64url_encode(&[0u8; 31])).unwrap();
    let defects: &[(&str, String)] = &[
        (
            "role outside closed set",
            base_payload.replace("\"role\":\"issuer\"", "\"role\":\"admin\""),
        ),
        ("public_key wrong width", {
            let mut p = base_payload.clone();
            let start = p.rfind("\"public_key\":\"").unwrap() + "\"public_key\":\"".len();
            p.replace_range(start..start + subject_x.len(), &short_key);
            p
        }),
        ("float nbf date", {
            let mut p = base_payload.clone();
            p.replace_range(
                p.rfind("\"nbf\":").unwrap()..p.rfind(",\"public_key\"").unwrap(),
                "\"nbf\":1735689600.0",
            );
            p
        }),
        ("float exp date", {
            let mut p = base_payload.clone();
            p.replace_range(
                p.find("\"exp\":").unwrap()..p.find(",\"jti\"").unwrap(),
                "\"exp\":1735693200.0",
            );
            p
        }),
        ("empty window nbf equals exp", {
            let mut p = base_payload.clone();
            p.replace_range(
                p.rfind("\"nbf\":").unwrap()..p.rfind(",\"public_key\"").unwrap(),
                "\"nbf\":1735693200",
            );
            p
        }),
        (
            "non-canonical payload order",
            format!(
                "{{\"v\":1,\"exp\":1735693200,\"jti\":\"urn:example:attestation:ra-1\",\
                 \"key_id\":\"{subject_key_id}\",\"nbf\":1735689600,\
                 \"public_key\":\"{subject_x}\",\"role\":\"issuer\"}}"
            ),
        ),
        (
            "duplicate member",
            format!(
                "{{\"exp\":1735693200,\"exp\":1735693200,\
                 \"jti\":\"urn:example:attestation:ra-1\",\"key_id\":\"{subject_key_id}\",\
                 \"nbf\":1735689600,\"public_key\":\"{subject_x}\",\"role\":\"issuer\",\"v\":1}}"
            ),
        ),
        (
            "unknown payload member",
            format!(
                "{{\"exp\":1735693200,\"jti\":\"urn:example:attestation:ra-1\",\
                 \"key_id\":\"{subject_key_id}\",\"nbf\":1735689600,\
                 \"public_key\":\"{subject_x}\",\"role\":\"issuer\",\"scope\":\"everything\",\
                 \"v\":1}}"
            ),
        ),
    ];
    for (label, payload_json) in defects {
        let input = SigningInput {
            kind: SigningKind::RoleAttestation,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: base64url_encode(payload_json.as_bytes()),
        };
        assert!(
            assemble_attestation_compact(&input, &signature, Some(&bounds)).is_err(),
            "{label}: assembly must revalidate and fail closed"
        );
        let mut compact = input.protected_segment.clone();
        compact.push(b'.');
        compact.extend_from_slice(&input.payload_segment);
        compact.push(b'.');
        compact.extend_from_slice(&base64url_encode(&signature));
        assert!(
            decode_attestation(&compact, &bounds).is_err(),
            "{label}: decode must fail closed"
        );
    }

    // Wrong signature width: a structurally-valid compact whose signature
    // segment decodes to 63 bytes is rejected by the decode path.
    let valid_input = SigningInput {
        kind: SigningKind::RoleAttestation,
        protected_segment: produced.protected_segment.clone(),
        payload_segment: produced.payload_segment.clone(),
    };
    let good_compact =
        assemble_attestation_compact(&valid_input, &signature, Some(&bounds)).unwrap();
    let mut short_sig_compact = good_compact.clone();
    let sig_start = short_sig_compact.iter().rposition(|&b| b == b'.').unwrap() + 1;
    short_sig_compact.truncate(sig_start);
    short_sig_compact.extend_from_slice(&base64url_encode(&[0u8; 63]));
    assert!(decode_attestation(&short_sig_compact, &bounds).is_err());
}
