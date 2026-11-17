use bounded_authority_protocol::{
    content_assertion::DecodedContentAssertion,
    facts::NotEvaluated,
    json::JsonValue,
    types::{AttestationDecoded, GrantDecoded, ProofDecoded, Role},
};
#[test]
fn decoded_rendering_matches_reference() {
    let gold: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/decoded-rendering.json")).unwrap();
    for version in 1..=3 {
        let grant = GrantDecoded {
            version,
            key_id: "kid".into(),
            issuer: "issuer".into(),
            grant_id: "grant".into(),
            audiences: vec!["aud".into()],
            issued_at: 1,
            not_before: 2,
            expires_at: 3,
            holder_thumbprint: [0; 32],
            operations: vec![JsonValue::Object(vec![
                ("name".into(), JsonValue::String("read".into())),
                (
                    "selectors".into(),
                    JsonValue::Array(vec![JsonValue::Object(vec![(
                        "kind".into(),
                        JsonValue::String("all".into()),
                    )])]),
                ),
            ])],
            verification: NotEvaluated,
        };
        let proof = ProofDecoded {
            version,
            key_id: String::new(),
            proof_id: "proof".into(),
            method: "POST".into(),
            target_uri: "https://example.test/".into(),
            issued_at: 1,
            nonce: Some("hidden-nonce".into()),
            invocation_id: "invocation".into(),
            operation: "read".into(),
            grant_hash: [0; 32],
            request_hash: [0; 32],
            holder_public_key: vec![0; 32],
            holder_thumbprint: [0; 32],
            verification: NotEvaluated,
        };
        let attestation = AttestationDecoded {
            attestor_key_id: "attestor".into(),
            jti: "jti".into(),
            key_id: "subject".into(),
            public_key: [0; 32],
            role: Role::Issuer,
            nbf: 1,
            exp: 2,
            verification: NotEvaluated,
        };
        let content = DecodedContentAssertion {
            version: 1,
            attestor_key_id: "hidden-attestor".into(),
            jti: "hidden-content".into(),
            iss: "hidden-issuer".into(),
            aud: "hidden-aud".into(),
            sub: "hidden-sub".into(),
            profile: "hidden-profile".into(),
            profile_digest: [0; 32],
            content_digest: [0; 32],
            generation: 1,
            previous: [0; 32],
            issued_at: 1,
            not_before: 1,
            expires_at: 2,
            verification: NotEvaluated,
        };
        for (key, value) in [
            (format!("grant{version}"), &grant as &dyn std::fmt::Debug),
            (format!("proof{version}"), &proof),
            ("attestation".into(), &attestation),
            ("content".into(), &content),
        ] {
            assert_eq!(format!("{value:?}"), gold[&key].as_str().unwrap());
            assert_eq!(format!("{value:#?}"), gold[&key].as_str().unwrap());
        }
    }
}

#[test]
fn decoded_wire_rendering_matches_reference() {
    use bounded_authority_protocol::{bounds::Bounds, v1, v2, v3};
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/decoded-wire-rendering.json")).unwrap();
    let b = Bounds::maximum();
    for row in rows.as_array().unwrap() {
        let compact = row["compact"].as_str().unwrap().as_bytes();
        let major = row["major"].as_i64().unwrap();
        let rendered = if row["kind"] == "grant" {
            let d = match major {
                1 => v1::decode_grant(compact, &b),
                2 => v2::decode_grant(compact, &b),
                3 => v3::decode_grant(compact, &b),
                _ => panic!("unknown fixture major"),
            }
            .unwrap();
            format!("{d:?}")
        } else {
            let d = match major {
                1 => v1::decode_proof(compact, &b),
                2 => v2::decode_proof(compact, &b),
                3 => v3::decode_proof(compact, &b),
                _ => panic!("unknown fixture major"),
            }
            .unwrap();
            format!("{d:?}")
        };
        assert_eq!(rendered, row["expected"].as_str().unwrap(), "{}", row["id"]);
    }
}

#[test]
fn hand_built_public_fields_escape_controls_and_keep_nonce_redacted() {
    let bad = "x\ny\u{7f}".to_string();
    for version in 1..=3 {
        let grant = GrantDecoded {
            operations: vec![JsonValue::Object(vec![
                ("name".into(), JsonValue::String(bad.clone())),
                (
                    "selectors".into(),
                    JsonValue::Array(vec![JsonValue::Object(vec![])]),
                ),
            ])],
            key_id: bad.clone(),
            version,
            issuer: bad.clone(),
            grant_id: bad.clone(),
            audiences: vec![bad.clone()],
            holder_thumbprint: [255; 32],
            issued_at: i64::MIN,
            not_before: 0,
            expires_at: i64::MAX,
            verification: NotEvaluated,
        };
        let proof = ProofDecoded {
            version,
            holder_public_key: vec![255],
            key_id: bad.clone(),
            proof_id: bad.clone(),
            method: bad.clone(),
            target_uri: bad.clone(),
            invocation_id: bad.clone(),
            operation: bad.clone(),
            grant_hash: [255; 32],
            request_hash: [255; 32],
            issued_at: i64::MIN,
            holder_thumbprint: [255; 32],
            nonce: Some("hidden".into()),
            verification: NotEvaluated,
        };
        let attestation = AttestationDecoded {
            attestor_key_id: bad.clone(),
            jti: bad.clone(),
            key_id: bad.clone(),
            public_key: [255; 32],
            role: Role::Issuer,
            nbf: i64::MIN,
            exp: i64::MAX,
            verification: NotEvaluated,
        };
        for value in [&grant as &dyn std::fmt::Debug, &proof, &attestation] {
            for output in [format!("{value:?}"), format!("{value:#?}")] {
                assert!(!output.contains(['\n', '\r', '\0']));
                assert!(!output.contains("hidden"));
                assert!(output.contains("\\n"));
            }
        }
        assert!(format!("{grant:?}").contains("selectors: [#unrenderable]"));
        assert!(format!("{proof:?}").contains("nonce: :redacted"));
    }
}
