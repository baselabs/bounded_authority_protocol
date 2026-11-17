use bounded_authority_protocol::content_assertion::ContentAssertionFacts;
use bounded_authority_protocol::facts::*;

fn grant() -> GrantFacts {
    GrantFacts {
        version: 987654321,
        issuer: "caller-text-7f3a".into(),
        grant_id: "caller-text-7f3a".into(),
        issuer_key_fingerprint: [173; 32],
        holder_thumbprint: [173; 32],
        matched_audience: "caller-text-7f3a".into(),
        iat: 987654321,
        nbf: 987654321,
        exp: 987654321,
        authorization: NotEvaluated,
    }
}

#[test]
fn grant_facts_rendering_is_fixed() {
    let facts = GrantFacts {
        version: 987654321,
        issuer: "caller-text-7f3a".into(),
        grant_id: "caller-text-7f3a".into(),
        issuer_key_fingerprint: [173; 32],
        holder_thumbprint: [173; 32],
        matched_audience: "caller-text-7f3a".into(),
        iat: 987654321,
        nbf: 987654321,
        exp: 987654321,
        authorization: NotEvaluated,
    };
    let expected = "#GrantFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn envelope_facts_rendering_is_fixed() {
    let facts = EnvelopeFacts {
        grant: grant(),
        proof_id: "caller-text-7f3a".into(),
        invocation_id: "caller-text-7f3a".into(),
        operation: "caller-text-7f3a".into(),
        normalized_uri: "caller-text-7f3a".into(),
        grant_hash: [173; 32],
        request_hash: [173; 32],
        proof_iat: 987654321,
        authorization: NotEvaluated,
    };
    let expected = "#EnvelopeFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn chain_facts_rendering_is_fixed() {
    let facts = ChainFacts {
        chain_id: "caller-text-7f3a".into(),
        row_count: 987654321,
        first_sequence: 987654321,
        last_sequence: 987654321,
        previous_hash: [173; 32],
        head_hash: [173; 32],
        trust: NotEvaluated,
    };
    let expected = "#ChainFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn anchor_facts_rendering_is_fixed() {
    let facts = AnchorFacts {
        anchor_id: "caller-text-7f3a".into(),
        anchored_at: 987654321,
        chain_id: "caller-text-7f3a".into(),
        sequence: 987654321,
        chain_hash: [173; 32],
        key_fingerprint: [173; 32],
        key_id: "caller-text-7f3a".into(),
        trust: NotEvaluated,
    };
    let expected = "#AnchorFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn key_transition_facts_rendering_is_fixed() {
    let facts = KeyTransitionFacts {
        transition_id: "caller-text-7f3a".into(),
        chain_id: "caller-text-7f3a".into(),
        effective_at: 987654321,
        current_key_fingerprint: [173; 32],
        current_key_id: "caller-text-7f3a".into(),
        next_key_fingerprint: [173; 32],
        next_key_id: "caller-text-7f3a".into(),
        trust: NotEvaluated,
    };
    let expected = "#KeyTransitionFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn anchored_export_facts_rendering_is_fixed() {
    let facts = AnchoredExportFacts {
        chain_id: "caller-text-7f3a".into(),
        first_sequence: 987654321,
        last_sequence: 987654321,
        row_count: 987654321,
        transition_count: 987654321,
        previous_hash: [173; 32],
        head_hash: [173; 32],
        digest: [173; 32],
        object_version: "caller-text-7f3a".into(),
        trust: NotEvaluated,
        authorization: NotEvaluated,
    };
    let expected = "#AnchoredExportFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn attestation_facts_rendering_is_fixed() {
    let facts = AttestationFacts {
        attestor_key_id: "caller-text-7f3a".into(),
        attestor_key_fingerprint: [173; 32],
        subject_key_id: "caller-text-7f3a".into(),
        subject_key_fingerprint: [173; 32],
        role: bounded_authority_protocol::types::Role::Holder,
        jti: "caller-text-7f3a".into(),
        nbf: 987654321,
        exp: 987654321,
        verification: SignatureAndWindow,
        trust: NotEvaluated,
    };
    let expected = "#AttestationFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}

#[test]
fn content_assertion_facts_rendering_is_fixed() {
    let facts = ContentAssertionFacts {
        version: 987654321,
        attestor_key_id: "caller-text-7f3a".into(),
        attestor_key_fingerprint: [173; 32],
        jti: "caller-text-7f3a".into(),
        iss: "caller-text-7f3a".into(),
        aud: "caller-text-7f3a".into(),
        sub: "caller-text-7f3a".into(),
        profile: "caller-text-7f3a".into(),
        profile_digest: [173; 32],
        content_digest: [173; 32],
        generation: 987654321,
        previous: [173; 32],
        issued_at: 987654321,
        not_before: 987654321,
        expires_at: 987654321,
        digest: [173; 32],
        verification: SignatureAndWindow,
        trust: NotEvaluated,
    };
    let expected = "#ContentAssertionFacts<redacted>";
    for rendered in [
        format!("{facts:?}"),
        format!("{facts:#?}"),
        format!("{facts:>80?}"),
        format!("{facts:.3?}"),
    ] {
        assert_eq!(rendered, expected);
        for value in ["caller-text-7f3a", "caller-role-7f3a", "987654321", "173"] {
            assert!(!rendered.contains(value));
        }
    }
    assert_eq!(
        format!("{:?}", Ok::<_, ()>(facts)),
        format!("Ok({expected})")
    );
}
