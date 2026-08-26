//! Redacted-by-construction verification facts (the public value records the
//! façade returns on success).
//!
//! These six structs are the ONLY public outputs of the verification surfaces
//! (`verify_grant`, `check_envelope`, `check_chain`, `verify_historical_anchor`,
//! `verify_key_transition`, `verify_anchored_export`). They are
//! **value-bearing, fixed-redacted, and non-authorizing**: each carries an
//! explicit `NotEvaluated` marker so a successful result can never be read as a
//! decision, receipt, or execution credential
//! (`REQ1-VERIFY-facts-redacted`, `REQ1-VERIFY-facts-not-credentials`,
//! `REQ1-CHAIN-facts-not-evaluated`).
//!
//! # Redaction contract (load-bearing)
//!
//! Every facts struct derives **only** [`Debug`], [`Clone`], and [`PartialEq`].
//! It deliberately does NOT derive `serde::Serialize`, `serde::Deserialize`,
//! or `std::fmt::Display`, and it implements no generic encoder, string,
//! enumeration, collection, or access protocol. This makes the facts impossible
//! to turn into a credential-shaped value: there is no `to_string`, no
//! `serialize`, and no `as_bytes`.
//!
//! No facts field holds a raw Ed25519 signature, a JWK container, a nonce, the
//! raw `cast_arguments`, or selector values. The `[u8; 32]` fields below are
//! SHA-256 DIGESTS or RFC 7638 thumbprints (derived hashes), never raw
//! credentials (`REQ1-HEADER-digest-width`).
//!
//! # Derivation
//!
//! Derived first-hand from `spec/bap-v1.md` § Public verification contract
//! (lines 336–373) and § Consumption chain and anchored export (lines 443–465),
//! and `docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md`
//! § Results and authority (lines 82–91) — NOT from any sibling-SDK or Elixir
//! source (ADR 0014 D5). The chain/anchor/transition/export fact field sets come
//! from the ADR 0004 contract (the conformance corpus `expected` for those
//! surfaces carries only `verdict`, so the contract is the authority for the
//! fact shapes).

/// The single not-evaluated marker carried by every facts struct.
///
/// A unit struct used as the type of both the `authorization` and `trust`
/// fields — the FIELD NAME distinguishes the semantics, matching the
/// protocol's single `:not_evaluated` atom. `GrantFacts` / `EnvelopeFacts` /
/// `AnchoredExportFacts` expose `authorization: NotEvaluated`; the diagnostic
/// chain / anchor / transition / export facts expose `trust: NotEvaluated`;
/// `AnchoredExportFacts` carries BOTH (`REQ1-CHAIN-facts-shape`:
/// "Only `AnchoredExportFacts` additionally carries `authorization:
/// not_evaluated`").
///
/// Derives [`Debug`], [`Clone`], [`Copy`], [`PartialEq`], [`Eq`] only — it
/// renders as the bare token `NotEvaluated` and carries no value, so it cannot
/// be mistaken for a positive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotEvaluated;

// ============================================================================
// Grant / envelope facts (authorization: NotEvaluated)
// ============================================================================

/// Redacted facts returned by grant verification (`verify_grant`).
///
/// "contains exactly version, issuer, grant ID, raw 32-byte issuer-key
/// fingerprint, raw 32-byte holder thumbprint, matched audience, grant times,
/// and `authorization: :not_evaluated`" (`spec/bap-v1.md` lines 347–349).
/// Grant times are the decoded `iat` / `nbf` / `exp` NumericDates. The
/// fingerprints/thumbprints are raw 32-byte SHA-256 digests, not raw keys.
///
/// It MUST NOT carry the raw signature, the issuer JWK, a nonce, the
/// operations' selector values, or any caller argument
/// (`REQ1-VERIFY-facts-not-credentials`).
#[derive(Debug, Clone, PartialEq)]
pub struct GrantFacts {
    /// The grant `v` claim (integral contract-major; v1 == `1`).
    pub version: i64,
    /// The grant `iss` claim (StringOrURI).
    pub issuer: String,
    /// The grant `jti` (grant identifier).
    pub grant_id: String,
    /// Raw 32-byte SHA-256 fingerprint of the caller's trusted issuer public
    /// key (`REQ1-HEADER-issuer-fingerprint`). A digest, not a raw key.
    pub issuer_key_fingerprint: [u8; 32],
    /// Raw 32-byte RFC 7638 thumbprint of the grant's `cnf.jkt`
    /// (`REQ1-HEADER-thumbprint`, `REQ1-HEADER-digest-width`).
    pub holder_thumbprint: [u8; 32],
    /// The single audience value that matched the caller's expected audience.
    pub matched_audience: String,
    /// Grant `iat` (integral NumericDate).
    pub iat: i64,
    /// Grant `nbf` (integral NumericDate).
    pub nbf: i64,
    /// Grant `exp` (integral NumericDate).
    pub exp: i64,
    /// Authorization was not evaluated — verification is not authority.
    pub authorization: NotEvaluated,
}

/// Redacted facts returned by combined envelope verification (`check_envelope`).
///
/// "adds proof ID, invocation ID, operation, normalized URI, raw grant/request
/// hashes, and proof issuance time" (`spec/bap-v1.md` lines 369–370) on top
/// of the grant result. `check_envelope` re-verifies the raw grant, so
/// `EnvelopeFacts` **embeds** [`GrantFacts`] (the grant view it re-established)
/// rather than duplicating its fields. Both the embedded grant view and the
/// envelope itself carry `authorization: NotEvaluated` — neither is authorized
/// (`REQ1-VERIFY-grant-not-authorized`, `REQ1-VERIFY-envelope-binding`).
///
/// The grant/request hashes are raw 32-byte SHA-256 digests (`ath` over the
/// received grant compact, `ba_req` over the request-digest preimage). It MUST
/// NOT carry the raw proof signature, the proof JWK, a nonce, selector values,
/// or the raw `cast_arguments`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopeFacts {
    /// The re-verified grant facts (the envelope re-runs grant verification on
    /// the raw grant compact before binding the proof).
    pub grant: GrantFacts,
    /// The proof `jti` (proof identifier).
    pub proof_id: String,
    /// The proof `ba_inv` (lowercase RFC 4122 invocation UUID).
    pub invocation_id: String,
    /// The proof `ba_op` (operation name).
    pub operation: String,
    /// The proof `htu` (normalized HTTPS target URI).
    pub normalized_uri: String,
    /// Raw 32-byte `ath` — SHA-256 over the ASCII bytes of the received grant
    /// compact value (`REQ1-CLAIM-ath`).
    pub grant_hash: [u8; 32],
    /// Raw 32-byte `ba_req` — the request digest
    /// (`base64url(SHA-256("BAP1-REQUEST\0" || JCS([op, typed(cast_args)])))`).
    pub request_hash: [u8; 32],
    /// The proof `iat` (integral NumericDate).
    pub proof_iat: i64,
    /// Authorization was not evaluated — verification is not authority.
    pub authorization: NotEvaluated,
}

// ============================================================================
// Chain / anchor / transition / export facts (trust: NotEvaluated)
// ============================================================================

/// Redacted facts returned by consumption-chain range verification
/// (`check_chain`).
///
/// "Successful facts state the performed cryptographic checks and always retain
/// `trust: :not_evaluated`" (`spec/bap-v1.md` line 462). The fields are the
/// VERIFIED chain boundaries: chain identity, row count, first/last sequence,
/// and the caller predecessor / caller head the range was bound against
/// (ADR 0004 § Consumption rows: "requires ... chain identity, consecutive
/// sequence, predecessor links, row count, first/last sequence, caller
/// predecessor, and caller head"). The corpus `expected` for `check_chain`
/// carries only `verdict`, so the ADR 0004 contract is the field-set authority.
///
/// Chain facts carry `trust` only — they make no `authorization` field part of
/// their public shape (`REQ1-CHAIN-facts-shape`).
#[derive(Debug, Clone, PartialEq)]
pub struct ChainFacts {
    /// The verified chain identity (`chain_id`).
    pub chain_id: String,
    /// Number of rows in the verified range.
    pub row_count: i64,
    /// Sequence number of the first row in the range.
    pub first_sequence: i64,
    /// Sequence number of the last row in the range.
    pub last_sequence: i64,
    /// Raw 32-byte caller predecessor: the hash the first row's `previous`
    /// link MUST equal (the all-zero hash for a sequence-zero genesis row).
    pub previous_hash: [u8; 32],
    /// Raw 32-byte caller head: the hash of the last row in the range
    /// (`SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)` of the final row).
    pub head_hash: [u8; 32],
    /// Trust was not evaluated — a self-consistent chain does not certify
    /// completeness (`REQ1-CHAIN-no-deletion-cert`).
    pub trust: NotEvaluated,
}

/// Redacted facts returned by historical boundary-anchor verification
/// (`verify_historical_anchor`).
///
/// A boundary anchor is a compact JWS whose closed JCS payload "binds protocol
/// version, anchor identity and time, chain identity, sequence, chain hash, and
/// the RFC 7638 fingerprint derived from the raw Ed25519 public key"
/// (ADR 0004 § Boundary anchors). These verified values are echoed in the
/// facts. Anchor facts carry `trust` only (`REQ1-CHAIN-facts-shape`).
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorFacts {
    /// The anchor `anchor_id`.
    pub anchor_id: String,
    /// The anchor `anchored_at` (integral NumericDate).
    pub anchored_at: i64,
    /// The anchor `chain_id`.
    pub chain_id: String,
    /// The anchor `sequence` (zero for a start anchor requires the all-zero
    /// chain hash).
    pub sequence: i64,
    /// Raw 32-byte `chain_hash` bound by the anchor.
    pub chain_hash: [u8; 32],
    /// Raw 32-byte RFC 7638 fingerprint of the signing public key, derived
    /// from the caller's raw 32-byte key (a digest, not a raw key).
    pub key_fingerprint: [u8; 32],
    /// The protected-header `kid` of the key that authenticated the anchor.
    pub key_id: String,
    /// Trust was not evaluated.
    pub trust: NotEvaluated,
}

/// Redacted facts returned by historical key-transition verification
/// (`verify_key_transition`).
///
/// A transition is a compact JWS whose closed payload "binds transition and
/// chain identities, effective time, current fingerprint, next key ID, and next
/// fingerprint" (ADR 0004 § Authenticated key transitions). Transition facts
/// carry `trust` only (`REQ1-CHAIN-facts-shape`).
#[derive(Debug, Clone, PartialEq)]
pub struct KeyTransitionFacts {
    /// The transition `transition_id`.
    pub transition_id: String,
    /// The transition `chain_id`.
    pub chain_id: String,
    /// The transition `effective_at` (integral NumericDate).
    pub effective_at: i64,
    /// Raw 32-byte RFC 7638 fingerprint of the current (signing) key.
    pub current_key_fingerprint: [u8; 32],
    /// The current key's `kid` (may equal the next key's `kid`).
    pub current_key_id: String,
    /// Raw 32-byte RFC 7638 fingerprint of the next key.
    pub next_key_fingerprint: [u8; 32],
    /// The next key's `kid`.
    pub next_key_id: String,
    /// Trust was not evaluated.
    pub trust: NotEvaluated,
}

/// Redacted facts returned by anchored-export verification
/// (`verify_anchored_export`).
///
/// "anchored-export results additionally carry `authorization: :not_evaluated`"
/// (`REQ1-CHAIN-facts-shape`) — this is the ONLY chain-family fact that exposes
/// an `authorization` field, because an anchored export binds the retrieved
/// object generation. The closed archive header "binds chain identity,
/// first/last sequence, row count, transition count, predecessor, head, and
/// version one" (ADR 0004 § Anchored export); verification also independently
/// recomputes the complete-archive SHA-256 and compares the out-of-band
/// object-store version.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchoredExportFacts {
    /// The verified chain identity.
    pub chain_id: String,
    /// Sequence number of the first row in the archived range.
    pub first_sequence: i64,
    /// Sequence number of the last row in the archived range.
    pub last_sequence: i64,
    /// Number of consumption rows in the archive.
    pub row_count: i64,
    /// Number of authenticated key transitions framed in the archive.
    pub transition_count: i64,
    /// Raw 32-byte caller predecessor (start boundary).
    pub previous_hash: [u8; 32],
    /// Raw 32-byte caller head (end boundary).
    pub head_hash: [u8; 32],
    /// Raw 32-byte SHA-256 over the complete archive byte concatenation.
    pub digest: [u8; 32],
    /// The caller's out-of-band expected object-store version, confirmed equal
    /// to the observed version (`REQ1-EXPORT-version-exact`). Out-of-band
    /// context; NOT embedded in the archive bytes.
    pub object_version: String,
    /// Trust was not evaluated.
    pub trust: NotEvaluated,
    /// Authorization was not evaluated — even a fully authenticated export is
    /// not an execution decision.
    pub authorization: NotEvaluated,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forbidden substrings that MUST NOT appear in any facts Debug output.
    /// Each catches a class of credential-shaped leak: a raw signature, a JWK
    /// container, a nonce, a private exponent label, a secret, or the raw
    /// caller arguments. None of these fragments appears in any legitimate
    /// field name on the six facts structs.
    const FORBIDDEN: &[&str] = &[
        "signature",
        "jwk",
        "nonce",
        "private",
        "secret",
        "arguments",
    ];

    /// Detects a JWK private-exponent `d` member in Debug output.
    ///
    /// The plan specifies forbidding the substring `" d"` (the JWK private
    /// field). A literal `" d"` match is too broad: it collides with the
    /// contracted `digest` field, whose Debug rendering is `], digest:` — the
    /// `, d` of `, digest:` matches `" d"` even though `digest` is a public
    /// SHA-256 hash (the opposite of private material). This refines the check
    /// to the actual JWK-`d` leak signatures: `d` as a standalone struct field
    /// (`d:` preceded by a space, brace, or comma) or as a JSON map key
    /// (`"d"`). The legitimate `digest:` field is `d` followed by `i`, so it
    /// does not match.
    fn leaks_jwk_private_d(debug: &str) -> bool {
        // Struct-field form: `d:` as a complete field name (a boundary char
        // then `d` then `:`/`=`). Catches `Jwk { x: .., d: .. }`-style leaks.
        // Byte walk is ASCII-boundary safe (`d`, `:`, `=` are all ASCII).
        let bytes = debug.as_bytes();
        let mut prev = b'\n';
        for i in 0..bytes.len() {
            let cur = bytes[i];
            if cur == b'd' {
                let next = bytes.get(i + 1).copied().unwrap_or(b'\0');
                let prev_is_boundary = matches!(prev, b' ' | b'{' | b',');
                if prev_is_boundary && matches!(next, b':' | b'=') {
                    return true;
                }
            }
            prev = cur;
        }
        // JSON map-key form: `"d"` (a quoted `d` member, e.g. a leaked
        // serde_json::Value JWK).
        debug.contains("\"d\"")
    }

    /// Asserts no forbidden substring and no JWK-private-`d` leak appears in
    /// the Debug rendering.
    fn assert_redacted(debug: &str) {
        for &needle in FORBIDDEN {
            assert!(
                !debug.contains(needle),
                "redaction violation: Debug output contains forbidden substring {needle:?}\n{debug}"
            );
        }
        assert!(
            !leaks_jwk_private_d(debug),
            "redaction violation: Debug output leaks a JWK private-exponent `d` member\n{debug}"
        );
    }

    fn zero32() -> [u8; 32] {
        [0u8; 32]
    }

    // ==========================================================================
    // Redaction Debug-property test (red-first): each facts struct's Debug
    // output is free of signature / jwk / nonce / private / secret / arguments.
    // ==========================================================================

    #[test]
    fn grant_facts_debug_is_redacted() {
        let facts = GrantFacts {
            version: 1,
            issuer: "https://issuer.example.test".to_string(),
            grant_id: "urn:example:grant:1".to_string(),
            issuer_key_fingerprint: zero32(),
            holder_thumbprint: zero32(),
            matched_audience: "https://resource.example.test".to_string(),
            iat: 1000,
            nbf: 1000,
            exp: 2000,
            authorization: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("GrantFacts"));
        assert!(debug.contains("NotEvaluated"));
        assert_redacted(&debug);
    }

    #[test]
    fn envelope_facts_debug_is_redacted() {
        let grant = GrantFacts {
            version: 1,
            issuer: "https://issuer.example.test".to_string(),
            grant_id: "urn:example:grant:1".to_string(),
            issuer_key_fingerprint: zero32(),
            holder_thumbprint: zero32(),
            matched_audience: "https://resource.example.test".to_string(),
            iat: 1000,
            nbf: 1000,
            exp: 2000,
            authorization: NotEvaluated,
        };
        let facts = EnvelopeFacts {
            grant,
            proof_id: "urn:example:proof:1".to_string(),
            invocation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            operation: "read".to_string(),
            normalized_uri: "https://resource.example.test/invoke".to_string(),
            grant_hash: zero32(),
            request_hash: zero32(),
            proof_iat: 1100,
            authorization: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("EnvelopeFacts"));
        assert!(debug.contains("proof_iat"));
        assert_redacted(&debug);
    }

    #[test]
    fn chain_facts_debug_is_redacted() {
        let facts = ChainFacts {
            chain_id: "urn:example:chain".to_string(),
            row_count: 2,
            first_sequence: 1,
            last_sequence: 2,
            previous_hash: zero32(),
            head_hash: zero32(),
            trust: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("ChainFacts"));
        assert_redacted(&debug);
    }

    #[test]
    fn anchor_facts_debug_is_redacted() {
        let facts = AnchorFacts {
            anchor_id: "urn:example:anchor:start".to_string(),
            anchored_at: 1000,
            chain_id: "urn:example:chain".to_string(),
            sequence: 0,
            chain_hash: zero32(),
            key_fingerprint: zero32(),
            key_id: "archive-a".to_string(),
            trust: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("AnchorFacts"));
        assert_redacted(&debug);
    }

    #[test]
    fn key_transition_facts_debug_is_redacted() {
        let facts = KeyTransitionFacts {
            transition_id: "urn:example:transition:a-b".to_string(),
            chain_id: "urn:example:chain".to_string(),
            effective_at: 1500,
            current_key_fingerprint: zero32(),
            current_key_id: "archive-a".to_string(),
            next_key_fingerprint: zero32(),
            next_key_id: "archive-b".to_string(),
            trust: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("KeyTransitionFacts"));
        assert_redacted(&debug);
    }

    #[test]
    fn anchored_export_facts_debug_is_redacted() {
        let facts = AnchoredExportFacts {
            chain_id: "urn:example:chain".to_string(),
            first_sequence: 1,
            last_sequence: 1,
            row_count: 1,
            transition_count: 1,
            previous_hash: zero32(),
            head_hash: zero32(),
            digest: zero32(),
            object_version: "v1".to_string(),
            trust: NotEvaluated,
            authorization: NotEvaluated,
        };
        let debug = format!("{facts:?}");
        assert!(debug.contains("AnchoredExportFacts"));
        // AnchoredExportFacts is the ONLY chain-family fact carrying both
        // markers — confirm both field names render.
        assert!(debug.contains("trust"));
        assert!(debug.contains("authorization"));
        assert_redacted(&debug);
    }

    // ==========================================================================
    // Red-capability proof: a `raw_signature` field on a facts-shaped struct
    // WOULD trip the gate. This proves the redaction assertion is capable of
    // catching a planted signature field without ever adding one to the real
    // structs (which must stay signature-free).
    // ==========================================================================

    #[test]
    fn red_capability_a_signature_field_would_be_caught() {
        // A throwaway struct mirroring the facts shape but carrying the
        // forbidden raw-signature field. If anyone ever adds such a field to a
        // real facts struct, this is exactly the assertion that goes red.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct LeakyFacts {
            grant_id: String,
            raw_signature: [u8; 64],
            authorization: NotEvaluated,
        }
        let leaky = LeakyFacts {
            grant_id: "urn:example:grant:1".to_string(),
            raw_signature: [0u8; 64],
            authorization: NotEvaluated,
        };
        let debug = format!("{leaky:?}");
        // The Debug output DOES contain "signature" — proving the
        // `assert_redacted` gate above would fail closed on this struct.
        assert!(
            debug.contains("signature"),
            "red-capability check broken: signature field not rendered"
        );
        // And the redaction gate rejects it (this is the red state).
        let mut tripped = None;
        for &needle in FORBIDDEN {
            if debug.contains(needle) {
                tripped = Some(needle);
                break;
            }
        }
        assert_eq!(tripped, Some("signature"));
    }

    #[test]
    fn red_capability_a_jwk_private_d_field_would_be_caught() {
        // Proves the refined JWK-private-`d` detector is red-capable: a field
        // literally named `d` (the JWK private-exponent member) renders as
        // `d:` and IS caught, while the contracted `digest:` field is NOT
        // (its `d` is followed by `i`, so it is not a standalone `d` field).
        #[derive(Debug)]
        #[allow(dead_code)]
        struct LeakyJwk {
            x: [u8; 32],
            d: [u8; 32],
        }
        let leaky = LeakyJwk {
            x: [0u8; 32],
            d: [1u8; 32],
        };
        let debug = format!("{leaky:?}");
        assert!(leaks_jwk_private_d(&debug), "d-field detector missed `d:`");

        // The benign mirror: a `digest` field must NOT trip the detector.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct CleanFacts {
            digest: [u8; 32],
        }
        let clean = CleanFacts { digest: [0u8; 32] };
        let clean_debug = format!("{clean:?}");
        assert!(
            !leaks_jwk_private_d(&clean_debug),
            "d-field detector false-positive on `digest:`\n{clean_debug}"
        );
    }

    // ==========================================================================
    // NotEvaluated marker
    // ==========================================================================

    #[test]
    fn not_evaluated_renders_as_bare_token() {
        let debug = format!("{:?}", NotEvaluated);
        assert_eq!(debug, "NotEvaluated");
        assert_redacted(&debug);
    }

    #[test]
    fn not_evaluated_is_copy_eq() {
        let a = NotEvaluated;
        let b = a; // Copy: no move
        assert_eq!(a, b); // Eq
    }

    // ==========================================================================
    // Structural sanity: Clone + PartialEq + the embed-vs-duplicate decision.
    // ==========================================================================

    #[test]
    fn grant_facts_clone_and_eq() {
        let a = GrantFacts {
            version: 1,
            issuer: "iss".to_string(),
            grant_id: "jti".to_string(),
            issuer_key_fingerprint: [1u8; 32],
            holder_thumbprint: [2u8; 32],
            matched_audience: "aud".to_string(),
            iat: 1,
            nbf: 2,
            exp: 3,
            authorization: NotEvaluated,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let mut c = b.clone();
        c.version = 2;
        assert_ne!(a, c);
    }

    #[test]
    fn envelope_facts_embeds_grant_facts() {
        // EnvelopeFacts embeds GrantFacts (documented design choice): the
        // envelope re-verifies the grant and surfaces the grant facts as a
        // unit via `.grant`, rather than duplicating the nine grant fields.
        let grant = GrantFacts {
            version: 1,
            issuer: "iss".to_string(),
            grant_id: "jti".to_string(),
            issuer_key_fingerprint: [9u8; 32],
            holder_thumbprint: [8u8; 32],
            matched_audience: "aud".to_string(),
            iat: 10,
            nbf: 11,
            exp: 12,
            authorization: NotEvaluated,
        };
        let env = EnvelopeFacts {
            grant: grant.clone(),
            proof_id: "proof".to_string(),
            invocation_id: "inv".to_string(),
            operation: "read".to_string(),
            normalized_uri: "https://x.test/".to_string(),
            grant_hash: [7u8; 32],
            request_hash: [6u8; 32],
            proof_iat: 13,
            authorization: NotEvaluated,
        };
        // The embedded grant is reachable as a unit.
        assert_eq!(env.grant.grant_id, "jti");
        assert_eq!(env.grant.iat, 10);
        // Both the envelope and its embedded grant carry authorization.
        let _auth = env.authorization;
        let _grant_auth = env.grant.authorization;
        // Clone + Eq hold.
        let env2 = env.clone();
        assert_eq!(env, env2);
    }

    #[test]
    fn all_six_facts_clone() {
        // Smoke: every facts struct is Clone and produces a Debug rendering.
        let g = GrantFacts {
            version: 1,
            issuer: String::new(),
            grant_id: String::new(),
            issuer_key_fingerprint: zero32(),
            holder_thumbprint: zero32(),
            matched_audience: String::new(),
            iat: 0,
            nbf: 0,
            exp: 0,
            authorization: NotEvaluated,
        };
        let _ = g.clone();
        let e = EnvelopeFacts {
            grant: g,
            proof_id: String::new(),
            invocation_id: String::new(),
            operation: String::new(),
            normalized_uri: String::new(),
            grant_hash: zero32(),
            request_hash: zero32(),
            proof_iat: 0,
            authorization: NotEvaluated,
        };
        let _ = e.clone();
        let c = ChainFacts {
            chain_id: String::new(),
            row_count: 0,
            first_sequence: 0,
            last_sequence: 0,
            previous_hash: zero32(),
            head_hash: zero32(),
            trust: NotEvaluated,
        };
        let _ = c.clone();
        let a = AnchorFacts {
            anchor_id: String::new(),
            anchored_at: 0,
            chain_id: String::new(),
            sequence: 0,
            chain_hash: zero32(),
            key_fingerprint: zero32(),
            key_id: String::new(),
            trust: NotEvaluated,
        };
        let _ = a.clone();
        let t = KeyTransitionFacts {
            transition_id: String::new(),
            chain_id: String::new(),
            effective_at: 0,
            current_key_fingerprint: zero32(),
            current_key_id: String::new(),
            next_key_fingerprint: zero32(),
            next_key_id: String::new(),
            trust: NotEvaluated,
        };
        let _ = t.clone();
        let x = AnchoredExportFacts {
            chain_id: String::new(),
            first_sequence: 0,
            last_sequence: 0,
            row_count: 0,
            transition_count: 0,
            previous_hash: zero32(),
            head_hash: zero32(),
            digest: zero32(),
            object_version: String::new(),
            trust: NotEvaluated,
            authorization: NotEvaluated,
        };
        let _ = x.clone();
    }
}
