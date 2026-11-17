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
//! `REQ1-CHAIN-facts-not-evaluated`). The sibling role-attestation profile
//! (`bap-role-attestation/1`) adds a seventh — [`AttestationFacts`] — under
//! the same redaction contract.
//!
//! # Redaction contract (load-bearing)
//!
//! Every facts struct implements the specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering), for example
//! `#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`, including alternate, width,
//! and precision formatting. Only the contract-major selects the constant text.
//! Facts derive [`Clone`] and [`PartialEq`], but never `serde::Serialize`,
//! `serde::Deserialize`, or `std::fmt::Display`; there is no generic encoder.
//!
//! No facts field holds a raw Ed25519 signature, a JWK container, a nonce, the
//! raw `cast_arguments`, or selector values. The `[u8; 32]` fields below are
//! SHA-256 DIGESTS or RFC 7638 thumbprints (derived hashes), never raw
//! credentials (`REQ1-HEADER-digest-width`).
//!
//! # Normative sources
//!
//! Fact fields, markers, and fixed redacted rendering follow `spec/bap-v1.md`
//! §16 Public verification contract and §15 Consumption chain and anchored
//! export. Attestation and content-assertion facts follow the public verification
//! contracts in `spec/bap-role-attestation-v1.md` and
//! `spec/bap-content-assertion-v1.md`.

use crate::types::Role;

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

/// The signature-and-window marker carried by the sibling role-attestation
/// profile's facts (`verification: :signature_and_window`,
/// `bap-role-attestation/1` §3 `REQ-RA1-VERIFY-facts`).
///
/// The positive-but-bounded spelling of what a role-attestation verification
/// proved: the Ed25519 signature under the attestor key and the window
/// containment — nothing more. It is deliberately NOT an authorization: trust
/// scope, the required role, replay, and revocation stay caller-side
/// (`REQ-RA1-VERIFY-policy-caller-side`, `REQ-RA1-SECURITY-not-authority`).
///
/// Derives [`Debug`], [`Clone`], [`Copy`], [`PartialEq`], [`Eq`] only — it
/// renders as the bare token `SignatureAndWindow` and carries no value, so it
/// cannot be mistaken for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureAndWindow;

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
#[derive(Clone, PartialEq)]
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
#[derive(Clone, PartialEq)]
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
#[derive(Clone, PartialEq)]
pub struct ChainFacts {
    /// The verified contract-major, used by the fixed redacted rendering.
    pub version: i64,
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
#[derive(Clone, PartialEq)]
pub struct AnchorFacts {
    /// The verified contract-major, used by the fixed redacted rendering.
    pub version: i64,
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
#[derive(Clone, PartialEq)]
pub struct KeyTransitionFacts {
    /// The verified contract-major, used by the fixed redacted rendering.
    pub version: i64,
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
#[derive(Clone, PartialEq)]
pub struct AnchoredExportFacts {
    /// The verified contract-major, used by the fixed redacted rendering.
    pub version: i64,
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

// ============================================================================
// Role-attestation facts (the standalone sibling attestation profile)
// ============================================================================

/// Redacted facts returned by role-attestation verification
/// (`verify_attestation`, `bap-role-attestation/1` §3 `REQ-RA1-VERIFY-facts`).
///
/// Carries the attestor key id and RFC 7638 thumbprint, the subject key id and
/// thumbprint, the role, the `jti`, the window, `verification:
/// SignatureAndWindow` (the signature + window containment that were proved),
/// and `trust: NotEvaluated`. A role attestation is evidence of a binding, not
/// an authorization: facts carry no raw key material, no signature, and no
/// decision (`REQ-RA1-VERIFY-facts-non-authorizing`,
/// `REQ-RA1-SECURITY-not-authority`).
#[derive(Clone, PartialEq)]
pub struct AttestationFacts {
    /// The attestor key id (the protected-header `kid`, matched to the
    /// caller's trusted attestor key id).
    pub attestor_key_id: String,
    /// Raw 32-byte RFC 7638 thumbprint of the caller's trusted attestor
    /// public key (a digest, not a raw key).
    pub attestor_key_fingerprint: [u8; 32],
    /// The attested subject key id.
    pub subject_key_id: String,
    /// Raw 32-byte RFC 7638 thumbprint of the attested subject public key.
    pub subject_key_fingerprint: [u8; 32],
    /// The attested role.
    pub role: Role,
    /// The `jti` (the audit and revocation-reference handle).
    pub jti: String,
    /// The `nbf` (integral NumericDate).
    pub nbf: i64,
    /// The `exp` (integral NumericDate).
    pub exp: i64,
    /// The signature and the window containment were verified — and nothing
    /// else.
    pub verification: SignatureAndWindow,
    /// Trust was not evaluated.
    pub trust: NotEvaluated,
}

impl std::fmt::Debug for GrantFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.version {
            2 => "#BoundedAuthorityProtocol.V2.GrantFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.GrantFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.GrantFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for EnvelopeFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.grant.version {
            2 => "#BoundedAuthorityProtocol.V2.EnvelopeFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.EnvelopeFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for ChainFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.version {
            2 => "#BoundedAuthorityProtocol.V2.ChainFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.ChainFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.ChainFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for AnchorFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.version {
            2 => "#BoundedAuthorityProtocol.V2.AnchorFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.AnchorFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.AnchorFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for KeyTransitionFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.version {
            2 => "#BoundedAuthorityProtocol.V2.KeyTransitionFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.KeyTransitionFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.KeyTransitionFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for AnchoredExportFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.version {
            2 => "#BoundedAuthorityProtocol.V2.AnchoredExportFacts<redacted>",
            3 => "#BoundedAuthorityProtocol.V3.AnchoredExportFacts<redacted>",
            _ => "#BoundedAuthorityProtocol.V1.AnchoredExportFacts<redacted>",
        })
    }
}

impl std::fmt::Debug for AttestationFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("#BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero32() -> [u8; 32] {
        [0; 32]
    }

    // ==========================================================================
    // NotEvaluated marker
    // ==========================================================================

    #[test]
    fn not_evaluated_renders_as_bare_token() {
        let debug = format!("{NotEvaluated:?}");
        assert_eq!(debug, "NotEvaluated");
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
            version: 1,
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
            version: 1,
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
            version: 1,
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
            version: 1,
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
