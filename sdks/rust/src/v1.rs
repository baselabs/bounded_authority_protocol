//! Façade A — the public v1 verification entry points (Tasks 10–13).
//!
//! This module is the implementation home for the frozen v1 façade functions
//! named in `docs/protocol-v1.md` § Public verification contract (lines
//! 291–373). Task 10 lands Façade A: the untrusted key locator, the grant/proof
//! decodes, and the four signing-input producers (the first half of the 17-
//! function public surface).
//!
//! This is a **silent-auth-class surface**: a header/claim closed-set leak
//! (accepting `alg:"none"`, an unknown claim, or a private JWK member) is an
//! algorithm-confusion / unknown-claim acceptance; a single wrong signing-input
//! byte is a wrong signature. Every reject collapses to exactly
//! [`Invalid`](crate::Invalid) (`REQ1-VERIFY-return-shape`) with no value leak
//! (`REQ1-LOCATOR-no-value-leak`). Decode results carry
//! `verification: NotEvaluated` (`REQ1-VERIFY-decode-not-evaluated`); the
//! locator carries `trust: NotEvaluated` (`REQ1-LOCATOR-not-authority`).
//!
//! # Derivation
//!
//! Derived first-hand from `docs/protocol-v1.md` (§ Protected headers,
//! § Claims, § Signing and digest inputs, § Untrusted key locator, § Public
//! verification contract), `docs/adr/0004-...` (§ Boundary anchors, §
//! Authenticated key transitions), RFC 7515/7638/8785, and the conformance
//! corpus under `priv/conformance/v1/corpus/cases/` — NOT from any sibling-SDK
//! or Elixir source (ADR 0014 D5). The exact JCS payload member names are
//! derived by base64url-decoding each surface's corpus `payload_segment`
//! first-hand (the corpus is the falsifier).

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::compact;
use crate::digest;
use crate::error::{Invalid, Result};
use crate::facts::NotEvaluated;
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::jwk::{jwk_decode_public, public_key_thumbprint_raw, thumbprint_raw};
use crate::types::{
    BoundaryAnchor, GrantDecoded, GrantInput, KeyLocator, KeyTransition, ProducedSigningInput,
    ProofDecoded, ProofInput,
};
use crate::uri::uri_normalize;

use sha2::{Digest, Sha256};

// ============================================================================
// Constants — closed header/claim member values (suite BAP1-Ed25519-SHA256)
// ============================================================================

const ALG_EDDSA: &str = "EdDSA";
const TYP_GRANT: &str = "ba+cap";
const TYP_PROOF: &str = "dpop+jwt";
const TYP_CHAIN_ANCHOR: &str = "ba+chain-anchor";
const TYP_KEY_TRANSITION: &str = "ba+key-transition";
const CRV_ED25519: &str = "Ed25519";
const KTY_OKP: &str = "OKP";

// ============================================================================
// untrusted_key_locator
// ============================================================================

/// Bound, split, and validate ONLY the protected grant header; return the
/// `kid` hint with `trust: NotEvaluated`.
///
/// `REQ1-LOCATOR-three-segments`: the compact MUST have exactly three segments.
/// `REQ1-LOCATOR-opaque-payload`: the payload and signature segments are NOT
/// decoded, validated, or even required to be non-empty — they stay opaque.
/// `REQ1-LOCATOR-not-authority`: the result is a `kid` hint plus
/// `trust: NotEvaluated`; it selects no key and authorizes nothing.
/// `REQ1-LOCATOR-no-value-leak`: every failure returns `Err(Invalid)` with no
/// input values.
pub fn untrusted_key_locator(compact: &[u8], bounds: &Bounds) -> Result<KeyLocator> {
    // REQ1-BOUNDS-ordering: raw compact size precedes any structural work.
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    // Split into EXACTLY three segments. Unlike parse_compact (which validates
    // every segment as non-empty canonical b64url), the locator leaves the
    // payload+signature segments completely opaque — they may even be empty
    // (the corpus `untrusted-key-locator-empty-payload-signature` case is
    // `header..`). Only the protected segment is examined.
    let (protected, _payload, _signature) = split_three_segments(compact)?;
    // Bound + decode + validate ONLY the protected grant header.
    if protected.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let protected_bytes = base64url_decode(protected)?;
    if protected_bytes.len() as u64 > bounds.decoded_segment_bytes() {
        return Err(Invalid);
    }
    let header = json_decode(&protected_bytes, bounds)?;
    let kid = validate_grant_header(&header, bounds)?;
    Ok(KeyLocator {
        key_id: kid,
        trust: NotEvaluated,
    })
}

// ============================================================================
// decode_grant
// ============================================================================

/// Parse, bound, and structurally validate a grant compact without verifying
/// the Ed25519 signature.
///
/// Returns a [`GrantDecoded`] carrying the decoded identity/timing claims plus
/// `verification: NotEvaluated` (`REQ1-VERIFY-decode-not-evaluated`). The
/// protected header is validated against the grant closed set
/// (`REQ1-HEADER-closed-set`); the payload claims against the grant claim table
/// (`REQ1-CLAIM-closed-set`). All three compact segments MUST be non-empty
/// canonical base64url (via [`compact::parse_compact`]).
pub fn decode_grant(compact: &[u8], bounds: &Bounds) -> Result<GrantDecoded> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, _signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    let header = json_decode(&header_bytes, bounds)?;
    let payload = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_grant_header(&header, bounds)?;
    let decoded = validate_grant_payload(&payload, bounds)?;
    Ok(GrantDecoded {
        key_id,
        version: decoded.version,
        issuer: decoded.issuer,
        grant_id: decoded.grant_id,
        audiences: decoded.audiences,
        holder_thumbprint: decoded.holder_thumbprint,
        issued_at: decoded.issued_at,
        not_before: decoded.not_before,
        expires_at: decoded.expires_at,
        verification: NotEvaluated,
    })
}

// ============================================================================
// decode_proof
// ============================================================================

/// Parse, bound, and structurally validate a proof compact without verifying
/// the signature.
///
/// Returns a [`ProofDecoded`] carrying the decoded proof claims plus
/// `verification: NotEvaluated`. The proof header is validated against the
/// proof closed set `{alg:"EdDSA", typ:"dpop+jwt", jwk:{crv,kty,x}}`
/// (`REQ1-HEADER-closed-set`, `REQ1-HEADER-proof-jwk`,
/// `REQ1-HEADER-no-private-jwk`); the payload against the proof claim table
/// (every claim required except `nonce`; `REQ1-CLAIM-proof-required`,
/// `REQ1-CLAIM-no-extra`).
pub fn decode_proof(compact: &[u8], bounds: &Bounds) -> Result<ProofDecoded> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, _signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    let header = json_decode(&header_bytes, bounds)?;
    let payload = json_decode(&payload_bytes, bounds)?;
    // validate_proof_header returns the decoded holder [u8;32] public key.
    let holder_public_key = validate_proof_header(&header, bounds)?;
    let holder_thumbprint = thumbprint_raw(&holder_public_key);
    let decoded = validate_proof_payload(&payload, bounds)?;
    Ok(ProofDecoded {
        // The proof header carries a JWK, not a kid; the field is empty.
        key_id: String::new(),
        proof_id: decoded.proof_id,
        method: decoded.method,
        target_uri: decoded.target_uri,
        invocation_id: decoded.invocation_id,
        operation: decoded.operation,
        grant_hash: decoded.grant_hash,
        request_hash: decoded.request_hash,
        issued_at: decoded.issued_at,
        holder_thumbprint,
        nonce: decoded.nonce,
        verification: NotEvaluated,
    })
}

// ============================================================================
// grant_signing_input
// ============================================================================

/// Produce the deterministic grant signing input from structured grant fields.
///
/// Emits one canonical JCS representation (`REQ1-SIGNING-deterministic-produce`)
/// of the protected header `{alg:"EdDSA", kid, typ:"ba+cap"}` and the grant
/// payload, then assembles `ASCII(base64url(protected) || "." ||
/// base64url(payload))` (`REQ1-SIGNING-exact-input`). The corpus pins all three
/// of `protected_segment`, `payload_segment`, and `message` byte-exact.
pub fn grant_signing_input(grant: &GrantInput, bounds: &Bounds) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate: validate every input field.
    validate_kid(&grant.key_id, bounds)?;
    validate_identifier(&grant.issuer, bounds)?;
    validate_identifier(&grant.grant_id, bounds)?;
    if grant.audiences.is_empty() || grant.audiences.len() as u64 > bounds.audiences() {
        return Err(Invalid);
    }
    let mut seen_aud = std::collections::HashSet::new();
    for aud in &grant.audiences {
        validate_identifier(aud, bounds)?;
        if !seen_aud.insert(aud.clone()) {
            return Err(Invalid); // duplicate audience
        }
    }
    if grant.operations.is_empty() || grant.operations.len() as u64 > bounds.operations() {
        return Err(Invalid);
    }
    let mut seen_op = std::collections::HashSet::new();
    for op in &grant.operations {
        validate_operation_name(&op.name, bounds)?;
        if !seen_op.insert(op.name.clone()) {
            return Err(Invalid); // duplicate operation name
        }
        if op.selectors.is_empty() || op.selectors.len() as u64 > bounds.selectors() {
            return Err(Invalid);
        }
    }

    // Build header object (JCS sorts members: alg < kid < typ).
    let header = JsonValue::Object(vec![
        ("alg".to_string(), JsonValue::String(ALG_EDDSA.to_string())),
        ("kid".to_string(), JsonValue::String(grant.key_id.clone())),
        ("typ".to_string(), JsonValue::String(TYP_GRANT.to_string())),
    ]);

    // Build payload object (member names derived first-hand from the corpus's
    // grant payload_segment: aud, cnf.jkt, exp, iat, iss, jti, nbf, operations, v).
    let aud_array = JsonValue::Array(
        grant
            .audiences
            .iter()
            .map(|a| JsonValue::String(a.clone()))
            .collect(),
    );
    let jkt = b64url_to_string(&base64url_encode(&grant.holder_thumbprint))?;
    let cnf = JsonValue::Object(vec![("jkt".to_string(), JsonValue::String(jkt))]);
    let ops_array = JsonValue::Array(
        grant
            .operations
            .iter()
            .map(|op| {
                JsonValue::Object(vec![
                    ("name".to_string(), JsonValue::String(op.name.clone())),
                    (
                        "selectors".to_string(),
                        JsonValue::Array(op.selectors.clone()),
                    ),
                ])
            })
            .collect(),
    );
    let payload = JsonValue::Object(vec![
        ("aud".to_string(), aud_array),
        ("cnf".to_string(), cnf),
        ("exp".to_string(), JsonValue::Int(grant.expires_at)),
        ("iat".to_string(), JsonValue::Int(grant.issued_at)),
        ("iss".to_string(), JsonValue::String(grant.issuer.clone())),
        ("jti".to_string(), JsonValue::String(grant.grant_id.clone())),
        ("nbf".to_string(), JsonValue::Int(grant.not_before)),
        ("operations".to_string(), ops_array),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// proof_signing_input
// ============================================================================

/// Produce the deterministic proof signing input from structured proof fields.
///
/// Derives `ath = base64url(SHA-256(grant_compact ASCII))` (`REQ1-CLAIM-ath`),
/// `ba_req = request_digest(operation, cast_arguments, bounds)`, and
/// `htu = uri_normalize(target_uri, bounds)` (`REQ1-URI-pre-normalized`). The
/// header `jwk` is built from `holder_public_key` via the canonical OKP form.
pub fn proof_signing_input(proof: &ProofInput, bounds: &Bounds) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate.
    validate_identifier(&proof.proof_id, bounds)?;
    validate_method_token(&proof.method, bounds)?;
    validate_operation_name(&proof.operation, bounds)?;
    validate_uuid(&proof.invocation_id)?;
    // htu MUST already be the normal form (REQ1-URI-pre-normalized).
    let htu = uri_normalize(&proof.target_uri, bounds)?;
    if htu != proof.target_uri {
        return Err(Invalid);
    }

    // ath = base64url(SHA-256(grant_compact ASCII bytes)) — REQ1-CLAIM-ath.
    let mut ath_hasher = Sha256::new();
    ath_hasher.update(&proof.grant_compact);
    let ath = b64url_to_string(&base64url_encode(&ath_hasher.finalize()))?;

    // ba_req = request_digest(operation, cast_arguments, bounds).
    let ba_req = digest::request_digest(&proof.operation, &proof.cast_arguments, bounds)?;
    let ba_req_str = String::from_utf8(ba_req).map_err(|_| Invalid)?;

    // Build header: {alg, jwk:{crv,kty,x}, typ}. JCS sorts: alg < jwk < typ;
    // nested jwk: crv < kty < x (matches the RFC 7638 preimage order).
    let x = b64url_to_string(&base64url_encode(&proof.holder_public_key))?;
    let jwk = JsonValue::Object(vec![
        (
            "crv".to_string(),
            JsonValue::String(CRV_ED25519.to_string()),
        ),
        ("kty".to_string(), JsonValue::String(KTY_OKP.to_string())),
        ("x".to_string(), JsonValue::String(x)),
    ]);
    let header = JsonValue::Object(vec![
        ("alg".to_string(), JsonValue::String(ALG_EDDSA.to_string())),
        ("jwk".to_string(), jwk),
        ("typ".to_string(), JsonValue::String(TYP_PROOF.to_string())),
    ]);

    // Build payload (member names derived first-hand from the corpus's proof
    // payload_segment: ath, ba_inv, ba_op, ba_req, htm, htu, iat, jti, v).
    let payload = JsonValue::Object(vec![
        ("ath".to_string(), JsonValue::String(ath)),
        (
            "ba_inv".to_string(),
            JsonValue::String(proof.invocation_id.clone()),
        ),
        (
            "ba_op".to_string(),
            JsonValue::String(proof.operation.clone()),
        ),
        ("ba_req".to_string(), JsonValue::String(ba_req_str)),
        ("htm".to_string(), JsonValue::String(proof.method.clone())),
        (
            "htu".to_string(),
            JsonValue::String(proof.target_uri.clone()),
        ),
        ("iat".to_string(), JsonValue::Int(proof.issued_at)),
        ("jti".to_string(), JsonValue::String(proof.proof_id.clone())),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// boundary_anchor_signing_input
// ============================================================================

/// Produce the deterministic boundary-anchor signing input.
///
/// The protected header is `{alg:"EdDSA", kid, typ:"ba+chain-anchor"}` (ADR
/// 0004 § Boundary anchors). The payload binds protocol version, anchor
/// identity+time, chain identity, sequence, the chain hash, and the RFC 7638
/// fingerprint derived from `public_key`. Sequence zero requires the all-zero
/// chain hash.
pub fn boundary_anchor_signing_input(
    anchor: &BoundaryAnchor,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate.
    validate_kid(&anchor.key_id, bounds)?;
    validate_identifier(&anchor.anchor_id, bounds)?;
    validate_identifier(&anchor.chain_id, bounds)?;
    if anchor.sequence < 0 {
        return Err(Invalid);
    }
    // Sequence zero requires the all-zero chain hash (ADR 0004 § Boundary
    // anchors; corpus `boundary-anchor-signing-input-invalid-seq0-nonzero-chain-hash`).
    if anchor.sequence == 0 && anchor.chain_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }

    let header = JsonValue::Object(vec![
        ("alg".to_string(), JsonValue::String(ALG_EDDSA.to_string())),
        ("kid".to_string(), JsonValue::String(anchor.key_id.clone())),
        (
            "typ".to_string(),
            JsonValue::String(TYP_CHAIN_ANCHOR.to_string()),
        ),
    ]);

    // Payload members derived first-hand from the corpus's anchor
    // payload_segment: anchor_id, anchored_at, chain_hash, chain_id,
    // key_fingerprint, sequence, v.
    let chain_hash_str = b64url_to_string(&base64url_encode(&anchor.chain_hash))?;
    let fingerprint = public_key_thumbprint_raw(&anchor.public_key);
    let fingerprint_str = b64url_to_string(&base64url_encode(&fingerprint))?;
    let payload = JsonValue::Object(vec![
        (
            "anchor_id".to_string(),
            JsonValue::String(anchor.anchor_id.clone()),
        ),
        (
            "anchored_at".to_string(),
            JsonValue::Int(anchor.anchored_at),
        ),
        ("chain_hash".to_string(), JsonValue::String(chain_hash_str)),
        (
            "chain_id".to_string(),
            JsonValue::String(anchor.chain_id.clone()),
        ),
        (
            "key_fingerprint".to_string(),
            JsonValue::String(fingerprint_str),
        ),
        ("sequence".to_string(), JsonValue::Int(anchor.sequence)),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// key_transition_signing_input
// ============================================================================

/// Produce the deterministic historical key-transition signing input.
///
/// The protected header is `{alg:"EdDSA", kid:current_key_id,
/// typ:"ba+key-transition"}` (ADR 0004 § Authenticated key transitions). The
/// payload binds transition+chain identities, effective time, the current key
/// fingerprint (`from_key_fingerprint`), the next key id (`to_key_id`), and the
/// next fingerprint (`to_key_fingerprint`). The current and next public keys
/// MUST differ.
pub fn key_transition_signing_input(
    transition: &KeyTransition,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate.
    validate_kid(&transition.current_key_id, bounds)?;
    validate_kid(&transition.next_key_id, bounds)?;
    validate_identifier(&transition.chain_id, bounds)?;
    validate_identifier(&transition.transition_id, bounds)?;
    // Current and next public keys MUST differ (corpus
    // `key-transition-signing-input-invalid-same-keys`); their key IDs may equal.
    if transition.current_public_key == transition.next_public_key {
        return Err(Invalid);
    }

    let header = JsonValue::Object(vec![
        ("alg".to_string(), JsonValue::String(ALG_EDDSA.to_string())),
        (
            "kid".to_string(),
            JsonValue::String(transition.current_key_id.clone()),
        ),
        (
            "typ".to_string(),
            JsonValue::String(TYP_KEY_TRANSITION.to_string()),
        ),
    ]);

    // Payload members derived first-hand from the corpus's transition
    // payload_segment: chain_id, effective_at, from_key_fingerprint,
    // to_key_fingerprint, to_key_id, transition_id, v.
    let from_fp = public_key_thumbprint_raw(&transition.current_public_key);
    let to_fp = public_key_thumbprint_raw(&transition.next_public_key);
    let from_str = b64url_to_string(&base64url_encode(&from_fp))?;
    let to_str = b64url_to_string(&base64url_encode(&to_fp))?;
    let payload = JsonValue::Object(vec![
        (
            "chain_id".to_string(),
            JsonValue::String(transition.chain_id.clone()),
        ),
        (
            "effective_at".to_string(),
            JsonValue::Int(transition.effective_at),
        ),
        (
            "from_key_fingerprint".to_string(),
            JsonValue::String(from_str),
        ),
        ("to_key_fingerprint".to_string(), JsonValue::String(to_str)),
        (
            "to_key_id".to_string(),
            JsonValue::String(transition.next_key_id.clone()),
        ),
        (
            "transition_id".to_string(),
            JsonValue::String(transition.transition_id.clone()),
        ),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// Internal helpers — segment splitting / decoding / production
// ============================================================================

/// Splits `compact` on `.` into EXACTLY three segments without validating any
/// of them. Used by [`untrusted_key_locator`] where the payload+signature
/// segments stay completely opaque (`REQ1-LOCATOR-opaque-payload`): they may be
/// empty (the `header..` form) and are never decoded.
///
/// This is deliberately distinct from [`compact::parse_compact`], which
/// validates every segment as non-empty canonical base64url (the contract
/// decode_grant/decode_proof require, since they must decode the payload).
fn split_three_segments(compact: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let mut iter = compact.split(|&b| b == b'.');
    let s0 = iter.next().unwrap_or(&[]);
    let s1 = iter.next().ok_or(Invalid)?;
    let s2 = iter.next().ok_or(Invalid)?;
    if iter.next().is_some() {
        return Err(Invalid); // more than three segments
    }
    Ok((s0, s1, s2))
}

/// Decodes one canonical base64url segment under the caller's bounds.
///
/// Enforces `REQ1-BOUNDS-ordering`: the encoded byte ceiling precedes
/// decoding, the decoded byte ceiling precedes JSON parsing.
fn decode_segment(segment: &[u8], bounds: &Bounds) -> Result<Vec<u8>> {
    if segment.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let decoded = base64url_decode(segment)?;
    if decoded.len() as u64 > bounds.decoded_segment_bytes() {
        return Err(Invalid);
    }
    Ok(decoded)
}

/// JCS-encodes each object, base64url-encodes the result, and assembles the
/// two-segment RFC 7515 signing input (`REQ1-SIGNING-exact-input`).
fn build_produced(
    header: &JsonValue,
    payload: &JsonValue,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    let header_jcs = jcs_encode(header, bounds)?;
    let payload_jcs = jcs_encode(payload, bounds)?;
    let protected_segment = base64url_encode(&header_jcs);
    let payload_segment = base64url_encode(&payload_jcs);
    let mut message = Vec::with_capacity(protected_segment.len() + 1 + payload_segment.len());
    message.extend_from_slice(&protected_segment);
    message.push(b'.');
    message.extend_from_slice(&payload_segment);
    Ok(ProducedSigningInput {
        protected_segment,
        payload_segment,
        message,
    })
}

/// Converts a base64url byte vector to a `String` (the output is always valid
/// ASCII; the `map_err` keeps the failure closed regardless).
fn b64url_to_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Invalid)
}

// ============================================================================
// Internal helpers — closed-set header / claim validation
// ============================================================================

/// Validates the grant protected header is exactly
/// `{alg:"EdDSA", typ:"ba+cap", kid:<valid kid>}` (`REQ1-HEADER-closed-set`).
/// Returns the validated `kid`.
fn validate_grant_header(header: &JsonValue, bounds: &Bounds) -> Result<String> {
    let members = match header {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut alg = None;
    let mut typ = None;
    let mut kid = None;
    for (name, val) in members {
        match name.as_str() {
            "alg" => alg = Some(val),
            "typ" => typ = Some(val),
            "kid" => kid = Some(val),
            // crit, b64, embedded grant keys, and every unlisted member are
            // invalid (REQ1-HEADER-closed-set).
            _ => return Err(Invalid),
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_EDDSA => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_GRANT => {}
        _ => return Err(Invalid),
    }
    let kid_str = match kid {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_kid(kid_str, bounds)?;
    Ok(kid_str.clone())
}

/// Validates the proof protected header is exactly
/// `{alg:"EdDSA", typ:"dpop+jwt", jwk:{crv,kty,x}}` (`REQ1-HEADER-closed-set`,
/// `REQ1-HEADER-proof-jwk`, `REQ1-HEADER-no-private-jwk`). Returns the decoded
/// 32-byte holder public key.
fn validate_proof_header(header: &JsonValue, bounds: &Bounds) -> Result<[u8; 32]> {
    let members = match header {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut alg = None;
    let mut typ = None;
    let mut jwk = None;
    for (name, val) in members {
        match name.as_str() {
            "alg" => alg = Some(val),
            "typ" => typ = Some(val),
            "jwk" => jwk = Some(val),
            _ => return Err(Invalid),
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_EDDSA => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_PROOF => {}
        _ => return Err(Invalid),
    }
    let jwk_val = jwk.ok_or(Invalid)?;
    // Re-encode the jwk member to canonical JSON and delegate to the JWK
    // primitive's full closed-set + crv/kty/x-width + canonical-b64url
    // validation (rejects the private `d`, `kid`, `alg`, and any extra member).
    let jwk_bytes = jcs_encode(jwk_val, bounds)?;
    jwk_decode_public(&jwk_bytes)
}

/// Intermediate grant-payload decode (the fields GrantDecoded carries).
struct GrantPayload {
    version: i64,
    issuer: String,
    grant_id: String,
    audiences: Vec<String>,
    holder_thumbprint: [u8; 32],
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
}

/// Validates the grant payload against the closed claim table
/// (`REQ1-CLAIM-closed-set`, `REQ1-CLAIM-v`). All nine claims are required and
/// no other claim is accepted.
fn validate_grant_payload(payload: &JsonValue, bounds: &Bounds) -> Result<GrantPayload> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut version = None;
    let mut issuer = None;
    let mut grant_id = None;
    let mut aud = None;
    let mut iat = None;
    let mut nbf = None;
    let mut exp = None;
    let mut cnf = None;
    let mut operations = None;
    for (name, val) in members {
        match name.as_str() {
            "v" => version = Some(val),
            "iss" => issuer = Some(val),
            "jti" => grant_id = Some(val),
            "aud" => aud = Some(val),
            "iat" => iat = Some(val),
            "nbf" => nbf = Some(val),
            "exp" => exp = Some(val),
            "cnf" => cnf = Some(val),
            "operations" => operations = Some(val),
            _ => return Err(Invalid), // REQ1-CLAIM-closed-set
        }
    }
    // v MUST be exactly the integer 1 (REQ1-CLAIM-v).
    let version = match version {
        Some(JsonValue::Int(1)) => 1,
        _ => return Err(Invalid),
    };
    let issuer = take_string_or_uri(issuer, bounds)?;
    let grant_id = take_string_or_uri(grant_id, bounds)?;
    let audiences = take_audiences(aud, bounds)?;
    let issued_at = take_integral_date(iat)?;
    let not_before = take_integral_date(nbf)?;
    let expires_at = take_integral_date(exp)?;
    let holder_thumbprint = take_cnf_jkt(cnf, bounds)?;
    validate_operations(operations, bounds)?;
    // Coherent signed times: iat < exp and nbf < exp (REQ1-VERIFY-grant-times).
    // The protocol does not require iat <= nbf (REQ1-VERIFY-no-iat-nbf-order).
    if !(issued_at < expires_at && not_before < expires_at) {
        return Err(Invalid);
    }
    Ok(GrantPayload {
        version,
        issuer,
        grant_id,
        audiences,
        holder_thumbprint,
        issued_at,
        not_before,
        expires_at,
    })
}

/// Intermediate proof-payload decode (the fields ProofDecoded carries).
struct ProofPayload {
    proof_id: String,
    method: String,
    target_uri: String,
    invocation_id: String,
    operation: String,
    grant_hash: [u8; 32],
    request_hash: [u8; 32],
    issued_at: i64,
    nonce: Option<String>,
}

/// Validates the proof payload against the closed claim table. Every claim
/// except `nonce` is required; no other claim is accepted
/// (`REQ1-CLAIM-proof-required`, `REQ1-CLAIM-no-extra`).
fn validate_proof_payload(payload: &JsonValue, bounds: &Bounds) -> Result<ProofPayload> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut version = None;
    let mut jti = None;
    let mut htm = None;
    let mut htu = None;
    let mut iat = None;
    let mut nonce = None;
    let mut ba_inv = None;
    let mut ba_op = None;
    let mut ath = None;
    let mut ba_req = None;
    for (name, val) in members {
        match name.as_str() {
            "v" => version = Some(val),
            "jti" => jti = Some(val),
            "htm" => htm = Some(val),
            "htu" => htu = Some(val),
            "iat" => iat = Some(val),
            "nonce" => nonce = Some(val),
            "ba_inv" => ba_inv = Some(val),
            "ba_op" => ba_op = Some(val),
            "ath" => ath = Some(val),
            "ba_req" => ba_req = Some(val),
            _ => return Err(Invalid), // REQ1-CLAIM-no-extra
        }
    }
    // v MUST be exactly the integer 1 (REQ1-CLAIM-proof-v).
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let proof_id = take_string_or_uri(jti, bounds)?;
    let method = take_method_token(htm, bounds)?;
    let invocation_id = take_uuid(ba_inv)?;
    let operation = take_operation_name(ba_op, bounds)?;
    let grant_hash = take_digest_b64u(ath, bounds)?;
    let request_hash = take_digest_b64u(ba_req, bounds)?;
    let issued_at = take_integral_date(iat)?;
    // htu MUST already be normalized (REQ1-URI-pre-normalized).
    let target_uri = match htu {
        Some(JsonValue::String(s)) => {
            let normalized = uri_normalize(s, bounds)?;
            if normalized != *s {
                return Err(Invalid);
            }
            s.clone()
        }
        _ => return Err(Invalid),
    };
    // nonce is OPTIONAL but, if present, MUST be a non-empty string ≤512 bytes.
    let nonce = match nonce {
        None => None,
        Some(JsonValue::String(s)) => {
            if s.is_empty() {
                return Err(Invalid);
            }
            if s.len() as u64 > bounds.nonce_bytes() {
                return Err(Invalid);
            }
            Some(s.clone())
        }
        _ => return Err(Invalid),
    };
    Ok(ProofPayload {
        proof_id,
        method,
        target_uri,
        invocation_id,
        operation,
        grant_hash,
        request_hash,
        issued_at,
        nonce,
    })
}

// ============================================================================
// Internal helpers — claim-type extraction
// ============================================================================

/// Extracts a non-empty StringOrURI (≤ `identifier_bytes`).
///
/// Per RFC 7519: a value containing `:` is treated as a URI and its structure
/// is validated; otherwise it is an opaque string. Rejects control/whitespace/
/// DEL/non-ASCII bytes anywhere, an empty value, and a malformed scheme or
/// non-numeric authority port. `None` (claim absent) → `Invalid`.
fn take_string_or_uri(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_identifier(s, bounds)?;
    Ok(s.clone())
}

/// Validates a StringOrURI / identifier scalar: non-empty, ≤ identifier_bytes,
/// no control/whitespace/DEL/non-ASCII; if it contains `:`, the scheme and
/// (when `//` follows) authority port grammar are checked.
fn validate_identifier(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.identifier_bytes() {
        return Err(Invalid);
    }
    for b in s.bytes() {
        if b <= 0x20 || b == 0x7f || b >= 0x80 {
            return Err(Invalid);
        }
    }
    match s.find(':') {
        None => Ok(()), // opaque string
        Some(colon) => {
            let scheme = &s[..colon];
            validate_scheme(scheme)?;
            let rest = &s[colon + 1..];
            if let Some(after) = rest.strip_prefix("//") {
                let auth_end = after.find('/').unwrap_or(after.len());
                validate_authority_port(&after[..auth_end])?;
            }
            Ok(())
        }
    }
}

/// RFC 3986 scheme: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn validate_scheme(scheme: &str) -> Result<()> {
    let bytes = scheme.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return Err(Invalid);
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Checks the authority port grammar: a `:` after the host (outside an IP
/// literal bracket) MUST introduce an all-digit, non-empty port.
fn validate_authority_port(authority: &str) -> Result<()> {
    if authority.starts_with('[') {
        return Ok(()); // IP literal — colons inside brackets are not a port.
    }
    if let Some(c) = authority.find(':') {
        let port = &authority[c + 1..];
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Extracts the `aud` claim: one StringOrURI or a nonempty unique array of ≤64.
/// `None` → `Invalid` (aud is required).
fn take_audiences(value: Option<&JsonValue>, bounds: &Bounds) -> Result<Vec<String>> {
    let value = value.ok_or(Invalid)?;
    match value {
        JsonValue::String(s) => {
            validate_identifier(s, bounds)?;
            Ok(vec![s.clone()])
        }
        JsonValue::Array(items) => {
            if items.is_empty() || items.len() as u64 > bounds.audiences() {
                return Err(Invalid);
            }
            let mut audiences = Vec::with_capacity(items.len());
            let mut seen = std::collections::HashSet::new();
            for item in items {
                let s = match item {
                    JsonValue::String(s) => s,
                    _ => return Err(Invalid),
                };
                validate_identifier(s, bounds)?;
                if !seen.insert(s.as_str()) {
                    return Err(Invalid); // duplicate audience
                }
                audiences.push(s.clone());
            }
            Ok(audiences)
        }
        _ => Err(Invalid),
    }
}

/// Extracts an integral NumericDate (`JsonValue::Int` only — a float is not
/// integral and is rejected). `None` → `Invalid`.
fn take_integral_date(value: Option<&JsonValue>) -> Result<i64> {
    match value {
        Some(JsonValue::Int(n)) => Ok(*n),
        _ => Err(Invalid),
    }
}

/// Extracts `cnf.jkt`: exactly `{jkt: canonical_base64url_sha256}` (decodes to
/// 32 bytes), no extra members (`REQ1-CLAIM-closed-set`). `None` → `Invalid`.
fn take_cnf_jkt(value: Option<&JsonValue>, bounds: &Bounds) -> Result<[u8; 32]> {
    let value = value.ok_or(Invalid)?;
    let members = match value {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    if members.len() != 1 {
        return Err(Invalid);
    }
    let (name, val) = &members[0];
    if name != "jkt" {
        return Err(Invalid);
    }
    let s = match val {
        JsonValue::String(s) => s,
        _ => return Err(Invalid),
    };
    // bounds.encoded_segment_bytes is the b64u-string ceiling for a digest.
    if s.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let raw = base64url_decode(s.as_bytes())?;
    if raw.len() != 32 {
        return Err(Invalid);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

/// Validates the `operations` array shape without deep-validating selector
/// semantics (selector evaluation is T12). Each element MUST be exactly
/// `{name: string, selectors: non_empty_array}` (`REQ1-CLAIM-operation-shape`).
/// `None` → `Invalid` (operations is required).
fn validate_operations(value: Option<&JsonValue>, bounds: &Bounds) -> Result<()> {
    let value = value.ok_or(Invalid)?;
    let items = match value {
        JsonValue::Array(a) => a,
        _ => return Err(Invalid),
    };
    if items.is_empty() || items.len() as u64 > bounds.operations() {
        return Err(Invalid);
    }
    let mut seen_names = std::collections::HashSet::new();
    for op in items {
        let members = match op {
            JsonValue::Object(m) => m,
            _ => return Err(Invalid),
        };
        if members.len() != 2 {
            return Err(Invalid);
        }
        let mut name = None;
        let mut selectors = None;
        for (k, v) in members {
            match k.as_str() {
                "name" => name = Some(v),
                "selectors" => selectors = Some(v),
                _ => return Err(Invalid),
            }
        }
        let name_str = match name {
            Some(JsonValue::String(s)) => s,
            _ => return Err(Invalid),
        };
        validate_operation_name(name_str, bounds)?;
        if !seen_names.insert(name_str.as_str()) {
            return Err(Invalid); // unique names within the grant
        }
        let sel_items = match selectors {
            Some(JsonValue::Array(a)) => a,
            _ => return Err(Invalid),
        };
        if sel_items.is_empty() || sel_items.len() as u64 > bounds.selectors() {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Extracts an `htm` method token (1–32 bytes of the RFC 9110 token alphabet).
/// `None` → `Invalid`.
fn take_method_token(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_method_token(s, bounds)?;
    Ok(s.clone())
}

/// Validates an RFC 9110 method token: 1–`method_bytes` bytes, each in the
/// token alphabet (`REQ1-CLAIM-htm-bytes`), compared byte-for-byte without
/// case normalization (`REQ1-CLAIM-htm-no-case-normalize`).
fn validate_method_token(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.method_bytes() {
        return Err(Invalid);
    }
    for &b in s.as_bytes() {
        if !is_htm_byte(b) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Extracts a `ba_op` operation name (1–128 printable ASCII bytes).
/// `None` → `Invalid`.
fn take_operation_name(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_operation_name(s, bounds)?;
    Ok(s.clone())
}

/// Validates an operation name: non-empty, ≤ `operation_bytes`, printable ASCII
/// (0x20–0x7E).
fn validate_operation_name(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.operation_bytes() {
        return Err(Invalid);
    }
    for &b in s.as_bytes() {
        if !is_printable_ascii(b) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Extracts a canonical unpadded base64url SHA-256 string (decodes to 32 bytes).
/// Used for `ath` and `ba_req`. `None` → `Invalid`.
fn take_digest_b64u(value: Option<&JsonValue>, bounds: &Bounds) -> Result<[u8; 32]> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    if s.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let raw = base64url_decode(s.as_bytes())?;
    if raw.len() != 32 {
        return Err(Invalid);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

/// Extracts a lowercase RFC 4122 UUID (`ba_inv`). `None` → `Invalid`.
fn take_uuid(value: Option<&JsonValue>) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_uuid(s)?;
    Ok(s.clone())
}

/// Validates a lowercase RFC 4122 UUID: exactly
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (36 chars, hyphens at 8/13/18/23, all
/// other bytes lowercase hex).
fn validate_uuid(s: &str) -> Result<()> {
    const UUID_LEN: usize = 36;
    if s.len() != UUID_LEN {
        return Err(Invalid);
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return Err(Invalid);
                }
            }
            _ => {
                if !b.is_ascii_digit() && !matches!(b, b'a'..=b'f') {
                    return Err(Invalid); // lowercase hex only
                }
            }
        }
    }
    Ok(())
}

/// Validates a `kid`: 1–`kid_bytes`, each byte an ASCII letter, digit, or one
/// of `-`, `.`, `_`, `~` (`REQ1-HEADER-kid-bytes`).
fn validate_kid(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.kid_bytes() {
        return Err(Invalid);
    }
    for &b in s.as_bytes() {
        if !is_kid_byte(b) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// `kid` alphabet: unreserved (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
fn is_kid_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 9110 tchar: `ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*"`
/// `/ "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"` (RFC 7230 §3.2.6 tchar
/// plus the grave accent per `REQ1-CLAIM-htm-bytes`).
fn is_htm_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Printable ASCII (0x20–0x7E), the JSON-Schema VCHAR range.
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;
    use crate::types::GrantOperation;

    fn max() -> Bounds {
        Bounds::maximum()
    }

    fn corpus_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("priv")
            .join("conformance")
            .join("v1")
            .join("corpus")
    }

    fn load_cases(rel: &str) -> Vec<serde_json::Value> {
        let path = corpus_root().join("cases").join(rel);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let root: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        root["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("{} cases array", path.display()))
            .clone()
    }

    /// Converts a corpus selector element to the full JsonValue selector object.
    /// The corpus uses a dev-friendly shorthand: a bare string `"all"` means
    /// `{"kind":"all"}`; a full object passes through as-is. This is the F3
    /// dev-only construction seam (the producer's `GrantOperation.selectors`
    /// takes full selector objects).
    fn corpus_selector_to_json(v: &serde_json::Value) -> JsonValue {
        match v {
            serde_json::Value::String(s) => {
                JsonValue::Object(vec![("kind".to_string(), JsonValue::String(s.clone()))])
            }
            _ => serde_to_json(v),
        }
    }

    /// Converts a serde_json::Value to the crate's tagged JsonValue, preserving
    /// the integer-vs-float tag (closure #5).
    fn serde_to_json(value: &serde_json::Value) -> JsonValue {
        match value {
            serde_json::Value::Null => JsonValue::Null,
            serde_json::Value::Bool(b) => JsonValue::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    JsonValue::Int(i)
                } else {
                    JsonValue::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(s) => JsonValue::String(s.clone()),
            serde_json::Value::Array(arr) => {
                JsonValue::Array(arr.iter().map(serde_to_json).collect())
            }
            serde_json::Value::Object(obj) => JsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), serde_to_json(v)))
                    .collect(),
            ),
        }
    }

    /// Decodes a base64url string to a 32-byte array, or None if wrong width.
    fn b64url_to_32(field: &serde_json::Value) -> Option<[u8; 32]> {
        let b64 = field.as_str()?;
        let raw = crate::base64url_decode(b64.as_bytes()).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Some(arr)
    }

    // ==========================================================================
    // RED-CAPABLE PROOFS — each test asserts a behavior that a wrong impl would
    // break. The comment names the red state (what the test catches).
    // ==========================================================================

    // --- Header closed-set (algorithm-confusion class) ---
    // RED if the alg/typ closed-set check were removed: alg:"none" would be
    // accepted as a valid grant header.
    #[test]
    fn red_grant_header_rejects_alg_none() {
        // Corpus case grant-decode-invalid-algorithm-none: alg="none".
        let cases = load_cases("grant-decode/decode.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("grant-decode-invalid-algorithm-none"))
            .expect("case exists");
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        assert_eq!(decode_grant(compact, &max()), Err(Invalid));
    }

    #[test]
    fn red_proof_header_rejects_alg_none() {
        let cases = load_cases("proof-decode/decode.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("proof-decode-invalid-algorithm-none"))
            .expect("case exists");
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        assert_eq!(decode_proof(compact, &max()), Err(Invalid));
    }

    // --- Header extra member (closed-set leakage) ---
    // RED if unknown header members were silently ignored.
    #[test]
    fn red_grant_header_rejects_extra_crit_member() {
        // Build a grant compact whose protected header carries an extra `crit`
        // member (REQ1-HEADER-closed-set rejects it).
        let header_with_crit = br#"{"alg":"EdDSA","crit":["x"],"kid":"issuer","typ":"ba+cap"}"#;
        let payload = br#"{"aud":["x"],"cnf":{"jkt":"d4ucEZwvJTfwxXCN4f2xmIE5ZBFoH5i5mlzeWZaB3yI"},"exp":2000,"iat":1000,"iss":"https://i.test","jti":"g1","nbf":1000,"operations":[{"name":"read","selectors":[{"kind":"all"}]}],"v":1}"#;
        let compact = format!(
            "{}.{}.AA",
            String::from_utf8(crate::base64url_encode(header_with_crit)).unwrap(),
            String::from_utf8(crate::base64url_encode(payload)).unwrap(),
        );
        assert_eq!(
            untrusted_key_locator(compact.as_bytes(), &max()),
            Err(Invalid)
        );
    }

    // --- Claim closed-set ---
    // RED if an unknown payload claim were accepted.
    #[test]
    fn red_grant_payload_rejects_unknown_claim() {
        // Inject an `extra` claim into an otherwise-valid grant payload.
        let payload = br#"{"aud":["x"],"cnf":{"jkt":"d4ucEZwvJTfwxXCN4f2xmIE5ZBFoH5i5mlzeWZaB3yI"},"exp":2000,"extra":1,"iat":1000,"iss":"https://i.test","jti":"g1","nbf":1000,"operations":[{"name":"read","selectors":[{"kind":"all"}]}],"v":1}"#;
        let header = br#"{"alg":"EdDSA","kid":"issuer","typ":"ba+cap"}"#;
        let compact = format!(
            "{}.{}.AA",
            String::from_utf8(crate::base64url_encode(header)).unwrap(),
            String::from_utf8(crate::base64url_encode(payload)).unwrap(),
        );
        assert_eq!(decode_grant(compact.as_bytes(), &max()), Err(Invalid));
    }

    // --- kid bytes ---
    // RED if kid accepted a non-allowed byte (e.g. `/`).
    #[test]
    fn red_grant_header_rejects_bad_kid_byte() {
        let header = br#"{"alg":"EdDSA","kid":"bad/kid","typ":"ba+cap"}"#;
        let compact = format!(
            "{}.{}.AA",
            String::from_utf8(crate::base64url_encode(header)).unwrap(),
            "YWJj", // valid b64url payload segment (opaque to locator)
        );
        assert_eq!(
            untrusted_key_locator(compact.as_bytes(), &max()),
            Err(Invalid)
        );
    }

    // --- htm bytes ---
    // RED if htm accepted a space (corpus decode-proof-invalid-encoding-method-token).
    #[test]
    fn red_proof_payload_rejects_htm_with_space() {
        let cases = load_cases("proof-decode/decode.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("decode-proof-invalid-encoding-method-token"))
            .expect("case exists");
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        assert_eq!(decode_proof(compact, &max()), Err(Invalid));
    }

    // --- UUID ---
    // RED if ba_inv accepted a non-UUID string.
    #[test]
    fn red_proof_payload_rejects_non_uuid_invocation() {
        let cases = load_cases("proof-decode/decode.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("decode-proof-invalid-encoding-invocation-not-uuid"))
            .expect("case exists");
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        assert_eq!(decode_proof(compact, &max()), Err(Invalid));
    }

    // --- Signing-input byte-exactness ---
    // RED if a producer emitted a wrong member name, wrong tag (Int vs Float),
    // or wrong value: the segment would mismatch the corpus byte-exact.
    #[test]
    fn red_grant_signing_input_byte_exact() {
        let cases = load_cases("signing-input/grant.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("grant-signing-input-valid"))
            .expect("case exists");
        let input = &case["input"];
        let grant = GrantInput {
            issuer: input["issuer"].as_str().unwrap().to_string(),
            grant_id: input["grant_id"].as_str().unwrap().to_string(),
            key_id: input["key_id"].as_str().unwrap().to_string(),
            holder_thumbprint: b64url_to_32(&input["holder_thumbprint"]).expect("32 bytes"),
            issued_at: input["issued_at"].as_i64().unwrap(),
            not_before: input["not_before"].as_i64().unwrap(),
            expires_at: input["expires_at"].as_i64().unwrap(),
            audiences: input["audiences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
            operations: input["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|op| GrantOperation {
                    name: op["name"].as_str().unwrap().to_string(),
                    selectors: op["selectors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(corpus_selector_to_json)
                        .collect(),
                })
                .collect(),
        };
        let produced = grant_signing_input(&grant, &max()).expect("produces");
        let expected = &case["expected"];
        // All three byte-exact.
        assert_eq!(
            produced.protected_segment,
            expected["protected_segment"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            produced.payload_segment,
            expected["payload_segment"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            produced.message,
            expected["message"].as_str().unwrap().as_bytes()
        );
    }

    // --- Anchor genesis binding ---
    // RED if sequence-0 + nonzero-chain-hash were not rejected (corpus
    // boundary-anchor-signing-input-invalid-seq0-nonzero-chain-hash).
    #[test]
    fn red_anchor_seq0_nonzero_chain_hash_rejected() {
        let cases = load_cases("signing-input/anchor.json");
        let case = cases
            .iter()
            .find(|c| {
                c["id"].as_str()
                    == Some("boundary-anchor-signing-input-invalid-seq0-nonzero-chain-hash")
            })
            .expect("case exists");
        let input = &case["input"];
        let anchor = BoundaryAnchor {
            anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
            anchored_at: input["anchored_at"].as_i64().unwrap(),
            chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
            chain_id: input["chain_id"].as_str().unwrap().to_string(),
            key_id: input["key_id"].as_str().unwrap().to_string(),
            public_key: b64url_to_32(&input["public_key"]).expect("32 bytes"),
            sequence: input["sequence"].as_i64().unwrap(),
        };
        assert_eq!(boundary_anchor_signing_input(&anchor, &max()), Err(Invalid));
    }

    // --- Transition same-keys ---
    // RED if current_public_key == next_public_key were not rejected.
    #[test]
    fn red_transition_same_keys_rejected() {
        let cases = load_cases("signing-input/transition.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("key-transition-signing-input-invalid-same-keys"))
            .expect("case exists");
        let input = &case["input"];
        let transition = KeyTransition {
            chain_id: input["chain_id"].as_str().unwrap().to_string(),
            current_key_id: input["current_key_id"].as_str().unwrap().to_string(),
            current_public_key: b64url_to_32(&input["current_public_key"]).expect("32 bytes"),
            effective_at: input["effective_at"].as_i64().unwrap(),
            next_key_id: input["next_key_id"].as_str().unwrap().to_string(),
            next_public_key: b64url_to_32(&input["next_public_key"]).expect("32 bytes"),
            transition_id: input["transition_id"].as_str().unwrap().to_string(),
        };
        assert_eq!(
            key_transition_signing_input(&transition, &max()),
            Err(Invalid)
        );
    }

    // ==========================================================================
    // Locator opacity — a corrupted payload/signature does NOT change the
    // verdict (REQ1-LOCATOR-opaque-payload).
    // ==========================================================================

    #[test]
    fn locator_empty_payload_signature_is_valid() {
        let cases = load_cases("key-locator/untrusted.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("untrusted-key-locator-empty-payload-signature"))
            .expect("case exists");
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        let loc = untrusted_key_locator(compact, &max()).expect("locator succeeds");
        assert_eq!(loc.key_id, "issuer");
        assert_eq!(loc.trust, NotEvaluated);
    }

    // ==========================================================================
    // Corpus: key-locator/untrusted.json (3 cases)
    // ==========================================================================

    #[test]
    fn corpus_key_locator_all_3_cases() {
        let cases = load_cases("key-locator/untrusted.json");
        assert_eq!(cases.len(), 3, "key-locator corpus has 3 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
            let result = untrusted_key_locator(compact, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(loc)) => loc.key_id == case["expected"]["kid"].as_str().unwrap(),
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 3, "agreed (key-locator corpus == 3)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: grant-decode/decode.json (11 cases)
    // ==========================================================================

    #[test]
    fn corpus_grant_decode_all_11_cases() {
        let cases = load_cases("grant-decode/decode.json");
        assert_eq!(cases.len(), 11, "grant-decode corpus has 11 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
            let result = decode_grant(compact, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(d)) => d.key_id == case["expected"]["key_id"].as_str().unwrap(),
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 11, "agreed (grant-decode corpus == 11)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: proof-decode/decode.json (10 cases)
    // ==========================================================================

    #[test]
    fn corpus_proof_decode_all_10_cases() {
        let cases = load_cases("proof-decode/decode.json");
        assert_eq!(cases.len(), 10, "proof-decode corpus has 10 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
            let result = decode_proof(compact, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(d)) => d.proof_id == case["expected"]["proof_id"].as_str().unwrap(),
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 10, "agreed (proof-decode corpus == 10)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: signing-input/grant.json (2 cases)
    // ==========================================================================

    #[test]
    fn corpus_grant_signing_input_all_2_cases() {
        let cases = load_cases("signing-input/grant.json");
        assert_eq!(cases.len(), 2, "grant-signing-input corpus has 2 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            // Construct GrantInput; for the invalid-empty-audience case the
            // producer itself rejects (empty audiences).
            let grant = GrantInput {
                issuer: input["issuer"].as_str().unwrap_or("").to_string(),
                grant_id: input["grant_id"].as_str().unwrap_or("").to_string(),
                key_id: input["key_id"].as_str().unwrap_or("").to_string(),
                holder_thumbprint: b64url_to_32(&input["holder_thumbprint"]).unwrap_or([0u8; 32]),
                issued_at: input["issued_at"].as_i64().unwrap_or(0),
                not_before: input["not_before"].as_i64().unwrap_or(0),
                expires_at: input["expires_at"].as_i64().unwrap_or(0),
                audiences: input["audiences"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default(),
                operations: input["operations"]
                    .as_array()
                    .map(|ops| {
                        ops.iter()
                            .map(|op| GrantOperation {
                                name: op["name"].as_str().unwrap_or("").to_string(),
                                selectors: op["selectors"]
                                    .as_array()
                                    .map(|s| s.iter().map(corpus_selector_to_json).collect())
                                    .unwrap_or_default(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let result = grant_signing_input(&grant, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(produced)) => {
                    let exp = &case["expected"];
                    produced.protected_segment
                        == exp["protected_segment"].as_str().unwrap().as_bytes()
                        && produced.payload_segment
                            == exp["payload_segment"].as_str().unwrap().as_bytes()
                        && produced.message == exp["message"].as_str().unwrap().as_bytes()
                }
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 2, "agreed (grant-signing-input corpus == 2)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: signing-input/proof.json (3 cases)
    // ==========================================================================

    #[test]
    fn corpus_proof_signing_input_all_3_cases() {
        let cases = load_cases("signing-input/proof.json");
        assert_eq!(cases.len(), 3, "proof-signing-input corpus has 3 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let proof = ProofInput {
                proof_id: input["proof_id"].as_str().unwrap_or("").to_string(),
                method: input["method"].as_str().unwrap_or("").to_string(),
                target_uri: input["target_uri"].as_str().unwrap_or("").to_string(),
                invocation_id: input["invocation_id"].as_str().unwrap_or("").to_string(),
                operation: input["operation"].as_str().unwrap_or("").to_string(),
                cast_arguments: serde_to_json(&input["cast_arguments"]),
                grant_compact: input["grant_compact"]
                    .as_str()
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec(),
                holder_public_key: b64url_to_32(&input["holder_public_key"]).unwrap_or([0u8; 32]),
                issued_at: input["issued_at"].as_i64().unwrap_or(0),
            };
            let result = proof_signing_input(&proof, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(produced)) => {
                    let exp = &case["expected"];
                    produced.protected_segment
                        == exp["protected_segment"].as_str().unwrap().as_bytes()
                        && produced.payload_segment
                            == exp["payload_segment"].as_str().unwrap().as_bytes()
                        && produced.message == exp["message"].as_str().unwrap().as_bytes()
                }
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 3, "agreed (proof-signing-input corpus == 3)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: signing-input/anchor.json (3 cases)
    // ==========================================================================

    #[test]
    fn corpus_anchor_signing_input_all_3_cases() {
        let cases = load_cases("signing-input/anchor.json");
        assert_eq!(cases.len(), 3, "anchor-signing-input corpus has 3 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            // The invalid-short-public-key case ("AAEC" = 3 bytes) can't form a
            // [u8;32]; b64url_to_32 returns None, and the case is invalid by
            // the import boundary (mirrors assemble-compact).
            let public_key = b64url_to_32(&input["public_key"]);
            let agree = match (expected_verdict, public_key) {
                ("valid", Some(pk)) => {
                    let anchor = BoundaryAnchor {
                        anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
                        anchored_at: input["anchored_at"].as_i64().unwrap(),
                        chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
                        chain_id: input["chain_id"].as_str().unwrap().to_string(),
                        key_id: input["key_id"].as_str().unwrap().to_string(),
                        public_key: pk,
                        sequence: input["sequence"].as_i64().unwrap(),
                    };
                    match boundary_anchor_signing_input(&anchor, &max()) {
                        Ok(produced) => {
                            let exp = &case["expected"];
                            produced.protected_segment
                                == exp["protected_segment"].as_str().unwrap().as_bytes()
                                && produced.payload_segment
                                    == exp["payload_segment"].as_str().unwrap().as_bytes()
                                && produced.message == exp["message"].as_str().unwrap().as_bytes()
                        }
                        Err(Invalid) => false,
                    }
                }
                ("invalid", None) => true, // wrong-width key -> import-boundary reject
                ("invalid", Some(_)) => {
                    // seq0-nonzero-chain-hash: the producer itself rejects.
                    let anchor = BoundaryAnchor {
                        anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
                        anchored_at: input["anchored_at"].as_i64().unwrap(),
                        chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
                        chain_id: input["chain_id"].as_str().unwrap().to_string(),
                        key_id: input["key_id"].as_str().unwrap().to_string(),
                        public_key: public_key.unwrap(),
                        sequence: input["sequence"].as_i64().unwrap(),
                    };
                    boundary_anchor_signing_input(&anchor, &max()) == Err(Invalid)
                }
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 3, "agreed (anchor-signing-input corpus == 3)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: signing-input/transition.json (2 cases)
    // ==========================================================================

    #[test]
    fn corpus_transition_signing_input_all_2_cases() {
        let cases = load_cases("signing-input/transition.json");
        assert_eq!(
            cases.len(),
            2,
            "transition-signing-input corpus has 2 cases"
        );
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let transition = KeyTransition {
                chain_id: input["chain_id"].as_str().unwrap().to_string(),
                current_key_id: input["current_key_id"].as_str().unwrap().to_string(),
                current_public_key: b64url_to_32(&input["current_public_key"]).expect("32 bytes"),
                effective_at: input["effective_at"].as_i64().unwrap(),
                next_key_id: input["next_key_id"].as_str().unwrap().to_string(),
                next_public_key: b64url_to_32(&input["next_public_key"]).expect("32 bytes"),
                transition_id: input["transition_id"].as_str().unwrap().to_string(),
            };
            let result = key_transition_signing_input(&transition, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(produced)) => {
                    let exp = &case["expected"];
                    produced.protected_segment
                        == exp["protected_segment"].as_str().unwrap().as_bytes()
                        && produced.payload_segment
                            == exp["payload_segment"].as_str().unwrap().as_bytes()
                        && produced.message == exp["message"].as_str().unwrap().as_bytes()
                }
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict}");
            }
        }
        assert_eq!(agreed, 2, "agreed (transition-signing-input corpus == 2)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Round-trip: produce a grant signing input, assemble_compact it, decode it
    // back — the decoded key_id must match. Wires assemble_compact at the root.
    // ==========================================================================

    #[test]
    fn grant_produce_assemble_decode_round_trip() {
        let cases = load_cases("signing-input/grant.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("grant-signing-input-valid"))
            .unwrap();
        let input = &case["input"];
        let grant = GrantInput {
            issuer: input["issuer"].as_str().unwrap().to_string(),
            grant_id: input["grant_id"].as_str().unwrap().to_string(),
            key_id: input["key_id"].as_str().unwrap().to_string(),
            holder_thumbprint: b64url_to_32(&input["holder_thumbprint"]).unwrap(),
            issued_at: input["issued_at"].as_i64().unwrap(),
            not_before: input["not_before"].as_i64().unwrap(),
            expires_at: input["expires_at"].as_i64().unwrap(),
            audiences: input["audiences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
            operations: input["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|op| GrantOperation {
                    name: op["name"].as_str().unwrap().to_string(),
                    selectors: op["selectors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(corpus_selector_to_json)
                        .collect(),
                })
                .collect(),
        };
        let produced = grant_signing_input(&grant, &max()).expect("produce");
        // assemble_compact (the re-exported crate-root fn) appends a signature.
        let sig = [0xaa; 64];
        let signing_input = crate::types::SigningInput {
            kind: crate::types::SigningKind::Grant,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: produced.payload_segment.clone(),
        };
        let compact = crate::assemble_compact(&signing_input, &sig).expect("assemble");
        // decode_grant round-trips the protected header + payload.
        let decoded = decode_grant(&compact, &max()).expect("decode");
        assert_eq!(decoded.key_id, grant.key_id);
        assert_eq!(decoded.issuer, grant.issuer);
        assert_eq!(decoded.grant_id, grant.grant_id);
        assert_eq!(decoded.version, 1);
    }
}
