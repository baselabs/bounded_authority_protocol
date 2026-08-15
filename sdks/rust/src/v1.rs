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
use crate::ed25519;
use crate::error::{Invalid, Result};
use crate::facts::{
    AnchorFacts, AnchoredExportFacts, ChainFacts, EnvelopeFacts, GrantFacts, KeyTransitionFacts,
    NotEvaluated,
};
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::jwk::{jwk_decode_public, public_key_thumbprint_raw, thumbprint_raw};
use crate::selector;
use crate::types::{
    AnchoredExportEncoded, AnchoredExportInput, ArchivedObject, BoundaryAnchor, ChainInput,
    ConsumptionEntry, Credentials, ExpectedAnchor, ExpectedAnchoredExport, ExpectedChain,
    ExpectedExport, ExpectedGrant, ExpectedKeyTransition, ExpectedRequest, GrantDecoded,
    GrantInput, HistoricalKeyChain, HistoricalPublicKey, KeyLocator, KeyTransition, NonceMode,
    ProducedSigningInput, ProofDecoded, ProofInput, SigningInput, SigningKind, TrustedIssuer,
    ValidityUpperBound,
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

/// The ASCII domain-separation prefix for the consumption row-domain hash,
/// including its FINAL NUL byte — the same `REQ1-SIGNING-digest-prefix` pattern
/// as `BAP1-REQUEST\0` (T5's request digest).
///
/// `"BAP1-CHAIN\0"` = `[B, A, P, 1, -, C, H, A, I, N, 0x00]` (10 ASCII + 1 NUL
/// = 11 bytes — confirmed byte-exact against the corpus entry.json row-domain
/// hash). The final zero byte is load-bearing (ADR 0004 § Consumption rows:
/// `SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)`).
const CHAIN_DIGEST_PREFIX: &[u8] = b"BAP1-CHAIN\0";

/// The 20-byte archive magic prefix (ADR 0004 § Anchored export): the exact
/// ASCII bytes `BAP1-ARCHIVE\0EXPORT\0` (12 + NUL + 6 + NUL = 20). Confirmed
/// byte-exact against the corpus `anchored-export/verify.json` `chunks[0]`.
const ARCHIVE_MAGIC: &[u8] = b"BAP1-ARCHIVE\0EXPORT\0";

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
    let g = decode_grant_parts(compact, bounds)?;
    Ok(GrantDecoded {
        key_id: g.key_id,
        version: g.payload.version,
        issuer: g.payload.issuer,
        grant_id: g.payload.grant_id,
        audiences: g.payload.audiences,
        holder_thumbprint: g.payload.holder_thumbprint,
        issued_at: g.payload.issued_at,
        not_before: g.payload.not_before,
        expires_at: g.payload.expires_at,
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
    let p = decode_proof_parts(compact, bounds)?;
    let holder_thumbprint = thumbprint_raw(&p.holder_public_key);
    Ok(ProofDecoded {
        // The proof header carries a JWK, not a kid; the field is empty.
        key_id: String::new(),
        proof_id: p.payload.proof_id,
        method: p.payload.method,
        target_uri: p.payload.target_uri,
        invocation_id: p.payload.invocation_id,
        operation: p.payload.operation,
        grant_hash: p.payload.grant_hash,
        request_hash: p.payload.request_hash,
        issued_at: p.payload.issued_at,
        holder_thumbprint,
        nonce: p.payload.nonce,
        verification: NotEvaluated,
    })
}

// ============================================================================
// verify_grant — Façade C (Task 12): grant verification (the authz surface)
// ============================================================================
//
// This is the **silent-forgery surface**: a permissive verify silently accepts
// FORGED CREDENTIALS. Every binding — exact key id, exact issuer/audience, the
// Ed25519 signature over the exact 2-segment signing input, coherent signed
// times, and the three skew invariants — collapses to exactly [`Invalid`] on
// any mismatch (`REQ1-VERIFY-return-shape`) with no value leak. The result is
// [`GrantFacts`] carrying `authorization: NotEvaluated` — verification is not
// authority (`REQ1-VERIFY-grant-not-authorized`).

/// Verify a grant compact against a trusted issuer and caller expectation.
///
/// Decodes the compact (reusing [`decode_grant_parts`]), then enforces
/// `REQ1-VERIFY-grant-exact` (exact key id, issuer, audience), verifies the
/// Ed25519 signature over the exact RFC 7515 two-segment signing input
/// (`REQ1-SIGNING-exact-input`, `REQ1-SIGNING-backend-reject`), and checks the
/// signed-time coherence (`REQ1-VERIFY-grant-times`: `iat < exp` and
/// `nbf < exp`; `iat <= nbf` is NOT required) plus the three skew invariants
/// (`REQ1-VERIFY-time-bounds`):
///
/// ```text
/// iat <= evaluation_time + skew
/// nbf <= evaluation_time + skew
/// exp >  evaluation_time - skew
/// ```
///
/// Returns [`GrantFacts`] carrying the raw 32-byte issuer-key fingerprint, the
/// decoded `cnf.jkt` holder thumbprint, the matched audience, the grant times,
/// and `authorization: NotEvaluated`. The issuer-key fingerprint is
/// `public_key_thumbprint_raw(issuer.public_key)` (`REQ1-HEADER-issuer-
/// fingerprint`); it is a digest of the caller's trusted key, never a raw key.
pub fn verify_grant(
    compact: &[u8],
    issuer: &TrustedIssuer,
    expected: &ExpectedGrant,
) -> Result<GrantFacts> {
    // REQ1-VERIFY-time-bounds: the caller's skew MUST NOT exceed the profile
    // ceiling (reference runtime.ex:523-524 validates clock_skew <= bounds.
    // clock_skew). A value above the ceiling silently widens the time window
    // (future iat/nbf, expired exp accepted); reject it before any time
    // arithmetic. The `bounds.clock_skew()` ceiling itself is a tightening-
    // only maximum (60) set via `Bounds::new`.
    if expected.skew > expected.bounds.clock_skew() {
        return Err(Invalid);
    }

    let g = decode_grant_parts(compact, &expected.bounds)?;

    // REQ1-VERIFY-grant-exact: exact key ID, issuer, audience.
    if g.key_id != issuer.key_id {
        return Err(Invalid);
    }
    if g.payload.issuer != expected.issuer {
        return Err(Invalid);
    }
    if !audience_matches(&g.payload.audiences, &expected.audience) {
        return Err(Invalid);
    }

    // Signature over the exact 2-segment signing input
    // (ASCII(base64url(protected) || "." || base64url(payload))).
    let sig_raw = base64url_decode(g.signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid); // REQ1-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_raw);
    let signing_input = signing_input_bytes(g.protected_seg, g.payload_seg);
    ed25519::verify(&issuer.public_key, &signing_input, &signature)?;

    // REQ1-VERIFY-grant-times: iat < exp and nbf < exp are already enforced by
    // validate_grant_payload. iat <= nbf is NOT required
    // (REQ1-VERIFY-no-iat-nbf-order). The skew invariants use checked
    // arithmetic; an overflow saturates so the bound cannot be mis-evaluated.
    let eval = expected.evaluation_time;
    let skew = expected.skew as i64;
    let upper = eval.checked_add(skew).unwrap_or(i64::MAX);
    if g.payload.issued_at > upper || g.payload.not_before > upper {
        return Err(Invalid);
    }
    let lower = eval.checked_sub(skew).unwrap_or(i64::MIN);
    if g.payload.expires_at <= lower {
        return Err(Invalid);
    }

    let issuer_key_fingerprint = public_key_thumbprint_raw(&issuer.public_key);
    Ok(GrantFacts {
        version: g.payload.version,
        issuer: g.payload.issuer,
        grant_id: g.payload.grant_id,
        issuer_key_fingerprint,
        holder_thumbprint: g.payload.holder_thumbprint,
        matched_audience: expected.audience.clone(),
        iat: g.payload.issued_at,
        nbf: g.payload.not_before,
        exp: g.payload.expires_at,
        authorization: NotEvaluated,
    })
}

// ============================================================================
// check_envelope — Façade C (Task 12): combined envelope verification
// ============================================================================
//
// The **highest-stakes silent-forgery surface**: a permissive check_envelope
// silently accepts a proof bound to a DIFFERENT grant, a different holder, a
// different request, or a replayed/stale proof. Combined verification
// re-verifies the raw grant; verifies the holder signature + RFC 7638
// thumbprint binding (the proof's holder key MUST be the grant's `cnf.jkt`);
// and binds `ath` (SHA-256 over the EXACT RECEIVED grant compact), method, URI,
// invocation, operation, `ba_req`, proof time window, nonce mode, and every
// selector (`REQ1-VERIFY-envelope-binding`). Every mismatch → `Err(Invalid)`.

/// Verify a holder proof bound to a grant against a caller's expected request.
///
/// Re-verifies the raw grant (via [`verify_grant`]); decodes the proof and
/// verifies the holder Ed25519 signature; binds the proof header JWK RFC 7638
/// thumbprint to the grant's `cnf.jkt` (holder binding); and enforces every
/// request binding (`REQ1-VERIFY-envelope-binding`): `ath` over the received
/// grant compact (`REQ1-CLAIM-ath`), `ba_req`, `htm` method, `htu` URI,
/// `ba_inv` invocation, `ba_op` operation (which MUST name a grant operation),
/// the proof time window (`REQ1-VERIFY-time-bounds`), the nonce mode
/// (`REQ1-VERIFY-nonce-mode`), and every selector of the matched grant
/// operation via [`selector::evaluate`].
///
/// Returns [`EnvelopeFacts`] embedding the re-verified [`GrantFacts`] plus the
/// proof identity, the normalized URI, the raw grant/request hashes, the proof
/// issuance time, and `authorization: NotEvaluated`.
pub fn check_envelope(
    credentials: &Credentials,
    expected: &ExpectedRequest,
) -> Result<EnvelopeFacts> {
    let bounds = &expected.bounds;

    // REQ1-VERIFY-time-bounds: proof_max_age MUST be positive AND MUST NOT exceed
    // the profile ceiling (reference runtime.ex:550-551: proof_max_age > 0 and
    // <= bounds.proof_max_age). A zero proof_max_age would admit any proof within
    // the skew window (no max-age floor). The skew ceiling is enforced by the
    // verify_grant call below (which carries expected.skew through ExpectedGrant).
    if expected.proof_max_age < 1 || expected.proof_max_age > bounds.proof_max_age() {
        return Err(Invalid);
    }

    // Re-verify the raw grant: construct an ExpectedGrant from the request's
    // issuer/audience/timing/bounds and verify_grant the received compact.
    let expected_grant = ExpectedGrant {
        issuer: expected.issuer.clone(),
        audience: expected.audience.clone(),
        evaluation_time: expected.evaluation_time,
        skew: expected.skew,
        bounds: expected.bounds,
    };
    let grant_facts = verify_grant(
        &credentials.grant,
        &expected.trusted_issuer,
        &expected_grant,
    )?;

    // Decode the grant a second time to surface the operations array for
    // selector evaluation (GrantFacts is redacted and carries no operations).
    // The grant bytes were already authenticated by verify_grant; decode is
    // deterministic, so this yields the authentic operations of the verified
    // grant.
    let grant_parts = decode_grant_parts(&credentials.grant, bounds)?;
    let operations = extract_operations(&grant_parts.payload_json)?;

    // Decode the proof (header + payload + holder key + segments).
    let proof = decode_proof_parts(&credentials.proof, bounds)?;

    // Holder thumbprint binding: the proof header JWK RFC 7638 thumbprint MUST
    // equal the grant's cnf.jkt (REQ1-VERIFY-envelope-binding). This binds the
    // proof's holder key to the grant's confirmation.
    let holder_thumb = thumbprint_raw(&proof.holder_public_key);
    if holder_thumb != grant_facts.holder_thumbprint {
        return Err(Invalid);
    }

    // Holder signature verify over the proof's 2-segment signing input.
    let proof_sig_raw = base64url_decode(proof.signature_seg)?;
    if proof_sig_raw.len() != 64 {
        return Err(Invalid); // REQ1-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    let mut proof_signature = [0u8; 64];
    proof_signature.copy_from_slice(&proof_sig_raw);
    let proof_signing_input = signing_input_bytes(proof.protected_seg, proof.payload_seg);
    ed25519::verify(
        &proof.holder_public_key,
        &proof_signing_input,
        &proof_signature,
    )?;

    // ath binding (REQ1-CLAIM-ath): SHA-256 over the ASCII bytes of the EXACT
    // RECEIVED grant compact. Computing ath over a re-serialized compact would
    // let a modified compact pass — this is the parse!=verify protection.
    let mut ath_hasher = Sha256::new();
    ath_hasher.update(&credentials.grant);
    let mut recomputed_ath = [0u8; 32];
    recomputed_ath.copy_from_slice(&ath_hasher.finalize());
    if proof.payload.grant_hash != recomputed_ath {
        return Err(Invalid);
    }

    // ba_req binding: request_digest(operation, cast_arguments) MUST equal the
    // proof's ba_req.
    let ba_req_b64u =
        digest::request_digest(&expected.operation, &expected.cast_arguments, bounds)?;
    let ba_req_raw = base64url_decode(&ba_req_b64u)?;
    if ba_req_raw.len() != 32 {
        return Err(Invalid);
    }
    let mut recomputed_ba_req = [0u8; 32];
    recomputed_ba_req.copy_from_slice(&ba_req_raw);
    if proof.payload.request_hash != recomputed_ba_req {
        return Err(Invalid);
    }

    // method binding (byte-for-byte, case-sensitive).
    if proof.payload.method != expected.method {
        return Err(Invalid);
    }

    // URI binding: the expected URI MUST be pre-normalized (REQ1-URI-pre-
    // normalized) and the proof htu MUST equal it.
    let normalized_uri = uri_normalize(&expected.target_uri, bounds)?;
    if normalized_uri != expected.target_uri {
        return Err(Invalid);
    }
    if proof.payload.target_uri != normalized_uri {
        return Err(Invalid);
    }

    // invocation binding (lowercase UUID string compare).
    if proof.payload.invocation_id != expected.invocation_id {
        return Err(Invalid);
    }

    // operation binding: proof ba_op MUST equal the expected operation, AND the
    // grant MUST carry an operation of that name whose selectors are then
    // evaluated against the cast arguments.
    if proof.payload.operation != expected.operation {
        return Err(Invalid);
    }
    let matched_op = operations
        .iter()
        .find(|(name, _)| name == &expected.operation)
        .ok_or(Invalid)?;
    // REQ1-VERIFY-envelope-binding: EVERY selector of the matched operation
    // MUST evaluate Ok(true) against the cast arguments.
    for selector_value in &matched_op.1 {
        if !selector::evaluate(selector_value, &expected.cast_arguments, bounds)? {
            return Err(Invalid);
        }
    }

    // Proof time window (REQ1-VERIFY-time-bounds):
    //   evaluation_time - proof_max_age - skew <= iat <= evaluation_time + skew
    let eval = expected.evaluation_time;
    let skew = expected.skew as i64;
    let proof_max_age = expected.proof_max_age as i64;
    let lower = eval
        .checked_sub(proof_max_age)
        .unwrap_or(i64::MIN)
        .checked_sub(skew)
        .unwrap_or(i64::MIN);
    let upper = eval.checked_add(skew).unwrap_or(i64::MAX);
    if proof.payload.issued_at < lower || proof.payload.issued_at > upper {
        return Err(Invalid);
    }

    // Nonce mode (REQ1-VERIFY-nonce-mode).
    match &expected.nonce_mode {
        NonceMode::NotRequired => {
            if proof.payload.nonce.is_some() {
                return Err(Invalid);
            }
        }
        NonceMode::Required(expected_nonce) => match &proof.payload.nonce {
            Some(n) if n == expected_nonce => {}
            _ => return Err(Invalid),
        },
    }

    Ok(EnvelopeFacts {
        grant: grant_facts,
        proof_id: proof.payload.proof_id,
        invocation_id: proof.payload.invocation_id,
        operation: proof.payload.operation,
        normalized_uri,
        grant_hash: recomputed_ath,
        request_hash: recomputed_ba_req,
        proof_iat: proof.payload.issued_at,
        authorization: NotEvaluated,
    })
}

// ============================================================================
// scan_compact — faithful port of the reference CompactJws.scan (ath hash gate)
// ============================================================================

/// Faithful port of the reference `CompactJws.scan` (compact_jws.ex:16-27 +
/// `take_segment` :68-75): the compact MUST be ≤ `compact_bytes` and split into
/// exactly three non-empty segments (split on `.`), the protected and payload
/// each ≤ `encoded_segment_bytes`, and the signature non-empty, ≤
/// `encoded_segment_bytes`, and dot-free. Unlike [`compact::parse_compact`],
/// this does NOT require the segments be canonical base64url — the reference's
/// scan gates hashing (`ath`/`hash`), not verification, so a non-canonical
/// segment like `a!a` passes.
fn scan_compact(compact: &[u8], bounds: &Bounds) -> Result<()> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let dot1 = compact.iter().position(|&b| b == b'.').ok_or(Invalid)?;
    if dot1 == 0 || dot1 as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let after1 = &compact[dot1 + 1..];
    let dot2 = after1.iter().position(|&b| b == b'.').ok_or(Invalid)?;
    if dot2 == 0 || dot2 as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    let signature = &after1[dot2 + 1..];
    if signature.is_empty() || signature.len() as u64 > bounds.encoded_segment_bytes() {
        return Err(Invalid);
    }
    if signature.contains(&b'.') {
        return Err(Invalid);
    }
    Ok(())
}

// ============================================================================
// assemble_compact — public façade wrapper (compose + per-kind validation)
// ============================================================================

/// Assemble the 3-segment compact serialization from a signing input + raw
/// signature, then validate the composed compact parses as its kind.
///
/// Wraps [`compact::compose_compact`] (composition + segment well-formedness)
/// with the per-kind CONTENT validation the reference's
/// `validate_assembled_compact` performs (runtime.ex:151 — it re-parses the
/// composed output as a grant/proof/anchor/transition). The public contract is
/// `/2` (no caller bounds — protocol-v1.md:299), so the per-kind parse runs
/// against the profile maximum bounds. A caller passing segments that compose
/// to a structurally-invalid credential — wrong segment count, non-canonical
/// base64url, or a header/payload that does not parse as the declared kind's
/// closed header/claim set — is rejected.
pub fn assemble_compact(input: &SigningInput, signature: &[u8; 64]) -> Result<Vec<u8>> {
    let compact = compact::compose_compact(input, signature)?;
    let bounds = Bounds::maximum();
    match input.kind {
        SigningKind::Grant => {
            decode_grant_parts(&compact, &bounds)?;
        }
        SigningKind::Proof => {
            decode_proof_parts(&compact, &bounds)?;
        }
        SigningKind::ChainAnchor => {
            decode_anchor_parts(&compact, &bounds)?;
        }
        SigningKind::KeyTransition => {
            decode_transition_parts(&compact, &bounds)?;
        }
    }
    Ok(compact)
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
    let mut seen_aud = std::collections::BTreeSet::new();
    for aud in &grant.audiences {
        validate_identifier(aud, bounds)?;
        if !seen_aud.insert(aud.clone()) {
            return Err(Invalid); // duplicate audience
        }
    }
    if grant.operations.is_empty() || grant.operations.len() as u64 > bounds.operations() {
        return Err(Invalid);
    }
    let mut seen_op = std::collections::BTreeSet::new();
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
    // Gate SHA-256 on the reference `CompactJws.scan` (compact_jws.ex:16-27):
    // total <= compact_bytes AND three non-empty segments each <=
    // encoded_segment_bytes (signature dot-free). The scan does NOT require
    // base64url canonicity — it gates hashing, not verification — so a
    // non-canonical segment (e.g. `a!a`) passes, matching the reference.
    scan_compact(proof.grant_compact.as_slice(), bounds)?;
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
// Façade B — consumption entry + chain verification (Task 11)
// ============================================================================
//
// This is a **silent-relink surface**: a permissive chain check silently
// certifies a relinked, shortened, or omitted archive. Every invariant —
// canonical re-encode, genesis binding, predecessor links, and the caller
// head/predecessor/sequence/count boundaries — collapses to exactly
// [`Invalid`](crate::Invalid) on any mismatch (`REQ1-VERIFY-return-shape`).
// [`ChainFacts`] carries `trust: NotEvaluated` and makes no `authorization`
// field part of its shape (`REQ1-CHAIN-facts-shape`,
// `REQ1-CHAIN-facts-not-evaluated`). A self-consistent chain does NOT certify
// completeness (`REQ1-CHAIN-no-deletion-cert`): a validly shortened or relinked
// range fails only against the ORIGINAL caller boundaries.

/// Encode one canonical consumption row and compute its row-domain hash.
///
/// Builds the closed JCS row object
/// `{"chain_id","commitment","previous","sequence","v":1}` (ADR 0004 §
/// Consumption rows), enforces `sequence >= 1` and the genesis binding
/// (`sequence == 1` requires the all-zero predecessor), bounds the canonical
/// bytes by `bounds.chain_row_bytes()`, and returns
/// `(canonical_bytes, SHA-256("BAP1-CHAIN\0" || canonical_bytes))`.
///
/// The corpus `entry.json` `input.previous_hash` (a base64url string) maps to
/// the row member `previous`; the producer adds `v: 1`. The corpus pins `bytes`
/// (the canonical ASCII) and `hash` (the base64url row-domain hash) byte-exact.
pub fn encode_consumption_entry(
    entry: &ConsumptionEntry,
    bounds: &Bounds,
) -> Result<(Vec<u8>, [u8; 32])> {
    // sequence MUST be a positive integer (corpus invalid-zero-sequence).
    if entry.sequence < 1 {
        return Err(Invalid);
    }
    // chain_id is a StringOrURI identifier, not an arbitrary string (reference
    // consumption_chain.ex:169-172 valid_identifier?): non-empty, ≤ identifier
    // _bytes, no control/DEL/non-ASCII, valid scheme if `:`-bearing.
    validate_identifier(&entry.chain_id, bounds)?;
    // Genesis binding: sequence 1 requires the all-zero predecessor (corpus
    // invalid-seq1-nonzero-previous). A sequence > 1 MAY carry any predecessor —
    // the encoder does not know the prior row's hash; the verifier binds it.
    if entry.sequence == 1 && entry.previous_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }

    let previous_str = b64url_to_string(&base64url_encode(&entry.previous_hash))?;
    let commitment_str = b64url_to_string(&base64url_encode(&entry.commitment))?;
    // Member names + order derived first-hand from ADR 0004 § Consumption rows
    // + the corpus entry.json expected.bytes: chain_id, commitment, previous,
    // sequence, v (already in JCS / UTF-16-sorted order).
    let row = JsonValue::Object(vec![
        (
            "chain_id".to_string(),
            JsonValue::String(entry.chain_id.clone()),
        ),
        ("commitment".to_string(), JsonValue::String(commitment_str)),
        ("previous".to_string(), JsonValue::String(previous_str)),
        ("sequence".to_string(), JsonValue::Int(entry.sequence)),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    let canonical = jcs_encode(&row, bounds)?;
    // REQ1-CHAIN-raw-rows-bounds: the canonical row is bounded by chain_row_bytes.
    if canonical.len() as u64 > bounds.chain_row_bytes() {
        return Err(Invalid);
    }
    let hash = row_domain_hash(&canonical);
    Ok((canonical, hash))
}

/// Verify a bounded range of raw canonical consumption rows against the
/// caller's expected chain boundaries.
///
/// `input.rows` is the nonempty proper list of raw canonical row binaries (each
/// already base64url-decoded by the caller); `expected` carries the caller's
/// intended chain identity, sequence span, row count, predecessor, and head
/// (`REQ1-CHAIN-no-deletion-cert`). Verification requires: the closed row shape
/// `{chain_id, commitment, previous, sequence, v:1}`, exact canonical bytes (a
/// re-`jcs_encode` of each decoded row must equal the received bytes), chain
/// identity, consecutive sequence, the genesis/caller predecessor, predecessor
/// links, row count, last sequence, and the caller head. Every failure is
/// `Err(Invalid)` with no value leak.
///
/// The row-count (≤ 65,536) and per-row-byte (≤ 4,096) ceilings are the
/// immutable profile maxima from [`Bounds::maximum`]
/// (`REQ1-CHAIN-raw-rows-bounds`); caller-tightenable via `expected.bounds`
/// (None = the immutable profile maxima — the reference threads the caller's
/// bounds here too, consumption_chain.ex:43).
pub fn check_chain(input: &ChainInput, expected: &ExpectedChain) -> Result<ChainFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());
    let rows = &input.rows;

    // REQ1-CHAIN-raw-rows-bounds: nonempty + ≤ chain_rows; each row ≤ chain_row_bytes.
    if rows.is_empty() || rows.len() as u64 > bounds.chain_rows() {
        return Err(Invalid);
    }
    for row in rows {
        if row.len() as u64 > bounds.chain_row_bytes() {
            return Err(Invalid);
        }
    }

    // Parse + canonical-reencode-check + row-domain-hash every row.
    let mut parsed: Vec<ParsedRow> = Vec::with_capacity(rows.len());
    for row in rows {
        parsed.push(parse_row(row, &bounds)?);
    }

    // Chain identity: validate the identifier shape (reference consumption_chain
    // .ex:169-172 + context_validation.ex:155-159 valid_identifier?), then every
    // row's chain_id == expected.chain_id (the rows therefore also agree amongst
    // themselves). Corpus: cross-graft.
    validate_identifier(&expected.chain_id, &bounds)?;
    for p in &parsed {
        validate_identifier(&p.chain_id, &bounds)?;
        if p.chain_id != expected.chain_id {
            return Err(Invalid);
        }
    }

    // Consecutive sequence: row i sequence == expected.first_sequence + i.
    for (i, p) in parsed.iter().enumerate() {
        let want = expected
            .first_sequence
            .checked_add(i as i64)
            .ok_or(Invalid)?;
        if p.sequence != want {
            return Err(Invalid);
        }
    }

    // Genesis binding. first_sequence < 1 is invalid (sequences begin at 1).
    // The first row's previous is ALWAYS bound to expected.previous_hash
    // (reference consumption_chain.ex:113, seeded at :47-54), and when
    // first_sequence == 1 expected.previous_hash MUST be the all-zero hash
    // (reference context_validation.ex:106-107 — a fresh chain has no
    // predecessor, so a caller-inconsistent predecessor is rejected, not
    // attested unchecked into ChainFacts). Corpus: sequence-zero-row +
    // genesis-previous-hash-forge.
    let first = &parsed[0];
    if expected.first_sequence < 1 {
        return Err(Invalid);
    }
    if expected.first_sequence == 1 && expected.previous_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }
    if first.previous != expected.previous_hash {
        return Err(Invalid);
    }

    // Predecessor links: row i's previous (32 bytes) == row_domain_hash(row i-1).
    // Corpus: invalid-encoding-broken-link.
    for i in 1..parsed.len() {
        if parsed[i].previous != parsed[i - 1].hash {
            return Err(Invalid);
        }
    }

    // Row count. Corpus: invalid-claim-count.
    if parsed.len() as i64 != expected.row_count {
        return Err(Invalid);
    }

    // Last sequence + caller head. Corpus: invalid-claim-sequence,
    // invalid-bad-last-hash, tamper-commitment-byte.
    let last = parsed.last().expect("nonempty");
    if last.sequence != expected.last_sequence {
        return Err(Invalid);
    }
    if last.hash != expected.head_hash {
        return Err(Invalid);
    }

    Ok(ChainFacts {
        chain_id: expected.chain_id.clone(),
        row_count: parsed.len() as i64,
        first_sequence: expected.first_sequence,
        last_sequence: expected.last_sequence,
        previous_hash: expected.previous_hash,
        head_hash: expected.head_hash,
        trust: NotEvaluated,
    })
}

// ----------------------------------------------------------------------------
// Chain helpers
// ----------------------------------------------------------------------------

/// One parsed + canonical-reencoded + hashed consumption row.
struct ParsedRow {
    chain_id: String,
    /// Decoded 32-byte `previous` field (for the genesis + predecessor checks).
    previous: [u8; 32],
    sequence: i64,
    /// `SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)`.
    hash: [u8; 32],
}

/// Computes `SHA-256("BAP1-CHAIN\0" || canonical_row_bytes)` as a raw 32-byte
/// digest — the row-domain hash (ADR 0004 § Consumption rows).
fn row_domain_hash(canonical_row: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DIGEST_PREFIX);
    hasher.update(canonical_row);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Decodes + structurally validates one closed consumption row, enforces the
/// canonical re-encode check, and returns the parsed fields plus the row-domain
/// hash.
///
/// Closed row shape: exactly `{chain_id: string, commitment: base64url-32,
/// previous: base64url-32, sequence: int, v: 1}` — no extra members.
/// `commitment` is validated to decode to exactly 32 bytes but otherwise stays
/// opaque (it is neither stored nor compared). The canonical re-encode check
/// rejects any row whose received bytes are not the exact JCS encoding of the
/// decoded value (corpus `check-chain-canonical-reencode`).
fn parse_row(row: &[u8], bounds: &Bounds) -> Result<ParsedRow> {
    let value = json_decode(row, bounds)?;
    let members = match &value {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut chain_id = None;
    let mut commitment = None;
    let mut previous = None;
    let mut sequence = None;
    let mut version = None;
    for (name, val) in members {
        match name.as_str() {
            "chain_id" => chain_id = Some(val),
            "commitment" => commitment = Some(val),
            "previous" => previous = Some(val),
            "sequence" => sequence = Some(val),
            "v" => version = Some(val),
            _ => return Err(Invalid), // closed set
        }
    }
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let chain_id = match chain_id {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return Err(Invalid),
    };
    let sequence = match sequence {
        Some(JsonValue::Int(n)) => *n,
        _ => return Err(Invalid),
    };
    // commitment + previous MUST be canonical base64url of exactly 32 bytes
    // (ADR 0004: "<base64url-32>"). base64url_decode enforces the canonical
    // encoding, so a non-canonical lexeme is rejected here.
    let _commitment = take_b64url_32(commitment)?;
    let previous = take_b64url_32(previous)?;

    // Canonical re-encode check: re-jcs the decoded value and require byte-exact
    // equality with the received row bytes. A whitespace or member-order variant
    // that decodes identically MUST fail closed (canonical bytes are the hash
    // preimage contract).
    let reencoded = jcs_encode(&value, bounds)?;
    if reencoded.as_slice() != row {
        return Err(Invalid);
    }

    let hash = row_domain_hash(row);
    Ok(ParsedRow {
        chain_id,
        previous,
        sequence,
        hash,
    })
}

/// Extracts a base64url string member that decodes to exactly 32 bytes.
fn take_b64url_32(value: Option<&JsonValue>) -> Result<[u8; 32]> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    let raw = base64url_decode(s.as_bytes())?;
    if raw.len() != 32 {
        return Err(Invalid);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

// ============================================================================
// Façade D — anchored export verify/encode (Task 13)
// ============================================================================
//
// This is the **silent-relink surface**: a permissive export verify silently
// certifies a RELINKED or SHORTENED archive, and a permissive rollover silently
// accepts a key path with no authenticated transition. Every binding — the
// exact archive bytes (magic + frames + EOF), the constant-time SHA-256 digest,
// the out-of-band object-store version, the closed header, the authenticated
// start/end anchors, the positional key-transition path, the chronology
// (strictly increasing effective times, no fingerprint cycle, anchor ordering),
// the surplus-key invariant (`keys.len() == transitions.len() + 1`), and the
// re-checked row-domain hash chain — collapses to exactly [`Invalid`] on any
// mismatch. [`AnchoredExportFacts`] is the ONLY chain-family fact that carries
// BOTH `trust: NotEvaluated` and `authorization: NotEvaluated`
// (`REQ1-CHAIN-facts-shape`): an anchored export binds the retrieved object
// generation, but even a fully authenticated export is not an execution
// decision.

/// Verify a signed historical boundary anchor against a trusted key and caller
/// expectation.
///
/// Parses the 3-segment compact (reusing the anchor decode helper), enforces
/// the closed protected header `{alg:"EdDSA", kid, typ:"ba+chain-anchor"}` and
/// the closed payload set, then requires: the header `kid` equals both
/// `key.key_id` and `expected.key_id`; the RFC 7638 fingerprint derived from
/// `key.public_key` equals the signed `key_fingerprint` and the expected
/// fingerprint; the signed values equal `expected`; sequence zero requires the
/// all-zero `chain_hash`; `key.valid_from <= anchored_at < valid_before` (open
/// upper under [`ValidityUpperBound::Unbounded`]); and the Ed25519 signature
/// over the exact 2-segment signing input verifies under `key.public_key`.
///
/// Returns [`AnchorFacts`] carrying `trust: NotEvaluated`.
pub fn verify_historical_anchor(
    compact: &[u8],
    key: &HistoricalPublicKey,
    expected: &ExpectedAnchor,
) -> Result<AnchorFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());
    // Key-window endpoints are magnitude-bounded under the resolved bounds
    // (context_validation.ex valid_time? — cross-vendor round 4: interval
    // membership alone accepted out-of-magnitude endpoints).
    if key.valid_from.unsigned_abs() > bounds.integer_magnitude() {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = key.valid_before {
        if v.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        // The reference's valid_before? also requires valid_before > valid_from
        // (context_validation.ex:139-140 — the closing cross-vendor note).
        if v <= key.valid_from {
            return Err(Invalid);
        }
    }
    let a = decode_anchor_parts(compact, &bounds)?;

    // Key ID: header.kid == key.key_id == expected.key_id.
    if a.key_id != key.key_id || a.key_id != expected.key_id {
        return Err(Invalid);
    }

    // Derived fingerprint == signed key_fingerprint == expected.key_fingerprint.
    let derived = public_key_thumbprint_raw(&key.public_key);
    if a.payload.key_fingerprint != derived || a.payload.key_fingerprint != expected.key_fingerprint
    {
        return Err(Invalid);
    }

    // Signed values == expected.
    if a.payload.anchor_id != expected.anchor_id
        || a.payload.anchored_at != expected.anchored_at
        || a.payload.chain_id != expected.chain_id
        || a.payload.sequence != expected.sequence
        || a.payload.chain_hash != expected.chain_hash
    {
        return Err(Invalid);
    }

    // Sequence-zero binding: sequence 0 requires the all-zero chain hash
    // (ADR 0004 § Boundary anchors).
    if a.payload.sequence == 0 && a.payload.chain_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }

    // Validity interval: valid_from <= anchored_at < valid_before.
    if !in_interval(a.payload.anchored_at, key.valid_from, &key.valid_before) {
        return Err(Invalid);
    }

    // Ed25519 signature over the exact 2-segment signing input.
    let mut signature = [0u8; 64];
    decode_signature64(a.signature_seg, &mut signature)?;
    let signing_input = signing_input_bytes(a.protected_seg, a.payload_seg);
    ed25519::verify(&key.public_key, &signing_input, &signature)?;

    Ok(AnchorFacts {
        anchor_id: a.payload.anchor_id,
        anchored_at: a.payload.anchored_at,
        chain_id: a.payload.chain_id,
        sequence: a.payload.sequence,
        chain_hash: a.payload.chain_hash,
        key_fingerprint: derived,
        key_id: a.key_id,
        trust: NotEvaluated,
    })
}

/// Verify a signed historical key transition: the current key signs the rollover
/// to the next key.
///
/// Enforces the closed protected header `{alg:"EdDSA", kid:current_key_id,
/// typ:"ba+key-transition"}` and the closed payload set, then requires: the
/// header `kid` equals `current.key_id` and `expected.current_key_id`; the
/// derived current/next fingerprints equal the signed `from_key_fingerprint`/
/// `to_key_fingerprint` and the expected fingerprints; the signed `to_key_id`,
/// `chain_id`, `effective_at`, and `transition_id` equal `expected`; the current
/// and next fingerprints DIFFER (their key IDs may be equal); `effective_at`
/// lies in BOTH historical intervals; and the current key's Ed25519 signature
/// over the 2-segment signing input verifies.
///
/// Returns [`KeyTransitionFacts`] carrying `trust: NotEvaluated`.
pub fn verify_key_transition(
    compact: &[u8],
    current: &HistoricalPublicKey,
    next: &HistoricalPublicKey,
    expected: &ExpectedKeyTransition,
) -> Result<KeyTransitionFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());
    // Key-window endpoints magnitude-bounded (same as the anchor path).
    if current.valid_from.unsigned_abs() > bounds.integer_magnitude() {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = current.valid_before {
        if v.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        if v <= current.valid_from {
            return Err(Invalid);
        }
    }
    if next.valid_from.unsigned_abs() > bounds.integer_magnitude() {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = next.valid_before {
        if v.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        if v <= next.valid_from {
            return Err(Invalid);
        }
    }
    let t = decode_transition_parts(compact, &bounds)?;

    // header.kid == current.key_id == expected.current_key_id.
    if t.key_id != current.key_id || t.key_id != expected.current_key_id {
        return Err(Invalid);
    }

    let current_derived = public_key_thumbprint_raw(&current.public_key);
    let next_derived = public_key_thumbprint_raw(&next.public_key);

    // from_fingerprint == derived(current) == expected.current_key_fingerprint.
    if t.payload.from_fingerprint != current_derived
        || t.payload.from_fingerprint != expected.current_key_fingerprint
    {
        return Err(Invalid);
    }
    // to_fingerprint == derived(next) == expected.next_key_fingerprint.
    if t.payload.to_fingerprint != next_derived
        || t.payload.to_fingerprint != expected.next_key_fingerprint
    {
        return Err(Invalid);
    }
    // Signed to_key_id / chain_id / effective_at / transition_id == expected.
    // to_key_id is bound to BOTH the positional next key's identifier AND the
    // caller's expected id (reference key_transition_codec.ex:68-69) — the
    // current-key side at line ~11 binds header.kid to current.key_id; the
    // next side must bind to_key_id to next.key_id too, or the positional key
    // chain could advance under a mismatched identifier.
    if t.payload.to_key_id != next.key_id
        || t.payload.to_key_id != expected.next_key_id
        || t.payload.chain_id != expected.chain_id
        || t.payload.effective_at != expected.effective_at
        || t.payload.transition_id != expected.transition_id
    {
        return Err(Invalid);
    }

    // Current and next fingerprints MUST differ (public keys differ); their
    // key IDs MAY be equal.
    if current_derived == next_derived {
        return Err(Invalid);
    }

    // Effective time in BOTH historical intervals.
    if !in_interval(
        t.payload.effective_at,
        current.valid_from,
        &current.valid_before,
    ) {
        return Err(Invalid);
    }
    if !in_interval(t.payload.effective_at, next.valid_from, &next.valid_before) {
        return Err(Invalid);
    }

    // The current key signs the transition.
    let mut signature = [0u8; 64];
    decode_signature64(t.signature_seg, &mut signature)?;
    let signing_input = signing_input_bytes(t.protected_seg, t.payload_seg);
    ed25519::verify(&current.public_key, &signing_input, &signature)?;

    Ok(KeyTransitionFacts {
        transition_id: t.payload.transition_id,
        chain_id: t.payload.chain_id,
        effective_at: t.payload.effective_at,
        current_key_fingerprint: current_derived,
        current_key_id: t.key_id,
        next_key_fingerprint: next_derived,
        next_key_id: t.payload.to_key_id,
        trust: NotEvaluated,
    })
}

/// Encode an anchored export archive (the producer).
///
/// Builds the exact binary concatenation (ADR 0004 § Anchored export):
/// `ARCHIVE_MAGIC || frame(canonical_header) || frame(start_anchor) ||
/// frame(each transition) || frame(each row) || frame(end_anchor)`, where each
/// frame is `UINT32_BE(nonzero_length) || bytes`. The closed canonical header
/// binds `chain_id, first_sequence, last_hash, last_sequence, previous_hash,
/// row_count, transition_count, v:1` (member names derived first-hand from the
/// corpus header frame).
///
/// Mirrors the reference producer's FULL validation contract
/// (`anchored_export_codec.ex` encode): expected-side consistency (the chain_id
/// binding of both anchors and every transition; the start/end sequence + hash
/// bindings to the chain — the start binding caught by the corpus
/// `encode-anchored-export-invalid-start-anchor-binding` case), a full
/// [`check_chain`] re-check of the rows, gated parses + 7-field matches for
/// BOTH anchors and every transition (the decoded signature width and the
/// canonical-form byte-equality of each segment enforced by the shared decode
/// path), and the key-path walk (running key from the start anchor,
/// strictly-after transition times, a fingerprint no-cycle seen-list, the end
/// anchor binding the final key with NON-STRICT `>=` chronology). Aggregate
/// ceilings are checked before the archive allocation. Computes `byte_count`
/// and the SHA-256 `digest` over the full byte stream; encode never verifies
/// Ed25519 signatures (a producer, not an authority). The result is the public
/// archive a caller stores; it is not a credential.
pub fn encode_anchored_export(
    input: &AnchoredExportInput,
    expected: &ExpectedExport,
) -> Result<AnchoredExportEncoded> {
    let bounds = resolve_bounds(expected.bounds.as_ref());

    // The count ceiling BEFORE any per-element walk (cross-vendor round 3: the
    // pin loop walked unbounded caller input first — O(n) work past the ceiling).
    if expected.transitions.len() as u64 > bounds.key_transitions() {
        return Err(Invalid);
    }

    // The nested-bounds pins (the reference applies them at encode AND verify —
    // validate_expected_export :352-354/:404-406 via :33 AND :387).
    require_bounds_equal(expected.chain.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.start_anchor.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.end_anchor.bounds.as_ref(), &bounds)?;
    for t in &expected.transitions {
        require_bounds_equal(t.bounds.as_ref(), &bounds)?;
    }

    // Consistency between the artifacts and the caller's expected boundaries.
    if input.rows.len() as i64 != expected.chain.row_count {
        return Err(Invalid);
    }
    if input.transitions.len() != expected.transitions.len() {
        return Err(Invalid);
    }
    if input.transitions.len() as u64 > bounds.key_transitions() {
        return Err(Invalid);
    }
    if input.rows.is_empty() || input.rows.len() as u64 > bounds.chain_rows() {
        return Err(Invalid);
    }
    if input.start_anchor.len() as u64 > bounds.anchor_bytes()
        || input.end_anchor.len() as u64 > bounds.anchor_bytes()
    {
        return Err(Invalid);
    }

    // Expected-side consistency (reference validate_expected_export,
    // anchored_export_codec.ex:344-375): every transition and both anchors
    // belong to the expected chain; the anchors bind the chain's sequence span
    // and hash boundaries.
    // checked_sub: a caller-supplied first_sequence of i64::MIN would underflow
    // a bare `- 1` (debug panic / release wrap); fail closed to Invalid instead.
    let expected_start_seq = expected
        .chain
        .first_sequence
        .checked_sub(1)
        .ok_or(Invalid)?;
    if expected.start_anchor.chain_id != expected.chain.chain_id
        || expected.end_anchor.chain_id != expected.chain.chain_id
    {
        return Err(Invalid);
    }
    for t in &expected.transitions {
        if t.chain_id != expected.chain.chain_id {
            return Err(Invalid);
        }
    }
    if expected.start_anchor.sequence != expected_start_seq
        || expected.start_anchor.chain_hash != expected.chain.previous_hash
        || expected.end_anchor.sequence != expected.chain.last_sequence
        || expected.end_anchor.chain_hash != expected.chain.head_hash
    {
        return Err(Invalid);
    }

    // Row chain re-check (reference ConsumptionChain.check,
    // anchored_export_codec.ex:37-39): the rows must verify against the
    // expected boundaries before they are archived. Per-row byte ceilings are
    // enforced BEFORE the row set is cloned into ChainInput (which owns its
    // rows) — cloning an oversized caller-controlled row first would amplify
    // memory before the rejection (cross-vendor finding; the surrounding
    // encode posture is reject-before-large-allocation).
    for r in &input.rows {
        if r.len() as u64 > bounds.chain_row_bytes() {
            return Err(Invalid);
        }
    }
    check_chain(
        &ChainInput {
            rows: input.rows.clone(),
        },
        &ExpectedChain {
            bounds: Some(bounds),
            ..expected.chain.clone()
        },
    )?;

    // Start-anchor binding: parse through the width+canonical-gated decoder,
    // then match ALL signed fields against the expected anchor (reference
    // anchor_matches?, anchored_export_codec.ex:485-492).
    let start_parts = decode_anchor_parts(&input.start_anchor, &bounds)?;
    if !anchor_matches(
        &start_parts.payload,
        &start_parts.key_id,
        &expected.start_anchor,
    ) {
        return Err(Invalid);
    }

    // End anchor: the same gated parse + full match.
    let end_parts = decode_anchor_parts(&input.end_anchor, &bounds)?;
    if !anchor_matches(&end_parts.payload, &end_parts.key_id, &expected.end_anchor) {
        return Err(Invalid);
    }

    // Transitions: gated parse + full match, positionally (reference
    // parse_expected_transitions + transition_matches?,
    // anchored_export_codec.ex:443-504).
    for (compact, exp) in input.transitions.iter().zip(&expected.transitions) {
        let t = decode_transition_parts(compact, &bounds)?;
        if !transition_matches(&t.payload, &t.key_id, exp) {
            return Err(Invalid);
        }
    }

    // Key-path walk (reference validate_expected_key_path,
    // anchored_export_codec.ex:506-572): the running key starts at the start
    // anchor's, every transition carries it and advances strictly in time
    // without cycling fingerprints, and the end anchor binds the final key with
    // NON-STRICT chronology (chronological_end?, .ex:723: >=).
    key_path_ok(
        &expected.start_anchor,
        &expected.transitions,
        &expected.end_anchor,
    )?;

    // Canonical header JCS object (member names + order derived first-hand from
    // the corpus header frame: chain_id, first_sequence, last_hash,
    // last_sequence, previous_hash, row_count, transition_count, v).
    let transition_count = input.transitions.len() as i64;
    let previous_hash_str = b64url_to_string(&base64url_encode(&expected.chain.previous_hash))?;
    let last_hash_str = b64url_to_string(&base64url_encode(&expected.chain.head_hash))?;
    let header_value = JsonValue::Object(vec![
        (
            "chain_id".to_string(),
            JsonValue::String(expected.chain.chain_id.clone()),
        ),
        (
            "first_sequence".to_string(),
            JsonValue::Int(expected.chain.first_sequence),
        ),
        ("last_hash".to_string(), JsonValue::String(last_hash_str)),
        (
            "last_sequence".to_string(),
            JsonValue::Int(expected.chain.last_sequence),
        ),
        (
            "previous_hash".to_string(),
            JsonValue::String(previous_hash_str),
        ),
        (
            "row_count".to_string(),
            JsonValue::Int(expected.chain.row_count),
        ),
        (
            "transition_count".to_string(),
            JsonValue::Int(transition_count),
        ),
        ("v".to_string(), JsonValue::Int(1)),
    ]);
    let header_bytes = jcs_encode(&header_value, &bounds)?;
    if header_bytes.len() as u64 > bounds.archive_header_bytes() {
        return Err(Invalid);
    }

    // Aggregate ceilings at encode (reference anchored_export_codec.ex:69 ->
    // validate_chunks :337-340): chunk count <= archive_chunks and total bytes
    // <= archive_bytes, checked BEFORE assembling so an over-budget input cannot
    // force a full-archive allocation. Chunk count = magic + header + start +
    // transitions + rows + end — the reference's build_chunks emits the archive
    // magic as the FIRST chunk and validate_chunks counts it (the maximum
    // archive_chunks = 4 + 256 + 65,536 includes it); total = magic +
    // sum(4-byte length prefix + content) per frame.
    let frame_count = 1u64
        .checked_add(1)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(input.transitions.len() as u64))
        .and_then(|n| n.checked_add(input.rows.len() as u64))
        .and_then(|n| n.checked_add(1))
        .ok_or(Invalid)?;
    if frame_count > bounds.archive_chunks() {
        return Err(Invalid);
    }
    let mut total_bytes = ARCHIVE_MAGIC.len() as u64;
    total_bytes = total_bytes
        .checked_add(4 + header_bytes.len() as u64)
        .ok_or(Invalid)?;
    total_bytes = total_bytes
        .checked_add(4 + input.start_anchor.len() as u64)
        .ok_or(Invalid)?;
    for t in &input.transitions {
        total_bytes = total_bytes.checked_add(4 + t.len() as u64).ok_or(Invalid)?;
    }
    for r in &input.rows {
        total_bytes = total_bytes.checked_add(4 + r.len() as u64).ok_or(Invalid)?;
    }
    total_bytes = total_bytes
        .checked_add(4 + input.end_anchor.len() as u64)
        .ok_or(Invalid)?;
    if total_bytes > bounds.archive_bytes() {
        return Err(Invalid);
    }

    // Assemble the archive: magic + frames + EOF. Each frame's content MUST be
    // non-empty (UINT32_BE(nonzero_length)).
    let mut bytes = Vec::with_capacity(
        ARCHIVE_MAGIC.len()
            + header_bytes.len()
            + input.start_anchor.len()
            + input.end_anchor.len(),
    );
    bytes.extend_from_slice(ARCHIVE_MAGIC);
    frame_into(&header_bytes, &mut bytes);
    if input.start_anchor.is_empty() {
        return Err(Invalid);
    }
    frame_into(&input.start_anchor, &mut bytes);
    for t in &input.transitions {
        if t.is_empty() {
            return Err(Invalid);
        }
        frame_into(t, &mut bytes);
    }
    for r in &input.rows {
        if r.is_empty() {
            return Err(Invalid);
        }
        frame_into(r, &mut bytes);
    }
    if input.end_anchor.is_empty() {
        return Err(Invalid);
    }
    frame_into(&input.end_anchor, &mut bytes);

    let byte_count = bytes.len() as u64;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());

    Ok(AnchoredExportEncoded {
        bytes,
        byte_count,
        digest,
    })
}

/// Resolves a caller-supplied optional bounds to the effective value: `None`
/// is the profile maximum (the reference's `%{}` default-to-maximum coerce,
/// bounds.ex:139-147). Tighten-only by construction — `Bounds::new` rejects
/// widenings and merges overrides onto the maximum struct, so an identity
/// override (value == maximum) resolves EQUAL to the maximum: the sibling
/// map-size trap is structurally inexpressible against the full-struct
/// `PartialEq` this helper uses.
pub fn resolve_bounds(nested: Option<&Bounds>) -> Bounds {
    match nested {
        None => Bounds::maximum(),
        Some(b) => *b,
    }
}

/// The nested-bounds pin (reference `{:ok, ^bounds} <- Bounds.coerce(x.bounds)`,
/// anchored_export_codec.ex:352-354/:404-406): a present nested bounds must
/// equal the outer; an absent nested is valid only when the outer is
/// effectively maximum (identity overrides are NOT tightening — struct
/// equality against the maximum, the semantics the siblings' cross-vendor
/// finding corrected).
pub fn require_bounds_equal(nested: Option<&Bounds>, outer: &Bounds) -> Result<()> {
    match nested {
        Some(b) => {
            if b != outer {
                return Err(Invalid);
            }
            Ok(())
        }
        None => {
            if *outer != Bounds::maximum() {
                return Err(Invalid);
            }
            Ok(())
        }
    }
}

/// Full signed-field match of a parsed anchor against its expected values
/// (reference `anchor_matches?`, anchored_export_codec.ex:485-492 — all seven
/// fields).
fn anchor_matches(payload: &AnchorPayload, key_id: &str, expected: &ExpectedAnchor) -> bool {
    payload.anchor_id == expected.anchor_id
        && payload.anchored_at == expected.anchored_at
        && payload.chain_id == expected.chain_id
        && payload.sequence == expected.sequence
        && key_id == expected.key_id
        && payload.chain_hash == expected.chain_hash
        && payload.key_fingerprint == expected.key_fingerprint
}

/// Full signed-field match of a parsed transition against its expected values
/// (reference `transition_matches?`, anchored_export_codec.ex:493-504 — all
/// seven fields: both key ids, both fingerprints, chain, time, identity).
fn transition_matches(
    payload: &TransitionPayload,
    current_kid: &str,
    exp: &ExpectedKeyTransition,
) -> bool {
    payload.transition_id == exp.transition_id
        && payload.chain_id == exp.chain_id
        && payload.effective_at == exp.effective_at
        && current_kid == exp.current_key_id
        && payload.from_fingerprint == exp.current_key_fingerprint
        && payload.to_key_id == exp.next_key_id
        && payload.to_fingerprint == exp.next_key_fingerprint
}

/// The key-path walk over the EXPECTED set (reference
/// `validate_expected_key_path`, anchored_export_codec.ex:506-572): the running
/// `(key_id, fingerprint)` starts at the start anchor's; each transition must
/// carry it as its current key, be STRICTLY after the previous time, and name a
/// next fingerprint not already seen (cycle guard — the running current is
/// always in `seen`, so a self-loop rejects here, which is also what enforces
/// the reference's distinct-fingerprints rule by composition); the end anchor
/// must bind the final running key and carry `anchored_at >=` the running time
/// (NON-STRICT — `chronological_end?`, .ex:723; the zero-transition case
/// compares against the start anchor's time the same way, .ex:506-513).
fn key_path_ok(
    start: &ExpectedAnchor,
    transitions: &[ExpectedKeyTransition],
    end: &ExpectedAnchor,
) -> Result<()> {
    let mut current_key_id = &start.key_id;
    let mut current_fingerprint = start.key_fingerprint;
    let mut previous_time = start.anchored_at;
    // Seed the seen-list with the start fingerprint (the reference seeds
    // `[start_anchor.key_fingerprint]`, .ex:523).
    let mut seen: Vec<[u8; 32]> = vec![start.key_fingerprint];
    for t in transitions {
        if t.current_key_id != *current_key_id || t.current_key_fingerprint != current_fingerprint {
            return Err(Invalid);
        }
        if t.effective_at <= previous_time {
            return Err(Invalid);
        }
        if seen.contains(&t.next_key_fingerprint) {
            return Err(Invalid);
        }
        current_key_id = &t.next_key_id;
        current_fingerprint = t.next_key_fingerprint;
        previous_time = t.effective_at;
        seen.push(t.next_key_fingerprint);
    }
    if current_key_id != &end.key_id || current_fingerprint != end.key_fingerprint {
        return Err(Invalid);
    }
    if end.anchored_at < previous_time {
        return Err(Invalid);
    }
    Ok(())
}

/// Verify a retrieved archived object against an ordered historical key chain
/// and caller-expected anchored-export boundaries.
///
/// `obj.chunks` is the bounded nonempty proper flat chunk list (each raw
/// binary, base64url-decoded by the caller); `obj.version` is the observed
/// object-store version. Verification: bounds the chunk count + total bytes +
/// per-chunk non-emptiness; materializes the stream; checks the exact 20-byte
/// magic; hashes every raw byte and compares the SHA-256 to `expected.digest`
/// in CONSTANT TIME; requires exact `obj.version == expected.object_version`;
/// scans frames incrementally (header, start anchor, transitions, rows, end
/// anchor) requiring exact EOF; decodes + validates the closed header against
/// the caller's chain boundaries; enforces the **surplus-key invariant**
/// `keys.len() == transitions.len() + 1`; authenticates the start anchor with
/// `keys[0]`, each transition positionally (`keys[i]` signs, `keys[i+1]` is
/// next), and the end anchor with the last key; checks chronology (strictly
/// increasing effective times, no fingerprint cycle, anchor ordering); and
/// re-checks every row via [`check_chain`].
///
/// Returns [`AnchoredExportFacts`] carrying `trust: NotEvaluated` AND
/// `authorization: NotEvaluated`.
pub fn verify_anchored_export(
    obj: &ArchivedObject,
    keys: &HistoricalKeyChain,
    expected: &ExpectedAnchoredExport,
) -> Result<AnchoredExportFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());

    // The count ceiling BEFORE any per-element walk (cross-vendor round 3).
    if expected.transitions.len() as u64 > bounds.key_transitions() {
        return Err(Invalid);
    }

    // The nested-bounds pins at verify (validate_expected_anchored_export :387
    // -> validate_expected_export :352-354/:404-406).
    require_bounds_equal(expected.chain.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.start_anchor.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.end_anchor.bounds.as_ref(), &bounds)?;
    for t in &expected.transitions {
        require_bounds_equal(t.bounds.as_ref(), &bounds)?;
    }

    // Key-count ceiling BEFORE the per-key window walk (cross-vendor: the walk
    // previously consumed the entire caller chain before keys == transitions + 1).
    if keys.keys.len() as u64 != expected.transitions.len() as u64 + 1 {
        return Err(Invalid);
    }
    // Key-window validity BEFORE chunk processing/hashing (the reference
    // validates key shapes at :91 before validate_chunks — malformed intervals
    // should not force processing of the full archive).
    for k in &keys.keys {
        if k.valid_from.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        if let ValidityUpperBound::Bounded(v) = k.valid_before {
            if v.unsigned_abs() > bounds.integer_magnitude() {
                return Err(Invalid);
            }
            if v <= k.valid_from {
                return Err(Invalid);
            }
        }
    }

    // Static expected-side bindings (reference validate_expected_anchored_export
    // → validate_expected_export, anchored_export_codec.ex:362-371, reached at
    // verify :92/:387): the caller's expected anchors belong to the expected chain
    // — sequence/hash bindings are re-checked on the verified facts below, but the
    // chain_id membership is ONLY checked here (cross-vendor round 2: all three
    // SDKs enforced none of the six at verify; Rust had hash+sequence via the
    // fact comparison but not chain_id).
    let expected_start_seq = expected
        .chain
        .first_sequence
        .checked_sub(1)
        .ok_or(Invalid)?;
    if expected.start_anchor.chain_id != expected.chain.chain_id
        || expected.end_anchor.chain_id != expected.chain.chain_id
        || expected.start_anchor.sequence != expected_start_seq
        || expected.start_anchor.chain_hash != expected.chain.previous_hash
        || expected.end_anchor.sequence != expected.chain.last_sequence
        || expected.end_anchor.chain_hash != expected.chain.head_hash
    {
        return Err(Invalid);
    }
    for t in &expected.transitions {
        if t.chain_id != expected.chain.chain_id {
            return Err(Invalid);
        }
    }

    let chunks = &obj.chunks;

    // Bounded nonempty proper flat chunk list; each chunk non-empty.
    if chunks.is_empty() || chunks.len() as u64 > bounds.archive_chunks() {
        return Err(Invalid);
    }
    let mut total: u64 = 0;
    for c in chunks {
        if c.is_empty() {
            return Err(Invalid);
        }
        total = total.checked_add(c.len() as u64).ok_or(Invalid)?;
    }
    if total > bounds.archive_bytes() {
        return Err(Invalid);
    }
    if total < ARCHIVE_MAGIC.len() as u64 {
        return Err(Invalid);
    }
    // (the full version shape gate — non-empty, ≤ object_version_bytes, both
    // sides — runs at the compare below; cross-vendor round 11.)

    // Stream the digest over the chunks WITHOUT materializing the whole archive
    // first (reference hash_chunks, anchored_export_codec.ex:705-714 —
    // incremental SHA-256 over each chunk, no concat). A huge inauthentic
    // archive fails this compare before the buf is allocated, so the materialize
    // step below runs only for digest-matching (caller-legitimate) archives.
    // Version shape + key-count BEFORE the digest (cross-vendor round 12:
    // malformed metadata should not force maximum-sized hashing — the
    // reference validates both before chunk processing, :91).
    if obj.version.is_empty()
        || obj.version.len() as u64 > bounds.object_version_bytes()
        || expected.object_version.is_empty()
        || expected.object_version.len() as u64 > bounds.object_version_bytes()
    {
        return Err(Invalid);
    }
    // (the key-count gate ran before the digest — round 12.)

    let mut hasher = Sha256::new();
    for c in chunks {
        hasher.update(c);
    }
    let mut computed = [0u8; 32];
    computed.copy_from_slice(&hasher.finalize());
    if !constant_time_eq(&computed, &expected.digest) {
        return Err(Invalid);
    }

    // Out-of-band object-store version exact equality (after the digest, before
    // the byte stream is materialized).
    // (the version-shape gate ran before the digest — round 12.)
    if obj.version != expected.object_version {
        return Err(Invalid);
    }

    // Materialize the byte stream for the magic check + incremental frame scan.
    let mut buf = Vec::with_capacity(total as usize);
    for c in chunks {
        buf.extend_from_slice(c);
    }

    // Exact magic prefix.
    if &buf[..ARCHIVE_MAGIC.len()] != ARCHIVE_MAGIC {
        return Err(Invalid);
    }

    // Incremental frame scan.
    let mut cursor = ARCHIVE_MAGIC.len();
    let header_frame = read_frame(&buf, &mut cursor)?;
    let start_anchor_compact = read_frame_bounded(&buf, &mut cursor, bounds.anchor_bytes())?;
    let header = decode_archive_header(header_frame, &bounds)?;

    // Header's closed claims == caller's chain boundaries + transition count.
    if header.chain_id != expected.chain.chain_id
        || header.first_sequence != expected.chain.first_sequence
        || header.last_sequence != expected.chain.last_sequence
        || header.row_count != expected.chain.row_count
        || header.previous_hash != expected.chain.previous_hash
        || header.last_hash != expected.chain.head_hash
        || header.transition_count != expected.transitions.len() as i64
    {
        return Err(Invalid);
    }

    // Read transition_count + row_count frames (counts come from the header).
    let mut transition_compacts: Vec<&[u8]> = Vec::with_capacity(header.transition_count as usize);
    for _ in 0..header.transition_count {
        transition_compacts.push(read_frame_bounded(
            &buf,
            &mut cursor,
            bounds.anchor_bytes(),
        )?);
    }
    let mut rows: Vec<Vec<u8>> = Vec::with_capacity(header.row_count as usize);
    for _ in 0..header.row_count {
        rows.push(read_frame_bounded(&buf, &mut cursor, bounds.chain_row_bytes())?.to_vec());
    }
    let end_anchor_compact = read_frame_bounded(&buf, &mut cursor, bounds.anchor_bytes())?;
    // Exact EOF — nothing follows the end-anchor frame.
    if cursor != buf.len() {
        return Err(Invalid);
    }

    // F1 surplus-key invariant: keys.len() == transitions.len() + 1. WITHOUT
    // this check a 0-transition archive carrying two distinct keys (start
    // signed by keys[0], end by keys[1]) would be accepted — both anchors
    // verify individually, but no transition authenticates the rollover.
    if keys.keys.len() as i64 != header.transition_count + 1 {
        return Err(Invalid);
    }

    // Authenticate the start anchor with keys[0]; bind it to the chain start.
    let start_facts =
        verify_historical_anchor(start_anchor_compact, &keys.keys[0], &expected.start_anchor)?;
    if start_facts.chain_hash != expected.chain.previous_hash {
        return Err(Invalid);
    }
    let expected_start_seq = expected
        .chain
        .first_sequence
        .checked_sub(1)
        .ok_or(Invalid)?;
    if start_facts.sequence != expected_start_seq {
        return Err(Invalid);
    }

    // Authenticate each transition positionally: keys[i] signs, keys[i+1] next.
    let mut effective_times: Vec<i64> = Vec::with_capacity(transition_compacts.len());
    for (i, tcompact) in transition_compacts.iter().enumerate() {
        let exp_t = expected.transitions.get(i).ok_or(Invalid)?;
        let t_facts = verify_key_transition(tcompact, &keys.keys[i], &keys.keys[i + 1], exp_t)?;
        effective_times.push(t_facts.effective_at);
    }

    // Authenticate the end anchor with the last key; bind it to the chain head.
    let end_facts = verify_historical_anchor(
        end_anchor_compact,
        &keys.keys[header.transition_count as usize],
        &expected.end_anchor,
    )?;
    if end_facts.chain_hash != expected.chain.head_hash {
        return Err(Invalid);
    }
    if end_facts.sequence != expected.chain.last_sequence {
        return Err(Invalid);
    }

    // Chronology + rollover (strictly increasing effective times, no fingerprint
    // cycle, anchor ordering).
    check_export_chronology(
        start_facts.anchored_at,
        end_facts.anchored_at,
        &effective_times,
        &keys.keys,
    )?;

    // Re-check every row (canonical re-encode, predecessor links, genesis,
    // sequence, count, head — reused from Façade B).
    let chain_input = ChainInput { rows };
    check_chain(
        &chain_input,
        &ExpectedChain {
            bounds: Some(bounds),
            ..expected.chain.clone()
        },
    )?;

    Ok(AnchoredExportFacts {
        chain_id: header.chain_id,
        first_sequence: header.first_sequence,
        last_sequence: header.last_sequence,
        row_count: header.row_count,
        transition_count: header.transition_count,
        previous_hash: header.previous_hash,
        head_hash: header.last_hash,
        digest: computed,
        object_version: expected.object_version.clone(),
        trust: NotEvaluated,
        authorization: NotEvaluated,
    })
}

// ----------------------------------------------------------------------------
// Façade D helpers — anchor/transition decode, archive framing, chronology
// ----------------------------------------------------------------------------

/// The fully-decoded boundary-anchor compact (segments borrowed from input).
struct DecodedAnchor<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    key_id: String,
    payload: AnchorPayload,
}

/// Decoded closed anchor payload fields.
struct AnchorPayload {
    anchor_id: String,
    anchored_at: i64,
    chain_hash: [u8; 32],
    chain_id: String,
    key_fingerprint: [u8; 32],
    sequence: i64,
}

/// Splits, bounds, decodes, and structurally validates a boundary-anchor
/// compact. Shared by [`verify_historical_anchor`], [`assemble_compact`], and
/// the encode path's start-anchor binding check. The decoded signature segment
/// MUST be exactly 64 bytes (REQ1-BOUNDS-fixed-widths, mirroring
/// boundary_anchor_codec.ex:88), and the protected/payload segments must equal
/// their exact JCS re-encoding (canonical form, boundary_anchor_codec.ex:95-96
/// + 118-119) — enforced inside the validators below.
fn decode_anchor_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedAnchor<'a>> {
    // The whole-input compact_bytes ceiling FIRST (the reference's scan gates it
    // before the codec's anchor_bytes clause — compact_jws.ex:16-18; cross-vendor
    // round 4: a tightened compact_bytes below anchor_bytes was bypassed).
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    if compact.len() as u64 > bounds.anchor_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ1-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (boundary_anchor_codec.ex:88).
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid);
    }
    let header = json_decode(&header_bytes, bounds)?;
    let payload_json = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_anchor_header(&header, &header_bytes, bounds)?;
    let payload = validate_anchor_payload(&payload_json, &payload_bytes, bounds)?;
    Ok(DecodedAnchor {
        protected_seg,
        payload_seg,
        signature_seg,
        key_id,
        payload,
    })
}

/// Validates the anchor protected header is exactly
/// `{alg:"EdDSA", typ:"ba+chain-anchor", kid:<valid kid>}`. Returns the kid.
/// Canonical form: the protected segment bytes must equal the exact JCS
/// re-encoding of the header (boundary_anchor_codec.ex:95-96).
fn validate_anchor_header(
    header: &JsonValue,
    header_bytes: &[u8],
    bounds: &Bounds,
) -> Result<String> {
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
            _ => return Err(Invalid), // closed set
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_EDDSA => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_CHAIN_ANCHOR => {}
        _ => return Err(Invalid),
    }
    let kid_str = match kid {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_kid(kid_str, bounds)?;
    if jcs_encode(header, bounds)?.as_slice() != header_bytes {
        return Err(Invalid); // canonical form
    }
    Ok(kid_str.clone())
}

/// Validates the anchor payload against the closed set (member names derived
/// first-hand from the corpus anchor `payload_segment`): exactly
/// `{anchor_id, anchored_at, chain_hash, chain_id, key_fingerprint, sequence,
/// v:1}`, no extra members. `chain_hash`/`key_fingerprint` are canonical
/// base64url of exactly 32 bytes. Canonical form: the payload segment bytes
/// must equal the exact JCS re-encoding of the payload
/// (boundary_anchor_codec.ex:118-119).
fn validate_anchor_payload(
    payload: &JsonValue,
    payload_bytes: &[u8],
    bounds: &Bounds,
) -> Result<AnchorPayload> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut anchor_id = None;
    let mut anchored_at = None;
    let mut chain_hash = None;
    let mut chain_id = None;
    let mut key_fingerprint = None;
    let mut sequence = None;
    let mut version = None;
    for (name, val) in members {
        match name.as_str() {
            "anchor_id" => anchor_id = Some(val),
            "anchored_at" => anchored_at = Some(val),
            "chain_hash" => chain_hash = Some(val),
            "chain_id" => chain_id = Some(val),
            "key_fingerprint" => key_fingerprint = Some(val),
            "sequence" => sequence = Some(val),
            "v" => version = Some(val),
            _ => return Err(Invalid), // closed set
        }
    }
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let anchor_id = take_string_or_uri(anchor_id, bounds)?;
    let chain_id = take_string_or_uri(chain_id, bounds)?;
    let anchored_at = take_integral_date(anchored_at)?;
    let sequence = take_integral_date(sequence)?;
    if sequence < 0 {
        return Err(Invalid);
    }
    let chain_hash = take_digest_b64u(chain_hash, bounds)?;
    let key_fingerprint = take_digest_b64u(key_fingerprint, bounds)?;
    if jcs_encode(payload, bounds)?.as_slice() != payload_bytes {
        return Err(Invalid); // canonical form
    }
    Ok(AnchorPayload {
        anchor_id,
        anchored_at,
        chain_hash,
        chain_id,
        key_fingerprint,
        sequence,
    })
}

/// The fully-decoded key-transition compact (segments borrowed from input).
struct DecodedTransition<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    key_id: String,
    payload: TransitionPayload,
}

/// Decoded closed transition payload fields.
struct TransitionPayload {
    chain_id: String,
    effective_at: i64,
    from_fingerprint: [u8; 32],
    to_fingerprint: [u8; 32],
    to_key_id: String,
    transition_id: String,
}

/// Splits, bounds, decodes, and structurally validates a key-transition compact.
fn decode_transition_parts<'a>(
    compact: &'a [u8],
    bounds: &Bounds,
) -> Result<DecodedTransition<'a>> {
    // The whole-input compact_bytes ceiling FIRST (the reference's scan gates it
    // before the codec's anchor_bytes clause — compact_jws.ex:16-18; cross-vendor
    // round 4: a tightened compact_bytes below anchor_bytes was bypassed).
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    if compact.len() as u64 > bounds.anchor_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ1-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (key_transition_codec.ex:120). Publicly reachable through
    // encode_anchored_export, which parses caller-supplied transitions here —
    // battery leg `encode_transition_signature_width_rejected` drives a
    // 32-byte signature to exactly this gate. assemble_compact stays
    // [u8; 64]-type-locked and verify_key_transition's decode_signature64
    // independently enforces the width on the verify path.
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid);
    }
    let header = json_decode(&header_bytes, bounds)?;
    let payload_json = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_transition_header(&header, &header_bytes, bounds)?;
    let payload = validate_transition_payload(&payload_json, &payload_bytes, bounds)?;
    Ok(DecodedTransition {
        protected_seg,
        payload_seg,
        signature_seg,
        key_id,
        payload,
    })
}

/// Validates the transition protected header is exactly
/// `{alg:"EdDSA", typ:"ba+key-transition", kid:<valid kid>}`. Returns the kid.
/// Canonical form: the protected segment bytes must equal the exact JCS
/// re-encoding of the header (key_transition_codec.ex:127-128).
fn validate_transition_header(
    header: &JsonValue,
    header_bytes: &[u8],
    bounds: &Bounds,
) -> Result<String> {
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
            _ => return Err(Invalid), // closed set
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_EDDSA => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_KEY_TRANSITION => {}
        _ => return Err(Invalid),
    }
    let kid_str = match kid {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_kid(kid_str, bounds)?;
    if jcs_encode(header, bounds)?.as_slice() != header_bytes {
        return Err(Invalid); // canonical form
    }
    Ok(kid_str.clone())
}

/// Validates the transition payload against the closed set (member names
/// derived first-hand from the corpus transition `payload_segment`): exactly
/// `{chain_id, effective_at, from_key_fingerprint, to_key_fingerprint,
/// to_key_id, transition_id, v:1}`. Canonical form: the payload segment bytes
/// must equal the exact JCS re-encoding of the payload
/// (key_transition_codec.ex:151-152).
fn validate_transition_payload(
    payload: &JsonValue,
    payload_bytes: &[u8],
    bounds: &Bounds,
) -> Result<TransitionPayload> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut chain_id = None;
    let mut effective_at = None;
    let mut from_key_fingerprint = None;
    let mut to_key_fingerprint = None;
    let mut to_key_id = None;
    let mut transition_id = None;
    let mut version = None;
    for (name, val) in members {
        match name.as_str() {
            "chain_id" => chain_id = Some(val),
            "effective_at" => effective_at = Some(val),
            "from_key_fingerprint" => from_key_fingerprint = Some(val),
            "to_key_fingerprint" => to_key_fingerprint = Some(val),
            "to_key_id" => to_key_id = Some(val),
            "transition_id" => transition_id = Some(val),
            "v" => version = Some(val),
            _ => return Err(Invalid), // closed set
        }
    }
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let chain_id = take_string_or_uri(chain_id, bounds)?;
    let transition_id = take_string_or_uri(transition_id, bounds)?;
    let to_key_id = match to_key_id {
        Some(JsonValue::String(s)) => {
            validate_kid(s, bounds)?;
            s.clone()
        }
        _ => return Err(Invalid),
    };
    let effective_at = take_integral_date(effective_at)?;
    let from_fingerprint = take_digest_b64u(from_key_fingerprint, bounds)?;
    let to_fingerprint = take_digest_b64u(to_key_fingerprint, bounds)?;
    if jcs_encode(payload, bounds)?.as_slice() != payload_bytes {
        return Err(Invalid); // canonical form
    }
    Ok(TransitionPayload {
        chain_id,
        effective_at,
        from_fingerprint,
        to_fingerprint,
        to_key_id,
        transition_id,
    })
}

/// The closed anchored-export archive header.
struct ArchiveHeader {
    chain_id: String,
    first_sequence: i64,
    last_sequence: i64,
    row_count: i64,
    transition_count: i64,
    previous_hash: [u8; 32],
    last_hash: [u8; 32],
}

/// Decodes + structurally validates the closed archive header (member names
/// derived first-hand from the corpus header frame): exactly
/// `{chain_id, first_sequence, last_hash, last_sequence, previous_hash,
/// row_count, transition_count, v:1}`. Enforces the canonical re-encode check
/// (the header bytes MUST be the exact JCS encoding) and bounds the counts.
fn decode_archive_header(bytes: &[u8], bounds: &Bounds) -> Result<ArchiveHeader> {
    if bytes.len() as u64 > bounds.archive_header_bytes() {
        return Err(Invalid);
    }
    let value = json_decode(bytes, bounds)?;
    let members = match &value {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut chain_id = None;
    let mut first_sequence = None;
    let mut last_hash = None;
    let mut last_sequence = None;
    let mut previous_hash = None;
    let mut row_count = None;
    let mut transition_count = None;
    let mut version = None;
    for (name, val) in members {
        match name.as_str() {
            "chain_id" => chain_id = Some(val),
            "first_sequence" => first_sequence = Some(val),
            "last_hash" => last_hash = Some(val),
            "last_sequence" => last_sequence = Some(val),
            "previous_hash" => previous_hash = Some(val),
            "row_count" => row_count = Some(val),
            "transition_count" => transition_count = Some(val),
            "v" => version = Some(val),
            _ => return Err(Invalid), // closed set
        }
    }
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let chain_id = take_string_or_uri(chain_id, bounds)?;
    let first_sequence = take_integral_date(first_sequence)?;
    let last_sequence = take_integral_date(last_sequence)?;
    let row_count = take_integral_date(row_count)?;
    let transition_count = take_integral_date(transition_count)?;
    if row_count < 0 || transition_count < 0 {
        return Err(Invalid);
    }
    if first_sequence < 1 || last_sequence < first_sequence {
        return Err(Invalid);
    }
    if row_count as u64 > bounds.chain_rows() {
        return Err(Invalid);
    }
    if transition_count as u64 > bounds.key_transitions() {
        return Err(Invalid);
    }
    let previous_hash = take_digest_b64u(previous_hash, bounds)?;
    let last_hash = take_digest_b64u(last_hash, bounds)?;
    // Canonical re-encode check (the header is the canonical_header).
    let reencoded = jcs_encode(&value, bounds)?;
    if reencoded.as_slice() != bytes {
        return Err(Invalid);
    }
    Ok(ArchiveHeader {
        chain_id,
        first_sequence,
        last_sequence,
        row_count,
        transition_count,
        previous_hash,
        last_hash,
    })
}

/// Appends one archive frame `UINT32_BE(len) || bytes` (caller guarantees
/// non-empty content; the framing of empty content is rejected at the call
/// sites). `len` fits in `u32` for every protocol element (anchor/transition ≤
/// 8,192 bytes; row ≤ 4,096 bytes; header ≤ 8,192 bytes).
fn frame_into(content: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(content.len() as u32).to_be_bytes());
    out.extend_from_slice(content);
}

/// Reads one archive frame at `*cursor`: a UINT32_BE nonzero length prefix
/// followed by exactly that many bytes. Returns a borrowed slice of the frame
/// payload and advances `*cursor` past it.
/// read_frame with a per-frame byte ceiling — the row/anchor reads cap each
/// frame at its role's bound (chain_row_bytes / anchor_bytes) so a
/// digest-matching malformed archive cannot materialize a ~full-archive frame
/// before check_chain's per-row gate (cross-vendor round 11).
fn read_frame_bounded<'a>(buf: &'a [u8], cursor: &mut usize, ceiling: u64) -> Result<&'a [u8]> {
    let frame = read_frame(buf, cursor)?;
    if frame.len() as u64 > ceiling {
        return Err(Invalid);
    }
    Ok(frame)
}

fn read_frame<'a>(buf: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let prefix_end = cursor.checked_add(4).ok_or(Invalid)?;
    if prefix_end > buf.len() {
        return Err(Invalid);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[*cursor..prefix_end]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    *cursor = prefix_end;
    if len == 0 {
        return Err(Invalid); // REQ: nonzero_length
    }
    let end = cursor.checked_add(len).ok_or(Invalid)?;
    if end > buf.len() {
        return Err(Invalid);
    }
    let frame = &buf[*cursor..end];
    *cursor = end;
    Ok(frame)
}

/// Decodes a compact signature segment into a fixed 64-byte array.
fn decode_signature64(signature_seg: &[u8], out: &mut [u8; 64]) -> Result<()> {
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid); // REQ1-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    out.copy_from_slice(&sig_raw);
    Ok(())
}

/// Half-open interval membership: `valid_from <= t < upper` (`Unbounded` is the
/// only open upper interval).
fn in_interval(t: i64, valid_from: i64, upper: &ValidityUpperBound) -> bool {
    if t < valid_from {
        return false;
    }
    match upper {
        ValidityUpperBound::Bounded(v) => t < *v,
        ValidityUpperBound::Unbounded => true,
    }
}

/// Chronology + rollover checks for an anchored export (ADR 0004 §49-55):
/// fingerprints cannot cycle (all key fingerprints distinct); transition
/// effective times strictly increase; the start anchor precedes every
/// transition; the end anchor is at or after the last transition. Equal
/// start/end times are permitted only for the no-transition same-key case
/// (implied: no transitions + `start <= end`).
fn check_export_chronology(
    start_at: i64,
    end_at: i64,
    effective_times: &[i64],
    keys: &[HistoricalPublicKey],
) -> Result<()> {
    // Fingerprints cannot cycle: no key fingerprint may recur.
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(keys.len());
    for k in keys {
        let fp = public_key_thumbprint_raw(&k.public_key);
        if seen.iter().any(|s| *s == fp) {
            return Err(Invalid);
        }
        seen.push(fp);
    }

    if effective_times.is_empty() {
        // No-transition same-key case: start <= end.
        if start_at > end_at {
            return Err(Invalid);
        }
    } else {
        // Strictly increasing effective times.
        for i in 1..effective_times.len() {
            if effective_times[i - 1] >= effective_times[i] {
                return Err(Invalid);
            }
        }
        // Start anchor precedes every transition.
        if start_at >= effective_times[0] {
            return Err(Invalid);
        }
        // End anchor at or after the last transition.
        if end_at < effective_times[effective_times.len() - 1] {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Constant-time byte equality for two equal-width digests. The length check
/// leaks length only (both sides are fixed 32-byte SHA-256 digests, so the
/// length is a protocol constant, not secret); the byte loop runs in constant
/// time for equal-length inputs with no early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
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

/// The fully-decoded grant compact: the three raw segments (borrowed from the
/// input compact), the validated `kid`, the validated [`GrantPayload`], and the
/// parsed payload [`JsonValue`] (retained so [`check_envelope`] can extract the
/// operations array the redacted [`GrantFacts`] does not carry).
struct DecodedGrant<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    key_id: String,
    payload: GrantPayload,
    payload_json: JsonValue,
}

/// Shared grant decode used by [`decode_grant`] (signature-not-verified view)
/// and [`verify_grant`] (which adds the signature, identity, and time checks).
/// Splits, bounds, decodes, and structurally validates the protected header +
/// payload claims. The decoded signature segment MUST be exactly 64 bytes
/// (REQ1-BOUNDS-fixed-widths, mirroring runtime.ex:237 parse_grant).
fn decode_grant_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedGrant<'a>> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ1-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (runtime.ex:237).
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid);
    }
    let header = json_decode(&header_bytes, bounds)?;
    let payload_json = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_grant_header(&header, bounds)?;
    let payload = validate_grant_payload(&payload_json, bounds)?;
    Ok(DecodedGrant {
        protected_seg,
        payload_seg,
        signature_seg,
        key_id,
        payload,
        payload_json,
    })
}

/// The fully-decoded proof compact: the three raw segments (borrowed), the
/// decoded 32-byte holder public key, and the validated [`ProofPayload`].
struct DecodedProof<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    holder_public_key: [u8; 32],
    payload: ProofPayload,
}

/// Shared proof decode used by [`decode_proof`] and [`check_envelope`]. Splits,
/// bounds, decodes, and structurally validates the proof header (returning the
/// holder public key) and payload claims. The decoded signature segment MUST be
/// exactly 64 bytes (REQ1-BOUNDS-fixed-widths, mirroring runtime.ex:259
/// parse_proof).
fn decode_proof_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedProof<'a>> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ1-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (runtime.ex:259).
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid);
    }
    let header = json_decode(&header_bytes, bounds)?;
    let payload_json = json_decode(&payload_bytes, bounds)?;
    let holder_public_key = validate_proof_header(&header, bounds)?;
    let payload = validate_proof_payload(&payload_json, bounds)?;
    Ok(DecodedProof {
        protected_seg,
        payload_seg,
        signature_seg,
        holder_public_key,
        payload,
    })
}

/// Assembles the RFC 7515 two-segment signing input
/// (`protected_segment || "." || payload_segment`) — the exact bytes the
/// Ed25519 signature covers (`REQ1-SIGNING-exact-input`).
fn signing_input_bytes(protected_seg: &[u8], payload_seg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected_seg.len() + 1 + payload_seg.len());
    out.extend_from_slice(protected_seg);
    out.push(b'.');
    out.extend_from_slice(payload_seg);
    out
}

/// Audience match: `expected` MUST be one of the grant's decoded audiences.
/// `take_audiences` normalizes a single-string `aud` to a one-element Vec, so
/// this handles both the string and array `aud` shapes uniformly.
fn audience_matches(grant_audiences: &[String], expected: &str) -> bool {
    grant_audiences.iter().any(|a| a == expected)
}

/// Extracts the grant `operations` array as `(name, selectors)` pairs for
/// selector evaluation. The payload is already structurally validated by
/// [`validate_operations`]; this re-walks the array to surface each operation's
/// selector objects (cloned, so they outlive the borrowed payload).
fn extract_operations(payload: &JsonValue) -> Result<Vec<(String, Vec<JsonValue>)>> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let ops_value = members
        .iter()
        .find(|(k, _)| k == "operations")
        .map(|(_, v)| v)
        .ok_or(Invalid)?;
    let ops = match ops_value {
        JsonValue::Array(a) => a,
        _ => return Err(Invalid),
    };
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        let omembers = match op {
            JsonValue::Object(m) => m,
            _ => return Err(Invalid),
        };
        let name = omembers
            .iter()
            .find(|(k, _)| k == "name")
            .and_then(|(_, v)| match v {
                JsonValue::String(s) => Some(s),
                _ => None,
            })
            .ok_or(Invalid)?;
        let selectors = omembers
            .iter()
            .find(|(k, _)| k == "selectors")
            .and_then(|(_, v)| match v {
                JsonValue::Array(a) => Some(a),
                _ => None,
            })
            .ok_or(Invalid)?;
        out.push((name.clone(), selectors.clone()));
    }
    Ok(out)
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
/// Per RFC 7519 + the reference `string_or_uri.ex`: a colon-free value is a
/// PLAIN string (any valid UTF-8 is accepted); a colon-bearing value is a URI
/// whose scheme is valid, every byte is alnum / URI-punctuation / a well-formed
/// `%HH` escape, and (for a `://` authority) the port is all-digit. Rejects an
/// empty value, a bad scheme, a non-URI byte (e.g. `{`), a malformed `%HH`, or a
/// non-numeric authority port. `None` (claim absent) → `Invalid`. (A Rust `&str`
/// is always valid UTF-8, so `String.valid?` is automatic.)
fn take_string_or_uri(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_identifier(s, bounds)?;
    Ok(s.clone())
}

/// Validates a StringOrURI / identifier scalar — a faithful port of the
/// reference `string_or_uri.ex`. A colon-free value is a PLAIN string (any valid
/// UTF-8 — `String.valid?`, automatic for a Rust `&str`); a colon-bearing value
/// is a URI whose scheme is valid and whose every byte is alphanumeric, a URI
/// punctuation byte (`-._~:/?#[]@!$&'()*+,;=`), or part of a well-formed `%HH`
/// escape. There is NO global control/non-ASCII restriction on the plain branch
/// (a prior byte loop over-rejected UTF-8 like "café" that the reference
/// accepts); the URI branch's `uri_bytes` is what rejects non-URI bytes like `{`
/// (`urn:{a}`). (The reference additionally requires `URI.new/1` to parse
/// structurally with a scheme; for identifier-shaped inputs that is subsumed by
/// `validate_scheme` + `validate_uri_bytes`, the load-bearing checks.)
fn validate_identifier(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.identifier_bytes() {
        return Err(Invalid);
    }
    match s.find(':') {
        None => Ok(()), // plain string — any valid UTF-8 (a Rust &str guarantees it)
        Some(colon) => {
            validate_scheme(&s[..colon])?;
            validate_uri_bytes(s.as_bytes())?;
            // Structural authority/port check (the reference delegates to URI.new;
            // the corpus case `http://a:b` exercises it — a `:` after the host,
            // outside an IP-literal bracket, MUST introduce an all-digit port).
            // uri_bytes already permits `:`/`/`, so this is the structural gate
            // that rejects malformed authorities.
            validate_authority_port(s)?;
            Ok(())
        }
    }
}

/// Reference `URI.new` authority/port structure: when the URI has an authority
/// (`://authority`), a `:` in the authority outside an IP-literal bracket (`[…]`)
/// MUST introduce an all-digit port. Rejects e.g. `http://a:b` (port "b"). The
/// reference enforces this via `URI.new`; this is the faithful structural gate.
fn validate_authority_port(value: &str) -> Result<()> {
    let after_scheme_host = match value.find("://") {
        Some(i) => &value[i + 3..],
        None => return Ok(()), // no authority (e.g. `urn:…`) — nothing to port-check
    };
    let auth_end = after_scheme_host
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme_host.len());
    let authority = &after_scheme_host[..auth_end];
    if authority.starts_with('[') {
        return Ok(()); // IP literal — colons inside […] are not a port.
    }
    if let Some(c) = authority.rfind(':') {
        let port = &authority[c + 1..];
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Reference `string_or_uri.ex` `uri_bytes?/1`: every byte is alphanumeric, one
/// of the URI punctuation bytes `-._~:/?#[]@!$&'()*+,;=`, or part of a
/// well-formed `%HH` percent-escape. Rejects `{`, whitespace, control, non-ASCII,
/// and a bare `%` / `%G` (`urn:{a}`, `urn:trunc%`).
fn validate_uri_bytes(bytes: &[u8]) -> Result<()> {
    const URI_PUNCT: &[u8] = b"-._~:/?#[]@!$&'()*+,;=";
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || URI_PUNCT.contains(&b) {
            i += 1;
        } else if b == b'%' && i + 2 < bytes.len() && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            i += 3;
        } else {
            return Err(Invalid);
        }
    }
    Ok(())
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (0x41..=0x46).contains(&b) || (0x61..=0x66).contains(&b)
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
            let mut seen = std::collections::BTreeSet::new();
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
    let mut seen_names = std::collections::BTreeSet::new();
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
        // Each selector MUST carry a known `kind` (REQ1-SELECTOR-closed-set).
        // This is the structural check exercised at grant-verify time (corpus
        // `verify-grant-invalid-selector-operation-selector-content`: a
        // `kind:"bogus"` selector is rejected here, before the signature check).
        // Path/value shape and the equals/one_of exact-member sets are enforced
        // at envelope time by selector::evaluate; JSON-decoder bounds catch
        // oversized selector values and lone-surrogate path bytes (corpus
        // `verify-grant-invalid-selector-path-lone-surrogate`,
        // `-selector-value-object-members`, `-selector-value-magnitude`).
        for sel in sel_items {
            validate_selector_kind(sel)?;
        }
    }
    Ok(())
}

/// Structural selector check at decode time: the selector MUST be a JSON object
/// whose `kind` member is exactly one of the closed set {all, equals, one_of}
/// (`REQ1-SELECTOR-closed-set`). Catches an unknown `kind` (corpus
/// `kind:"bogus"`) before signature verification. Per-kind member/path/value
/// validation runs in `selector::evaluate` at envelope time (which needs the
/// cast arguments a grant-verify does not have).
fn validate_selector_kind(selector: &JsonValue) -> Result<()> {
    let members = match selector {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut kind = None;
    for (k, v) in members {
        if k == "kind" {
            kind = Some(v);
        }
    }
    match kind {
        Some(JsonValue::String(s)) if matches!(s.as_str(), "all" | "equals" | "one_of") => Ok(()),
        _ => Err(Invalid),
    }
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

    /// assemble_compact validates the composed compact parses as its kind
    /// (reference validate_assembled_compact, runtime.ex:151). Segments that are
    /// canonical base64url but decode to non-grant content (here "a"."b") are
    /// rejected, not composed into a malformed credential. RED-capable: routing
    /// the public fn straight to compose_compact (dropping the per-kind parse)
    /// makes this accept.
    #[test]
    fn assemble_compact_rejects_non_grant_content() {
        let sig = [0xaa; 64];
        let bad = crate::types::SigningInput {
            kind: crate::types::SigningKind::Grant,
            protected_segment: b"YQ".to_vec(), // decodes to "a" — not a grant header
            payload_segment: b"Yg".to_vec(),   // decodes to "b"
        };
        assert_eq!(crate::assemble_compact(&bad, &sig), Err(Invalid));
    }

    // ==========================================================================
    // Façade B — consumption entry + chain verification (Task 11)
    // ==========================================================================

    /// Encodes a canonical row directly via jcs_encode — a test helper for
    /// building rows with arbitrary previous/sequence (including rows the
    /// encoder itself would reject, e.g. a forged genesis row).
    fn encode_row_canonical(
        chain_id: &str,
        commitment: &[u8; 32],
        previous: &[u8; 32],
        sequence: i64,
    ) -> Vec<u8> {
        let row = JsonValue::Object(vec![
            (
                "chain_id".to_string(),
                JsonValue::String(chain_id.to_string()),
            ),
            (
                "commitment".to_string(),
                JsonValue::String(String::from_utf8(crate::base64url_encode(commitment)).unwrap()),
            ),
            (
                "previous".to_string(),
                JsonValue::String(String::from_utf8(crate::base64url_encode(previous)).unwrap()),
            ),
            ("sequence".to_string(), JsonValue::Int(sequence)),
            ("v".to_string(), JsonValue::Int(1)),
        ]);
        jcs_encode(&row, &max()).expect("encodes")
    }

    // --- Encoder row-domain hash: the "BAP1-CHAIN\0" prefix is load-bearing ---
    // RED if the prefix omitted the final NUL byte (or used the wrong prefix):
    // the corpus-pinned hash would mismatch.
    #[test]
    fn red_encoder_hash_prefix_nul_is_load_bearing() {
        let entry = ConsumptionEntry {
            chain_id: "urn:example:chain".to_string(),
            commitment: [1u8; 32],
            previous_hash: [0u8; 32],
            sequence: 1,
        };
        let (canonical, hash) = encode_consumption_entry(&entry, &max()).expect("encodes");
        // The produced hash equals SHA-256("BAP1-CHAIN\0" || canonical).
        let mut h = Sha256::new();
        h.update(CHAIN_DIGEST_PREFIX);
        h.update(&canonical);
        let mut want = [0u8; 32];
        want.copy_from_slice(&h.finalize());
        assert_eq!(
            hash, want,
            "hash MUST be SHA-256(\"BAP1-CHAIN\\0\" || canonical)"
        );
        // Dropping the NUL byte from the prefix MUST change the digest — the
        // zero byte is load-bearing (this is the red state).
        let mut h2 = Sha256::new();
        h2.update(b"BAP1-CHAIN"); // NO NUL byte
        h2.update(&canonical);
        let mut wrong = [0u8; 32];
        wrong.copy_from_slice(&h2.finalize());
        assert_ne!(
            hash, wrong,
            "dropping the NUL byte MUST change the row-domain hash"
        );
        // The prefix is exactly 11 bytes (10 ASCII "BAP1-CHAIN" + 1 NUL).
        assert_eq!(CHAIN_DIGEST_PREFIX, b"BAP1-CHAIN\0");
        assert_eq!(CHAIN_DIGEST_PREFIX.len(), 11);
        assert_eq!(CHAIN_DIGEST_PREFIX.last(), Some(&0u8));
    }

    // --- Encoder genesis binding ---
    // RED if the encoder accepted sequence 0 or a sequence-1 nonzero previous.
    #[test]
    fn red_encoder_rejects_zero_sequence_and_forged_genesis() {
        let zero_seq = ConsumptionEntry {
            chain_id: "urn:example:chain".to_string(),
            commitment: [1u8; 32],
            previous_hash: [0u8; 32],
            sequence: 0,
        };
        assert_eq!(encode_consumption_entry(&zero_seq, &max()), Err(Invalid));

        let forged_genesis = ConsumptionEntry {
            chain_id: "urn:example:chain".to_string(),
            commitment: [1u8; 32],
            previous_hash: [9u8; 32], // nonzero previous at sequence 1
            sequence: 1,
        };
        assert_eq!(
            encode_consumption_entry(&forged_genesis, &max()),
            Err(Invalid)
        );
    }

    #[test]
    fn red_encode_chain_id_string_or_uri() {
        // chain_id is a StringOrURI identifier, faithfully ported from
        // string_or_uri.ex (consumption_chain.ex:169-172 valid_identifier?). A
        // colon-free value is a PLAIN string — any valid UTF-8 (incl. "café" and
        // a newline) is accepted; a colon-bearing value is a URI whose scheme is
        // valid and whose every byte is alnum / URI-punctuation / %HH. The
        // URI-branch rejections are RED-capable (removing validate_identifier /
        // validate_uri_bytes makes them accept).
        let mk = |chain_id: &str| ConsumptionEntry {
            chain_id: chain_id.to_string(),
            commitment: [1u8; 32],
            previous_hash: [0u8; 32],
            sequence: 1,
        };
        // Plain branch: any UTF-8 (length-bounded) is accepted.
        assert!(encode_consumption_entry(&mk("café"), &max()).is_ok());
        assert!(encode_consumption_entry(&mk("chain\nid"), &max()).is_ok());
        // Empty rejected (length).
        assert_eq!(encode_consumption_entry(&mk(""), &max()), Err(Invalid));
        // URI branch: bad scheme / byte / %HH / authority-port rejected.
        assert_eq!(
            encode_consumption_entry(&mk("1bad:u"), &max()),
            Err(Invalid)
        );
        assert_eq!(
            encode_consumption_entry(&mk("urn:{a}"), &max()),
            Err(Invalid)
        );
        assert_eq!(
            encode_consumption_entry(&mk("http://a:b"), &max()),
            Err(Invalid)
        );
        assert_eq!(
            encode_consumption_entry(&mk("urn:exa%GGmple"), &max()),
            Err(Invalid)
        );
        assert_eq!(
            encode_consumption_entry(&mk("urn:trunc%"), &max()),
            Err(Invalid)
        );
        // Valid URIs (opaque-suffix + well-formed %HH) accepted.
        assert!(encode_consumption_entry(&mk("urn:example:chain"), &max()).is_ok());
        assert!(encode_consumption_entry(&mk("urn:exa%41mple"), &max()).is_ok());
    }

    /// scan_compact faithfully ports the reference `CompactJws.scan`: it gates
    /// hashing on shape + size, NOT base64url canonicity. A non-canonical
    /// segment (e.g. `a!a`) passes the scan (the reference accepts it for ath);
    /// an over-canonical check (the prior parse_compact) would wrongly reject it.
    #[test]
    fn scan_compact_accepts_non_canonical_segment() {
        // `a!a.YQ.YQ` — three non-empty dot-free size-bounded segments; `a!a` is
        // NOT canonical base64url but the reference scan does not require it.
        assert!(scan_compact(b"a!a.YQ.YQ", &max()).is_ok());
        // Shape/size rejections still fire.
        assert_eq!(scan_compact(b"", &max()), Err(Invalid)); // no dots
        assert_eq!(scan_compact(b"a.b", &max()), Err(Invalid)); // one dot
        assert_eq!(scan_compact(b".b.c", &max()), Err(Invalid)); // empty protected
        assert_eq!(scan_compact(b"a.b.c.d", &max()), Err(Invalid)); // signature has '.'
    }

    // --- Chain canonical re-encode check ---
    // RED if the canonical re-encode check were removed: a row whose received
    // bytes are valid JSON but NOT canonical (here, a space after `{`) would be
    // accepted, silently certifying a non-canonical hash preimage.
    #[test]
    fn red_check_chain_canonical_reencode() {
        let (row, hash) = encode_consumption_entry(
            &ConsumptionEntry {
                chain_id: "urn:example:chain".to_string(),
                commitment: [1u8; 32],
                previous_hash: [0u8; 32],
                sequence: 1,
            },
            &max(),
        )
        .expect("encodes");
        // Inject a space after `{`: valid JSON (json_decode skips whitespace),
        // but NOT canonical -> re-encode differs -> the canonical check fires.
        let mut non_canonical = row.clone();
        non_canonical.insert(1, b' ');
        let input = ChainInput {
            rows: vec![non_canonical],
        };
        let expected = ExpectedChain {
            chain_id: "urn:example:chain".to_string(),
            first_sequence: 1,
            last_sequence: 1,
            row_count: 1,
            previous_hash: [0u8; 32],
            head_hash: hash, // honest head; the canonical check fires first
            bounds: None,
        };
        assert_eq!(check_chain(&input, &expected), Err(Invalid));
    }

    // --- Chain genesis binding ---
    // RED if the genesis binding were removed: a sequence-1 row with a nonzero
    // previous would be accepted as a forged genesis.
    #[test]
    fn red_check_chain_genesis_binding() {
        let forged = encode_row_canonical("urn:example:chain", &[1u8; 32], &[2u8; 32], 1);
        let input = ChainInput { rows: vec![forged] };
        let expected = ExpectedChain {
            chain_id: "urn:example:chain".to_string(),
            first_sequence: 1,
            last_sequence: 1,
            row_count: 1,
            previous_hash: [0u8; 32],
            head_hash: [0u8; 32],
            bounds: None,
        };
        assert_eq!(check_chain(&input, &expected), Err(Invalid));
    }

    // --- Chain predecessor link ---
    // RED if the predecessor-link check were removed: a row whose previous does
    // not equal the prior row's hash would be accepted as a valid link.
    #[test]
    fn red_check_chain_predecessor_link() {
        let (row0, hash0) = encode_consumption_entry(
            &ConsumptionEntry {
                chain_id: "urn:example:chain".to_string(),
                commitment: [1u8; 32],
                previous_hash: [0u8; 32],
                sequence: 1,
            },
            &max(),
        )
        .expect("encodes");
        // row1 claims a previous that is NOT hash0.
        let row1 = encode_row_canonical("urn:example:chain", &[3u8; 32], &[9u8; 32], 2);
        let input = ChainInput {
            rows: vec![row0, row1],
        };
        let expected = ExpectedChain {
            chain_id: "urn:example:chain".to_string(),
            first_sequence: 1,
            last_sequence: 2,
            row_count: 2,
            previous_hash: [0u8; 32],
            head_hash: hash0, // the link check fires before the head check
            bounds: None,
        };
        assert_ne!(
            [9u8; 32], hash0,
            "test precondition: link is genuinely broken"
        );
        assert_eq!(check_chain(&input, &expected), Err(Invalid));
    }

    // ==========================================================================
    // Corpus: consumption-chain/entry.json (3 cases)
    // ==========================================================================

    #[test]
    fn corpus_encode_consumption_entry_all_3_cases() {
        let cases = load_cases("consumption-chain/entry.json");
        assert_eq!(cases.len(), 3, "entry corpus has 3 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let entry = ConsumptionEntry {
                chain_id: input["chain_id"].as_str().unwrap_or("").to_string(),
                commitment: b64url_to_32(&input["commitment"]).unwrap_or([0u8; 32]),
                previous_hash: b64url_to_32(&input["previous_hash"]).unwrap_or([0u8; 32]),
                sequence: input["sequence"].as_i64().unwrap_or(0),
            };
            let result = encode_consumption_entry(&entry, &max());
            let agree = match (expected_verdict, &result) {
                ("valid", Ok((bytes, hash))) => {
                    let exp = &case["expected"];
                    bytes.as_slice() == exp["bytes"].as_str().unwrap().as_bytes()
                        && crate::base64url_encode(hash).as_slice()
                            == exp["hash"].as_str().unwrap().as_bytes()
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
        assert_eq!(agreed, 3, "agreed (entry corpus == 3)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: consumption-chain/check.json (10 cases)
    // ==========================================================================

    #[test]
    fn corpus_check_chain_all_10_cases() {
        let cases = load_cases("consumption-chain/check.json");
        assert_eq!(cases.len(), 10, "check corpus has 10 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let rows: Vec<Vec<u8>> = input["rows"]
                .as_array()
                .expect("rows array")
                .iter()
                .map(|r| {
                    crate::base64url_decode(r.as_str().expect("b64 row").as_bytes())
                        .expect("row decodes")
                })
                .collect();
            let chain_input = ChainInput { rows };
            let expected = ExpectedChain {
                chain_id: input["chain_id"].as_str().unwrap_or("").to_string(),
                first_sequence: input["first_sequence"].as_i64().unwrap_or(0),
                last_sequence: input["last_sequence"].as_i64().unwrap_or(0),
                row_count: input["row_count"].as_i64().unwrap_or(0),
                previous_hash: b64url_to_32(&input["previous_hash"]).unwrap_or([0u8; 32]),
                head_hash: b64url_to_32(&input["last_hash"]).unwrap_or([0u8; 32]),
                bounds: None,
            };
            let result = check_chain(&chain_input, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.chain_id == input["chain_id"].as_str().unwrap()
                        && facts.row_count == input["row_count"].as_i64().unwrap()
                        && facts.trust == NotEvaluated
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
        assert_eq!(agreed, 10, "agreed (check corpus == 10)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Façade C — grant + envelope verification (Task 12)
    //
    // The FORGED-CREDENTIAL surface: a permissive verify silently accepts
    // forged credentials. The red-capable battery below asserts each binding's
    // reject; the corpus tests assert byte-level agreement with the falsifier.
    // ==========================================================================

    /// Builds the `verify-grant-valid` corpus fixture (a real Ed25519-signed
    /// grant compact + its trusted issuer + expectation).
    fn valid_grant_verify_fixture() -> (Vec<u8>, TrustedIssuer, ExpectedGrant) {
        let cases = load_cases("grant-verify/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-grant-valid"))
            .expect("valid grant-verify case");
        let input = &case["input"];
        let compact = input["compact"].as_str().unwrap().as_bytes().to_vec();
        let issuer = TrustedIssuer {
            key_id: input["key_id"].as_str().unwrap().to_string(),
            public_key: b64url_to_32(&input["public_key"]).expect("32 bytes"),
        };
        let expected = ExpectedGrant {
            issuer: input["issuer"].as_str().unwrap().to_string(),
            audience: input["audience"].as_str().unwrap().to_string(),
            evaluation_time: input["evaluation_time"].as_i64().unwrap(),
            skew: input["clock_skew"].as_u64().unwrap(),
            bounds: max(),
        };
        (compact, issuer, expected)
    }

    /// REQ1-VERIFY-time-bounds ceiling: a caller-supplied skew above the profile
    /// maximum MUST be rejected before the time arithmetic, else the window
    /// silently widens (future iat/nbf, expired exp accepted). Reference
    /// runtime.ex:523-524 enforces clock_skew <= bounds.clock_skew. Removing the
    /// ceiling check makes this test go RED (the otherwise-valid grant accepts).
    #[test]
    fn red_grant_skew_over_ceiling_rejected() {
        let (compact, issuer, mut expected) = valid_grant_verify_fixture();
        expected.skew = expected.bounds.clock_skew() + 1; // 61 > 60
        assert_eq!(
            verify_grant(&compact, &issuer, &expected),
            Err(Invalid),
            "skew above the bounds.clock_skew ceiling must be rejected"
        );
    }

    /// REQ1-VERIFY-time-bounds ceiling for the proof window: proof_max_age above
    /// the profile maximum MUST be rejected, else stale proofs are admitted.
    /// Reference runtime.ex:550-551. Removing the check makes this test go RED.
    #[test]
    fn red_envelope_proof_max_age_over_ceiling_rejected() {
        let (credentials, mut expected) = valid_envelope_fixture();
        expected.proof_max_age = expected.bounds.proof_max_age() + 1; // 301 > 300
        assert_eq!(
            check_envelope(&credentials, &expected),
            Err(Invalid),
            "proof_max_age above the bounds.proof_max_age ceiling must be rejected"
        );
    }

    /// REQ1-VERIFY-time-bounds: proof_max_age MUST be positive (reference
    /// runtime.ex:550 `proof_max_age > 0`). A zero value would admit any proof
    /// within the skew window (no max-age floor). Removing the `< 1` guard makes
    /// this test go RED.
    #[test]
    fn red_envelope_proof_max_age_zero_rejected() {
        let (credentials, mut expected) = valid_envelope_fixture();
        expected.proof_max_age = 0;
        assert_eq!(
            check_envelope(&credentials, &expected),
            Err(Invalid),
            "proof_max_age == 0 must be rejected (required positive)"
        );
    }

    /// Builds the `check-envelope-valid` corpus fixture (real signed grant +
    /// proof compacts + the matching ExpectedRequest, NonceMode::NotRequired).
    fn valid_envelope_fixture() -> (Credentials, ExpectedRequest) {
        envelope_fixture_for("check-envelope-valid")
    }

    /// Loads one envelope corpus case into (Credentials, ExpectedRequest).
    fn envelope_fixture_for(id: &str) -> (Credentials, ExpectedRequest) {
        let cases = load_cases("envelope/check.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("envelope case {id}"));
        let input = &case["input"];
        let exp = &input["expected"];
        let trusted = TrustedIssuer {
            key_id: exp["trusted_issuer"]["key_id"]
                .as_str()
                .unwrap()
                .to_string(),
            public_key: b64url_to_32(&exp["trusted_issuer"]["public_key"]).unwrap_or([0u8; 32]),
        };
        let nonce_mode = match exp.get("nonce") {
            None => NonceMode::NotRequired,
            Some(n) => NonceMode::Required(
                n["required"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {id} nonce.required"))
                    .to_string(),
            ),
        };
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
            cast_arguments: serde_to_json(&exp["cast_arguments"]),
            proof_max_age: exp["proof_max_age"].as_u64().unwrap(),
            nonce_mode,
            trusted_issuer: trusted,
        };
        let credentials = Credentials {
            grant: input["grant"].as_str().unwrap().as_bytes().to_vec(),
            proof: input["proof"].as_str().unwrap().as_bytes().to_vec(),
        };
        (credentials, expected)
    }

    // ==========================================================================
    // RED-CAPABLE BATTERY — each test names the red state it catches.
    // ==========================================================================

    // --- Signature tamper: a decodable-but-wrong 64-byte signature -> Invalid.
    // Uses the corpus's properly-tampered signature case (a single signature
    // byte flipped then re-canonicalized, so the segment still decodes to 64
    // bytes — this isolates the Ed25519 verify, not the b64 decoder).
    // RED-capable: if ed25519::verify returned Ok(()) unconditionally, the
    // tampered signature would pass (forged credential accepted).
    #[test]
    fn red_grant_signature_tamper_rejected() {
        let cases = load_cases("grant-verify/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-grant-tamper-signature-byte"))
            .expect("tamper case");
        let input = &case["input"];
        let issuer = TrustedIssuer {
            key_id: input["key_id"].as_str().unwrap().to_string(),
            public_key: b64url_to_32(&input["public_key"]).expect("32 bytes"),
        };
        let expected = ExpectedGrant {
            issuer: input["issuer"].as_str().unwrap().to_string(),
            audience: input["audience"].as_str().unwrap().to_string(),
            evaluation_time: input["evaluation_time"].as_i64().unwrap(),
            skew: input["clock_skew"].as_u64().unwrap(),
            bounds: max(),
        };
        let compact = input["compact"].as_str().unwrap().as_bytes();
        assert_eq!(verify_grant(compact, &issuer, &expected), Err(Invalid));
    }

    // --- Key confusion: verifying the grant with the WRONG issuer key -> Invalid.
    // RED-capable: if the key arg were ignored (verify always against the
    // grant's own embedded key), the wrong key would pass.
    #[test]
    fn red_grant_wrong_issuer_key_rejected() {
        let (compact, mut issuer, expected) = valid_grant_verify_fixture();
        issuer.public_key[0] ^= 0x01; // a different 32-byte key
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // --- Key-ID mismatch: header.kid != issuer.key_id -> Invalid.
    #[test]
    fn red_grant_kid_mismatch_rejected() {
        let (compact, mut issuer, expected) = valid_grant_verify_fixture();
        issuer.key_id = "different-kid".to_string();
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // --- Issuer mismatch: claim.iss != expected.issuer -> Invalid.
    #[test]
    fn red_grant_issuer_mismatch_rejected() {
        let (compact, issuer, mut expected) = valid_grant_verify_fixture();
        expected.issuer = "https://wrong-issuer.test".to_string();
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // --- Audience mismatch: expected audience not in grant aud -> Invalid.
    #[test]
    fn red_grant_audience_mismatch_rejected() {
        let (compact, issuer, mut expected) = valid_grant_verify_fixture();
        expected.audience = "https://wrong-audience.test".to_string();
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // --- Time window: an expired grant (exp <= eval - skew) -> Invalid.
    // RED-capable: skip the exp skew check -> red. (corpus invalid-expired:
    // eval=3000, exp=2000, skew=60 -> 2000 > 2940 is false.)
    #[test]
    fn red_grant_expired_rejected() {
        let (compact, issuer, mut expected) = valid_grant_verify_fixture();
        expected.evaluation_time = 3000; // iat=1000,nbf=1000,exp=2000,skew=60
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // --- iat-future: iat > eval + skew -> Invalid.
    #[test]
    fn red_grant_iat_future_rejected() {
        let (compact, issuer, mut expected) = valid_grant_verify_fixture();
        // iat=1000, skew=60 -> eval=939 makes eval+skew=999 < iat(1000).
        expected.evaluation_time = 939;
        assert_eq!(verify_grant(&compact, &issuer, &expected), Err(Invalid));
    }

    // ==========================================================================
    // Envelope red battery
    // ==========================================================================

    // --- Proof signature tamper: flip one proof-signature byte -> Invalid.
    // RED-capable: bypass the holder ed25519::verify -> a forged proof passes.
    #[test]
    fn red_envelope_proof_signature_tamper_rejected() {
        let (mut creds, expected) = valid_envelope_fixture();
        *creds.proof.last_mut().unwrap() ^= 0x01;
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- Holder thumbprint binding: proof JWK thumbprint != grant cnf.jkt ->
    // Invalid. (corpus invalid-claim-holder-binding.)
    #[test]
    fn red_envelope_holder_binding_rejected() {
        let (creds, expected) = envelope_fixture_for("check-envelope-invalid-claim-holder-binding");
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- ath binding (parse!=verify): proof.ath != SHA-256(RECEIVED grant) ->
    // Invalid. (corpus invalid-claim-grant-binding: a proof built over a
    // DIFFERENT grant compact.)
    // RED-capable: compute ath over re-serialized JSON instead of received
    // bytes -> a modified compact wrongly passes.
    #[test]
    fn red_envelope_ath_over_received_bytes_rejected() {
        let (creds, expected) = envelope_fixture_for("check-envelope-invalid-claim-grant-binding");
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- ba_req binding: proof.ba_req != request_digest(op, args) -> Invalid.
    // (corpus invalid-claim-request-arguments.)
    #[test]
    fn red_envelope_ba_req_rejected() {
        let (creds, expected) =
            envelope_fixture_for("check-envelope-invalid-claim-request-arguments");
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- Selector non-match: an equals selector returning Ok(false) -> Invalid.
    // RED-capable: skip selector evaluation -> a non-matching selector passes.
    // (corpus invalid-selector: selector value "rec-1", args id "rec-2".)
    #[test]
    fn red_envelope_selector_non_match_rejected() {
        let (creds, expected) = envelope_fixture_for("check-envelope-invalid-selector");
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- method / uri / invocation / operation mismatch -> each Invalid.
    #[test]
    fn red_envelope_request_bindings_rejected() {
        let (creds, expected) = valid_envelope_fixture();

        // method
        {
            let mut e = expected.clone();
            e.method = "GET".to_string();
            assert_eq!(check_envelope(&creds, &e), Err(Invalid), "method mismatch");
        }
        // uri
        {
            let mut e = expected.clone();
            e.target_uri = "https://resource.example.test/different".to_string();
            assert_eq!(check_envelope(&creds, &e), Err(Invalid), "uri mismatch");
        }
        // invocation
        {
            let mut e = expected.clone();
            e.invocation_id = "00000000-0000-0000-0000-000000000001".to_string();
            assert_eq!(
                check_envelope(&creds, &e),
                Err(Invalid),
                "invocation mismatch"
            );
        }
        // operation (not present in the grant)
        {
            let mut e = expected.clone();
            e.operation = "nonexistent-op".to_string();
            assert_eq!(
                check_envelope(&creds, &e),
                Err(Invalid),
                "operation mismatch"
            );
        }
    }

    // --- Nonce mode: NotRequired rejects a proof that carries a nonce.
    // (Mirror of corpus invalid-nonce-required, which is the Required direction:
    // a Required proof missing its nonce.)
    #[test]
    fn red_envelope_nonce_mode_rejected() {
        // corpus invalid-nonce-required: Required("server-nonce-x") but proof
        // carries no nonce -> Invalid.
        let (creds, expected) = envelope_fixture_for("check-envelope-invalid-nonce-required");
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // --- Proof time window: a stale proof (iat < eval - proof_max_age - skew)
    // -> Invalid. Constructed by pushing evaluation_time forward against the
    // valid fixture's proof iat (1100).
    #[test]
    fn red_envelope_proof_time_window_rejected() {
        let (creds, mut expected) = valid_envelope_fixture();
        // valid: proof iat=1100, eval=1200, proof_max_age=300, skew=60 ->
        // window [840,1260]. Push eval to 2000 -> lower = 2000-300-60 = 1640 >
        // 1100 -> stale -> Invalid.
        expected.evaluation_time = 2000;
        assert_eq!(check_envelope(&creds, &expected), Err(Invalid));
    }

    // ==========================================================================
    // Corpus: grant-verify/verify.json (13 cases) + envelope/check.json (26)
    // ==========================================================================

    #[test]
    fn corpus_verify_grant_all_13_cases() {
        let cases = load_cases("grant-verify/verify.json");
        assert_eq!(cases.len(), 13, "grant-verify corpus has 13 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let issuer = TrustedIssuer {
                key_id: input["key_id"].as_str().unwrap().to_string(),
                public_key: b64url_to_32(&input["public_key"]).unwrap_or([0u8; 32]),
            };
            let expected = ExpectedGrant {
                issuer: input["issuer"].as_str().unwrap().to_string(),
                audience: input["audience"].as_str().unwrap().to_string(),
                evaluation_time: input["evaluation_time"].as_i64().unwrap(),
                skew: input["clock_skew"].as_u64().unwrap(),
                bounds: max(),
            };
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let result = verify_grant(compact, &issuer, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.grant_id == case["expected"]["grant_id"].as_str().unwrap()
                        && facts.issuer == case["expected"]["issuer"].as_str().unwrap()
                        && facts.authorization == NotEvaluated
                        && facts.version == 1
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
        assert_eq!(agreed, 13, "agreed (grant-verify corpus == 13)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    #[test]
    fn corpus_check_envelope_all_26_cases() {
        let cases = load_cases("envelope/check.json");
        assert_eq!(cases.len(), 26, "envelope corpus has 26 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let (creds, expected) = envelope_fixture_for(id);
            let result = check_envelope(&creds, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.authorization == NotEvaluated
                        && facts.grant.authorization == NotEvaluated
                        && facts.grant.version == 1
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
        assert_eq!(agreed, 26, "agreed (envelope corpus == 26)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // GrantFacts shape: verify_grant on the valid case populates every field.
    // ==========================================================================

    #[test]
    fn verify_grant_valid_populates_facts() {
        let (compact, issuer, expected) = valid_grant_verify_fixture();
        let facts = verify_grant(&compact, &issuer, &expected).expect("valid");
        assert_eq!(facts.version, 1);
        assert_eq!(facts.issuer, expected.issuer);
        assert_eq!(facts.matched_audience, expected.audience);
        assert_eq!(facts.authorization, NotEvaluated);
        // issuer_key_fingerprint is the raw 32-byte thumbprint of the trusted key.
        assert_eq!(
            facts.issuer_key_fingerprint,
            public_key_thumbprint_raw(&issuer.public_key)
        );
    }

    // ==========================================================================
    // EnvelopeFacts shape: check_envelope on the valid case embeds the grant
    // facts and populates the envelope-only fields.
    // ==========================================================================

    #[test]
    fn check_envelope_valid_populates_facts() {
        let (creds, expected) = valid_envelope_fixture();
        let facts = check_envelope(&creds, &expected).expect("valid");
        assert_eq!(facts.authorization, NotEvaluated);
        assert_eq!(facts.grant.authorization, NotEvaluated);
        assert_eq!(facts.operation, expected.operation);
        assert_eq!(facts.invocation_id, expected.invocation_id);
        assert_eq!(facts.normalized_uri, expected.target_uri);
        // grant_hash == SHA-256(received grant compact).
        let mut h = Sha256::new();
        h.update(&creds.grant);
        let mut want = [0u8; 32];
        want.copy_from_slice(&h.finalize());
        assert_eq!(facts.grant_hash, want);
        assert_eq!(facts.grant.matched_audience, expected.audience);
    }

    // ==========================================================================
    // Façade D — anchored export verify/encode (Task 13)
    //
    // The SILENT-RELINK surface: a permissive export verify silently certifies a
    // relinked/shortened archive; a permissive rollover silently accepts an
    // unauthenticated key path. The corpus tests pin byte-level agreement with
    // the falsifier; the F1 defect-injection proves the surplus-key invariant
    // is red-capable.
    // ==========================================================================

    /// Builds a HistoricalPublicKey from a corpus key object. The corpus always
    /// carries an integral `valid_before`; a missing upper bound maps to
    /// `Unbounded` (the only open upper interval).
    fn historical_key_from(v: &serde_json::Value) -> HistoricalPublicKey {
        let valid_before = match v["valid_before"].as_i64() {
            Some(n) => ValidityUpperBound::Bounded(n),
            None => ValidityUpperBound::Unbounded,
        };
        HistoricalPublicKey {
            key_id: v["key_id"].as_str().unwrap().to_string(),
            public_key: b64url_to_32(&v["public_key"]).expect("32-byte public key"),
            valid_from: v["valid_from"].as_i64().unwrap(),
            valid_before,
        }
    }

    /// Builds an ExpectedAnchor from a corpus expected-anchor object.
    fn expected_anchor_from(v: &serde_json::Value) -> ExpectedAnchor {
        ExpectedAnchor {
            anchor_id: v["anchor_id"].as_str().unwrap().to_string(),
            anchored_at: v["anchored_at"].as_i64().unwrap(),
            chain_hash: b64url_to_32(&v["chain_hash"]).expect("32-byte chain_hash"),
            chain_id: v["chain_id"].as_str().unwrap().to_string(),
            key_fingerprint: b64url_to_32(&v["key_fingerprint"]).expect("32-byte fp"),
            key_id: v["key_id"].as_str().unwrap().to_string(),
            sequence: v["sequence"].as_i64().unwrap(),
            bounds: None,
        }
    }

    /// Builds an ExpectedKeyTransition from a corpus expected-transition object.
    fn expected_transition_from(v: &serde_json::Value) -> ExpectedKeyTransition {
        ExpectedKeyTransition {
            chain_id: v["chain_id"].as_str().unwrap().to_string(),
            current_key_fingerprint: b64url_to_32(&v["current_key_fingerprint"]).expect("32"),
            current_key_id: v["current_key_id"].as_str().unwrap().to_string(),
            effective_at: v["effective_at"].as_i64().unwrap(),
            next_key_fingerprint: b64url_to_32(&v["next_key_fingerprint"]).expect("32"),
            next_key_id: v["next_key_id"].as_str().unwrap().to_string(),
            transition_id: v["transition_id"].as_str().unwrap().to_string(),
            bounds: None,
        }
    }

    /// Builds an ExpectedChain from a corpus chain object (corpus `last_hash`
    /// maps to `head_hash`).
    fn expected_chain_from(v: &serde_json::Value) -> ExpectedChain {
        ExpectedChain {
            chain_id: v["chain_id"].as_str().unwrap().to_string(),
            first_sequence: v["first_sequence"].as_i64().unwrap(),
            last_sequence: v["last_sequence"].as_i64().unwrap(),
            row_count: v["row_count"].as_i64().unwrap(),
            previous_hash: b64url_to_32(&v["previous_hash"]).expect("32"),
            head_hash: b64url_to_32(&v["last_hash"]).expect("32"),
            bounds: None,
        }
    }

    /// Builds an ExpectedAnchoredExport from the corpus expected object.
    fn expected_anchored_export_from(exp: &serde_json::Value) -> ExpectedAnchoredExport {
        ExpectedAnchoredExport {
            chain: expected_chain_from(&exp["chain"]),
            digest: b64url_to_32(&exp["digest"]).expect("32-byte digest"),
            start_anchor: expected_anchor_from(&exp["start_anchor"]),
            end_anchor: expected_anchor_from(&exp["end_anchor"]),
            transitions: exp["transitions"]
                .as_array()
                .unwrap()
                .iter()
                .map(expected_transition_from)
                .collect(),
            object_version: exp["object_version"].as_str().unwrap().to_string(),
            bounds: None,
        }
    }

    // ==========================================================================
    // RED-CAPABLE battery — anchor / transition / export bindings.
    // ==========================================================================

    // --- Anchor signature tamper (corpus tamper case): a flipped signature
    // byte -> Invalid. RED-capable: skip the ed25519::verify call and the
    // tampered anchor would pass.
    #[test]
    fn red_historical_anchor_tamper_rejected() {
        let cases = load_cases("boundary-anchor/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-historical-anchor-tamper-signature-byte"))
            .expect("tamper case");
        let input = &case["input"];
        let compact = input["compact"].as_str().unwrap().as_bytes();
        let key = historical_key_from(&input["key"]);
        let expected = expected_anchor_from(&input["expected"]);
        assert_eq!(
            verify_historical_anchor(compact, &key, &expected),
            Err(Invalid)
        );
    }

    // --- Anchor wrong key (corpus invalid_key): derived fingerprint != signed.
    #[test]
    fn red_historical_anchor_wrong_key_rejected() {
        let cases = load_cases("boundary-anchor/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-historical-anchor-invalid-bad-key"))
            .expect("bad-key case");
        let input = &case["input"];
        let key = historical_key_from(&input["key"]);
        let expected = expected_anchor_from(&input["expected"]);
        assert_eq!(
            verify_historical_anchor(
                input["compact"].as_str().unwrap().as_bytes(),
                &key,
                &expected
            ),
            Err(Invalid)
        );
    }

    // --- Anchor alg=none (corpus invalid_algorithm): closed-set header reject.
    #[test]
    fn red_historical_anchor_alg_none_rejected() {
        let cases = load_cases("boundary-anchor/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-historical-anchor-invalid-algorithm-none"))
            .expect("alg case");
        let input = &case["input"];
        let key = historical_key_from(&input["key"]);
        let expected = expected_anchor_from(&input["expected"]);
        assert_eq!(
            verify_historical_anchor(
                input["compact"].as_str().unwrap().as_bytes(),
                &key,
                &expected
            ),
            Err(Invalid)
        );
    }

    // --- Anchor validity window (corpus invalid_time): anchored_at >=
    // valid_before -> Invalid.
    #[test]
    fn red_historical_anchor_time_window_rejected() {
        let cases = load_cases("boundary-anchor/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-historical-anchor-invalid-time-window"))
            .expect("time case");
        let input = &case["input"];
        let key = historical_key_from(&input["key"]);
        let expected = expected_anchor_from(&input["expected"]);
        assert_eq!(
            verify_historical_anchor(
                input["compact"].as_str().unwrap().as_bytes(),
                &key,
                &expected
            ),
            Err(Invalid)
        );
    }

    // --- Transition signature tamper + bad current key + alg none + time.
    #[test]
    fn red_key_transition_battery_rejected() {
        for (case_id, label) in [
            ("verify-key-transition-tamper-signature-byte", "tamper"),
            (
                "verify-key-transition-invalid-bad-current-key",
                "bad-current-key",
            ),
            ("verify-key-transition-invalid-algorithm-none", "alg-none"),
            ("verify-key-transition-invalid-time-window", "time-window"),
        ] {
            let cases = load_cases("key-transition/verify.json");
            let case = cases
                .iter()
                .find(|c| c["id"].as_str() == Some(case_id))
                .unwrap_or_else(|| panic!("case {case_id}"));
            let input = &case["input"];
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let current = historical_key_from(&input["current_key"]);
            let next = historical_key_from(&input["next_key"]);
            let expected = expected_transition_from(&input["expected"]);
            assert_eq!(
                verify_key_transition(compact, &current, &next, &expected),
                Err(Invalid),
                "{label}"
            );
        }
    }

    // --- Encode byte-exact: the valid encode's byte_count + digest match the
    // corpus byte-exact. RED-capable: a wrong magic or wrong frame order yields
    // a different digest.
    #[test]
    fn red_encode_anchored_export_byte_exact() {
        let cases = load_cases("anchored-export/encode.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("encode-anchored-export-valid"))
            .unwrap();
        let input = &case["input"];
        let anchored_input = AnchoredExportInput {
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
                .map(|r| {
                    crate::base64url_decode(r.as_str().unwrap().as_bytes()).expect("row decodes")
                })
                .collect(),
        };
        let expected = ExpectedExport {
            chain: expected_chain_from(&input["expected"]["chain"]),
            digest: b64url_to_32(&input["expected"]["digest"]).expect("32"),
            start_anchor: expected_anchor_from(&input["expected"]["start_anchor"]),
            end_anchor: expected_anchor_from(&input["expected"]["end_anchor"]),
            transitions: input["expected"]["transitions"]
                .as_array()
                .unwrap()
                .iter()
                .map(expected_transition_from)
                .collect(),
            object_version: input["expected"]["object_version"]
                .as_str()
                .unwrap()
                .to_string(),
            bounds: None,
        };
        let encoded = encode_anchored_export(&anchored_input, &expected).expect("encodes");
        let exp = &case["expected"];
        assert_eq!(
            encoded.byte_count,
            exp["byte_count"].as_i64().unwrap() as u64
        );
        assert_eq!(
            crate::base64url_encode(&encoded.digest).as_slice(),
            exp["digest"].as_str().unwrap().as_bytes()
        );
        // The first 20 bytes are exactly the archive magic.
        assert_eq!(&encoded.bytes[..ARCHIVE_MAGIC.len()], ARCHIVE_MAGIC);
    }

    // --- Encode start-anchor binding (corpus invalid case): start sequence !=
    // first_sequence - 1 -> Invalid.
    #[test]
    fn red_encode_start_anchor_binding_rejected() {
        let cases = load_cases("anchored-export/encode.json");
        let case = cases
            .iter()
            .find(|c| {
                c["id"].as_str() == Some("encode-anchored-export-invalid-start-anchor-binding")
            })
            .unwrap();
        let input = &case["input"];
        let anchored_input = AnchoredExportInput {
            start_anchor: input["start_anchor"].as_str().unwrap().as_bytes().to_vec(),
            end_anchor: input["end_anchor"].as_str().unwrap().as_bytes().to_vec(),
            transitions: vec![],
            rows: input["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    crate::base64url_decode(r.as_str().unwrap().as_bytes()).expect("row decodes")
                })
                .collect(),
        };
        let expected = ExpectedExport {
            chain: expected_chain_from(&input["expected"]["chain"]),
            digest: b64url_to_32(&input["expected"]["digest"]).expect("32"),
            start_anchor: expected_anchor_from(&input["expected"]["start_anchor"]),
            end_anchor: expected_anchor_from(&input["expected"]["end_anchor"]),
            transitions: vec![],
            object_version: input["expected"]["object_version"]
                .as_str()
                .unwrap()
                .to_string(),
            bounds: None,
        };
        assert_eq!(
            encode_anchored_export(&anchored_input, &expected),
            Err(Invalid)
        );
    }

    // --- Export digest mismatch (corpus invalid-encoding-digest): a wrong
    // expected digest -> constant-time compare fails -> Invalid.
    #[test]
    fn red_export_digest_mismatch_rejected() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-invalid-encoding-digest"))
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        assert_eq!(verify_anchored_export(&obj, &keys, &expected), Err(Invalid));
    }

    // --- Export version mismatch (corpus invalid-claim-version).
    #[test]
    fn red_export_version_mismatch_rejected() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-invalid-claim-version"))
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        assert_eq!(verify_anchored_export(&obj, &keys, &expected), Err(Invalid));
    }

    // --- The 3 signed cases from the 696384c gating prerequisite: non-monotone
    // effective_at -> Invalid; fingerprint cycle -> Invalid; one-key/zero-
    // transition -> Ok. These MUST pass.
    #[test]
    fn signed_prerequisite_non_monotone_rejected() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| {
                c["id"].as_str() == Some("verify-anchored-export-invalid-non-monotone-transitions")
            })
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        assert_eq!(verify_anchored_export(&obj, &keys, &expected), Err(Invalid));
    }

    #[test]
    fn signed_prerequisite_fingerprint_cycle_rejected() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-invalid-fingerprint-cycle"))
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        assert_eq!(verify_anchored_export(&obj, &keys, &expected), Err(Invalid));
    }

    #[test]
    fn signed_prerequisite_one_key_zero_transition_valid() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-valid-one-key"))
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        let facts = verify_anchored_export(&obj, &keys, &expected).expect("one-key valid");
        assert_eq!(facts.transition_count, 0);
        assert_eq!(facts.trust, NotEvaluated);
        assert_eq!(facts.authorization, NotEvaluated);
    }

    // --- F1 surplus-key invariant (MANDATORY defect injection). NO corpus case
    // constructs this: a 0-transition archive (one signing key) presented with
    // a 2-key chain. The F1 check (keys.len() == transitions.len() + 1) is the
    // ONLY thing that catches it: without F1, the surplus key is silently
    // ignored (start+end both verify against keys[0], no transitions to
    // authenticate, the two distinct fingerprints pass the cycle check) and the
    // archive is WRONGLY accepted as Ok.
    //
    // RED-capable proof (executed separately): mechanically remove the F1 check
    // -> this test returns Ok (RED). Restore -> Invalid (GREEN).
    #[test]
    fn red_f1_surplus_key_invariant_zero_transition() {
        let cases = load_cases("anchored-export/verify.json");
        let one_key = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-valid-one-key"))
            .unwrap();
        let input = &one_key["input"];
        let exp = &input["expected"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let archive_c = historical_key_from(&input["keys"][0]);
        // A second DISTINCT key (archive-d, from the non-monotone case) as the
        // surplus entry the no-transition archive never authenticates.
        let nm = cases
            .iter()
            .find(|c| {
                c["id"].as_str() == Some("verify-anchored-export-invalid-non-monotone-transitions")
            })
            .unwrap();
        let archive_d = historical_key_from(&nm["input"]["keys"][1]);
        assert_ne!(
            archive_c.public_key, archive_d.public_key,
            "precondition: surplus key must be distinct"
        );
        let keys = HistoricalKeyChain {
            keys: vec![archive_c, archive_d],
        };
        let expected = expected_anchored_export_from(exp);
        assert_eq!(
            verify_anchored_export(&obj, &keys, &expected),
            Err(Invalid),
            "F1: a 0-transition archive with 2 keys MUST be Invalid"
        );
    }

    // --- constant_time_eq sanity: equal-length digest compare is byte-exact
    // and rejects a single-byte difference (the tamper-digest defense).
    #[test]
    fn constant_time_eq_rejects_single_byte_difference() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[17] ^= 0x01;
        assert!(!constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &[0u8; 31]));
    }

    // ==========================================================================
    // Corpus: boundary-anchor/verify.json (5 cases)
    // ==========================================================================

    #[test]
    fn corpus_verify_historical_anchor_all_5_cases() {
        let cases = load_cases("boundary-anchor/verify.json");
        assert_eq!(cases.len(), 5, "boundary-anchor corpus has 5 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let key = historical_key_from(&input["key"]);
            let expected = expected_anchor_from(&input["expected"]);
            let result = verify_historical_anchor(compact, &key, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.anchor_id == expected.anchor_id
                        && facts.sequence == expected.sequence
                        && facts.chain_hash == expected.chain_hash
                        && facts.key_fingerprint == expected.key_fingerprint
                        && facts.trust == NotEvaluated
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
        assert_eq!(agreed, 5, "agreed (boundary-anchor corpus == 5)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: key-transition/verify.json (5 cases)
    // ==========================================================================

    #[test]
    fn corpus_verify_key_transition_all_5_cases() {
        let cases = load_cases("key-transition/verify.json");
        assert_eq!(cases.len(), 5, "key-transition corpus has 5 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let compact = input["compact"].as_str().unwrap().as_bytes();
            let current = historical_key_from(&input["current_key"]);
            let next = historical_key_from(&input["next_key"]);
            let expected = expected_transition_from(&input["expected"]);
            let result = verify_key_transition(compact, &current, &next, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.transition_id == expected.transition_id
                        && facts.current_key_fingerprint == expected.current_key_fingerprint
                        && facts.next_key_fingerprint == expected.next_key_fingerprint
                        && facts.trust == NotEvaluated
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
        assert_eq!(agreed, 5, "agreed (key-transition corpus == 5)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: anchored-export/encode.json (2 cases)
    // ==========================================================================

    #[test]
    fn corpus_encode_anchored_export_all_2_cases() {
        let cases = load_cases("anchored-export/encode.json");
        assert_eq!(cases.len(), 2, "anchored-export encode corpus has 2 cases");
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let anchored_input = AnchoredExportInput {
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
                    .map(|r| {
                        crate::base64url_decode(r.as_str().unwrap().as_bytes())
                            .expect("row decodes")
                    })
                    .collect(),
            };
            let expected = ExpectedExport {
                chain: expected_chain_from(&input["expected"]["chain"]),
                digest: b64url_to_32(&input["expected"]["digest"]).unwrap_or([0u8; 32]),
                start_anchor: expected_anchor_from(&input["expected"]["start_anchor"]),
                end_anchor: expected_anchor_from(&input["expected"]["end_anchor"]),
                transitions: input["expected"]["transitions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(expected_transition_from)
                    .collect(),
                object_version: input["expected"]["object_version"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                bounds: None,
            };
            let result = encode_anchored_export(&anchored_input, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(encoded)) => {
                    let exp = &case["expected"];
                    encoded.byte_count == exp["byte_count"].as_i64().unwrap() as u64
                        && crate::base64url_encode(&encoded.digest).as_slice()
                            == exp["digest"].as_str().unwrap().as_bytes()
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
        assert_eq!(agreed, 2, "agreed (anchored-export encode corpus == 2)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // Corpus: anchored-export/verify.json (10 cases)
    // ==========================================================================

    #[test]
    fn corpus_verify_anchored_export_all_10_cases() {
        let cases = load_cases("anchored-export/verify.json");
        assert_eq!(
            cases.len(),
            10,
            "anchored-export verify corpus has 10 cases"
        );
        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
            let input = &case["input"];
            let chunks: Vec<Vec<u8>> = input["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default()
                })
                .collect();
            let obj = ArchivedObject {
                chunks,
                version: input["version"].as_str().unwrap().to_string(),
            };
            let keys = HistoricalKeyChain {
                keys: input["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(historical_key_from)
                    .collect(),
            };
            let expected = expected_anchored_export_from(&input["expected"]);
            let result = verify_anchored_export(&obj, &keys, &expected);
            let agree = match (expected_verdict, &result) {
                ("valid", Ok(facts)) => {
                    facts.trust == NotEvaluated
                        && facts.authorization == NotEvaluated
                        && facts.chain_id
                            == input["expected"]["chain"]["chain_id"].as_str().unwrap()
                        && facts.row_count
                            == input["expected"]["chain"]["row_count"].as_i64().unwrap()
                }
                ("invalid", Err(Invalid)) => true,
                _ => false,
            };
            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!(
                    "DISAGREE: id={id} expected={expected_verdict} ok={}",
                    result.is_ok()
                );
            }
        }
        assert_eq!(agreed, 10, "agreed (anchored-export verify corpus == 10)");
        assert_eq!(disagreed, 0, "disagreed");
    }

    // ==========================================================================
    // AnchoredExportFacts shape: the valid 2-key case populates every field and
    // carries BOTH trust + authorization markers.
    // ==========================================================================

    #[test]
    fn verify_anchored_export_valid_populates_facts() {
        let cases = load_cases("anchored-export/verify.json");
        let case = cases
            .iter()
            .find(|c| c["id"].as_str() == Some("verify-anchored-export-valid"))
            .unwrap();
        let input = &case["input"];
        let chunks: Vec<Vec<u8>> = input["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| crate::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
            .collect();
        let obj = ArchivedObject {
            chunks,
            version: input["version"].as_str().unwrap().to_string(),
        };
        let keys = HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(historical_key_from)
                .collect(),
        };
        let expected = expected_anchored_export_from(&input["expected"]);
        let facts = verify_anchored_export(&obj, &keys, &expected).expect("valid");
        assert_eq!(facts.trust, NotEvaluated);
        assert_eq!(facts.authorization, NotEvaluated);
        assert_eq!(facts.transition_count, 1);
        assert_eq!(facts.row_count, 1);
        assert_eq!(facts.object_version, "v1");
        // digest == SHA-256 over the complete archive byte stream.
        let mut recomputed = [0u8; 32];
        let mut h = Sha256::new();
        for c in &obj.chunks {
            h.update(c);
        }
        recomputed.copy_from_slice(&h.finalize());
        assert_eq!(facts.digest, recomputed);
    }
}
