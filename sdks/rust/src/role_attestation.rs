//! The standalone sibling role-attestation profile (`bap-role-attestation/1`).
//!
//! A role attestation is a compact JWS in which an attestor key binds a
//! subject key to a role (`"issuer"` or `"holder"`) for a bounded window. The
//! profile single-sources the contract-major 1 primitives (Ed25519/EdDSA under
//! `BAP1-Ed25519-SHA256`, the bounded JSON/JCS/base64url/JWK machinery) and is
//! parsed by no contract-major profile: this façade rejects every
//! contract-major `typ` and every contract-major façade rejects
//! `ba+role-attestation` (`REQ-RA1-CORE-cross-profile-reject`). The artifact
//! is standalone and grant-unbound — it binds no grant, names no issuer
//! identity, audience, or scope, and carries no authorization
//! (`REQ-RA1-CORE-profile-identity`).
//!
//! The four public surfaces (`REQ-RA1-API-complete`):
//! [`attestation_signing_input`] (signing-input production),
//! [`assemble_attestation_compact`] (compact assembly from a signing input +
//! external signature), [`decode_attestation`] (decode), and
//! [`verify_attestation`] (the citation symbol). The package owns no signer
//! and accepts no private key or signing callback — only external signature
//! bytes (`REQ-RA1-API-no-signer`). Every failure collapses to exactly
//! [`Invalid`](crate::Invalid) (`REQ-RA1-API-return-shape`); profile selection
//! is trusted caller code and is never inferred from bytes, context, or a
//! failed verification (`REQ-RA1-CORE-no-inference-fallback`).
//!
//! This is a **silent-auth-class surface**: a header/claim closed-set leak, an
//! ES256-signed confusion, or a single wrong signing-input byte is a wrong
//! verdict. **Verification is not authority** — a verified attestation is
//! evidence of a binding, never an authorization decision
//! (`REQ-RA1-SECURITY-not-authority`).
//!
//! # Derivation
//!
//! Derived first-hand from `spec/bap-role-attestation-v1.md` (§2 Protected
//! header and payload claims, §3 Verification contract, §4 Public verification
//! contract), ADR 0036, and the certified corpus under
//! `priv/conformance/attestation-profiles/role-attestation/v1/` (the corpus is
//! the falsifier; the payload member order below is derived by
//! base64url-decoding the corpus `payload_segment` first-hand) — NOT from any
//! Elixir or sibling-SDK source (ADR 0014 D5). The shared BAP1 validation
//! helpers mirror the v1 façade's own private set (each façade carries its
//! copy — the v2/v3 precedent).

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::compact;
use crate::ed25519;
use crate::error::{Invalid, Result};
use crate::facts::{AttestationFacts, NotEvaluated, SignatureAndWindow};
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::jwk::{public_key_thumbprint_raw, thumbprint_raw};
use crate::types::{
    AttestationDecoded, AttestationInput, ExpectedAttestation, ProducedSigningInput, Role,
    SigningInput, SigningKind, ValidityUpperBound,
};

// ============================================================================
// Constants — closed header/claim member values (bap-role-attestation/1 §2)
// ============================================================================

const ALG_EDDSA: &str = "EdDSA";
const TYP_ROLE_ATTESTATION: &str = "ba+role-attestation";

// ============================================================================
// attestation_signing_input — signing-input production (§4 surface 1)
// ============================================================================

/// Produce the deterministic role-attestation signing input from structured
/// fields.
///
/// Emits one canonical JCS representation of the protected header
/// `{alg:"EdDSA", kid:attestor_key_id, typ:"ba+role-attestation"}` and the
/// payload `{exp, jti, key_id, nbf, public_key, role, v:1}` (JCS sorts both
/// objects; the payload member order is pinned by the corpus
/// `payload_segment`), then assembles the two-segment RFC 7515 signing input
/// `ASCII(base64url(protected) || "." || base64url(payload))`. The producer
/// uses the same profile semantics as assembly, decode, and verify
/// (`REQ-RA1-API-symmetry`): every input field is revalidated (`kid` rules,
/// grant-`jti` StringOrURI rules, `nbf < exp`) before any byte is emitted.
pub fn attestation_signing_input(
    attestation: &AttestationInput,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    // REQ-RA1-CLAIM-closed-required / -window: validate every input field.
    validate_kid(&attestation.attestor_key_id, bounds)?;
    validate_identifier(&attestation.jti, bounds)?;
    validate_kid(&attestation.key_id, bounds)?;
    if attestation.nbf >= attestation.exp {
        return Err(Invalid); // REQ-RA1-CLAIM-window (nbf < exp)
    }

    // Header object (JCS sorts members: alg < kid < typ).
    let header = JsonValue::Object(vec![
        ("alg".to_string(), JsonValue::String(ALG_EDDSA.to_string())),
        (
            "kid".to_string(),
            JsonValue::String(attestation.attestor_key_id.clone()),
        ),
        (
            "typ".to_string(),
            JsonValue::String(TYP_ROLE_ATTESTATION.to_string()),
        ),
    ]);

    // Payload object (JCS sorts members: exp < jti < key_id < nbf <
    // public_key < role < v; derived first-hand from the corpus payload
    // segment). `public_key` is base64url of exactly the 32 raw key bytes
    // (REQ-RA1-CLAIM-public-key); `role` is exactly "issuer"/"holder"
    // (REQ-RA1-CLAIM-role-closed-set).
    let public_key = b64url_to_string(&base64url_encode(&attestation.public_key))?;
    let payload = JsonValue::Object(vec![
        ("exp".to_string(), JsonValue::Int(attestation.exp)),
        (
            "jti".to_string(),
            JsonValue::String(attestation.jti.clone()),
        ),
        (
            "key_id".to_string(),
            JsonValue::String(attestation.key_id.clone()),
        ),
        ("nbf".to_string(), JsonValue::Int(attestation.nbf)),
        ("public_key".to_string(), JsonValue::String(public_key)),
        (
            "role".to_string(),
            JsonValue::String(attestation.role.as_str().to_string()),
        ),
        ("v".to_string(), JsonValue::Int(1)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// assemble_attestation_compact — compact assembly (§4 surface 2)
// ============================================================================

/// Assemble the 3-segment compact serialization from a signing input + raw
/// 64-byte external signature, then revalidate the composed compact under
/// THIS profile.
///
/// Wraps [`compact::compose_compact`] (composition + segment
/// well-formedness) with the per-kind content revalidation
/// `REQ-RA1-API-assembly-revalidate` mandates: the composed bytes are
/// re-parsed through the same decoder [`decode_attestation`] uses — closed
/// header/payload sets, member rules, JCS canonical byte equality on both
/// segments (`REQ-RA1-CLAIM-canonical`), segment bounds, and the 64-byte
/// signature width. A caller-supplied segment set that composes to anything
/// this profile does not parse (wrong kind, non-canonical member order,
/// duplicate members, wrong `public_key` width) is rejected — there is no
/// permissive compatibility path.
pub fn assemble_attestation_compact(
    input: &SigningInput,
    signature: &[u8; 64],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    if input.kind != SigningKind::RoleAttestation {
        return Err(Invalid);
    }
    let bounds = resolve_bounds(bounds);
    if input.protected_segment.len() as u64 > bounds.encoded_segment_bytes()
        || input.payload_segment.len() as u64 > bounds.encoded_segment_bytes()
    {
        return Err(Invalid);
    }
    let compact = compact::compose_compact(input, signature)?;
    // REQ-RA1-API-assembly-revalidate + REQ-RA1-API-symmetry: the same
    // profile semantics as decode/verify gate the composed bytes.
    decode_attestation_parts(&compact, &bounds)?;
    Ok(compact)
}

// ============================================================================
// decode_attestation — attestation decoding (§4 surface 3)
// ============================================================================

/// Parse, bound, and structurally validate a role-attestation compact without
/// verifying the Ed25519 signature.
///
/// Returns an [`AttestationDecoded`] carrying the decoded claims plus
/// `verification: NotEvaluated`. The protected header is validated against
/// the closed set `{alg:"EdDSA", kid, typ:"ba+role-attestation"}` and the
/// payload against the closed claim table `{v:1, jti, key_id, public_key,
/// role, nbf, exp}` (`REQ-RA1-HEADER-closed-set`,
/// `REQ-RA1-CLAIM-closed-required`); both segments MUST equal their RFC 8785
/// canonical re-encoding and duplicate members are invalid
/// (`REQ-RA1-CLAIM-canonical`); the decoded signature MUST be exactly 64
/// bytes.
pub fn decode_attestation(compact: &[u8], bounds: &Bounds) -> Result<AttestationDecoded> {
    let a = decode_attestation_parts(compact, bounds)?;
    Ok(AttestationDecoded {
        attestor_key_id: a.key_id,
        jti: a.payload.jti,
        key_id: a.payload.key_id,
        public_key: a.payload.public_key,
        role: a.payload.role,
        nbf: a.payload.not_before,
        exp: a.payload.expires_at,
        verification: NotEvaluated,
    })
}

// ============================================================================
// verify_attestation — attestation verification (§4 surface 4, the citation
// symbol `RoleAttestation.V1.verify_attestation/2`)
// ============================================================================

/// Verify a role-attestation compact against caller-supplied trusted inputs
/// and expected context (`REQ-RA1-VERIFY-caller-supplied`).
///
/// Proves, in order (`REQ-RA1-VERIFY-fail-closed` — any failure returns
/// exactly `Err(Invalid)`, value-free):
///
/// 1. the closed header/payload sets and canonical bytes of §2
///    (`REQ-RA1-VERIFY-closed-sets`);
/// 2. the header `kid` equals the attestor key id, and the Ed25519 signature
///    verifies under the attestor public key over the exact two-segment
///    signing input (`REQ-RA1-VERIFY-attestor-signature`);
/// 3. the payload subject binding equals the expected subject binding —
///    `key_id` equality and raw `public_key` byte-equality
///    (`REQ-RA1-VERIFY-subject-binding`);
/// 4. the attestor and the subject are distinct: the RFC 7638 thumbprints
///    differ AND the key ids differ (`REQ-RA1-VERIFY-no-self-attestation`);
/// 5. window containment: `nbf >= attestor.valid_from` and, when the attestor
///    window is bounded, `exp <= attestor.valid_before` (`exp ==
///    valid_before` is containment and is valid)
///    (`REQ-RA1-VERIFY-window-containment`);
/// 6. the caller-supplied `now` lies in the half-open `[nbf, exp)`
///    (`REQ-RA1-VERIFY-now-window`).
///
/// Returns [`AttestationFacts`] — closed, value-bearing, redacted,
/// non-authorizing: the thumbprints are RFC 7638 digests over the
/// `{"crv":"Ed25519","kty":"OKP","x":…}` preimage, never hashes of raw key
/// bytes (`REQ-RA1-CLAIM-canonical`), and the facts carry no raw key
/// material, no signature, and no decision
/// (`REQ-RA1-VERIFY-facts-non-authorizing`). Which attestor to trust, which
/// role a consumer requires, and replay reservation are caller obligations
/// (`REQ-RA1-VERIFY-policy-caller-side`).
pub fn verify_attestation(
    compact: &[u8],
    expected: &ExpectedAttestation,
) -> Result<AttestationFacts> {
    let bounds = expected.bounds;
    // Attestor-window endpoints are magnitude-bounded under the resolved
    // bounds, and a bounded window must be nonempty — the same
    // HistoricalPublicKey gates `verify_historical_anchor` applies (the
    // attestor context reuses that key shape; window containment alone would
    // accept out-of-magnitude or empty caller windows).
    if expected.attestor.valid_from.unsigned_abs() > bounds.integer_magnitude() {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = expected.attestor.valid_before {
        if v.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        if v <= expected.attestor.valid_from {
            return Err(Invalid);
        }
    }

    let a = decode_attestation_parts(compact, &bounds)?;

    // REQ-RA1-VERIFY-attestor-signature: the header kid equals the attestor
    // key id (the kid is a hint; the TRUSTED key is the caller's), and the
    // signature verifies under the attestor public key over the exact
    // two-segment signing input.
    if a.key_id != expected.attestor.key_id {
        return Err(Invalid);
    }
    let signing_input = signing_input_bytes(a.protected_seg, a.payload_seg);
    ed25519::verify(&expected.attestor.public_key, &signing_input, &a.signature)?;

    // REQ-RA1-VERIFY-subject-binding: key_id equality + raw byte-equality.
    if a.payload.key_id != expected.subject_key_id {
        return Err(Invalid);
    }
    if a.payload.public_key != expected.subject_public_key {
        return Err(Invalid);
    }

    // REQ-RA1-VERIFY-no-self-attestation: the attestor thumbprint MUST NOT
    // equal the subject thumbprint AND the attestor key id MUST NOT equal the
    // subject key id (either equality alone is self-attestation).
    let attestor_thumbprint = public_key_thumbprint_raw(&expected.attestor.public_key);
    let subject_thumbprint = thumbprint_raw(&a.payload.public_key);
    if attestor_thumbprint == subject_thumbprint {
        return Err(Invalid);
    }
    if expected.attestor.key_id == a.payload.key_id {
        return Err(Invalid);
    }

    // REQ-RA1-VERIFY-window-containment: nbf >= valid_from and (unbounded OR
    // exp <= valid_before — equality is containment).
    if a.payload.not_before < expected.attestor.valid_from {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = expected.attestor.valid_before {
        if a.payload.expires_at > v {
            return Err(Invalid);
        }
    }

    // REQ-RA1-VERIFY-now-window: now in the half-open [nbf, exp).
    if expected.now < a.payload.not_before || expected.now >= a.payload.expires_at {
        return Err(Invalid);
    }

    Ok(AttestationFacts {
        attestor_key_id: a.key_id,
        attestor_key_fingerprint: attestor_thumbprint,
        subject_key_id: a.payload.key_id,
        subject_key_fingerprint: subject_thumbprint,
        role: a.payload.role,
        jti: a.payload.jti,
        nbf: a.payload.not_before,
        exp: a.payload.expires_at,
        verification: SignatureAndWindow,
        trust: NotEvaluated,
    })
}

// ============================================================================
// Internal — shared decode (the assembly/decode/verify symmetry point)
// ============================================================================

/// The fully-decoded role-attestation compact: the two raw segments (borrowed
/// from the input compact), the decoded 64-byte signature, the validated
/// header `kid`, and the validated payload.
struct DecodedAttestation<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature: [u8; 64],
    key_id: String,
    payload: AttestationPayload,
}

/// Intermediate attestation-payload decode (the fields the surfaces carry).
struct AttestationPayload {
    jti: String,
    key_id: String,
    public_key: [u8; 32],
    role: Role,
    not_before: i64,
    expires_at: i64,
}

/// Splits, bounds, decodes, and structurally validates a role-attestation
/// compact. Shared by [`decode_attestation`], [`verify_attestation`], and the
/// assembly revalidation — the `REQ-RA1-API-symmetry` single seam. The
/// decoded signature segment MUST be exactly 64 bytes; both JSON segments
/// MUST equal their JCS re-encoding.
fn decode_attestation_parts<'a>(
    compact: &'a [u8],
    bounds: &Bounds,
) -> Result<DecodedAttestation<'a>> {
    // REQ1-BOUNDS-ordering: the whole-input compact_bytes ceiling precedes
    // any structural work.
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // Fixed widths: the decoded signature is exactly 64 bytes
    // (REQ1-BOUNDS-fixed-widths — a wrong-width signature segment is
    // structurally invalid, not merely unverifiable).
    let sig_raw = base64url_decode(signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_raw);
    let header = json_decode(&header_bytes, bounds)?;
    let payload_json = json_decode(&payload_bytes, bounds)?;
    let key_id = validate_attestation_header(&header, &header_bytes, bounds)?;
    let payload = validate_attestation_payload(&payload_json, &payload_bytes, bounds)?;
    Ok(DecodedAttestation {
        protected_seg,
        payload_seg,
        signature,
        key_id,
        payload,
    })
}

/// Validates the protected header is exactly
/// `{alg:"EdDSA", kid:<valid kid>, typ:"ba+role-attestation"}`
/// (`REQ-RA1-HEADER-closed-set`; every unlisted member or value is invalid).
/// Returns the validated `kid` (the attestor key id hint). Canonical form: the
/// protected segment bytes MUST equal the exact JCS re-encoding of the header
/// (`REQ-RA1-CLAIM-canonical`).
fn validate_attestation_header(
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
            // cty, crit, jwk, and every unlisted member are invalid
            // (REQ-RA1-HEADER-closed-set).
            _ => return Err(Invalid),
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_EDDSA => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_ROLE_ATTESTATION => {}
        _ => return Err(Invalid),
    }
    let kid_str = match kid {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_kid(kid_str, bounds)?;
    if jcs_encode(header, bounds)?.as_slice() != header_bytes {
        return Err(Invalid); // canonical form (REQ-RA1-CLAIM-canonical)
    }
    Ok(kid_str.clone())
}

/// Validates the payload against the closed claim table
/// (`REQ-RA1-CLAIM-closed-required`): exactly `{v:1, jti, key_id,
/// public_key, role, nbf, exp}`, every member required, no other member
/// accepted, a numeric member encoded as a float invalid. `jti` is a
/// non-empty bounded StringOrURI (grant-`jti` rules), `key_id` follows the
/// `kid` rules, `public_key` is canonical base64url of exactly 32 raw bytes,
/// `role` is exactly `"issuer"` or `"holder"`, and `nbf < exp`
/// (`REQ-RA1-CLAIM-window`). Canonical form: the payload segment bytes MUST
/// equal the exact JCS re-encoding of the payload.
fn validate_attestation_payload(
    payload: &JsonValue,
    payload_bytes: &[u8],
    bounds: &Bounds,
) -> Result<AttestationPayload> {
    let members = match payload {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    let mut version = None;
    let mut jti = None;
    let mut key_id = None;
    let mut public_key = None;
    let mut role = None;
    let mut nbf = None;
    let mut exp = None;
    for (name, val) in members {
        match name.as_str() {
            "v" => version = Some(val),
            "jti" => jti = Some(val),
            "key_id" => key_id = Some(val),
            "public_key" => public_key = Some(val),
            "role" => role = Some(val),
            "nbf" => nbf = Some(val),
            "exp" => exp = Some(val),
            _ => return Err(Invalid), // REQ-RA1-CLAIM-closed-required
        }
    }
    // v MUST be exactly the integer 1 (REQ-RA1-CLAIM-v; `1.0` decodes to
    // Float and is rejected).
    match version {
        Some(JsonValue::Int(1)) => {}
        _ => return Err(Invalid),
    }
    let jti = take_string_or_uri(jti, bounds)?;
    let key_id = take_kid(key_id, bounds)?;
    let public_key = take_public_key(public_key, bounds)?;
    let role = take_role(role)?;
    let not_before = take_integral_date(nbf)?;
    let expires_at = take_integral_date(exp)?;
    // REQ-RA1-CLAIM-window: nbf < exp (the acceptance window is [nbf, exp) —
    // nonempty).
    if not_before >= expires_at {
        return Err(Invalid);
    }
    if jcs_encode(payload, bounds)?.as_slice() != payload_bytes {
        return Err(Invalid); // canonical form (REQ-RA1-CLAIM-canonical)
    }
    Ok(AttestationPayload {
        jti,
        key_id,
        public_key,
        role,
        not_before,
        expires_at,
    })
}

// ============================================================================
// Internal helpers — claim-type extraction + the shared BAP1 scalar rules
// (the same private-helper-per-façade set the v2/v3 façades carry)
// ============================================================================

/// Decodes one canonical base64url segment under the caller's bounds
/// (`REQ1-BOUNDS-ordering`: the encoded byte ceiling precedes decoding, the
/// decoded byte ceiling precedes JSON parsing).
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

/// Resolves the caller's nested bounds: `None` = the profile maximum
/// (tighten-only by `Bounds::new` construction).
fn resolve_bounds(nested: Option<&Bounds>) -> Bounds {
    match nested {
        None => Bounds::maximum(),
        Some(b) => *b,
    }
}

/// Converts a base64url byte vector to a `String` (the output is always valid
/// ASCII; the `map_err` keeps the failure closed regardless).
fn b64url_to_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Invalid)
}

/// Extracts a non-empty StringOrURI (≤ `identifier_bytes`) — the grant-`jti`
/// rule set `REQ-RA1-CLAIM-jti` pins. `None` (claim absent) → `Invalid`.
fn take_string_or_uri(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_identifier(s, bounds)?;
    Ok(s.clone())
}

/// Extracts the subject `key_id` under the `kid` rules
/// (`REQ-RA1-CLAIM-key-id`). `None` → `Invalid`.
fn take_kid(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_kid(s, bounds)?;
    Ok(s.clone())
}

/// Extracts `public_key`: a string whose canonical base64url decodes to
/// exactly 32 raw Ed25519 bytes (`REQ-RA1-CLAIM-public-key`). `None` →
/// `Invalid`.
fn take_public_key(value: Option<&JsonValue>, bounds: &Bounds) -> Result<[u8; 32]> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    // encoded_segment_bytes is the b64u-string ceiling for a fixed-width key.
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

/// Extracts `role`: exactly the string `"issuer"` or `"holder"`
/// (`REQ-RA1-CLAIM-role-closed-set`). `None` → `Invalid`.
fn take_role(value: Option<&JsonValue>) -> Result<Role> {
    match value {
        Some(JsonValue::String(s)) if s == "issuer" => Ok(Role::Issuer),
        Some(JsonValue::String(s)) if s == "holder" => Ok(Role::Holder),
        _ => Err(Invalid),
    }
}

/// Extracts an integral NumericDate (`JsonValue::Int` only — a float lexeme
/// such as `1735689600.0` decodes to `Float` and is rejected,
/// `REQ-RA1-CLAIM-closed-required`). `None` → `Invalid`.
fn take_integral_date(value: Option<&JsonValue>) -> Result<i64> {
    match value {
        Some(JsonValue::Int(n)) => Ok(*n),
        _ => Err(Invalid),
    }
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

/// Validates a StringOrURI / identifier scalar — the BAP1 rule set: a
/// colon-free value is a PLAIN string (any valid UTF-8 — a Rust `&str`
/// guarantees it); a colon-bearing value is a URI whose scheme is valid, every
/// byte is alnum / URI-punctuation / a well-formed `%HH` escape, and (for a
/// `://` authority) the port is all-digit.
fn validate_identifier(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.identifier_bytes() {
        return Err(Invalid);
    }
    match s.find(':') {
        None => Ok(()), // plain string — any valid UTF-8
        Some(colon) => {
            validate_scheme(&s[..colon])?;
            validate_uri_bytes(s.as_bytes())?;
            validate_authority_port(s)?;
            Ok(())
        }
    }
}

/// Structural authority/port gate: when the identifier has an authority
/// (`://authority`), a `:` in the authority outside an IP-literal bracket
/// MUST introduce an all-digit port.
fn validate_authority_port(value: &str) -> Result<()> {
    let after_scheme_host = match value.find("://") {
        Some(i) => &value[i + 3..],
        None => return Ok(()), // no authority (e.g. `urn:…`)
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

/// Every byte is alphanumeric, one of the URI punctuation bytes
/// `-._~:/?#[]@!$&'()*+,;=`, or part of a well-formed `%HH` percent-escape.
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
