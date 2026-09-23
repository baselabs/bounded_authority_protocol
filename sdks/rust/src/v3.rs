//! Façade — the public v3 verification entry points (contract-major 3,
//! suite `BAP3-ES256-SHA256`).
//!
//! The v3 profile is the v1 wire contract carried at major 3 under the
//! ES256 signature suite (spec/bap-v3.md §2, `REQ3-CORE-v1-incorporation`):
//! every payload validator below requires `"v": 3` and every domain
//! separator is `BAP3-*` (`BAP3-REQUEST\0`, `BAP3-CHAIN\0`,
//! `BAP3-ARCHIVE\0EXPORT\0`), so v3 bytes never verify under v1/v2 and vice
//! versa (`REQ3-CORE-cross-major-reject`: a v3 verifier rejects EVERY
//! artifact whose `v` is not exactly `3`, including all v1 and v2 artifacts,
//! with the single closed error). The signature suite changes from
//! EdDSA/Ed25519 to ECDSA over NIST P-256 with SHA-256 (`alg: "ES256"`): the
//! proof JWK is the EC form `{crv:"P-256", kty:"EC", x, y}`, the RFC 7638
//! thumbprint runs over exactly that member set, raw public keys are the
//! 65-byte uncompressed SEC1 point `0x04||x||y`, and signatures are the
//! RFC 7518 §3.4 raw 64-byte `r||s` with low-S enforced at verification
//! (`REQ3-SIGNING-low-s`). The selector algebra is the v2 algebra unchanged
//! — the FIVE kinds `{all, equals, one_of, lte, gte}`
//! ([`selector::evaluate_v2`], spec/bap-v3.md §4).
//!
//! Derivation hygiene mirrors the v1/v2 façades (ADR 0014 D5): derived from
//! `spec/bap-v3.md`, `spec/bap-v1.md` (incorporated with the §2
//! substitutions), `spec/bap-v2.md` §4, and the certified v3 conformance
//! corpus (`conformance/corpus-v3/`) — NOT from the Elixir v3 implementation
//! or any sibling-SDK source. `REQ1-*`/`REQ2-*` citations below name the
//! incorporated requirement of the same name; v3 carries them as
//! `REQ3-*` (spec/bap-v3.md §6).
//!
//! This is a **silent-auth-class surface**: a header/claim closed-set leak,
//! a cross-major confusion, a permissive JWK/point gate, or a single wrong
//! signing-input byte is a wrong verdict. Every reject collapses to exactly
//! [`Invalid`](crate::Invalid) with no value leak. Verification is not
//! authority: facts carry `authorization`/`trust: NotEvaluated` and there is
//! no `allowed?` anywhere.
//!
//! The v3 profile has no local-loopback application-proof typ (the loopback
//! profile is bound to contract-major 1, spec/bap-v3.md §2): the
//! byte-distinct loopback kinds stay closed out of this façade.

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::compact;
use crate::digest;
use crate::error::{Invalid, Result};
use crate::es256;
use crate::facts::{
    AnchorFacts, AnchoredExportFacts, ChainFacts, EnvelopeFacts, GrantFacts, KeyTransitionFacts,
    NotEvaluated,
};
use crate::jcs::jcs_encode;
use crate::json::{json_decode, JsonValue};
use crate::selector;
use crate::types::{
    AnchoredExportEncoded, AnchoredExportInput, ArchivedObject, ChainInput, ConsumptionEntry,
    Credentials, ExpectedAnchor, ExpectedAnchoredExport, ExpectedChain, ExpectedExport,
    ExpectedGrant, ExpectedKeyTransition, GrantDecoded, GrantInput, KeyLocator, NonceMode,
    ProducedSigningInput, ProofDecoded, SigningInput, SigningKind, ValidityUpperBound,
};
use crate::uri::uri_normalize;

use sha2::{Digest, Sha256};

// ============================================================================
// request_digest — the v3 auth-binding primitive
// ============================================================================

/// Compute the v3 request digest.
///
/// The identical typed projection and JCS preimage as the v1/v2 primitives,
/// hashed under `BAP3-REQUEST\0` (`REQ3-SIGNING-digest-prefix`) — no two
/// majors share a request-binding domain (a v1/v2 `ba_req` can never satisfy
/// a v3 binding).
pub fn request_digest(
    operation: &str,
    cast_arguments: &JsonValue,
    bounds: &Bounds,
) -> Result<Vec<u8>> {
    digest::request_digest_v3(operation, cast_arguments, bounds)
}

// ============================================================================
// Constants — closed header/claim member values (suite BAP3-ES256-SHA256)
// ============================================================================

const ALG_ECDSA_P256: &str = "ES256";
const TYP_GRANT: &str = "ba+cap";
const TYP_PROOF: &str = "dpop+jwt";
const TYP_CHAIN_ANCHOR: &str = "ba+chain-anchor";
const TYP_KEY_TRANSITION: &str = "ba+key-transition";
const CRV_NIST: &str = "P-256";
const KTY_EC: &str = "EC";

/// The ASCII domain-separation prefix for the consumption row-domain hash,
/// including its FINAL NUL byte — the same `REQ1-SIGNING-digest-prefix`
/// pattern as `BAP3-REQUEST\0` (the v3 request digest), carried at major 3
/// (`REQ3-SIGNING-digest-prefix` incorporation).
///
/// `"BAP3-CHAIN\0"` = `[B, A, P, 3, -, C, H, A, I, N, 0x00]` (10 ASCII + 1
/// NUL = 11 bytes — confirmed byte-exact against the v3 corpus entry.json
/// row-domain hash). The final zero byte is load-bearing (ADR 0004 §
/// Consumption rows: `SHA-256("BAP3-CHAIN\0" || canonical_row_bytes)`).
const CHAIN_DIGEST_PREFIX: &[u8] = b"BAP3-CHAIN\0";

/// The 20-byte archive magic prefix (ADR 0004 § Anchored export, carried at
/// major 3): the exact ASCII bytes `BAP3-ARCHIVE\0EXPORT\0` (12 + NUL + 6 +
/// NUL = 20). Confirmed byte-exact against the v3 corpus
/// `anchored-export/verify.json` `chunks[0]`.
const ARCHIVE_MAGIC: &[u8] = b"BAP3-ARCHIVE\0EXPORT\0";

// ============================================================================
// v3 input types — the 65-byte-key family
// ============================================================================
//
// The shared `types` structs are reused everywhere a v1/v2 struct carries no
// key material (ExpectedGrant, ExpectedRequest's scalar fields via the v3
// struct below, ChainInput/ExpectedChain/ConsumptionEntry, ExpectedAnchor,
// ExpectedKeyTransition, ExpectedExport/ExpectedAnchoredExport,
// ArchivedObject, AnchoredExportInput, SigningInput/SigningKind, Credentials,
// KeyLocator, GrantInput/GrantOperation, and every decoded/fact struct).
// Only the structs whose key field is the suite's raw public key fork here:
// the v3 raw form is the 65-byte uncompressed SEC1 point
// (`REQ3-KEY-uncompressed-sec1`), not the v1/v2 32-byte Ed25519 key.

/// A caller-trusted v3 issuer key: exact `kid` + raw 65-byte uncompressed
/// SEC1 P-256 public key (`0x04 || x || y`, `REQ3-KEY-uncompressed-sec1`).
///
/// The verifier accepts public keys only (`REQ1-HEADER-no-private-jwk`
/// incorporated); there is no field for a private exponent. Sourced from the
/// v3 corpus `grant-verify` / `envelope/check` `trusted_issuer`
/// `key_id`+`public_key` members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    /// The exact key ID (`kid`) the grant protected header must carry.
    pub key_id: String,
    /// The raw 65-byte uncompressed SEC1 P-256 public key
    /// (`REQ3-BOUNDS-fixed-widths`).
    pub public_key: [u8; es256::PUBLIC_KEY_WIDTH],
}

/// Caller expectation for combined envelope verification (`check_envelope`)
/// at major 3 — the v1/v2 `ExpectedRequest` shape with the v3 trusted-issuer
/// key width. Embeds the trusted issuer because `check_envelope(Credentials,
/// ExpectedRequest)` takes no separate trusted-issuer argument.
#[derive(Debug, Clone)]
pub struct ExpectedRequest {
    // --- ExpectedGrant fields (the envelope re-verifies the grant) ---
    /// Expected grant `iss`.
    pub issuer: String,
    /// Expected audience.
    pub audience: String,
    /// Integral evaluation time (seconds).
    pub evaluation_time: i64,
    /// Nonnegative clock skew (seconds); at most 60.
    pub skew: u64,
    /// Tightening bounds (defaults to [`Bounds::maximum()`]).
    pub bounds: Bounds,
    // --- Request-specific expected context ---
    /// Case-sensitive RFC 9110 HTTP method token (`htm`).
    pub method: String,
    /// Already-normalized HTTPS target URI (`htu`, `REQ1-URI-pre-normalized`).
    pub target_uri: String,
    /// Lowercase RFC 4122 invocation UUID (`ba_inv`).
    pub invocation_id: String,
    /// Operation name (`ba_op`).
    pub operation: String,
    /// Tagged JSON cast arguments (the server-derived arguments the
    /// selectors apply against).
    pub cast_arguments: JsonValue,
    /// Positive proof maximum age (seconds); at most 300.
    pub proof_max_age: u64,
    /// Caller's nonce policy (`:not_required | {:required, nonce}`).
    pub nonce_mode: NonceMode,
    /// The trusted issuer the grant must be signed by.
    pub trusted_issuer: TrustedIssuer,
}

/// A historical v3 public key with its validity interval — the v1/v2
/// `HistoricalPublicKey` shape with the 65-byte EC key width. Used by
/// `verify_historical_anchor` (one key), `verify_key_transition` (current +
/// next), and `verify_anchored_export` (an ordered chain via
/// [`HistoricalKeyChain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalPublicKey {
    /// The key's `kid`.
    pub key_id: String,
    /// Raw 65-byte uncompressed SEC1 P-256 public key.
    pub public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    /// Lower validity bound (integral NumericDate, always bounded).
    pub valid_from: i64,
    /// Upper validity bound (bounded NumericDate or
    /// [`ValidityUpperBound::Unbounded`] — the only open upper interval).
    pub valid_before: ValidityUpperBound,
}

/// Ordered historical public-key chain a v3 anchored export advances through
/// (positional order is load-bearing, ADR 0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalKeyChain {
    /// Ordered historical keys (start key first).
    pub keys: Vec<HistoricalPublicKey>,
}

/// A boundary anchor the v3 producer frames into a compact signing input —
/// the v1/v2 `BoundaryAnchor` shape with the 65-byte EC key width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryAnchor {
    /// The anchor identity.
    pub anchor_id: String,
    /// The anchor time (integral NumericDate).
    pub anchored_at: i64,
    /// Raw 32-byte chain hash (all-zero for sequence zero).
    pub chain_hash: [u8; 32],
    /// The chain identity.
    pub chain_id: String,
    /// The signing key's `kid`.
    pub key_id: String,
    /// Raw 65-byte uncompressed SEC1 P-256 public key (the producer derives
    /// the EC RFC 7638 fingerprint).
    pub public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    /// Anchor sequence (zero for a start anchor).
    pub sequence: i64,
}

/// A historical key transition the v3 producer frames into a compact signing
/// input — the v1/v2 `KeyTransition` shape with the 65-byte EC key widths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTransition {
    /// The chain identity.
    pub chain_id: String,
    /// The current (signing) key's `kid`.
    pub current_key_id: String,
    /// Raw 65-byte current P-256 public key (signs the transition).
    pub current_public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    /// Effective time of the transition (integral NumericDate).
    pub effective_at: i64,
    /// The next key's `kid`.
    pub next_key_id: String,
    /// Raw 65-byte next P-256 public key.
    pub next_public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    /// The transition identity.
    pub transition_id: String,
}

/// The structured v3 proof fields the proof producer frames into a signing
/// input — the v1/v2 `ProofInput` shape with the 65-byte EC holder key. The
/// producer derives `ath`, `ba_req` (under `BAP3-REQUEST\0`), `htu`, and the
/// header `jwk` in the EC canonical form.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofInput {
    /// Expected `jti` claim (proof identifier).
    pub proof_id: String,
    /// Expected `htm` claim (case-sensitive RFC 9110 method token).
    pub method: String,
    /// The target URI; the producer normalizes it into the `htu` claim.
    pub target_uri: String,
    /// Expected `ba_inv` claim (lowercase RFC 4122 invocation UUID).
    pub invocation_id: String,
    /// Expected `ba_op` claim (operation name).
    pub operation: String,
    /// Tagged JSON cast arguments — the `ba_req` digest preimage (NOT emitted
    /// in the payload; only its digest is).
    pub cast_arguments: JsonValue,
    /// The received grant compact bytes — the `ath` hash preimage.
    pub grant_compact: Vec<u8>,
    /// Raw 65-byte uncompressed SEC1 P-256 holder public key (the header
    /// `jwk` source).
    pub holder_public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    /// Proof `iat` (integral NumericDate).
    pub issued_at: i64,
}

// ============================================================================
// The EC JWK + RFC 7638 thumbprint family (suite-bound, spec/bap-v3.md §3.1)
// ============================================================================

/// Encode a 65-byte uncompressed SEC1 P-256 public key as the canonical EC
/// JWK JSON object.
///
/// Emits the four RFC 7638 preimage members in their lexicographic
/// (`crv`, `kty`, `x`, `y`) order, with no whitespace and no additional
/// members (`REQ3-HEADER-proof-jwk`):
///
/// ```json
/// {"crv":"P-256","kty":"EC","x":"<canonical_b64url_32>","y":"<canonical_b64url_32>"}
/// ```
///
/// `x`/`y` are the canonical unpadded base64url of the fixed-width 32-byte
/// big-endian coordinates (RFC 7518 §6.2.1.2/§6.2.1.3). Infallible: the
/// 65-byte width and `0x04` prefix are fixed by the parameter type... except
/// the prefix, which IS checked (a compressed-form array cannot occur through
/// the type, but a constructed array with a non-0x04 first byte is rejected
/// rather than mis-encoded).
pub fn jwk_encode_public(public_key: &[u8; es256::PUBLIC_KEY_WIDTH]) -> Result<Vec<u8>> {
    // The uncompressed prefix is a profile constant; reject (rather than
    // silently re-encode) any array that is not `0x04 || x || y`.
    es256::validate_point(public_key)?;
    let x = base64url_encode(&public_key[1..33]);
    let y = base64url_encode(&public_key[33..65]);
    // Exact bytes: no whitespace, crv<kty<x<y order (the RFC 7638 preimage
    // order).
    let mut out = Vec::with_capacity(64 + x.len() + y.len());
    out.extend_from_slice(br#"{"crv":""#);
    out.extend_from_slice(CRV_NIST.as_bytes());
    out.extend_from_slice(b"\",\"kty\":\"");
    out.extend_from_slice(KTY_EC.as_bytes());
    out.extend_from_slice(b"\",\"x\":\"");
    out.extend_from_slice(&x);
    out.extend_from_slice(b"\",\"y\":\"");
    out.extend_from_slice(&y);
    out.extend_from_slice(b"\"}");
    Ok(out)
}

/// Decode an EC JWK JSON text into the 65-byte uncompressed SEC1 P-256
/// public key.
///
/// Parses `text` via the duplicate-rejecting, closed-set JSON decoder
/// (inheriting `REQ1-JSON-no-duplicate`, `REQ1-JSON-single-value`, and the
/// raw-lexeme / magnitude bounds) and then enforces the exact EC JWK shape
/// (`REQ3-HEADER-proof-jwk`). Returns `Err(Invalid)` for any of:
/// - malformed JSON or a non-object root;
/// - a member set other than exactly `{crv, kty, x, y}` — any extra member,
///   including the private `d`, is rejected (`REQ3-HEADER-no-private-jwk`);
/// - `crv` other than `"P-256"` or `kty` other than `"EC"`;
/// - a non-string or wrong-valued `crv` / `kty` / `x` / `y`;
/// - an `x` or `y` that is not canonical unpadded base64url of exactly 32
///   bytes (fixed-width coordinate spelling, RFC 7518 §6.2.1);
/// - coordinates `>= p` or a point not on the curve
///   (`REQ3-KEY-point-on-curve` — pure arithmetic, before any backend).
pub fn jwk_decode_public(text: &[u8]) -> Result<[u8; es256::PUBLIC_KEY_WIDTH]> {
    // Parse under profile maxima (the JWK is a tiny fixed-shape object well
    // within every ceiling; no caller tightening applies at this primitive).
    let value = json_decode(text, &Bounds::maximum())?;
    let members = match value {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };

    // Walk the members, accepting only the four known names and rejecting
    // everything else (catches the private `d`, `kid`, `alg`, and any future
    // extension). The closed-set check is per-member, so a JWK with the right
    // four names PLUS an extra is rejected here, not by a separate count.
    let mut crv = None;
    let mut kty = None;
    let mut x = None;
    let mut y = None;
    for (name, val) in members {
        match name.as_str() {
            "crv" => crv = Some(val),
            "kty" => kty = Some(val),
            "x" => x = Some(val),
            "y" => y = Some(val),
            _ => return Err(Invalid), // unknown member — closed set
        }
    }

    // crv must be exactly the string "P-256".
    match crv {
        Some(JsonValue::String(s)) if s == CRV_NIST => {}
        _ => return Err(Invalid),
    }
    // kty must be exactly the string "EC".
    match kty {
        Some(JsonValue::String(s)) if s == KTY_EC => {}
        _ => return Err(Invalid),
    }
    // x and y must be strings whose canonical base64url decodes to exactly
    // 32 bytes each (the fixed-width unsigned big-endian coordinates).
    let x_str = match x {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    let y_str = match y {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    let x_bytes = base64url_decode(x_str.as_bytes())?;
    if x_bytes.len() != 32 {
        return Err(Invalid);
    }
    let y_bytes = base64url_decode(y_str.as_bytes())?;
    if y_bytes.len() != 32 {
        return Err(Invalid);
    }

    // Reassemble the uncompressed SEC1 point and run the profile's pure
    // arithmetic gate: 0x04 prefix (by construction), coordinates < p, and
    // on-curve (REQ3-KEY-point-on-curve).
    let mut public_key = [0u8; es256::PUBLIC_KEY_WIDTH];
    public_key[0] = 0x04;
    public_key[1..33].copy_from_slice(&x_bytes);
    public_key[33..65].copy_from_slice(&y_bytes);
    es256::validate_point(&public_key)?;
    Ok(public_key)
}

/// The RFC 7638 thumbprint preimage for a P-256 public key.
///
/// Returns the exact UTF-8 bytes of the sorted JSON object
/// `{"crv":"P-256","kty":"EC","x":"<canonical-x>","y":"<canonical-y>"}` —
/// the four required EC members in lexicographic order, no whitespace
/// (`REQ3-HEADER-thumbprint`). This is byte-identical to
/// [`jwk_encode_public`]: for a P-256 EC key the RFC 7638 preimage IS the
/// canonical sorted JWK.
pub fn thumbprint_preimage(public_key: &[u8; es256::PUBLIC_KEY_WIDTH]) -> Result<Vec<u8>> {
    jwk_encode_public(public_key)
}

/// The RFC 7638 thumbprint: unpadded base64url SHA-256 of the preimage
/// bytes (`REQ3-HEADER-thumbprint`).
pub fn thumbprint(public_key: &[u8; es256::PUBLIC_KEY_WIDTH]) -> Result<Vec<u8>> {
    Ok(base64url_encode(&thumbprint_raw(public_key)?))
}

/// The raw 32-byte SHA-256 digest of the thumbprint preimage.
///
/// `REQ3-HEADER-digest-width` (incorporated): verified facts carry the raw
/// 32-byte digest.
pub fn thumbprint_raw(public_key: &[u8; es256::PUBLIC_KEY_WIDTH]) -> Result<[u8; 32]> {
    let preimage = thumbprint_preimage(public_key)?;
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let output = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&output);
    Ok(arr)
}

/// The issuer-key fingerprint: the same RFC 7638 construction over the
/// caller's raw 65-byte public key (`kid` excluded).
///
/// `REQ1-HEADER-issuer-fingerprint` incorporated: the issuer fingerprint uses
/// exactly the same `{crv, kty, x, y}` preimage + SHA-256 as the holder
/// thumbprint — the only difference is naming (the input is the caller's raw
/// trusted key, not a decoded proof JWK). `kid` never enters the preimage.
pub fn public_key_thumbprint_raw(public_key: &[u8; es256::PUBLIC_KEY_WIDTH]) -> Result<[u8; 32]> {
    thumbprint_raw(public_key)
}

// ============================================================================
// untrusted_key_locator
// ============================================================================

/// Bound, split, and validate ONLY the protected grant header; return the
/// `kid` hint with `trust: NotEvaluated`.
///
/// `REQ1-LOCATOR-three-segments` (incorporated): the compact MUST have
/// exactly three segments. `REQ1-LOCATOR-opaque-payload`: the payload and
/// signature segments are NOT decoded, validated, or even required to be
/// non-empty — they stay opaque. `REQ1-LOCATOR-not-authority`: the result is
/// a `kid` hint plus `trust: NotEvaluated`; it selects no key and authorizes
/// nothing. `REQ1-LOCATOR-no-value-leak`: every failure returns `Err(Invalid)`
/// with no input values.
pub fn untrusted_key_locator(compact: &[u8], bounds: &Bounds) -> Result<KeyLocator> {
    // REQ1-BOUNDS-ordering: raw compact size precedes any structural work.
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    // Split into EXACTLY three segments. Unlike parse_compact (which validates
    // every segment as non-empty canonical b64url), the locator leaves the
    // payload+signature segments completely opaque — they may even be empty
    // (the `header..` form). Only the protected segment is examined.
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
/// the ES256 signature.
///
/// Returns a [`GrantDecoded`] carrying the decoded identity/timing claims
/// plus `verification: NotEvaluated` (`REQ1-VERIFY-decode-not-evaluated`
/// incorporated). The protected header is validated against the grant closed
/// set (`REQ3-HEADER-closed-set`); the payload claims against the grant claim
/// table (`REQ1-CLAIM-closed-set` incorporated) with `v: 3` exactly
/// (`REQ3-CLAIM-v`). All three compact segments MUST be non-empty canonical
/// base64url (via [`compact::parse_compact`]).
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
/// proof closed set `{alg:"ES256", typ:"dpop+jwt", jwk:{crv,kty,x,y}}`
/// (`REQ3-HEADER-closed-set`, `REQ3-HEADER-proof-jwk`,
/// `REQ3-HEADER-no-private-jwk`); the payload against the proof claim table
/// with `v: 3` exactly (`REQ3-CLAIM-proof-v`; every claim required except
/// `nonce`).
pub fn decode_proof(compact: &[u8], bounds: &Bounds) -> Result<ProofDecoded> {
    let p = decode_proof_parts(compact, bounds)?;
    let holder_thumbprint = thumbprint_raw(&p.holder_public_key)?;
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
// verify_grant — the grant verification surface (the authz surface)
// ============================================================================
//
// This is the **silent-forgery surface**: a permissive verify silently
// accepts FORGED CREDENTIALS. Every binding — exact key id, exact
// issuer/audience, the ES256 signature (point-form, range, low-S, then the
// backend) over the exact 2-segment signing input, coherent signed times,
// and the three skew invariants — collapses to exactly [`Invalid`] on any
// mismatch (`REQ1-VERIFY-return-shape` incorporated) with no value leak. The
// result is [`GrantFacts`] carrying `authorization: NotEvaluated` —
// verification is not authority (`REQ1-VERIFY-grant-not-authorized`).

/// Verify a grant compact against a trusted issuer and caller expectation.
///
/// Decodes the compact (reusing [`decode_grant_parts`]), then enforces
/// `REQ1-VERIFY-grant-exact` (exact key id, issuer, audience), verifies the
/// ES256 signature over the exact RFC 7515 two-segment signing input
/// (`REQ1-SIGNING-exact-input`, `REQ3-SIGNING-backend-reject`), and checks
/// the signed-time coherence (`REQ1-VERIFY-grant-times`: `iat < exp` and
/// `nbf < exp`; `iat <= nbf` is NOT required) plus the three skew invariants
/// (`REQ1-VERIFY-time-bounds`):
///
/// ```text
/// iat <= evaluation_time + skew
/// nbf <= evaluation_time + skew
/// exp >  evaluation_time - skew
/// ```
///
/// Returns [`GrantFacts`] carrying the raw 32-byte issuer-key fingerprint
/// (the EC RFC 7638 construction over the caller's trusted key), the decoded
/// `cnf.jkt` holder thumbprint, the matched audience, the grant times, and
/// `authorization: NotEvaluated`.
pub fn verify_grant(
    compact: &[u8],
    issuer: &TrustedIssuer,
    expected: &ExpectedGrant,
) -> Result<GrantFacts> {
    // REQ1-VERIFY-time-bounds: the caller's skew MUST NOT exceed the profile
    // ceiling. A value above the ceiling silently widens the time window
    // (future iat/nbf, expired exp accepted); reject it before any time
    // arithmetic.
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
    // (ASCII(base64url(protected) || "." || base64url(payload))). The ES256
    // path runs the profile gates (65-byte uncompressed point, on-curve, <
    // p; 64-byte raw r||s; zero/range/low-S) then the backend.
    let sig_raw = base64url_decode(g.signature_seg)?;
    if sig_raw.len() != 64 {
        return Err(Invalid); // REQ3-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_raw);
    let signing_input = signing_input_bytes(g.protected_seg, g.payload_seg);
    es256::verify(&issuer.public_key, &signing_input, &signature)?;

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

    let issuer_key_fingerprint = public_key_thumbprint_raw(&issuer.public_key)?;
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
// check_envelope — combined envelope verification
// ============================================================================
//
// The **highest-stakes silent-forgery surface**: a permissive check_envelope
// silently accepts a proof bound to a DIFFERENT grant, a different holder, a
// different request, or a replayed/stale proof. Combined verification
// re-verifies the raw grant; verifies the holder ES256 signature + EC RFC
// 7638 thumbprint binding (the proof's holder key MUST be the grant's
// `cnf.jkt`); and binds `ath` (SHA-256 over the EXACT RECEIVED grant
// compact), method, URI, invocation, operation, `ba_req` (BAP3-domain),
// proof time window, nonce mode, and every selector
// (`REQ1-VERIFY-envelope-binding` incorporated). A v3 proof MUST pair with a
// v3 grant end-to-end (`REQ3-EVO-proof-major-equals-grant`,
// `REQ3-EVO-mixed-major-invalid`): both artifacts carry `v: 3` through their
// own closed checks, so a mixed-major pair fails by construction. Every
// mismatch → `Err(Invalid)`.

/// Verify a holder proof bound to a grant against a caller's expected request.
///
/// Re-verifies the raw grant (via [`verify_grant`]); decodes the proof and
/// verifies the holder ES256 signature; binds the proof header JWK's EC RFC
/// 7638 thumbprint to the grant's `cnf.jkt` (holder binding); and enforces
/// every request binding: `ath` over the received grant compact
/// (`REQ1-CLAIM-ath`), `ba_req`, `htm` method, `htu` URI, `ba_inv`
/// invocation, `ba_op` operation (which MUST name a grant operation), the
/// proof time window, the nonce mode (`REQ1-VERIFY-nonce-mode`), and every
/// selector of the matched grant operation via [`selector::evaluate_v2`]
/// (the v2 algebra incorporated at major 3, spec/bap-v3.md §4).
///
/// Returns [`EnvelopeFacts`] embedding the re-verified [`GrantFacts`] plus
/// the proof identity, the normalized URI, the raw grant/request hashes, the
/// proof issuance time, and `authorization: NotEvaluated`.
pub fn check_envelope(
    credentials: &Credentials,
    expected: &ExpectedRequest,
) -> Result<EnvelopeFacts> {
    let bounds = &expected.bounds;

    // REQ1-VERIFY-time-bounds: proof_max_age MUST be positive AND MUST NOT
    // exceed the profile ceiling. A zero proof_max_age would admit any proof
    // within the skew window (no max-age floor).
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

    // Holder thumbprint binding: the proof header JWK's EC RFC 7638
    // thumbprint MUST equal the grant's cnf.jkt
    // (REQ1-VERIFY-envelope-binding). This binds the proof's holder key to
    // the grant's confirmation.
    let holder_thumb = thumbprint_raw(&proof.holder_public_key)?;
    if holder_thumb != grant_facts.holder_thumbprint {
        return Err(Invalid);
    }

    // Holder signature verify over the proof's 2-segment signing input.
    let proof_sig_raw = base64url_decode(proof.signature_seg)?;
    if proof_sig_raw.len() != 64 {
        return Err(Invalid); // REQ3-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    let mut proof_signature = [0u8; 64];
    proof_signature.copy_from_slice(&proof_sig_raw);
    let proof_signing_input = signing_input_bytes(proof.protected_seg, proof.payload_seg);
    es256::verify(
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

    // ba_req binding: request_digest(operation, cast_arguments) under
    // BAP3-REQUEST\0 MUST equal the proof's ba_req.
    let ba_req_b64u =
        digest::request_digest_v3(&expected.operation, &expected.cast_arguments, bounds)?;
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

    // operation binding: proof ba_op MUST equal the expected operation, AND
    // the grant MUST carry an operation of that name whose selectors are then
    // evaluated against the cast arguments.
    if proof.payload.operation != expected.operation {
        return Err(Invalid);
    }
    let matched_op = operations
        .iter()
        .find(|(name, _)| name == &expected.operation)
        .ok_or(Invalid)?;
    // REQ1-VERIFY-envelope-binding: EVERY selector of the matched operation
    // MUST evaluate Ok(true) against the cast arguments (the v2 range
    // algebra incorporated, spec/bap-v3.md §4).
    for selector_value in &matched_op.1 {
        if !selector::evaluate_v2(selector_value, &expected.cast_arguments, bounds)? {
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

/// Faithful port of the reference `CompactJws.scan`: the compact MUST be ≤
/// `compact_bytes` and split into exactly three non-empty segments (split on
/// `.`), the protected and payload each ≤ `encoded_segment_bytes`, and the
/// signature non-empty, ≤ `encoded_segment_bytes`, and dot-free. Unlike
/// [`compact::parse_compact`], this does NOT require the segments be
/// canonical base64url — the reference's scan gates hashing (`ath`/`hash`),
/// not verification, so a non-canonical segment like `a!a` passes.
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
/// with the per-kind CONTENT validation (it re-parses the composed output as
/// a grant/proof/anchor/transition). `None` bounds = the profile maximum. A
/// caller passing segments that compose to a structurally-invalid credential
/// — wrong segment count, non-canonical base64url, or a header/payload that
/// does not parse as the declared kind's closed header/claim set — is
/// rejected.
pub fn assemble_compact(
    input: &SigningInput,
    signature: &[u8; 64],
    bounds: Option<&Bounds>,
) -> Result<Vec<u8>> {
    let bounds = resolve_bounds(bounds);
    if input.protected_segment.len() as u64 > bounds.encoded_segment_bytes()
        || input.payload_segment.len() as u64 > bounds.encoded_segment_bytes()
    {
        return Err(Invalid);
    }
    // (signature_bytes needs no gate: it is a FIXED-WIDTH key rejected at
    // Bounds construction unless 64 — the reference's assemble-time check is
    // subsumed; the v3 raw r||s spelling is the same 64-byte width.)
    let compact = compact::compose_compact(input, signature)?;
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    match input.kind {
        SigningKind::Grant => {
            decode_grant_parts(&compact, &bounds)?;
        }
        SigningKind::Proof => {
            decode_proof_parts(&compact, &bounds)?;
        }
        // The v3 profile has no local-loopback application-proof typ (the
        // loopback profile is bound to contract-major 1, spec/bap-v3.md §2):
        // the byte-distinct loopback kind stays closed out (corpus
        // `assemble-compact-v3-invalid-local-loopback-kind`).
        SigningKind::LocalLoopbackHttpProof => {
            return Err(Invalid);
        }
        // The v3 profile parses no role-attestation typ: the standalone
        // sibling profile's bytes stay closed out of this façade
        // (`REQ-RA1-CORE-cross-profile-reject`).
        SigningKind::RoleAttestation => {
            return Err(Invalid);
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

/// Produce the deterministic grant signing input from structured grant
/// fields.
///
/// Emits one canonical JCS representation (`REQ1-SIGNING-deterministic-
/// produce` incorporated) of the protected header
/// `{alg:"ES256", kid, typ:"ba+cap"}` and the grant payload (with `v: 3`,
/// `REQ3-CLAIM-v`), then assembles `ASCII(base64url(protected) || "." ||
/// base64url(payload))` (`REQ1-SIGNING-exact-input`). The corpus pins all
/// three of `protected_segment`, `payload_segment`, and `message`
/// byte-exact.
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
        for selector in &op.selectors {
            selector::validate_v2(selector, bounds)?;
        }
    }

    // Build header object (JCS sorts members: alg < kid < typ).
    let header = JsonValue::Object(vec![
        (
            "alg".to_string(),
            JsonValue::String(ALG_ECDSA_P256.to_string()),
        ),
        ("kid".to_string(), JsonValue::String(grant.key_id.clone())),
        ("typ".to_string(), JsonValue::String(TYP_GRANT.to_string())),
    ]);

    // Build payload object (member names derived first-hand from the v3
    // corpus's grant payload_segment: aud, cnf.jkt, exp, iat, iss, jti, nbf,
    // operations, v).
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
        ("v".to_string(), JsonValue::Int(3)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// proof_signing_input
// ============================================================================

/// Produce the deterministic proof signing input from structured proof
/// fields.
///
/// Derives `ath = base64url(SHA-256(grant_compact ASCII))` (`REQ1-CLAIM-ath`),
/// `ba_req = request_digest(operation, cast_arguments, bounds)` under
/// `BAP3-REQUEST\0`, and `htu = uri_normalize(target_uri, bounds)`
/// (`REQ1-URI-pre-normalized`). The header `jwk` is built from
/// `holder_public_key` via the canonical EC form.
pub fn proof_signing_input(proof: &ProofInput, bounds: &Bounds) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate.
    validate_identifier(&proof.proof_id, bounds)?;
    validate_method_token(&proof.method, bounds)?;
    validate_operation_name(&proof.operation, bounds)?;
    validate_uuid(&proof.invocation_id)?;
    // The holder key MUST be a valid v3 EC point before it is encoded into
    // the header (a wrong-form key cannot produce a canonical EC JWK).
    es256::validate_point(&proof.holder_public_key)?;
    // htu MUST already be the normal form (REQ1-URI-pre-normalized).
    let htu = uri_normalize(&proof.target_uri, bounds)?;
    if htu != proof.target_uri {
        return Err(Invalid);
    }

    // ath = base64url(SHA-256(grant_compact ASCII bytes)) — REQ1-CLAIM-ath.
    // Gate SHA-256 on the reference `CompactJws.scan`: total <= compact_bytes
    // AND three non-empty segments each <= encoded_segment_bytes (signature
    // dot-free). The scan does NOT require base64url canonicity — it gates
    // hashing, not verification.
    scan_compact(proof.grant_compact.as_slice(), bounds)?;
    let mut ath_hasher = Sha256::new();
    ath_hasher.update(&proof.grant_compact);
    let ath = b64url_to_string(&base64url_encode(&ath_hasher.finalize()))?;

    // ba_req = request_digest(operation, cast_arguments, bounds) under
    // BAP3-REQUEST\0.
    let ba_req = digest::request_digest_v3(&proof.operation, &proof.cast_arguments, bounds)?;
    let ba_req_str = String::from_utf8(ba_req).map_err(|_| Invalid)?;

    // Build header: {alg, jwk:{crv,kty,x,y}, typ}. JCS sorts: alg < jwk <
    // typ; nested jwk: crv < kty < x < y (matches the RFC 7638 preimage
    // order).
    let x = b64url_to_string(&base64url_encode(&proof.holder_public_key[1..33]))?;
    let y = b64url_to_string(&base64url_encode(&proof.holder_public_key[33..65]))?;
    let jwk = JsonValue::Object(vec![
        ("crv".to_string(), JsonValue::String(CRV_NIST.to_string())),
        ("kty".to_string(), JsonValue::String(KTY_EC.to_string())),
        ("x".to_string(), JsonValue::String(x)),
        ("y".to_string(), JsonValue::String(y)),
    ]);
    let header = JsonValue::Object(vec![
        (
            "alg".to_string(),
            JsonValue::String(ALG_ECDSA_P256.to_string()),
        ),
        ("jwk".to_string(), jwk),
        ("typ".to_string(), JsonValue::String(TYP_PROOF.to_string())),
    ]);

    // Build payload (member names derived first-hand from the v3 corpus's
    // proof payload_segment: ath, ba_inv, ba_op, ba_req, htm, htu, iat, jti,
    // v).
    let payload_members = vec![
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
        ("v".to_string(), JsonValue::Int(3)),
    ];
    let payload = JsonValue::Object(payload_members);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// boundary_anchor_signing_input
// ============================================================================

/// Produce the deterministic boundary-anchor signing input.
///
/// The protected header is `{alg:"ES256", kid, typ:"ba+chain-anchor"}` (the
/// v1 form with the ES256 substitution, spec/bap-v3.md §3.3). The payload
/// binds protocol version (`v: 3`), anchor identity+time, chain identity,
/// sequence, the chain hash, and the EC RFC 7638 fingerprint derived from
/// `public_key`. Sequence zero requires the all-zero chain hash.
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
    // The signing key MUST be a valid v3 EC point (the fingerprint is derived
    // from its canonical EC JWK form).
    es256::validate_point(&anchor.public_key)?;
    // Sequence zero requires the all-zero chain hash (ADR 0004 § Boundary
    // anchors; corpus `boundary-anchor-signing-input-v3-invalid-*`).
    if anchor.sequence == 0 && anchor.chain_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }

    let header = JsonValue::Object(vec![
        (
            "alg".to_string(),
            JsonValue::String(ALG_ECDSA_P256.to_string()),
        ),
        ("kid".to_string(), JsonValue::String(anchor.key_id.clone())),
        (
            "typ".to_string(),
            JsonValue::String(TYP_CHAIN_ANCHOR.to_string()),
        ),
    ]);

    // Payload members derived first-hand from the v3 corpus's anchor
    // payload_segment: anchor_id, anchored_at, chain_hash, chain_id,
    // key_fingerprint, sequence, v.
    let chain_hash_str = b64url_to_string(&base64url_encode(&anchor.chain_hash))?;
    let fingerprint = public_key_thumbprint_raw(&anchor.public_key)?;
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
        ("v".to_string(), JsonValue::Int(3)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// key_transition_signing_input
// ============================================================================

/// Produce the deterministic historical key-transition signing input.
///
/// The protected header is `{alg:"ES256", kid:current_key_id,
/// typ:"ba+key-transition"}`. The payload binds transition+chain identities,
/// effective time, the current key EC fingerprint
/// (`from_key_fingerprint`), the next key id (`to_key_id`), and the next
/// fingerprint (`to_key_fingerprint`), with `v: 3`. The current and next
/// public keys MUST differ.
pub fn key_transition_signing_input(
    transition: &KeyTransition,
    bounds: &Bounds,
) -> Result<ProducedSigningInput> {
    // REQ1-VERIFY-revalidate.
    validate_kid(&transition.current_key_id, bounds)?;
    validate_kid(&transition.next_key_id, bounds)?;
    validate_identifier(&transition.chain_id, bounds)?;
    validate_identifier(&transition.transition_id, bounds)?;
    // Both keys MUST be valid v3 EC points (their fingerprints are derived
    // from the canonical EC JWK forms).
    es256::validate_point(&transition.current_public_key)?;
    es256::validate_point(&transition.next_public_key)?;
    // Current and next public keys MUST differ (corpus
    // `key-transition-signing-input-v3-invalid-same-keys`); their key IDs may
    // equal.
    if transition.current_public_key == transition.next_public_key {
        return Err(Invalid);
    }

    let header = JsonValue::Object(vec![
        (
            "alg".to_string(),
            JsonValue::String(ALG_ECDSA_P256.to_string()),
        ),
        (
            "kid".to_string(),
            JsonValue::String(transition.current_key_id.clone()),
        ),
        (
            "typ".to_string(),
            JsonValue::String(TYP_KEY_TRANSITION.to_string()),
        ),
    ]);

    // Payload members derived first-hand from the v3 corpus's transition
    // payload_segment: chain_id, effective_at, from_key_fingerprint,
    // to_key_fingerprint, to_key_id, transition_id, v.
    let from_fp = public_key_thumbprint_raw(&transition.current_public_key)?;
    let to_fp = public_key_thumbprint_raw(&transition.next_public_key)?;
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
        ("v".to_string(), JsonValue::Int(3)),
    ]);

    build_produced(&header, &payload, bounds)
}

// ============================================================================
// Façade B — consumption entry + chain verification
// ============================================================================
//
// This is a **silent-relink surface**: a permissive chain check silently
// certifies a relinked, shortened, or omitted archive. Every invariant —
// canonical re-encode, genesis binding, predecessor links, and the caller
// head/predecessor/sequence/count boundaries — collapses to exactly
// [`Invalid`](crate::Invalid) on any mismatch. [`ChainFacts`] carries
// `trust: NotEvaluated` and makes no `authorization` field part of its
// shape. A self-consistent chain does NOT certify completeness
// (`REQ1-CHAIN-no-deletion-cert` incorporated): a validly shortened or
// relinked range fails only against the ORIGINAL caller boundaries.

/// Encode one canonical consumption row and compute its row-domain hash.
///
/// Builds the closed JCS row object
/// `{"chain_id","commitment","previous","sequence","v":3}` (ADR 0004 §
/// Consumption rows carried at major 3), enforces `sequence >= 1` and the
/// genesis binding (`sequence == 1` requires the all-zero predecessor),
/// bounds the canonical bytes by `bounds.chain_row_bytes()`, and returns
/// `(canonical_bytes, SHA-256("BAP3-CHAIN\0" || canonical_bytes))`.
///
/// The corpus `entry.json` `input.previous_hash` (a base64url string) maps
/// to the row member `previous`; the producer adds `v: 3`. The corpus pins
/// `bytes` (the canonical ASCII) and `hash` (the base64url row-domain hash)
/// byte-exact.
pub fn encode_consumption_entry(
    entry: &ConsumptionEntry,
    bounds: &Bounds,
) -> Result<(Vec<u8>, [u8; 32])> {
    // sequence MUST be a positive integer (corpus invalid-zero-sequence).
    if entry.sequence < 1 {
        return Err(Invalid);
    }
    // chain_id is a StringOrURI identifier, not an arbitrary string:
    // non-empty, <= identifier_bytes, valid scheme if `:`-bearing.
    validate_identifier(&entry.chain_id, bounds)?;
    // Genesis binding: sequence 1 requires the all-zero predecessor (corpus
    // invalid-seq1-nonzero-previous). A sequence > 1 MAY carry any
    // predecessor — the encoder does not know the prior row's hash; the
    // verifier binds it.
    if entry.sequence == 1 && entry.previous_hash.iter().any(|&b| b != 0) {
        return Err(Invalid);
    }

    let previous_str = b64url_to_string(&base64url_encode(&entry.previous_hash))?;
    let commitment_str = b64url_to_string(&base64url_encode(&entry.commitment))?;
    // Member names + order derived first-hand from ADR 0004 § Consumption
    // rows + the v3 corpus entry.json expected.bytes: chain_id, commitment,
    // previous, sequence, v (already in JCS / UTF-16-sorted order).
    let row = JsonValue::Object(vec![
        (
            "chain_id".to_string(),
            JsonValue::String(entry.chain_id.clone()),
        ),
        ("commitment".to_string(), JsonValue::String(commitment_str)),
        ("previous".to_string(), JsonValue::String(previous_str)),
        ("sequence".to_string(), JsonValue::Int(entry.sequence)),
        ("v".to_string(), JsonValue::Int(3)),
    ]);

    let canonical = jcs_encode(&row, bounds)?;
    // REQ1-CHAIN-raw-rows-bounds: the canonical row is bounded by
    // chain_row_bytes.
    if canonical.len() as u64 > bounds.chain_row_bytes() {
        return Err(Invalid);
    }
    let hash = row_domain_hash(&canonical);
    Ok((canonical, hash))
}

/// Verify a bounded range of raw canonical consumption rows against the
/// caller's expected chain boundaries.
///
/// `input.rows` is the nonempty proper list of raw canonical row binaries;
/// `expected` carries the caller's intended chain identity, sequence span,
/// row count, predecessor, and head (`REQ1-CHAIN-no-deletion-cert`).
/// Verification requires: the closed row shape
/// `{chain_id, commitment, previous, sequence, v:3}`, exact canonical bytes
/// (a re-`jcs_encode` of each decoded row must equal the received bytes),
/// chain identity, consecutive sequence, the genesis/caller predecessor,
/// predecessor links under `BAP3-CHAIN\0`, row count, last sequence, and the
/// caller head. Every failure is `Err(Invalid)` with no value leak.
pub fn check_chain(input: &ChainInput, expected: &ExpectedChain) -> Result<ChainFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());
    let rows = &input.rows;

    // REQ1-CHAIN-raw-rows-bounds: nonempty + <= chain_rows; each row <=
    // chain_row_bytes.
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

    // Chain identity: validate the identifier shape, then every row's
    // chain_id == expected.chain_id (the rows therefore also agree amongst
    // themselves). Corpus: cross-graft + cross-major rows (v:1/v:2 rows are
    // rejected at the row version check).
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
    // The first row's previous is ALWAYS bound to expected.previous_hash,
    // and when first_sequence == 1 expected.previous_hash MUST be the
    // all-zero hash (a fresh chain has no predecessor, so a
    // caller-inconsistent predecessor is rejected, not attested unchecked
    // into ChainFacts). Corpus: sequence-zero-row + genesis-previous-hash-
    // forge.
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

    // Predecessor links: row i's previous (32 bytes) ==
    // row_domain_hash(row i-1) under BAP3-CHAIN\0.
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
    /// Decoded 32-byte `previous` field (for the genesis + predecessor
    /// checks).
    previous: [u8; 32],
    sequence: i64,
    /// `SHA-256("BAP3-CHAIN\0" || canonical_row_bytes)`.
    hash: [u8; 32],
}

/// Computes `SHA-256("BAP3-CHAIN\0" || canonical_row_bytes)` as a raw 32-byte
/// digest — the v3 row-domain hash (ADR 0004 § Consumption rows carried at
/// major 3).
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
/// canonical re-encode check, and returns the parsed fields plus the
/// row-domain hash.
///
/// Closed row shape: exactly `{chain_id: string, commitment: base64url-32,
/// previous: base64url-32, sequence: int, v: 3}` — no extra members.
/// `commitment` is validated to decode to exactly 32 bytes but otherwise
/// stays opaque (it is neither stored nor compared). The canonical re-encode
/// check rejects any row whose received bytes are not the exact JCS encoding
/// of the decoded value (corpus `check-chain-canonical-reencode` discipline).
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
        Some(JsonValue::Int(3)) => {}
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

    // Canonical re-encode check: re-jcs the decoded value and require
    // byte-exact equality with the received row bytes. A whitespace or
    // member-order variant that decodes identically MUST fail closed
    // (canonical bytes are the hash preimage contract).
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
// Façade D — anchored export verify/encode
// ============================================================================
//
// This is the **silent-relink surface**: a permissive export verify silently
// certifies a RELINKED or SHORTENED archive, and a permissive rollover
// silently accepts a key path with no authenticated transition. Every
// binding — the exact archive bytes (`BAP3-ARCHIVE\0EXPORT\0` magic + frames
// + EOF), the constant-time SHA-256 digest, the out-of-band object-store
// version, the closed header, the authenticated start/end anchors, the
// positional key-transition path, the chronology, the surplus-key invariant
// (`keys.len() == transitions.len() + 1`), and the re-checked row-domain
// hash chain — collapses to exactly [`Invalid`] on any mismatch.
// [`AnchoredExportFacts`] is the ONLY chain-family fact that carries BOTH
// `trust: NotEvaluated` and `authorization: NotEvaluated`: an anchored
// export binds the retrieved object generation, but even a fully
// authenticated export is not an execution decision.

/// Verify a signed historical boundary anchor against a trusted key and
/// caller expectation.
///
/// Parses the 3-segment compact (reusing the anchor decode helper), enforces
/// the closed protected header `{alg:"ES256", kid, typ:"ba+chain-anchor"}`
/// and the closed payload set (with `v: 3`), then requires: the header `kid`
/// equals both `key.key_id` and `expected.key_id`; the EC RFC 7638
/// fingerprint derived from `key.public_key` equals the signed
/// `key_fingerprint` and the expected fingerprint; the signed values equal
/// `expected`; sequence zero requires the all-zero `chain_hash`;
/// `key.valid_from <= anchored_at < valid_before` (open upper under
/// [`ValidityUpperBound::Unbounded`]); and the ES256 signature over the
/// exact 2-segment signing input verifies under `key.public_key`.
///
/// Returns [`AnchorFacts`] carrying `trust: NotEvaluated`.
pub fn verify_historical_anchor(
    compact: &[u8],
    key: &HistoricalPublicKey,
    expected: &ExpectedAnchor,
) -> Result<AnchorFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());
    // Key-window endpoints are magnitude-bounded under the resolved bounds
    // (interval membership alone must not accept out-of-magnitude
    // endpoints).
    if key.valid_from.unsigned_abs() > bounds.integer_magnitude() {
        return Err(Invalid);
    }
    if let ValidityUpperBound::Bounded(v) = key.valid_before {
        if v.unsigned_abs() > bounds.integer_magnitude() {
            return Err(Invalid);
        }
        // valid_before must also exceed valid_from.
        if v <= key.valid_from {
            return Err(Invalid);
        }
    }
    let a = decode_anchor_parts(compact, &bounds)?;

    // Key ID: header.kid == key.key_id == expected.key_id.
    if a.key_id != key.key_id || a.key_id != expected.key_id {
        return Err(Invalid);
    }

    // Derived fingerprint == signed key_fingerprint == expected
    // key_fingerprint (the EC RFC 7638 construction).
    let derived = public_key_thumbprint_raw(&key.public_key)?;
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

    // ES256 signature over the exact 2-segment signing input.
    let mut signature = [0u8; 64];
    decode_signature64(a.signature_seg, &mut signature)?;
    let signing_input = signing_input_bytes(a.protected_seg, a.payload_seg);
    es256::verify(&key.public_key, &signing_input, &signature)?;

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

/// Verify a signed historical key transition: the current key signs the
/// rollover to the next key.
///
/// Enforces the closed protected header `{alg:"ES256", kid:current_key_id,
/// typ:"ba+key-transition"}` and the closed payload set (with `v: 3`), then
/// requires: the header `kid` equals `current.key_id` and
/// `expected.current_key_id`; the derived current/next EC fingerprints equal
/// the signed `from_key_fingerprint`/`to_key_fingerprint` and the expected
/// fingerprints; the signed `to_key_id`, `chain_id`, `effective_at`, and
/// `transition_id` equal `expected` (`to_key_id` is bound to BOTH the
/// positional next key's identifier AND the caller's expected id); the
/// current and next fingerprints DIFFER (their key IDs may be equal);
/// `effective_at` lies in BOTH historical intervals; and the current key's
/// ES256 signature over the 2-segment signing input verifies.
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

    let current_derived = public_key_thumbprint_raw(&current.public_key)?;
    let next_derived = public_key_thumbprint_raw(&next.public_key)?;

    // from_fingerprint == derived(current) == expected
    // current_key_fingerprint.
    if t.payload.from_fingerprint != current_derived
        || t.payload.from_fingerprint != expected.current_key_fingerprint
    {
        return Err(Invalid);
    }
    // to_fingerprint == derived(next) == expected next_key_fingerprint.
    if t.payload.to_fingerprint != next_derived
        || t.payload.to_fingerprint != expected.next_key_fingerprint
    {
        return Err(Invalid);
    }
    // Signed to_key_id / chain_id / effective_at / transition_id == expected.
    // to_key_id is bound to BOTH the positional next key's identifier AND the
    // caller's expected id — the next side must bind to next.key_id too, or
    // the positional key chain could advance under a mismatched identifier.
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
    es256::verify(&current.public_key, &signing_input, &signature)?;

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
/// Builds the exact binary concatenation (ADR 0004 § Anchored export, at
/// major 3): `ARCHIVE_MAGIC || frame(canonical_header) ||
/// frame(start_anchor) || frame(each transition) || frame(each row) ||
/// frame(end_anchor)`, where each frame is `UINT32_BE(nonzero_length) ||
/// bytes`. The closed canonical header binds `chain_id, first_sequence,
/// last_hash, last_sequence, previous_hash, row_count, transition_count,
/// v:3` (member names derived first-hand from the v3 corpus header frame).
///
/// Mirrors the reference producer's FULL validation contract: expected-side
/// consistency (the chain_id binding of both anchors and every transition;
/// the start/end sequence + hash bindings to the chain), a full
/// [`check_chain`] re-check of the rows, gated parses + 7-field matches for
/// BOTH anchors and every transition, and the key-path walk (running key
/// from the start anchor, strictly-after transition times, a fingerprint
/// no-cycle seen-list, the end anchor binding the final key with NON-STRICT
/// `>=` chronology). Aggregate ceilings are checked before the archive
/// allocation. Computes `byte_count` and the SHA-256 `digest` over the full
/// byte stream; encode never verifies ES256 signatures (a producer, not an
/// authority). The result is the public archive a caller stores; it is not a
/// credential.
pub fn encode_anchored_export(
    input: &AnchoredExportInput,
    expected: &ExpectedExport,
) -> Result<AnchoredExportEncoded> {
    let bounds = resolve_bounds(expected.bounds.as_ref());

    // The count ceiling BEFORE any per-element walk (an unbounded caller
    // input must not be walked past the ceiling).
    if expected.transitions.len() as u64 > bounds.key_transitions() {
        return Err(Invalid);
    }

    // The nested-bounds pins (a present nested bounds must equal the outer;
    // an absent nested is valid only when the outer is effectively maximum).
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

    // Expected-side consistency: every transition and both anchors belong to
    // the expected chain; the anchors bind the chain's sequence span and
    // hash boundaries. checked_sub: a caller-supplied first_sequence of
    // i64::MIN would underflow a bare `- 1`; fail closed instead.
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

    // Row chain re-check: the rows must verify against the expected
    // boundaries before they are archived. Per-row byte ceilings are
    // enforced BEFORE the row set is cloned into ChainInput (which owns its
    // rows) — cloning an oversized caller-controlled row first would amplify
    // memory before the rejection.
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
    // then match ALL signed fields against the expected anchor.
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

    // Transitions: gated parse + full match, positionally.
    for (compact, exp) in input.transitions.iter().zip(&expected.transitions) {
        let t = decode_transition_parts(compact, &bounds)?;
        if !transition_matches(&t.payload, &t.key_id, exp) {
            return Err(Invalid);
        }
    }

    // Key-path walk: the running key starts at the start anchor's, every
    // transition carries it and advances strictly in time without cycling
    // fingerprints, and the end anchor binds the final key with NON-STRICT
    // chronology (`>=`).
    key_path_ok(
        &expected.start_anchor,
        &expected.transitions,
        &expected.end_anchor,
    )?;

    // Canonical header JCS object (member names + order derived first-hand
    // from the v3 corpus header frame: chain_id, first_sequence, last_hash,
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
        ("v".to_string(), JsonValue::Int(3)),
    ]);
    let header_bytes = jcs_encode(&header_value, &bounds)?;
    if header_bytes.len() as u64 > bounds.archive_header_bytes() {
        return Err(Invalid);
    }

    // Aggregate ceilings at encode: chunk count <= archive_chunks and total
    // bytes <= archive_bytes, checked BEFORE assembling so an over-budget
    // input cannot force a full-archive allocation. Chunk count = magic +
    // header + start + transitions + rows + end.
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

    // Assemble the archive: magic + frames + EOF. Each frame's content MUST
    // be non-empty (UINT32_BE(nonzero_length)).
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
/// is the profile maximum. Tighten-only by construction — `Bounds::new`
/// rejects widenings and merges overrides onto the maximum struct, so an
/// identity override (value == maximum) resolves EQUAL to the maximum.
pub fn resolve_bounds(nested: Option<&Bounds>) -> Bounds {
    match nested {
        None => Bounds::maximum(),
        Some(b) => *b,
    }
}

/// The nested-bounds pin: a present nested bounds must equal the outer; an
/// absent nested is valid only when the outer is effectively maximum
/// (identity overrides are NOT tightening — struct equality against the
/// maximum).
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
/// (all seven fields).
fn anchor_matches(payload: &AnchorPayload, key_id: &str, expected: &ExpectedAnchor) -> bool {
    payload.anchor_id == expected.anchor_id
        && payload.anchored_at == expected.anchored_at
        && payload.chain_id == expected.chain_id
        && payload.sequence == expected.sequence
        && key_id == expected.key_id
        && payload.chain_hash == expected.chain_hash
        && payload.key_fingerprint == expected.key_fingerprint
}

/// Full signed-field match of a parsed transition against its expected
/// values (all seven fields: both key ids, both fingerprints, chain, time,
/// identity).
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

/// The key-path walk over the EXPECTED set: the running
/// `(key_id, fingerprint)` starts at the start anchor's; each transition
/// must carry it as its current key, be STRICTLY after the previous time,
/// and name a next fingerprint not already seen (cycle guard — the running
/// current is always in `seen`, so a self-loop rejects here); the end anchor
/// must bind the final running key and carry `anchored_at >=` the running
/// time (NON-STRICT; the zero-transition case compares against the start
/// anchor's time the same way).
fn key_path_ok(
    start: &ExpectedAnchor,
    transitions: &[ExpectedKeyTransition],
    end: &ExpectedAnchor,
) -> Result<()> {
    let mut current_key_id = &start.key_id;
    let mut current_fingerprint = start.key_fingerprint;
    let mut previous_time = start.anchored_at;
    // Seed the seen-list with the start fingerprint.
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
/// object-store version. Verification bounds the chunk count, total bytes,
/// and per-chunk non-emptiness; materializes the stream; checks the exact
/// 20-byte `BAP3-ARCHIVE\0EXPORT\0` magic; hashes every raw byte and compares
/// the SHA-256 to `expected.digest` in CONSTANT TIME; requires exact
/// `obj.version == expected.object_version`; scans frames incrementally
/// (header, start anchor, transitions, rows, end anchor) requiring exact
/// EOF; decodes and validates the closed header (v:3) against the caller's
/// chain boundaries; enforces the **surplus-key invariant**
/// `keys.len() == transitions.len() + 1`; authenticates the start anchor
/// with `keys[0]`, each transition positionally (`keys[i]` signs,
/// `keys[i+1]` is next), and the end anchor with the last key; checks
/// chronology (strictly increasing effective times, no fingerprint cycle,
/// anchor ordering); and re-checks every row via [`check_chain`].
///
/// Returns [`AnchoredExportFacts`] carrying `trust: NotEvaluated` AND
/// `authorization: NotEvaluated`.
pub fn verify_anchored_export(
    obj: &ArchivedObject,
    keys: &HistoricalKeyChain,
    expected: &ExpectedAnchoredExport,
) -> Result<AnchoredExportFacts> {
    let bounds = resolve_bounds(expected.bounds.as_ref());

    // Expected-struct well-formedness BEFORE the digest (the reference
    // ordering: chain + both anchors + transitions validated before key
    // shapes, chunks, and hashing).
    {
        // The count ceiling BEFORE the hoisted per-element walk.
        if expected.transitions.len() as u64 > bounds.key_transitions() {
            return Err(Invalid);
        }
        validate_identifier(&expected.chain.chain_id, &bounds)?;
        let mag = bounds.integer_magnitude();
        if expected.chain.first_sequence < 1
            || expected.chain.first_sequence.unsigned_abs() > mag
            || expected.chain.last_sequence < 1
            || expected.chain.last_sequence.unsigned_abs() > mag
            || expected.chain.first_sequence > expected.chain.last_sequence
        {
            return Err(Invalid);
        }
        if expected.chain.row_count < 1
            || expected.chain.row_count as u64 > bounds.chain_rows()
            || expected.chain.row_count
                != expected.chain.last_sequence - expected.chain.first_sequence + 1
        {
            return Err(Invalid);
        }
        if expected.chain.first_sequence == 1 && expected.chain.previous_hash != [0u8; 32] {
            return Err(Invalid);
        }
        for anch in [&expected.start_anchor, &expected.end_anchor] {
            validate_identifier(&anch.anchor_id, &bounds)?;
            validate_identifier(&anch.chain_id, &bounds)?;
            if anch.anchored_at.unsigned_abs() > mag {
                return Err(Invalid);
            }
            if anch.sequence < 0 || anch.sequence.unsigned_abs() > mag {
                return Err(Invalid);
            }
            if anch.key_id.is_empty()
                || anch.key_id.len() as u64 > bounds.kid_bytes()
                || !anch.key_id.bytes().all(is_kid_byte)
            {
                return Err(Invalid);
            }
            if anch.sequence == 0 && anch.chain_hash != [0u8; 32] {
                return Err(Invalid);
            }
        }
        for t in &expected.transitions {
            validate_identifier(&t.transition_id, &bounds)?;
            validate_identifier(&t.chain_id, &bounds)?;
            if t.effective_at.unsigned_abs() > mag {
                return Err(Invalid);
            }
            for kid in [&t.current_key_id, &t.next_key_id] {
                if kid.is_empty()
                    || kid.len() as u64 > bounds.kid_bytes()
                    || !kid.bytes().all(is_kid_byte)
                {
                    return Err(Invalid);
                }
            }
            if t.current_key_fingerprint == t.next_key_fingerprint {
                return Err(Invalid);
            }
        }
    }

    // The nested-bounds pins at verify.
    require_bounds_equal(expected.chain.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.start_anchor.bounds.as_ref(), &bounds)?;
    require_bounds_equal(expected.end_anchor.bounds.as_ref(), &bounds)?;
    for t in &expected.transitions {
        require_bounds_equal(t.bounds.as_ref(), &bounds)?;
    }

    // Key-count ceiling BEFORE the per-key window walk.
    if keys.keys.len() as u64 != expected.transitions.len() as u64 + 1 {
        return Err(Invalid);
    }
    // Key-window validity BEFORE chunk processing/hashing (malformed
    // intervals must not force processing of the full archive).
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

    // Static expected-side bindings: the caller's expected anchors belong to
    // the expected chain — sequence/hash bindings are re-checked on the
    // verified facts below, but the chain_id membership is checked here.
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

    // Version shape + EQUALITY + key-count + key shape BEFORE the digest
    // (malformed metadata must not force maximum-sized hashing). The key
    // width is type-inherent ([u8; 65]); the profile's point-form gate runs
    // inside es256::verify at each authentication step below.
    if obj.version.is_empty()
        || obj.version.len() as u64 > bounds.object_version_bytes()
        || expected.object_version.is_empty()
        || expected.object_version.len() as u64 > bounds.object_version_bytes()
        || obj.version != expected.object_version
    {
        return Err(Invalid);
    }
    for k in &keys.keys {
        if k.key_id.is_empty() || k.key_id.len() as u64 > bounds.kid_bytes() {
            return Err(Invalid);
        }
        if !k.key_id.bytes().all(is_kid_byte) {
            return Err(Invalid); // ASCII-unreserved class
        }
    }

    let mut hasher = Sha256::new();
    for c in chunks {
        hasher.update(c);
    }
    let mut computed = [0u8; 32];
    computed.copy_from_slice(&hasher.finalize());
    if !constant_time_eq(&computed, &expected.digest) {
        return Err(Invalid);
    }

    // Materialize the byte stream for the magic check + incremental frame
    // scan.
    let mut buf = Vec::with_capacity(total as usize);
    for c in chunks {
        buf.extend_from_slice(c);
    }

    // Exact magic prefix (a v1/v2 archive carries BAP1/BAP2 magic — the
    // cross-major archive cases reject here).
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

    // Surplus-key invariant: keys.len() == transitions.len() + 1. WITHOUT
    // this check a 0-transition archive carrying two distinct keys (start
    // signed by keys[0], end by keys[1]) would be accepted — both anchors
    // verify individually, but no transition authenticates the rollover.
    // Deliberate redundancy (implied by the pre-digest keys==transitions+1
    // gate + the header equality — kept as defense-in-depth).
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

    // Authenticate each transition positionally: keys[i] signs, keys[i+1]
    // next.
    let mut effective_times: Vec<i64> = Vec::with_capacity(transition_compacts.len());
    for (i, tcompact) in transition_compacts.iter().enumerate() {
        let exp_t = expected.transitions.get(i).ok_or(Invalid)?;
        let t_facts = verify_key_transition(tcompact, &keys.keys[i], &keys.keys[i + 1], exp_t)?;
        effective_times.push(t_facts.effective_at);
    }

    // Authenticate the end anchor with the last key; bind it to the chain
    // head.
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

    // Chronology + rollover (strictly increasing effective times, no
    // fingerprint cycle, anchor ordering).
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
/// the encode path's start-anchor binding check. The decoded signature
/// segment MUST be exactly 64 bytes (`REQ3-BOUNDS-fixed-widths` — the raw
/// ES256 `r||s` width), and the protected/payload segments must equal their
/// exact JCS re-encoding (canonical form) — enforced inside the validators
/// below.
fn decode_anchor_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedAnchor<'a>> {
    // The whole-input compact_bytes ceiling FIRST (a tightened compact_bytes
    // below anchor_bytes must not be bypassed).
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    if compact.len() as u64 > bounds.anchor_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ3-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (the raw ES256 r||s form; DER is never a v3 wire spelling).
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
/// `{alg:"ES256", typ:"ba+chain-anchor", kid:<valid kid>}`. Returns the kid.
/// Canonical form: the protected segment bytes must equal the exact JCS
/// re-encoding of the header.
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
        Some(JsonValue::String(s)) if s == ALG_ECDSA_P256 => {}
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
/// first-hand from the v3 corpus anchor `payload_segment`): exactly
/// `{anchor_id, anchored_at, chain_hash, chain_id, key_fingerprint,
/// sequence, v:3}`, no extra members. `chain_hash`/`key_fingerprint` are
/// canonical base64url of exactly 32 bytes. Canonical form: the payload
/// segment bytes must equal the exact JCS re-encoding of the payload.
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
        Some(JsonValue::Int(3)) => {}
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
    // Genesis binding: sequence 0 carries the all-zero chain hash.
    if sequence == 0 && chain_hash != [0u8; 32] {
        return Err(Invalid);
    }
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

/// Splits, bounds, decodes, and structurally validates a key-transition
/// compact. The decoded signature segment MUST be exactly 64 bytes (raw
/// `r||s`); publicly reachable through `encode_anchored_export`, which parses
/// caller-supplied transitions here.
fn decode_transition_parts<'a>(
    compact: &'a [u8],
    bounds: &Bounds,
) -> Result<DecodedTransition<'a>> {
    // The whole-input compact_bytes ceiling FIRST.
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    if compact.len() as u64 > bounds.anchor_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ3-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (the raw ES256 r||s form).
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
/// `{alg:"ES256", typ:"ba+key-transition", kid:<valid kid>}`. Returns the
/// kid. Canonical form enforced against the protected segment bytes.
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
        Some(JsonValue::String(s)) if s == ALG_ECDSA_P256 => {}
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
/// derived first-hand from the v3 corpus transition `payload_segment`):
/// exactly `{chain_id, effective_at, from_key_fingerprint,
/// to_key_fingerprint, to_key_id, transition_id, v:3}`. Canonical form
/// enforced against the payload segment bytes.
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
        Some(JsonValue::Int(3)) => {}
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
/// derived first-hand from the v3 corpus header frame): exactly
/// `{chain_id, first_sequence, last_hash, last_sequence, previous_hash,
/// row_count, transition_count, v:3}`. Enforces the canonical re-encode
/// check (the header bytes MUST be the exact JCS encoding) and bounds the
/// counts.
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
        Some(JsonValue::Int(3)) => {}
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
/// sites). `len` fits in `u32` for every protocol element (anchor/transition
/// <= 8,192 bytes; row <= 4,096 bytes; header <= 8,192 bytes).
fn frame_into(content: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(content.len() as u32).to_be_bytes());
    out.extend_from_slice(content);
}

/// Reads one archive frame at `*cursor`: a UINT32_BE nonzero length prefix
/// followed by exactly that many bytes. Returns a borrowed slice of the
/// frame payload and advances `*cursor` past it.
/// read_frame with a per-frame byte ceiling — the row/anchor reads cap each
/// frame at its role's bound (chain_row_bytes / anchor_bytes) so a
/// digest-matching malformed archive cannot materialize a ~full-archive
/// frame before check_chain's per-row gate.
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
        return Err(Invalid); // REQ3-BOUNDS-fixed-widths (signature = 64 bytes)
    }
    out.copy_from_slice(&sig_raw);
    Ok(())
}

/// Half-open interval membership: `valid_from <= t < upper` (`Unbounded` is
/// the only open upper interval).
fn in_interval(t: i64, valid_from: i64, upper: &ValidityUpperBound) -> bool {
    if t < valid_from {
        return false;
    }
    match upper {
        ValidityUpperBound::Bounded(v) => t < *v,
        ValidityUpperBound::Unbounded => true,
    }
}

/// Chronology + rollover checks for a v3 anchored export (ADR 0004 §49-55):
/// fingerprints cannot cycle (all key fingerprints distinct); transition
/// effective times strictly increase; the start anchor precedes every
/// transition; the end anchor is at or after the last transition. Equal
/// start/end times are permitted only for the no-transition same-key case.
fn check_export_chronology(
    start_at: i64,
    end_at: i64,
    effective_times: &[i64],
    keys: &[HistoricalPublicKey],
) -> Result<()> {
    // Fingerprints cannot cycle: no key fingerprint may recur.
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(keys.len());
    for k in keys {
        let fp = public_key_thumbprint_raw(&k.public_key)?;
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
/// length is a protocol constant, not secret); the byte loop runs in
/// constant time for equal-length inputs with no early exit.
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
/// segments stay completely opaque (`REQ1-LOCATOR-opaque-payload`): they may
/// be empty (the `header..` form) and are never decoded.
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
/// Enforces `REQ1-BOUNDS-ordering` (incorporated): the encoded byte ceiling
/// precedes decoding, the decoded byte ceiling precedes JSON parsing.
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
/// input compact), the validated `kid`, the validated [`GrantPayload`], and
/// the parsed payload [`JsonValue`] (retained so [`check_envelope`] can
/// extract the operations array the redacted [`GrantFacts`] does not carry).
struct DecodedGrant<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    key_id: String,
    payload: GrantPayload,
    payload_json: JsonValue,
}

/// Shared grant decode used by [`decode_grant`] (signature-not-verified view)
/// and [`verify_grant`] (which adds the signature, identity, and time
/// checks). Splits, bounds, decodes, and structurally validates the
/// protected header + payload claims. The decoded signature segment MUST be
/// exactly 64 bytes (`REQ3-BOUNDS-fixed-widths`, the raw ES256 `r||s`
/// width).
fn decode_grant_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedGrant<'a>> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ3-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes
    // (the raw ES256 r||s form; DER is never a v3 wire spelling).
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
/// decoded 65-byte holder public key, and the validated [`ProofPayload`].
struct DecodedProof<'a> {
    protected_seg: &'a [u8],
    payload_seg: &'a [u8],
    signature_seg: &'a [u8],
    holder_public_key: [u8; es256::PUBLIC_KEY_WIDTH],
    payload: ProofPayload,
}

/// Shared proof decode used by [`decode_proof`] and [`check_envelope`].
/// Splits, bounds, decodes, and structurally validates the proof header
/// (returning the holder public key) and payload claims. The decoded
/// signature segment MUST be exactly 64 bytes.
fn decode_proof_parts<'a>(compact: &'a [u8], bounds: &Bounds) -> Result<DecodedProof<'a>> {
    if compact.len() as u64 > bounds.compact_bytes() {
        return Err(Invalid);
    }
    let (protected_seg, payload_seg, signature_seg) = compact::parse_compact(compact)?;
    let header_bytes = decode_segment(protected_seg, bounds)?;
    let payload_bytes = decode_segment(payload_seg, bounds)?;
    // REQ3-BOUNDS-fixed-widths: the decoded signature is exactly 64 bytes.
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
/// ES256 signature covers (`REQ1-SIGNING-exact-input` incorporated).
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
/// [`validate_operations`]; this re-walks the array to surface each
/// operation's selector objects (cloned, so they outlive the borrowed
/// payload).
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
/// `{alg:"ES256", typ:"ba+cap", kid:<valid kid>}` (`REQ3-HEADER-closed-set`).
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
            // invalid (REQ3-HEADER-closed-set, incorporated).
            _ => return Err(Invalid),
        }
    }
    match alg {
        Some(JsonValue::String(s)) if s == ALG_ECDSA_P256 => {}
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
/// `{alg:"ES256", typ:"dpop+jwt", jwk:{crv,kty,x,y}}`
/// (`REQ3-HEADER-closed-set`, `REQ3-HEADER-proof-jwk`,
/// `REQ3-HEADER-no-private-jwk`). Returns the validated 65-byte holder
/// public key.
fn validate_proof_header(
    header: &JsonValue,
    bounds: &Bounds,
) -> Result<[u8; es256::PUBLIC_KEY_WIDTH]> {
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
        Some(JsonValue::String(s)) if s == ALG_ECDSA_P256 => {}
        _ => return Err(Invalid),
    }
    match typ {
        Some(JsonValue::String(s)) if s == TYP_PROOF => {}
        _ => return Err(Invalid),
    }
    let jwk_val = jwk.ok_or(Invalid)?;
    // Re-encode the jwk member to canonical JSON and delegate to the v3 EC
    // JWK primitive's full closed-set + crv/kty + fixed-width coordinate +
    // canonical-b64url + point-on-curve validation (rejects the private
    // `d`, `kid`, `alg`, and any extra member).
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
/// (`REQ1-CLAIM-closed-set` incorporated, `REQ3-CLAIM-v`). All nine claims
/// are required and no other claim is accepted.
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
    // v MUST be exactly the integer 3 (`REQ3-CLAIM-v`; every v1/v2 artifact
    // — and any other version — rejects here:
    // `REQ3-CORE-cross-major-reject`).
    let version = match version {
        Some(JsonValue::Int(3)) => 3,
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
    // Coherent signed times: iat < exp and nbf < exp
    // (`REQ1-VERIFY-grant-times` incorporated). The protocol does not
    // require iat <= nbf (`REQ1-VERIFY-no-iat-nbf-order`).
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
/// (`REQ1-CLAIM-proof-required`, `REQ1-CLAIM-no-extra` incorporated) with
/// `v: 3` exactly (`REQ3-CLAIM-proof-v`).
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
    // v MUST be exactly the integer 3 (`REQ3-CLAIM-proof-v`).
    match version {
        Some(JsonValue::Int(3)) => {}
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
    let target_uri_input = match htu {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return Err(Invalid),
    };
    // nonce is OPTIONAL but, if present, MUST be a non-empty string <=512
    // bytes.
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
    let target_uri = uri_normalize(&target_uri_input, bounds)?;
    if target_uri != target_uri_input {
        return Err(Invalid);
    }
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

/// Extracts a non-empty StringOrURI (<= `identifier_bytes`).
///
/// Per RFC 7519 + the reference `string_or_uri.ex` semantics (incorporated):
/// a colon-free value is a PLAIN string (any valid UTF-8 is accepted); a
/// colon-bearing value is a URI whose scheme is valid, every byte is alnum /
/// URI-punctuation / a well-formed `%HH` escape, and (for a `://` authority)
/// the port is all-digit. Rejects an empty value, a bad scheme, a non-URI
/// byte (e.g. `{`), a malformed `%HH`, or a non-numeric authority port.
/// `None` (claim absent) → `Invalid`.
fn take_string_or_uri(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_identifier(s, bounds)?;
    Ok(s.clone())
}

/// Validates a StringOrURI / identifier scalar: a colon-free value is a
/// PLAIN string (any valid UTF-8 — automatic for a Rust `&str`); a
/// colon-bearing value is a URI whose scheme is valid and whose every byte
/// is alphanumeric, a URI punctuation byte
/// (`-._~:/?#[]@!$&'()*+,;=`), or part of a well-formed `%HH` escape.
fn validate_identifier(s: &str, bounds: &Bounds) -> Result<()> {
    if s.is_empty() || s.len() as u64 > bounds.identifier_bytes() {
        return Err(Invalid);
    }
    match s.find(':') {
        None => Ok(()), // plain string — any valid UTF-8
        Some(colon) => {
            validate_scheme(&s[..colon])?;
            validate_uri_bytes(s.as_bytes())?;
            // Structural authority/port check: a `:` in the authority outside
            // an IP-literal bracket (`[…]`) MUST introduce an all-digit
            // port.
            validate_authority_port(s)?;
            Ok(())
        }
    }
}

/// Authority/port structure: when the URI has an authority (`://authority`),
/// a `:` in the authority outside an IP-literal bracket (`[…]`) MUST
/// introduce an all-digit port. Rejects e.g. `http://a:b` (port "b").
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

/// `uri_bytes?/1`: every byte is alphanumeric, one of the URI punctuation
/// bytes `-._~:/?#[]@!$&'()*+,;=`, or part of a well-formed `%HH`
/// percent-escape. Rejects `{`, whitespace, control, non-ASCII, and a bare
/// `%` / `%G`.
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

/// Extracts the `aud` claim: one StringOrURI or a nonempty unique array of
/// <=64. `None` → `Invalid` (aud is required).
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

/// Extracts `cnf.jkt`: exactly `{jkt: canonical_base64url_sha256}` (decodes
/// to 32 bytes), no extra members (`REQ1-CLAIM-closed-set` incorporated).
/// `None` → `Invalid`.
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

/// Validates the `operations` array shape: each element MUST be exactly
/// `{name: string, selectors: non_empty_array}`
/// (`REQ1-CLAIM-operation-shape` incorporated); selectors are validated
/// through the incorporated v2 algebra (`selector::validate_v2` — the five
/// kinds). `None` → `Invalid` (operations is required).
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
        // Grant decode/verify validates the complete selector shape before
        // signature acceptance; envelope evaluation reuses the same
        // validator.
        for sel in sel_items {
            selector::validate_v2(sel, bounds)?;
        }
    }
    Ok(())
}

/// Extracts an `htm` method token (1-32 bytes of the RFC 9110 token
/// alphabet). `None` → `Invalid`.
fn take_method_token(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_method_token(s, bounds)?;
    Ok(s.clone())
}

/// Validates an RFC 9110 method token: 1-`method_bytes` bytes, each in the
/// token alphabet (`REQ1-CLAIM-htm-bytes` incorporated), compared
/// byte-for-byte without case normalization
/// (`REQ1-CLAIM-htm-no-case-normalize`).
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

/// Extracts a `ba_op` operation name (1-128 printable ASCII bytes). `None` →
/// `Invalid`.
fn take_operation_name(value: Option<&JsonValue>, bounds: &Bounds) -> Result<String> {
    let s = match value {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    validate_operation_name(s, bounds)?;
    Ok(s.clone())
}

/// Validates an operation name: non-empty, <= `operation_bytes`, printable
/// ASCII (0x20-0x7E).
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

/// Extracts a canonical unpadded base64url SHA-256 string (decodes to 32
/// bytes). Used for `ath` and `ba_req`. `None` → `Invalid`.
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
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (36 chars, hyphens at 8/13/18/23,
/// all other bytes lowercase hex).
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

/// Validates a `kid`: 1-`kid_bytes`, each byte an ASCII letter, digit, or
/// one of `-`, `.`, `_`, `~` (`REQ1-HEADER-kid-bytes` incorporated).
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

/// Printable ASCII (0x20-0x7E), the JSON-Schema VCHAR range.
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

// ============================================================================
// Tests — the vendored v3 corpus pins + the cross-major and suite closures.
// Mirrors the v2 façade's in-module battery (which mirrors the v1 one),
// re-derived against spec/bap-v3.md and the certified corpus-v3 snapshot.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;
    use crate::types::GrantOperation;
    use sha2::Digest;

    fn max() -> Bounds {
        Bounds::maximum()
    }

    /// The vendored self-contained v3 corpus snapshot (ADR 0015 D5) — NOT the
    /// monorepo source tree.
    fn corpus_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("conformance")
            .join("corpus-v3")
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

    fn find_case(rel: &str, id: &str) -> serde_json::Value {
        load_cases(rel)
            .into_iter()
            .find(|c| c["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("case {id} exists"))
    }

    /// Converts a serde_json::Value to the crate's tagged JsonValue,
    /// preserving the integer-vs-float tag (closure #5).
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

    /// Corpus selector shorthand: a bare string `"all"` expands to
    /// `{"kind":"all"}`; a full object passes through.
    fn corpus_selector_to_json(v: &serde_json::Value) -> JsonValue {
        match v {
            serde_json::Value::String(s) => {
                JsonValue::Object(vec![("kind".to_string(), JsonValue::String(s.clone()))])
            }
            _ => serde_to_json(v),
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

    /// Decodes a base64url string to the 65-byte v3 raw public key, or None.
    fn b64url_to_65(field: &serde_json::Value) -> Option<[u8; 65]> {
        let b64 = field.as_str()?;
        let raw = crate::base64url_decode(b64.as_bytes()).ok()?;
        if raw.len() != 65 {
            return None;
        }
        let mut arr = [0u8; 65];
        arr.copy_from_slice(&raw);
        Some(arr)
    }

    /// Builds a v3 range-selector grant input (the corpus's v3 shape).
    fn range_grant() -> GrantInput {
        GrantInput {
            issuer: "https://issuer.example.test".to_string(),
            grant_id: "urn:example:grant:v3-1".to_string(),
            key_id: "issuer".to_string(),
            holder_thumbprint: [0u8; 32],
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 2_000,
            audiences: vec!["https://resource.example.test".to_string()],
            operations: vec![GrantOperation {
                name: "transfer".to_string(),
                selectors: vec![
                    JsonValue::Object(vec![
                        ("kind".to_string(), JsonValue::String("gte".to_string())),
                        (
                            "path".to_string(),
                            JsonValue::Array(vec![JsonValue::String("amount".to_string())]),
                        ),
                        ("value".to_string(), JsonValue::Int(50)),
                    ]),
                    JsonValue::Object(vec![
                        ("kind".to_string(), JsonValue::String("lte".to_string())),
                        (
                            "path".to_string(),
                            JsonValue::Array(vec![JsonValue::String("amount".to_string())]),
                        ),
                        ("value".to_string(), JsonValue::Int(5000)),
                    ]),
                ],
            }],
        }
    }

    // ==========================================================================
    // Domain separators — the BAP3-* bytes are load-bearing (major confusion
    // is the silent-auth failure this profile exists to prevent)
    // ==========================================================================

    #[test]
    fn chain_and_archive_domain_separators_carry_the_major_three_prefix() {
        // "BAP3-CHAIN\0" = 10 ASCII + 1 NUL = 11 bytes.
        assert_eq!(CHAIN_DIGEST_PREFIX, b"BAP3-CHAIN\0");
        assert_eq!(CHAIN_DIGEST_PREFIX.len(), 11);
        assert_eq!(CHAIN_DIGEST_PREFIX.last(), Some(&0u8));
        // "BAP3-ARCHIVE\0EXPORT\0" = 20 bytes (12 + NUL + 6 + NUL).
        assert_eq!(ARCHIVE_MAGIC, b"BAP3-ARCHIVE\0EXPORT\0");
        assert_eq!(ARCHIVE_MAGIC.len(), 20);
    }

    #[test]
    fn cross_major_chain_row_hashes_never_collide() {
        // Identical row fields hashed under BAP1/BAP2/BAP3 MUST differ — a
        // shared row hash would let a prior-major chain graft onto a v3
        // verification.
        let entry = ConsumptionEntry {
            chain_id: "chain-x".to_string(),
            commitment: [5u8; 32],
            previous_hash: [0u8; 32],
            sequence: 1,
        };
        let (v3_bytes, v3_hash) = encode_consumption_entry(&entry, &max()).expect("v3 row");
        let (v2_bytes, v2_hash) =
            crate::v2::encode_consumption_entry(&entry, &max()).expect("v2 row");
        let (v1_bytes, v1_hash) =
            crate::v1::encode_consumption_entry(&entry, &max()).expect("v1 row");
        // The canonical bytes differ ONLY in the version member...
        assert_ne!(v3_bytes, v2_bytes);
        assert_ne!(v3_bytes, v1_bytes);
        // ...but the hash differs even ignoring that: the domain separator is
        // an independent axis (manual BAP1/BAP2-domain hashes of the v3 row
        // bytes).
        let mut h1 = sha2::Sha256::new();
        h1.update(b"BAP1-CHAIN\0");
        h1.update(&v3_bytes);
        let mut bap1_of_v3 = [0u8; 32];
        bap1_of_v3.copy_from_slice(&h1.finalize());
        let mut h2 = sha2::Sha256::new();
        h2.update(b"BAP2-CHAIN\0");
        h2.update(&v3_bytes);
        let mut bap2_of_v3 = [0u8; 32];
        bap2_of_v3.copy_from_slice(&h2.finalize());
        assert_ne!(v3_hash, bap1_of_v3);
        assert_ne!(v3_hash, bap2_of_v3);
        assert_ne!(v3_hash, v1_hash);
        assert_ne!(v3_hash, v2_hash);
    }

    // ==========================================================================
    // Cross-major rejection — each major verifies under its own closed
    // profile only. RED if a v:3 check were widened (or vice versa).
    // ==========================================================================

    #[test]
    fn each_facade_rejects_the_other_majors_bytes() {
        // The v3 producer emits v:3/ES256 bytes; v1 AND v2 decode_grant both
        // reject them, v3 decode_grant accepts. The corpus's pinned
        // cross-major fixtures drive the reverse direction below.
        let successor_produced = grant_signing_input(&range_grant(), &max()).expect("v3 grant");
        let compact = format!(
            "{}.{}.{}",
            String::from_utf8(successor_produced.protected_segment.clone()).unwrap(),
            String::from_utf8(successor_produced.payload_segment.clone()).unwrap(),
            String::from_utf8(crate::base64url_encode(&[0u8; 64])).unwrap(),
        );
        assert!(decode_grant(compact.as_bytes(), &max()).is_ok());
        assert_eq!(
            crate::v1::decode_grant(compact.as_bytes(), &max()),
            Err(Invalid)
        );
        assert_eq!(
            crate::v2::decode_grant(compact.as_bytes(), &max()),
            Err(Invalid)
        );
    }

    #[test]
    fn decode_grant_rejects_both_prior_majors_from_corpus() {
        // Corpus grant-decode-v3-invalid-cross-major-v1-bytes and
        // grant-decode-v3-invalid-cross-major-v2-bytes: authentic v1/v2
        // compacts, rejected by the v3 façade with the single closed error.
        for id in [
            "grant-decode-v3-invalid-cross-major-v1-bytes",
            "grant-decode-v3-invalid-cross-major-v2-bytes",
        ] {
            let case = find_case("grant-decode/decode.json", id);
            let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
            assert_eq!(decode_grant(compact, &max()), Err(Invalid), "{id}");
        }
    }

    #[test]
    fn rejects_cross_major_chain_rows_from_corpus() {
        // Corpus check-chain-v3-invalid-cross-major-v1-rows /
        // -v2-rows: prior-major rows (v:1 / v:2) are rejected; the v3 rows
        // verify.
        let valid = find_case("consumption-chain/check.json", "check-chain-v3-valid");
        let input = &valid["input"];
        let rows: Vec<Vec<u8>> = input["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| crate::base64url_decode(r.as_str().unwrap().as_bytes()).expect("row decodes"))
            .collect();
        let expected = ExpectedChain {
            chain_id: input["chain_id"].as_str().unwrap().to_string(),
            first_sequence: input["first_sequence"].as_i64().unwrap(),
            last_sequence: input["last_sequence"].as_i64().unwrap(),
            row_count: input["row_count"].as_i64().unwrap(),
            previous_hash: b64url_to_32(&input["previous_hash"]).unwrap(),
            head_hash: b64url_to_32(&input["last_hash"]).unwrap(),
            bounds: None,
        };
        assert!(check_chain(&ChainInput { rows: rows.clone() }, &expected).is_ok());
        for id in [
            "check-chain-v3-invalid-cross-major-v1-rows",
            "check-chain-v3-invalid-cross-major-v2-rows",
        ] {
            let case = find_case("consumption-chain/check.json", id);
            let prior_rows: Vec<Vec<u8>> = case["input"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    crate::base64url_decode(r.as_str().unwrap().as_bytes()).expect("row decodes")
                })
                .collect();
            assert_eq!(
                check_chain(&ChainInput { rows: prior_rows }, &expected),
                Err(Invalid),
                "{id}"
            );
        }
    }

    #[test]
    fn rejects_cross_major_proof_bytes_from_corpus() {
        // Corpus proof-decode-v3-invalid-cross-major-v1-proof / -v2-bytes.
        for id in [
            "proof-decode-v3-invalid-cross-major-v1-proof",
            "proof-decode-v3-invalid-cross-major-v2-bytes",
        ] {
            let case = find_case("proof-decode/decode.json", id);
            let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
            assert_eq!(decode_proof(compact, &max()), Err(Invalid), "{id}");
        }
    }

    #[test]
    fn prior_majors_and_successor_reject_each_others_bytes() {
        // The v1/v2/v3 grant producers emit mutually exclusive bytes: a v3
        // compact is rejected by v1/v2, and v1/v2 compacts are rejected by
        // v3 (the corpus fixtures above); the proof family flips the same
        // way.
        let grant = range_grant();
        let successor_produced = grant_signing_input(&grant, &max()).expect("v3 grant");
        let successor_compact = format!(
            "{}.{}.{}",
            String::from_utf8(successor_produced.protected_segment.clone()).unwrap(),
            String::from_utf8(successor_produced.payload_segment.clone()).unwrap(),
            String::from_utf8(crate::base64url_encode(&[0u8; 64])).unwrap(),
        );
        assert_eq!(
            crate::v1::decode_grant(successor_compact.as_bytes(), &max()),
            Err(Invalid)
        );
        assert_eq!(
            crate::v2::decode_grant(successor_compact.as_bytes(), &max()),
            Err(Invalid)
        );
        // The v3 producer accepts the five-kind selector set the v1 producer
        // rejects (the contract-major verdict flip).
        assert!(grant_signing_input(&grant, &max()).is_ok());
        assert_eq!(crate::v1::grant_signing_input(&grant, &max()), Err(Invalid));
    }

    // ==========================================================================
    // v3 request digest — BAP3-REQUEST\0, pinned by the corpus
    // ==========================================================================

    #[test]
    fn request_digest_matches_pinned_corpus_value() {
        // request-digest-v3-valid: op="read", args={limit:10,record:{id:rec-1}}
        // -> the pinned BAP3 digest (distinct from the identical v1/v2
        // inputs' digests).
        let digest = request_digest(
            "read",
            &serde_to_json(&serde_json::json!({"limit": 10, "record": {"id": "rec-1"}})),
            &max(),
        )
        .expect("digest");
        assert_eq!(
            String::from_utf8(digest).unwrap(),
            "JC0FZ6A4AnpYHiMWL9AY3xfDxc3igxnGRE73jUHc4Uo"
        );
        // Domain separation against BOTH prior majors.
        let args = JsonValue::Object(vec![("amount".to_string(), JsonValue::Int(10))]);
        let successor_digest = request_digest("transfer", &args, &max()).unwrap();
        let prior_digest = crate::v2::request_digest("transfer", &args, &max()).unwrap();
        let earliest_digest = crate::request_digest("transfer", &args, &max()).unwrap();
        assert_ne!(successor_digest, prior_digest);
        assert_ne!(successor_digest, earliest_digest);
    }

    // ==========================================================================
    // lte/gte — producer byte-exactness + closed-set at the v3 façade
    // ==========================================================================

    #[test]
    fn grant_producer_emits_range_selectors_byte_exact() {
        // Corpus grant-signing-input-v3-valid-range-selectors pins all three
        // segments byte-exact — including the "ES256" alg and the "v":3
        // member.
        let case = find_case(
            "signing-input/grant.json",
            "grant-signing-input-v3-valid-range-selectors",
        );
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

    #[test]
    fn grant_producer_rejects_non_numeric_range_bound() {
        // Corpus grant-signing-input-v3-invalid-non-numeric-bound: the lte
        // bound "5000" (a string) is rejected at production.
        let mut grant = range_grant();
        grant.operations[0].selectors[1] = JsonValue::Object(vec![
            ("kind".to_string(), JsonValue::String("lte".to_string())),
            (
                "path".to_string(),
                JsonValue::Array(vec![JsonValue::String("amount".to_string())]),
            ),
            ("value".to_string(), JsonValue::String("5000".to_string())),
        ]);
        assert_eq!(grant_signing_input(&grant, &max()), Err(Invalid));
    }

    #[test]
    fn decode_grant_rejects_non_numeric_bound_from_corpus() {
        // Corpus grant-decode-v3-invalid-selector-non-numeric-bound.
        let case = find_case(
            "grant-decode/decode.json",
            "grant-decode-v3-invalid-selector-non-numeric-bound",
        );
        let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
        assert_eq!(decode_grant(compact, &max()), Err(Invalid));
    }

    #[test]
    fn assemble_compact_rejects_local_loopback_kind() {
        // Corpus assemble-compact-v3-invalid-local-loopback-kind: the v3
        // profile has no loopback typ (the loopback profile is bound to
        // contract-major 1), so the kind is closed out.
        let produced = grant_signing_input(&range_grant(), &max()).expect("grant input");
        let input = SigningInput {
            kind: SigningKind::LocalLoopbackHttpProof,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: produced.payload_segment.clone(),
        };
        assert_eq!(assemble_compact(&input, &[0u8; 64], None), Err(Invalid));
    }

    // ==========================================================================
    // The ES256 suite matrices — signature canonicality + key encodings
    // (spec/bap-v3.md §7), driven through the public verify path.
    // ==========================================================================

    /// Builds the (compact, issuer, expected) fixture from one corpus
    /// grant-verify case.
    fn grant_verify_fixture(id: &str) -> (Vec<u8>, TrustedIssuer, ExpectedGrant) {
        let case = find_case("grant-verify/verify.json", id);
        let input = &case["input"];
        let compact = input["compact"].as_str().unwrap().as_bytes().to_vec();
        let issuer = TrustedIssuer {
            key_id: input["key_id"].as_str().unwrap().to_string(),
            public_key: b64url_to_65(&input["public_key"]).expect("65-byte key"),
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

    #[test]
    fn corpus_valid_grant_verifies_under_es256() {
        // The minted low-S corpus signature verifies end-to-end through the
        // p256 backend over the exact signing input.
        let (compact, issuer, expected) = grant_verify_fixture("verify-grant-v3-valid");
        let facts = verify_grant(&compact, &issuer, &expected).expect("valid grant verifies");
        assert_eq!(facts.version, 3);
        assert_eq!(facts.authorization, NotEvaluated);
    }

    #[test]
    fn corpus_suite_matrix_signatures_are_rejected() {
        // The §7 signature-canonicality matrix: tampered r, tampered s,
        // high-s, zero r, zero s, r >= n, s >= n — every one rejected by the
        // profile gates (and, where subsumed, the backend).
        for id in [
            "verify-grant-v3-tamper-signature-r",
            "verify-grant-v3-tamper-signature-s",
            "verify-grant-v3-invalid-signature-high-s",
            "verify-grant-v3-invalid-signature-zero-r",
            "verify-grant-v3-invalid-signature-zero-s",
            "verify-grant-v3-invalid-signature-r-at-n",
            "verify-grant-v3-invalid-signature-s-at-n",
        ] {
            let (compact, issuer, expected) = grant_verify_fixture(id);
            assert_eq!(
                verify_grant(&compact, &issuer, &expected),
                Err(Invalid),
                "{id}"
            );
        }
    }

    #[test]
    fn high_s_malleable_counterpart_is_rejected() {
        // The load-bearing low-S closure: (r, n - s) of the VALID corpus
        // signature also satisfies the ECDSA equation, so ONLY the low-S
        // gate rejects it. Constructing it here proves the malleability the
        // rule exists to close (RED driver for the permissiveness battery's
        // low-S leg).
        let (compact, issuer, expected) = grant_verify_fixture("verify-grant-v3-valid");
        let text = std::str::from_utf8(&compact).unwrap();
        let (h, p, s) = {
            let mut parts = text.split('.');
            (
                parts.next().unwrap(),
                parts.next().unwrap(),
                parts.next().unwrap(),
            )
        };
        let mut sig = crate::base64url_decode(s.as_bytes()).expect("sig decodes");
        assert_eq!(sig.len(), 64);
        // s' = n - s (one conditional borrow subtraction on the 32-byte
        // big-endian half).
        let mut s_prime = [0u8; 32];
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let diff = es256::N[i] as i16 - sig[32 + i] as i16 - borrow;
            if diff < 0 {
                s_prime[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                s_prime[i] = diff as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "s < n so n - s does not underflow");
        // The counterpart is canonical (s' < n) and HIGH (the low half was
        // low): the backend would accept it; the profile low-S gate must not.
        assert!(s_prime > es256::HALF_N, "counterpart is the high half");
        sig[32..].copy_from_slice(&s_prime);
        let high_compact = format!(
            "{h}.{p}.{}",
            String::from_utf8(crate::base64url_encode(&sig)).unwrap()
        );
        assert_eq!(
            verify_grant(high_compact.as_bytes(), &issuer, &expected),
            Err(Invalid),
            "the malleable (r, n-s) counterpart MUST be rejected (low-S)"
        );
    }

    #[test]
    fn corpus_key_encoding_matrix_is_rejected() {
        // The §7 key-encoding matrix through jwk_decode_public: wrong crv,
        // wrong kty, extra member (private d), missing y, short coordinate,
        // padded coordinate, off-curve point, coordinate at the field prime,
        // and the OKP-form member set.
        for id in [
            "jwk-decode-public-invalid-crv-p384",
            "jwk-decode-public-invalid-kty-okp",
            "jwk-decode-public-invalid-extra-member-d",
            "jwk-decode-public-invalid-missing-y",
            "jwk-decode-public-invalid-short-coordinate",
            "jwk-decode-public-invalid-padded-coordinate",
            "jwk-decode-public-invalid-off-curve",
            "jwk-decode-public-invalid-coordinate-at-field-prime",
            "jwk-decode-public-invalid-member-order-okp-preimage",
            "jwk-decode-public-tamper-meaningful-byte",
        ] {
            let case = find_case("jwk/jwk.json", id);
            let text = case["input"]["text"].as_str().unwrap().as_bytes();
            assert_eq!(jwk_decode_public(text), Err(Invalid), "{id}");
        }
    }

    #[test]
    fn corpus_wrong_width_raw_keys_are_rejected() {
        // 64-byte (truncated) and compressed (33-byte, 0x02-prefixed) raw
        // keys never encode: the SEC1 uncompressed form is 0x04 || x || y
        // exactly (corpus jwk-encode-public-invalid-length-64 and
        // -invalid-compressed-form).
        let truncated = find_case("jwk/jwk.json", "jwk-encode-public-invalid-length-64");
        let b64 = truncated["input"]["public_key"].as_str().unwrap();
        let raw = crate::base64url_decode(b64.as_bytes()).unwrap();
        assert_eq!(raw.len(), 64);
        let mut arr = [0u8; 65];
        arr[..64].copy_from_slice(&raw);
        assert_eq!(jwk_encode_public(&arr), Err(Invalid));

        let compressed = find_case("jwk/jwk.json", "jwk-encode-public-invalid-compressed-form");
        let b64 = compressed["input"]["public_key"].as_str().unwrap();
        let raw = crate::base64url_decode(b64.as_bytes()).unwrap();
        assert_eq!(raw.len(), 33);
        assert_eq!(raw[0], 0x02, "the corpus compressed-form fixture");
        let mut arr = [0u8; 65];
        arr[0] = 0x02; // a compressed point padded into 65 bytes
        arr[1..33].copy_from_slice(&raw[1..33]);
        assert_eq!(jwk_encode_public(&arr), Err(Invalid));
    }

    #[test]
    fn ec_thumbprint_family_matches_pinned_corpus_values() {
        // Corpus jwk-thumbprint-valid-ec / jwk-thumbprint-preimage-valid-ec /
        // jwk-thumbprint-raw-valid-ec / jwk-encode-public-valid-ec.
        let tp_case = find_case("jwk/jwk.json", "jwk-thumbprint-valid-ec");
        let key =
            jwk_decode_public(tp_case["input"]["text"].as_str().unwrap().as_bytes()).expect("key");
        assert_eq!(
            String::from_utf8(thumbprint(&key).unwrap()).unwrap(),
            tp_case["expected"]["thumbprint"].as_str().unwrap()
        );
        let pre_case = find_case("jwk/jwk.json", "jwk-thumbprint-preimage-valid-ec");
        assert_eq!(
            String::from_utf8(thumbprint_preimage(&key).unwrap()).unwrap(),
            pre_case["expected"]["preimage"].as_str().unwrap()
        );
        let raw_case = find_case("jwk/jwk.json", "jwk-thumbprint-raw-valid-ec");
        assert_eq!(
            String::from_utf8(crate::base64url_encode(&thumbprint_raw(&key).unwrap())).unwrap(),
            raw_case["expected"]["thumbprint_raw"].as_str().unwrap()
        );
        let enc_case = find_case("jwk/jwk.json", "jwk-encode-public-valid-ec");
        assert_eq!(
            String::from_utf8(jwk_encode_public(&key).unwrap()).unwrap(),
            enc_case["expected"]["encoded"].as_str().unwrap()
        );
        // RFC 7638: the preimage IS the canonical sorted EC JWK (crv<kty<x<y).
        assert_eq!(
            thumbprint_preimage(&key).unwrap(),
            jwk_encode_public(&key).unwrap()
        );
        // The issuer fingerprint is the same construction over the raw key.
        assert_eq!(
            public_key_thumbprint_raw(&key).unwrap(),
            thumbprint_raw(&key).unwrap()
        );
    }

    // ==========================================================================
    // Envelope + export corpus smoke — the valid cases verify end-to-end
    // ==========================================================================

    #[test]
    fn corpus_valid_envelope_verifies() {
        let case = find_case("envelope/check.json", "check-envelope-v3-valid");
        let input = &case["input"];
        let exp = &input["expected"];
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
            nonce_mode: NonceMode::NotRequired,
            trusted_issuer: TrustedIssuer {
                key_id: exp["trusted_issuer"]["key_id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                public_key: b64url_to_65(&exp["trusted_issuer"]["public_key"]).expect("65"),
            },
        };
        let credentials = Credentials {
            grant: input["grant"].as_str().unwrap().as_bytes().to_vec(),
            proof: input["proof"].as_str().unwrap().as_bytes().to_vec(),
        };
        let facts = check_envelope(&credentials, &expected).expect("valid envelope verifies");
        assert_eq!(facts.grant.version, 3);
        assert_eq!(facts.authorization, NotEvaluated);
        assert_eq!(facts.grant.authorization, NotEvaluated);
    }
}
