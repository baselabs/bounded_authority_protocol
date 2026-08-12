//! Public input structs for the v1 verification façade.
//!
//! This module is the data-model home for the typed structs the public façade
//! (Tasks 10–13) consumes. Task 8 landed the compact-signing kind enum and the
//! [`SigningInput`] struct that [`crate::compact::assemble_compact`] takes;
//! Task 9 EXTENDS this file with the remaining trusted-issuer, expected-grant,
//! expected-request, consumption-chain, boundary-anchor, key-transition, and
//! anchored-export input structs the façade and conformance runner (Task 14)
//! consume. No struct in this module derives `serde` (see F3 below).
//!
//! # F3 — no serde on any `src/` struct
//!
//! `serde` is a `[dev-dependencies]` entry only (invisible to the lib build);
//! every struct here is a plain Rust struct with `pub` fields that the
//! conformance runner assembles field-by-field from `serde_json::Value`. There
//! is deliberately NO `#[derive(serde::Serialize)]` or `Deserialize` anywhere
//! in `src/` — the lib build must not depend on serde, and planting such a
//! derive is a compile error (the T9 tripwire proves this). The fixed
//! cryptographic widths (`[u8; 32]` / `[u8; 64]`) are enforced as array types,
//! not stored in [`Bounds`] (`REQ1-BOUNDS-fixed-widths`).
//!
//! Derived first-hand from `docs/protocol-v1.md` § Public verification contract
//! (lines 291–373) and § Consumption chain and anchored export (lines 443–465),
//! `docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md`,
//! and the conformance corpus under `priv/conformance/v1/corpus/cases/` — NOT
//! from any sibling-SDK or Elixir source (ADR 0014 D5).

use crate::bounds::Bounds;
use crate::error::{Invalid, Result};
use crate::facts::NotEvaluated;
use crate::json::JsonValue;

/// The compact-JWS signing-input kind.
///
/// Tags which compact form a [`SigningInput`] belongs to. Only [`Grant`] is
/// corpus-exercised at Task 8; [`Proof`], [`ChainAnchor`], and [`KeyTransition`]
/// are the kinds the Task 10–13 producers / decoders of proof / anchor /
/// transition compacts consume (the protected-header `typ` check keys on this).
///
/// [`Grant`]: SigningKind::Grant
/// [`Proof`]: SigningKind::Proof
/// [`ChainAnchor`]: SigningKind::ChainAnchor
/// [`KeyTransition`]: SigningKind::KeyTransition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKind {
    /// A grant compact (`typ: "ba+cap"`).
    Grant,
    /// A proof compact (`typ: "ba+cap-proof"`).
    Proof,
    /// A signed consumption-chain boundary anchor.
    ChainAnchor,
    /// A signed historical-key transition.
    KeyTransition,
}

impl SigningKind {
    /// Decodes the lowercase corpus kind string to a [`SigningKind`].
    ///
    /// `"grant"` is corpus-pinned (the `assemble-compact` corpus). `"proof"`,
    /// `"chain_anchor"`, and `"key_transition"` are the snake-case forms the
    /// Task 10–13 proof / anchor / transition corpora finalize; only `"grant"`
    /// is exercised at Task 8. Any unknown kind string is `Invalid` — the set
    /// is closed (there is no generic / future-proof kind).
    //
    // `pub(crate)` but, until the v1 façade wires it (Task 10), the only caller
    // is this module's corpus test. `pub(crate)` does not suppress dead-code the
    // way `pub` does, so the per-item allow keeps the lint clean. Remove once
    // the façade decodes kinds through this.
    #[allow(dead_code)]
    pub(crate) fn decode(s: &str) -> Result<Self> {
        Ok(match s {
            "grant" => Self::Grant,
            "proof" => Self::Proof,
            "chain_anchor" => Self::ChainAnchor,
            "key_transition" => Self::KeyTransition,
            _ => return Err(Invalid),
        })
    }
}

/// The compact-JWS signing input: two already-canonical base64url segments.
///
/// Carries the two segments that form the exact RFC 7515 signing input
/// `ASCII(base64url(protected) || "." || base64url(payload))`
/// (`REQ1-SIGNING-exact-input`) plus the [`SigningKind`] the Task 10 façade
/// uses to validate the protected-header `typ`. The segments are
/// already-canonical base64url ASCII bytes;
/// [`crate::compact::assemble_compact`] passes them through VERBATIM and
/// appends the base64url-encoded signature — the composer does not re-encode or
/// re-validate the segments (`REQ1-SIGNING-any-order`: a correctly signed
/// closed JSON object may use any member order, so the producer's deterministic
/// JCS representation is the contract, not a re-canonicalization).
#[derive(Debug, Clone)]
pub struct SigningInput {
    /// The compact kind (grant / proof / anchor / transition).
    pub kind: SigningKind,
    /// The already-canonical base64url ASCII bytes of the protected header.
    pub protected_segment: Vec<u8>,
    /// The already-canonical base64url ASCII bytes of the payload.
    pub payload_segment: Vec<u8>,
}

// ============================================================================
// Trusted issuer + expected-context structs (verify_grant / check_envelope)
// ============================================================================

/// A caller-trusted issuer key: exact `kid` + raw 32-byte Ed25519 public key.
///
/// "`TrustedIssuer` contains exact `kid` and raw 32-byte public key"
/// (`docs/protocol-v1.md` line 336). The verifier accepts public keys only;
/// there is no field for a private exponent (`REQ1-HEADER-no-private-jwk`).
/// Sourced from the `grant-verify` / `envelope/check` corpus `trusted_issuer`
/// / `key_id`+`public_key` members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    /// The exact key ID (`kid`) the grant protected header must carry.
    pub key_id: String,
    /// The raw 32-byte Ed25519 public key (`REQ1-BOUNDS-fixed-widths`).
    pub public_key: [u8; 32],
}

/// Caller expectation for grant verification.
///
/// "`ExpectedGrant` contains issuer, audience, integral evaluation time,
/// nonnegative skew, and tightening bounds" (`docs/protocol-v1.md` lines
/// 336–338). The corpus `grant-verify` input supplies `issuer`, `audience`,
/// `evaluation_time`, `clock_skew`; `bounds` defaults to
/// [`Bounds::maximum()`] when the corpus carries no overrides, stored here so
/// the façade can tighten per-call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedGrant {
    /// Expected grant `iss` (StringOrURI, exact match).
    pub issuer: String,
    /// Expected audience (the caller asserts this exact resource).
    pub audience: String,
    /// Integral evaluation time (NumericDate seconds) the time invariants
    /// are checked against.
    pub evaluation_time: i64,
    /// Nonnegative clock skew (seconds); at most 60 (`REQ1-VERIFY-time-bounds`).
    pub skew: u64,
    /// Tightening bounds (defaults to [`Bounds::maximum()`]).
    pub bounds: Bounds,
}

/// Whether a proof nonce is required by the caller's replay policy.
///
/// The protocol's `:not_required | {:required, nonce}` spelled as a Rust enum
/// (`docs/protocol-v1.md` line 353). In `NotRequired` mode the proof MUST NOT
/// carry a `nonce`; in `Required(nonce)` it MUST carry exactly that nonce
/// (`REQ1-VERIFY-nonce-mode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceMode {
    /// The proof MUST NOT carry a `nonce` claim.
    NotRequired,
    /// The proof MUST carry exactly this `nonce` claim, once.
    Required(String),
}

/// Caller expectation for combined envelope verification (`check_envelope`).
///
/// "`ExpectedRequest` additionally contains a case-sensitive RFC 9110 token
/// method, normalized HTTPS URI, lowercase RFC 4122 invocation UUID, operation,
/// any tagged JSON cast arguments, positive proof maximum age, and
/// `:not_required | {:required, nonce}`" (`docs/protocol-v1.md` lines 351–353),
/// on top of the [`ExpectedGrant`] scalar/timing fields. The corpus
/// `envelope/check.json` `input.expected` object also embeds the
/// [`TrustedIssuer`] (the `check_envelope(Credentials, ExpectedRequest)` façade
/// takes no separate trusted-issuer argument, so it rides here).
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
    /// Tagged JSON cast arguments (the server-derived arguments the selectors
    /// applied against). Stored as [`JsonValue`] to preserve the protocol's
    /// integer/float tag distinction.
    pub cast_arguments: JsonValue,
    /// Positive proof maximum age (seconds); at most 300
    /// (`REQ1-VERIFY-time-bounds`).
    pub proof_max_age: u64,
    /// Caller's nonce policy (`:not_required | {:required, nonce}`).
    pub nonce_mode: NonceMode,
    /// The trusted issuer the grant must be signed by. Embedded because
    /// `check_envelope` takes no separate trusted-issuer argument.
    pub trusted_issuer: TrustedIssuer,
}

/// The raw holder credentials `check_envelope` binds.
///
/// Mirrors the `envelope/check.json` corpus `input.{grant, proof}` pair: the
/// received grant compact and proof compact bytes. Not in the T9 plan's
/// explicit name list, but required by the `check_envelope(Credentials,
/// ExpectedRequest)` façade signature (`docs/protocol-v1.md` line 303).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The received grant compact bytes (ASCII).
    pub grant: Vec<u8>,
    /// The received proof compact bytes (ASCII).
    pub proof: Vec<u8>,
}

// ============================================================================
// Untrusted key locator
// ============================================================================

/// The non-authorizing locator result: a `kid` hint plus `trust: not_evaluated`.
///
/// `untrusted_key_locator` "returns only `{:ok, %KeyLocator{kid: kid, trust:
/// :not_evaluated}}`" (`docs/protocol-v1.md` lines 433–435). It does not select
/// a key, decode claims, verify, evaluate trust, or authorize
/// (`REQ1-LOCATOR-not-authority`). Sourced from `key-locator/untrusted.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLocator {
    /// The grant protected-header `kid` hint (NOT a trust selector).
    pub key_id: String,
    /// Trust was not evaluated — the locator is not authority.
    pub trust: NotEvaluated,
}

// ============================================================================
// Decode results (verification: NotEvaluated)
// ============================================================================

/// Decoded (but NOT signature-verified) grant claims.
///
/// `decode_grant` parses and structurally validates the compact without
/// verifying the Ed25519 signature, so the result carries
/// `verification: NotEvaluated` (`REQ1-VERIFY-decode-not-evaluated`). It
/// surfaces the decoded identity/timing claims a caller inspects before
/// deciding to verify — a REDACTED VIEW of the parsed compact, not a verified
/// fact. The corpus `grant-decode/decode.json` `expected` pins only `key_id`;
/// the remaining fields are the unambiguous decoded scalars (the
/// `holder_thumbprint` is the decoded `cnf.jkt`, not a verified digest). It
/// carries NO operations/selectors (the authorization scope is intentionally
/// not surfaced by the decode view).
#[derive(Debug, Clone, PartialEq)]
pub struct GrantDecoded {
    /// The protected-header `kid` (corpus-pinned).
    pub key_id: String,
    /// The grant `v` claim (integral contract-major).
    pub version: i64,
    /// The grant `iss` claim.
    pub issuer: String,
    /// The grant `jti` (grant identifier).
    pub grant_id: String,
    /// The decoded `aud` claim (one or more audiences; the matched audience is
    /// not determined at decode time).
    pub audiences: Vec<String>,
    /// Decoded `cnf.jkt` (RFC 7638 thumbprint of the holder key) — parsed, not
    /// verified against a holder proof.
    pub holder_thumbprint: [u8; 32],
    /// Grant `iat` (integral NumericDate).
    pub issued_at: i64,
    /// Grant `nbf` (integral NumericDate).
    pub not_before: i64,
    /// Grant `exp` (integral NumericDate).
    pub expires_at: i64,
    /// Signature verification was not performed.
    pub verification: NotEvaluated,
}

/// Decoded (but NOT signature-verified) proof claims.
///
/// `decode_proof` parses and structurally validates the proof compact without
/// verifying the signature (`REQ1-VERIFY-decode-not-evaluated`). The corpus
/// `proof-decode/decode.json` `expected` pins only `proof_id`; the remaining
/// fields are the decoded proof claims. `nonce` is surfaced as an `Option`
/// because a proof MAY carry one (decode reflects what was decoded; the
/// facts-redaction contract governs verified facts, not decode views — the
/// nonce is already public in the proof's cleartext payload).
#[derive(Debug, Clone, PartialEq)]
pub struct ProofDecoded {
    /// The protected-header `kid` hint (the proof header carries a JWK, not a
    /// trusted `kid`).
    pub key_id: String,
    /// The proof `jti` (corpus-pinned).
    pub proof_id: String,
    /// The proof `htm` (case-sensitive HTTP method).
    pub method: String,
    /// The proof `htu` (normalized HTTPS URI).
    pub target_uri: String,
    /// The proof `ba_inv` (lowercase RFC 4122 invocation UUID).
    pub invocation_id: String,
    /// The proof `ba_op` (operation name).
    pub operation: String,
    /// Decoded `ath` — raw 32-byte SHA-256 over the received grant compact.
    pub grant_hash: [u8; 32],
    /// Decoded `ba_req` — raw 32-byte request digest.
    pub request_hash: [u8; 32],
    /// The proof `iat` (integral NumericDate).
    pub issued_at: i64,
    /// Decoded RFC 7638 thumbprint of the proof-header JWK (the holder key),
    /// parsed not verified.
    pub holder_thumbprint: [u8; 32],
    /// The optional proof `nonce` (None iff absent).
    pub nonce: Option<String>,
    /// Signature verification was not performed.
    pub verification: NotEvaluated,
}

// ============================================================================
// Consumption chain
// ============================================================================

/// Raw consumption-row bytes for chain range verification.
///
/// Per the `check_chain(ChainInput, ExpectedChain)` façade split,
/// [`ChainInput`] carries ONLY the received raw canonical row binaries; every
/// boundary the range is bound against lives in [`ExpectedChain`]. ADR 0004:
/// "Verification accepts a nonempty proper list of raw row binaries and an
/// `ExpectedChain`." Each entry is `base64url`-decoded from the corpus
/// `consumption-chain/check.json` `input.rows` member (a row is the closed JCS
/// object `{"chain_id","commitment","previous","sequence","v"}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainInput {
    /// Raw canonical consumption-row bytes (one `Vec<u8>` per row).
    pub rows: Vec<Vec<u8>>,
}

/// Caller-expected chain boundaries for `check_chain`.
///
/// The caller's intended range context: chain identity, sequence span, row
/// count, and the predecessor/head digests a self-consistent chain alone
/// cannot prove (`REQ1-CHAIN-no-deletion-cert`). Mapped from the corpus
/// `consumption-chain/check.json` `input` members; the corpus `last_hash` maps
/// to `head_hash` (ADR 0004 calls this "caller head").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedChain {
    /// Expected chain identity.
    pub chain_id: String,
    /// Expected first row sequence.
    pub first_sequence: i64,
    /// Expected last row sequence.
    pub last_sequence: i64,
    /// Expected row count.
    pub row_count: i64,
    /// Raw 32-byte caller predecessor (the all-zero hash for a genesis range).
    pub previous_hash: [u8; 32],
    /// Raw 32-byte caller head (corpus `last_hash`).
    pub head_hash: [u8; 32],
}

/// A single canonical consumption row the caller asks the encoder to frame.
///
/// Closed row shape (ADR 0004 § Consumption rows):
/// `{"chain_id":"<StringOrURI>","commitment":"<base64url-32>","previous":
/// "<base64url-32>","sequence":1,"v":1}`. Sequence one requires the all-zero
/// predecessor. Sourced from `consumption-chain/entry.json` `input`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionEntry {
    /// The chain identity.
    pub chain_id: String,
    /// Raw 32-byte commitment (opaque to the protocol).
    pub commitment: [u8; 32],
    /// Raw 32-byte predecessor hash.
    pub previous_hash: [u8; 32],
    /// Row sequence number (positive; 0 is invalid).
    pub sequence: i64,
}

// ============================================================================
// Boundary anchor + key transition (producer inputs + historical-key shape)
// ============================================================================

/// Open vs. bounded upper validity interval for a historical key.
///
/// ADR 0004: "`:unbounded` is the only open upper interval" for a
/// [`HistoricalPublicKey`]. The corpus always carries an integral
/// `valid_before`, but the contract permits an unbounded upper bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidityUpperBound {
    /// A bounded upper NumericDate.
    Bounded(i64),
    /// The open upper interval (`:unbounded`).
    Unbounded,
}

/// A historical Ed25519 public key with its validity interval.
///
/// Used by `verify_historical_anchor` (one key), `verify_key_transition`
/// (current + next), and `verify_anchored_export` (an ordered chain via
/// [`HistoricalKeyChain`]). Sourced from the `key`/`current_key`/`next_key`/
/// `keys` members of the boundary-anchor, key-transition, and anchored-export
/// corpora.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalPublicKey {
    /// The key's `kid`.
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// Lower validity bound (integral NumericDate, always bounded).
    pub valid_from: i64,
    /// Upper validity bound (bounded NumericDate or [`ValidityUpperBound::Unbounded`]).
    pub valid_before: ValidityUpperBound,
}

/// Ordered historical public-key chain an anchored export advances through.
///
/// A newtype around `Vec<HistoricalPublicKey>` so the
/// `verify_anchored_export(ArchivedObject, HistoricalKeyChain,
/// ExpectedAnchoredExport)` façade takes a distinct named struct. Sourced from
/// `anchored-export/verify.json` `input.keys`. Positional order is load-bearing
/// (ADR 0004: "advances through the caller-supplied ordered key list
/// positionally").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalKeyChain {
    /// Ordered historical keys (start key first).
    pub keys: Vec<HistoricalPublicKey>,
}

/// A boundary anchor the producer frames into a compact signing input.
///
/// Closed payload binds: protocol version, anchor identity and time, chain
/// identity, sequence, chain hash, and the key ID (ADR 0004 § Boundary
/// anchors). `public_key` is the raw 32-byte signing key supplied to the
/// producer (the verifier receives it separately as a [`HistoricalPublicKey`]).
/// Sourced from `signing-input/anchor.json` `input`.
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
    /// Raw 32-byte Ed25519 public key (the producer derives the fingerprint).
    pub public_key: [u8; 32],
    /// Anchor sequence (zero for a start anchor).
    pub sequence: i64,
}

/// A historical key transition the producer frames into a compact signing input.
///
/// Closed payload binds: transition and chain identities, effective time,
/// current fingerprint, next key ID, and next fingerprint (ADR 0004 §
/// Authenticated key transitions). The current key signs it. Sourced from
/// `signing-input/transition.json` `input`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTransition {
    /// The chain identity.
    pub chain_id: String,
    /// The current (signing) key's `kid`.
    pub current_key_id: String,
    /// Raw 32-byte current Ed25519 public key (signs the transition).
    pub current_public_key: [u8; 32],
    /// Effective time of the transition (integral NumericDate).
    pub effective_at: i64,
    /// The next key's `kid`.
    pub next_key_id: String,
    /// Raw 32-byte next Ed25519 public key.
    pub next_public_key: [u8; 32],
    /// The transition identity.
    pub transition_id: String,
}

/// Caller-expected signed boundary-anchor values for `verify_historical_anchor`.
///
/// Sourced from `boundary-anchor/verify.json` `input.expected`. Verification
/// requires the signed values, key ID, derived fingerprint, Ed25519 signature,
/// and `valid_from <= anchored_at < valid_before`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAnchor {
    /// Expected `anchor_id`.
    pub anchor_id: String,
    /// Expected `anchored_at` (integral NumericDate).
    pub anchored_at: i64,
    /// Raw 32-byte expected `chain_hash`.
    pub chain_hash: [u8; 32],
    /// Expected `chain_id`.
    pub chain_id: String,
    /// Raw 32-byte expected RFC 7638 key fingerprint.
    pub key_fingerprint: [u8; 32],
    /// Expected `kid`.
    pub key_id: String,
    /// Expected anchor sequence.
    pub sequence: i64,
}

/// Caller-expected signed key-transition values for `verify_key_transition`.
///
/// Sourced from `key-transition/verify.json` `input.expected`. Current and next
/// public keys/fingerprints must differ; their key IDs may be equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedKeyTransition {
    /// Expected `chain_id`.
    pub chain_id: String,
    /// Raw 32-byte expected current key fingerprint.
    pub current_key_fingerprint: [u8; 32],
    /// Expected current `kid`.
    pub current_key_id: String,
    /// Expected `effective_at` (integral NumericDate).
    pub effective_at: i64,
    /// Raw 32-byte expected next key fingerprint.
    pub next_key_fingerprint: [u8; 32],
    /// Expected next `kid`.
    pub next_key_id: String,
    /// Expected `transition_id`.
    pub transition_id: String,
}

// ============================================================================
// Anchored export
// ============================================================================

/// The retrieved archived object an anchored-export verification binds.
///
/// "`anchored export verification accepts only %ArchivedObject{chunks:
/// raw_binary_chunks, version: version}`" (`docs/protocol-v1.md` lines
/// 450–452). `chunks` is the bounded nonempty proper flat chunk list (each
/// `base64url`-decoded from `anchored-export/verify.json` `input.chunks`);
/// `version` is the observed object-store version, compared for exact equality
/// against the caller-supplied expected version
/// (`REQ1-EXPORT-version-exact`). Commitment preimages stay opaque/private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedObject {
    /// Raw binary archive chunks (the framed concatenation).
    pub chunks: Vec<Vec<u8>>,
    /// The observed object-store version (out-of-band context).
    pub version: String,
}

/// Artifacts the anchored-export producer frames into the archive bytes.
///
/// The `encode_anchored_export(AnchoredExportInput, ExpectedExport)` façade
/// splits the corpus `anchored-export/encode.json` `input` blob into the
/// artifacts (here) and the caller's expected boundaries ([`ExpectedExport`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredExportInput {
    /// The start-anchor compact bytes.
    pub start_anchor: Vec<u8>,
    /// The end-anchor compact bytes.
    pub end_anchor: Vec<u8>,
    /// Ordered key-transition compact bytes (possibly empty).
    pub transitions: Vec<Vec<u8>>,
    /// Raw canonical consumption-row bytes (possibly the encode input set).
    pub rows: Vec<Vec<u8>>,
}

/// Caller-expected anchored-export boundaries (the encode path).
///
/// Sourced from `anchored-export/encode.json` `input.expected`. Reuses
/// [`ExpectedChain`], [`ExpectedAnchor`], and [`ExpectedKeyTransition`] — the
/// same shapes the verify path's [`ExpectedAnchoredExport`] carries. Kept a
/// distinct struct so the `encode_anchored_export(…, ExpectedExport)` façade
/// param is a distinct named type.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedExport {
    /// Expected chain boundaries (chain id, sequence span, row count,
    /// predecessor, head).
    pub chain: ExpectedChain,
    /// Raw 32-byte expected complete-archive SHA-256.
    pub digest: [u8; 32],
    /// Expected start-anchor signed values.
    pub start_anchor: ExpectedAnchor,
    /// Expected end-anchor signed values.
    pub end_anchor: ExpectedAnchor,
    /// Expected ordered transition signed values (possibly empty).
    pub transitions: Vec<ExpectedKeyTransition>,
    /// Expected object-store version.
    pub object_version: String,
}

/// Caller-expected anchored-export boundaries (the verify path).
///
/// Sourced from `anchored-export/verify.json` `input.expected`. Field-identical
/// to [`ExpectedExport`] (both describe the archive's expected bindings), but a
/// distinct struct so the `verify_anchored_export(…, ExpectedAnchoredExport)`
/// façade param is a distinct named type.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedAnchoredExport {
    /// Expected chain boundaries.
    pub chain: ExpectedChain,
    /// Raw 32-byte expected complete-archive SHA-256.
    pub digest: [u8; 32],
    /// Expected start-anchor signed values.
    pub start_anchor: ExpectedAnchor,
    /// Expected end-anchor signed values.
    pub end_anchor: ExpectedAnchor,
    /// Expected ordered transition signed values.
    pub transitions: Vec<ExpectedKeyTransition>,
    /// Expected object-store version (`REQ1-EXPORT-version-exact`).
    pub object_version: String,
}

/// The encode-anchored-export producer result.
///
/// Sourced from `anchored-export/encode.json` `expected` (`byte_count` +
/// `digest`). `bytes` is the framed archive concatenation the caller stores;
/// `byte_count` and `digest` are the derived conveniences the corpus pins. None
/// of the three is a credential — the archive is public, and the digest is a
/// SHA-256 over public bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredExportEncoded {
    /// The framed archive bytes (`"BAP1-ARCHIVE\0EXPORT\0"` + frames + EOF).
    pub bytes: Vec<u8>,
    /// Length of `bytes` (the corpus-pinned `byte_count`).
    pub byte_count: u64,
    /// Raw 32-byte SHA-256 over `bytes` (the corpus-pinned `digest`).
    pub digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // SigningKind::decode — closed lowercase kind set
    // ==========================================================================

    #[test]
    fn decode_grant() {
        assert_eq!(SigningKind::decode("grant"), Ok(SigningKind::Grant));
    }

    #[test]
    fn decode_proof() {
        // Not corpus-exercised at Task 8; the snake-case form is the T10
        // proof-corpus convention to finalize.
        assert_eq!(SigningKind::decode("proof"), Ok(SigningKind::Proof));
    }

    #[test]
    fn decode_chain_anchor() {
        assert_eq!(
            SigningKind::decode("chain_anchor"),
            Ok(SigningKind::ChainAnchor)
        );
    }

    #[test]
    fn decode_key_transition() {
        assert_eq!(
            SigningKind::decode("key_transition"),
            Ok(SigningKind::KeyTransition)
        );
    }

    #[test]
    fn decode_unknown_is_invalid() {
        // Closed set: there is no generic / future-proof kind.
        assert_eq!(SigningKind::decode("matches"), Err(Invalid));
        assert_eq!(SigningKind::decode("GRANT"), Err(Invalid)); // case-sensitive
        assert_eq!(SigningKind::decode(""), Err(Invalid));
    }

    // ==========================================================================
    // SigningInput — construction (kind carried as metadata)
    // ==========================================================================

    #[test]
    fn signing_input_carries_segments_and_kind() {
        let input = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: b"prot".to_vec(),
            payload_segment: b"pay".to_vec(),
        };
        assert_eq!(input.kind, SigningKind::Grant);
        assert_eq!(input.protected_segment, b"prot");
        assert_eq!(input.payload_segment, b"pay");
    }

    // ==========================================================================
    // Task 9 — input-struct structural sanity (Debug renders, Clone works,
    // the fixed crypto widths are the array types). These are smoke tests; the
    // real exercise of every field lands in Tasks 10–14.
    // ==========================================================================

    fn zero32() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn trusted_ispector_constructs_and_clones() {
        let a = TrustedIssuer {
            key_id: "issuer".to_string(),
            public_key: zero32(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let debug = format!("{a:?}");
        assert!(debug.contains("TrustedIssuer"));
    }

    #[test]
    fn expected_grant_carries_bounds() {
        let g = ExpectedGrant {
            issuer: "https://issuer.example.test".to_string(),
            audience: "https://resource.example.test".to_string(),
            evaluation_time: 1500,
            skew: 60,
            bounds: Bounds::maximum(),
        };
        assert_eq!(g.bounds.compact_bytes(), Bounds::maximum().compact_bytes());
        let _ = g.clone();
    }

    #[test]
    fn nonce_mode_variants() {
        assert_eq!(NonceMode::NotRequired, NonceMode::NotRequired);
        let r1 = NonceMode::Required("server-nonce-x".to_string());
        let r2 = NonceMode::Required("server-nonce-x".to_string());
        assert_eq!(r1, r2);
        assert_ne!(NonceMode::NotRequired, r1);
    }

    #[test]
    fn expected_request_constructs_with_all_fields() {
        let req = ExpectedRequest {
            issuer: "https://issuer.example.test".to_string(),
            audience: "https://resource.example.test".to_string(),
            evaluation_time: 1200,
            skew: 60,
            bounds: Bounds::maximum(),
            method: "POST".to_string(),
            target_uri: "https://resource.example.test/invoke".to_string(),
            invocation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            operation: "read".to_string(),
            cast_arguments: JsonValue::Null,
            proof_max_age: 300,
            nonce_mode: NonceMode::NotRequired,
            trusted_issuer: TrustedIssuer {
                key_id: "issuer".to_string(),
                public_key: zero32(),
            },
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("ExpectedRequest"));
        assert!(debug.contains("cast_arguments"));
        let _ = req.clone();
    }

    #[test]
    fn credentials_constructs() {
        let c = Credentials {
            grant: b"g".to_vec(),
            proof: b"p".to_vec(),
        };
        assert_eq!(c.grant, b"g");
        assert_eq!(c.proof, b"p");
        let _ = c.clone();
    }

    #[test]
    fn key_locator_carries_not_evaluated() {
        let loc = KeyLocator {
            key_id: "issuer".to_string(),
            trust: NotEvaluated,
        };
        let debug = format!("{loc:?}");
        assert!(debug.contains("NotEvaluated"));
        let _ = loc.clone();
    }

    #[test]
    fn grant_decoded_constructs() {
        let d = GrantDecoded {
            key_id: "issuer".to_string(),
            version: 1,
            issuer: "https://issuer.example.test".to_string(),
            grant_id: "urn:example:grant:1".to_string(),
            audiences: vec!["https://resource.example.test".to_string()],
            holder_thumbprint: zero32(),
            issued_at: 1000,
            not_before: 1000,
            expires_at: 2000,
            verification: NotEvaluated,
        };
        let debug = format!("{d:?}");
        assert!(debug.contains("GrantDecoded"));
        assert!(debug.contains("verification"));
        let _ = d.clone();
    }

    #[test]
    fn proof_decoded_constructs_with_and_without_nonce() {
        let base = || ProofDecoded {
            key_id: "issuer".to_string(),
            proof_id: "urn:example:proof:1".to_string(),
            method: "POST".to_string(),
            target_uri: "https://resource.example.test/invoke".to_string(),
            invocation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            operation: "read".to_string(),
            grant_hash: zero32(),
            request_hash: zero32(),
            issued_at: 1100,
            holder_thumbprint: zero32(),
            nonce: None,
            verification: NotEvaluated,
        };
        let without = base();
        let mut with = base();
        with.nonce = Some("server-nonce-x".to_string());
        assert_ne!(without, with);
        assert_eq!(without.nonce, None);
        assert_eq!(with.nonce.as_deref(), Some("server-nonce-x"));
        let _ = without.clone();
        let _ = with.clone();
    }

    #[test]
    fn chain_input_and_expected_chain_constructs() {
        let input = ChainInput {
            rows: vec![b"row1".to_vec(), b"row2".to_vec()],
        };
        let expected = ExpectedChain {
            chain_id: "urn:example:chain".to_string(),
            first_sequence: 1,
            last_sequence: 2,
            row_count: 2,
            previous_hash: zero32(),
            head_hash: zero32(),
        };
        assert_eq!(input.rows.len(), 2);
        assert_eq!(expected.row_count, 2);
        let _ = input.clone();
        let _ = expected.clone();
    }

    #[test]
    fn consumption_entry_constructs() {
        let e = ConsumptionEntry {
            chain_id: "urn:example:chain".to_string(),
            commitment: zero32(),
            previous_hash: zero32(),
            sequence: 1,
        };
        let _ = e.clone();
        assert_eq!(e.sequence, 1);
    }

    #[test]
    fn validity_upper_bound_variants() {
        assert_eq!(
            ValidityUpperBound::Bounded(3000),
            ValidityUpperBound::Bounded(3000)
        );
        assert_eq!(ValidityUpperBound::Unbounded, ValidityUpperBound::Unbounded);
        assert_ne!(
            ValidityUpperBound::Bounded(3000),
            ValidityUpperBound::Unbounded
        );
    }

    #[test]
    fn historical_public_key_and_chain_constructs() {
        let k = HistoricalPublicKey {
            key_id: "archive-a".to_string(),
            public_key: zero32(),
            valid_from: 0,
            valid_before: ValidityUpperBound::Bounded(3000),
        };
        let k_unbounded = HistoricalPublicKey {
            key_id: "archive-a".to_string(),
            public_key: zero32(),
            valid_from: 0,
            valid_before: ValidityUpperBound::Unbounded,
        };
        assert_ne!(k, k_unbounded);
        let chain = HistoricalKeyChain {
            keys: vec![k, k_unbounded],
        };
        assert_eq!(chain.keys.len(), 2);
        let _ = chain.clone();
    }

    #[test]
    fn boundary_anchor_constructs() {
        let a = BoundaryAnchor {
            anchor_id: "urn:example:anchor:start".to_string(),
            anchored_at: 1000,
            chain_hash: zero32(),
            chain_id: "urn:example:chain".to_string(),
            key_id: "anchor-a".to_string(),
            public_key: zero32(),
            sequence: 0,
        };
        let debug = format!("{a:?}");
        assert!(debug.contains("BoundaryAnchor"));
        let _ = a.clone();
    }

    #[test]
    fn key_transition_constructs() {
        let t = KeyTransition {
            chain_id: "urn:example:chain".to_string(),
            current_key_id: "anchor-a".to_string(),
            current_public_key: zero32(),
            effective_at: 1500,
            next_key_id: "anchor-b".to_string(),
            next_public_key: [1u8; 32],
            transition_id: "urn:example:transition:a-b".to_string(),
        };
        let _ = t.clone();
        assert_eq!(t.effective_at, 1500);
    }

    #[test]
    fn expected_anchor_and_transition_constructs() {
        let anchor = ExpectedAnchor {
            anchor_id: "urn:example:anchor:start".to_string(),
            anchored_at: 1000,
            chain_hash: zero32(),
            chain_id: "urn:example:chain".to_string(),
            key_fingerprint: zero32(),
            key_id: "archive-a".to_string(),
            sequence: 0,
        };
        let transition = ExpectedKeyTransition {
            chain_id: "urn:example:chain".to_string(),
            current_key_fingerprint: zero32(),
            current_key_id: "archive-a".to_string(),
            effective_at: 1500,
            next_key_fingerprint: zero32(),
            next_key_id: "archive-b".to_string(),
            transition_id: "urn:example:transition:a-b".to_string(),
        };
        let _ = anchor.clone();
        let _ = transition.clone();
    }

    #[test]
    fn anchored_export_structs_construct() {
        let object = ArchivedObject {
            chunks: vec![b"chunk1".to_vec()],
            version: "v1".to_string(),
        };
        let input = AnchoredExportInput {
            start_anchor: b"s".to_vec(),
            end_anchor: b"e".to_vec(),
            transitions: vec![b"t".to_vec()],
            rows: vec![b"r".to_vec()],
        };
        let expected_anchor = ExpectedAnchor {
            anchor_id: String::new(),
            anchored_at: 0,
            chain_hash: zero32(),
            chain_id: String::new(),
            key_fingerprint: zero32(),
            key_id: String::new(),
            sequence: 0,
        };
        let expected_chain = ExpectedChain {
            chain_id: String::new(),
            first_sequence: 1,
            last_sequence: 1,
            row_count: 1,
            previous_hash: zero32(),
            head_hash: zero32(),
        };
        let expected_export = ExpectedExport {
            chain: expected_chain.clone(),
            digest: zero32(),
            start_anchor: expected_anchor.clone(),
            end_anchor: expected_anchor.clone(),
            transitions: vec![],
            object_version: "v1".to_string(),
        };
        let expected_verify = ExpectedAnchoredExport {
            chain: expected_chain,
            digest: zero32(),
            start_anchor: expected_anchor.clone(),
            end_anchor: expected_anchor,
            transitions: vec![],
            object_version: "v1".to_string(),
        };
        let encoded = AnchoredExportEncoded {
            bytes: b"archive".to_vec(),
            byte_count: 7,
            digest: zero32(),
        };
        assert_eq!(encoded.byte_count, 7);
        assert_eq!(object.version, "v1");
        assert_eq!(input.rows.len(), 1);
        assert_eq!(expected_export.object_version, "v1");
        assert_eq!(expected_verify.object_version, "v1");
        let _ = object.clone();
        let _ = input.clone();
        let _ = expected_export.clone();
        let _ = expected_verify.clone();
        let _ = encoded.clone();
    }
}
