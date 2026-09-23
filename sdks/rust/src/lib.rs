//! Bounded proof-of-possession authority verification — frozen v1 profile and
//! contract-major v2 profile.
//!
//! Pure, deterministic, fail-closed reimplementation of the v1 profile from
//! `spec/bap-v1.md` and the v2 profile (`BAP2-Ed25519-SHA256`) from the same
//! requirement table carried at major 2, governed by the ADRs and the
//! per-major conformance corpora. **Verification is not authority**: a
//! successful result proves only that caller-supplied bytes satisfy
//! caller-supplied trusted inputs and expected context. It never selects
//! keys, reserves replay, grants execution, or overrides a host policy.
//!
//! Every public function returns [`Result<T>`](crate::Result), the Rust
//! spelling of `{:ok, value}` / `{:error, :invalid}`. There is exactly one
//! error shape ([`Invalid`]) — the protocol forbids variants.

#![forbid(unsafe_code)]

pub mod base64url;
pub mod bounds;
pub mod error;
pub mod facts;
pub mod jcs;
pub mod json;
pub mod jwk;
pub mod role_attestation;
pub mod types;
pub mod uri;
pub mod v1;
pub mod v2;
pub mod v3;

// `compact`, `digest`, `ed25519`, `es256`, and `selector` are internal mechanics behind
// the façades (spec/bap-v1.md §lines 329–330 names only `jcs`/`jwk`/`uri`/
// `base64url`/`bounds`/`json` as public primitives, and notes that request-
// digest, selector, and compact-JWS composition mechanics "remain internal
// implementation behind the supported façade; their modules are not additional
// stable façade contracts"). The MODULES are `pub(crate)` so the façades can
// call them; they are intentionally NOT re-exported as module contracts and do
// not widen the 0.1.0 public module surface. `assemble_compact` is `pub fn` so
// the Task 10 façade can `pub use` re-export it, but the module itself stays
// internal. All five are wired by the v1/v2/v3 façade call chains.
//
// One distinction the line-329 note draws: request-digest, selector, and
// compact-JWS MODULES are not additional stable façade contracts, BUT
// `request_digest/3` IS named in the 17-function public verification contract
// (spec/bap-v1.md line 304). So the `digest` MODULE stays `pub(crate)` while
// its `request_digest` FUNCTION is re-exported at the crate root as a public
// façade entry point (the conformance runner — Task 14 — dispatches the 9-case
// `request_digest` corpus through this public re-export). `selector` and
// `compact` have no equivalently-named façade function and stay fully internal.
pub(crate) mod compact;
pub(crate) mod digest;
pub(crate) mod ed25519;
pub(crate) mod es256;
pub(crate) mod selector;

// Façade A/B/C/D re-exports (Tasks 10–13): the public v1 entry points reachable
// at the crate root. `assemble_compact` is re-exported from the `v1` façade
// (compose + per-kind content validation); the pure composer lives internal to
// `compact`. `request_digest` is re-exported from the internal `digest` MODULE
// (the function is public — spec/bap-v1.md line 304 — even though the module is
// not a stable façade contract — line 329).
//
// The v2 and v3 façades keep their entry points on the `v2`/`v3` modules
// (`v2::verify_grant`, `v3::verify_grant`, etc.): the majors expose
// same-named functions with byte-distinct contracts, so a root-level
// re-export set would collide; the module path IS the major namespace.
pub use digest::request_digest;
pub use role_attestation::{
    assemble_attestation_compact, attestation_signing_input, decode_attestation, verify_attestation,
};
pub use v1::assemble_compact;
pub use v1::{
    assemble_local_loopback_http_compact, boundary_anchor_signing_input, check_chain,
    check_envelope, check_local_loopback_http_envelope, decode_grant,
    decode_local_loopback_http_proof, decode_proof, encode_anchored_export,
    encode_consumption_entry, grant_signing_input, key_transition_signing_input,
    local_loopback_http_proof_signing_input, proof_signing_input, untrusted_key_locator,
    verify_anchored_export, verify_grant, verify_historical_anchor, verify_key_transition,
};

pub use base64url::{base64url_decode, base64url_encode};
pub use bounds::Bounds;
pub use error::{Invalid, Result};
pub use jcs::jcs_encode;
pub use json::{json_decode, JsonValue};
pub use jwk::{
    jwk_decode_public, jwk_encode_public, public_key_thumbprint_raw, thumbprint,
    thumbprint_preimage, thumbprint_raw,
};
pub use uri::{local_loopback_http_uri_normalize, uri_normalize};
pub use v1::{require_bounds_equal, resolve_bounds};
