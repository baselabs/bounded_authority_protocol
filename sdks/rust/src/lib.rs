//! Bounded proof-of-possession authority verification — frozen v1 profile.
//!
//! Pure, deterministic, fail-closed reimplementation of the v1 profile from
//! `docs/protocol-v1.md`, governed by the ADRs and the conformance corpus.
//! **Verification is not authority**: a successful result proves only that
//! caller-supplied bytes satisfy caller-supplied trusted inputs and expected
//! context. It never selects keys, reserves replay, grants execution, or
//! overrides a host policy.
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
pub mod types;
pub mod uri;

// `compact`, `digest`, `ed25519`, and `selector` are internal mechanics behind
// the v1 façade (protocol-v1.md §lines 329–330 names only `jcs`/`jwk`/`uri`/
// `base64url`/`bounds`/`json` as public primitives, and notes that request-
// digest, selector, and compact-JWS composition mechanics "remain internal
// implementation behind the supported façade; their modules are not additional
// stable façade contracts"). They are `pub(crate)` so the façade (Task 10–13)
// can call them; they are intentionally NOT re-exported at the crate root and
// do not widen the 0.1.0 public surface. `assemble_compact` is `pub fn` so the
// Task 10 façade can `pub use` re-export it, but the module itself stays
// internal. Until the façade wires them, nothing in the non-test crate calls
// any of these, so the dead-code allow inside each module keeps the lint clean
// (removed once the façade makes the call chain reachable).
pub(crate) mod compact;
pub(crate) mod digest;
pub(crate) mod ed25519;
pub(crate) mod selector;

pub use base64url::{base64url_decode, base64url_encode};
pub use bounds::Bounds;
pub use error::{Invalid, Result};
pub use jcs::jcs_encode;
pub use json::{json_decode, JsonValue};
pub use jwk::{
    jwk_decode_public, jwk_encode_public, public_key_thumbprint_raw, thumbprint,
    thumbprint_preimage, thumbprint_raw,
};
pub use uri::uri_normalize;
