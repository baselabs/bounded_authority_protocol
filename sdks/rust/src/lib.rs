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
pub mod jcs;
pub mod json;

// `digest` is an internal mechanic behind the v1 façade (protocol-v1.md §lines
// 329–330): its typed projection is not a stable public primitive. The module
// is `pub(crate)` so the façade (Task 10–12) can call `request_digest`; it is
// intentionally NOT re-exported at the crate root and does not widen the 0.1.0
// public surface. Until the façade wires it, nothing in the non-test crate
// calls `request_digest`, so the dead-code allow inside the module keeps the
// lint clean (removed once the façade makes the call chain reachable).
pub(crate) mod digest;

pub use base64url::{base64url_decode, base64url_encode};
pub use bounds::Bounds;
pub use error::{Invalid, Result};
pub use jcs::jcs_encode;
pub use json::{json_decode, JsonValue};
