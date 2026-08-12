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
pub mod json;

pub use base64url::{base64url_decode, base64url_encode};
pub use bounds::Bounds;
pub use error::{Invalid, Result};
pub use json::{json_decode, JsonValue};
