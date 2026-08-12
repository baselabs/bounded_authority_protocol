//! Public input structs for the v1 verification façade (Task 8 subset).
//!
//! This module is the data-model home for the typed structs the public façade
//! (Tasks 10–13) consumes. Task 8 needs only the compact-signing kind enum and
//! the [`SigningInput`] struct that [`crate::compact::assemble_compact`] takes;
//! the remaining grant / proof / anchor / transition / envelope structs are
//! added by later tasks as their consumers land. Kept minimal and
//! dependency-free so Task 9 can EXTEND this file without rework.
//!
//! Derived first-hand from `docs/protocol-v1.md` § Public verification contract
//! (lines 291–330) and the `assemble-compact` conformance corpus — NOT from any
//! sibling-SDK or Elixir source (ADR 0014 D5).

use crate::error::{Invalid, Result};

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
}
