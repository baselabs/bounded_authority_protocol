//! Ed25519 verify wrapper — the `BAP1-Ed25519-SHA256` signature backend.
//!
//! Thin wrapper over `ed25519-dalek` 2.2 with `default-features = false` (the
//! serial verify backend — no `fast`/`asm`/`pkcs8`/`pem`/`rand_core` features;
//! verify-only). Per design-note D-RISK-2, the accepted posture is that
//! `curve25519-dalek` / `ed25519-dalek` carry transitive `unsafe` internally;
//! the crate-level `#![forbid(unsafe_code)]` covers OUR code only and does not
//! reach into the backend. This module does not attempt to eliminate that
//! transitive `unsafe` — it is the documented, accepted trade for a reviewed
//! pure-Rust Ed25519 verify path.
//!
//! **Verify-only, public keys only.** No key generation, no signing callback,
//! and no secret material enters this module or the crate. **Verification is
//! not authority:** this function proves only that caller-supplied bytes
//! satisfy caller-supplied trusted inputs; it never selects keys, reserves
//! replay, checks live revocation, or grants execution.
//!
//! Every backend rejection or exception — a public-key encoding that does not
//! decompress to a valid Edwards point, a signature that does not verify, or
//! any internal error inside the backend — collapses to exactly `Err(Invalid)`
//! (`REQ1-SIGNING-backend-reject`). The backend's `SignatureError` carries
//! diagnostic detail that the protocol forbids leaking, so it is mapped to the
//! single closed error shape and discarded.

// `verify` is `pub(crate)` but, until the v1 façade wires it (Task 10–13),
// nothing in the non-test crate calls it. `pub(crate)` does NOT suppress the
// dead-code lint the way `pub` does (the compiler sees the whole crate and
// knows nothing calls it), so the module-level allow keeps the lint clean.
// Remove this once the façade makes the call chain reachable. Mirrors the
// `digest` module's precedent.
#![allow(dead_code)]

use crate::error::{Invalid, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify an Ed25519 signature of `message` against a 32-byte public key.
///
/// `public_key` (`[u8; 32]`) and `signature` (`[u8; 64]`) are the fixed
/// cryptographic encodings (`REQ1-BOUNDS-fixed-widths`); they arrive as fixed
/// array types, so no width check is possible or needed at this boundary.
///
/// Returns `Ok(())` when the signature verifies, or `Err(Invalid)` for any
/// backend rejection or exception (`REQ1-SIGNING-backend-reject`):
/// - a 32-byte public-key encoding that does not decompress to a valid Edwards
///   point (some bit patterns are not on the curve — `from_bytes` rejects
///   them, e.g. the all-zero key);
/// - a signature that does not verify against the key and message;
/// - any internal error inside the backend.
///
/// `Signature::from_bytes` on a `[u8; 64]` is structurally infallible (every
/// 64-byte pattern is a syntactically valid signature encoding); an invalid
/// signature is rejected by `verify`, not by construction.
pub(crate) fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    // REQ1-SIGNING-backend-reject: any backend error -> Invalid. Some 32-byte
    // patterns are not valid Edwards-Y points; from_bytes returns a
    // PointDecompression error which we collapse to Invalid.
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| Invalid)?;
    // Canonical-encoding infallible constructor on the fixed 64-byte array.
    let sig = Signature::from_bytes(signature);
    // The actual Ed25519 verification; any failure (or internal backend error)
    // -> Invalid. The error's diagnostic detail is deliberately discarded.
    vk.verify(message, &sig).map_err(|_| Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string to bytes (test-only fixture helper).
    fn hex_decode(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "hex length must be even");
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .unwrap_or_else(|_| panic!("invalid hex byte {}", &hex[i..i + 2]))
            })
            .collect()
    }

    fn to_arr_32(v: Vec<u8>) -> [u8; 32] {
        assert_eq!(v.len(), 32, "expected 32 bytes");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn to_arr_64(v: Vec<u8>) -> [u8; 64] {
        assert_eq!(v.len(), 64, "expected 64 bytes");
        let mut a = [0u8; 64];
        a.copy_from_slice(&v);
        a
    }

    // ==========================================================================
    // RFC 8032 §7.1 TEST 1 — the independent positive + tamper battery
    //
    // ALL test material below is PUBLIC (the RFC's published public key +
    // signature + empty message). This crate is verify-only and public-keys-
    // only (AGENTS.md rule #6): no SigningKey, secret seed, or private scalar
    // enters the source even in tests. The RFC vector is an INDEPENDENT
    // implementation's output — NOT a self-round-trip — so a passing verify
    // proves ed25519-dalek interoperates with the RFC reference.
    // ==========================================================================

    /// RFC 8032 §7.1 TEST 1 PUBLIC material (fetched from
    /// https://www.rfc-editor.org/rfc/rfc8032.html):
    ///   PUBLIC KEY:  d75a980182b10ab7d54bfed3c964073a
    ///                0ee172f3daa62325af021a68f707511a
    ///   MESSAGE:     (empty, length 0)
    ///   SIGNATURE:   e5564300c360ac729086e2cc806e828a
    ///                84877f1eb8e5d974d873e06522490155
    ///                5fb8821590a33bacc61e39701cf9b46b
    ///                d25bf5f0595bbe24655141438e7a100b
    fn rfc8032_test_1_public() -> ([u8; 32], [u8; 64]) {
        let pk = to_arr_32(hex_decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let sig = to_arr_64(hex_decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ));
        (pk, sig)
    }

    #[test]
    fn rfc8032_test_1_empty_message_verifies() {
        let (pk, sig) = rfc8032_test_1_public();
        assert_eq!(verify(&pk, b"", &sig), Ok(()));
    }

    #[test]
    fn tampered_signature_byte_is_rejected() {
        // REQ1-SIGNING-backend-reject: flipping one signature byte must fail.
        let (pk, mut sig) = rfc8032_test_1_public();
        sig[0] ^= 0x01;
        assert_eq!(verify(&pk, b"", &sig), Err(Invalid));
    }

    #[test]
    fn tampered_message_is_rejected() {
        // The RFC signature is over the EMPTY message; any non-empty message
        // is a mismatch -> Invalid.
        let (pk, sig) = rfc8032_test_1_public();
        assert_eq!(verify(&pk, b"tampered", &sig), Err(Invalid));
    }

    #[test]
    fn tampered_public_key_byte_is_rejected() {
        let (mut pk, sig) = rfc8032_test_1_public();
        pk[0] ^= 0x01;
        assert_eq!(verify(&pk, b"", &sig), Err(Invalid));
    }

    #[test]
    fn all_zero_public_key_is_rejected() {
        // The all-zero 32-byte pattern is NOT a valid Edwards-Y point;
        // from_bytes rejects it -> Invalid (REQ1-SIGNING-backend-reject). This
        // is distinct from a signature mismatch: the key encoding itself is
        // invalid, so verification never proceeds.
        let (_, sig) = rfc8032_test_1_public();
        let pk = [0u8; 32];
        assert_eq!(verify(&pk, b"", &sig), Err(Invalid));
    }
}
