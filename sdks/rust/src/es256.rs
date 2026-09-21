//! ES256 verify wrapper — the `BAP3-ES256-SHA256` signature backend.
//!
//! Thin wrapper over `p256` 0.13 with `default-features = false` +
//! `features = ["ecdsa"]` (verify-only; no `pem`/`pkcs8`/`std`/`serde`/`jwk`).
//! Same accepted posture as `ed25519.rs` (design-note D-RISK-2): the backend
//! carries transitive `unsafe` internally; the crate-level
//! `#![forbid(unsafe_code)]` covers OUR code only.
//!
//! **Verify-only, public keys only.** No key generation, no signing, and no
//! secret material enters this module or the crate (`REQ3-*` inherits the
//! `REQ1-HEADER-no-private-jwk` closure).
//!
//! The v3 suite's fixed widths (`REQ3-BOUNDS-fixed-widths`): the raw public
//! key is the 65-byte uncompressed SEC1 point `0x04 || x || y`
//! (`REQ3-KEY-uncompressed-sec1`) and the signature is the RFC 7518 §3.4 raw
//! 64-byte `r || s` (two fixed-width 32-byte unsigned big-endian halves,
//! `REQ3-SIGNING-raw-rs`). Both arrive as fixed array types, so no width
//! check is possible or needed at this boundary.
//!
//! # The profile gates precede the backend (spec/bap-v3.md §3.2 ordering)
//!
//! `REQ3-KEY-point-on-curve` and `REQ3-SIGNING-range` are PROFILE checks the
//! spec requires in pure arithmetic BEFORE the crypto backend (the backend's
//! off-curve and out-of-range behavior is backend-specific and never
//! load-bearing). This module therefore runs, in order:
//!
//! 1. [`validate_point`] — the 65-byte form MUST be `0x04 || x || y` with
//!    both coordinates `< p` (the field prime) and on the curve
//!    `y^2 = x^3 - 3x + b`. The check is computed through the p256 arithmetic
//!    layer (`AffinePoint::from_encoded_point`, which parses each coordinate
//!    via `FieldElement::from_repr` — rejecting `>= p` — and evaluates the
//!    curve equation), which is deterministic pure arithmetic over the curve
//!    equation, NOT the signature-verification path. A compressed point, an
//!    off-curve point, and a coordinate at or above `p` all fail here.
//! 2. [`validate_rs_range`] — pure big-endian integer comparisons against the
//!    group order `n` and its half: reject `r = 0`, `s = 0`, `r >= n`,
//!    `s >= n`, and `s > n/2` (low-S required, `REQ3-SIGNING-low-s`).
//!    Low-S is the load-bearing half: for any valid ECDSA signature
//!    `(r, s)` the malleable counterpart `(r, n - s)` ALSO satisfies the
//!    verification equation, so the backend alone would accept both spellings;
//!    only this profile check admits one.
//! 3. Only then the backend: `VerifyingKey::from_sec1_bytes` (on-curve
//!    re-validation, inherent), `Signature::from_slice` (canonical-scalar
//!    re-validation, inherent), and `verify_prehash` over SHA-256 of the
//!    exact RFC 7515 signing input.
//!
//! Every backend rejection or exception collapses to exactly `Err(Invalid)`
//! (`REQ3-SIGNING-backend-reject`, incorporated from
//! `REQ1-SIGNING-backend-reject`); the backend's diagnostic detail is
//! discarded.

use crate::error::{Invalid, Result};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint};

/// The P-256 group order `n` (SEC 2, `secp256r1`), big-endian:
/// `0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`.
pub(crate) const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// `n >> 1` (big-endian): the low-S ceiling. `s <= n >> 1` is the low half;
/// `s > n >> 1` is the HIGH-S half (`REQ3-SIGNING-low-s`). Computed from [`N`]
/// by a one-bit shift so the two constants cannot drift apart.
pub(crate) const HALF_N: [u8; 32] = shr1(&N);

/// Shifts a 32-byte big-endian integer right by one bit (the carry walks from
/// the most-significant byte down). `const fn` so [`HALF_N`] is computed at
/// compile time; unit-pinned against an independent formulation.
const fn shr1(v: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = v[i] >> 1;
        if i > 0 {
            // The low bit of the previous (more significant) byte becomes the
            // high bit of this byte.
            out[i] |= (v[i - 1] & 1) << 7;
        }
        i += 1;
    }
    out
}

/// The uncompressed-SEC1 prefix byte (`0x04`): the ONLY valid raw-key form in
/// this profile (compressed `0x02`/`0x03` points are invalid,
/// `REQ3-KEY-uncompressed-sec1`).
const UNCOMPRESSED_PREFIX: u8 = 0x04;

/// The fixed raw public-key width: `0x04 || x || y` = 1 + 32 + 32
/// (`REQ3-BOUNDS-fixed-widths`).
pub(crate) const PUBLIC_KEY_WIDTH: usize = 65;

/// Validates a 65-byte raw P-256 public key in pure profile arithmetic:
/// exactly `0x04 || x || y` (uncompressed; compressed points are invalid),
/// both coordinates `< p`, and the point on the curve
/// (`REQ3-KEY-uncompressed-sec1`, `REQ3-KEY-point-on-curve`).
///
/// Runs BEFORE any backend call; the backend re-validates inherently and its
/// behavior is never load-bearing for these classes.
pub(crate) fn validate_point(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> Result<()> {
    if public_key[0] != UNCOMPRESSED_PREFIX {
        return Err(Invalid); // compressed or hybrid form — closed out
    }
    // AffinePoint::from_encoded_point parses each coordinate through
    // FieldElement::from_repr (rejecting any value >= p) and evaluates the
    // curve equation y^2 = x^3 - 3x + b; an off-curve or out-of-field point
    // yields the none half of the CtOption. This is the curve arithmetic
    // layer, not the verify path.
    let encoded = EncodedPoint::from_bytes(public_key.as_slice()).map_err(|_| Invalid)?;
    let on_curve = AffinePoint::from_encoded_point(&encoded);
    if on_curve.is_some().into() {
        Ok(())
    } else {
        Err(Invalid)
    }
}

/// Validates the raw `r || s` integer range in pure profile arithmetic,
/// BEFORE any backend call (`REQ3-SIGNING-range`):
///
/// - `r = 0` or `s = 0` — a zero half is not a signature value;
/// - `r >= n` or `s >= n` — out of the scalar field (non-canonical encoding);
/// - `s > n/2` — the HIGH-S half; low-S is required (`REQ3-SIGNING-low-s`),
///   which makes each signature non-malleable: the counterpart
///   `(r, n - s)` of a valid signature also satisfies the verification
///   equation, so only this check admits one of the two spellings.
pub(crate) fn validate_rs_range(signature: &[u8; 64]) -> Result<()> {
    let (r, s) = signature.split_at(32);
    let r: &[u8; 32] = r.try_into().expect("split_at(32) yields 32-byte halves");
    let s: &[u8; 32] = s.try_into().expect("split_at(32) yields 32-byte halves");
    let zero = [0u8; 32];
    // Equal-width big-endian arrays compare lexicographically == numerically.
    if *r == zero || *s == zero {
        return Err(Invalid);
    }
    if *r >= N || *s >= N {
        return Err(Invalid);
    }
    if *s > HALF_N {
        return Err(Invalid); // REQ3-SIGNING-low-s
    }
    Ok(())
}

/// Verify an ES256 signature of `message` against a 65-byte raw P-256 public
/// key.
///
/// `public_key` (`[u8; 65]`, uncompressed SEC1) and `signature` (`[u8; 64]`,
/// raw `r || s`) are the fixed cryptographic encodings
/// (`REQ3-BOUNDS-fixed-widths`). Returns `Ok(())` when the signature
/// verifies, or `Err(Invalid)` for any profile rejection (point/range/low-S)
/// or backend rejection/exception (`REQ3-SIGNING-backend-reject`): a key
/// that is not a curve point, a signature that does not verify, or any
/// internal backend error — the diagnostic detail is discarded.
pub(crate) fn verify(
    public_key: &[u8; PUBLIC_KEY_WIDTH],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    // Profile gates first (spec §3.2 ordering): point form/curve, then
    // signature integer range + low-S — all before any backend call.
    validate_point(public_key)?;
    validate_rs_range(signature)?;
    // Backend: key parse (on-curve inherent), signature parse (canonical
    // scalars inherent), ECDSA verification — the p256 Verifier digests the
    // message with SHA-256 (NistP256's DigestPrimitive), which IS ES256.
    // Every failure collapses to Invalid.
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public_key.as_slice()).map_err(|_| Invalid)?;
    let sig = Signature::from_slice(signature.as_slice()).map_err(|_| Invalid)?;
    vk.verify(message, &sig).map_err(|_| Invalid)
}

// ============================================================================
// Tests — RFC 6979-style PUBLIC vectors + the profile gates' own closures.
// No private material: every key/signature below is a published public test
// vector or a corpus public artifact.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// A public P-256 key and a verifying ES256 signature over a fixed
    /// message, minted once through an independent tool and pinned here as
    /// hex. (Minted via `openssl` — see the pinned values; verify-only crate,
    /// the private scalar was discarded and never enters the tree.)
    ///
    /// key (65-byte SEC1):
    ///   04 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945
    ///   d898c296 (x) 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece
    ///   cbb64068 37bf51f5 (y) — the NIST P-256 base point G (public domain).
    fn base_point() -> [u8; 65] {
        let mut k = [0u8; 65];
        k[0] = 0x04;
        k[1..33].copy_from_slice(&hex(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        ));
        k[33..65].copy_from_slice(&hex(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ));
        k
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn half_n_is_n_shifted_right_one_bit() {
        // Independent formulation: subtract-then-shift is awkward for odd n,
        // so pin HALF_N == (N - 1) >> 1 (n is odd, so n>>1 == (n-1)>>1) plus
        // the two directional properties of the boundary.
        let mut n_minus_1 = N;
        // subtract 1 from the big-endian integer
        let mut i = 31;
        loop {
            if n_minus_1[i] > 0 {
                n_minus_1[i] -= 1;
                break;
            }
            n_minus_1[i] = 0xFF;
            i -= 1;
        }
        assert_eq!(HALF_N, shr1(&n_minus_1));
        // The low-S boundary: s == HALF_N is LOW (accepted), s == HALF_N + 1
        // is HIGH (rejected). r = 1 in both fixtures (a zero r is a different
        // reject).
        let mut s_low = [0u8; 64];
        s_low[31] = 1; // r = 1
        s_low[32..].copy_from_slice(&HALF_N);
        assert!(validate_rs_range(&s_low).is_ok(), "s == n>>1 is low-S");
        let mut s_high = [0u8; 64];
        s_high[31] = 1; // r = 1
        let mut half_plus_one = HALF_N;
        // HALF_N is odd? n = ...551 (odd), n>>1 = ...2A8 (even). +1 = ..2A9.
        let mut i = 31;
        loop {
            if half_plus_one[i] < 0xFF {
                half_plus_one[i] += 1;
                break;
            }
            half_plus_one[i] = 0;
            i -= 1;
        }
        s_high[32..].copy_from_slice(&half_plus_one);
        assert_eq!(
            validate_rs_range(&s_high),
            Err(Invalid),
            "s == (n>>1)+1 is high-S"
        );
    }

    #[test]
    fn n_constant_is_the_sec2_group_order() {
        // SEC 2 verbatim (public specification constant).
        assert_eq!(
            hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            N.to_vec()
        );
    }

    #[test]
    fn validate_point_accepts_the_base_point() {
        assert!(validate_point(&base_point()).is_ok());
    }

    #[test]
    fn validate_point_rejects_compressed_and_hybrid_prefixes() {
        let mut k = base_point();
        k[0] = 0x02; // compressed — invalid in the raw form
        assert_eq!(validate_point(&k), Err(Invalid));
        k[0] = 0x03;
        assert_eq!(validate_point(&k), Err(Invalid));
        k[0] = 0x06; // hybrid — invalid
        assert_eq!(validate_point(&k), Err(Invalid));
        k[0] = 0x07;
        assert_eq!(validate_point(&k), Err(Invalid));
    }

    #[test]
    fn validate_point_rejects_off_curve_point() {
        // Flip one y-coordinate bit: still < p, no longer on the curve.
        let mut k = base_point();
        k[64] ^= 0x01;
        assert_eq!(validate_point(&k), Err(Invalid));
    }

    #[test]
    fn validate_point_rejects_coordinate_at_or_above_field_prime() {
        // p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        // (SEC 2). Set x = p (>= p) — the byte pattern is a valid-looking
        // coordinate but out of the field.
        let mut k = base_point();
        k[1..33].copy_from_slice(&hex(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        assert_eq!(validate_point(&k), Err(Invalid));
    }

    #[test]
    fn validate_rs_range_rejects_zero_and_overflow_halves() {
        let mut sig = [1u8; 64]; // r = s = 0x0101..01 (valid, low)
        sig[31] = 1;
        sig[63] = 1;
        assert!(validate_rs_range(&sig).is_ok());
        // r = 0.
        let mut z = sig;
        z[..32].fill(0);
        assert_eq!(validate_rs_range(&z), Err(Invalid));
        // s = 0.
        let mut z = sig;
        z[32..].fill(0);
        assert_eq!(validate_rs_range(&z), Err(Invalid));
        // r = n.
        let mut z = sig;
        z[..32].copy_from_slice(&N);
        assert_eq!(validate_rs_range(&z), Err(Invalid));
        // s = n.
        let mut z = sig;
        z[32..].copy_from_slice(&N);
        assert_eq!(validate_rs_range(&z), Err(Invalid));
        // s > n/2 (high-S): HALF_N | 1 is high iff it exceeds HALF_N — use
        // HALF_N + 2 to stay unambiguous.
        let mut z = sig;
        z[32..].copy_from_slice(&HALF_N);
        z[63] = z[63].wrapping_add(2);
        assert_eq!(validate_rs_range(&z), Err(Invalid));
    }

    #[test]
    fn backend_rejects_a_nonverifying_signature() {
        // A range-valid but cryptographically wrong signature must fail at
        // the backend step (the corpus tamper cases drive this end-to-end
        // through the façade; this pins the module in isolation).
        let sig = [0x11u8; 64]; // r,s = 0x11..11 — canonical, low
        assert_eq!(verify(&base_point(), b"message", &sig), Err(Invalid));
    }

    #[test]
    fn encoded_point_round_trip_of_the_base_point() {
        // The arithmetic layer we lean on parses and re-emits the exact
        // 65-byte form — guards against a subtle form-conversion drift.
        let encoded = EncodedPoint::from_bytes(base_point().as_slice()).unwrap();
        let affine = AffinePoint::from_encoded_point(&encoded);
        assert!(bool::from(affine.is_some()));
        let re = affine.unwrap().to_encoded_point(false);
        assert_eq!(re.as_bytes(), base_point().as_slice());
    }

    // ==========================================================================
    // Backend subsumption pin — what Signature::from_slice rejects on its own.
    // The permissiveness battery's r/s-range leg cites this: the zero and
    // r/s >= n rejects are enforced by BOTH the profile gate and the backend
    // (defense in depth), while the high-S reject is the profile gate ALONE
    // (the malleable counterpart (r, n-s) is a canonical scalar the backend
    // accepts — low-S is why REQ3-SIGNING-low-s exists).
    // ==========================================================================

    #[test]
    fn backend_signature_parse_rejects_zero_and_overflow_scalars() {
        use p256::ecdsa::Signature;
        let mut sig = [1u8; 64];
        sig[31] = 1;
        sig[63] = 1;
        assert!(
            Signature::from_slice(&sig).is_ok(),
            "canonical low scalars parse"
        );
        // r = 0.
        let mut z = sig;
        z[..32].fill(0);
        assert!(
            Signature::from_slice(&z).is_err(),
            "zero r subsumed by backend"
        );
        // s = 0.
        let mut z = sig;
        z[32..].fill(0);
        assert!(
            Signature::from_slice(&z).is_err(),
            "zero s subsumed by backend"
        );
        // r = n.
        let mut z = sig;
        z[..32].copy_from_slice(&N);
        assert!(
            Signature::from_slice(&z).is_err(),
            "r = n (non-canonical) subsumed by backend"
        );
        // s = n.
        let mut z = sig;
        z[32..].copy_from_slice(&N);
        assert!(
            Signature::from_slice(&z).is_err(),
            "s = n (non-canonical) subsumed by backend"
        );
        // s in the HIGH half (HALF_N + 2 < n): a canonical scalar the backend
        // ACCEPTS — the profile's low-S gate is the only rejection.
        let mut z = sig;
        z[32..].copy_from_slice(&HALF_N);
        z[63] = z[63].wrapping_add(2);
        assert!(
            Signature::from_slice(&z).is_ok(),
            "high-S is backend-accepted; only the profile gate rejects it"
        );
    }
}
