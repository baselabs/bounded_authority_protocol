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

// `verify` is `pub(crate)` and is wired by the v1 façade: `verify_grant` and
// `check_envelope` (Task 12) call it for the grant and holder-proof Ed25519
// signatures. The crate-level `#![forbid(unsafe_code)]` is unaffected.
//
// # Rule S1 (strict verification)
//
// This module is the single owner of the Ed25519 point and scalar rules for the
// SDK; every signature check (grant, proof, anchor, transition, role
// attestation, content assertion; contract-majors 1 and 2) goes through
// [`verify`]. S1 accepts a signature `R || S` over a message under a public key
// `A` only if all of these hold, checked in this order before any backend call:
//
// 1. the key is exactly 32 bytes and the signature exactly 64 bytes (the array
//    types here; an exact-length check in the slice mirrors);
// 2. `A` and `R` are canonical encodings: the encoded `y` is below
//    `p = 2^255 - 19`, and the sign bit is clear whenever `x = 0`
//    (RFC 8032 section 5.1.3);
// 3. neither `A` nor `R` is one of the eight small-order encodings (one shared
//    table serves both);
// 4. `S < L`, the prime order of the base point (RFC 8032 section 5.1.7);
// 5. the cofactorless equation `encode([S]B - [k]A) == R` holds, computed by the
//    `ed25519-dalek` `verify` backend (it compares the recomputed `R` byte for
//    byte).
//
// Curve membership of `A` is left to the backend at verification (it rejects
// off-curve keys). There is no subgroup check at verification: a key with a
// small torsion component passes S1 if its signature satisfies the cofactorless
// equation. Hosts close that gap once per key with [`torsion_free`]. A `true`
// result proves only that the bytes satisfy the rule; it never selects trusted
// keys or grants authority.

use crate::error::{Invalid, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The eight small-order encodings (the points of E[8]) in canonical form. One
/// table serves both the key `A` and the signature's `R`.
const SMALL_ORDER: [[u8; 32]; 8] = [
    // order 1 (identity)
    hex32("0100000000000000000000000000000000000000000000000000000000000000"),
    // order 2
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    // order 4
    hex32("0000000000000000000000000000000000000000000000000000000000000000"),
    hex32("0000000000000000000000000000000000000000000000000000000000000080"),
    // order 8
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
];

/// `L = 2^252 + 27742317777372353535851937790883648493`, little-endian.
const GROUP_ORDER_LE: [u8; 32] =
    hex32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex constant"),
    }
}

const fn hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

fn is_small_order(encoding: &[u8; 32]) -> bool {
    SMALL_ORDER.iter().any(|entry| entry == encoding)
}

/// Canonical: `y < p`, and the sign bit is clear on the two `x = 0` points
/// (`y = 1` and `y = p - 1`).
fn canonical(b: &[u8; 32]) -> bool {
    // y >= p <=> the low 255 bits are 0x7f ff..ff with a low byte >= 0xed.
    if b[31] & 0x7f == 0x7f && b[1..31].iter().all(|x| *x == 0xff) && b[0] >= 0xed {
        return false;
    }
    if b[31] & 0x80 != 0 {
        if b[0] == 0x01 && b[1..31].iter().all(|x| *x == 0x00) && b[31] == 0x80 {
            return false; // y = 1, x = 0, sign bit set
        }
        if b[0] == 0xec && b[1..31].iter().all(|x| *x == 0xff) && b[31] == 0xff {
            return false; // y = p - 1, x = 0, sign bit set
        }
    }
    true
}

/// `S < L` for a 32-byte little-endian scalar.
fn scalar_below_group_order(s: &[u8]) -> bool {
    for i in (0..32).rev() {
        if s[i] != GROUP_ORDER_LE[i] {
            return s[i] < GROUP_ORDER_LE[i];
        }
    }
    false // S == L
}

/// The byte-level part of rule S1 (clauses 1 to 4), separate from the backend so
/// each clause stays testable on its own: a cofactorless backend already refuses
/// a non-canonical `R` and `S >= L`, so only a direct test of the gate can show
/// those two clauses are present.
pub(crate) fn strict_gate(signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let mut r = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    canonical(public_key)
        && canonical(&r)
        && !is_small_order(public_key)
        && !is_small_order(&r)
        && scalar_below_group_order(&signature[32..])
}

/// Verify an Ed25519 signature of `message` against a 32-byte public key under
/// rule S1.
///
/// `public_key` (`[u8; 32]`) and `signature` (`[u8; 64]`) are the fixed
/// cryptographic encodings (`REQ1-BOUNDS-fixed-widths`); they arrive as fixed
/// array types, so no width check is possible or needed at this boundary.
///
/// Returns `Ok(())` when the signature verifies, or `Err(Invalid)` for any
/// gate rejection or backend rejection or exception
/// (`REQ1-SIGNING-backend-reject`):
/// - a key or `R` that is non-canonical or of small order, or an `S >= L`;
/// - a 32-byte public-key encoding that does not decompress to a valid Edwards
///   point (some bit patterns are not on the curve; `from_bytes` rejects them);
/// - a signature that does not verify against the key and message;
/// - any internal error inside the backend.
///
/// `Signature::from_bytes` on a `[u8; 64]` is structurally infallible (every
/// 64-byte pattern is a syntactically valid signature encoding); an invalid
/// signature is rejected by `verify`, not by construction.
pub(crate) fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    if !strict_gate(signature, public_key) {
        return Err(Invalid);
    }
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

/// Public mirror of rule S1 over slices. Never panics: any input that is not a
/// 32-byte key and a 64-byte signature passing the gate and the cofactorless
/// equation returns `false`.
pub fn verify_strict(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let (Ok(signature), Ok(public_key)) = (
        <&[u8; 64]>::try_from(signature),
        <&[u8; 32]>::try_from(public_key),
    ) else {
        return false;
    };
    verify(public_key, message, signature).is_ok()
}

/// Whether a raw 32-byte Ed25519 public key may enter a verification input:
/// canonical, not one of the eight small-order encodings, and on the curve (the
/// RFC 8032 section 5.1.3 decoding succeeds). Any other input returns `false`.
pub fn acceptable_public_key(public_key: &[u8]) -> bool {
    let Ok(key) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    canonical(key) && !is_small_order(key) && VerifyingKey::from_bytes(key).is_ok()
}

/// Whether a raw 32-byte key is acceptable and torsion free (`[L]A = O`).
///
/// A host calls this at key enrollment, at trust install, and before any
/// deny-list or revocation comparison. It runs one full scalar multiplication,
/// so it never belongs on the per-signature verification path. A canonical,
/// torsion-free key has exactly one encoding per secret, so key equality is
/// identity equality.
pub fn torsion_free(public_key: &[u8]) -> bool {
    if !acceptable_public_key(public_key) {
        return false;
    }
    let Ok(key) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    match VerifyingKey::from_bytes(key) {
        Ok(vk) => vk.to_edwards().is_torsion_free(),
        Err(_) => false,
    }
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
        // The all-zero 32-byte pattern decodes to a valid curve point: the order-4
        // point with y = 0. It is NOT "not a valid point", and it is a weak key:
        // R = identity, S = 0 satisfies the bare cofactorless equation for every
        // message under it, so the bare backend ACCEPTS a signature forged
        // without any secret. Rule S1 refuses the key (small-order A) before the
        // backend runs (rule S1).
        let (_, sig) = rfc8032_test_1_public();
        let pk = [0u8; 32];
        // The RFC signature does not verify under the zero key either way.
        assert_eq!(verify(&pk, b"", &sig), Err(Invalid));

        // The forged signature: R = the identity encoding, S = 0. Under an order-4 key
        // the bare equation [S]B = R + [k]A holds exactly when [k]A = O, i.e. for the
        // messages whose challenge k is a multiple of 4 (about one in four), so search
        // for such a message; no secret is involved.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let vk = VerifyingKey::from_bytes(&pk).expect("the zero key decodes to an order-4 point");
        let message = (0u32..256)
            .map(|n| format!("forgery-search-{n}").into_bytes())
            .find(|m| vk.verify(m, &Signature::from_bytes(&forged)).is_ok())
            .expect("a message accepted by the bare backend exists within 256 tries");
        // Control: the bare backend accepts the forgery for that message, so the
        // rejection asserted below can only come from the strict gate.
        assert!(vk.verify(&message, &Signature::from_bytes(&forged)).is_ok());
        assert_eq!(verify(&pk, &message, &forged), Err(Invalid));
        assert_eq!(verify(&pk, b"", &forged), Err(Invalid));
    }

    // ==========================================================================
    // Rule S1 (strict verification) and key acceptance.
    //
    // Every expectation about WHICH encodings are small-order or canonical is
    // derived here by curve arithmetic (the group law on `VerifyingKey::to_edwards`
    // points, public data only, no signing), never copied from the module's own
    // table (finding 12), so a wrong table entry goes red. Backend-redundant
    // clauses (R canonical, S < L) are tested on the byte-level gate directly,
    // because the cofactorless backend would refuse those inputs anyway and only
    // a gate test can show the clause exists. Widths are enforced by the array
    // types of the gate and by the `try_into` of the slice mirrors.
    // ==========================================================================

    const IDENTITY: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };

    /// L = 2^252 + 27742317777372353535851937790883648493, built independently of the module.
    fn group_order_le() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..16]
            .copy_from_slice(&27_742_317_777_372_353_535_851_937_790_883_648_493u128.to_le_bytes());
        b[31] = 0x10;
        b
    }

    fn le_plus(mut a: [u8; 32], n: u8) -> [u8; 32] {
        let mut carry = u16::from(n);
        for byte in a.iter_mut() {
            let v = u16::from(*byte) + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        a
    }

    fn le_minus_one(mut a: [u8; 32]) -> [u8; 32] {
        for byte in a.iter_mut() {
            if *byte == 0 {
                *byte = 0xff;
            } else {
                *byte -= 1;
                break;
            }
        }
        a
    }

    fn add_enc(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let pa = VerifyingKey::from_bytes(a)
            .expect("on the curve")
            .to_edwards();
        let pb = VerifyingKey::from_bytes(b)
            .expect("on the curve")
            .to_edwards();
        (pa + pb).compress().to_bytes()
    }

    /// [L]Q by double-and-add over encodings.
    fn times_group_order(q: &[u8; 32]) -> [u8; 32] {
        let l = group_order_le();
        let mut acc: Option<[u8; 32]> = None;
        let mut addend = *q;
        for bit in 0..253 {
            if (l[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = Some(match acc {
                    None => addend,
                    Some(a) => add_enc(&a, &addend),
                });
            }
            addend = add_enc(&addend, &addend);
        }
        acc.expect("L is nonzero")
    }

    /// E[8]: the curve has order 8L, so [L]Q lies in E[8] for any point Q; a point whose image has
    /// order 8 generates the subgroup. Returns T, 2T, ..., 8T (= the identity).
    fn torsion_subgroup() -> Vec<[u8; 32]> {
        for y in 2u32.. {
            let mut q = [0u8; 32];
            q[..4].copy_from_slice(&y.to_le_bytes());
            if VerifyingKey::from_bytes(&q).is_err() {
                continue;
            }
            let t = times_group_order(&q);
            let t2 = add_enc(&t, &t);
            let t4 = add_enc(&t2, &t2);
            if t4 == IDENTITY {
                continue; // order below 8
            }
            let mut out = vec![t];
            for i in 1..8 {
                let next = add_enc(&out[i - 1], &t);
                out.push(next);
            }
            return out;
        }
        unreachable!()
    }

    fn small_order_set() -> Vec<[u8; 32]> {
        let e8 = torsion_subgroup();
        assert_eq!(e8[7], IDENTITY, "8T must be the identity");
        let mut distinct = e8.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 8, "E[8] has eight distinct points");
        e8
    }

    /// The 40 non-canonical encodings: y in [p, 2^255) with either sign bit, plus the two x = 0
    /// sign-bit encodings (y = 1 and y = p - 1).
    fn noncanonical_aliases() -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for k in 0u8..=18 {
            for sign in [0x00u8, 0x80] {
                let mut b = [0xffu8; 32];
                b[0] = 0xed + k;
                b[31] = 0x7f | sign;
                out.push(b);
            }
        }
        let mut one_signed = IDENTITY;
        one_signed[31] = 0x80;
        out.push(one_signed);
        let mut p_minus_one_signed = [0xffu8; 32];
        p_minus_one_signed[0] = 0xec;
        out.push(p_minus_one_signed);
        out
    }

    fn with_r(sig: &[u8; 64], r: &[u8; 32]) -> [u8; 64] {
        let mut out = *sig;
        out[..32].copy_from_slice(r);
        out
    }

    fn with_s(sig: &[u8; 64], s: &[u8; 32]) -> [u8; 64] {
        let mut out = *sig;
        out[32..].copy_from_slice(s);
        out
    }

    #[test]
    fn derived_subgroup_equals_the_modules_small_order_table() {
        let derived = small_order_set();
        let mut table: Vec<[u8; 32]> = SMALL_ORDER.to_vec();
        let mut expected = derived;
        table.sort();
        expected.sort();
        assert_eq!(table, expected);
    }

    #[test]
    fn gate_rejects_each_derived_small_order_key_and_r() {
        let (pk, sig) = rfc8032_test_1_public();
        assert!(
            strict_gate(&sig, &pk),
            "positive control: the honest pair passes the gate"
        );
        for (i, weak) in small_order_set().iter().enumerate() {
            assert!(
                !strict_gate(&sig, weak),
                "small-order key #{i} must be refused"
            );
            assert!(
                !strict_gate(&with_r(&sig, weak), &pk),
                "small-order R #{i} must be refused (one table serves both)"
            );
            assert!(!acceptable_public_key(weak));
            assert!(!torsion_free(weak));
            assert!(!verify_strict(b"", &sig, weak));
        }
    }

    #[test]
    fn noncanonical_aliases_are_refused_as_key_and_as_r() {
        let (pk, sig) = rfc8032_test_1_public();
        let aliases = noncanonical_aliases();
        assert_eq!(aliases.len(), 40);
        for alias in &aliases {
            assert!(!strict_gate(&sig, alias), "alias key {alias:02x?}");
            assert!(
                !strict_gate(&with_r(&sig, alias), &pk),
                "alias R {alias:02x?}"
            );
            assert!(!acceptable_public_key(alias));
            assert!(!torsion_free(alias));
        }
    }

    #[test]
    fn the_canonical_clause_is_isolated_by_aliases_that_are_not_small_order() {
        // Of the 40 aliases only 6 alias a small-order point; the rest would slip past a table-only
        // gate, so refusing them is the canonical clause's own work (for A and for R).
        let (pk, sig) = rfc8032_test_1_public();
        let mut isolating = 0;
        for alias in noncanonical_aliases() {
            // Reduce y modulo p (y - p = k < 19) and keep the sign bit.
            let mut reduced = [0u8; 32];
            reduced[0] = alias[0].wrapping_sub(0xed);
            reduced[31] = alias[31] & 0x80;
            let weak_or_off_curve = match VerifyingKey::from_bytes(&reduced) {
                Ok(vk) => vk.is_weak(),
                Err(_) => true,
            };
            if alias[1..31].iter().all(|b| *b == 0xff) && alias[0] >= 0xed && !weak_or_off_curve {
                isolating += 1;
                assert!(!strict_gate(&sig, &alias));
                assert!(!strict_gate(&with_r(&sig, &alias), &pk));
            }
        }
        assert!(
            isolating >= 10,
            "only {isolating} aliases isolate the canonical clause"
        );
    }

    #[test]
    fn y_equal_p_is_noncanonical_and_p_minus_two_is_canonical() {
        let (pk, sig) = rfc8032_test_1_public();
        let mut y_eq_p = [0xffu8; 32];
        y_eq_p[0] = 0xed;
        y_eq_p[31] = 0x7f;
        assert!(!strict_gate(&sig, &y_eq_p));
        assert!(!strict_gate(&with_r(&sig, &y_eq_p), &pk));
        let mut below = y_eq_p;
        below[0] = 0xeb; // p - 2
        assert!(
            strict_gate(&sig, &below),
            "y = p - 2 is canonical and not small-order"
        );
        assert!(strict_gate(&with_r(&sig, &below), &pk));
    }

    #[test]
    fn scalar_at_or_above_l_is_refused_by_the_gate() {
        let (pk, sig) = rfc8032_test_1_public();
        let l = group_order_le();
        let mut max = [0xffu8; 32];
        let mut two_l = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(l[i]) * 2 + carry;
            two_l[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        for s in [l, le_plus(l, 1), le_plus(l, 200), two_l, max] {
            assert!(!strict_gate(&with_s(&sig, &s), &pk), "S = {s:02x?}");
            assert!(!verify_strict(b"", &with_s(&sig, &s), &pk));
        }
        max[31] = 0x80; // 2^255
        assert!(!strict_gate(&with_s(&sig, &max), &pk));
        for s in [le_minus_one(l), [0u8; 32]] {
            assert!(
                strict_gate(&with_s(&sig, &s), &pk),
                "S = {s:02x?} < L must pass the gate"
            );
        }
    }

    #[test]
    fn rfc_vector_is_accepted_by_every_mirror() {
        let (pk, sig) = rfc8032_test_1_public();
        assert!(verify_strict(b"", &sig, &pk));
        assert!(acceptable_public_key(&pk));
        assert!(torsion_free(&pk));
        assert_eq!(verify(&pk, b"", &sig), Ok(()));
    }

    #[test]
    fn mirror_widths_are_exact_and_nothing_panics() {
        let (pk, sig) = rfc8032_test_1_public();
        for len in [0usize, 1, 31, 33, 64] {
            let key = vec![0x42u8; len];
            assert!(!verify_strict(b"", &sig, &key));
            assert!(!acceptable_public_key(&key));
            assert!(!torsion_free(&key));
        }
        for len in [0usize, 32, 63, 65, 128] {
            let bad_sig = vec![0u8; len];
            assert!(!verify_strict(b"", &bad_sig, &pk));
        }
    }

    #[test]
    fn torsion_variants_are_acceptable_but_not_torsion_free() {
        let (pk, sig) = rfc8032_test_1_public();
        for (i, t) in torsion_subgroup().iter().enumerate().take(7) {
            let variant = add_enc(&pk, t);
            assert_ne!(variant, pk);
            assert!(
                acceptable_public_key(&variant),
                "variant {i} is canonical, not small-order, on the curve"
            );
            assert!(
                !torsion_free(&variant),
                "variant {i} carries a torsion component"
            );
            // No key substitution: the honest signature does not verify under A + T.
            assert!(!verify_strict(b"", &sig, &variant), "variant {i}");
        }
    }

    #[test]
    fn off_curve_key_is_refused_everywhere() {
        let (_, sig) = rfc8032_test_1_public();
        let off = (2u32..)
            .map(|y| {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&y.to_le_bytes());
                b
            })
            .find(|b| VerifyingKey::from_bytes(b).is_err())
            .unwrap();
        assert!(!acceptable_public_key(&off));
        assert!(!torsion_free(&off));
        assert!(!verify_strict(b"", &sig, &off));
    }

    #[test]
    fn identity_key_forgery_is_rejected_for_every_message() {
        // The identity key (order 1) admits R = identity, S = 0 for EVERY message.
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);
        let vk = VerifyingKey::from_bytes(&IDENTITY).unwrap();
        for n in 0..16u8 {
            let message = [n; 7];
            assert!(
                vk.verify(&message, &Signature::from_bytes(&forged)).is_ok(),
                "control: the bare backend accepts the forgery"
            );
            assert_eq!(verify(&IDENTITY, &message, &forged), Err(Invalid));
            assert!(!verify_strict(&message, &forged, &IDENTITY));
        }
    }
}
