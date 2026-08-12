//! JSON Canonicalization Scheme (RFC 8785) encoder over the tagged
//! [`JsonValue`](crate::json::JsonValue) algebra.
//!
//! Canonicalization IS the wire contract: every signature and request digest in
//! the v1 profile is computed over JCS bytes, so a single byte of divergence
//! here silently breaks (or silently accepts) a credential. The encoder is
//! derived first-hand from RFC 8785 (§3.2.2.2 strings, §3.2.2.3 numbers) +
//! ECMA-262 §6.1.6.1.20 `Number::toString` + `docs/protocol-v1.md` § JCS, NOT
//! from any sibling-SDK or Elixir source (ADR 0014 D5).
//!
//! Rules enforced:
//! - **Strings** (`REQ1-JSON-jcs-exact`, RFC 8785 §3.2.2.2): the escape
//!   predicate keys on the explicit C0 range `U+0000..=U+001F` — NOT on Rust's
//!   `char::is_control()`, which also catches the C1/DEL range and would
//!   over-escape `U+007F`. `\b\t\n\f\r` for `0x08/09/0A/0C/0D`; lowercase
//!   `\u00XX` for the rest of C0; `\\` and `\"` only; every other code point
//!   (including DEL `U+007F` and astral `≥ U+10000`) is emitted as its raw UTF-8
//!   bytes. Lone surrogates are structurally impossible: a Rust `String` holds
//!   only Unicode scalar values, and the decoder ([`crate::json::json_decode`])
//!   rejects lone surrogates at decode time.
//! - **Numbers — integers**: plain decimal text, no exponent.
//! - **Numbers — floats** (RFC 8785 §3.2.2.3, delegated to ECMA-262
//!   `Number::toString`): shortest round-trip text via `ryu-js` (the
//!   ECMAScript-flavored Ryu that RFC 8785 §3.2.2.3 names as a reference
//!   implementation). `-0.0` serializes as `0` (the sign of zero is dropped);
//!   the `e < -6` → scientific / `e >= 21` → scientific / otherwise fixed
//!   thresholds are ryu-js's own.
//! - **Non-finite floats** (RFC 8785 §3.2.2.3 + AGENTS rule 3): `NaN`, `+Inf`,
//!   `-Inf` are `Err(Invalid)` — they MUST fail closed BEFORE formatting (ryu-js
//!   would otherwise emit `"NaN"`/`"Infinity"`, violating the RFC). This is the
//!   F2 tripwire: [`JsonValue::Float`] can hold non-finite values and
//!   [`jcs_encode`] is a public primitive reachable by a direct caller, not only
//!   via the [`crate::json::json_decode`] path that rejects NaN/Inf literals.
//! - **Objects** (RFC 8785 §3.2.3): members are sorted by UNSIGNED UTF-16
//!   code-unit comparison of their names at EVERY depth (NOT Rust `String` /
//!   UTF-8 byte ordering, NOT code-point ordering). Arrays preserve source
//!   order; values are recursively encoded.
//! - **Bounds** (`REQ1-BOUNDS-ordering`): the JCS output byte ceiling
//!   (`jcs_bytes`, 65536) AND the per-node/per-depth structural ceilings
//!   (`total_nodes`, `depth`) are enforced DURING recursion, so a hand-built
//!   (not decode-bounded) value passed directly to this public primitive cannot
//!   force unbounded recursion, traversal, or intermediate allocation — the
//!   `(d)`-class per-node encode-bounds closure (ADR 0014 D6/D7; the corpus
//!   cannot express it, so the permissiveness battery proves it red-capable).

use crate::bounds::Bounds;
use crate::error::{Invalid, Result};
use crate::json::JsonValue;

/// Emit RFC 8785 canonical bytes for `value` under the caller's [`Bounds`].
///
/// Returns the exact canonical byte sequence (object members UTF-16-sorted at
/// every depth, strings escaped per §3.2.2.2, numbers formatted per §3.2.2.3),
/// or `Err(Invalid)` if any float is non-finite, the encoded output exceeds
/// `bounds.jcs_bytes()`, or `value` itself violates a structural ceiling
/// (`total_nodes`, `depth`) enforced per-node during recursion. The structural
/// ceilings mirror [`crate::json::json_decode`]; a value that came through the
/// decoder is already within them, but `jcs_encode` is a public primitive
/// reachable by a direct caller with a hand-built value, so the ceilings are
/// re-enforced here (the `(d)`-class closure, ADR 0014 D6/D7).
pub fn jcs_encode(value: &JsonValue, bounds: &Bounds) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut nodes: u64 = 0;
    encode_value(value, 1, bounds, &mut out, &mut nodes)?;
    // Authoritative final ceiling on the complete output. The per-node early
    // bail inside encode_value already fires at this threshold; this is the
    // contract-level check on the finished encoding.
    if out.len() as u64 > bounds.jcs_bytes() {
        return Err(Invalid);
    }
    Ok(out)
}

/// Recursive encoder. Threads the full per-node budget set through the
/// recursion so a hand-built (not decode-bounded) value cannot force unbounded
/// recursion/traversal/allocation AND cannot smuggle an out-of-profile scalar
/// or duplicate member past the encoder: `total_nodes`, container `depth`,
/// `integer_magnitude`/`float_magnitude`, `string_bytes`, `array_items`,
/// `object_members`, `key_bytes`, duplicate-key rejection, non-finite-float
/// rejection, and the `jcs_bytes` output ceiling (the `(d)`-class closure,
/// ADR 0014 D6/D7; mirrors the reference `jcs.ex` `encode_value` guard set).
/// `depth` is the container nesting level (root container = 1), mirroring
/// [`crate::json::json_decode`]'s accounting.
fn encode_value(
    v: &JsonValue,
    depth: u64,
    bounds: &Bounds,
    out: &mut Vec<u8>,
    nodes: &mut u64,
) -> Result<()> {
    // (d)-class per-node encode bounds — total_nodes counts every value.
    *nodes += 1;
    if *nodes > bounds.total_nodes() {
        return Err(Invalid);
    }
    match v {
        JsonValue::Null => out.extend_from_slice(b"null"),
        JsonValue::Bool(true) => out.extend_from_slice(b"true"),
        JsonValue::Bool(false) => out.extend_from_slice(b"false"),
        JsonValue::Int(n) => {
            // Magnitude bound (reference jcs.ex:40-41): a hand-built integer
            // outside ±integer_magnitude is rejected at encode, matching the
            // decoder. The decoded path never carries such a value.
            let mag = bounds.integer_magnitude() as i64;
            if *n < -mag || *n > mag {
                return Err(Invalid);
            }
            encode_int(*n, out);
        }
        JsonValue::Float(f) => {
            // Finite + magnitude (reference jcs.ex:49-50): non-finite (the F2
            // tripwire) OR over-magnitude floats are rejected before formatting.
            let mag = bounds.float_magnitude() as f64;
            if !f.is_finite() || f.abs() > mag {
                return Err(Invalid);
            }
            encode_float(*f, out)?;
        }
        JsonValue::String(s) => {
            // byte_size bound (reference jcs.ex:58). A Rust `String` is valid
            // UTF-8 by construction, so the reference's String.valid? check is
            // structurally guaranteed here.
            if s.len() as u64 > bounds.string_bytes() {
                return Err(Invalid);
            }
            encode_string(s, out);
        }
        JsonValue::Array(items) => {
            if depth > bounds.depth() {
                return Err(Invalid);
            }
            // item-count bound (reference jcs.ex:65 length_bounded?).
            if items.len() as u64 > bounds.array_items() {
                return Err(Invalid);
            }
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_value(item, depth + 1, bounds, out, nodes)?;
            }
            out.push(b']');
        }
        JsonValue::Object(members) => {
            if depth > bounds.depth() {
                return Err(Invalid);
            }
            // member-count bound (reference jcs.ex:77).
            if members.len() as u64 > bounds.object_members() {
                return Err(Invalid);
            }
            // Per-member key-width bound (reference jcs.ex:83) AND duplicate-key
            // rejection (reference jcs.ex:92): a hand-built Object can carry
            // duplicate names (the Vec carrier allows it); the reference rejects
            // any object whose member-name set is smaller than its length.
            let mut seen = std::collections::HashSet::with_capacity(members.len());
            for (k, _) in members {
                if k.len() as u64 > bounds.key_bytes() || !seen.insert(k.as_str()) {
                    return Err(Invalid);
                }
            }
            // RFC 8785 §3.2.3: sort members by unsigned UTF-16 code-unit
            // comparison of names. The duplicate check above proves the names
            // are distinct, so the sort has no ties and stability is irrelevant
            // — `sort_unstable_by` is correct.
            let mut order: Vec<usize> = (0..members.len()).collect();
            order.sort_unstable_by(|&a, &b| utf16_compare(&members[a].0, &members[b].0));
            out.push(b'{');
            for (rank, &idx) in order.iter().enumerate() {
                if rank > 0 {
                    out.push(b',');
                }
                encode_string(&members[idx].0, out);
                out.push(b':');
                encode_value(&members[idx].1, depth + 1, bounds, out, nodes)?;
            }
            out.push(b'}');
        }
    }
    // Per-node output-budget early bail: stop the moment the encoding crosses
    // jcs_bytes, so an over-budget value cannot force materialization of its
    // full encoding before the final check rejects it.
    if out.len() as u64 > bounds.jcs_bytes() {
        return Err(Invalid);
    }
    Ok(())
}

/// Encodes an integer as plain decimal text (no exponent). `i64::MIN` formats
/// correctly without panic; there is no negative-zero integer.
fn encode_int(n: i64, out: &mut Vec<u8>) {
    // to_string never panics and yields the canonical decimal lexeme.
    let s = n.to_string();
    out.extend_from_slice(s.as_bytes());
}

/// Encodes a float per ECMAScript `Number::toString` via `ryu-js`.
///
/// The non-finite guard is the F2 fail-closed tripwire: it MUST run before any
/// ryu-js call. With it removed, `ryu-js`'s `format` emits `"NaN"`/`"Infinity"`
/// and `format_finite` is unsound on non-finite input — either violates RFC
/// 8785 §3.2.2.3.
fn encode_float(f: f64, out: &mut Vec<u8>) -> Result<()> {
    if !f.is_finite() {
        return Err(Invalid);
    }
    let mut buf = ryu_js::Buffer::new();
    // Safe: `f` is finite (guarded above); `format_finite` is the non-checking
    // fast path and is correct for finite input.
    let s = buf.format_finite(f);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Encodes a string per RFC 8785 §3.2.2.2.
///
/// The escape predicate keys on the explicit C0 range `0x00..=0x1f`. Using
/// `char::is_control()` instead would also catch `0x7f` (DEL) and the C1 range,
/// over-escaping DEL and violating the RFC — DEL is OUTSIDE C0 and is neither
/// `\` nor `"`, so it serializes "as is" as a raw `0x7f` byte.
fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        let cp = c as u32;
        if cp <= 0x1f {
            // C0 control range — the 5 predefined short escapes, else \u00XX.
            match cp {
                0x08 => out.extend_from_slice(b"\\b"),
                0x09 => out.extend_from_slice(b"\\t"),
                0x0a => out.extend_from_slice(b"\\n"),
                0x0c => out.extend_from_slice(b"\\f"),
                0x0d => out.extend_from_slice(b"\\r"),
                _ => {
                    out.extend_from_slice(b"\\u00");
                    out.push(hex_nibble((cp >> 4) as u8));
                    out.push(hex_nibble((cp & 0x0f) as u8));
                }
            }
        } else if cp == 0x5c {
            out.extend_from_slice(b"\\\\");
        } else if cp == 0x22 {
            out.extend_from_slice(b"\\\"");
        } else {
            // Everything else — including DEL (0x7f) and astral (>= 0x10000) —
            // emitted as raw UTF-8 bytes. JCS does NOT emit surrogate-pair
            // escapes for astral code points.
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            out.extend_from_slice(s.as_bytes());
        }
    }
    out.push(b'"');
}

/// Lowercase hex digit for a nibble in `0..=0x0f`.
fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Lexicographic unsigned-UTF-16 code-unit comparison of two member names.
///
/// This is RFC 8785's object-name ordering: each `String` is viewed as a
/// sequence of `u16` code units (with surrogate pairs for astral code points),
/// compared element-wise as unsigned `u16`, with the shorter sequence ordering
/// first when it is a prefix. This is NOT Rust's `String`/UTF-8-byte ordering
/// and NOT Unicode code-point ordering — astral code points differ between the
/// three (e.g. `U+10000` < `U+FFFF` in UTF-16 because `0xd800 < 0xffff`, but
/// `U+10000` > `U+FFFF` in UTF-8-byte order because `0xf0 > 0xef`).
fn utf16_compare(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;
    use crate::json::{json_decode, JsonValue};

    fn max() -> Bounds {
        Bounds::maximum()
    }

    fn enc(v: &JsonValue) -> Vec<u8> {
        jcs_encode(v, &max()).expect("encode")
    }

    fn enc_str(s: &str) -> Vec<u8> {
        let v = json_decode(s.as_bytes(), &max()).expect("decode");
        enc(&v)
    }

    fn f64_(x: f64) -> JsonValue {
        JsonValue::Float(x)
    }

    // ==========================================================================
    // Closure — DEL U+007F emitted RAW (not \u007f). RFC 8785 §3.2.2.2.
    // ==========================================================================

    #[test]
    fn del_byte_is_emitted_raw_not_escaped() {
        // The corpus `jcs-encode-del-raw` case: input `"x\u007fy"` decodes to
        // the 3-char string x·DEL·y. JCS emits the raw 0x7f byte, NOT \u007f.
        // Expected bytes: 22 78 7F 79 22.
        let out = enc(&JsonValue::String("x\u{7f}y".to_string()));
        assert_eq!(out, b"\"x\x7fy\"");
        // The load-bearing assertion: 0x7f appears literally; no backslash-u.
        assert!(out.contains(&0x7f), "raw DEL byte must be present");
        assert!(
            !windows_of(&out, 6).any(|w| w == b"\\u007f"),
            "must NOT contain the \\u007f escape"
        );
    }

    fn windows_of(buf: &[u8], n: usize) -> impl Iterator<Item = &[u8]> {
        buf.windows(n)
    }

    // ==========================================================================
    // Closure — astral codepoint emitted RAW as UTF-8 (not surrogate-pair escape)
    // ==========================================================================

    #[test]
    fn astral_codepoint_is_emitted_raw_utf8() {
        // U+1F600 grinning face: UTF-8 = F0 9F 98 80. JCS emits the 4 raw bytes,
        // NOT a \uD83D\uDE00 surrogate-pair escape.
        let out = enc(&JsonValue::String("\u{1F600}".to_string()));
        assert_eq!(out, vec![b'"', 0xF0, 0x9F, 0x98, 0x80, b'"']);
        assert!(
            !out.windows(2).any(|w| w == b"\\u"),
            "no surrogate-pair escape for astral"
        );
    }

    #[test]
    fn astral_linear_b_u10000_emitted_raw_utf8() {
        // The corpus `jcs-encode-astral-raw` case: the codepoint is U+10000
        // (LINEAR B SYLLABLE B008 A, 𐀀), UTF-8 = F0 90 80 80. JCS emits the 4
        // raw bytes, NOT a \uD800\uDC00 surrogate-pair escape. (The JCS
        // source-read note mislabels this codepoint as U+10300; the corpus is
        // the authority and carries U+10000 — confirmed by reading the raw
        // codepoints of encode.json.)
        let out = enc(&JsonValue::String("\u{10000}".to_string()));
        assert_eq!(out, vec![b'"', 0xF0, 0x90, 0x80, 0x80, b'"']);
    }

    // ==========================================================================
    // Closure — float thresholds (the 5 jcs-encode-float-* cases via ryu-js)
    // ==========================================================================

    #[test]
    fn float_15_serializes_as_15() {
        let out = enc(&f64_(1.5));
        assert_eq!(out, b"1.5");
    }

    #[test]
    fn float_1e_neg6_serializes_fixed_decimal() {
        // e = -6 -> fixed decimal (the JCS threshold boundary).
        let out = enc(&f64_(1e-6));
        assert_eq!(out, b"0.000001");
    }

    #[test]
    fn float_1e_neg7_serializes_scientific() {
        // e = -7 -> scientific (one past the fixed-decimal threshold).
        let out = enc(&f64_(1e-7));
        assert_eq!(out, b"1e-7");
    }

    #[test]
    fn float_over_magnitude_is_rejected_at_encode() {
        // 1e20 and 1e21 exceed the float magnitude bound (±2^53−1 ≈ 9.0e15), so
        // jcs_encode rejects them — the magnitude half of the (d)-class
        // per-node closure (reference jcs.ex:49-50). NOTE: these values were
        // previously used to exercise ryu-js's e≥21 scientific threshold, but
        // that threshold is UNREACHABLE from within-magnitude floats (the
        // largest representable float has decimal exponent ≈ 15.95 — see
        // docs/design/conformance-contract.md), so the decoder cannot produce
        // them and the corpus pins no case for it. The lower (e<−6) threshold
        // stays pinned by `float_1e_neg7_serializes_scientific`.
        assert_eq!(jcs_encode(&f64_(1e20), &max()), Err(Invalid));
        assert_eq!(jcs_encode(&f64_(1e21), &max()), Err(Invalid));
    }

    #[test]
    fn float_negative_zero_normalizes_to_zero() {
        // RFC 8785 Appendix B + ECMA-262: sign of zero dropped.
        let out = enc(&f64_(-0.0f64));
        assert_eq!(out, b"0");
    }

    #[test]
    fn float_appendix_b_sample_matches() {
        // RFC 8785 Appendix B canonical sample: shortest round-trip.
        let out = enc(&f64_(333_333_333.333_333_3));
        assert_eq!(out, b"333333333.3333333");
    }

    // ==========================================================================
    // F2 — NaN / +Infinity / -Infinity MUST fail closed (MANDATORY tripwire)
    // ==========================================================================

    #[test]
    fn float_nan_is_rejected_not_formatted() {
        // ryu-js would emit "NaN"; we MUST fail closed before formatting.
        let out = jcs_encode(&f64_(f64::NAN), &max());
        assert_eq!(out, Err(Invalid));
    }

    #[test]
    fn float_positive_infinity_is_rejected_not_formatted() {
        let out = jcs_encode(&f64_(f64::INFINITY), &max());
        assert_eq!(out, Err(Invalid));
    }

    #[test]
    fn float_negative_infinity_is_rejected_not_formatted() {
        let out = jcs_encode(&f64_(f64::NEG_INFINITY), &max());
        assert_eq!(out, Err(Invalid));
    }

    #[test]
    fn nan_inside_object_is_rejected() {
        // The guard fires at the recursion site, so a non-finite float buried
        // in a structure still fails closed (no partial output leaks).
        let v = JsonValue::Object(vec![("x".to_string(), f64_(f64::NAN))]);
        assert_eq!(jcs_encode(&v, &max()), Err(Invalid));
    }

    // ==========================================================================
    // Closure — object members sorted by UNSIGNED UTF-16 code units
    // ==========================================================================

    #[test]
    fn object_members_sorted_by_utf16_at_root() {
        // Basic ASCII: source b,a -> canonical a,b (the corpus valid-order case).
        let out = enc_str("{\"b\":2,\"a\":1}");
        assert_eq!(out, b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn object_members_sorted_by_utf16_at_every_depth() {
        // Nested objects sort independently at each level.
        let out = enc_str("{\"z\":{\"b\":1,\"a\":2},\"a\":0}");
        assert_eq!(out, b"{\"a\":0,\"z\":{\"a\":2,\"b\":1}}");
    }

    #[test]
    fn utf16_sort_disagrees_with_rust_string_sort_for_astral() {
        // The load-bearing UTF-16-vs-Rust-byte disagreement:
        //   "\u{FFFF}"   -> UTF-8 EF BF BF,   UTF-16 [FFFF]
        //   "\u{10000}"  -> UTF-8 F0 90 80 80, UTF-16 [D800, DC00]
        // Rust String/byte order: EF < F0  ->  U+FFFF < U+10000.
        // UTF-16 order:           D800 < FFFF -> U+10000 < U+FFFF.
        // JCS (UTF-16) MUST place U+10000 first.
        let k_ffff = "\u{FFFF}".to_string();
        let k_10000 = "\u{10000}".to_string();
        // Sanity: confirm the two orderings genuinely disagree.
        assert!(
            k_ffff.as_str() < k_10000.as_str(),
            "precondition: Rust String order puts U+FFFF first"
        );
        let v = JsonValue::Object(vec![
            (k_ffff.clone(), JsonValue::Int(1)),
            (k_10000.clone(), JsonValue::Int(2)),
        ]);
        let out = enc(&v);
        let mut s = std::str::from_utf8(&out).unwrap().chars();
        // Canonical object opens with the UTF-16-smaller key: U+10000 (F0 90 80
        // 80) immediately after the opening brace + quote.
        let _brace = s.next();
        let _quote = s.next();
        let first = s.next().unwrap();
        assert_eq!(
            first, '\u{10000}',
            "UTF-16 sort must place U+10000 before U+FFFF"
        );
    }

    // ==========================================================================
    // Closure — integers plain decimal; arrays preserve order; basic shapes
    // ==========================================================================

    #[test]
    fn integer_is_plain_decimal_no_exponent() {
        assert_eq!(enc(&JsonValue::Int(42)), b"42");
        assert_eq!(enc(&JsonValue::Int(-1)), b"-1");
        assert_eq!(enc(&JsonValue::Int(0)), b"0");
        // The exact magnitude bound (±2^53−1 = 9007199254740991) encodes.
        assert_eq!(
            enc(&JsonValue::Int(9_007_199_254_740_991)),
            b"9007199254740991"
        );
        assert_eq!(
            enc(&JsonValue::Int(-9_007_199_254_740_991)),
            b"-9007199254740991"
        );
        // i64::MIN is far over the magnitude bound, so jcs_encode rejects it
        // (the encode_int formatter itself is panic-free for all i64, but it is
        // only reached for in-magnitude values).
        assert_eq!(jcs_encode(&JsonValue::Int(i64::MIN), &max()), Err(Invalid));
    }

    #[test]
    fn arrays_preserve_source_order() {
        let v = JsonValue::Array(vec![
            JsonValue::Int(3),
            JsonValue::Int(2),
            JsonValue::Int(1),
        ]);
        assert_eq!(enc(&v), b"[3,2,1]");
    }

    #[test]
    fn scalars_encode_canonically() {
        assert_eq!(enc(&JsonValue::Null), b"null");
        assert_eq!(enc(&JsonValue::Bool(true)), b"true");
        assert_eq!(enc(&JsonValue::Bool(false)), b"false");
    }

    #[test]
    fn string_control_chars_use_short_and_lower_u_escapes() {
        // The 5 short escapes + lowercase \u00XX for the rest of C0.
        let s = "\u{00}\u{01}\u{08}\u{09}\u{0a}\u{0c}\u{0d}\u{1f}".to_string();
        let out = enc(&JsonValue::String(s));
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "\"\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f\""
        );
    }

    #[test]
    fn quote_and_backslash_are_escaped() {
        let out = enc(&JsonValue::String("\\\"".to_string()));
        assert_eq!(std::str::from_utf8(&out).unwrap(), "\"\\\\\\\"\"");
    }

    // ==========================================================================
    // Bounds — jcs_bytes ceiling
    // ==========================================================================

    #[test]
    fn jcs_output_over_jcs_bytes_ceiling_is_rejected() {
        // Tighten jcs_bytes to a value smaller than the canonical encoding of a
        // 2-member object -> over the ceiling -> Invalid.
        let overrides = json_decode(b"{\"jcs_bytes\":3}", &max()).unwrap();
        let b = Bounds::new(Some(&overrides)).expect("tighten jcs_bytes");
        let v = JsonValue::Object(vec![
            ("a".to_string(), JsonValue::Int(1)),
            ("b".to_string(), JsonValue::Int(2)),
        ]);
        // Canonical = {"a":1,"b":2} = 12 bytes > 3.
        assert_eq!(jcs_encode(&v, &b), Err(Invalid));
    }

    #[test]
    fn jcs_output_at_exact_jcs_bytes_ceiling_is_accepted() {
        // "0" = 1 byte; set the ceiling to exactly that.
        let overrides = json_decode(b"{\"jcs_bytes\":1}", &max()).unwrap();
        let b = Bounds::new(Some(&overrides)).expect("tighten jcs_bytes");
        assert_eq!(jcs_encode(&JsonValue::Int(0), &b).unwrap(), b"0");
    }

    // ==========================================================================
    // Corpus: priv/conformance/v1/corpus/cases/jcs/encode.json (11 cases)
    // ==========================================================================

    fn corpus_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("priv")
            .join("conformance")
            .join("v1")
            .join("corpus")
    }

    #[test]
    fn corpus_jcs_encode_all_11_cases() {
        let root = corpus_root();
        let path = root.join("cases").join("jcs").join("encode.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let file: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        let cases = file["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("cases array"));

        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        let mut applicability = std::collections::BTreeMap::<&str, usize>::new();

        for case in cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let class = case["class"].as_str().unwrap_or("<no class>");
            *applicability.entry(class).or_default() += 1;
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            let text = case["input"]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing input.text"));

            // The JCS surface is decode-then-encode: an unparseable input is the
            // `invalid` verdict (the invalid_encoding + tamper cases); a decoded
            // value is JCS-encoded and compared byte-exact against `expected.encoded`.
            let actual = match json_decode(text.as_bytes(), &max()) {
                Err(Invalid) => EncodeOutcome::Invalid,
                Ok(value) => match jcs_encode(&value, &max()) {
                    Err(Invalid) => EncodeOutcome::Invalid,
                    Ok(bytes) => EncodeOutcome::Bytes(bytes),
                },
            };

            let agree = match (expected_verdict, &actual) {
                ("valid", EncodeOutcome::Bytes(b)) => {
                    // Byte-exact comparison against expected.encoded.
                    let expected_encoded = case["expected"]["encoded"]
                        .as_str()
                        .unwrap_or_else(|| panic!("case {id} (valid) missing expected.encoded"));
                    b.as_slice() == expected_encoded.as_bytes()
                }
                ("invalid", EncodeOutcome::Invalid) => true,
                _ => false,
            };

            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                match &actual {
                    EncodeOutcome::Bytes(b) => eprintln!(
                        "DISAGREE: id={id} class={class} expected={expected_verdict} \
                         actual_bytes={:?}",
                        std::str::from_utf8(b).ok()
                    ),
                    EncodeOutcome::Invalid => eprintln!(
                        "DISAGREE: id={id} class={class} expected={expected_verdict} actual=Invalid"
                    ),
                }
            }
        }

        eprintln!("applicability: {applicability:?}");
        eprintln!("agreed={agreed} disagreed={disagreed}");
        assert_eq!(agreed, 11, "agreed (jcs encode corpus == 11)");
        assert_eq!(disagreed, 0, "disagreed");
        assert_eq!(applicability["valid"], 9, "valid applicability");
        assert_eq!(applicability["invalid_encoding"], 1, "invalid_encoding");
        assert_eq!(
            applicability["tamper_meaningful_byte"], 1,
            "tamper_meaningful_byte"
        );
    }

    enum EncodeOutcome {
        Bytes(Vec<u8>),
        Invalid,
    }
}
