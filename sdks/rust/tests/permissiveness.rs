//! Permissiveness mutation-gate battery — BAP-15 Task 15.
//!
//! Each test names one ADR 0014 D6 permissiveness closure, asserts the SDK
//! REJECTs the host-specific permissive defect that closure defeats, and names
//! the exact mechanical mutation that makes the SAME test go RED (the ADR
//! 0005:240-246 discipline — a gate that cannot go red is vacuous). The closures
//! are exercised through the PUBLIC crate surface only (this file lives outside
//! `src/` so it cannot reach internals), which is the boundary a consumer sees.
//!
//! Closures #1/#3/#4/#5 are owned by `json_decode`; closure #6 is owned by
//! `jcs_encode`; the base64url pad-bits closure is owned by `base64url_decode`.
//! Closure #2 (ordered collision-free members) is, in Rust, structurally
//! immune to the prototype-absorption half (a `Vec<(String, JsonValue)>` has no
//! Object-prototype model — `__proto__`/`constructor` are ordinary `String`
//! keys, un-absorbable by any mutation), so its red-capable half here is
//! **source-order preservation**.
//!
//! The red-capability of closure #6 (the `(d)`-class per-node encode-bounds —
//! the one closure the corpus CANNOT express) was proven live at authoring by
//! removing each per-node check from `jcs_encode`, watching the corresponding
//! test flip RED, and restoring it; the quoted runs ride the T15 commit body.

use bounded_authority_protocol::{
    base64url_decode, jcs_encode, json_decode, request_digest, Bounds, JsonValue,
};

fn max() -> Bounds {
    Bounds::maximum()
}

// =============================================================================
// Closure #1 — REQ1-JSON-no-duplicate (duplicate member at ANY depth rejected)
// =============================================================================
//
// The load-bearing permissiveness case (ADR 0005:240-246): a last-wins host
// decoder silently accepts `{"a":1,"a":2}` (keeping `a:2`), letting a smuggled
// `alg:"none"` override `alg:"EdDSA"`. RED-capable mutation: convert the
// decoder's `Object` accumulation to a last-write-wins insert (drop the
// `members.iter().any(|(k, _)| k == &name)` dup check in `json::parse_object`)
// → this test goes RED (the decode succeeds).

#[test]
fn closure_1_duplicate_member_rejected() {
    assert_eq!(
        json_decode(br#"{"a":1,"a":2}"#, &max()),
        Err(bounded_authority_protocol::Invalid)
    );
    // At depth (not only root) — the legacy algorithm-swap shape.
    assert_eq!(
        json_decode(br#"{"o":{"alg":"EdDSA","alg":"none"}}"#, &max()),
        Err(bounded_authority_protocol::Invalid)
    );
}

// =============================================================================
// Closure #2 — ordered collision-free members (source order preserved)
// =============================================================================
//
// RFC 8785 sorts object members at JCS encode time, NOT at decode time, so the
// DECODER must preserve source member order — selector semantic identity and
// the canonical re-encode both depend on a stable order surviving the round
// trip. RED-capable mutation: change `JsonValue::Object`'s carrier from
// `Vec<(String, JsonValue)>` to a `HashMap<String, JsonValue>` or `BTreeMap`
// (non-order-preserving) → this test goes RED (the recovered names are no
// longer the source order).

#[test]
fn closure_2_source_member_order_preserved() {
    let v = json_decode(br#"{"b":1,"a":2,"c":3}"#, &max()).expect("decodes");
    match v {
        JsonValue::Object(members) => {
            let names: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                names,
                vec!["b", "a", "c"],
                "source order must survive decode"
            );
        }
        _ => panic!("expected object"),
    }
}

// =============================================================================
// Closure #3 — REQ1-JSON-raw-lexeme (64-byte ceiling + exact magnitude,
//              enforced BEFORE host conversion)
// =============================================================================
//
// A 65-byte number lexeme and an over-magnitude integer (`2^53`, which fits
// `i64` and would decode under a permissive host parse) are rejected on the RAW
// lexeme before any `f64`/`i64` conversion. RED-capable mutation: delete the
// raw-lexeme scan block in `json::parse_number` (the `number_lexeme_bytes` +
// `magnitude_ok` checks) → these tests go RED (the over-long / over-magnitude
// lexemes decode).

#[test]
fn closure_3_raw_lexeme_byte_ceiling_and_magnitude_enforced_pre_conversion() {
    // 65-byte float lexeme (`1.` + 63 zeros) — over the 64-byte ceiling.
    let mut over = String::from("1.");
    over.push_str(&"0".repeat(63));
    assert_eq!(
        json_decode(over.as_bytes(), &max()),
        Err(bounded_authority_protocol::Invalid),
        "65-byte lexeme rejected before conversion"
    );
    // 2^53 fits i64 (a permissive host parse accepts it) but the exact
    // magnitude check rejects it on the raw lexeme.
    assert_eq!(
        json_decode(b"9007199254740992", &max()),
        Err(bounded_authority_protocol::Invalid),
        "2^53 rejected before conversion"
    );
}

// =============================================================================
// Closure #4 — REQ1-JSON-single-value (one value + trailing whitespace only)
// =============================================================================
//
// RED-capable mutation: make the trailing-bytes check accept any suffix (drop
// the `d.pos != d.input.len` single-value check) → this test goes RED (the
// trailing `1` is accepted).

#[test]
fn closure_4_trailing_bytes_after_single_value_rejected() {
    // Trailing whitespace is permitted; trailing non-whitespace is not.
    assert!(
        json_decode(b"{}  \t\n\r", &max()).is_ok(),
        "trailing ws accepted"
    );
    assert_eq!(
        json_decode(b"{} 1", &max()),
        Err(bounded_authority_protocol::Invalid),
        "trailing value rejected"
    );
    assert_eq!(
        json_decode(b"1 2", &max()),
        Err(bounded_authority_protocol::Invalid),
        "two back-to-back values rejected"
    );
}

// =============================================================================
// Closure #5 — int/float tag distinction (no tag collapse)
// =============================================================================
//
// `1` decodes to `Int(1)` and `1.0` to `Float(1.0)` — distinct variants — and
// they produce DIFFERENT request digests (the typed projection wraps them as
// `["integer",1]` vs `["float",1]`). RED-capable mutation: collapse both number
// lexemes to `Float` (force `is_float = true` in `json::parse_number`), OR
// collapse the typed projection to a bare number → the digest-distinctness
// assertion goes RED (the two digests collide).

#[test]
fn closure_5_int_and_float_tags_do_not_collapse() {
    let i = json_decode(b"1", &max()).expect("1 decodes");
    let f = json_decode(b"1.0", &max()).expect("1.0 decodes");
    assert!(matches!(i, JsonValue::Int(_)), "1 is Int");
    assert!(matches!(f, JsonValue::Float(_)), "1.0 is Float");
    assert_ne!(i, f, "Int(1) and Float(1.0) are distinct variants");

    // End-to-end at the auth-binding primitive: distinct tags -> distinct
    // request digests (a collapse would make the digests collide, a silent
    // request-binding bypass).
    let int_digest = request_digest("read", &JsonValue::Int(1), &max()).expect("int digest");
    let float_digest =
        request_digest("read", &JsonValue::Float(1.0), &max()).expect("float digest");
    assert_ne!(
        int_digest, float_digest,
        "Int(1) and Float(1.0) MUST produce different request digests"
    );
}

// =============================================================================
// Closure #6 — (d)-class per-node encode bounds in `jcs_encode`
// =============================================================================
//
// `jcs_encode` is a PUBLIC primitive reachable by a direct caller with a
// hand-built (not decode-bounded) value, so it must enforce the structural
// ceilings DURING recursion — not only the final output length — or a
// pathological hand-built value could force unbounded recursion (stack
// overflow), unbounded traversal, or over-budget intermediate allocation. The
// corpus cannot express this (a hand-built value never enters it), so the
// closure is proven red-capable here.
//
// RED-capable mutations (proven live at authoring; quoted in the commit body):
//   * remove the `depth > bounds.depth()` guards in `jcs::encode_value` →
//     `closure_6_depth_over_bound_rejected` goes RED (the 33-deep hand-built
//     value encodes to ~67 bytes and returns Ok).
//   * remove the `*nodes > bounds.total_nodes()` guard in `jcs::encode_value`
//     → `closure_6_total_nodes_over_bound_rejected` goes RED (the 4370-node
//     hand-built value encodes to ~9 KB, under jcs_bytes, and returns Ok).
//
// The per-node `jcs_bytes` early bail is an allocation guard (it stops
// materializing the encoding the moment the budget is crossed); its VERDICT is
// identical to the final-only check, so it is a code-review property, not a
// verdict test — the depth and total_nodes guards are the verdict-observable
// red-capable half.

/// Build a value nested `depth` arrays deep around `leaf` (depth counted on
/// containers, mirroring the decoder).
fn nested_arrays(depth: usize, leaf: JsonValue) -> JsonValue {
    let mut v = leaf;
    for _ in 0..depth {
        v = JsonValue::Array(vec![v]);
    }
    v
}

#[test]
fn closure_6_depth_over_bound_rejected() {
    // 33 nested arrays around Int(0): the innermost array sits at depth 33 >
    // max 32. This shape is INexpressible via `json_decode` (the decoder rejects
    // depth 33), so it can only arrive at `jcs_encode` as a hand-built value —
    // exactly the direct-caller threat the closure defends.
    let v = nested_arrays(33, JsonValue::Int(0));
    assert_eq!(
        jcs_encode(&v, &max()),
        Err(bounded_authority_protocol::Invalid),
        "depth-33 hand-built value rejected"
    );
    // 32 deep is the exact bound and MUST still encode.
    let ok = nested_arrays(32, JsonValue::Int(0));
    assert!(
        jcs_encode(&ok, &max()).is_ok(),
        "depth-32 exact bound encodes"
    );
}

#[test]
fn closure_6_total_nodes_over_bound_rejected() {
    // 17 arrays each of 256 zeros: 1 (root) + 17 (mids) + 17 * 257 (inner arrays
    // + their leaves) = 4370 nodes > max 4096. Every array is within
    // `array_items` (root 17, inner 256 == exact bound) and depth is 2, so ONLY
    // the total_nodes ceiling fires — isolating that guard.
    let inner = JsonValue::Array(vec![JsonValue::Int(0); 256]);
    let root = JsonValue::Array(vec![inner; 17]);
    assert_eq!(
        jcs_encode(&root, &max()),
        Err(bounded_authority_protocol::Invalid),
        "4370-node hand-built value rejected (total_nodes > 4096)"
    );
}

#[test]
fn closure_6_output_over_jcs_bytes_rejected() {
    // The output-budget ceiling (the final-check verdict, present since T4).
    // A single 70_000-byte string encodes to 70_002 bytes > jcs_bytes (65536).
    let big = JsonValue::String("a".repeat(70_000));
    assert_eq!(
        jcs_encode(&big, &max()),
        Err(bounded_authority_protocol::Invalid),
        "over-jcs_bytes output rejected"
    );
}

// =============================================================================
// base64url pad-bits closure — REQ1-B64-canonical (corpus-blind)
// =============================================================================
//
// The two corpus `base64url.decode.invalid_encoding` cases are caught by the
// padding/alphabet rules, so the non-zero-unused-pad-bits rejection is NOT
// exercised by any corpus case — it is proven red-capable here. `AB` decodes to
// `[0x00]` but its trailing 4 bits are non-zero, so the canonical re-encode is
// `AA` != `AB`. RED-capable mutation: drop the `base64url_encode(&out) != input`
// canonical re-encode check in `base64url::base64url_decode` → this test goes
// RED (`AB` decodes to `[0x00]`).

#[test]
fn base64url_non_canonical_pad_bits_rejected() {
    // 2-char group, 4 non-zero unused pad bits: `AB` -> would decode to [0x00]
    // but re-encodes to `AA`.
    assert_eq!(
        base64url_decode(b"AB"),
        Err(bounded_authority_protocol::Invalid)
    );
    // 3-char group, 2 non-zero unused pad bits: `AAB` -> would decode to
    // [0x00, 0x00] but re-encodes to `AAA`.
    assert_eq!(
        base64url_decode(b"AAB"),
        Err(bounded_authority_protocol::Invalid)
    );
    // The mirror: zero pad bits are canonical and accepted.
    assert_eq!(base64url_decode(b"AA"), Ok(vec![0x00]));
    assert_eq!(base64url_decode(b"AAA"), Ok(vec![0x00, 0x00]));
}
