//! Permissiveness mutation-gate battery — BAP-15 Task 15.
//!
//! Three families live here: the ADR 0014 D6 permissiveness closures (each
//! asserts the SDK REJECTs the host-specific permissive defect that closure
//! defeats), the decode-path
//! conformance legs (signature width + canonical form; same RED discipline), and
//! the canonical-exclusion pins (grant/proof have NO canonical gate — pinned).
//! Each carries the exact mechanical mutation that makes the SAME test go RED (the ADR
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

#[test]
fn closure_6_over_magnitude_and_duplicate_members_rejected() {
    // The scalar/members half of closure #6 (mirrors reference jcs.ex encode_value
    // guards that the closeout cross-vendor review found the Rust encoder was
    // missing). A hand-built integer above ±2^53−1, and a hand-built Object with
    // a duplicate member name, are both rejected at encode — a permissive encoder
    // would accept them. The decoded path cannot produce either (the decoder
    // magnitude-checks and dup-rejects), so these are only reachable via a
    // direct caller of the public `jcs_encode` primitive.
    assert_eq!(
        jcs_encode(&JsonValue::Int(i64::MAX), &max()),
        Err(bounded_authority_protocol::Invalid),
        "over-magnitude integer rejected"
    );
    let dup = JsonValue::Object(vec![
        ("a".to_string(), JsonValue::Int(1)),
        ("a".to_string(), JsonValue::Int(2)),
    ]);
    assert_eq!(
        jcs_encode(&dup, &max()),
        Err(bounded_authority_protocol::Invalid),
        "duplicate object member rejected"
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

// =============================================================================
// Decode-path conformance — canonical form + decoded signature width
// (reference boundary_anchor_codec.ex / key_transition_codec.ex / runtime.ex)
// =============================================================================
//
// Two conformance closures the corpus does not express (it is frozen; the
// drifted-accept classes below have no vector) and the shared validators own:
//
// (a) CANONICAL FORM — the reference anchor/transition codecs require the
//     protected AND payload segments to equal their exact JCS re-encoding
//     (boundary_anchor_codec.ex:95-96 + :118-119; key_transition_codec.ex:127-128
//     + :151-152). The Rust validators checked only the closed member set, so a
//     member-REORDERED (non-canonical) segment with valid fields was accepted.
//     RED-capable mutation: drop the `jcs_encode(value) == bytes` equality in
//     `validate_anchor_header` / `validate_anchor_payload` /
//     `validate_transition_header` / `validate_transition_payload` → the
//     corresponding test goes RED. Exercised through `assemble_compact`, which
//     validates structure WITHOUT cryptographic verification (no key argument),
//     so a dummy 64-byte signature reaches the checks; every verify/encode path
//     rides the same validators via `decode_anchor_parts`/`decode_transition_parts`.
//
// (b) DECODED SIGNATURE WIDTH — the reference gates byte_size(signature) == 64
//     at DECODE (runtime.ex:237 parse_grant + :259 parse_proof;
//     boundary_anchor_codec.ex:88; key_transition_codec.ex:120). The Rust
//     `decode_grant`/`decode_proof` accepted any width (verify checked later),
//     and `encode_anchored_export`'s start-anchor parse (v1.rs:1387) never
//     width-checked at all. RED-capable mutation: delete the width clause in
//     `decode_grant_parts` / `decode_proof_parts` / `decode_anchor_parts` → the
//     corresponding test goes RED. (The transition width clause in
//     `decode_transition_parts` was verdict-inert placement parity at
//     bap-18; the encode-parity slice made it publicly reachable (encode
//     parses caller transitions) and it carries its own leg:
//     `encode_transition_signature_width_rejected`.)

use bounded_authority_protocol::types::{
    AnchoredExportInput, ArchivedObject, BoundaryAnchor, ExpectedAnchor, ExpectedAnchoredExport,
    ExpectedChain, ExpectedExport, GrantInput, GrantOperation, HistoricalKeyChain,
    HistoricalPublicKey, KeyTransition, ProofInput, SigningInput, SigningKind, ValidityUpperBound,
};
use bounded_authority_protocol::{
    assemble_compact, base64url_encode, boundary_anchor_signing_input, decode_grant, decode_proof,
    encode_anchored_export, grant_signing_input, key_transition_signing_input, proof_signing_input,
    verify_anchored_export,
};

/// Minimal JSON string literal serializer for fixture members (plain ASCII
/// values; `"`, `\`, and control bytes escaped — nothing else reachable here).
fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Serializes a JsonValue in SOURCE member order (no JCS sorting) — the
/// order-preserving counterpart `jcs_encode` refuses to be.
fn raw_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Object(members) => {
            let parts: Vec<String> = members
                .iter()
                .map(|(k, v)| format!("{}:{}", json_str(k), raw_json(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        JsonValue::Array(items) => {
            let parts: Vec<String> = items.iter().map(raw_json).collect();
            format!("[{}]", parts.join(","))
        }
        JsonValue::String(s) => json_str(s),
        JsonValue::Int(i) => i.to_string(),
        _ => panic!("fixture: string/int/array/object values only"),
    }
}

/// Re-serializes an object's members in REVERSE source order (values
/// untouched, nested values preserved as-is). The input segment is
/// JCS-canonical (sorted), so the reversal of a >=2-member object is a
/// valid-JSON, non-canonical byte sequence.
fn reversed_segment(segment: &[u8]) -> Vec<u8> {
    let decoded = base64url_decode(segment).expect("canonical segment decodes");
    let value = json_decode(&decoded, &max()).expect("canonical segment parses");
    let members = match &value {
        JsonValue::Object(m) => m,
        _ => panic!("fixture: object segment expected"),
    };
    let mut parts: Vec<String> = members
        .iter()
        .map(|(k, v)| format!("{}:{}", json_str(k), raw_json(v)))
        .collect();
    parts.reverse();
    base64url_encode(format!("{{{}}}", parts.join(",")).as_bytes())
}

/// The all-zero chain hash (sequence-0 anchor requirement).
const Z32: [u8; 32] = [0u8; 32];

fn anchor_fixture() -> BoundaryAnchor {
    BoundaryAnchor {
        anchor_id: "anchor-start".to_string(),
        anchored_at: 1000,
        chain_hash: Z32,
        chain_id: "chain-x".to_string(),
        key_id: "anchor-a".to_string(),
        public_key: [7u8; 32],
        sequence: 0,
    }
}

fn transition_fixture() -> KeyTransition {
    KeyTransition {
        chain_id: "chain-x".to_string(),
        current_key_id: "anchor-a".to_string(),
        current_public_key: [7u8; 32],
        effective_at: 1500,
        next_key_id: "anchor-b".to_string(),
        next_public_key: [8u8; 32],
        transition_id: "transition-1".to_string(),
    }
}

fn compact_with_signature(protected: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + payload.len() + signature.len() + 2);
    out.extend_from_slice(protected);
    out.push(b'.');
    out.extend_from_slice(payload);
    out.push(b'.');
    out.extend_from_slice(&base64url_encode(signature));
    out
}

#[test]
fn canonical_form_anchor_header_rejected() {
    let produced =
        boundary_anchor_signing_input(&anchor_fixture(), &max()).expect("anchor signing input ok");
    // Control: the canonical segments assemble Ok (fixture would pass but-for order).
    let canonical = assemble_compact(
        &SigningInput {
            kind: SigningKind::ChainAnchor,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: produced.payload_segment.clone(),
        },
        &[0u8; 64],
    );
    assert!(canonical.is_ok(), "canonical anchor must assemble");
    // Non-canonical protected header (members reversed, values untouched).
    let r = assemble_compact(
        &SigningInput {
            kind: SigningKind::ChainAnchor,
            protected_segment: reversed_segment(&produced.protected_segment),
            payload_segment: produced.payload_segment.clone(),
        },
        &[0u8; 64],
    );
    assert!(r.is_err(), "non-canonical anchor header must reject");
}

#[test]
fn canonical_form_anchor_payload_rejected() {
    let produced =
        boundary_anchor_signing_input(&anchor_fixture(), &max()).expect("anchor signing input ok");
    // Non-canonical payload (members reversed, values untouched).
    let r = assemble_compact(
        &SigningInput {
            kind: SigningKind::ChainAnchor,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: reversed_segment(&produced.payload_segment),
        },
        &[0u8; 64],
    );
    assert!(r.is_err(), "non-canonical anchor payload must reject");
}

#[test]
fn canonical_form_transition_header_rejected() {
    let produced = key_transition_signing_input(&transition_fixture(), &max())
        .expect("transition signing input ok");
    // Control: the canonical segments assemble Ok.
    let canonical = assemble_compact(
        &SigningInput {
            kind: SigningKind::KeyTransition,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: produced.payload_segment.clone(),
        },
        &[0u8; 64],
    );
    assert!(canonical.is_ok(), "canonical transition must assemble");
    // Non-canonical protected header.
    let r = assemble_compact(
        &SigningInput {
            kind: SigningKind::KeyTransition,
            protected_segment: reversed_segment(&produced.protected_segment),
            payload_segment: produced.payload_segment.clone(),
        },
        &[0u8; 64],
    );
    assert!(r.is_err(), "non-canonical transition header must reject");
}

#[test]
fn canonical_form_transition_payload_rejected() {
    let produced = key_transition_signing_input(&transition_fixture(), &max())
        .expect("transition signing input ok");
    // Non-canonical payload.
    let r = assemble_compact(
        &SigningInput {
            kind: SigningKind::KeyTransition,
            protected_segment: produced.protected_segment.clone(),
            payload_segment: reversed_segment(&produced.payload_segment),
        },
        &[0u8; 64],
    );
    assert!(r.is_err(), "non-canonical transition payload must reject");
}

#[test]
fn signature_width_grant_decode_rejected() {
    let grant = GrantInput {
        issuer: "issuer-a".to_string(),
        grant_id: "grant-1".to_string(),
        key_id: "issuer-key-1".to_string(),
        holder_thumbprint: Z32,
        issued_at: 1000,
        not_before: 1000,
        expires_at: 2000,
        audiences: vec!["aud-a".to_string()],
        operations: vec![GrantOperation {
            name: "do.thing".to_string(),
            selectors: vec![JsonValue::Object(vec![(
                "kind".to_string(),
                JsonValue::String("all".to_string()),
            )])],
        }],
    };
    let produced = grant_signing_input(&grant, &max()).expect("grant signing input ok");
    // Control: a 64-byte signature segment decodes Ok (decode does not verify).
    let ok = decode_grant(
        &compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 64],
        ),
        &max(),
    );
    assert!(ok.is_ok(), "64-byte-signature grant must decode");
    // A 32-byte signature segment must reject at decode.
    let r = decode_grant(
        &compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 32],
        ),
        &max(),
    );
    assert!(
        r.is_err(),
        "wrong-width grant signature must reject at decode"
    );
}

#[test]
fn signature_width_proof_decode_rejected() {
    let proof = ProofInput {
        proof_id: "proof-1".to_string(),
        method: "POST".to_string(),
        target_uri: "https://example.test/api".to_string(),
        invocation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
        operation: "do.thing".to_string(),
        cast_arguments: JsonValue::Object(vec![(
            "q".to_string(),
            JsonValue::String("v".to_string()),
        )]),
        grant_compact: b"grant.gher.compact".to_vec(),
        holder_public_key: [9u8; 32],
        issued_at: 2000,
    };
    let produced = proof_signing_input(&proof, &max()).expect("proof signing input ok");
    // Control: a 64-byte signature segment decodes Ok.
    let ok = decode_proof(
        &compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 64],
        ),
        &max(),
    );
    assert!(ok.is_ok(), "64-byte-signature proof must decode");
    // A 32-byte signature segment must reject at decode.
    let r = decode_proof(
        &compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 32],
        ),
        &max(),
    );
    assert!(
        r.is_err(),
        "wrong-width proof signature must reject at decode"
    );
}

#[test]
fn signature_width_export_encode_start_anchor_rejected() {
    // The encode path parses the START anchor (decode_anchor_parts) and never
    // width-checks its signature segment elsewhere — this is the anchor width
    // gate's one public flip (the plan-review F1 leg of bap-18). Rebuilt on the
    // conformant fixture (the closeout cross-vendor blocking finding: the old
    // garbage-end-anchor control locked in malformed-archive acceptance).
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.start_anchor.split(|&b| b == b'.').collect();
    // Control: the conformant fixture encodes Ok.
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_ok(),
        "conformant export must encode"
    );
    // A 32-byte-signature start anchor must reject at the parse.
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[1]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&base64url_encode(&[0u8; 32]));
    let mut input = f.input.clone();
    input.start_anchor = rebuilt;
    assert!(
        encode_anchored_export(&input, &f.expected).is_err(),
        "wrong-width start-anchor signature must reject at encode"
    );
}

// =============================================================================
// Canonical-EXCLUSION pinning — grant/proof compacts have NO canonical-form gate
// =============================================================================
//
// The reference parse_grant/parse_proof (runtime.ex:237/:259) gate the decoded
// signature width but impose NO Jcs.encode byte-equality on grant/proof
// segments (REQ1-SIGNING-any-order; canonical-form is an anchor/transition
// codec property only). These legs PIN that exclusion: a member-reordered
// grant/proof compact with valid fields MUST still decode Ok. RED-capable
// mutation: add a `jcs_encode(value) == bytes` check to
// `validate_grant_header`/`validate_grant_payload` (or the proof validators) —
// an over-rejection divergence from the reference that would otherwise land
// silently green (no other leg covers the exclusion).

#[test]
fn canonical_exclusion_grant_reorder_still_decodes() {
    let grant = GrantInput {
        issuer: "issuer-a".to_string(),
        grant_id: "grant-1".to_string(),
        key_id: "issuer-key-1".to_string(),
        holder_thumbprint: Z32,
        issued_at: 1000,
        not_before: 1000,
        expires_at: 2000,
        audiences: vec!["aud-a".to_string()],
        operations: vec![GrantOperation {
            name: "do.thing".to_string(),
            selectors: vec![JsonValue::Object(vec![(
                "kind".to_string(),
                JsonValue::String("all".to_string()),
            )])],
        }],
    };
    let produced = grant_signing_input(&grant, &max()).expect("grant signing input ok");
    // Member-reordered (non-canonical) header AND payload still decode Ok — the
    // reference imposes no canonical-form gate on grant compacts.
    let r = decode_grant(
        &compact_with_signature(
            &reversed_segment(&produced.protected_segment),
            &reversed_segment(&produced.payload_segment),
            &[0u8; 64],
        ),
        &max(),
    );
    assert!(
        r.is_ok(),
        "non-canonical grant must still decode (reference has no canonical gate)"
    );
}

#[test]
fn canonical_exclusion_proof_reorder_still_decodes() {
    let proof = ProofInput {
        proof_id: "proof-1".to_string(),
        method: "POST".to_string(),
        target_uri: "https://example.test/api".to_string(),
        invocation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
        operation: "do.thing".to_string(),
        cast_arguments: JsonValue::Object(vec![(
            "q".to_string(),
            JsonValue::String("v".to_string()),
        )]),
        grant_compact: b"grant.gher.compact".to_vec(),
        holder_public_key: [9u8; 32],
        issued_at: 2000,
    };
    let produced = proof_signing_input(&proof, &max()).expect("proof signing input ok");
    // Member-reordered (non-canonical) header AND payload still decode Ok.
    let r = decode_proof(
        &compact_with_signature(
            &reversed_segment(&produced.protected_segment),
            &reversed_segment(&produced.payload_segment),
            &[0u8; 64],
        ),
        &max(),
    );
    assert!(
        r.is_ok(),
        "non-canonical proof must still decode (reference has no canonical gate)"
    );
}

// =============================================================================
// Encode-path validation parity — the reference producer's full contract
// (anchored_export_codec.ex encode: expected-side consistency, row chain
// re-check, gated parses + 7-field matches, key-path walk). One red-capable
// leg per NEW clause/call-site; each names its red mutation. Match legs (5,6,9)
// tamper ONE side only; expected↔chain and key-path legs (1,2,3,12,13,14,15)
// tamper BOTH sides to the same off-value so the targeted clause is the sole
// rejector. Non-canonical legs (7,10) hand-assemble (assemble_compact re-parses
// and would reject the reorder).
// =============================================================================

use bounded_authority_protocol::jwk::public_key_thumbprint_raw;
use bounded_authority_protocol::types::{ChainInput, ConsumptionEntry, ExpectedKeyTransition};
use bounded_authority_protocol::{check_chain, encode_consumption_entry};

const KEY_A: [u8; 32] = [7u8; 32];
const KEY_B: [u8; 32] = [8u8; 32];

/// A fully conformant export: 1 genesis row, start anchor (seq 0, key A), one
/// transition (A→B), end anchor (seq 1, key B). Every value ties to `expected`.
struct ConformantExport {
    input: AnchoredExportInput,
    expected: ExpectedExport,
}

fn build_start_anchor(chain_hash: [u8; 32]) -> Vec<u8> {
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-start".to_string(),
            anchored_at: 1000,
            chain_hash,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-a".to_string(),
            public_key: KEY_A,
            sequence: 0,
        },
        &max(),
    )
    .expect("start anchor signing input ok");
    compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    )
}

fn build_end_anchor(
    chain_hash: [u8; 32],
    key_id: &str,
    public_key: [u8; 32],
    anchored_at: i64,
) -> Vec<u8> {
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at,
            chain_hash,
            chain_id: "chain-x".to_string(),
            key_id: key_id.to_string(),
            public_key,
            sequence: 1,
        },
        &max(),
    )
    .expect("end anchor signing input ok");
    compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    )
}

fn build_transition(effective_at: i64) -> Vec<u8> {
    let produced = key_transition_signing_input(
        &KeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_id: "anchor-a".to_string(),
            current_public_key: KEY_A,
            effective_at,
            next_key_id: "anchor-b".to_string(),
            next_public_key: KEY_B,
            transition_id: "transition-1".to_string(),
        },
        &max(),
    )
    .expect("transition signing input ok");
    compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    )
}

fn expected_start_anchor(chain_hash: [u8; 32]) -> ExpectedAnchor {
    ExpectedAnchor {
        anchor_id: "anchor-start".to_string(),
        anchored_at: 1000,
        chain_hash,
        chain_id: "chain-x".to_string(),
        key_fingerprint: public_key_thumbprint_raw(&KEY_A),
        key_id: "anchor-a".to_string(),
        sequence: 0,
        bounds: None,
    }
}

fn expected_end_anchor(
    chain_hash: [u8; 32],
    key_id: &str,
    public_key: [u8; 32],
    anchored_at: i64,
) -> ExpectedAnchor {
    ExpectedAnchor {
        anchor_id: "anchor-end".to_string(),
        anchored_at,
        chain_hash,
        chain_id: "chain-x".to_string(),
        key_fingerprint: public_key_thumbprint_raw(&public_key),
        key_id: key_id.to_string(),
        sequence: 1,
        bounds: None,
    }
}

fn conformant_export() -> ConformantExport {
    // One genesis row: sequence 1, all-zero previous, its hash is the chain head.
    let (row, head_hash) = encode_consumption_entry(
        &ConsumptionEntry {
            chain_id: "chain-x".to_string(),
            commitment: [5u8; 32],
            previous_hash: Z32,
            sequence: 1,
        },
        &max(),
    )
    .expect("genesis row encodes");
    let rows = vec![row];
    let expected_chain = ExpectedChain {
        chain_id: "chain-x".to_string(),
        first_sequence: 1,
        last_sequence: 1,
        row_count: 1,
        previous_hash: Z32,
        head_hash,
        bounds: None,
    };
    let transitions = vec![build_transition(1500)];
    let expected = ExpectedExport {
        chain: expected_chain.clone(),
        digest: Z32,
        start_anchor: expected_start_anchor(Z32),
        end_anchor: expected_end_anchor(head_hash, "anchor-b", KEY_B, 1600),
        transitions: vec![ExpectedKeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_fingerprint: public_key_thumbprint_raw(&KEY_A),
            current_key_id: "anchor-a".to_string(),
            effective_at: 1500,
            next_key_fingerprint: public_key_thumbprint_raw(&KEY_B),
            next_key_id: "anchor-b".to_string(),
            transition_id: "transition-1".to_string(),
            bounds: None,
        }],
        object_version: "v1".to_string(),
        bounds: None,
    };
    let input = AnchoredExportInput {
        start_anchor: build_start_anchor(Z32),
        end_anchor: build_end_anchor(head_hash, "anchor-b", KEY_B, 1600),
        transitions,
        rows,
    };
    // Self-check: the row set passes check_chain under the expected boundaries.
    assert!(
        check_chain(
            &ChainInput {
                rows: input.rows.clone()
            },
            &expected_chain
        )
        .is_ok(),
        "fixture: rows must pass check_chain"
    );
    ConformantExport { input, expected }
}

// Leg 1 — expected-side: a transition's chain_id drifts from the chain's.
// Mutation: drop the transitions-chain_id clause of the expected-side check.
#[test]
fn encode_expected_chain_id_drift_rejected() {
    let mut f = conformant_export();
    f.expected.transitions[0].chain_id = "chain-OTHER".to_string();
    // Two-sided: the signed transition carries the same drifted chain_id.
    let produced = key_transition_signing_input(
        &KeyTransition {
            chain_id: "chain-OTHER".to_string(),
            current_key_id: "anchor-a".to_string(),
            current_public_key: KEY_A,
            effective_at: 1500,
            next_key_id: "anchor-b".to_string(),
            next_public_key: KEY_B,
            transition_id: "transition-1".to_string(),
        },
        &max(),
    )
    .expect("drifted transition encodes");
    f.input.transitions[0] = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "transition chain_id drift must reject at encode"
    );
}

// Leg 2 — expected-side: start.chain_hash != chain.previous_hash. Two-sided:
// expected.start_anchor carries the same (mismatching) hash the match would
// accept; only the expected-side binding catches it.
#[test]
fn encode_expected_start_hash_binding_rejected() {
    let mut f = conformant_export();
    let wrong = [9u8; 32];
    // Two-sided ANCHOR tamper: the signed start anchor AND expected carry the
    // wrong hash (the match passes); chain.previous_hash stays all-zero so the
    // genesis/check_chain clauses stay satisfied — only the binding fires.
    // Hand-modified payload (the producer rightly refuses a sequence-0 anchor
    // with a non-zero chain hash; the DECODER carries no such rule — the
    // encode-side binding under test is what rejects it, mirroring how the
    // reference's validate_expected_export sees it before any parse).
    let segs: Vec<&[u8]> = f.input.start_anchor.split(|&b| b == b'.').collect();
    let payload_json =
        json_decode(&base64url_decode(segs[1]).expect("payload"), &max()).expect("payload parses");
    let members = match &payload_json {
        JsonValue::Object(m) => m.clone(),
        _ => panic!("object"),
    };
    let get = |k: &str| members.iter().find(|(n, _)| n == k).expect(k).1.clone();
    let wrong_str = String::from_utf8(base64url_encode(&wrong)).unwrap();
    let modified = JsonValue::Object(vec![
        ("anchor_id".to_string(), get("anchor_id")),
        ("anchored_at".to_string(), get("anchored_at")),
        ("chain_hash".to_string(), JsonValue::String(wrong_str)),
        ("chain_id".to_string(), get("chain_id")),
        ("key_fingerprint".to_string(), get("key_fingerprint")),
        ("sequence".to_string(), get("sequence")),
        ("v".to_string(), JsonValue::Int(1)),
    ]);
    let modified_payload = jcs_encode(&modified, &max()).expect("canonical re-encode");
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&base64url_encode(&modified_payload));
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[2]);
    f.input.start_anchor = rebuilt;
    f.expected.start_anchor.chain_hash = wrong;
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "start.chain_hash != chain.previous_hash must reject"
    );
}

// Leg 3 — expected-side: end.sequence != chain.last_sequence (two-sided).
#[test]
fn encode_expected_end_sequence_binding_rejected() {
    let mut f = conformant_export();
    let head = f.expected.chain.head_hash;
    // Two-sided ANCHOR tamper: the signed end anchor AND expected carry
    // sequence 7; chain.last_sequence stays 1 (row-conformant) so check_chain
    // stays satisfied — only the binding fires.
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1600,
            chain_hash: head,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-b".to_string(),
            public_key: KEY_B,
            sequence: 7,
        },
        &max(),
    )
    .expect("re-signed end anchor (seq 7)");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.end_anchor.sequence = 7;
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "end.sequence != chain.last_sequence must reject"
    );
}

// Leg 3b — expected-side: an ANCHOR's chain_id drifts from the chain's
// (two-sided on the end anchor: the 7-field match passes; ONLY the expected-side
// anchors'-chain_id clause fires — the SOLE Rust enforcement of this binding:
// the verify path binds only the header chain_id, never the anchor payload's).
// Mutation: drop the anchors' chain_id clause. (Security-lens F2a; gate-integrity R4.)
#[test]
fn encode_expected_anchor_chain_id_binding_rejected() {
    let mut f = conformant_export();
    let head = f.expected.chain.head_hash;
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1600,
            chain_hash: head,
            chain_id: "chain-OTHER".to_string(),
            key_id: "anchor-b".to_string(),
            public_key: KEY_B,
            sequence: 1,
        },
        &max(),
    )
    .expect("re-signed end anchor (chain drift)");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.end_anchor.chain_id = "chain-OTHER".to_string();
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "anchor chain_id drift from the chain must reject"
    );
}

// Leg 3c — expected-side: end.chain_hash != chain.head_hash (two-sided on the
// anchor; the match passes; only the end-hash binding fires). Mutation: drop
// the end-hash clause. (Security-lens F2b; gate-integrity R3.)
#[test]
fn encode_expected_end_hash_binding_rejected() {
    let mut f = conformant_export();
    let wrong = [9u8; 32];
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1600,
            chain_hash: wrong,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-b".to_string(),
            public_key: KEY_B,
            sequence: 1,
        },
        &max(),
    )
    .expect("re-signed end anchor (hash drift)");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.end_anchor.chain_hash = wrong;
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "end.chain_hash != chain.head_hash must reject"
    );
}

// Leg 16 — key-path end chronology: end.anchored_at BELOW the running time
// (two-sided; the match passes; only the chronology clause fires). Mutation:
// drop the end-chronology clause. (Gate-integrity BLOCKING — the clause was
// mutation-invisible: plan-review F4 was resolved by rewording, not a leg.)
#[test]
fn encode_key_path_end_before_last_time_rejected() {
    let mut f = conformant_export();
    let head = f.expected.chain.head_hash;
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1400,
            chain_hash: head,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-b".to_string(),
            public_key: KEY_B,
            sequence: 1,
        },
        &max(),
    )
    .expect("re-signed end anchor (early)");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.end_anchor.anchored_at = 1400;
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "end anchor before the last transition time must reject"
    );
}

// Leg 17 — the NON-STRICT pin: end.anchored_at == the running time MUST be
// ACCEPTED (chronological_end? is >=, .ex:723). Mutation: flip the clause
// strict (<) — this leg goes RED. (The equality half of the same BLOCKING.)
#[test]
fn encode_key_path_end_time_equality_accepted() {
    let (row, head_hash) = encode_consumption_entry(
        &ConsumptionEntry {
            chain_id: "chain-x".to_string(),
            commitment: [5u8; 32],
            previous_hash: Z32,
            sequence: 1,
        },
        &max(),
    )
    .expect("genesis row encodes");
    let t = {
        let produced = key_transition_signing_input(
            &KeyTransition {
                chain_id: "chain-x".to_string(),
                current_key_id: "anchor-a".to_string(),
                current_public_key: KEY_A,
                effective_at: 1600,
                next_key_id: "anchor-b".to_string(),
                next_public_key: KEY_B,
                transition_id: "transition-1".to_string(),
            },
            &max(),
        )
        .expect("transition at 1600");
        compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 64],
        )
    };
    let expected = ExpectedExport {
        chain: ExpectedChain {
            chain_id: "chain-x".to_string(),
            first_sequence: 1,
            last_sequence: 1,
            row_count: 1,
            previous_hash: Z32,
            head_hash,
            bounds: None,
        },
        digest: Z32,
        start_anchor: expected_start_anchor(Z32),
        end_anchor: expected_end_anchor(head_hash, "anchor-b", KEY_B, 1600),
        transitions: vec![ExpectedKeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_fingerprint: public_key_thumbprint_raw(&KEY_A),
            current_key_id: "anchor-a".to_string(),
            effective_at: 1600,
            next_key_fingerprint: public_key_thumbprint_raw(&KEY_B),
            next_key_id: "anchor-b".to_string(),
            transition_id: "transition-1".to_string(),
            bounds: None,
        }],
        object_version: "v1".to_string(),
        bounds: None,
    };
    let input = AnchoredExportInput {
        start_anchor: build_start_anchor(Z32),
        end_anchor: build_end_anchor(head_hash, "anchor-b", KEY_B, 1600),
        transitions: vec![t],
        rows: vec![row],
    };
    assert!(
        encode_anchored_export(&input, &expected).is_ok(),
        "end.anchored_at == the running time MUST encode (NON-STRICT >=)"
    );
}

// Leg 4 — rows failing the chain re-check. Mutation: drop the check_chain call.
#[test]
fn encode_rows_chain_recheck_rejected() {
    let mut f = conformant_export();
    f.input.rows[0][0] ^= 0x01; // tamper a meaningful byte of the canonical row
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "a row failing check_chain must reject at encode"
    );
}

// Leg 5 — the START-anchor 7-field match call-site: the signed anchor_id
// contradicts expected (two-sided to the same off-value).
#[test]
fn encode_start_anchor_full_match_rejected() {
    let mut f = conformant_export();
    // ONE-SIDED: only the signed anchor_id drifts; expected stays conformant so
    // the 3a MATCH is the sole rejecting clause.
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-WRONG".to_string(),
            anchored_at: 1000,
            chain_hash: Z32,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-a".to_string(),
            public_key: KEY_A,
            sequence: 0,
        },
        &max(),
    )
    .expect("re-signed start anchor");
    f.input.start_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "start-anchor field mismatch must reject"
    );
}

// Leg 6 — the END-anchor match call-site: signed chain_id drifts (two-sided).
#[test]
fn encode_end_anchor_full_match_rejected() {
    let mut f = conformant_export();
    let head = f.expected.chain.head_hash;
    // ONE-SIDED: only the SIGNED anchor_id drifts (chain_id stays conformant so
    // the expected-side clause is not the rejector).
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-WRONG".to_string(),
            anchored_at: 1600,
            chain_hash: head,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-b".to_string(),
            public_key: KEY_B,
            sequence: 1,
        },
        &max(),
    )
    .expect("re-signed end anchor");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "end-anchor field mismatch must reject"
    );
}

// Leg 7 — the END-anchor gated parse: member-reordered (non-canonical) payload.
// Hand-assembled (assemble_compact would reject the reorder). Mutation: drop the
// 3b decode_anchor_parts call (legs 7+8 flip together — one call-site).
#[test]
fn encode_end_anchor_canonical_form_rejected() {
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.end_anchor.split(|&b| b == b'.').collect();
    let payload = segs[1];
    let non_canonical = reversed_segment(payload);
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&non_canonical);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[2]);
    let mut input = f.input.clone();
    input.end_anchor = rebuilt;
    assert!(
        encode_anchored_export(&input, &f.expected).is_err(),
        "non-canonical end anchor must reject at encode"
    );
}

// Leg 8 — the END-anchor gated parse: wrong-width signature. Same call-site as 7.
#[test]
fn encode_end_anchor_signature_width_rejected() {
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.end_anchor.split(|&b| b == b'.').collect();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[1]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&base64url_encode(&[0u8; 32]));
    let mut input = f.input.clone();
    input.end_anchor = rebuilt;
    assert!(
        encode_anchored_export(&input, &f.expected).is_err(),
        "wrong-width end-anchor signature must reject at encode"
    );
}

// Leg 9 — the transition match call-site: signed effective_at drifts (two-sided).
#[test]
fn encode_transition_full_match_rejected() {
    let mut f = conformant_export();
    // ONE-SIDED: only the signed effective_at drifts; expected stays at 1500 so
    // the 3c MATCH is the sole rejecting clause (a two-sided tamper passes the
    // match and the walk — 1501 > 1000, 1600 >= 1501 — and encodes Ok).
    let produced = key_transition_signing_input(
        &KeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_id: "anchor-a".to_string(),
            current_public_key: KEY_A,
            effective_at: 1501,
            next_key_id: "anchor-b".to_string(),
            next_public_key: KEY_B,
            transition_id: "transition-1".to_string(),
        },
        &max(),
    )
    .expect("re-signed transition");
    f.input.transitions[0] = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "transition field mismatch must reject at encode"
    );
}

// Leg 10 — the transition gated parse: non-canonical payload (hand-assembled).
// Mutation: drop the 3c decode_transition_parts call (legs 10+11 together).
#[test]
fn encode_transition_canonical_form_rejected() {
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.transitions[0].split(|&b| b == b'.').collect();
    let non_canonical = reversed_segment(segs[1]);
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&non_canonical);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[2]);
    let mut input = f.input.clone();
    input.transitions[0] = rebuilt;
    assert!(
        encode_anchored_export(&input, &f.expected).is_err(),
        "non-canonical transition must reject at encode"
    );
}

// Leg 11 — the transition gated parse: wrong-width signature. Same call-site as 10.
#[test]
fn encode_transition_signature_width_rejected() {
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.transitions[0].split(|&b| b == b'.').collect();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[1]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&base64url_encode(&[0u8; 32]));
    let mut input = f.input.clone();
    input.transitions[0] = rebuilt;
    assert!(
        encode_anchored_export(&input, &f.expected).is_err(),
        "wrong-width transition signature must reject at encode"
    );
}

// Leg 12 — key-path no-cycle: a SELF-LOOP transition (next fingerprint ==
// current) — caught by the seen-list (current is always already in seen); also
// covers the distinct-fingerprints semantic check by composition (design C4a).
// Hand-built (the producer refuses current==next public keys): take the valid
// transition, set to_key_fingerprint := from_fingerprint, re-encode canonically.
// Mutation: drop the seen-list check.
#[test]
fn encode_key_path_self_loop_rejected() {
    let f = conformant_export();
    let segs: Vec<&[u8]> = f.input.transitions[0].split(|&b| b == b'.').collect();
    let payload_json =
        json_decode(&base64url_decode(segs[1]).expect("payload"), &max()).expect("payload parses");
    let members = match &payload_json {
        JsonValue::Object(m) => m.clone(),
        _ => panic!("object"),
    };
    let get = |k: &str| members.iter().find(|(n, _)| n == k).expect(k).1.clone();
    let from_fp = get("from_key_fingerprint");
    let looped = JsonValue::Object(vec![
        ("chain_id".to_string(), get("chain_id")),
        ("effective_at".to_string(), get("effective_at")),
        ("from_key_fingerprint".to_string(), from_fp.clone()),
        ("to_key_fingerprint".to_string(), from_fp),
        (
            "to_key_id".to_string(),
            JsonValue::String("anchor-a".to_string()),
        ),
        ("transition_id".to_string(), get("transition_id")),
        ("v".to_string(), JsonValue::Int(1)),
    ]);
    let looped_payload = jcs_encode(&looped, &max()).expect("canonical re-encode");
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(segs[0]);
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(&base64url_encode(&looped_payload));
    rebuilt.push(b'.');
    rebuilt.extend_from_slice(segs[2]);
    let mut input = f.input.clone();
    input.transitions[0] = rebuilt;
    // Two-sided: expected mirrors the self-loop exactly, and the END anchor
    // moves to KEY_A — after a self-loop the running key IS A, so the walk ends
    // consistently WITHOUT the cycle guard; the seen-list is the sole rejector
    // (left on KEY_B, the end-binding clause would backstop under the mutation).
    let mut expected = f.expected.clone();
    expected.transitions[0].next_key_fingerprint = public_key_thumbprint_raw(&KEY_A);
    expected.transitions[0].next_key_id = "anchor-a".to_string();
    expected.end_anchor = expected_end_anchor(expected.chain.head_hash, "anchor-a", KEY_A, 1600);
    input.end_anchor = build_end_anchor(expected.chain.head_hash, "anchor-a", KEY_A, 1600);
    assert!(
        encode_anchored_export(&input, &expected).is_err(),
        "self-loop transition must reject at the key-path walk"
    );
}

// Leg 13 — key-path: transition 1's current key != the start anchor's key
// (KEY_C signs, expected mirrors — the match passes; only the walk rejects).
// Mutation: drop the current-key clause.
#[test]
fn encode_key_path_wrong_current_key_rejected() {
    let mut f = conformant_export();
    let produced = key_transition_signing_input(
        &KeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_id: "anchor-c".to_string(),
            current_public_key: [3u8; 32],
            effective_at: 1500,
            next_key_id: "anchor-b".to_string(),
            next_public_key: KEY_B,
            transition_id: "transition-1".to_string(),
        },
        &max(),
    )
    .expect("re-signed transition (current KEY_C)");
    f.input.transitions[0] = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.transitions[0].current_key_id = "anchor-c".to_string();
    f.expected.transitions[0].current_key_fingerprint = public_key_thumbprint_raw(&[3u8; 32]);
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "wrong current key at transition 1 must reject"
    );
}

// Leg 14 — key-path: the end anchor's key != the final running key (KEY_B).
// Re-signed end anchor + mirrored expected; only the end-binding rejects.
// Mutation: drop the end-binding clause.
#[test]
fn encode_key_path_end_key_mismatch_rejected() {
    let mut f = conformant_export();
    let head = f.expected.chain.head_hash;
    let produced = boundary_anchor_signing_input(
        &BoundaryAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1600,
            chain_hash: head,
            chain_id: "chain-x".to_string(),
            key_id: "anchor-c".to_string(),
            public_key: [3u8; 32],
            sequence: 1,
        },
        &max(),
    )
    .expect("re-signed end anchor (KEY_C)");
    f.input.end_anchor = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.end_anchor.key_id = "anchor-c".to_string();
    f.expected.end_anchor.key_fingerprint = public_key_thumbprint_raw(&[3u8; 32]);
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "end anchor on a non-final key must reject"
    );
}

// Leg 15 — key-path chronology: the transition effective_at (999) is NOT
// strictly after the start anchor's anchored_at (1000); expected mirrors.
// Mutation: drop the strictly-after clause.
#[test]
fn encode_key_path_non_chronology_rejected() {
    let mut f = conformant_export();
    let produced = key_transition_signing_input(
        &KeyTransition {
            chain_id: "chain-x".to_string(),
            current_key_id: "anchor-a".to_string(),
            current_public_key: KEY_A,
            effective_at: 999,
            next_key_id: "anchor-b".to_string(),
            next_public_key: KEY_B,
            transition_id: "transition-1".to_string(),
        },
        &max(),
    )
    .expect("re-signed transition (early)");
    f.input.transitions[0] = compact_with_signature(
        &produced.protected_segment,
        &produced.payload_segment,
        &[0u8; 64],
    );
    f.expected.transitions[0].effective_at = 999;
    assert!(
        encode_anchored_export(&f.input, &f.expected).is_err(),
        "non-chronological transition must reject"
    );
}

// Cross-vendor round-2 leg — the verify-side static expected↔chain bindings.
// (The anchor_bytes encode ceiling is TS/Python-specific at the default bounds:
// Rust's identifier_bytes maximum (512) makes a valid anchor compact physically
// unable to exceed the 8192 default anchor_bytes — the Rust pre-check at the
// encode entry is unreachable-at-maximum defense-in-depth, Q4-class. The codex
// probe was the caller-TIGHTENED case, which only the sibling SDKs accept today
// and which the bounds-parity slice will bring to Rust with its own leg.)

#[test]
fn verify_expected_anchor_chain_id_binding_rejected() {
    // Verify-side static binding (round 2): the caller's expected end anchor
    // carries a chain_id from another chain — one-sided expected tamper; the
    // static check fires before any parse.
    let f = conformant_export();
    let encoded = encode_anchored_export(&f.input, &f.expected).expect("encodes");
    let obj = ArchivedObject {
        chunks: {
            // split the archive back into frames: magic + header + start + t + row + end
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let bytes = &encoded.bytes;
            let magic_len = 20; // "BAP1-ARCHIVE\0EXPORT\0"
            let mut off = magic_len;
            while off < bytes.len() {
                let len = u32::from_be_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]) as usize;
                chunks.push(bytes[off + 4..off + 4 + len].to_vec());
                off += 4 + len;
            }
            chunks
        },
        version: "v1".to_string(),
    };
    let keys = HistoricalKeyChain {
        keys: vec![
            HistoricalPublicKey {
                key_id: "anchor-a".to_string(),
                public_key: KEY_A,
                valid_from: 900,
                valid_before: ValidityUpperBound::Unbounded,
            },
            HistoricalPublicKey {
                key_id: "anchor-b".to_string(),
                public_key: KEY_B,
                valid_from: 1400,
                valid_before: ValidityUpperBound::Unbounded,
            },
        ],
    };
    let mut v_expected = ExpectedAnchoredExport {
        chain: f.expected.chain.clone(),
        digest: encoded.digest,
        start_anchor: f.expected.start_anchor.clone(),
        end_anchor: f.expected.end_anchor.clone(),
        transitions: f.expected.transitions.clone(),
        object_version: "v1".to_string(),
        bounds: None,
    };
    // One-sided: the signed anchors are untouched; only the expected end anchor's
    // chain_id is caller-inconsistent.
    v_expected.end_anchor.chain_id = "chain-OTHER".to_string();
    assert!(
        verify_anchored_export(&obj, &keys, &v_expected).is_err(),
        "a caller-inconsistent expected anchor chain_id must reject at verify"
    );
}

/// The corpus anchored-export verify fixture (REAL signatures — the only way a
/// verify leg reaches the deep bounds gates past crypto).
struct CorpusVerifyFixture {
    obj: ArchivedObject,
    keys: HistoricalKeyChain,
    expected: ExpectedAnchoredExport,
}

fn corpus_export_verify_fixture() -> CorpusVerifyFixture {
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/anchored-export/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let c = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid case");
    let input = &c["input"];
    let b64_vec = |v: &serde_json::Value| -> Vec<Vec<u8>> {
        v.as_array()
            .expect("chunks array")
            .iter()
            .map(|x| base64url_decode(x.as_str().expect("b64").as_bytes()).expect("decodes"))
            .collect()
    };
    let mk_key = |v: &serde_json::Value| -> HistoricalPublicKey {
        let raw_pk = base64url_decode(v["public_key"].as_str().expect("pk").as_bytes())
            .expect("key decodes");
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw_pk);
        HistoricalPublicKey {
            key_id: v["key_id"].as_str().expect("kid").to_string(),
            public_key: pk,
            valid_from: v["valid_from"].as_i64().expect("vf"),
            valid_before: match v["valid_before"].as_i64() {
                Some(vb) => ValidityUpperBound::Bounded(vb),
                None => ValidityUpperBound::Unbounded,
            },
        }
    };
    let b64_32 = |v: &serde_json::Value, k: &str| -> [u8; 32] {
        let t = v[k].as_str().unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(t.as_bytes()).expect("32 bytes"));
        out
    };
    let e = &input["expected"];
    let ea = |v: &serde_json::Value| -> ExpectedAnchor {
        ExpectedAnchor {
            anchor_id: v["anchor_id"].as_str().unwrap().to_string(),
            anchored_at: v["anchored_at"].as_i64().unwrap(),
            chain_hash: b64_32(v, "chain_hash"),
            chain_id: v["chain_id"].as_str().unwrap().to_string(),
            key_fingerprint: b64_32(v, "key_fingerprint"),
            key_id: v["key_id"].as_str().unwrap().to_string(),
            sequence: v["sequence"].as_i64().unwrap(),
            bounds: None,
        }
    };
    let ec = &e["chain"];
    let expected = ExpectedAnchoredExport {
        chain: ExpectedChain {
            chain_id: ec["chain_id"].as_str().unwrap().to_string(),
            first_sequence: ec["first_sequence"].as_i64().unwrap(),
            last_sequence: ec["last_sequence"].as_i64().unwrap(),
            row_count: ec["row_count"].as_i64().unwrap(),
            previous_hash: b64_32(ec, "previous_hash"),
            head_hash: b64_32(ec, "last_hash"),
            bounds: None,
        },
        digest: b64_32(e, "digest"),
        start_anchor: ea(&e["start_anchor"]),
        end_anchor: ea(&e["end_anchor"]),
        transitions: e["transitions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|t| ExpectedKeyTransition {
                        chain_id: t["chain_id"].as_str().unwrap().to_string(),
                        current_key_fingerprint: b64_32(t, "current_key_fingerprint"),
                        current_key_id: t["current_key_id"].as_str().unwrap().to_string(),
                        effective_at: t["effective_at"].as_i64().unwrap(),
                        next_key_fingerprint: b64_32(t, "next_key_fingerprint"),
                        next_key_id: t["next_key_id"].as_str().unwrap().to_string(),
                        transition_id: t["transition_id"].as_str().unwrap().to_string(),
                        bounds: None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        object_version: e["object_version"].as_str().unwrap().to_string(),
        bounds: None,
    };
    CorpusVerifyFixture {
        obj: ArchivedObject {
            chunks: b64_vec(&input["chunks"]),
            version: input["version"].as_str().unwrap().to_string(),
        },
        keys: HistoricalKeyChain {
            keys: input["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .map(mk_key)
                .collect(),
        },
        expected,
    }
}

// =============================================================================
// Bounds parity — caller-tightenable bounds through the expected structs.
// Fixture discipline (plan S1): every tightened-outer leg carries present-and-
// equal nested bounds on chain + both anchors + every transition, EXCEPT the
// pin's own legs (7/7b/8).
// =============================================================================

use bounded_authority_protocol::{resolve_bounds, verify_historical_anchor, verify_key_transition};

fn tight(v: &[(&str, u64)]) -> Bounds {
    let mut m = std::collections::BTreeMap::<String, JsonValue>::new();
    for (k, n) in v {
        m.insert(k.to_string(), JsonValue::Int(*n as i64));
    }
    Bounds::new(Some(&JsonValue::Object(m.into_iter().collect()))).expect("tight bounds construct")
}

/// The full nested-equal overlay for a tightened outer (S1 discipline).
fn all_nested_equal(f: &mut ConformantExport, b: Bounds) {
    f.expected.chain.bounds = Some(b);
    f.expected.start_anchor.bounds = Some(b);
    f.expected.end_anchor.bounds = Some(b);
    for t in &mut f.expected.transitions {
        t.bounds = Some(b);
    }
}

#[test]
fn bounds_resolve_none_is_maximum_and_identity_not_tightening() {
    assert_eq!(resolve_bounds(None), Bounds::maximum());
    // identity override: value == the maximum merges to the maximum struct
    let identity = tight(&[("anchor_bytes", 8192)]);
    assert_eq!(resolve_bounds(Some(&identity)), Bounds::maximum());
    // a real tightening differs
    let t = tight(&[("anchor_bytes", 100)]);
    assert_ne!(resolve_bounds(Some(&t)), Bounds::maximum());
}

#[test]
fn bounds_encode_tightened_anchor_bytes_rejects() {
    let mut f = conformant_export();
    let b = tight(&[("anchor_bytes", 100)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_tightened_key_transitions_rejects() {
    // Two transitions (the second chained after the first), limit 1 (S2: 0 is
    // unconstructable — the constructors floor at 1).
    let mut f = two_transition_export();
    let b = tight(&[("key_transitions", 1)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_tightened_chain_row_bytes_rejects() {
    let mut f = conformant_export();
    // the fixture's single row is ~130 bytes; 100 rejects it
    let b = tight(&[("chain_row_bytes", 100)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_tightened_archive_chunks_pins_the_magic() {
    // THE chunk-count magic pin: the fixture's frames = magic + header + start +
    // 1 transition + 1 row + end = 6 WITH the magic, 5 without. Tighten
    // archive_chunks to 5: the count passes WITHOUT the magic and rejects WITH
    // it — this leg goes red exactly if the magic leaves the count.
    let mut f = conformant_export();
    let b = tight(&[("archive_chunks", 5)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_tightened_archive_bytes_rejects() {
    let mut f = conformant_export();
    let b = tight(&[("archive_bytes", 100)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_nested_pin_mismatch_rejects() {
    // Isolated: outer at maximum (untightened — absent nested passes), only the
    // chain nested mismatched.
    let mut f = conformant_export();
    f.expected.chain.bounds = Some(tight(&[("chain_row_bytes", 4000)]));
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_absent_nested_under_tightened_outer_rejects() {
    // B1: the pin's absent branch — outer tightened, ALL nested None → reject
    // (the wrong-ACCEPT direction; the reference rejects at .ex:352-354).
    let mut f = conformant_export();
    // use a genuinely tightening value so the absent branch is the rejector
    f.expected.bounds = Some(tight(&[("chain_row_bytes", 4000)]));
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_encode_identity_outer_absent_nested_accepts() {
    // identity override (anchor_bytes=8192 == the maximum) is NOT tightening:
    // absent nested passes.
    let mut f = conformant_export();
    f.expected.bounds = Some(tight(&[("anchor_bytes", 8192)]));
    assert!(encode_anchored_export(&f.input, &f.expected).is_ok());
}

#[test]
fn bounds_verify_tightened_rejects() {
    // On the corpus' REAL signed archive: control Ok at maximum, Err under a
    // tightened archive_chunks (the correctness lens' F1 — the prior fixture
    // was content-only-chunked + zero-signature, vacuously rejecting at the
    // digest compare before any bounds gate).
    let f = corpus_export_verify_fixture();
    // Control: the corpus archive verifies Ok at maximum (real signatures).
    assert!(verify_anchored_export(&f.obj, &f.keys, &f.expected).is_ok());
    let mut v = f.expected.clone();
    let b = tight(&[("archive_chunks", 3)]);
    v.bounds = Some(b);
    // S1 discipline: present-and-equal nested (the absent-under-tightened pin
    // would otherwise reject first — the mutation-proof caught it).
    v.chain.bounds = Some(b);
    v.start_anchor.bounds = Some(b);
    v.end_anchor.bounds = Some(b);
    for t in &mut v.transitions {
        t.bounds = Some(b);
    }
    // The corpus archive has more than 3 chunks -> Err at the verify chunk gate.
    assert!(verify_anchored_export(&f.obj, &f.keys, &v).is_err());
}

#[test]
fn bounds_standalone_anchor_verify_tightened_rejects() {
    // A REAL corpus-signed anchor (the battery's own dummies fail crypto-verify
    // first, masking the bounds gate): the valid boundary-anchor case verifies
    // Ok at maximum and Err under a tightened anchor_bytes — the standalone
    // entry's bounds threading, red-capable at its own gate.
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/boundary-anchor/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("a valid case exists");
    let input = &valid_case["input"];
    let sj_key = &input["key"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let key = HistoricalPublicKey {
        key_id: sj_key["key_id"].as_str().expect("kid").to_string(),
        public_key: {
            let raw_pk = base64url_decode(sj_key["public_key"].as_str().expect("pk").as_bytes())
                .expect("key decodes");
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&raw_pk);
            pk
        },
        valid_from: sj_key["valid_from"].as_i64().expect("vf"),
        valid_before: match sj_key["valid_before"].as_i64() {
            Some(vb) => ValidityUpperBound::Bounded(vb),
            None => ValidityUpperBound::Unbounded,
        },
    };
    let sj_exp = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let t = sj_exp[k].as_str().unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(t.as_bytes()).expect("32 bytes"));
        out
    };
    let expected = ExpectedAnchor {
        anchor_id: sj_exp["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: sj_exp["anchored_at"].as_i64().unwrap(),
        chain_hash: b64_32("chain_hash"),
        chain_id: sj_exp["chain_id"].as_str().unwrap().to_string(),
        key_fingerprint: b64_32("key_fingerprint"),
        key_id: sj_exp["key_id"].as_str().unwrap().to_string(),
        sequence: sj_exp["sequence"].as_i64().unwrap(),
        bounds: None,
    };
    // Control at maximum: Ok (the real signature verifies).
    assert!(verify_historical_anchor(&compact, &key, &expected).is_ok());
    // Tightened anchor_bytes below the compact length: Err at the standalone entry.
    let mut tight_expected = expected;
    tight_expected.bounds = Some(tight(&[("anchor_bytes", 10)]));
    assert!(verify_historical_anchor(&compact, &key, &tight_expected).is_err());
}

#[test]
fn bounds_two_transition_control_encodes() {
    // The control for the tightened legs: the multi-row/multi-transition fixture
    // must encode Ok at maximum bounds (if this fails, the tightened legs are
    // red for the wrong reason).
    let f = two_transition_export();
    assert!(encode_anchored_export(&f.input, &f.expected).is_ok());
}

fn two_transition_export() -> ConformantExport {
    // Chain: start (A) → t1 (A→B) → t2 (B→C) → end (C, seq 2). Two rows.
    let (row1, h1) = encode_consumption_entry(
        &ConsumptionEntry {
            chain_id: "chain-x".to_string(),
            commitment: [5u8; 32],
            previous_hash: Z32,
            sequence: 1,
        },
        &max(),
    )
    .expect("row1");
    let (row2, h2) = encode_consumption_entry(
        &ConsumptionEntry {
            chain_id: "chain-x".to_string(),
            commitment: [6u8; 32],
            previous_hash: h1,
            sequence: 2,
        },
        &max(),
    )
    .expect("row2");
    let key_c = [3u8; 32];
    let t1 = {
        let p = key_transition_signing_input(
            &KeyTransition {
                chain_id: "chain-x".to_string(),
                current_key_id: "anchor-a".to_string(),
                current_public_key: KEY_A,
                effective_at: 1500,
                next_key_id: "anchor-b".to_string(),
                next_public_key: KEY_B,
                transition_id: "transition-1".to_string(),
            },
            &max(),
        )
        .expect("t1");
        compact_with_signature(&p.protected_segment, &p.payload_segment, &[0u8; 64])
    };
    let t2 = {
        let p = key_transition_signing_input(
            &KeyTransition {
                chain_id: "chain-x".to_string(),
                current_key_id: "anchor-b".to_string(),
                current_public_key: KEY_B,
                effective_at: 1550,
                next_key_id: "anchor-c".to_string(),
                next_public_key: key_c,
                transition_id: "transition-2".to_string(),
            },
            &max(),
        )
        .expect("t2");
        compact_with_signature(&p.protected_segment, &p.payload_segment, &[0u8; 64])
    };
    let end = {
        let p = boundary_anchor_signing_input(
            &BoundaryAnchor {
                anchor_id: "anchor-end".to_string(),
                anchored_at: 1600,
                chain_hash: h2,
                chain_id: "chain-x".to_string(),
                key_id: "anchor-c".to_string(),
                public_key: key_c,
                sequence: 2,
            },
            &max(),
        )
        .expect("end anchor (seq 2)");
        compact_with_signature(&p.protected_segment, &p.payload_segment, &[0u8; 64])
    };
    let expected = ExpectedExport {
        chain: ExpectedChain {
            chain_id: "chain-x".to_string(),
            first_sequence: 1,
            last_sequence: 2,
            row_count: 2,
            previous_hash: Z32,
            head_hash: h2,
            bounds: None,
        },
        digest: Z32,
        start_anchor: expected_start_anchor(Z32),
        end_anchor: {
            let mut ea = expected_end_anchor(h2, "anchor-c", key_c, 1600);
            ea.sequence = 2;
            ea
        },
        transitions: vec![
            ExpectedKeyTransition {
                chain_id: "chain-x".to_string(),
                current_key_fingerprint: public_key_thumbprint_raw(&KEY_A),
                current_key_id: "anchor-a".to_string(),
                effective_at: 1500,
                next_key_fingerprint: public_key_thumbprint_raw(&KEY_B),
                next_key_id: "anchor-b".to_string(),
                transition_id: "transition-1".to_string(),
                bounds: None,
            },
            ExpectedKeyTransition {
                chain_id: "chain-x".to_string(),
                current_key_fingerprint: public_key_thumbprint_raw(&KEY_B),
                current_key_id: "anchor-b".to_string(),
                effective_at: 1550,
                next_key_fingerprint: public_key_thumbprint_raw(&key_c),
                next_key_id: "anchor-c".to_string(),
                transition_id: "transition-2".to_string(),
                bounds: None,
            },
        ],
        object_version: "v1".to_string(),
        bounds: None,
    };
    let input = AnchoredExportInput {
        start_anchor: build_start_anchor(Z32),
        end_anchor: end,
        transitions: vec![t1, t2],
        rows: vec![row1, row2],
    };
    ConformantExport { input, expected }
}

#[test]
fn bounds_standalone_transition_verify_tightened_rejects() {
    // The F1 leg (gate-integrity + security lenses, convergent): the standalone
    // verify_key_transition threading, on a REAL corpus-signed transition (the
    // dummy-signature fixtures fail crypto-verify before the gate).
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/key-transition/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("a valid case exists");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let mk_key = |v: &serde_json::Value| -> HistoricalPublicKey {
        let raw_pk = base64url_decode(v["public_key"].as_str().expect("pk").as_bytes())
            .expect("key decodes");
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw_pk);
        HistoricalPublicKey {
            key_id: v["key_id"].as_str().expect("kid").to_string(),
            public_key: pk,
            valid_from: v["valid_from"].as_i64().expect("vf"),
            valid_before: match v["valid_before"].as_i64() {
                Some(vb) => ValidityUpperBound::Bounded(vb),
                None => ValidityUpperBound::Unbounded,
            },
        }
    };
    let current = mk_key(&input["current_key"]);
    let next = mk_key(&input["next_key"]);
    let b64_32 = |v: &serde_json::Value, k: &str| -> [u8; 32] {
        let t = v[k].as_str().unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(t.as_bytes()).expect("32 bytes"));
        out
    };
    let e = &input["expected"];
    let expected = ExpectedKeyTransition {
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        current_key_fingerprint: b64_32(e, "current_key_fingerprint"),
        current_key_id: e["current_key_id"].as_str().unwrap().to_string(),
        effective_at: e["effective_at"].as_i64().unwrap(),
        next_key_fingerprint: b64_32(e, "next_key_fingerprint"),
        next_key_id: e["next_key_id"].as_str().unwrap().to_string(),
        transition_id: e["transition_id"].as_str().unwrap().to_string(),
        bounds: None,
    };
    // Control at maximum: Ok.
    assert!(verify_key_transition(&compact, &current, &next, &expected).is_ok());
    // Tightened anchor_bytes below the compact length: Err at the standalone entry.
    let mut tight_expected = expected;
    tight_expected.bounds = Some(tight(&[("anchor_bytes", 10)]));
    assert!(verify_key_transition(&compact, &current, &next, &tight_expected).is_err());
}

#[test]
fn bounds_encode_tightened_chain_rows_count_rejects() {
    // The F4 leg: the chain_rows COUNT ceiling (not the per-row byte ceiling) —
    // two rows, limit 1.
    let mut f = two_transition_export();
    let b = tight(&[("chain_rows", 1)]);
    f.expected.bounds = Some(b);
    all_nested_equal(&mut f, b);
    assert!(encode_anchored_export(&f.input, &f.expected).is_err());
}

#[test]
fn bounds_verify_nested_pin_mismatch_rejects() {
    // The verify-side nested pin (F2): the corpus archive + expected at maximum
    // verifies Ok; a mismatched chain nested under an absent outer rejects at
    // the verify-side pin.
    let f = corpus_export_verify_fixture();
    assert!(verify_anchored_export(&f.obj, &f.keys, &f.expected).is_ok());
    let mut v = f.expected.clone();
    v.chain.bounds = Some(tight(&[("chain_row_bytes", 4000)]));
    assert!(verify_anchored_export(&f.obj, &f.keys, &v).is_err());
}

#[test]
fn bounds_verify_absent_nested_under_tightened_outer_rejects() {
    // The verify-side absent branch (F2): outer tightened + all nested None.
    let f = corpus_export_verify_fixture();
    let mut v = f.expected.clone();
    v.bounds = Some(tight(&[("chain_row_bytes", 4000)]));
    assert!(verify_anchored_export(&f.obj, &f.keys, &v).is_err());
}

#[test]
fn bounds_verify_identity_outer_absent_nested_accepts() {
    // The identity acceptance at verify: an outer built from an explicit maximum
    // value is not tightening; the corpus archive verifies Ok.
    let f = corpus_export_verify_fixture();
    let mut v = f.expected.clone();
    v.bounds = Some(tight(&[("chain_row_bytes", 4096)])); // == the maximum
    assert!(verify_anchored_export(&f.obj, &f.keys, &v).is_ok());
}

// Cross-vendor round-4 legs — the compact_bytes ceiling in the decoders + the
// key-window magnitude gates. Each names its red mutation.

#[test]
fn bounds_standalone_anchor_tightened_compact_bytes_rejects() {
    // compact_bytes tightened BELOW the compact length (anchor_bytes left at the
    // 8192 maximum so only the new ceiling can fire).
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/boundary-anchor/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let k = &input["key"];
    let key = HistoricalPublicKey {
        key_id: k["key_id"].as_str().expect("kid").to_string(),
        public_key: {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(
                &base64url_decode(k["public_key"].as_str().expect("pk").as_bytes()).expect("k"),
            );
            pk
        },
        valid_from: k["valid_from"].as_i64().expect("vf"),
        valid_before: match k["valid_before"].as_i64() {
            Some(vb) => ValidityUpperBound::Bounded(vb),
            None => ValidityUpperBound::Unbounded,
        },
    };
    let e = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(e[k].as_str().unwrap().as_bytes()).expect("32"));
        out
    };
    let expected = ExpectedAnchor {
        anchor_id: e["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: e["anchored_at"].as_i64().unwrap(),
        chain_hash: b64_32("chain_hash"),
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        key_fingerprint: b64_32("key_fingerprint"),
        key_id: e["key_id"].as_str().unwrap().to_string(),
        sequence: e["sequence"].as_i64().unwrap(),
        bounds: Some(tight(&[("compact_bytes", 100)])),
    };
    // control: the same fixture with bounds None verifies Ok
    let mut ctrl = expected.clone();
    ctrl.bounds = None;
    assert!(verify_historical_anchor(&compact, &key, &ctrl).is_ok());
    assert!(verify_historical_anchor(&compact, &key, &expected).is_err());
}

#[test]
fn bounds_standalone_anchor_key_window_magnitude_rejects() {
    // The BOUNDED-VALID_BEFORE half: a huge bounded upper bound (2^62) —
    // membership holds (anchored_at is inside), only the magnitude gate fires.
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/boundary-anchor/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let k = &input["key"];
    let mut key = HistoricalPublicKey {
        key_id: k["key_id"].as_str().expect("kid").to_string(),
        public_key: {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(
                &base64url_decode(k["public_key"].as_str().expect("pk").as_bytes()).expect("k"),
            );
            pk
        },
        valid_from: 0,
        valid_before: ValidityUpperBound::Unbounded,
    };
    // Membership must still hold so ONLY the magnitude gate can fire: a huge
    // BOUNDED valid_before (2^62) with valid_from 0 — anchored_at 1000 is inside
    // [0, 2^62), but 2^62 > the integer_magnitude maximum (2^53-1).
    key.valid_before = ValidityUpperBound::Bounded(4_611_686_018_427_387_904); // 2^62
    let e = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(e[k].as_str().unwrap().as_bytes()).expect("32"));
        out
    };
    let expected = ExpectedAnchor {
        anchor_id: e["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: e["anchored_at"].as_i64().unwrap(),
        chain_hash: b64_32("chain_hash"),
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        key_fingerprint: b64_32("key_fingerprint"),
        key_id: e["key_id"].as_str().unwrap().to_string(),
        sequence: e["sequence"].as_i64().unwrap(),
        bounds: None,
    };
    assert!(verify_historical_anchor(&compact, &key, &expected).is_err());
}

// Round-5 legs (the claude peer): the transition-path round-4 gates + the
// valid_from half of the anchor magnitude family.

#[test]
fn bounds_standalone_transition_tightened_compact_bytes_rejects() {
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/key-transition/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let mk_key = |v: &serde_json::Value| -> HistoricalPublicKey {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(
            &base64url_decode(v["public_key"].as_str().expect("pk").as_bytes()).expect("k"),
        );
        HistoricalPublicKey {
            key_id: v["key_id"].as_str().expect("kid").to_string(),
            public_key: pk,
            valid_from: v["valid_from"].as_i64().expect("vf"),
            valid_before: match v["valid_before"].as_i64() {
                Some(vb) => ValidityUpperBound::Bounded(vb),
                None => ValidityUpperBound::Unbounded,
            },
        }
    };
    let current = mk_key(&input["current_key"]);
    let next = mk_key(&input["next_key"]);
    let e = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(e[k].as_str().unwrap().as_bytes()).expect("32"));
        out
    };
    let expected = ExpectedKeyTransition {
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        current_key_fingerprint: b64_32("current_key_fingerprint"),
        current_key_id: e["current_key_id"].as_str().unwrap().to_string(),
        effective_at: e["effective_at"].as_i64().unwrap(),
        next_key_fingerprint: b64_32("next_key_fingerprint"),
        next_key_id: e["next_key_id"].as_str().unwrap().to_string(),
        transition_id: e["transition_id"].as_str().unwrap().to_string(),
        bounds: Some(tight(&[("compact_bytes", 100)])),
    };
    // Control at maximum: Ok.
    let mut ctrl = expected.clone();
    ctrl.bounds = None;
    assert!(verify_key_transition(&compact, &current, &next, &ctrl).is_ok());
    assert!(verify_key_transition(&compact, &current, &next, &expected).is_err());
}

#[test]
fn bounds_standalone_transition_key_window_magnitude_rejects() {
    // The huge-BOUNDED-valid_before variant on the CURRENT key of the transition
    // path (membership holds; only the magnitude gate fires).
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/key-transition/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let mk_key = |v: &serde_json::Value| -> HistoricalPublicKey {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(
            &base64url_decode(v["public_key"].as_str().expect("pk").as_bytes()).expect("k"),
        );
        HistoricalPublicKey {
            key_id: v["key_id"].as_str().expect("kid").to_string(),
            public_key: pk,
            valid_from: v["valid_from"].as_i64().expect("vf"),
            valid_before: match v["valid_before"].as_i64() {
                Some(vb) => ValidityUpperBound::Bounded(vb),
                None => ValidityUpperBound::Unbounded,
            },
        }
    };
    let mut current = mk_key(&input["current_key"]);
    current.valid_before = ValidityUpperBound::Bounded(4_611_686_018_427_387_904); // 2^62
    let next = mk_key(&input["next_key"]);
    let e = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(e[k].as_str().unwrap().as_bytes()).expect("32"));
        out
    };
    let expected = ExpectedKeyTransition {
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        current_key_fingerprint: b64_32("current_key_fingerprint"),
        current_key_id: e["current_key_id"].as_str().unwrap().to_string(),
        effective_at: e["effective_at"].as_i64().unwrap(),
        next_key_fingerprint: b64_32("next_key_fingerprint"),
        next_key_id: e["next_key_id"].as_str().unwrap().to_string(),
        transition_id: e["transition_id"].as_str().unwrap().to_string(),
        bounds: None,
    };
    assert!(verify_key_transition(&compact, &current, &next, &expected).is_err());
}

#[test]
fn bounds_standalone_anchor_key_window_magnitude_valid_from_rejects() {
    // The valid_from half, symmetric-sign: a NEGATIVE out-of-magnitude
    // valid_from (i64::MIN + 1 — membership holds for any positive anchored_at
    // only if... it does not; instead use valid_from = -(2^62) with anchored_at
    // 1000: 1000 >= valid_from passes; unsigned_abs(2^62) > 2^53-1 fires).
    let case_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/corpus/cases/boundary-anchor/verify.json"
    );
    let raw = std::fs::read(case_path).expect("corpus readable");
    let root: serde_json::Value = serde_json::from_slice(&raw).expect("corpus parses");
    let valid_case = root["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["class"].as_str() == Some("valid"))
        .expect("valid");
    let input = &valid_case["input"];
    let compact = input["compact"]
        .as_str()
        .expect("compact")
        .as_bytes()
        .to_vec();
    let k = &input["key"];
    let mut key = HistoricalPublicKey {
        key_id: k["key_id"].as_str().expect("kid").to_string(),
        public_key: {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(
                &base64url_decode(k["public_key"].as_str().expect("pk").as_bytes()).expect("k"),
            );
            pk
        },
        valid_from: 0,
        valid_before: ValidityUpperBound::Unbounded,
    };
    key.valid_from = -(4_611_686_018_427_387_904i64); // -2^62: membership holds, magnitude fires
    let e = &input["expected"];
    let b64_32 = |k: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&base64url_decode(e[k].as_str().unwrap().as_bytes()).expect("32"));
        out
    };
    let expected = ExpectedAnchor {
        anchor_id: e["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: e["anchored_at"].as_i64().unwrap(),
        chain_hash: b64_32("chain_hash"),
        chain_id: e["chain_id"].as_str().unwrap().to_string(),
        key_fingerprint: b64_32("key_fingerprint"),
        key_id: e["key_id"].as_str().unwrap().to_string(),
        sequence: e["sequence"].as_i64().unwrap(),
        bounds: None,
    };
    assert!(verify_historical_anchor(&compact, &key, &expected).is_err());
}
