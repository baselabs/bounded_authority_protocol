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
//     `decode_transition_parts` is verdict-inert placement parity — every public
//     path already rejected wrong-width transitions — and carries no test leg;
//     see the BAP-15 evidence amendment.)

use bounded_authority_protocol::types::{
    AnchoredExportInput, BoundaryAnchor, ExpectedAnchor, ExpectedChain, ExpectedExport, GrantInput,
    GrantOperation, KeyTransition, ProofInput, SigningInput, SigningKind,
};
use bounded_authority_protocol::{
    assemble_compact, base64url_encode, boundary_anchor_signing_input, decode_grant, decode_proof,
    encode_anchored_export, grant_signing_input, key_transition_signing_input, proof_signing_input,
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
    // The encode path parses the START anchor (v1.rs decode_anchor_parts) and
    // never width-checks its signature segment elsewhere — this is the anchor
    // width gate's one public flip (the plan-review F1 leg).
    let produced =
        boundary_anchor_signing_input(&anchor_fixture(), &max()).expect("anchor signing input ok");
    let expected = ExpectedExport {
        chain: ExpectedChain {
            chain_id: "chain-x".to_string(),
            first_sequence: 1, // start_anchor.sequence + 1 (the :1390 binding)
            last_sequence: 1,
            row_count: 1,
            previous_hash: Z32,
            head_hash: [1u8; 32],
        },
        digest: Z32,
        start_anchor: ExpectedAnchor {
            anchor_id: "anchor-start".to_string(),
            anchored_at: 1000,
            chain_hash: Z32,
            chain_id: "chain-x".to_string(),
            key_fingerprint: Z32,
            key_id: "anchor-a".to_string(),
            sequence: 0,
        },
        end_anchor: ExpectedAnchor {
            anchor_id: "anchor-end".to_string(),
            anchored_at: 1100,
            chain_hash: [1u8; 32],
            chain_id: "chain-x".to_string(),
            key_fingerprint: Z32,
            key_id: "anchor-a".to_string(),
            sequence: 1,
        },
        transitions: vec![],
        object_version: "v1".to_string(),
    };
    // Control: a 64-byte-signature start anchor encodes Ok (rows/end frame raw).
    let ok_input = AnchoredExportInput {
        start_anchor: compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 64],
        ),
        end_anchor: b"end-anchor-bytes".to_vec(),
        transitions: vec![],
        rows: vec![b"row-0".to_vec()],
    };
    assert!(
        encode_anchored_export(&ok_input, &expected).is_ok(),
        "64-byte-signature start anchor must encode"
    );
    // A 32-byte-signature start anchor must reject at the parse.
    let bad_input = AnchoredExportInput {
        start_anchor: compact_with_signature(
            &produced.protected_segment,
            &produced.payload_segment,
            &[0u8; 32],
        ),
        ..ok_input
    };
    assert!(
        encode_anchored_export(&bad_input, &expected).is_err(),
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
