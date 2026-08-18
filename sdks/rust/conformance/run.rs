//! BAP-15 Task 14 — the conformance runner (acceptance gate).
//!
//! This is an integration test living OUTSIDE `src/`, so it can call ONLY the
//! crate's public surface. It is the consolidation of the per-surface corpus
//! harnesses written into the `src/` test modules during Tasks 1–13 into one
//! gate that:
//!
//! 1. **SHA-binds** the vendored corpus snapshot (ADR 0014 §D4): hashes
//!    `conformance/corpus/index.json` at startup and fails closed on mismatch
//!    with the certified SHA — a consumer who vendors a drifted corpus gets a
//!    hard failure, not silent drift.
//! 2. **Dispatches all 283 cases** across the 28 surfaces through the public
//!    façade + versioned primitives, constructing each `src/` input struct
//!    field-by-field (the F3 construction seam — there is NO serde derive on any
//!    `src/` struct; `serde_json` reads the corpus into `serde_json::Value` and
//!    the runner hand-builds every input).
//! 3. **Runs the two-boundary key census** (ADR 0014 §D9): the set of public
//!    keys imported at the SDK's `[u8;32]` crypto boundary — every key the
//!    runner feeds to a crate function — thumbprinted and compared BOTH
//!    directions against the index `public_key_fingerprints` (no extra, no
//!    missing).
//! 4. Asserts `agreed == total_cases (283)` and `disagreed == 0`.
//!
//! Derivation hygiene (ADR 0014 §D5): the runner is derived from ADR 0014,
//! `docs/protocol-v1.md`, and the existing in-crate harnesses only. It does NOT
//! read the reference Elixir implementation or any sibling SDK. The corpus is
//! the falsifier; the SHA binding + census are the mechanisms.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use bounded_authority_protocol as bap;
use bounded_authority_protocol::facts::NotEvaluated;
use bounded_authority_protocol::types::*;
use bounded_authority_protocol::{Bounds, Invalid, JsonValue};
// `sha2` is a runtime dependency of the crate, re-used here for the SHA-bind.
use sha2::{Digest, Sha256};

// ============================================================================
// ADR 0014 §D4 — the certified corpus index SHA-256 (verified by hashing the
// source corpus index.json, then byte-copied into the SDK's vendored snapshot).
// ============================================================================

const CERTIFIED_INDEX_SHA: &str =
    "a5ac7361c508d2bb55c6ca3045a5cc06ec4a3f64f65904214108c6f10c704dcc";

/// The vendored corpus root (self-contained SDK test corpus — ADR 0015 D5).
fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance")
        .join("corpus")
}

fn max() -> Bounds {
    Bounds::maximum()
}

/// Hex lowercase SHA-256.
fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    use std::fmt::Write;
    digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut acc, b| {
            write!(acc, "{b:02x}").unwrap();
            acc
        })
}

/// ADR 0014 §D4 binding: panic on any drift from the certified index SHA.
fn assert_certified_index_sha(bytes: &[u8]) {
    let actual = hex_sha256(bytes);
    assert_eq!(
        actual, CERTIFIED_INDEX_SHA,
        "index.json SHA mismatch — corpus drift (expected {CERTIFIED_INDEX_SHA}, got {actual})"
    );
}

// ============================================================================
// ADR 0014 §D9 — the two-boundary key census.
// ============================================================================

/// Collects the base64url RFC 7638 thumbprints of every `[u8;32]` public key
/// the runner imports at the crate's crypto boundary. Wrong-width keys never
/// reach this set: the import helpers (`b64url_to_32`) reject them first, so a
/// fixture's invalid-short-key case contributes nothing (mirroring the crate's
/// own import boundary).
#[derive(Default)]
struct KeyCensus {
    observed: BTreeSet<String>,
}

impl KeyCensus {
    /// Records a 32-byte public key by computing its RFC 7638 thumbprint via the
    /// crate's own `thumbprint` function (the crate is the thumbprint authority).
    fn observe(&mut self, public_key: &[u8; 32]) {
        let tp = bap::thumbprint(public_key);
        // `thumbprint` returns base64url ASCII bytes; the index fingerprints are
        // base64url strings.
        self.observed
            .insert(String::from_utf8(tp).expect("thumbprint is base64url ASCII"));
    }
}

/// Two-direction census: every observed thumbprint IS declared AND every
/// declared thumbprint IS observed. Panics naming the direction that fails.
fn assert_census(observed: &BTreeSet<String>, declared: &BTreeSet<String>) {
    let extra: Vec<&String> = observed.difference(declared).collect();
    let missing: Vec<&String> = declared.difference(observed).collect();
    assert!(
        extra.is_empty(),
        "census EXTRA keys (observed at the boundary but NOT declared in index): {extra:?}"
    );
    assert!(
        missing.is_empty(),
        "census MISSING keys (declared in index but NOT observed at the boundary): {missing:?}"
    );
}

// ============================================================================
// F3 construction seam — hand-build `src/` inputs from `serde_json::Value`.
// Lifted verbatim from the in-crate harnesses (src/v1.rs, src/digest.rs, etc.).
// ============================================================================

/// serde_json::Value → crate tagged JsonValue, preserving the integer-vs-float
/// tag (closure #5): a number serde_json stored as an i64 → Int, else Float.
fn serde_to_json(value: &serde_json::Value) -> JsonValue {
    match value {
        serde_json::Value::Null => JsonValue::Null,
        serde_json::Value::Bool(b) => JsonValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                JsonValue::Int(i)
            } else {
                JsonValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        serde_json::Value::String(s) => JsonValue::String(s.clone()),
        serde_json::Value::Array(arr) => JsonValue::Array(arr.iter().map(serde_to_json).collect()),
        serde_json::Value::Object(obj) => JsonValue::Object(
            obj.iter()
                .map(|(k, v)| (k.clone(), serde_to_json(v)))
                .collect(),
        ),
    }
}

/// Corpus selector shorthand: a bare string `"all"` expands to the full selector
/// object `{"kind":"all"}`; a full object passes through. (The producer's
/// `GrantOperation.selectors` takes full selector objects.)
fn corpus_selector_to_json(v: &serde_json::Value) -> JsonValue {
    match v {
        serde_json::Value::String(s) => {
            JsonValue::Object(vec![("kind".to_string(), JsonValue::String(s.clone()))])
        }
        _ => serde_to_json(v),
    }
}

/// Decodes a corpus base64url string field to a 32-byte array, or `None` if the
/// field is absent, not a string, undecodable, or NOT exactly 32 bytes. `None`
/// is the import-boundary reject (a wrong-width key never reaches a `[u8;32]`-
/// typed function).
fn b64url_to_32(field: &serde_json::Value) -> Option<[u8; 32]> {
    let b64 = field.as_str()?;
    let raw = bap::base64url_decode(b64.as_bytes()).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Some(arr)
}

/// Decodes a corpus base64url string field to a 64-byte array, or `None`.
fn b64url_to_64(field: &serde_json::Value) -> Option<[u8; 64]> {
    let b64 = field.as_str()?;
    let raw = bap::base64url_decode(b64.as_bytes()).ok()?;
    if raw.len() != 64 {
        return None;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&raw);
    Some(arr)
}

/// The closed lowercase `kind` set (`SigningKind::decode` is `pub(crate)`, so
/// the runner maps the public variants itself — the set is closed: an unknown
/// kind is `Invalid`).
fn kind_from_str(s: &str) -> Option<SigningKind> {
    Some(match s {
        "grant" => SigningKind::Grant,
        "proof" => SigningKind::Proof,
        "chain_anchor" => SigningKind::ChainAnchor,
        "key_transition" => SigningKind::KeyTransition,
        _ => return None,
    })
}

// ---- Historical-key / expected-context builders (Façade D harness) ---------

fn historical_key_from(v: &serde_json::Value) -> HistoricalPublicKey {
    let valid_before = match v["valid_before"].as_i64() {
        Some(n) => ValidityUpperBound::Bounded(n),
        None => ValidityUpperBound::Unbounded,
    };
    HistoricalPublicKey {
        key_id: v["key_id"].as_str().unwrap().to_string(),
        public_key: b64url_to_32(&v["public_key"]).expect("32-byte public key"),
        valid_from: v["valid_from"].as_i64().unwrap(),
        valid_before,
    }
}

fn expected_anchor_from(v: &serde_json::Value) -> ExpectedAnchor {
    ExpectedAnchor {
        anchor_id: v["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: v["anchored_at"].as_i64().unwrap(),
        chain_hash: b64url_to_32(&v["chain_hash"]).expect("32-byte chain_hash"),
        chain_id: v["chain_id"].as_str().unwrap().to_string(),
        key_fingerprint: b64url_to_32(&v["key_fingerprint"]).expect("32-byte fp"),
        key_id: v["key_id"].as_str().unwrap().to_string(),
        sequence: v["sequence"].as_i64().unwrap(),
        bounds: None,
    }
}

fn expected_transition_from(v: &serde_json::Value) -> ExpectedKeyTransition {
    ExpectedKeyTransition {
        chain_id: v["chain_id"].as_str().unwrap().to_string(),
        current_key_fingerprint: b64url_to_32(&v["current_key_fingerprint"]).expect("32"),
        current_key_id: v["current_key_id"].as_str().unwrap().to_string(),
        effective_at: v["effective_at"].as_i64().unwrap(),
        next_key_fingerprint: b64url_to_32(&v["next_key_fingerprint"]).expect("32"),
        next_key_id: v["next_key_id"].as_str().unwrap().to_string(),
        transition_id: v["transition_id"].as_str().unwrap().to_string(),
        bounds: None,
    }
}

fn expected_chain_from(v: &serde_json::Value) -> ExpectedChain {
    ExpectedChain {
        chain_id: v["chain_id"].as_str().unwrap().to_string(),
        first_sequence: v["first_sequence"].as_i64().unwrap(),
        last_sequence: v["last_sequence"].as_i64().unwrap(),
        row_count: v["row_count"].as_i64().unwrap(),
        previous_hash: b64url_to_32(&v["previous_hash"]).expect("32"),
        head_hash: b64url_to_32(&v["last_hash"]).expect("32"),
        bounds: None,
    }
}

fn expected_anchored_export_from(exp: &serde_json::Value) -> ExpectedAnchoredExport {
    ExpectedAnchoredExport {
        chain: expected_chain_from(&exp["chain"]),
        digest: b64url_to_32(&exp["digest"]).expect("32-byte digest"),
        start_anchor: expected_anchor_from(&exp["start_anchor"]),
        end_anchor: expected_anchor_from(&exp["end_anchor"]),
        transitions: exp["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(expected_transition_from)
            .collect(),
        object_version: exp["object_version"].as_str().unwrap().to_string(),
        bounds: None,
    }
}

/// Decodes the holder public key from a proof compact's protected-header JWK
/// (the key `check_envelope` feeds to Ed25519 verify internally). Used for the
/// census only. Returns `None` if the proof is not a decodable 3-segment compact
/// whose header carries a 32-byte `jwk.x`.
fn holder_key_from_proof_compact(proof: &[u8], census: &mut KeyCensus) {
    let Ok(text) = std::str::from_utf8(proof) else {
        return;
    };
    let mut parts = text.split('.');
    let (Some(header_seg), Some(_), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let Ok(header_bytes) = bap::base64url_decode(header_seg.as_bytes()) else {
        return;
    };
    // Decode the header JSON through the crate's duplicate-rejecting decoder.
    if let Ok(header) = bap::json_decode(&header_bytes, &max()) {
        if let Some(jwk_x) = header_object_get(&header, "jwk").and_then(|jwk| {
            header_object_get(jwk, "x").and_then(|x| match x {
                JsonValue::String(s) => Some(s.clone()),
                _ => None,
            })
        }) {
            if let Ok(raw) = bap::base64url_decode(jwk_x.as_bytes()) {
                if raw.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&raw);
                    census.observe(&arr);
                }
            }
        }
    }
}

/// Reads a single member of a `JsonValue::Object` by key (None for non-objects).
fn header_object_get<'a>(v: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, val)| val),
        _ => None,
    }
}

// ============================================================================
// Per-surface dispatch. Each fn returns `true` iff the crate verdict agrees with
// the corpus `expected.verdict` (and, for valid cases, the pinned value fields).
// Keys are recorded into `census` as they cross the `[u8;32]` boundary.
// ============================================================================

/// Resolve a case's input bytes for the json.decode surface (`text` / `base64url`
/// / `raw_file` sidecar shapes).
fn json_case_input_bytes(case: &serde_json::Value, root: &Path) -> Result<Vec<u8>, String> {
    let input = &case["input"];
    if let Some(text) = input["text"].as_str() {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(b64) = input["base64url"].as_str() {
        return bap::base64url_decode(b64.as_bytes()).map_err(|e| format!("b64: {e:?}"));
    }
    if let Some(raw) = input["raw_file"].as_str() {
        // `raw_file` is a repo-relative path under the corpus root.
        let p = root.join(raw);
        return fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()));
    }
    Err("no input shape".to_string())
}

fn d_base64url_decode(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = case["input"]["base64url"].as_str().unwrap();
    let result = bap::base64url_decode(input.as_bytes());
    match (expected_verdict, &result) {
        ("valid", Ok(got)) => {
            let want = case["expected"]["decoded"].as_str().unwrap();
            got.as_slice() == want.as_bytes()
        }
        ("invalid", Err(Invalid)) => true,
        _ => false,
    }
}

fn d_bounds_new(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let overrides = &case["input"]["overrides"];
    let overrides_bytes = serde_json::to_vec(overrides).unwrap();
    // Re-decode through the real tagged decoder so the `Bounds::new(Option<&JsonValue>)`
    // path is exercised end-to-end.
    let result = match bap::json_decode(&overrides_bytes, &max()) {
        Ok(value) => Bounds::new(Some(&value)),
        Err(Invalid) => Err(Invalid),
    };
    match expected_verdict {
        "valid" => result.is_ok(),
        "invalid" => result == Err(Invalid),
        _ => false,
    }
}

fn d_json_decode(case: &serde_json::Value, root: &Path, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let bytes = json_case_input_bytes(case, root).unwrap_or_else(|e| {
        panic!(
            "json case {} input: {e}",
            case["id"].as_str().unwrap_or("?")
        )
    });
    let actual_ok = bap::json_decode(&bytes, &max()).is_ok();
    let expected_ok = expected_verdict == "valid";
    actual_ok == expected_ok
}

fn d_jcs_encode(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let text = case["input"]["text"].as_str().unwrap();
    // JCS surface = decode-then-encode.
    match bap::json_decode(text.as_bytes(), &max()) {
        Err(Invalid) => expected_verdict == "invalid",
        Ok(value) => match bap::jcs_encode(&value, &max()) {
            Err(Invalid) => expected_verdict == "invalid",
            Ok(bytes) => match expected_verdict {
                "valid" => {
                    let want = case["expected"]["encoded"].as_str().unwrap();
                    bytes.as_slice() == want.as_bytes()
                }
                _ => false,
            },
        },
    }
}

fn d_uri_normalize(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = case["input"]["text"].as_str().unwrap();
    match bap::uri_normalize(input, &max()) {
        Ok(got) => match expected_verdict {
            "valid" => got == case["expected"]["normalized"].as_str().unwrap(),
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_request_digest(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let operation = case["input"]["operation"].as_str().unwrap();
    let cast_arguments = serde_to_json(&case["input"]["cast_arguments"]);
    match bap::request_digest(operation, &cast_arguments, &max()) {
        Ok(digest) => match expected_verdict {
            "valid" => {
                String::from_utf8(digest).unwrap() == case["expected"]["digest"].as_str().unwrap()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_assemble_compact(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let protected = case["input"]["protected_segment"]
        .as_str()
        .unwrap()
        .as_bytes();
    let payload = case["input"]["payload_segment"]
        .as_str()
        .unwrap()
        .as_bytes();
    let kind_str = case["input"]["kind"].as_str().unwrap();
    let sig_b64 = case["input"]["signature"].as_str().unwrap();
    // Import boundary: the raw signature must decode to exactly 64 bytes.
    let sig_decoded = bap::base64url_decode(sig_b64.as_bytes());
    let sig_is_64 = sig_decoded.as_ref().map(|r| r.len() == 64).unwrap_or(false);
    match (expected_verdict, sig_is_64) {
        ("valid", true) => {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_decoded.unwrap());
            let kind = kind_from_str(kind_str).expect("valid case has known kind");
            let input = SigningInput {
                kind,
                protected_segment: protected.to_vec(),
                payload_segment: payload.to_vec(),
            };
            match bap::assemble_compact(&input, &sig, None) {
                Ok(compact) => {
                    let want = case["expected"]["compact"].as_str().unwrap();
                    String::from_utf8(compact).unwrap() == want
                }
                Err(Invalid) => false,
            }
        }
        ("invalid", false) => true, // short-signature reject at the import boundary
        _ => false,
    }
}

fn d_untrusted_key_locator(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    match bap::untrusted_key_locator(compact, &max()) {
        Ok(loc) => match expected_verdict {
            "valid" => loc.key_id == case["expected"]["kid"].as_str().unwrap(),
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_decode_grant(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    match bap::decode_grant(compact, &max()) {
        Ok(d) => match expected_verdict {
            "valid" => d.key_id == case["expected"]["key_id"].as_str().unwrap(),
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_decode_proof(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    match bap::decode_proof(compact, &max()) {
        Ok(d) => match expected_verdict {
            "valid" => d.proof_id == case["expected"]["proof_id"].as_str().unwrap(),
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_grant_signing_input(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let grant = GrantInput {
        issuer: input["issuer"].as_str().unwrap_or("").to_string(),
        grant_id: input["grant_id"].as_str().unwrap_or("").to_string(),
        key_id: input["key_id"].as_str().unwrap_or("").to_string(),
        // holder_thumbprint is a [u8;32] DIGEST (cnf.jkt), not a key — not censused.
        holder_thumbprint: b64url_to_32(&input["holder_thumbprint"]).unwrap_or([0u8; 32]),
        issued_at: input["issued_at"].as_i64().unwrap_or(0),
        not_before: input["not_before"].as_i64().unwrap_or(0),
        expires_at: input["expires_at"].as_i64().unwrap_or(0),
        audiences: input["audiences"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default(),
        operations: input["operations"]
            .as_array()
            .map(|ops| {
                ops.iter()
                    .map(|op| GrantOperation {
                        name: op["name"].as_str().unwrap_or("").to_string(),
                        selectors: op["selectors"]
                            .as_array()
                            .map(|s| s.iter().map(corpus_selector_to_json).collect())
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    match bap::grant_signing_input(&grant, &max()) {
        Ok(produced) => match expected_verdict {
            "valid" => {
                let exp = &case["expected"];
                produced.protected_segment == exp["protected_segment"].as_str().unwrap().as_bytes()
                    && produced.payload_segment
                        == exp["payload_segment"].as_str().unwrap().as_bytes()
                    && produced.message == exp["message"].as_str().unwrap().as_bytes()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_proof_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let holder_public_key = b64url_to_32(&input["holder_public_key"]).unwrap_or([0u8; 32]);
    // Census the holder key iff it crossed the boundary as a real 32-byte key.
    if b64url_to_32(&input["holder_public_key"]).is_some() {
        census.observe(&holder_public_key);
    }
    let proof = ProofInput {
        proof_id: input["proof_id"].as_str().unwrap_or("").to_string(),
        method: input["method"].as_str().unwrap_or("").to_string(),
        target_uri: input["target_uri"].as_str().unwrap_or("").to_string(),
        invocation_id: input["invocation_id"].as_str().unwrap_or("").to_string(),
        operation: input["operation"].as_str().unwrap_or("").to_string(),
        cast_arguments: serde_to_json(&input["cast_arguments"]),
        grant_compact: input["grant_compact"]
            .as_str()
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        holder_public_key,
        issued_at: input["issued_at"].as_i64().unwrap_or(0),
    };
    match bap::proof_signing_input(&proof, &max()) {
        Ok(produced) => match expected_verdict {
            "valid" => {
                let exp = &case["expected"];
                produced.protected_segment == exp["protected_segment"].as_str().unwrap().as_bytes()
                    && produced.payload_segment
                        == exp["payload_segment"].as_str().unwrap().as_bytes()
                    && produced.message == exp["message"].as_str().unwrap().as_bytes()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_boundary_anchor_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let public_key_opt = b64url_to_32(&input["public_key"]);
    match (expected_verdict, public_key_opt) {
        ("valid", Some(pk)) => {
            census.observe(&pk);
            let anchor = BoundaryAnchor {
                anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
                anchored_at: input["anchored_at"].as_i64().unwrap(),
                chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
                chain_id: input["chain_id"].as_str().unwrap().to_string(),
                key_id: input["key_id"].as_str().unwrap().to_string(),
                public_key: pk,
                sequence: input["sequence"].as_i64().unwrap(),
            };
            match bap::boundary_anchor_signing_input(&anchor, &max()) {
                Ok(produced) => {
                    let exp = &case["expected"];
                    produced.protected_segment
                        == exp["protected_segment"].as_str().unwrap().as_bytes()
                        && produced.payload_segment
                            == exp["payload_segment"].as_str().unwrap().as_bytes()
                        && produced.message == exp["message"].as_str().unwrap().as_bytes()
                }
                Err(Invalid) => false,
            }
        }
        ("invalid", None) => true, // wrong-width key -> import-boundary reject
        ("invalid", Some(pk)) => {
            // The producer itself rejects (e.g. seq0 + nonzero chain_hash).
            census.observe(&pk);
            let anchor = BoundaryAnchor {
                anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
                anchored_at: input["anchored_at"].as_i64().unwrap(),
                chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
                chain_id: input["chain_id"].as_str().unwrap().to_string(),
                key_id: input["key_id"].as_str().unwrap().to_string(),
                public_key: pk,
                sequence: input["sequence"].as_i64().unwrap(),
            };
            bap::boundary_anchor_signing_input(&anchor, &max()) == Err(Invalid)
        }
        _ => false,
    }
}

fn d_key_transition_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let current_public_key = b64url_to_32(&input["current_public_key"]).expect("32 bytes");
    let next_public_key = b64url_to_32(&input["next_public_key"]).expect("32 bytes");
    census.observe(&current_public_key);
    census.observe(&next_public_key);
    let transition = KeyTransition {
        chain_id: input["chain_id"].as_str().unwrap().to_string(),
        current_key_id: input["current_key_id"].as_str().unwrap().to_string(),
        current_public_key,
        effective_at: input["effective_at"].as_i64().unwrap(),
        next_key_id: input["next_key_id"].as_str().unwrap().to_string(),
        next_public_key,
        transition_id: input["transition_id"].as_str().unwrap().to_string(),
    };
    match bap::key_transition_signing_input(&transition, &max()) {
        Ok(produced) => match expected_verdict {
            "valid" => {
                let exp = &case["expected"];
                produced.protected_segment == exp["protected_segment"].as_str().unwrap().as_bytes()
                    && produced.payload_segment
                        == exp["payload_segment"].as_str().unwrap().as_bytes()
                    && produced.message == exp["message"].as_str().unwrap().as_bytes()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_encode_consumption_entry(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let entry = ConsumptionEntry {
        chain_id: input["chain_id"].as_str().unwrap_or("").to_string(),
        commitment: b64url_to_32(&input["commitment"]).unwrap_or([0u8; 32]),
        previous_hash: b64url_to_32(&input["previous_hash"]).unwrap_or([0u8; 32]),
        sequence: input["sequence"].as_i64().unwrap_or(0),
    };
    match bap::encode_consumption_entry(&entry, &max()) {
        Ok((bytes, hash)) => match expected_verdict {
            "valid" => {
                let exp = &case["expected"];
                bytes.as_slice() == exp["bytes"].as_str().unwrap().as_bytes()
                    && bap::base64url_encode(&hash).as_slice()
                        == exp["hash"].as_str().unwrap().as_bytes()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_check_chain(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let rows: Vec<Vec<u8>> = input["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .map(|r| {
            bap::base64url_decode(r.as_str().expect("b64 row").as_bytes()).expect("row decodes")
        })
        .collect();
    let chain_input = ChainInput { rows };
    let expected = ExpectedChain {
        chain_id: input["chain_id"].as_str().unwrap_or("").to_string(),
        first_sequence: input["first_sequence"].as_i64().unwrap_or(0),
        last_sequence: input["last_sequence"].as_i64().unwrap_or(0),
        row_count: input["row_count"].as_i64().unwrap_or(0),
        previous_hash: b64url_to_32(&input["previous_hash"]).unwrap_or([0u8; 32]),
        head_hash: b64url_to_32(&input["last_hash"]).unwrap_or([0u8; 32]),
        bounds: None,
    };
    match bap::check_chain(&chain_input, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.chain_id == input["chain_id"].as_str().unwrap()
                    && facts.row_count == input["row_count"].as_i64().unwrap()
                    && facts.trust == NotEvaluated
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_verify_grant(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let public_key = b64url_to_32(&input["public_key"]).unwrap_or([0u8; 32]);
    if b64url_to_32(&input["public_key"]).is_some() {
        census.observe(&public_key);
    }
    let issuer = TrustedIssuer {
        key_id: input["key_id"].as_str().unwrap().to_string(),
        public_key,
    };
    let expected = ExpectedGrant {
        issuer: input["issuer"].as_str().unwrap().to_string(),
        audience: input["audience"].as_str().unwrap().to_string(),
        evaluation_time: input["evaluation_time"].as_i64().unwrap(),
        skew: input["clock_skew"].as_u64().unwrap(),
        bounds: max(),
    };
    let compact = input["compact"].as_str().unwrap().as_bytes();
    match bap::verify_grant(compact, &issuer, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.grant_id == case["expected"]["grant_id"].as_str().unwrap()
                    && facts.issuer == case["expected"]["issuer"].as_str().unwrap()
                    && facts.authorization == NotEvaluated
                    && facts.version == 1
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

/// Builds the (Credentials, ExpectedRequest) pair for one envelope case
/// (mirrors the Façade C harness `envelope_fixture_for`).
fn envelope_fixture(
    case: &serde_json::Value,
    census: &mut KeyCensus,
) -> (Credentials, ExpectedRequest) {
    let input = &case["input"];
    let exp = &input["expected"];
    let ti_pk = b64url_to_32(&exp["trusted_issuer"]["public_key"]).unwrap_or([0u8; 32]);
    if b64url_to_32(&exp["trusted_issuer"]["public_key"]).is_some() {
        census.observe(&ti_pk);
    }
    // Census the holder key embedded in the proof compact (fed to Ed25519 verify
    // internally by check_envelope).
    holder_key_from_proof_compact(input["proof"].as_str().unwrap().as_bytes(), census);
    let trusted = TrustedIssuer {
        key_id: exp["trusted_issuer"]["key_id"]
            .as_str()
            .unwrap()
            .to_string(),
        public_key: ti_pk,
    };
    let nonce_mode = match exp.get("nonce") {
        None => NonceMode::NotRequired,
        Some(n) => NonceMode::Required(n["required"].as_str().expect("nonce.required").to_string()),
    };
    let expected = ExpectedRequest {
        issuer: exp["issuer"].as_str().unwrap().to_string(),
        audience: exp["audience"].as_str().unwrap().to_string(),
        evaluation_time: exp["evaluation_time"].as_i64().unwrap(),
        skew: exp["clock_skew"].as_u64().unwrap(),
        bounds: max(),
        method: exp["method"].as_str().unwrap().to_string(),
        target_uri: exp["target_uri"].as_str().unwrap().to_string(),
        invocation_id: exp["invocation_id"].as_str().unwrap().to_string(),
        operation: exp["operation"].as_str().unwrap().to_string(),
        cast_arguments: serde_to_json(&exp["cast_arguments"]),
        proof_max_age: exp["proof_max_age"].as_u64().unwrap(),
        nonce_mode,
        trusted_issuer: trusted,
    };
    let credentials = Credentials {
        grant: input["grant"].as_str().unwrap().as_bytes().to_vec(),
        proof: input["proof"].as_str().unwrap().as_bytes().to_vec(),
    };
    (credentials, expected)
}

fn d_check_envelope(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let (creds, expected) = envelope_fixture(case, census);
    match bap::check_envelope(&creds, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.authorization == NotEvaluated
                    && facts.grant.authorization == NotEvaluated
                    && facts.grant.version == 1
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_verify_historical_anchor(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let key = historical_key_from(&input["key"]);
    census.observe(&key.public_key);
    let expected = expected_anchor_from(&input["expected"]);
    let compact = input["compact"].as_str().unwrap().as_bytes();
    match bap::verify_historical_anchor(compact, &key, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.anchor_id == expected.anchor_id
                    && facts.sequence == expected.sequence
                    && facts.chain_hash == expected.chain_hash
                    && facts.key_fingerprint == expected.key_fingerprint
                    && facts.trust == NotEvaluated
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_verify_key_transition(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let current = historical_key_from(&input["current_key"]);
    let next = historical_key_from(&input["next_key"]);
    census.observe(&current.public_key);
    census.observe(&next.public_key);
    let expected = expected_transition_from(&input["expected"]);
    let compact = input["compact"].as_str().unwrap().as_bytes();
    match bap::verify_key_transition(compact, &current, &next, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.transition_id == expected.transition_id
                    && facts.current_key_fingerprint == expected.current_key_fingerprint
                    && facts.next_key_fingerprint == expected.next_key_fingerprint
                    && facts.trust == NotEvaluated
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_encode_anchored_export(case: &serde_json::Value, _census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let anchored_input = AnchoredExportInput {
        start_anchor: input["start_anchor"].as_str().unwrap().as_bytes().to_vec(),
        end_anchor: input["end_anchor"].as_str().unwrap().as_bytes().to_vec(),
        transitions: input["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().as_bytes().to_vec())
            .collect(),
        rows: input["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| bap::base64url_decode(r.as_str().unwrap().as_bytes()).expect("row decodes"))
            .collect(),
    };
    let expected = ExpectedExport {
        chain: expected_chain_from(&input["expected"]["chain"]),
        digest: b64url_to_32(&input["expected"]["digest"]).unwrap_or([0u8; 32]),
        start_anchor: expected_anchor_from(&input["expected"]["start_anchor"]),
        end_anchor: expected_anchor_from(&input["expected"]["end_anchor"]),
        transitions: input["expected"]["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(expected_transition_from)
            .collect(),
        object_version: input["expected"]["object_version"]
            .as_str()
            .unwrap()
            .to_string(),
        bounds: None,
    };
    match bap::encode_anchored_export(&anchored_input, &expected) {
        Ok(encoded) => match expected_verdict {
            "valid" => {
                let exp = &case["expected"];
                encoded.byte_count == exp["byte_count"].as_i64().unwrap() as u64
                    && bap::base64url_encode(&encoded.digest).as_slice()
                        == exp["digest"].as_str().unwrap().as_bytes()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

fn d_verify_anchored_export(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    let input = &case["input"];
    let chunks: Vec<Vec<u8>> = input["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| bap::base64url_decode(c.as_str().unwrap().as_bytes()).unwrap_or_default())
        .collect();
    let obj = ArchivedObject {
        chunks,
        version: input["version"].as_str().unwrap().to_string(),
    };
    let keys = HistoricalKeyChain {
        keys: input["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                let hk = historical_key_from(k);
                census.observe(&hk.public_key);
                hk
            })
            .collect(),
    };
    let expected = expected_anchored_export_from(&input["expected"]);
    match bap::verify_anchored_export(&obj, &keys, &expected) {
        Ok(facts) => match expected_verdict {
            "valid" => {
                facts.trust == NotEvaluated
                    && facts.authorization == NotEvaluated
                    && facts.chain_id == input["expected"]["chain"]["chain_id"].as_str().unwrap()
                    && facts.row_count == input["expected"]["chain"]["row_count"].as_i64().unwrap()
            }
            _ => false,
        },
        Err(Invalid) => expected_verdict == "invalid",
    }
}

// ---- jwk.* (6 sub-surfaces, one file) --------------------------------------

fn d_jwk(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let surface = case["surface"].as_str().unwrap();
    let expected_verdict = case["expected"]["verdict"].as_str().unwrap();
    match surface {
        "jwk.encode_public" => {
            let key = b64url_to_32(&case["input"]["public_key"]);
            match (key, expected_verdict) {
                (Some(key), "valid") => {
                    census.observe(&key);
                    let encoded = bap::jwk_encode_public(&key);
                    String::from_utf8(encoded).unwrap()
                        == case["expected"]["encoded"].as_str().unwrap()
                }
                (None, "invalid") => true, // wrong-width key -> invalid_key
                _ => false,
            }
        }
        "jwk.decode_public" => {
            match bap::jwk_decode_public(case["input"]["text"].as_str().unwrap().as_bytes()) {
                Ok(key) => match expected_verdict {
                    "valid" => {
                        census.observe(&key);
                        String::from_utf8(bap::base64url_encode(&key)).unwrap()
                            == case["expected"]["public_key"].as_str().unwrap()
                    }
                    _ => false,
                },
                Err(Invalid) => expected_verdict == "invalid",
            }
        }
        "jwk.thumbprint" => {
            match bap::jwk_decode_public(case["input"]["text"].as_str().unwrap().as_bytes()) {
                Ok(key) => match expected_verdict {
                    "valid" => {
                        census.observe(&key);
                        String::from_utf8(bap::thumbprint(&key)).unwrap()
                            == case["expected"]["thumbprint"].as_str().unwrap()
                    }
                    _ => false,
                },
                Err(Invalid) => expected_verdict == "invalid",
            }
        }
        "jwk.thumbprint_preimage" => {
            match bap::jwk_decode_public(case["input"]["text"].as_str().unwrap().as_bytes()) {
                Ok(key) => match expected_verdict {
                    "valid" => {
                        census.observe(&key);
                        String::from_utf8(bap::thumbprint_preimage(&key)).unwrap()
                            == case["expected"]["preimage"].as_str().unwrap()
                    }
                    _ => false,
                },
                Err(Invalid) => expected_verdict == "invalid",
            }
        }
        "jwk.thumbprint_raw" => {
            match bap::jwk_decode_public(case["input"]["text"].as_str().unwrap().as_bytes()) {
                Ok(key) => match expected_verdict {
                    "valid" => {
                        census.observe(&key);
                        let _ = bap::thumbprint_raw(&key); // verdict-only pin
                        true
                    }
                    _ => false,
                },
                Err(Invalid) => expected_verdict == "invalid",
            }
        }
        "jwk.public_key_thumbprint_raw" => {
            let key = b64url_to_32(&case["input"]["public_key"]);
            match (key, expected_verdict) {
                (Some(key), "valid") => {
                    census.observe(&key);
                    let _ = bap::public_key_thumbprint_raw(&key); // verdict-only pin
                    true
                }
                (None, "invalid") => true,
                _ => false,
            }
        }
        other => panic!("unknown jwk surface: {other}"),
    }
}

// ============================================================================
// Dispatcher: route one case by its `surface` field.
// ============================================================================

fn dispatch(case: &serde_json::Value, root: &Path, census: &mut KeyCensus) -> bool {
    let surface = case["surface"].as_str().unwrap_or("<no surface>");
    match surface {
        "base64url.decode" => d_base64url_decode(case, census),
        "bounds.new" => d_bounds_new(case, census),
        "json.decode" => d_json_decode(case, root, census),
        "jcs.encode" => d_jcs_encode(case, census),
        "uri.normalize" => d_uri_normalize(case, census),
        "request_digest" => d_request_digest(case, census),
        "assemble_compact" => d_assemble_compact(case, census),
        "untrusted_key_locator" => d_untrusted_key_locator(case, census),
        "decode_grant" => d_decode_grant(case, census),
        "decode_proof" => d_decode_proof(case, census),
        "grant_signing_input" => d_grant_signing_input(case, census),
        "proof_signing_input" => d_proof_signing_input(case, census),
        "boundary_anchor_signing_input" => d_boundary_anchor_signing_input(case, census),
        "key_transition_signing_input" => d_key_transition_signing_input(case, census),
        "encode_consumption_entry" => d_encode_consumption_entry(case, census),
        "check_chain" => d_check_chain(case, census),
        "verify_grant" => d_verify_grant(case, census),
        "check_envelope" => d_check_envelope(case, census),
        "verify_historical_anchor" => d_verify_historical_anchor(case, census),
        "verify_key_transition" => d_verify_key_transition(case, census),
        "encode_anchored_export" => d_encode_anchored_export(case, census),
        "verify_anchored_export" => d_verify_anchored_export(case, census),
        "jwk.encode_public"
        | "jwk.decode_public"
        | "jwk.thumbprint"
        | "jwk.thumbprint_preimage"
        | "jwk.thumbprint_raw"
        | "jwk.public_key_thumbprint_raw" => d_jwk(case, census),
        other => panic!("unhandled surface: {other}"),
    }
}

// ============================================================================
// The acceptance gate.
// ============================================================================

#[test]
fn conformance_full_corpus() {
    let root = corpus_root();

    // (1) ADR 0014 §D4 — SHA-bind the vendored index.json.
    let index_bytes = fs::read(root.join("index.json")).expect("read vendored index.json");
    assert_certified_index_sha(&index_bytes);
    let index: serde_json::Value =
        serde_json::from_slice(&index_bytes).expect("index.json is valid JSON");

    let total_cases = index["total_cases"].as_u64().expect("total_cases") as usize;
    let declared_fps: BTreeSet<String> = index["public_key_fingerprints"]
        .as_array()
        .expect("public_key_fingerprints array")
        .iter()
        .map(|v| v.as_str().expect("fingerprint string").to_string())
        .collect();
    let applicability_keys: BTreeSet<String> = index["applicability"]
        .as_object()
        .expect("applicability object")
        .keys()
        .cloned()
        .collect();

    // (2) Load every case-bearing file named by the index `files` array, in the
    // index's declared order. Data-driven: no hardcoded surface→file map.
    let mut all_cases: Vec<serde_json::Value> = Vec::new();
    for entry in index["files"].as_array().expect("files array") {
        let path = entry["path"].as_str().expect("file path");
        let case_count = entry["cases"].as_u64().unwrap_or(0);
        if case_count == 0 {
            // The 5 `.raw` sidecars (raw byte inputs, not case containers).
            continue;
        }
        let content =
            fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("read {}: {e}", path));
        let file: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        let cases = file["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} cases array"));
        all_cases.extend(cases.iter().cloned());
    }

    assert_eq!(
        all_cases.len(),
        total_cases,
        "loaded cases ({}) == index total_cases ({})",
        all_cases.len(),
        total_cases,
    );

    // (3) Dispatch every case through the public surface; record observed keys.
    let mut census = KeyCensus::default();
    let mut agreed = 0usize;
    let mut disagreed = 0usize;
    let mut surfaces_seen: BTreeSet<String> = BTreeSet::new();
    for case in &all_cases {
        let surface = case["surface"]
            .as_str()
            .unwrap_or("<no surface>")
            .to_string();
        surfaces_seen.insert(surface.clone());
        let id = case["id"].as_str().unwrap_or("<no id>");
        let expected_verdict = case["expected"]["verdict"]
            .as_str()
            .unwrap_or("<no verdict>");
        let agree = dispatch(case, &root, &mut census);
        if agree {
            agreed += 1;
        } else {
            disagreed += 1;
            eprintln!("DISAGREE: surface={surface} id={id} expected={expected_verdict}");
        }
    }

    // (4) ADR 0014 §D9 — two-boundary key census (both directions).
    assert_census(&census.observed, &declared_fps);

    // (5) Every surface in the index applicability was exercised (skip-would-
    // accept guard): the runner dispatches the full matrix.
    assert_eq!(
        surfaces_seen, applicability_keys,
        "every applicability surface was exercised"
    );

    // (6) The acceptance bar.
    eprintln!(
        "conformance: agreed={agreed} disagreed={disagreed} total={total_cases} surfaces={} census={}/{}",
        surfaces_seen.len(),
        census.observed.len(),
        declared_fps.len(),
    );
    assert_eq!(agreed, total_cases, "agreed == total_cases (283)");
    assert_eq!(disagreed, 0, "disagreed == 0");
    assert_eq!(
        census.observed.len(),
        declared_fps.len(),
        "census cardinality"
    );
}

// ============================================================================
// RED-CAPABLE PROOFS — each test below proves a gate goes RED when its
// mechanism is removed/bypassed. (ADR 0005:240-246 discipline.)
// ============================================================================

/// RED-capable: if the SHA-bind compared against the WRONG certified hash (or
/// were a no-op), a tampered index would be silently accepted. This test goes
/// RED (panics from `assert_certified_index_sha`) when fed a byte-tampered index
/// — proving the bind is load-bearing.
#[test]
#[should_panic(expected = "index.json SHA mismatch")]
fn red_sha_binding_rejects_tampered_index() {
    let mut bytes = fs::read(corpus_root().join("index.json")).expect("read index.json");
    // Flip one byte that is inside the JSON payload (never the first byte if it
    // could be structural whitespace — flip a deep byte to guarantee content
    // change while keeping the test deterministic).
    bytes[100] ^= 0xFF;
    assert_certified_index_sha(&bytes);
}

/// RED-capable: the census rejects an EXTRA (fabricated) key observed at the
/// boundary but not declared in the index. Goes RED via `assert_census`.
#[test]
#[should_panic(expected = "census EXTRA")]
fn red_census_rejects_fabricated_key() {
    let declared: BTreeSet<String> = ["declared-a", "declared-b", "declared-c"]
        .into_iter()
        .map(String::from)
        .collect();
    let mut observed = declared.clone();
    observed.insert("FABRICATED-not-in-index".to_string());
    assert_census(&observed, &declared);
}

/// RED-capable: the census rejects a MISSING key (declared in the index but
/// never observed at the boundary). Goes RED via `assert_census`.
#[test]
#[should_panic(expected = "census MISSING")]
fn red_census_rejects_missing_declared_key() {
    let declared: BTreeSet<String> = ["declared-a", "declared-b", "declared-c"]
        .into_iter()
        .map(String::from)
        .collect();
    let mut observed = declared.clone();
    observed.remove("declared-a");
    assert_census(&observed, &declared);
}

/// RED-capable: `b64url_to_64` is unused by the dispatch today but documents the
/// import-boundary width check. Kept compiled; if it ever drifts it is caught.
#[test]
fn import_boundary_width_helpers_reject_wrong_widths() {
    // A 43-char base64url string is 32 bytes; a 4-char "AAEC" is 3 bytes — the
    // import boundary must reject it (the census must never see a 3-byte key).
    let short = serde_json::Value::String("AAEC".to_string());
    assert!(
        b64url_to_32(&short).is_none(),
        "3-byte key rejected at boundary"
    );
    assert!(
        b64url_to_64(&short).is_none(),
        "3-byte sig rejected at boundary"
    );
}
