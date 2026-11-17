//! The v3 conformance runner (contract-major 3 acceptance gate).
//!
//! The v3 twin of `conformance/run_v2.rs`, over the vendored 292-case
//! v3 corpus snapshot: an integration test living OUTSIDE `src/` so it can
//! call ONLY the crate's public surface. It:
//!
//! 1. **SHA-binds** the vendored v3 corpus snapshot: hashes
//!    `conformance/priv/conformance/v3/corpus/index.json` at startup and fails closed on
//!    mismatch with the certified v3 SHA.
//! 2. **Dispatches all 292 cases** across the same 28 surface names — the
//!    versioned façade functions through `bounded_authority_protocol::v3`
//!    (each executes v:3 payload validation, the `ES256` header pin, the EC
//!    JWK/point gates, and the BAP3 domain separators), the version-neutral
//!    primitives (`base64url`/`json`/`jcs`/`uri`/`bounds`) through the
//!    shared modules exactly as the v1/v2 runners do.
//! 3. **Runs the two-boundary key census** against the v3 index's 11 declared
//!    `public_key_fingerprints`, both directions. The v3 key boundary is the
//!    65-byte uncompressed SEC1 point (EC RFC 7638 thumbprints); the corpus's
//!    prior-major fixture keys (32-byte Ed25519 keys in the cross-major
//!    cases) are censused at their OKP-form RFC 7638 thumbprints —
//!    the identity those keys carry, and exactly what the curated index
//!    declares for them.
//! 4. Asserts `agreed == total_cases (292)` and `disagreed == 0`.
//!
//! Derivation hygiene mirrors the v1/v2 runners (ADR 0014 §D5): derived from
//! the v2 runner, spec/bap-v3.md, and the corpus alone. The corpus is the
//! falsifier.

#![forbid(unsafe_code)]

mod support;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use bounded_authority_protocol as bap;
use bounded_authority_protocol::facts::NotEvaluated;
use bounded_authority_protocol::types::*;
use bounded_authority_protocol::v3;
use bounded_authority_protocol::{Bounds, Invalid, JsonValue};
// `sha2` is a runtime dependency of the crate, re-used here for the SHA-bind
// and the wrong-width census arm.
use sha2::{Digest, Sha256};

// ============================================================================
// ADR 0014 §D4 — the certified corpus index SHA-256 (verified by hashing the
// source corpus index.json, then byte-copied into the SDK's vendored snapshot).
// ============================================================================

const CERTIFIED_INDEX_SHA: &str =
    "a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c";

/// The vendored v3 corpus root (self-contained SDK test corpus — ADR 0015 D5).
fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance/priv/conformance/v3/corpus")
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
// ADR 0014 §D9 — the two-boundary key census (v3: 65-byte EC boundary).
// ============================================================================

/// Collects the RFC 7638 thumbprints of every public key the runner imports
/// at the crate's crypto boundary. A v3 key is the 65-byte uncompressed SEC1
/// point and is thumbprinted through the crate's own v3 EC construction (the
/// crate is the thumbprint authority). The corpus's prior-major fixture keys
/// (32-byte Ed25519 keys, carried by the cross-major cases) are
/// wrong-width at the v3 boundary and never reach a crate verify function —
/// they are censused at their OKP-form thumbprint, the identity the curated
/// index declares for them.
#[derive(Default)]
struct KeyCensus {
    observed: BTreeSet<String>,
    actual: Option<serde_json::Value>,
}

impl KeyCensus {
    /// Records a 65-byte v3 public key by computing its EC RFC 7638
    /// thumbprint via the crate's own `v3::thumbprint`.
    fn observe(&mut self, public_key: &[u8; 65]) {
        let tp = v3::thumbprint(public_key).expect("65-byte EC key thumbprints");
        self.observed
            .insert(String::from_utf8(tp).expect("thumbprint is base64url ASCII"));
    }

    /// Records a key at its import ATTEMPT. A right-width (65-byte) key goes
    /// through [`KeyCensus::observe`]. A 32-byte key (a prior-major fixture
    /// key) is thumbprinted over the OKP-form RFC 7638 preimage assembled
    /// with the crate's own JCS encoder — the v2 corpus certified exactly
    /// this spelling for Ed25519 keys, and the v3 curated set declares the
    /// OKP thumbprints of its prior-major fixture keys. Any other wrong
    /// width contributes nothing (the curated set declares no identity for
    /// it).
    fn observe_attempted(&mut self, field: &serde_json::Value) {
        let Some(b64) = field.as_str() else { return };
        let Ok(raw) = bap::base64url_decode(b64.as_bytes()) else {
            return;
        };
        if raw.len() == 65 {
            let mut arr = [0u8; 65];
            arr.copy_from_slice(&raw);
            self.observe(&arr);
            return;
        }
        if raw.len() == 32 {
            let jwk = JsonValue::Object(vec![
                ("crv".to_string(), JsonValue::String("Ed25519".to_string())),
                ("kty".to_string(), JsonValue::String("OKP".to_string())),
                ("x".to_string(), JsonValue::String(b64.to_string())),
            ]);
            let Ok(preimage) = bap::jcs_encode(&jwk, &max()) else {
                return;
            };
            let digest = Sha256::digest(&preimage);
            self.observed.insert(
                String::from_utf8(bap::base64url_encode(&digest)).expect("base64url ASCII"),
            );
        }
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
// Lifted verbatim from the v2 runner (which lifted it from the in-crate
// harnesses).
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

/// Corpus selector shorthand: a bare string `"all"` expands to the full
/// selector object `{"kind":"all"}`; a full object passes through.
fn corpus_selector_to_json(v: &serde_json::Value) -> JsonValue {
    match v {
        serde_json::Value::String(s) => {
            JsonValue::Object(vec![("kind".to_string(), JsonValue::String(s.clone()))])
        }
        _ => serde_to_json(v),
    }
}

/// Decodes a corpus base64url string field to a 32-byte array, or `None` if
/// the field is absent, not a string, undecodable, or NOT exactly 32 bytes.
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

/// Decodes a corpus base64url string field to the v3 65-byte raw public key,
/// or `None` (the import-boundary reject: a wrong-width key — the corpus's
/// prior-major 32-byte fixture keys, a truncated 64-byte key, a compressed
/// 33-byte point, a 3-byte blob — never reaches a `[u8;65]`-typed function).
fn b64url_to_65(field: &serde_json::Value) -> Option<[u8; 65]> {
    let b64 = field.as_str()?;
    let raw = bap::base64url_decode(b64.as_bytes()).ok()?;
    if raw.len() != 65 {
        return None;
    }
    let mut arr = [0u8; 65];
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
        // Mapped so the corpus's closed-out loopback case REACHES the v3
        // façade (which rejects it — the v3 profile has no loopback typ);
        // leaving it unmapped would short-circuit at the runner instead.
        "local_loopback_http_proof" => SigningKind::LocalLoopbackHttpProof,
        _ => return None,
    })
}

// ---- Historical-key / expected-context builders (Façade D harness) ---------

fn historical_key_from(v: &serde_json::Value) -> Option<v3::HistoricalPublicKey> {
    let valid_before = match v["valid_before"].as_i64() {
        Some(n) => ValidityUpperBound::Bounded(n),
        None => ValidityUpperBound::Unbounded,
    };
    Some(v3::HistoricalPublicKey {
        key_id: v["key_id"].as_str()?.to_string(),
        public_key: b64url_to_65(&v["public_key"])?,
        valid_from: v["valid_from"].as_i64()?,
        valid_before,
    })
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
/// (the 65-byte EC key `check_envelope` feeds to ES256 verify internally).
/// Used for the census only. Returns `None` if the proof is not a decodable
/// 3-segment compact whose header carries BOTH a 32-byte `jwk.x` and a
/// 32-byte `jwk.y` (a prior-major OKP header has no `y` and yields nothing).
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
        let coords = header_object_get(&header, "jwk").and_then(|jwk| {
            let x = header_object_get(jwk, "x").and_then(|v| match v {
                JsonValue::String(s) => Some(s.clone()),
                _ => None,
            })?;
            let y = header_object_get(jwk, "y").and_then(|v| match v {
                JsonValue::String(s) => Some(s.clone()),
                _ => None,
            })?;
            Some((x, y))
        });
        if let Some((x_b64, y_b64)) = coords {
            let (Ok(x), Ok(y)) = (
                bap::base64url_decode(x_b64.as_bytes()),
                bap::base64url_decode(y_b64.as_bytes()),
            ) else {
                return;
            };
            if x.len() == 32 && y.len() == 32 {
                let mut arr = [0u8; 65];
                arr[0] = 0x04;
                arr[1..33].copy_from_slice(&x);
                arr[33..65].copy_from_slice(&y);
                census.observe(&arr);
            }
        }
    }
}

/// Reads a single member of a `JsonValue::Object` by key (None for
/// non-objects).
fn header_object_get<'a>(v: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, val)| val),
        _ => None,
    }
}

// ============================================================================
// Per-surface dispatch. Each fn returns `true` iff the crate verdict agrees
// with the corpus `expected.verdict` (and, for valid cases, the pinned value
// fields). Keys are recorded into `census` as they cross the `[u8;65]`
// boundary.
// ============================================================================

/// Resolve a case's input bytes for the json.decode surface (`text` /
/// `base64url` / `raw_file` sidecar shapes).
fn json_case_input_bytes(case: &serde_json::Value, root: &Path) -> Result<Vec<u8>, String> {
    let input = &case["input"];
    if let Some(text) = input["text"].as_str() {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(b64) = input["base64url"].as_str() {
        return bap::base64url_decode(b64.as_bytes()).map_err(|e| format!("b64: {e:?}"));
    }
    if let Some(raw) = input["raw_file"].as_str() {
        // `raw_file` is a corpus-root-relative path.
        let p = root.join(raw);
        return fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()));
    }
    Err("no input shape".to_string())
}

fn d_base64url_decode(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = case["input"]["base64url"].as_str().unwrap();
    let result = bap::base64url_decode(input.as_bytes());
    save(
        case,
        census,
        result.map(|got| json!({"decoded": String::from_utf8(got).unwrap()})),
    )
}

fn d_bounds_new(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let overrides = &case["input"]["overrides"];
    let overrides_bytes = serde_json::to_vec(overrides).unwrap();
    // Re-decode through the real tagged decoder so the `Bounds::new(Option<&JsonValue>)`
    // path is exercised end-to-end.
    let result = match bap::json_decode(&overrides_bytes, &max()) {
        Ok(value) => Bounds::new(Some(&value)),
        Err(Invalid) => Err(Invalid),
    };
    save(case, census, result.map(|b| {
        let all = json!({"compact_bytes": b.compact_bytes(),"encoded_segment_bytes": b.encoded_segment_bytes(),"decoded_segment_bytes": b.decoded_segment_bytes(),"json_bytes": b.json_bytes(),"depth": b.depth(),"object_members": b.object_members(),"array_items": b.array_items(),"total_nodes": b.total_nodes(),"string_bytes": b.string_bytes(),"key_bytes": b.key_bytes(),"number_lexeme_bytes": b.number_lexeme_bytes(),"integer_magnitude": b.integer_magnitude(),"float_magnitude": b.float_magnitude(),"kid_bytes": b.kid_bytes(),"jcs_bytes": b.jcs_bytes(),"uri_bytes": b.uri_bytes(),"identifier_bytes": b.identifier_bytes(),"nonce_bytes": b.nonce_bytes(),"method_bytes": b.method_bytes(),"operation_bytes": b.operation_bytes(),"audiences": b.audiences(),"operations": b.operations(),"selectors": b.selectors(),"path_segments": b.path_segments(),"one_of_values": b.one_of_values(),"clock_skew": b.clock_skew(),"proof_max_age": b.proof_max_age(),"chain_row_bytes": b.chain_row_bytes(),"chain_rows": b.chain_rows(),"anchor_bytes": b.anchor_bytes(),"archive_header_bytes": b.archive_header_bytes(),"key_transitions": b.key_transitions(),"archive_chunks": b.archive_chunks(),"archive_bytes": b.archive_bytes(),"object_version_bytes": b.object_version_bytes(),"content_bytes": b.content_bytes()});
        let projected: serde_json::Map<String,serde_json::Value> = overrides.as_object().unwrap().keys().map(|k|(k.clone(),all[k].clone())).collect();
        json!({"bounds": projected})
    }))
}

fn d_json_decode(case: &serde_json::Value, root: &Path, census: &mut KeyCensus) -> bool {
    let bytes = json_case_input_bytes(case, root).unwrap_or_else(|e| {
        panic!(
            "json case {} input: {e}",
            case["id"].as_str().unwrap_or("?")
        )
    });
    save(
        case,
        census,
        bap::json_decode(&bytes, &max()).map(|value| json!({"value": json_value(&value)})),
    )
}

fn d_jcs_encode(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let text = case["input"]["text"].as_str().unwrap();
    // JCS surface = decode-then-encode.
    let result =
        bap::json_decode(text.as_bytes(), &max()).and_then(|v| bap::jcs_encode(&v, &max()));
    save(
        case,
        census,
        result.map(|bytes| json!({"encoded":String::from_utf8(bytes).unwrap()})),
    )
}

fn d_uri_normalize(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = case["input"]["text"].as_str().unwrap();
    let result = bap::uri_normalize(input, &max());
    save(case, census, result.map(|got| json!({"normalized":got})))
}

fn d_request_digest(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let operation = case["input"]["operation"].as_str().unwrap();
    let cast_arguments = serde_to_json(&case["input"]["cast_arguments"]);
    let result = v3::request_digest(operation, &cast_arguments, &max());
    save(
        case,
        census,
        result.map(|digest| json!({"digest":String::from_utf8(digest).unwrap()})),
    )
}

fn d_assemble_compact(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    let result = (|| {
        let sig = b64url_to_64(&input["signature"]).ok_or(Invalid)?;
        let kind = kind_from_str(input["kind"].as_str().unwrap()).ok_or(Invalid)?;
        let signing = SigningInput {
            kind,
            protected_segment: input["protected_segment"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            payload_segment: input["payload_segment"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        v3::assemble_compact(&signing, &sig, None)
    })();
    save(
        case,
        census,
        result.map(|compact| json!({"compact":String::from_utf8(compact).unwrap()})),
    )
}

fn d_untrusted_key_locator(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    let result = v3::untrusted_key_locator(compact, &max());
    save(case, census, result.map(|loc| json!({"kid":loc.key_id})))
}

fn d_decode_grant(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    let result = v3::decode_grant(compact, &max());
    save(case, census, result.map(|loc| json!({"key_id":loc.key_id})))
}

fn d_decode_proof(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let compact = case["input"]["compact"].as_str().unwrap().as_bytes();
    let result = v3::decode_proof(compact, &max());
    save(
        case,
        census,
        result.map(|loc| json!({"proof_id":loc.proof_id})),
    )
}

fn d_grant_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    let grant = GrantInput {
        issuer: input["issuer"].as_str().unwrap_or("").to_string(),
        grant_id: input["grant_id"].as_str().unwrap_or("").to_string(),
        key_id: input["key_id"].as_str().unwrap_or("").to_string(),
        // holder_thumbprint is a [u8;32] DIGEST (cnf.jkt), not a key — not
        // censused.
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
    let result = v3::grant_signing_input(&grant, &max());
    save(
        case,
        census,
        result.map(|produced| {
            signing_value(
                &produced.protected_segment,
                &produced.payload_segment,
                &produced.message,
            )
        }),
    )
}

fn d_proof_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    census.observe_attempted(&input["holder_public_key"]);
    let Some(holder_public_key) = b64url_to_65(&input["holder_public_key"]) else {
        return save(case, census, Err(Invalid));
    };
    census.observe(&holder_public_key);
    let proof = v3::ProofInput {
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
    let result = v3::proof_signing_input(&proof, &max());
    save(
        case,
        census,
        result.map(|p| signing_value(&p.protected_segment, &p.payload_segment, &p.message)),
    )
}

fn d_boundary_anchor_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    census.observe_attempted(&input["public_key"]);
    let Some(pk) = b64url_to_65(&input["public_key"]) else {
        return save(case, census, Err(Invalid));
    };
    census.observe(&pk);
    let anchor = v3::BoundaryAnchor {
        anchor_id: input["anchor_id"].as_str().unwrap().to_string(),
        anchored_at: input["anchored_at"].as_i64().unwrap(),
        chain_hash: b64url_to_32(&input["chain_hash"]).expect("32 bytes"),
        chain_id: input["chain_id"].as_str().unwrap().to_string(),
        key_id: input["key_id"].as_str().unwrap().to_string(),
        public_key: pk,
        sequence: input["sequence"].as_i64().unwrap(),
    };
    let result = v3::boundary_anchor_signing_input(&anchor, &max());
    save(
        case,
        census,
        result.map(|p| signing_value(&p.protected_segment, &p.payload_segment, &p.message)),
    )
}

fn d_key_transition_signing_input(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    census.observe_attempted(&input["current_public_key"]);
    let Some(current_public_key) = b64url_to_65(&input["current_public_key"]) else {
        return save(case, census, Err(Invalid));
    };
    census.observe(&current_public_key);
    census.observe_attempted(&input["next_public_key"]);
    let Some(next_public_key) = b64url_to_65(&input["next_public_key"]) else {
        return save(case, census, Err(Invalid));
    };
    census.observe(&next_public_key);
    let transition = v3::KeyTransition {
        chain_id: input["chain_id"].as_str().unwrap().to_string(),
        current_key_id: input["current_key_id"].as_str().unwrap().to_string(),
        current_public_key,
        effective_at: input["effective_at"].as_i64().unwrap(),
        next_key_id: input["next_key_id"].as_str().unwrap().to_string(),
        next_public_key,
        transition_id: input["transition_id"].as_str().unwrap().to_string(),
    };
    let result = v3::key_transition_signing_input(&transition, &max());
    save(
        case,
        census,
        result.map(|p| signing_value(&p.protected_segment, &p.payload_segment, &p.message)),
    )
}

fn d_encode_consumption_entry(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    let entry = ConsumptionEntry {
        chain_id: input["chain_id"].as_str().unwrap_or("").to_string(),
        commitment: b64url_to_32(&input["commitment"]).unwrap_or([0u8; 32]),
        previous_hash: b64url_to_32(&input["previous_hash"]).unwrap_or([0u8; 32]),
        sequence: input["sequence"].as_i64().unwrap_or(0),
    };
    let result = v3::encode_consumption_entry(&entry, &max());
    save(case, census, result.map(|(bytes,hash)| json!({"bytes":String::from_utf8(bap::base64url_encode(&bytes)).unwrap(),"hash":String::from_utf8(bap::base64url_encode(&hash)).unwrap()})))
}

fn d_check_chain(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
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
    let result = v3::check_chain(&chain_input, &expected);
    save(
        case,
        census,
        result.map(|facts| json!({"chain_id":facts.chain_id})),
    )
}

fn d_verify_grant(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    // Census the key at its import attempt (the cross-major v1 case carries
    // a prior-major 32-byte key, observed via its OKP thumbprint).
    census.observe_attempted(&input["public_key"]);
    let Some(public_key) = b64url_to_65(&input["public_key"]) else {
        return save(case, census, Err(Invalid)); // import-boundary reject
    };
    let issuer = v3::TrustedIssuer {
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
    let result = v3::verify_grant(compact, &issuer, &expected);
    save(
        case,
        census,
        result.map(|facts| json!({"grant_id":facts.grant_id,"issuer":facts.issuer})),
    )
}

/// Builds the (Credentials, ExpectedRequest) pair for one envelope case.
fn envelope_fixture(
    case: &serde_json::Value,
    census: &mut KeyCensus,
) -> Option<(Credentials, v3::ExpectedRequest)> {
    let input = &case["input"];
    let exp = &input["expected"];
    // Census the trusted-issuer key at its import attempt; the fixture key
    // must cross as a 65-byte EC point (the cross-major cases carry
    // prior-major 32-byte keys).
    census.observe_attempted(&exp["trusted_issuer"]["public_key"]);
    let ti_pk = b64url_to_65(&exp["trusted_issuer"]["public_key"])?;
    // Census the holder key embedded in the proof compact (fed to ES256
    // verify internally by check_envelope).
    holder_key_from_proof_compact(input["proof"].as_str().unwrap().as_bytes(), census);
    let trusted = v3::TrustedIssuer {
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
    let expected = v3::ExpectedRequest {
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
    Some((credentials, expected))
}

fn d_check_envelope(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let result = envelope_fixture(case, census)
        .ok_or(Invalid)
        .and_then(|(creds, expected)| v3::check_envelope(&creds, &expected));
    save(
        case,
        census,
        result.map(|facts| {
            assert_eq!(facts.authorization, NotEvaluated);
            json!({})
        }),
    )
}

fn d_verify_historical_anchor(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    census.observe_attempted(&input["key"]["public_key"]);
    let Some(key) = historical_key_from(&input["key"]) else {
        return save(case, census, Err(Invalid)); // import-boundary reject
    };
    let expected = expected_anchor_from(&input["expected"]);
    let compact = input["compact"].as_str().unwrap().as_bytes();
    let result = v3::verify_historical_anchor(compact, &key, &expected);
    save(
        case,
        census,
        result.map(|facts| json!({"anchor_id":facts.anchor_id})),
    )
}

fn d_verify_key_transition(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let input = &case["input"];
    census.observe_attempted(&input["current_key"]["public_key"]);
    census.observe_attempted(&input["next_key"]["public_key"]);
    let (Some(current), Some(next)) = (
        historical_key_from(&input["current_key"]),
        historical_key_from(&input["next_key"]),
    ) else {
        return save(case, census, Err(Invalid)); // import-boundary reject
    };
    let expected = expected_transition_from(&input["expected"]);
    let compact = input["compact"].as_str().unwrap().as_bytes();
    let result = v3::verify_key_transition(compact, &current, &next, &expected);
    save(
        case,
        census,
        result.map(|facts| json!({"transition_id":facts.transition_id})),
    )
}

fn d_encode_anchored_export(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
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
        // The encode cases omit object_version (the producer never consults
        // it) — default when absent.
        object_version: input["expected"]["object_version"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        bounds: None,
    };
    let result = v3::encode_anchored_export(&anchored_input, &expected);
    save(case, census, result.map(|facts| json!({"byte_count":facts.byte_count,"digest":String::from_utf8(bap::base64url_encode(&facts.digest)).unwrap()})))
}

fn d_verify_anchored_export(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
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
    // Census every key at its import attempt; a wrong-width key (the
    // cross-major v1 case) is an import-boundary reject.
    let mut keys: Vec<v3::HistoricalPublicKey> = Vec::new();
    let mut all_imported = true;
    for k in input["keys"].as_array().unwrap() {
        census.observe_attempted(&k["public_key"]);
        match historical_key_from(k) {
            Some(hk) => keys.push(hk),
            None => all_imported = false,
        }
    }
    if !all_imported {
        return save(case, census, Err(Invalid));
    }
    let key_chain = v3::HistoricalKeyChain { keys };
    let expected = expected_anchored_export_from(&input["expected"]);
    let result = v3::verify_anchored_export(&obj, &key_chain, &expected);
    save(
        case,
        census,
        result.map(|facts| json!({"chain_id":facts.chain_id})),
    )
}

// ---- jwk.* (6 sub-surfaces, one file — the v3 EC forms) --------------------

fn d_jwk(case: &serde_json::Value, census: &mut KeyCensus) -> bool {
    let surface = case["surface"].as_str().unwrap();
    let input = &case["input"];
    let result = (|| {
        let key = if surface == "jwk.encode_public" || surface == "jwk.public_key_thumbprint_raw" {
            census.observe_attempted(&input["public_key"]);
            b64url_to_65(&input["public_key"]).ok_or(Invalid)?
        } else {
            v3::jwk_decode_public(input["text"].as_str().unwrap().as_bytes())?
        };
        census.observe(&key);
        Ok(match surface {
            "jwk.encode_public" => {
                json!({"encoded":String::from_utf8(v3::jwk_encode_public(&key)?).unwrap()})
            }
            "jwk.decode_public" => {
                json!({"public_key":String::from_utf8(bap::base64url_encode(&key)).unwrap()})
            }
            "jwk.thumbprint" => {
                json!({"thumbprint":String::from_utf8(v3::thumbprint(&key)?).unwrap()})
            }
            "jwk.thumbprint_preimage" => {
                json!({"preimage":String::from_utf8(v3::thumbprint_preimage(&key)?).unwrap()})
            }
            "jwk.thumbprint_raw" => {
                json!({"thumbprint_raw":String::from_utf8(bap::base64url_encode(&v3::thumbprint_raw(&key)?)).unwrap()})
            }
            "jwk.public_key_thumbprint_raw" => {
                json!({"thumbprint_raw":String::from_utf8(bap::base64url_encode(&v3::public_key_thumbprint_raw(&key)?)).unwrap()})
            }
            _ => panic!("unknown JWK surface"),
        })
    })();
    save(case, census, result)
}

// ============================================================================
// Dispatcher: route one case by its `surface` field.
// ============================================================================

fn save(
    case: &serde_json::Value,
    census: &mut KeyCensus,
    result: Result<serde_json::Value, Invalid>,
) -> bool {
    let actual = match result {
        Ok(mut value) => {
            value
                .as_object_mut()
                .unwrap()
                .insert("verdict".into(), json!("valid"));
            value
        }
        Err(Invalid) => json!({"verdict":"invalid"}),
    };
    let keys = case["expected"].as_object().unwrap();
    let projected = serde_json::Value::Object(
        keys.keys()
            .filter_map(|k| actual.get(k).map(|v| (k.clone(), v.clone())))
            .collect(),
    );
    let agrees = projected == case["expected"];
    census.actual = Some(projected);
    agrees
}
fn signing_value(protected: &[u8], payload: &[u8], message: &[u8]) -> serde_json::Value {
    json!({"protected_segment":std::str::from_utf8(protected).unwrap(),"payload_segment":std::str::from_utf8(payload).unwrap(),"message":std::str::from_utf8(message).unwrap()})
}
fn json_value(value: &JsonValue) -> serde_json::Value {
    match value {
        JsonValue::Null => serde_json::Value::Null,
        JsonValue::Bool(b) => json!(b),
        JsonValue::Int(n) => json!(n),
        JsonValue::Float(n) => json!(n),
        JsonValue::String(s) => json!(s),
        JsonValue::Array(a) => json!(a.iter().map(json_value).collect::<Vec<_>>()),
        JsonValue::Object(o) => {
            serde_json::Value::Object(o.iter().map(|(k, v)| (k.clone(), json_value(v))).collect())
        }
    }
}

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
    let mut execution = support::Run::new(&root, CERTIFIED_INDEX_SHA);

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

    // (2) Load every case-bearing file named by the index `files` array, in
    // the index's declared order. Data-driven: no hardcoded surface→file map.
    let mut all_cases: Vec<serde_json::Value> = Vec::new();
    for entry in index["files"].as_array().expect("files array") {
        let path = entry["path"].as_str().expect("file path");
        let case_count = entry["cases"].as_u64().unwrap_or(0);
        // The revision sidecar occupies the one reserved non-case JSON path. It
        // has no agreement backstop, so its SHA-256 is verified against the
        // index entry here and its member set is closed (exactly
        // format/revision/generated_from).
        if path == "revision.json" {
            let bytes = fs::read(root.join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let digest = Sha256::digest(&bytes);
            let want = entry["sha256_base64url"]
                .as_str()
                .expect("revision.json index hash");
            assert!(
                bap::base64url_encode(&digest).as_slice() == want.as_bytes(),
                "revision.json SHA-256 mismatch"
            );
            let sidecar: serde_json::Value =
                serde_json::from_slice(&bytes).expect("revision.json is valid JSON");
            let members = sidecar.as_object().expect("revision.json object");
            assert!(
                members.len() == 3
                    && members.contains_key("format")
                    && members.contains_key("revision")
                    && members.contains_key("generated_from"),
                "revision.json: closed member set"
            );
            assert_eq!(
                members["format"].as_str(),
                Some("bounded-authority-protocol-v3-conformance-corpus-revision"),
                "revision.json: format const"
            );
            assert!(
                members["revision"].as_u64().is_some_and(|r| r >= 1),
                "revision.json: monotone integer revision"
            );
            let source_len = members["generated_from"].as_str().map_or(0, str::len);
            assert!(
                (1..=256).contains(&source_len),
                "revision.json: generated_from provenance string"
            );
            assert_eq!(case_count, 0, "revision.json: case-free declaration");
            continue;
        }
        if case_count == 0 {
            // The 5 `.raw` sidecars (raw byte inputs, not case containers).
            continue;
        }
        let content =
            fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let file: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        let cases = file["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} cases array"));
        all_cases.extend(cases.iter().cloned().map(|mut c| {
            c["_file"] = json!(path);
            c
        }));
    }

    assert_eq!(
        all_cases.len(),
        total_cases,
        "loaded cases ({}) == index total_cases ({})",
        all_cases.len(),
        total_cases,
    );

    // (3) Dispatch every case through the public surface; record observed
    // keys.
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
        census.actual = None;
        let agree = dispatch(case, &root, &mut census);
        execution.record(
            id,
            case["_file"].as_str().unwrap(),
            census.actual.take().expect("missing computed outcome"),
        );
        if agree {
            agreed += 1;
        } else {
            disagreed += 1;
            eprintln!("DISAGREE: surface={surface} id={id} expected={expected_verdict}");
        }
    }

    execution.finish();

    // (4) ADR 0014 §D9 — two-boundary key census (both directions).
    assert_census(&census.observed, &declared_fps);

    // (5) Every surface in the index applicability was exercised
    // (skip-would-accept guard): the runner dispatches the full matrix.
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
    assert_eq!(agreed, total_cases, "agreed == total_cases (292)");
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
/// RED (panics from `assert_certified_index_sha`) when fed a byte-tampered
/// index — proving the bind is load-bearing.
#[test]
#[should_panic(expected = "index.json SHA mismatch")]
fn red_sha_binding_rejects_tampered_index() {
    let mut bytes = fs::read(corpus_root().join("index.json")).expect("read index.json");
    // Flip one byte that is inside the JSON payload (never the first byte if
    // it could be structural whitespace — flip a deep byte to guarantee
    // content change while keeping the test deterministic).
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

/// RED-capable: the import-boundary width helpers reject every wrong width —
/// a 3-byte blob at the 65-byte key boundary and at the 64-byte signature
/// boundary. The v3 census must never see a wrong-width key.
#[test]
fn import_boundary_width_helpers_reject_wrong_widths() {
    let short = serde_json::Value::String("AAEC".to_string());
    assert!(
        b64url_to_65(&short).is_none(),
        "3-byte key rejected at the 65-byte boundary"
    );
    assert!(
        b64url_to_64(&short).is_none(),
        "3-byte sig rejected at the 64-byte boundary"
    );
    // The corpus's prior-major fixture width (32 bytes) is equally rejected
    // at the v3 boundary.
    let prior_major_key =
        serde_json::Value::String("Jaq9eAorTEfcCDHUAP5STwcHHgJUDlxAVNypHEP7VwQ".to_string());
    assert!(
        b64url_to_65(&prior_major_key).is_none(),
        "32-byte prior-major key rejected at the 65-byte boundary"
    );
}
