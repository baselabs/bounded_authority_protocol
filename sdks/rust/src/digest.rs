//! Request digest — the auth-binding primitive (`BAP1-Ed25519-SHA256`).
//!
//! The request digest binds a specific operation + cast-arguments pair to the
//! proof's `ba_req` claim. A wrong digest → wrong `ba_req` → silent
//! request-binding bypass. The formula (`docs/protocol-v1.md` § Signing and
//! digest inputs, lines 263–289):
//!
//! ```text
//! base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
//! ```
//!
//! `typed/1` projects the tagged JSON algebra to a closed tagged JSON form
//! (wrapping each scalar in its explicit `["<kind>", value]` tag array and
//! recursing into arrays/objects) BEFORE JCS. The explicit scalar tags preserve
//! the integer-vs-integral-float distinction (permissiveness closure #5
//! end-to-end): `Int(1)` projects to `["integer",1]`, `Float(1.0)` to
//! `["float",1]` — distinct JCS bytes even though RFC 8785 would emit both
//! payloads as the bare number `1`.
//!
//! `operation` is the RAW operation string (the first signing-array element),
//! NOT `typed`-wrapped — only `cast_arguments` goes through `typed`.
//!
//! Per `protocol-v1.md` §lines 329–330, request-digest's typed projection is an
//! internal mechanic behind the v1 façade; this module is `pub(crate)` and
//! [`request_digest`] is re-exported through the façade at Task 12.

// `request_digest` is `pub(crate)` and is now wired by v1::proof_signing_input
// (Façade A); `typed` / `tag1` / `tag2` / `validate_bounds` are all reachable
// through that call chain. check_envelope (T12) will add a second caller.
use crate::base64url::base64url_encode;
use crate::bounds::Bounds;
use crate::error::{Invalid, Result};
use crate::jcs::jcs_encode;
use crate::json::JsonValue;
use sha2::{Digest, Sha256};

/// The ASCII domain-separation prefix for the request digest, including its
/// FINAL NUL byte (`REQ1-SIGNING-digest-prefix`).
///
/// `"BAP1-REQUEST\0"` = `[B, A, P, 1, -, R, E, Q, U, E, S, T, 0x00]` (13 bytes).
const REQUEST_DIGEST_PREFIX: &[u8] = b"BAP1-REQUEST\0";

/// Compute the v1 request digest.
///
/// Returns `base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation,
/// typed(cast_arguments)])))`, or `Err(Invalid)` if `operation` exceeds
/// `bounds.operation_bytes()`, the projected structure violates any structural
/// bound (depth / total-nodes / object-members / array-items / string /
/// object-name ceilings), the structure contains a non-finite float, or the JCS
/// encoding exceeds `bounds.jcs_bytes()`.
pub(crate) fn request_digest(
    operation: &str,
    cast_arguments: &JsonValue,
    bounds: &Bounds,
) -> Result<Vec<u8>> {
    // REQ1-BOUNDS-ordering: the raw operation byte ceiling precedes projection.
    if operation.len() as u64 > bounds.operation_bytes() {
        return Err(Invalid);
    }

    // typed/1 projects cast_arguments; operation stays raw (the first element).
    let projected = typed(cast_arguments)?;
    let signing_array = JsonValue::Array(vec![JsonValue::String(operation.to_string()), projected]);

    // Enforce structural bounds on the projected structure (the `(d)`-class
    // per-node budget; the JCS encoder itself enforces only jcs_bytes today).
    validate_bounds(&signing_array, 1, bounds, &mut 0)?;

    // JCS-encode the signing array (enforces jcs_bytes + rejects non-finite
    // floats a second time at the formatting site).
    let jcs_bytes = jcs_encode(&signing_array, bounds)?;

    // SHA-256 over the exact prefix || JCS preimage.
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_PREFIX);
    hasher.update(&jcs_bytes);
    let output = hasher.finalize();

    Ok(base64url_encode(&output))
}

/// Projects a tagged [`JsonValue`] to the closed typed JSON form per
/// `protocol-v1.md` §lines 271–281.
///
/// `Null` → `["null"]` (a 1-element tag array); every other variant → a
/// 2-element `["<kind>", value]` tag array, recursing into arrays/objects so
/// every nested value is itself projected. The explicit scalar tags carry the
/// integer-vs-float distinction into the JCS preimage (closure #5).
fn typed(value: &JsonValue) -> Result<JsonValue> {
    Ok(match value {
        JsonValue::Null => tag1("null"),
        JsonValue::Bool(b) => tag2("boolean", JsonValue::Bool(*b)),
        JsonValue::Int(n) => tag2("integer", JsonValue::Int(*n)),
        JsonValue::Float(f) => {
            // Fail closed on non-finite floats before they reach JCS (the JCS
            // encoder rejects them too, but typed() is the projection site).
            if !f.is_finite() {
                return Err(Invalid);
            }
            tag2("float", JsonValue::Float(*f))
        }
        JsonValue::String(s) => tag2("string", JsonValue::String(s.clone())),
        JsonValue::Array(items) => {
            let mut projected = Vec::with_capacity(items.len());
            for item in items {
                projected.push(typed(item)?);
            }
            tag2("array", JsonValue::Array(projected))
        }
        JsonValue::Object(members) => {
            let mut projected = Vec::with_capacity(members.len());
            for (k, v) in members {
                projected.push((k.clone(), typed(v)?));
            }
            tag2("object", JsonValue::Object(projected))
        }
    })
}

/// Wraps a tag string in a 1-element array (the `:null` projection).
fn tag1(tag: &str) -> JsonValue {
    JsonValue::Array(vec![JsonValue::String(tag.to_string())])
}

/// Wraps a tag string + value in a 2-element array (every non-null projection).
fn tag2(tag: &str, value: JsonValue) -> JsonValue {
    JsonValue::Array(vec![JsonValue::String(tag.to_string()), value])
}

/// Walks `value` and enforces structural bounds at every node.
///
/// This is the `(d)`-class per-node encode-budget closure for the
/// request-digest path: the projected structure can be deeper / larger than the
/// already-bounded `cast_arguments` input (each scalar gains a tag-array level;
/// each array/object gains a tag-array level), so depth / total-nodes /
/// object-members / array-items / string / object-name ceilings must be
/// re-checked on the projected form. `depth` is the container nesting level
/// (root container = 1), mirroring [`crate::json::json_decode`]'s accounting so
/// the depth corpus cases land at exactly the same boundary.
fn validate_bounds(value: &JsonValue, depth: u64, bounds: &Bounds, nodes: &mut u64) -> Result<()> {
    *nodes += 1;
    if *nodes > bounds.total_nodes() {
        return Err(Invalid);
    }
    match value {
        JsonValue::Array(items) => {
            if depth > bounds.depth() {
                return Err(Invalid);
            }
            if items.len() as u64 > bounds.array_items() {
                return Err(Invalid);
            }
            for item in items {
                validate_bounds(item, depth + 1, bounds, nodes)?;
            }
        }
        JsonValue::Object(members) => {
            if depth > bounds.depth() {
                return Err(Invalid);
            }
            if members.len() as u64 > bounds.object_members() {
                return Err(Invalid);
            }
            for (k, v) in members {
                if k.len() as u64 > bounds.key_bytes() {
                    return Err(Invalid);
                }
                validate_bounds(v, depth + 1, bounds, nodes)?;
            }
        }
        JsonValue::String(s) => {
            if s.len() as u64 > bounds.string_bytes() {
                return Err(Invalid);
            }
        }
        // Null / Bool / Int / Float — no structural bound at this node.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;
    use crate::json::JsonValue;

    fn max() -> Bounds {
        Bounds::maximum()
    }

    // ==========================================================================
    // Prefix — REQ1-SIGNING-digest-prefix (exact ASCII incl. the final NUL byte)
    // ==========================================================================

    #[test]
    fn prefix_is_exact_ascii_with_nul_byte() {
        // "BAP1-REQUEST\0" = 12 ASCII chars + 1 NUL byte = 13 bytes.
        assert_eq!(REQUEST_DIGEST_PREFIX, b"BAP1-REQUEST\0");
        assert_eq!(REQUEST_DIGEST_PREFIX.len(), 13);
        assert_eq!(REQUEST_DIGEST_PREFIX.last(), Some(&0u8));
    }

    #[test]
    fn prefix_with_nul_differs_from_prefix_without_nul() {
        // RED-capable: the final zero byte is load-bearing — the two prefixes
        // produce different digests for the same input.
        let args = JsonValue::Object(vec![]);
        let correct = request_digest("read", &args, &max()).expect("digest");
        // Manually compute the digest with the NUL byte omitted.
        let projected = typed(&args).unwrap();
        let signing = JsonValue::Array(vec![JsonValue::String("read".to_string()), projected]);
        let jcs = jcs_encode(&signing, &max()).unwrap();
        let mut h = Sha256::new();
        h.update(b"BAP1-REQUEST"); // NO NUL byte
        h.update(&jcs);
        let wrong = base64url_encode(&h.finalize());
        assert_ne!(
            correct, wrong,
            "digest MUST change when the NUL byte is dropped"
        );
    }

    // ==========================================================================
    // typed projection — every scalar wrapped in its explicit tag array
    // ==========================================================================

    #[test]
    fn integer_projects_to_integer_tag_array() {
        // The load-bearing projection: Int(10) -> ["integer", 10], NOT bare 10.
        let projected = typed(&JsonValue::Int(10)).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("integer".to_string()),
            JsonValue::Int(10),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn float_projects_to_float_tag_array() {
        let projected = typed(&JsonValue::Float(1e-7)).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("float".to_string()),
            JsonValue::Float(1e-7),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn null_projects_to_one_element_tag_array() {
        // :null is the ONLY 1-element projection (["null"], no value).
        let projected = typed(&JsonValue::Null).unwrap();
        assert_eq!(
            projected,
            JsonValue::Array(vec![JsonValue::String("null".to_string())])
        );
    }

    #[test]
    fn bool_projects_to_boolean_tag_array() {
        let projected = typed(&JsonValue::Bool(true)).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("boolean".to_string()),
            JsonValue::Bool(true),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn string_projects_to_string_tag_array() {
        let projected = typed(&JsonValue::String("x".to_string())).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("string".to_string()),
            JsonValue::String("x".to_string()),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn array_recursively_projects_elements() {
        // [Int(1), Float(2.0)] -> ["array", [["integer",1], ["float",2.0]]]
        let input = JsonValue::Array(vec![JsonValue::Int(1), JsonValue::Float(2.0)]);
        let projected = typed(&input).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("array".to_string()),
            JsonValue::Array(vec![
                JsonValue::Array(vec![
                    JsonValue::String("integer".to_string()),
                    JsonValue::Int(1),
                ]),
                JsonValue::Array(vec![
                    JsonValue::String("float".to_string()),
                    JsonValue::Float(2.0),
                ]),
            ]),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn object_recursively_projects_members() {
        // {"a": Int(1)} -> ["object", {"a": ["integer", 1]}]
        let input = JsonValue::Object(vec![("a".to_string(), JsonValue::Int(1))]);
        let projected = typed(&input).unwrap();
        let expected = JsonValue::Array(vec![
            JsonValue::String("object".to_string()),
            JsonValue::Object(vec![(
                "a".to_string(),
                JsonValue::Array(vec![
                    JsonValue::String("integer".to_string()),
                    JsonValue::Int(1),
                ]),
            )]),
        ]);
        assert_eq!(projected, expected);
    }

    #[test]
    fn non_finite_float_is_rejected_at_projection() {
        assert_eq!(typed(&JsonValue::Float(f64::NAN)), Err(Invalid));
        assert_eq!(typed(&JsonValue::Float(f64::INFINITY)), Err(Invalid));
        assert_eq!(typed(&JsonValue::Float(f64::NEG_INFINITY)), Err(Invalid));
    }

    // ==========================================================================
    // Closure #5 end-to-end — Int(1) vs Float(1.0) produce DIFFERENT digests
    // ==========================================================================

    #[test]
    fn int_one_and_float_one_zero_produce_different_digests() {
        // The load-bearing closure #5 test for request_digest: Int(1) projects
        // to ["integer",1] and Float(1.0) to ["float",1] (ryu-js emits "1" for
        // 1.0). The tag difference makes the JCS bytes — and thus the digest —
        // distinct. Collapsing both to the same tag makes the digests collide.
        let int_digest = request_digest("read", &JsonValue::Int(1), &max()).expect("int digest");
        let float_digest =
            request_digest("read", &JsonValue::Float(1.0), &max()).expect("float digest");
        assert_ne!(
            int_digest, float_digest,
            "Int(1) and Float(1.0) MUST produce different request digests"
        );
    }

    #[test]
    fn int_and_float_preimage_jcs_bytes_are_distinct() {
        // Pin the exact preimage distinction:
        //   Int(1)    -> ["read",["integer",1]]
        //   Float(1.0)-> ["read",["float",1]]     (ryu-js emits 1.0 as "1")
        let int_jcs = {
            let p = typed(&JsonValue::Int(1)).unwrap();
            let s = JsonValue::Array(vec![JsonValue::String("read".to_string()), p]);
            jcs_encode(&s, &max()).unwrap()
        };
        let float_jcs = {
            let p = typed(&JsonValue::Float(1.0)).unwrap();
            let s = JsonValue::Array(vec![JsonValue::String("read".to_string()), p]);
            jcs_encode(&s, &max()).unwrap()
        };
        assert_eq!(int_jcs, br#"["read",["integer",1]]"#);
        assert_eq!(float_jcs, br#"["read",["float",1]]"#);
        assert_ne!(int_jcs, float_jcs);
    }

    // ==========================================================================
    // operation — first element is the RAW operation string (NOT typed-wrapped)
    // ==========================================================================

    #[test]
    fn operation_is_raw_string_first_element() {
        // The signing array is [operation, typed(cast_arguments)] — operation
        // appears as a bare JSON string, NOT as ["string", operation].
        let args = JsonValue::Object(vec![]);
        let projected = typed(&args).unwrap();
        let signing = JsonValue::Array(vec![JsonValue::String("read".to_string()), projected]);
        let jcs = jcs_encode(&signing, &max()).unwrap();
        assert_eq!(jcs, br#"["read",["object",{}]]"#);
    }

    // ==========================================================================
    // Bounds — operation_bytes / depth / total_nodes / object_members
    // ==========================================================================

    #[test]
    fn operation_at_exact_bound_is_accepted() {
        // operation_bytes = 128; 128 ASCII chars is the exact bound.
        let op = "a".repeat(128);
        let args = JsonValue::Object(vec![]);
        assert!(request_digest(&op, &args, &max()).is_ok());
    }

    #[test]
    fn operation_over_bound_is_rejected() {
        let op = "a".repeat(129);
        let args = JsonValue::Object(vec![]);
        assert_eq!(request_digest(&op, &args, &max()), Err(Invalid));
    }

    #[test]
    fn depth_at_exact_bound_is_accepted() {
        // 15 nested arrays wrapping 0: projected depth = 2*15+2 = 32 (exact).
        let mut args = JsonValue::Int(0);
        for _ in 0..15 {
            args = JsonValue::Array(vec![args]);
        }
        assert!(request_digest("read", &args, &max()).is_ok());
    }

    #[test]
    fn depth_over_bound_is_rejected() {
        // 16 nested arrays: projected depth = 34 > 32.
        let mut args = JsonValue::Int(0);
        for _ in 0..16 {
            args = JsonValue::Array(vec![args]);
        }
        assert_eq!(request_digest("read", &args, &max()), Err(Invalid));
    }

    #[test]
    fn total_nodes_over_bound_is_rejected() {
        // 6 arrays of 256 zeros -> projected total_nodes > 4096.
        let inner = JsonValue::Array(vec![JsonValue::Int(0); 256]);
        let args = JsonValue::Array(vec![inner; 6]);
        assert_eq!(request_digest("read", &args, &max()), Err(Invalid));
    }

    #[test]
    fn object_members_at_exact_bound_is_accepted() {
        // 64 members: the projected object still has 64 members (exact bound).
        let members: Vec<(String, JsonValue)> = (1..=64)
            .map(|i| (format!("k{i}"), JsonValue::Int(i)))
            .collect();
        let args = JsonValue::Object(members);
        assert!(request_digest("read", &args, &max()).is_ok());
    }

    #[test]
    fn object_members_over_bound_is_rejected() {
        let members: Vec<(String, JsonValue)> = (1..=65)
            .map(|i| (format!("k{i}"), JsonValue::Int(i)))
            .collect();
        let args = JsonValue::Object(members);
        assert_eq!(request_digest("read", &args, &max()), Err(Invalid));
    }

    // ==========================================================================
    // Known digest — the request-digest-float-cast-arguments pin
    // ==========================================================================

    #[test]
    fn float_cast_arguments_digest_matches_pinned_value() {
        // The corpus case pins: op="read", args=Float(1e-07) ->
        //   "-fTRu1NZroD6L_Q_IDSrPoqfCItKMpV1GDM3FV5ol0Y"
        // This proves BOTH the typed projection (["float",1e-7]) AND the ryu-js
        // float formatting ("1e-7") in the JCS preimage.
        let digest = request_digest("read", &JsonValue::Float(1e-7), &max()).expect("digest");
        assert_eq!(
            String::from_utf8(digest).unwrap(),
            "-fTRu1NZroD6L_Q_IDSrPoqfCItKMpV1GDM3FV5ol0Y"
        );
    }

    // ==========================================================================
    // Corpus: digest.json (8) + digest-jcs-bytes.json (1) = 9 cases
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

    /// Converts a serde_json::Value to the crate's tagged JsonValue, preserving
    /// the integer-vs-float tag (closure #5): a JSON number that serde_json
    /// stored as an integer -> Int; otherwise -> Float.
    fn serde_to_json(value: &serde_json::Value) -> JsonValue {
        match value {
            serde_json::Value::Null => JsonValue::Null,
            serde_json::Value::Bool(b) => JsonValue::Bool(*b),
            serde_json::Value::Number(n) => {
                // as_i64() returns Some only for integer-stored numbers
                // (`10`, not `10.0` or `1e1`), preserving the tag distinction.
                if let Some(i) = n.as_i64() {
                    JsonValue::Int(i)
                } else {
                    JsonValue::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(s) => JsonValue::String(s.clone()),
            serde_json::Value::Array(arr) => {
                JsonValue::Array(arr.iter().map(serde_to_json).collect())
            }
            serde_json::Value::Object(obj) => JsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), serde_to_json(v)))
                    .collect(),
            ),
        }
    }

    #[test]
    fn corpus_request_digest_all_9_cases() {
        let root = corpus_root();
        let mut cases: Vec<serde_json::Value> = Vec::new();
        for name in ["digest.json", "digest-jcs-bytes.json"] {
            let path = root.join("cases").join("request-digest").join(name);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let file: serde_json::Value =
                serde_json::from_str(&content).expect("corpus file is valid JSON");
            cases.extend(
                file["cases"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{name} cases array"))
                    .clone(),
            );
        }

        assert_eq!(cases.len(), 9, "expected 9 total request-digest cases");

        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        let mut applicability = std::collections::BTreeMap::<&str, usize>::new();

        for case in &cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let class = case["class"].as_str().unwrap_or("<no class>");
            *applicability.entry(class).or_default() += 1;
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            let operation = case["input"]["operation"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing input.operation"));
            let cast_arguments = serde_to_json(&case["input"]["cast_arguments"]);

            let result = request_digest(operation, &cast_arguments, &max());

            let agree = match (expected_verdict, result) {
                ("valid", Ok(digest)) => {
                    let expected_digest = case["expected"]["digest"]
                        .as_str()
                        .unwrap_or_else(|| panic!("valid case {id} missing expected.digest"));
                    String::from_utf8(digest).unwrap() == expected_digest
                }
                ("invalid", Err(Invalid)) => true,
                ("valid", Err(Invalid)) => {
                    eprintln!("DISAGREE: id={id} expected=valid but got Invalid");
                    false
                }
                ("invalid", Ok(digest)) => {
                    eprintln!(
                        "DISAGREE: id={id} expected=invalid but got digest {}",
                        String::from_utf8(digest).unwrap()
                    );
                    false
                }
                _ => false,
            };

            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
            }
        }

        eprintln!("applicability: {applicability:?}");
        eprintln!("agreed={agreed} disagreed={disagreed}");
        assert_eq!(agreed, 9, "agreed (request-digest corpus == 9)");
        assert_eq!(disagreed, 0, "disagreed");
        // Cross-check per-class applicability the plan pins.
        assert_eq!(applicability["valid"], 2, "valid applicability");
        assert_eq!(applicability["exact_bound"], 3, "exact_bound applicability");
        assert_eq!(
            applicability["maximum_plus_one"], 4,
            "maximum_plus_one applicability"
        );
    }
}
