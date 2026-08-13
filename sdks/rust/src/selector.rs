//! Selector evaluation — the request-binding algebra (silent auth class).
//!
//! Selectors are the closed-set predicates a grant's operation uses to bind a
//! specific request's server-derived tagged arguments (`docs/protocol-v1.md`
//! § Selector algebra, lines 204–224). A selector bug that accepts a forged
//! token, or a tag-collapse that matches the wrong value, yields WRONG
//! AUTHORIZATION silently — this is the silent-auth-class module.
//!
//! Three kinds form a closed set (`REQ1-SELECTOR-closed-set`):
//!
//! | kind | exact members |
//! |---|---|
//! | `all` | `{kind: "all"}` — matches any JSON root |
//! | `equals` | `{kind: "equals", path, value}` — path must exist |
//! | `one_of` | `{kind: "one_of", path, values}` — path must exist |
//!
//! `equals` / `one_of` traverse `cast_arguments` along `path` (objects only;
//! 1–32 member names, each 1–128 UTF-8 bytes — `REQ1-SELECTOR-path-shape`) and
//! the path MUST resolve (`REQ1-SELECTOR-path-required`): a missing member or a
//! non-object mid-path is `Err(Invalid)` (fail-closed — never a silent
//! `Ok(false)`). Match is by **semantic identity**
//! (`REQ1-SELECTOR-semantic-identity`), which preserves tagged scalar
//! distinctions (`REQ1-SELECTOR-no-tag-collapse`: `Int(1)` is NOT
//! `Float(1.0)`), compares arrays positionally, and compares duplicate-free
//! objects as unordered key/value sets. No selector grants business
//! authorization (`REQ1-SELECTOR-not-authorization`).
//!
//! Derived first-hand from `docs/protocol-v1.md` § Selector algebra — NOT from
//! any sibling-SDK or Elixir source (ADR 0014 D5).

// `evaluate` / `semantic_identity` are `pub(crate)` and are wired by the v1
// façade: `evaluate` is called by `check_envelope` (Task 12) for every selector
// in the matched grant operation, and `semantic_identity` is reachable through
// that call chain. The crate-level `#![forbid(unsafe_code)]` is unaffected.

use crate::bounds::Bounds;
use crate::error::{Invalid, Result};
use crate::json::JsonValue;

/// Conjunctively evaluate one selector against the server-derived tagged
/// arguments.
///
/// Returns `Ok(true)` when the selector matches, `Ok(false)` when it is
/// well-formed but does not match (only `equals` / `one_of` can return this —
/// and only when the path resolves but the value differs), or `Err(Invalid)`
/// for any malformed selector, unknown kind, wrong member set, malformed /
/// over-limit path, missing path (`REQ1-SELECTOR-path-required`), or over-limit
/// `one_of`.
pub(crate) fn evaluate(
    selector: &JsonValue,
    cast_arguments: &JsonValue,
    bounds: &Bounds,
) -> Result<bool> {
    // REQ1-SELECTOR-closed-set: a selector MUST be a JSON object.
    let members = match selector {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };
    // `kind` MUST be present and a string of the closed set.
    let kind = member_str(members, "kind")?;
    match kind {
        "all" => {
            // `all` matches any JSON root. The conformance corpus
            // (`check-envelope-valid-selector-all-with-extra-members`, jti
            // `urn:example:grant:fat-all`) establishes that an `all` selector
            // carrying inert extra members (e.g. a stray `path`/`value`) still
            // matches. The canonical closed form is `{kind:"all"}`
            // (REQ1-SELECTOR-closed-set; selector.schema.json), but extra members
            // on `all` are not authorization-relevant — `all` returns true
            // regardless of any other members — so they are tolerated rather
            // than rejected. (Schemas are explicitly NOT byte-level oracles —
            // protocol-v1.md line 126 — the corpus is.) Only the `kind` itself
            // is examined here; `equals`/`one_of` below remain strict about
            // their exact member sets, which is security-relevant (an extra
            // `value`/`values` would be ambiguous) and uncontradicted by the
            // corpus.
            Ok(true)
        }
        "equals" => eval_equals(members, cast_arguments, bounds),
        "one_of" => eval_one_of(members, cast_arguments, bounds),
        _ => Err(Invalid), // unknown kind — closed set
    }
}

/// `equals`: exactly `{kind, path, value}`; traverse the path (fail-closed on
/// missing), then compare the found value to `value` by semantic identity.
fn eval_equals(
    members: &[(String, JsonValue)],
    cast_arguments: &JsonValue,
    bounds: &Bounds,
) -> Result<bool> {
    if members.len() != 3 {
        return Err(Invalid); // missing path/value, or an extra member
    }
    let path = extract_path(members, "path", bounds)?;
    let value = member_value(members, "value")?;
    let found = traverse(cast_arguments, &path)?;
    Ok(semantic_identity(found, value))
}

/// `one_of`: exactly `{kind, path, values}`; `values` is a non-empty array of
/// at most `bounds.one_of_values()` items; traverse the path (fail-closed on
/// missing), then `Ok(true)` if the found value is semantically identical to
/// ANY element of `values`.
fn eval_one_of(
    members: &[(String, JsonValue)],
    cast_arguments: &JsonValue,
    bounds: &Bounds,
) -> Result<bool> {
    if members.len() != 3 {
        return Err(Invalid);
    }
    let path = extract_path(members, "path", bounds)?;
    let values_raw = member_value(members, "values")?;
    let values = match values_raw {
        JsonValue::Array(a) => a,
        _ => return Err(Invalid), // values MUST be an array
    };
    if values.is_empty() {
        return Err(Invalid); // non-empty JSON array
    }
    if values.len() as u64 > bounds.one_of_values() {
        return Err(Invalid); // REQ1-SELECTOR-one-of-size (<= 256)
    }
    let found = traverse(cast_arguments, &path)?;
    Ok(values.iter().any(|v| semantic_identity(v, found)))
}

/// Extracts and validates a selector `path` member.
///
/// `path` MUST be a non-empty JSON array of 1..=`bounds.path_segments()`
/// strings, each 1..=`bounds.key_bytes()` UTF-8 bytes, all strings
/// (`REQ1-SELECTOR-path-shape`: paths traverse objects only and never index
/// arrays — a non-string element is invalid). Returns the path as owned
/// `String`s (bounded: at most 32 segments of 128 bytes).
fn extract_path(
    members: &[(String, JsonValue)],
    name: &str,
    bounds: &Bounds,
) -> Result<Vec<String>> {
    let raw = member_value(members, name)?;
    let arr = match raw {
        JsonValue::Array(a) => a,
        _ => return Err(Invalid), // path MUST be an array
    };
    if arr.is_empty() {
        return Err(Invalid); // 1 <= len
    }
    if arr.len() as u64 > bounds.path_segments() {
        return Err(Invalid); // len <= 32 (REQ1-SELECTOR-path-shape)
    }
    let mut path = Vec::with_capacity(arr.len());
    for elem in arr {
        let s = match elem {
            JsonValue::String(s) => s,
            // A non-string element (number / bool / null / structured) would
            // index an array — paths traverse objects only.
            _ => return Err(Invalid),
        };
        if s.is_empty() {
            return Err(Invalid); // 1 <= segment bytes
        }
        if s.len() as u64 > bounds.key_bytes() {
            return Err(Invalid); // segment bytes <= 128
        }
        path.push(s.clone());
    }
    Ok(path)
}

/// Traverses `root` along `path` (object-member names only).
///
/// Returns the resolved value, or `Err(Invalid)` if any step hits a non-object
/// (`REQ1-SELECTOR-path-shape`: never indexes arrays) or a member name that is
/// absent (`REQ1-SELECTOR-path-required`: the path MUST exist — fail-closed,
/// never a silent `Ok(false)`). The duplicate-rejecting JSON decoder guarantees
/// each member name is unique within its object, so the linear search resolves
/// at most one value.
fn traverse<'a>(root: &'a JsonValue, path: &[String]) -> Result<&'a JsonValue> {
    let mut current = root;
    for seg in path {
        match current {
            JsonValue::Object(members) => {
                match members.iter().find(|(k, _)| k == seg) {
                    Some((_, v)) => current = v,
                    // Member absent -> REQ1-SELECTOR-path-required (fail-closed).
                    None => return Err(Invalid),
                }
            }
            // Non-object mid-path -> REQ1-SELECTOR-path-shape (objects only).
            _ => return Err(Invalid),
        }
    }
    Ok(current)
}

/// Semantic identity — two tagged JSON values are identical iff their tags and
/// values match, recursively (`REQ1-SELECTOR-semantic-identity`).
///
/// - Scalars match only within the SAME tag: both `Null`; both `Bool` with
///   equal value; both `Int` with equal value; both `Float` with equal value;
///   both `String` with equal value.
/// - Arrays match positionally, element-wise, equal length.
/// - Objects match as UNORDERED key/value sets (duplicate-free by
///   construction): same key set and each key's value recursively identical.
///
/// `REQ1-SELECTOR-no-tag-collapse`: mismatched tags are NOT identical — the
/// catch-all `_ => false` arm means `Int(1)` is NOT `Float(1.0)`, `Bool(true)`
/// is NOT `Int(1)`, and `String("1")` is NOT `Int(1)`. Removing the tag guard
/// (e.g. casting both numbers to `f64`) collapses this distinction and yields
/// wrong authorization.
///
/// Returns `false` for a duplicate-bearing object: a decoded `Object` is always
/// duplicate-free, but a hand-built one (a direct caller's `cast_arguments`)
/// may not be, and find-first-match equality on a dup-bearing object is unsound.
fn unique_keys(members: &[(String, JsonValue)]) -> bool {
    // BTreeSet (deterministic): a std hash-set's RandomState reads OS entropy
    // (a randomness boundary the lib path forbids; the reference's MapSet has
    // none). BTreeSet has none, with the same insert-returns-bool semantics.
    let mut seen = std::collections::BTreeSet::new();
    members.iter().all(|(k, _)| seen.insert(k.as_str()))
}
pub(crate) fn semantic_identity(a: &JsonValue, b: &JsonValue) -> bool {
    match (a, b) {
        (JsonValue::Null, JsonValue::Null) => true,
        (JsonValue::Bool(x), JsonValue::Bool(y)) => x == y,
        // INT vs INT only — Int(1) is NOT Float(1.0).
        (JsonValue::Int(x), JsonValue::Int(y)) => x == y,
        // FLOAT vs FLOAT only.
        (JsonValue::Float(x), JsonValue::Float(y)) => x == y,
        (JsonValue::String(x), JsonValue::String(y)) => x == y,
        (JsonValue::Array(x), JsonValue::Array(y)) => {
            // Positional: same length, element-wise identical.
            x.len() == y.len() && x.iter().zip(y).all(|(xi, yi)| semantic_identity(xi, yi))
        }
        (JsonValue::Object(x), JsonValue::Object(y)) => {
            // Unordered key/value sets. Both MUST be duplicate-free (reference
            // selector.ex:51 unique_object?): a hand-built Object CAN carry
            // duplicate names (the Vec carrier allows it), and find-first-match
            // equality on a dup-bearing object is unsound — {a:1,a:1} would
            // otherwise equal {a:1,b:2}. Reject any dup-bearing object outright.
            if !unique_keys(x) || !unique_keys(y) {
                return false;
            }
            // Same key set (length equality + every x-key present in y) and each
            // value recursively identical.
            x.len() == y.len()
                && x.iter().all(|(kx, vx)| {
                    y.iter()
                        .find(|(ky, _)| ky == kx)
                        .map(|(_, vy)| semantic_identity(vx, vy))
                        .unwrap_or(false)
                })
        }
        // REQ1-SELECTOR-no-tag-collapse: any tag mismatch is NOT identical.
        _ => false,
    }
}

/// Looks up a member by name; `Err(Invalid)` if absent.
fn member_value<'a>(members: &'a [(String, JsonValue)], name: &str) -> Result<&'a JsonValue> {
    for (k, v) in members {
        if k == name {
            return Ok(v);
        }
    }
    Err(Invalid)
}

/// Looks up a member by name and asserts it is a string; returns its `&str`.
fn member_str<'a>(members: &'a [(String, JsonValue)], name: &str) -> Result<&'a str> {
    match member_value(members, name)? {
        JsonValue::String(s) => Ok(s.as_str()),
        _ => Err(Invalid),
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

    /// Decodes a JSON literal through the real tagged decoder (preserves the
    /// Int/Float tag distinction — closure #5 — so the selector tests exercise
    /// the same algebra the envelope binding uses).
    fn j(bytes: &[u8]) -> JsonValue {
        json_decode(bytes, &max()).expect("test JSON decodes")
    }

    // ==========================================================================
    // REQ1-SELECTOR-no-tag-collapse — the load-bearing silent-auth test
    // ==========================================================================

    #[test]
    fn equals_int_value_does_not_match_float_argument() {
        // selector value = Int(1) (lexeme `1`), argument carries Float(1.0)
        // (lexeme `1.0`) at path ["x"]. Semantic identity MUST preserve the tag:
        // these are NOT identical, so the verdict is Ok(false) (no match), NOT
        // Ok(true). Collapsing both numbers to f64 makes this wrongly Ok(true).
        let selector = j(br#"{"kind":"equals","path":["x"],"value":1}"#);
        let args = j(br#"{"x":1.0}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Ok(false));
    }

    #[test]
    fn equals_float_value_does_not_match_int_argument() {
        // The mirror direction: Float selector value vs Int argument.
        let selector = j(br#"{"kind":"equals","path":["x"],"value":1.0}"#);
        let args = j(br#"{"x":1}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Ok(false));
    }

    #[test]
    fn equals_int_matches_int_and_float_matches_float() {
        // Positive controls: same-tag values match.
        let sel_i = j(br#"{"kind":"equals","path":["x"],"value":1}"#);
        assert_eq!(evaluate(&sel_i, &j(br#"{"x":1}"#), &max()), Ok(true));
        let sel_f = j(br#"{"kind":"equals","path":["x"],"value":1.0}"#);
        assert_eq!(evaluate(&sel_f, &j(br#"{"x":1.0}"#), &max()), Ok(true));
    }

    #[test]
    fn bool_string_int_are_distinct_tags() {
        // Bool(true) is NOT Int(1); String("1") is NOT Int(1); Bool(true) is
        // NOT String("true").
        let sel_b = j(br#"{"kind":"equals","path":["x"],"value":true}"#);
        assert_eq!(evaluate(&sel_b, &j(br#"{"x":1}"#), &max()), Ok(false));
        let sel_s = j(br#"{"kind":"equals","path":["x"],"value":"1"}"#);
        assert_eq!(evaluate(&sel_s, &j(br#"{"x":1}"#), &max()), Ok(false));
        let sel_bt = j(br#"{"kind":"equals","path":["x"],"value":true}"#);
        assert_eq!(evaluate(&sel_bt, &j(br#"{"x":"true"}"#), &max()), Ok(false));
    }

    // ==========================================================================
    // REQ1-SELECTOR-path-required — missing path is Invalid, NOT Ok(false)
    // ==========================================================================

    #[test]
    fn equals_missing_path_member_is_invalid() {
        // path ["missing"] absent from args -> Err(Invalid) (fail-closed). A
        // silent Ok(false) here is the request-binding bypass.
        let selector = j(br#"{"kind":"equals","path":["missing"],"value":1}"#);
        let args = j(br#"{}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Err(Invalid));
    }

    #[test]
    fn equals_path_through_scalar_is_invalid() {
        // path ["a","b"] against {"a":1}: "a" resolves to Int(1), then "b" hits
        // a non-object -> Invalid (paths traverse objects only).
        let selector = j(br#"{"kind":"equals","path":["a","b"],"value":1}"#);
        let args = j(br#"{"a":1}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Err(Invalid));
    }

    #[test]
    fn equals_path_through_array_is_invalid() {
        // path ["a","0"] against {"a":[1]}: "a" resolves to Array, then "0"
        // hits an array -> Invalid (paths never index arrays).
        let selector = j(br#"{"kind":"equals","path":["a","0"],"value":1}"#);
        let args = j(br#"{"a":[1]}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Err(Invalid));
    }

    #[test]
    fn one_of_missing_path_is_invalid() {
        let selector = j(br#"{"kind":"one_of","path":["missing"],"values":[1]}"#);
        let args = j(br#"{}"#);
        assert_eq!(evaluate(&selector, &args, &max()), Err(Invalid));
    }

    // ==========================================================================
    // REQ1-SELECTOR-closed-set — malformed selectors are Invalid
    // ==========================================================================

    #[test]
    fn unknown_kind_is_invalid() {
        let selector = j(br#"{"kind":"matches","path":["x"],"value":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn non_string_kind_is_invalid() {
        let selector = j(br#"{"kind":1,"path":["x"],"value":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn missing_kind_is_invalid() {
        let selector = j(br#"{"path":["x"],"value":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn non_object_selector_is_invalid() {
        assert_eq!(
            evaluate(&j(br#""not-an-object""#), &j(br#"{"x":1}"#), &max()),
            Err(Invalid)
        );
        assert_eq!(
            evaluate(&j(b"[1,2]"), &j(br#"{"x":1}"#), &max()),
            Err(Invalid)
        );
        assert_eq!(
            evaluate(&JsonValue::Null, &j(br#"{"x":1}"#), &max()),
            Err(Invalid)
        );
    }

    #[test]
    fn equals_missing_path_member_field_is_invalid() {
        // {kind:"equals", value:1} — the `path` member is absent.
        let selector = j(br#"{"kind":"equals","value":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn equals_missing_value_member_field_is_invalid() {
        // {kind:"equals", path:["x"]} — the `value` member is absent.
        let selector = j(br#"{"kind":"equals","path":["x"]}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn equals_extra_member_is_invalid() {
        let selector = j(br#"{"kind":"equals","path":["x"],"value":1,"extra":2}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn all_tolerates_inert_extra_members() {
        // Corpus-driven (`check-envelope-valid-selector-all-with-extra-members`):
        // an `all` selector with inert extra members still matches any root.
        // `all` returns true regardless of the extra members, so tolerating them
        // is not authorization-relevant. Both a bare and a "fat" `all` match.
        let bare = j(br#"{"kind":"all"}"#);
        let fat = j(br#"{"kind":"all","path":["record"],"value":"zz"}"#);
        assert_eq!(evaluate(&bare, &JsonValue::Null, &max()), Ok(true));
        assert_eq!(
            evaluate(&fat, &j(br#"{"limit":10,"record":{"id":"rec-1"}}"#), &max()),
            Ok(true)
        );
    }

    #[test]
    fn one_of_values_not_array_is_invalid() {
        let selector = j(br#"{"kind":"one_of","path":["x"],"values":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    // ==========================================================================
    // REQ1-SELECTOR-path-shape — path bounds + objects-only traversal
    // ==========================================================================

    #[test]
    fn empty_path_is_invalid() {
        let selector = j(br#"{"kind":"equals","path":[],"value":1}"#);
        assert_eq!(evaluate(&selector, &j(br#"{}"#), &max()), Err(Invalid));
    }

    #[test]
    fn path_over_32_segments_is_invalid() {
        // 33 segments: json_decode accepts it (array_items bound is 256);
        // extract_path rejects it at path_segments (32).
        let segs: Vec<String> = (0..33).map(|i| format!("\"s{i}\"")).collect();
        let sel_text = format!(
            "{{\"kind\":\"equals\",\"path\":[{}],\"value\":1}}",
            segs.join(",")
        );
        let selector = j(sel_text.as_bytes());
        assert_eq!(evaluate(&selector, &j(br#"{}"#), &max()), Err(Invalid));
    }

    #[test]
    fn path_at_32_segments_is_accepted() {
        // 32 segments is the exact bound. Build nested args with the OUTERMOST
        // key = s0 (so the path ["s0",...,"s31"] resolves); wrap from the
        // innermost out.
        let mut args = JsonValue::Int(1);
        for i in (0..32).rev() {
            args = JsonValue::Object(vec![(format!("s{i}"), args)]);
        }
        let segs: Vec<String> = (0..32).map(|i| format!("\"s{i}\"")).collect();
        let sel_text = format!(
            "{{\"kind\":\"equals\",\"path\":[{}],\"value\":1}}",
            segs.join(",")
        );
        let selector = j(sel_text.as_bytes());
        assert_eq!(evaluate(&selector, &args, &max()), Ok(true));
    }

    #[test]
    fn path_segment_over_128_bytes_is_invalid() {
        // A 129-byte path-segment string decodes (string_bytes bound is 8192);
        // extract_path rejects it at key_bytes (128).
        let long = "a".repeat(129);
        let sel_text = format!(r#"{{"kind":"equals","path":["{long}"],"value":1}}"#);
        let selector = j(sel_text.as_bytes());
        assert_eq!(evaluate(&selector, &j(br#"{}"#), &max()), Err(Invalid));
    }

    #[test]
    fn path_segment_at_128_bytes_is_accepted() {
        let seg = "a".repeat(128);
        let sel_text = format!(r#"{{"kind":"equals","path":["{seg}"],"value":1}}"#);
        let selector = j(sel_text.as_bytes());
        let args = JsonValue::Object(vec![(seg, JsonValue::Int(1))]);
        assert_eq!(evaluate(&selector, &args, &max()), Ok(true));
    }

    #[test]
    fn path_with_non_string_element_is_invalid() {
        // path ["x",1] — a numeric element would index an array.
        let selector = j(br#"{"kind":"equals","path":["x",1],"value":1}"#);
        assert_eq!(
            evaluate(&selector, &j(br#"{"x":{"1":1}}"#), &max()),
            Err(Invalid)
        );
    }

    // ==========================================================================
    // REQ1-SELECTOR-one-of-size — values bound (<= 256, non-empty)
    // ==========================================================================

    #[test]
    fn one_of_with_257_values_is_invalid() {
        // Built directly: json_decode's array_items bound (256) would reject a
        // 257-element array first; this isolates evaluate's one_of_values check.
        let selector = JsonValue::Object(vec![
            ("kind".to_string(), JsonValue::String("one_of".to_string())),
            (
                "path".to_string(),
                JsonValue::Array(vec![JsonValue::String("x".to_string())]),
            ),
            (
                "values".to_string(),
                JsonValue::Array((0i64..257).map(JsonValue::Int).collect()),
            ),
        ]);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    #[test]
    fn one_of_with_256_values_is_accepted() {
        let selector = JsonValue::Object(vec![
            ("kind".to_string(), JsonValue::String("one_of".to_string())),
            (
                "path".to_string(),
                JsonValue::Array(vec![JsonValue::String("x".to_string())]),
            ),
            (
                "values".to_string(),
                JsonValue::Array((0i64..256).map(JsonValue::Int).collect()),
            ),
        ]);
        // 1 is among 0..256 -> Ok(true).
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Ok(true));
    }

    #[test]
    fn one_of_empty_values_is_invalid() {
        let selector = JsonValue::Object(vec![
            ("kind".to_string(), JsonValue::String("one_of".to_string())),
            (
                "path".to_string(),
                JsonValue::Array(vec![JsonValue::String("x".to_string())]),
            ),
            ("values".to_string(), JsonValue::Array(vec![])),
        ]);
        assert_eq!(evaluate(&selector, &j(br#"{"x":1}"#), &max()), Err(Invalid));
    }

    // ==========================================================================
    // all — matches any JSON root
    // ==========================================================================

    #[test]
    fn all_matches_any_root() {
        let sel = j(br#"{"kind":"all"}"#);
        assert_eq!(evaluate(&sel, &JsonValue::Null, &max()), Ok(true));
        assert_eq!(evaluate(&sel, &j(br#"{"a":1}"#), &max()), Ok(true));
        assert_eq!(evaluate(&sel, &j(br#"[1,2,3]"#), &max()), Ok(true));
        assert_eq!(evaluate(&sel, &JsonValue::Int(42), &max()), Ok(true));
        assert_eq!(evaluate(&sel, &JsonValue::Bool(false), &max()), Ok(true));
    }

    // ==========================================================================
    // equals / one_of — match / no-match (path resolves)
    // ==========================================================================

    #[test]
    fn equals_matches_identical_value() {
        let sel = j(br#"{"kind":"equals","path":["x"],"value":1}"#);
        assert_eq!(evaluate(&sel, &j(br#"{"x":1}"#), &max()), Ok(true));
    }

    #[test]
    fn equals_distinct_value_returns_false() {
        let sel = j(br#"{"kind":"equals","path":["x"],"value":2}"#);
        assert_eq!(evaluate(&sel, &j(br#"{"x":1}"#), &max()), Ok(false));
    }

    #[test]
    fn equals_nested_path_resolves() {
        let sel = j(br#"{"kind":"equals","path":["a","b"],"value":1}"#);
        assert_eq!(evaluate(&sel, &j(br#"{"a":{"b":1}}"#), &max()), Ok(true));
    }

    #[test]
    fn one_of_matches_when_value_present() {
        let sel = j(br#"{"kind":"one_of","path":["x"],"values":[1,2,3]}"#);
        assert_eq!(evaluate(&sel, &j(br#"{"x":2}"#), &max()), Ok(true));
    }

    #[test]
    fn one_of_returns_false_when_value_absent() {
        let sel = j(br#"{"kind":"one_of","path":["x"],"values":[1,2,3]}"#);
        assert_eq!(evaluate(&sel, &j(br#"{"x":9}"#), &max()), Ok(false));
    }

    // ==========================================================================
    // semantic_identity — set-equality, positionality, tag preservation
    // ==========================================================================

    #[test]
    fn object_member_order_is_semantically_identical() {
        // REQ1-SELECTOR-semantic-identity: objects compared as unordered sets.
        assert!(semantic_identity(
            &j(br#"{"a":1,"b":2}"#),
            &j(br#"{"b":2,"a":1}"#),
        ));
    }

    #[test]
    fn object_different_keys_not_identical() {
        assert!(!semantic_identity(
            &j(br#"{"a":1}"#),
            &j(br#"{"a":1,"b":2}"#),
        ));
    }

    #[test]
    fn arrays_are_positional_not_unordered() {
        assert!(!semantic_identity(&j(br#"[1,2]"#), &j(br#"[2,1]"#),));
    }

    #[test]
    fn arrays_equal_length_positional_match() {
        assert!(semantic_identity(&j(br#"[1,2,3]"#), &j(br#"[1,2,3]"#),));
        assert!(!semantic_identity(&j(br#"[1,2,3]"#), &j(br#"[1,2]"#),));
    }

    #[test]
    fn nested_object_recursive_identity() {
        assert!(semantic_identity(
            &j(br#"{"a":{"b":[1,2]}}"#),
            &j(br#"{"a":{"b":[1,2]}}"#),
        ));
        assert!(!semantic_identity(
            &j(br#"{"a":{"b":[1,2]}}"#),
            &j(br#"{"a":{"b":[2,1]}}"#),
        ));
    }

    #[test]
    fn null_only_matches_null() {
        assert!(semantic_identity(&JsonValue::Null, &JsonValue::Null));
        assert!(!semantic_identity(
            &JsonValue::Null,
            &JsonValue::Bool(false)
        ));
        assert!(!semantic_identity(&JsonValue::Null, &JsonValue::Int(0)));
    }

    #[test]
    fn dup_bearing_objects_are_not_semantically_equal() {
        // The bypass the unique_keys check defeats (reference selector.ex:51
        // unique_object?): WITHOUT it, find-first-match equality makes
        // {a:1,a:1} (dup, len 2) wrongly equal {a:1,b:2} (len 2) — both x-keys
        // ("a","a") find a match in y. unique_keys rejects the dup-bearing
        // object outright (RED-capable: removing the unique_keys guard makes
        // the first assertion fail).
        let dup_x = JsonValue::Object(vec![
            ("a".to_string(), JsonValue::Int(1)),
            ("a".to_string(), JsonValue::Int(1)),
        ]);
        let y = JsonValue::Object(vec![
            ("a".to_string(), JsonValue::Int(1)),
            ("b".to_string(), JsonValue::Int(2)),
        ]);
        assert!(
            !semantic_identity(&dup_x, &y),
            "dup-bearing object must not equal a distinct object"
        );
        assert!(
            !semantic_identity(&dup_x, &dup_x),
            "a dup-bearing object is not a valid value"
        );
        // Sanity: two identical dup-free objects ARE equal.
        let ok = JsonValue::Object(vec![
            ("a".to_string(), JsonValue::Int(1)),
            ("b".to_string(), JsonValue::Int(2)),
        ]);
        assert!(semantic_identity(&ok, &y));
    }
}
