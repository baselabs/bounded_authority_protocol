//! JWK encode/decode + the RFC 7638 thumbprint family for the fixed
//! Ed25519/OKP profile.
//!
//! Derived first-hand from `spec/bap-v1.md` § Protected headers
//! (lines 152–163), RFC 7638 §3.2 (canonical hash), and RFC 8037
//! (EdDSA/OKP in JOSE) — NOT from any sibling-SDK or Elixir source
//! (ADR 0014 D5).
//!
//! The proof JWK is exactly `{crv: "Ed25519", kty: "OKP",
//! x: canonical_base64url_32_bytes}` in any member order
//! (`REQ1-HEADER-proof-jwk`). Every additional member — including the
//! private `d` — is invalid (`REQ1-HEADER-no-private-jwk`). The RFC 7638
//! thumbprint preimage is the EXACT sorted JSON
//! `{"crv":"Ed25519","kty":"OKP","x":"<canonical-x>"}`; the thumbprint is
//! unpadded base64url SHA-256 of those UTF-8 bytes (`REQ1-HEADER-thumbprint`).
//! Issuer-key fingerprinting uses the SAME construction over the caller's raw
//! 32-byte public key; `kid` is excluded (`REQ1-HEADER-issuer-fingerprint`).
//!
//! # Thumbprint preimage byte-exactness
//!
//! RFC 7638 §3.1 constructs the preimage by serializing the JWK with ONLY the
//! required members, lexicographically sorted by UTF-16 code unit. For an
//! Ed25519 OKP key the sorted member order is `crv` < `kty` < `x`, so the
//! preimage is byte-identical to the canonical JWK this module emits —
//! [`thumbprint_preimage`] delegates to [`jwk_encode_public`]. The SHA-256 is
//! computed over those exact UTF-8 bytes; a single transposed member or a
//! stray space silently produces a wrong key identity, so the order is pinned
//! by the corpus `jwk.thumbprint` + `jwk.thumbprint_preimage` valid cases.

use crate::base64url::{base64url_decode, base64url_encode};
use crate::bounds::Bounds;
use crate::error::{Invalid, Result};
use crate::json::{json_decode, JsonValue};
use sha2::{Digest, Sha256};

/// The fixed `crv` (curve) member value for Ed25519 OKP keys (RFC 8037).
const CRV_ED25519: &str = "Ed25519";
/// The fixed `kty` (key type) member value for Octet Key Pair keys (RFC 7517).
const KTY_OKP: &str = "OKP";

/// The fixed width of an Ed25519 public key in bytes (RFC 8032).
const PUBLIC_KEY_WIDTH: usize = 32;

/// Encode a 32-byte Ed25519 public key as the canonical JWK JSON object.
///
/// Emits the three RFC 7638 preimage members in their lexicographic
/// (`crv`, `kty`, `x`) order, with no whitespace and no additional members:
///
/// ```json
/// {"crv":"Ed25519","kty":"OKP","x":"<canonical_base64url_32_bytes>"}
/// ```
///
/// The `x` coordinate is the canonical unpadded base64url of the 32 raw key
/// bytes. The output is byte-identical to the RFC 7638 thumbprint preimage
/// (see [`thumbprint_preimage`]). Infallible: the 32-byte width is fixed by
/// the parameter type, so no width check is possible or needed at this
/// boundary (`REQ1-HEADER-proof-jwk`).
pub fn jwk_encode_public(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> Vec<u8> {
    let x = base64url_encode(public_key);
    // Exact bytes: no whitespace, crv<kty<x order (the RFC 7638 preimage order).
    let mut out = Vec::with_capacity(34 + x.len() + 2);
    out.extend_from_slice(br#"{"crv":""#);
    out.extend_from_slice(CRV_ED25519.as_bytes());
    out.extend_from_slice(b"\",\"kty\":\"");
    out.extend_from_slice(KTY_OKP.as_bytes());
    out.extend_from_slice(b"\",\"x\":\"");
    out.extend_from_slice(&x);
    out.extend_from_slice(b"\"}");
    out
}

/// Decode a JWK JSON text into the 32-byte Ed25519 public key.
///
/// Parses `text` via the duplicate-rejecting, closed-set JSON decoder
/// (inheriting `REQ1-JSON-no-duplicate`, `REQ1-JSON-single-value`, and the
/// raw-lexeme / magnitude bounds) and then enforces the exact Ed25519/OKP
/// JWK shape. Returns `Err(Invalid)` for any of:
/// - malformed JSON or a non-object root (`REQ1-HEADER-proof-jwk`);
/// - a member set other than exactly `{crv, kty, x}` — any extra member,
///   including the private `d`, is rejected (`REQ1-HEADER-no-private-jwk`);
/// - `crv` other than `"Ed25519"` or `kty` other than `"OKP"`;
/// - a non-string or wrong-valued `crv` / `kty` / `x`;
/// - an `x` that is not canonical unpadded base64url of exactly 32 bytes.
pub fn jwk_decode_public(text: &[u8]) -> Result<[u8; PUBLIC_KEY_WIDTH]> {
    // Parse under profile maxima (the JWK is a tiny fixed-shape object well
    // within every ceiling; no caller tightening applies at this primitive).
    let value = json_decode(text, &Bounds::maximum())?;
    let members = match value {
        JsonValue::Object(m) => m,
        _ => return Err(Invalid),
    };

    // Walk the members, accepting only the three known names and rejecting
    // everything else (catches the private `d`, `kid`, `alg`, and any future
    // extension). The closed-set check is per-member, so a JWK with the right
    // three names PLUS an extra is rejected here, not by a separate count.
    let mut crv = None;
    let mut kty = None;
    let mut x = None;
    for (name, val) in members {
        match name.as_str() {
            "crv" => crv = Some(val),
            "kty" => kty = Some(val),
            "x" => x = Some(val),
            _ => return Err(Invalid), // unknown member — closed set (REQ1-HEADER-no-private-jwk)
        }
    }

    // crv must be exactly the string "Ed25519".
    match crv {
        Some(JsonValue::String(s)) if s == CRV_ED25519 => {}
        _ => return Err(Invalid),
    }
    // kty must be exactly the string "OKP".
    match kty {
        Some(JsonValue::String(s)) if s == KTY_OKP => {}
        _ => return Err(Invalid),
    }
    // x must be a string whose canonical base64url decodes to exactly 32 bytes.
    let x_str = match x {
        Some(JsonValue::String(s)) => s,
        _ => return Err(Invalid),
    };
    let x_bytes = base64url_decode(x_str.as_bytes())?;
    if x_bytes.len() != PUBLIC_KEY_WIDTH {
        return Err(Invalid);
    }
    let mut arr = [0u8; PUBLIC_KEY_WIDTH];
    arr.copy_from_slice(&x_bytes);
    Ok(arr)
}

/// The RFC 7638 thumbprint preimage for an Ed25519 public key.
///
/// Returns the exact UTF-8 bytes of the sorted JSON object
/// `{"crv":"Ed25519","kty":"OKP","x":"<canonical-x>"}` — the three required
/// members in lexicographic order, no whitespace (`REQ1-HEADER-thumbprint`).
/// This is byte-identical to [`jwk_encode_public`]: for an Ed25519 OKP key the
/// RFC 7638 preimage IS the canonical sorted JWK.
pub fn thumbprint_preimage(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> Vec<u8> {
    jwk_encode_public(public_key)
}

/// The RFC 7638 thumbprint: unpadded base64url SHA-256 of the preimage bytes.
///
/// `REQ1-HEADER-thumbprint`: thumbprint = base64url(SHA-256(preimage UTF-8)).
pub fn thumbprint(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> Vec<u8> {
    base64url_encode(&thumbprint_raw(public_key))
}

/// The raw 32-byte SHA-256 digest of the thumbprint preimage.
///
/// `REQ1-HEADER-digest-width`: verified facts carry the raw 32-byte digest.
pub fn thumbprint_raw(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> [u8; PUBLIC_KEY_WIDTH] {
    let preimage = thumbprint_preimage(public_key);
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let output = hasher.finalize();
    let mut arr = [0u8; PUBLIC_KEY_WIDTH];
    arr.copy_from_slice(&output);
    arr
}

/// The issuer-key fingerprint: the same RFC 7638 construction over the
/// caller's raw 32-byte public key (`kid` excluded).
///
/// `REQ1-HEADER-issuer-fingerprint`: the issuer fingerprint uses exactly the
/// same `{crv, kty, x}` preimage + SHA-256 as the holder thumbprint — the only
/// difference is naming (the input is the caller's raw trusted key, not a
/// decoded proof JWK). `kid` never enters the preimage.
pub fn public_key_thumbprint_raw(public_key: &[u8; PUBLIC_KEY_WIDTH]) -> [u8; PUBLIC_KEY_WIDTH] {
    thumbprint_raw(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical corpus public key (base64url of 32 bytes) used across the
    /// 6 JWK surfaces.
    const CORPUS_X: &str = "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk";

    fn corpus_key() -> [u8; PUBLIC_KEY_WIDTH] {
        let bytes = crate::base64url_decode(CORPUS_X.as_bytes()).expect("corpus x decodes");
        assert_eq!(bytes.len(), PUBLIC_KEY_WIDTH, "corpus x is 32 bytes");
        let mut arr = [0u8; PUBLIC_KEY_WIDTH];
        arr.copy_from_slice(&bytes);
        arr
    }

    // ==========================================================================
    // jwk_encode_public — exact bytes, RFC 7638 preimage order
    // ==========================================================================

    #[test]
    fn encode_public_emits_exact_canonical_bytes() {
        let key = corpus_key();
        let encoded = jwk_encode_public(&key);
        let expected = concat!(
            r#"{"crv":"Ed25519","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(std::str::from_utf8(&encoded).unwrap(), expected);
    }

    #[test]
    fn encode_public_has_no_whitespace_and_three_members() {
        let key = corpus_key();
        let encoded_bytes = jwk_encode_public(&key);
        let encoded = std::str::from_utf8(&encoded_bytes).unwrap();
        assert!(!encoded.contains(' '), "no spaces");
        assert!(!encoded.contains('\n'), "no newlines");
        // Exactly three members -> three colons, two commas.
        assert_eq!(encoded.matches(':').count(), 3, "three members");
        assert_eq!(encoded.matches(',').count(), 2, "two separators");
    }

    #[test]
    fn encode_public_round_trips_through_decode() {
        let key = corpus_key();
        let encoded = jwk_encode_public(&key);
        let decoded = jwk_decode_public(&encoded).expect("round-trip decodes");
        assert_eq!(decoded, key);
    }

    // ==========================================================================
    // jwk_decode_public — valid shape + member-order insensitivity
    // ==========================================================================

    #[test]
    fn decode_public_accepts_canonical_order() {
        let text = concat!(
            r#"{"crv":"Ed25519","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        let key = jwk_decode_public(text.as_bytes()).expect("decodes");
        assert_eq!(key, corpus_key());
    }

    #[test]
    fn decode_public_accepts_any_member_order() {
        // REQ1-HEADER-proof-jwk: member order is insignificant. The corpus
        // valid case uses crv,kty,x; a different legal order must also decode.
        let key = corpus_key();
        let expected_x = CORPUS_X;
        for text in [
            format!(r#"{{"x":"{expected_x}","crv":"Ed25519","kty":"OKP"}}"#),
            format!(r#"{{"kty":"OKP","x":"{expected_x}","crv":"Ed25519"}}"#),
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{expected_x}"}}"#),
        ] {
            let got = jwk_decode_public(text.as_bytes()).expect("any order decodes");
            assert_eq!(got, key, "order {text} must decode to the same key");
        }
    }

    // ==========================================================================
    // Closure — no-private-jwk: any member beyond {crv,kty,x} is invalid
    // ==========================================================================

    #[test]
    fn rejects_private_d_member() {
        // REQ1-HEADER-no-private-jwk: a JWK carrying the private `d` is invalid,
        // even alongside valid crv/kty/x. This is the load-bearing no-private
        // closure: a permissive decoder that ignores unknown members would
        // silently accept a private key.
        // The JWK text must be VALID JSON (x value closed, d appended as a
        // fourth member) so the rejection is attributable to the closed-set
        // member check, not to malformed JSON. Built with format! to avoid
        // concat! quote-counting errors that silently produce malformed JSON.
        let x = CORPUS_X;
        let d = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 A's
        let text = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}","d":"{d}"}}"#);
        // Sanity: the text must parse as JSON (proves the test is non-vacuous —
        // the rejection comes from the member-set check, not malformed JSON).
        assert!(crate::json::json_decode(text.as_bytes(), &Bounds::maximum()).is_ok());
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_kid_member() {
        // kid is also an extra member — rejected by the closed-set rule.
        let text = concat!(
            r#"{"crv":"Ed25519","kid":"issuer-1","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_alg_member() {
        let text = concat!(
            r#"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_missing_required_member() {
        // Missing x -> x is None -> Invalid (wrong member set).
        let text = r#"{"crv":"Ed25519","kty":"OKP"}"#;
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
        // Missing crv.
        let text = concat!(
            r#"{"kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    // ==========================================================================
    // Closure — wrong crv / wrong kty
    // ==========================================================================

    #[test]
    fn rejects_wrong_crv() {
        let text = concat!(
            r#"{"crv":"Ed448","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_wrong_kty() {
        let text = concat!(
            r#"{"crv":"Ed25519","kty":"EC","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_non_string_crv_kty_x() {
        // A non-string crv is rejected by the value-type check.
        let text = r#"{"crv":1,"kty":"OKP","x":"W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk"}"#;
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
        let text = r#"{"crv":"Ed25519","kty":1,"x":"W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk"}"#;
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
        let text = r#"{"crv":"Ed25519","kty":"OKP","x":1}"#;
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    // ==========================================================================
    // Closure — wrong-width x (must decode to exactly 32 bytes)
    // ==========================================================================

    #[test]
    fn rejects_short_31_byte_x() {
        // 31 raw bytes -> base64url is 42 chars; the wrong-width closure must
        // reject it even though the base64url itself is canonical.
        let short = vec![0u8; 31];
        let x_b64 = String::from_utf8(base64url_encode(&short)).unwrap();
        assert_eq!(x_b64.len(), 42);
        let text = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_long_33_byte_x() {
        let long = vec![0u8; 33];
        let x_b64 = String::from_utf8(base64url_encode(&long)).unwrap();
        let text = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_non_canonical_x_encoding() {
        // REQ1-B64-canonical (inherited): the `x` value must be canonical
        // base64url. `AB` has non-zero unused pad bits and is rejected by the
        // canonical re-encode check inside base64url_decode.
        let text = r#"{"crv":"Ed25519","kty":"OKP","x":"AB"}"#;
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    // ==========================================================================
    // Closure — malformed JSON / non-object / duplicate members
    // ==========================================================================

    #[test]
    fn rejects_non_object_root() {
        assert_eq!(jwk_decode_public(b"[]"), Err(Invalid));
        assert_eq!(jwk_decode_public(b"\"not-an-object\""), Err(Invalid));
        assert_eq!(jwk_decode_public(b"42"), Err(Invalid));
        assert_eq!(jwk_decode_public(b"null"), Err(Invalid));
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(jwk_decode_public(b"not-a-jwk"), Err(Invalid));
        assert_eq!(jwk_decode_public(b""), Err(Invalid));
        assert_eq!(jwk_decode_public(b"{"), Err(Invalid));
    }

    #[test]
    fn rejects_duplicate_member() {
        // REQ1-JSON-no-duplicate (inherited from json_decode): a duplicate crv
        // is rejected before the JWK shape check.
        let text = concat!(
            r#"{"crv":"Ed25519","crv":"Ed448","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(jwk_decode_public(text.as_bytes()), Err(Invalid));
    }

    #[test]
    fn rejects_tampered_object_opener() {
        // The corpus tamper case: first byte `{` (0x7B) XOR 1 = `z` (0x7A).
        let mut text = concat!(
            r#"{"crv":"Ed25519","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        )
        .as_bytes()
        .to_vec();
        text[0] ^= 1;
        assert_eq!(text[0], b'z');
        assert_eq!(jwk_decode_public(&text), Err(Invalid));
    }

    // ==========================================================================
    // Thumbprint family — preimage byte-exactness + internal consistency
    // ==========================================================================

    #[test]
    fn thumbprint_preimage_is_exact_sorted_json() {
        let key = corpus_key();
        let preimage = thumbprint_preimage(&key);
        let expected = concat!(
            r#"{"crv":"Ed25519","kty":"OKP","x":""#,
            "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk",
            r#""}"#
        );
        assert_eq!(std::str::from_utf8(&preimage).unwrap(), expected);
    }

    #[test]
    fn preimage_equals_encoded_jwk() {
        // RFC 7638: the preimage IS the canonical sorted JWK. For Ed25519 OKP
        // these must be byte-identical.
        let key = corpus_key();
        assert_eq!(thumbprint_preimage(&key), jwk_encode_public(&key));
    }

    #[test]
    fn preimage_order_is_crv_kty_x_not_insertion() {
        // RED-capable: the preimage MUST be lexicographic (crv, kty, x). If the
        // encoder emitted insertion order or any other order, the corpus
        // thumbprint would mismatch. Assert the exact member sequence.
        let key = corpus_key();
        let preimage_bytes = thumbprint_preimage(&key);
        let preimage = std::str::from_utf8(&preimage_bytes).unwrap();
        let crv_pos = preimage.find("\"crv\"").unwrap();
        let kty_pos = preimage.find("\"kty\"").unwrap();
        let x_pos = preimage.find("\"x\"").unwrap();
        assert!(crv_pos < kty_pos, "crv before kty");
        assert!(kty_pos < x_pos, "kty before x");
    }

    #[test]
    fn thumbprint_matches_corpus_pinned_value() {
        // The corpus jwk-thumbprint-valid case pins this exact base64url.
        let key = corpus_key();
        let tp = thumbprint(&key);
        assert_eq!(
            String::from_utf8(tp).unwrap(),
            "d4ucEZwvJTfwxXCN4f2xmIE5ZBFoH5i5mlzeWZaB3yI"
        );
    }

    #[test]
    fn thumbprint_raw_base64url_equals_thumbprint() {
        // Internal consistency: base64url(thumbprint_raw) == thumbprint.
        let key = corpus_key();
        let raw_b64 = base64url_encode(&thumbprint_raw(&key));
        assert_eq!(raw_b64, thumbprint(&key));
    }

    #[test]
    fn issuer_fingerprint_equals_holder_thumbprint_raw() {
        // REQ1-HEADER-issuer-fingerprint: the issuer form uses the SAME
        // construction as the holder thumbprint; for the same key they are
        // identical (the only difference is naming / input source).
        let key = corpus_key();
        assert_eq!(public_key_thumbprint_raw(&key), thumbprint_raw(&key));
    }

    #[test]
    fn different_keys_produce_different_thumbprints() {
        // A single-byte flip in the key must change the thumbprint (catches a
        // constant-output bug).
        let key = corpus_key();
        let mut other = key;
        other[0] ^= 0xff;
        assert_ne!(thumbprint_raw(&key), thumbprint_raw(&other));
        assert_ne!(thumbprint(&key), thumbprint(&other));
    }

    // ==========================================================================
    // Corpus: priv/conformance/v1/corpus/cases/jwk/jwk.json (16 cases, 6 surfaces)
    // ==========================================================================

    fn corpus_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("priv")
            .join("conformance")
            .join("v1")
            .join("corpus")
            .join("cases")
            .join("jwk")
            .join("jwk.json")
    }

    /// Decodes a corpus `public_key` (base64url) field to a 32-byte array, or
    /// returns `None` if the width is not exactly 32. This mirrors the runner's
    /// import boundary: a wrong-width key is the `invalid_key` verdict and
    /// never reaches the `[u8;32]`-typed function.
    fn public_key_input(field: &serde_json::Value) -> Option<[u8; PUBLIC_KEY_WIDTH]> {
        let b64 = field.as_str()?;
        let raw = crate::base64url_decode(b64.as_bytes()).ok()?;
        if raw.len() != PUBLIC_KEY_WIDTH {
            return None;
        }
        let mut arr = [0u8; PUBLIC_KEY_WIDTH];
        arr.copy_from_slice(&raw);
        Some(arr)
    }

    #[test]
    fn corpus_jwk_all_16_cases() {
        let path = corpus_path();
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let root: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        let cases = root["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("cases array"));

        assert_eq!(cases.len(), 16, "jwk corpus has 16 cases");

        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        let mut per_surface: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();

        for case in cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let surface = case["surface"].as_str().unwrap_or("<no surface>");
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            *per_surface.entry(surface).or_default() += 1;

            // Each surface returns `agree: bool` — the verdict matches AND any
            // pinned value field (encoded / public_key / thumbprint / preimage)
            // matches byte-for-byte.
            let agree = match surface {
                "jwk.encode_public" => {
                    let key = public_key_input(&case["input"]["public_key"]);
                    match (key, expected_verdict) {
                        (Some(key), "valid") => {
                            let encoded = jwk_encode_public(&key);
                            let expected_encoded =
                                case["expected"]["encoded"].as_str().unwrap_or_else(|| {
                                    panic!("valid case {id} missing expected.encoded")
                                });
                            String::from_utf8(encoded).unwrap() == expected_encoded
                        }
                        (None, "invalid") => true, // wrong-width key -> invalid_key
                        (Some(_), "invalid") => false,
                        (None, "valid") => false,
                        _ => false,
                    }
                }
                "jwk.decode_public" => match jwk_decode_public(
                    case["input"]["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("case {id} missing input.text"))
                        .as_bytes(),
                ) {
                    Ok(key) if expected_verdict == "valid" => {
                        let expected_pk =
                            case["expected"]["public_key"].as_str().unwrap_or_else(|| {
                                panic!("valid case {id} missing expected.public_key")
                            });
                        String::from_utf8(base64url_encode(&key)).unwrap() == expected_pk
                    }
                    Err(Invalid) => expected_verdict == "invalid",
                    Ok(_) => false,
                },
                "jwk.thumbprint" => match jwk_decode_public(
                    case["input"]["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("case {id} missing input.text"))
                        .as_bytes(),
                ) {
                    Ok(key) if expected_verdict == "valid" => {
                        let tp = thumbprint(&key);
                        let expected_tp =
                            case["expected"]["thumbprint"].as_str().unwrap_or_else(|| {
                                panic!("valid case {id} missing expected.thumbprint")
                            });
                        String::from_utf8(tp).unwrap() == expected_tp
                    }
                    Err(Invalid) => expected_verdict == "invalid",
                    Ok(_) => false,
                },
                "jwk.thumbprint_preimage" => match jwk_decode_public(
                    case["input"]["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("case {id} missing input.text"))
                        .as_bytes(),
                ) {
                    Ok(key) if expected_verdict == "valid" => {
                        let preimage = thumbprint_preimage(&key);
                        let expected_preimage = case["expected"]["preimage"]
                            .as_str()
                            .unwrap_or_else(|| panic!("valid case {id} missing expected.preimage"));
                        String::from_utf8(preimage).unwrap() == expected_preimage
                    }
                    Err(Invalid) => expected_verdict == "invalid",
                    Ok(_) => false,
                },
                "jwk.thumbprint_raw" => match jwk_decode_public(
                    case["input"]["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("case {id} missing input.text"))
                        .as_bytes(),
                ) {
                    // The corpus pins verdict only (no raw value to compare);
                    // a valid case just needs the call to succeed.
                    Ok(_) if expected_verdict == "valid" => true,
                    Err(Invalid) => expected_verdict == "invalid",
                    Ok(_) => false,
                },
                "jwk.public_key_thumbprint_raw" => {
                    let key = public_key_input(&case["input"]["public_key"]);
                    match (key, expected_verdict) {
                        (Some(key), "valid") => {
                            // Verdict-only pin: the call must succeed.
                            let _ = public_key_thumbprint_raw(&key);
                            true
                        }
                        (None, "invalid") => true, // wrong-width key -> invalid_key
                        (Some(_), "invalid") => false,
                        (None, "valid") => false,
                        _ => false,
                    }
                }
                other => panic!("case {id}: unknown surface {other}"),
            };

            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} surface={surface} expected={expected_verdict}");
            }
        }

        eprintln!("per_surface: {per_surface:?}");
        eprintln!("agreed={agreed} disagreed={disagreed}");
        assert_eq!(agreed, 16, "agreed (jwk corpus == 16)");
        assert_eq!(disagreed, 0, "disagreed");
        // Cross-check the per-surface applicability the index.json matrix pins.
        assert_eq!(per_surface["jwk.encode_public"], 2, "encode_public");
        assert_eq!(per_surface["jwk.decode_public"], 3, "decode_public");
        assert_eq!(per_surface["jwk.thumbprint"], 3, "thumbprint");
        assert_eq!(
            per_surface["jwk.thumbprint_preimage"], 3,
            "thumbprint_preimage"
        );
        assert_eq!(per_surface["jwk.thumbprint_raw"], 3, "thumbprint_raw");
        assert_eq!(
            per_surface["jwk.public_key_thumbprint_raw"], 2,
            "public_key_thumbprint_raw"
        );
    }
}
