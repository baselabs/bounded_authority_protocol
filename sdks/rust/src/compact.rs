//! Compact-JWS composition + parse (RFC 7515 §7.1) — the
//! `REQ1-SIGNING-exact-input` mechanic.
//!
//! The JWS compact serialization is
//! `BASE64URL(protected) || "." || BASE64URL(payload) || "." || BASE64URL(signature)`
//! (RFC 7515 §7.1). The **signing input** — the two-segment message that was
//! actually signed — is `ASCII(BASE64URL(protected) || "." || BASE64URL(payload))`
//! (`REQ1-SIGNING-exact-input`): no bytes precede or follow it.
//!
//! [`assemble_compact`] composes the three-segment form from an already-encoded
//! [`SigningInput`] and a raw 64-byte signature. The protected / payload
//! segments are already canonical base64url ASCII and pass through VERBATIM
//! (the producer's deterministic JCS representation is the contract;
//! `REQ1-SIGNING-any-order` — a correctly signed closed JSON object may use any
//! member order, so the composer must not re-encode or re-validate them); only
//! the signature is base64url-encoded. [`parse_compact`] is the inverse
//! structural split, enforcing exactly three non-empty canonical segments.
//!
//! Derived first-hand from `docs/protocol-v1.md` § Signing and digest inputs
//! (lines 246–261) and RFC 7515 §7.1 — NOT from any sibling-SDK or Elixir
//! source (ADR 0014 D5).

// `assemble_compact` is `pub` (re-exported at the crate root by the Façade A
// `pub use compact::assemble_compact;` in lib.rs) and `parse_compact` is
// `pub(crate)` (called by v1::decode_grant / decode_proof). Both are now
// reachable from the crate root through the Façade A call chain.
use crate::base64url::{base64url_decode, base64url_encode};
use crate::error::{Invalid, Result};
use crate::types::SigningInput;

/// Compose the 3-segment compact serialization from a signing input + raw
/// signature — the internal composer. The public [`crate::assemble_compact`]
/// (re-exported from the v1 façade) wraps this with per-kind content validation
/// (the reference `validate_assembled_compact`, runtime.ex:151).
///
/// Returns
/// `protected_segment || "." || payload_segment || "." || base64url(signature)`.
///
/// The protected / payload segments are passed through VERBATIM (byte-for-byte)
/// and the composed compact is validated for segment well-formedness via
/// [`parse_compact`] (three non-empty canonical unpadded base64url segments).
/// Returns `Err(Invalid)` when the composed bytes are not three canonical
/// base64url segments.
pub(crate) fn compose_compact(input: &SigningInput, signature: &[u8; 64]) -> Result<Vec<u8>> {
    // base64url of 64 bytes is always 86 chars (64 = 16 groups of 3 + ... ; 64
    // is not a multiple of 3, so the trailing group of 1 byte -> 2 chars;
    // 64/3 = 21 full groups (63 bytes) -> 84 chars + 1 trailing group of 1
    // byte -> 2 chars = 86). Plus two '.' separators.
    let mut out =
        Vec::with_capacity(input.protected_segment.len() + input.payload_segment.len() + 2 + 86);
    out.extend_from_slice(&input.protected_segment);
    out.push(b'.');
    out.extend_from_slice(&input.payload_segment);
    out.push(b'.');
    out.extend_from_slice(&base64url_encode(signature));
    // Segment well-formedness: three non-empty canonical unpadded base64url
    // segments. Per-kind CONTENT validation (closed header/claim set) is the
    // public façade wrapper's job (v1::assemble_compact).
    parse_compact(&out)?;
    Ok(out)
}

/// Parse the 3-segment compact serialization into its raw canonical segments.
///
/// Splits `text` on `.` requiring EXACTLY three non-empty segments, each
/// canonical unpadded base64url. Returns the three raw segment byte slices
/// (borrowed from `text`); the caller decodes them via
/// [`base64url_decode`] / [`crate::json::json_decode`] as needed. The
/// signature-segment width (must decode to 64 bytes) is NOT enforced here —
/// that is the façade's responsibility; this parser only asserts the
/// `REQ1-SIGNING-exact-input` shape.
///
/// Rejects (`Invalid`): more or fewer than three segments, an empty segment
/// (leading / trailing / doubled `.`), and any segment that is not canonical
/// base64url (padding `=`, standard-alphabet `+`/`/`, whitespace, `len % 4 ==
/// 1`, or non-zero unused pad bits — all inherited from [`base64url_decode`]'s
/// `REQ1-B64-*` enforcement).
pub(crate) fn parse_compact(text: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let mut iter = text.split(|&b| b == b'.');
    // split always yields at least one element (possibly empty) for a non-empty
    // or empty input; `""` yields one empty slice.
    let seg0 = iter.next().unwrap_or(&[]);
    let seg1 = iter.next().ok_or(Invalid)?;
    let seg2 = iter.next().ok_or(Invalid)?;
    // A fourth segment (3+ dots) means more than three segments -> Invalid.
    if iter.next().is_some() {
        return Err(Invalid);
    }
    validate_segment(seg0)?;
    validate_segment(seg1)?;
    validate_segment(seg2)?;
    Ok((seg0, seg1, seg2))
}

/// Asserts one segment is non-empty and canonical unpadded base64url.
///
/// Decodes (and discards the decoded bytes — only validity is needed here) to
/// inherit every `REQ1-B64-*` rule from [`base64url_decode`]: alphabet, no
/// padding, no whitespace, length mod 4, and the canonical re-encode check.
fn validate_segment(seg: &[u8]) -> Result<()> {
    if seg.is_empty() {
        return Err(Invalid);
    }
    // REQ1-SIGNING-exact-input: each segment must be canonical unpadded
    // base64url. base64url_decode enforces REQ1-B64-alphabet / -no-padding /
    // -length / -canonical; map any failure to Invalid.
    base64url_decode(seg).map(|_| ()).map_err(|_| Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64url::base64url_decode;
    use crate::types::{SigningInput, SigningKind};

    /// Canonical base64url segments from RFC 4648 (3 bytes -> 4 chars, no pad).
    const SEG_ABC: &[u8] = b"YWJj"; // "abc"
    const SEG_DEF: &[u8] = b"ZGVm"; // "def"
    const SEG_GHI: &[u8] = b"Z2hp"; // "ghi"

    fn to_arr_64(v: Vec<u8>) -> [u8; 64] {
        assert_eq!(v.len(), 64, "expected 64 bytes");
        let mut a = [0u8; 64];
        a.copy_from_slice(&v);
        a
    }

    // ==========================================================================
    // assemble_compact — verbatim segment pass-through + signature encode
    // ==========================================================================

    #[test]
    fn assemble_concatenates_segments_and_encodes_signature() {
        // assemble must pass the segments through VERBATIM and append
        // base64url(signature); no re-encode / re-validation of the segments.
        let sig_raw = to_arr_64(base64url_decode(
            b"NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA",
        )
        .expect("sig decodes"));
        let input = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: SEG_ABC.to_vec(),
            payload_segment: SEG_DEF.to_vec(),
        };
        let compact = compose_compact(&input, &sig_raw).expect("assemble");
        // Third segment is base64url_encode of the raw 64 bytes (canonical, so
        // it round-trips to the input b64u).
        let mut expected = Vec::new();
        expected.extend_from_slice(SEG_ABC);
        expected.push(b'.');
        expected.extend_from_slice(SEG_DEF);
        expected.push(b'.');
        expected.extend_from_slice(&base64url_encode(&sig_raw));
        assert_eq!(compact, expected);
    }

    #[test]
    fn assemble_rejects_non_canonical_or_empty_segment() {
        // validate_assembled_compact (reference runtime.ex:151): the composed
        // compact must be three canonical base64url segments. A caller-supplied
        // protected segment carrying standard-alphabet `+` (NOT base64url) or an
        // empty segment is rejected, not composed into a malformed compact.
        // RED-capable: removing the `parse_compact(&out)?` call makes these accept.
        let sig_raw = [0u8; 64];
        let bad = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: b"YW+J".to_vec(), // `+` is standard base64, NOT base64url
            payload_segment: SEG_DEF.to_vec(),
        };
        assert_eq!(compose_compact(&bad, &sig_raw), Err(Invalid));
        let empty = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: Vec::new(),
            payload_segment: SEG_DEF.to_vec(),
        };
        assert_eq!(compose_compact(&empty, &sig_raw), Err(Invalid));
    }

    #[test]
    fn assemble_tampered_signature_yields_different_third_segment() {
        // RED-capable: flipping a signature byte before encoding changes the
        // third segment, so two assembles over the same input + a one-byte
        // signature tamper must differ.
        let mut sig_a = [0u8; 64];
        for (i, b) in sig_a.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut sig_b = sig_a;
        sig_b[0] ^= 0x01;
        let input = SigningInput {
            kind: SigningKind::Grant,
            protected_segment: SEG_ABC.to_vec(),
            payload_segment: SEG_DEF.to_vec(),
        };
        let ca = compose_compact(&input, &sig_a).expect("assemble a");
        let cb = compose_compact(&input, &sig_b).expect("assemble b");
        assert_ne!(ca, cb, "tampered signature must change the compact");
        // The first two segments are identical; only the third differs.
        assert_eq!(&ca[..ca.len() - 86], &cb[..cb.len() - 86]);
        assert_ne!(&ca[ca.len() - 86..], &cb[cb.len() - 86..]);
    }

    // ==========================================================================
    // parse_compact — REQ1-SIGNING-exact-input shape enforcement
    // ==========================================================================

    #[test]
    fn parse_valid_three_canonical_segments() {
        let text = b"YWJj.ZGVm.Z2hp";
        let (s0, s1, s2) = parse_compact(text).expect("valid parse");
        assert_eq!(s0, SEG_ABC);
        assert_eq!(s1, SEG_DEF);
        assert_eq!(s2, SEG_GHI);
    }

    #[test]
    fn parse_rejects_four_segments() {
        assert_eq!(parse_compact(b"YWJj.ZGVm.Z2hp.YXNr"), Err(Invalid));
    }

    #[test]
    fn parse_rejects_two_segments() {
        assert_eq!(parse_compact(b"YWJj.ZGVm"), Err(Invalid));
    }

    #[test]
    fn parse_rejects_empty_segment() {
        // Middle empty (doubled dot).
        assert_eq!(parse_compact(b"YWJj..Z2hp"), Err(Invalid));
        // Leading empty.
        assert_eq!(parse_compact(b".ZGVm.Z2hp"), Err(Invalid));
        // Trailing empty.
        assert_eq!(parse_compact(b"YWJj.ZGVm."), Err(Invalid));
    }

    #[test]
    fn parse_rejects_padding() {
        // REQ1-B64-no-padding: `=` is outside the alphabet.
        assert_eq!(parse_compact(b"YWJj.ZGVm.Zg=="), Err(Invalid));
    }

    #[test]
    fn parse_rejects_standard_base64_alphabet() {
        // REQ1-B64-alphabet: `+` and `/` are standard base64, NOT base64url.
        assert_eq!(parse_compact(b"YW+J.ZGVm.Z2hp"), Err(Invalid));
        assert_eq!(parse_compact(b"YW/J.ZGVm.Z2hp"), Err(Invalid));
    }

    #[test]
    fn parse_rejects_non_canonical_pad_bits() {
        // REQ1-B64-canonical: `AB` has non-zero unused pad bits (re-encodes to
        // `AA`). Each of the three positions must reject it.
        assert_eq!(parse_compact(b"AB.ZGVm.Z2hp"), Err(Invalid));
        assert_eq!(parse_compact(b"YWJj.AB.Z2hp"), Err(Invalid));
        assert_eq!(parse_compact(b"YWJj.ZGVm.AB"), Err(Invalid));
    }

    #[test]
    fn parse_segments_are_borrowed_slices_of_input() {
        // The returned slices borrow from `text` (zero-alloc).
        let text = b"YWJj.ZGVm.Z2hp";
        let (s0, _, _) = parse_compact(text).expect("parse");
        assert_eq!(s0.as_ptr(), text[..4].as_ptr());
    }

    // ==========================================================================
    // Corpus: priv/conformance/v1/corpus/cases/assemble-compact/assemble.json
    // (2 cases: 1 valid, 1 invalid_encoding)
    // ==========================================================================

    #[test]
    fn corpus_assemble_compact_all_2_cases() {
        let path = format!(
            "{}/../../priv/conformance/v1/corpus/cases/assemble-compact/assemble.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read corpus {path}: {e}"));
        let root: serde_json::Value =
            serde_json::from_str(&content).expect("corpus file is valid JSON");
        let cases = root["cases"].as_array().expect("cases array");
        assert_eq!(cases.len(), 2, "assemble-compact corpus has 2 cases");

        let mut agreed = 0usize;
        let mut disagreed = 0usize;

        for case in cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            let protected = case["input"]["protected_segment"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing protected_segment"))
                .as_bytes();
            let payload = case["input"]["payload_segment"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing payload_segment"))
                .as_bytes();
            let kind_str = case["input"]["kind"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing kind"));
            let sig_b64 = case["input"]["signature"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing signature"));
            // The import boundary: the raw signature must decode to exactly 64
            // bytes to form the [u8;64] arg. The invalid corpus case
            // (`assemble-compact-invalid-short-signature`, sig "AAEC" -> 3
            // bytes) is rejected right here — it never reaches assemble_compact.
            let sig_decoded = base64url_decode(sig_b64.as_bytes());
            let sig_is_64 = sig_decoded.as_ref().map(|r| r.len() == 64).unwrap_or(false);

            let agree = match (expected_verdict, sig_is_64) {
                ("valid", true) => {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&sig_decoded.unwrap());
                    let kind = SigningKind::decode(kind_str).expect("valid case has known kind");
                    let input = SigningInput {
                        kind,
                        protected_segment: protected.to_vec(),
                        payload_segment: payload.to_vec(),
                    };
                    let compact = compose_compact(&input, &sig).expect("valid case assembles");
                    let expected_compact = case["expected"]["compact"]
                        .as_str()
                        .unwrap_or_else(|| panic!("valid case {id} missing expected.compact"));
                    String::from_utf8(compact).unwrap() == expected_compact
                }
                ("invalid", false) => true, // short-signature reject, as expected
                _ => false,
            };

            if agree {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict} sig_is_64={sig_is_64}");
            }
        }

        assert_eq!(agreed, 2, "agreed (assemble-compact corpus == 2)");
        assert_eq!(disagreed, 0, "disagreed count");
    }
}
