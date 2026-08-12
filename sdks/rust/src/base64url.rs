//! Canonical base64url encode/decode (RFC 4648 §5, unpadded).
//!
//! Hand-rolled per the design note (decision D4): the canonical re-encode
//! check is protocol-specific (`REQ1-B64-canonical`), so dropping the `base64`
//! crate both hand-verifies the semantics and shrinks the supply-chain surface.
//!
//! Rules enforced (`docs/protocol-v1.md` § Base64url, lines 131–135):
//! - `REQ1-B64-alphabet`: only `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`.
//! - `REQ1-B64-no-padding`: padding (`=`) and whitespace are forbidden.
//! - `REQ1-B64-length`: `input.len() % 4 == 1` is invalid.
//! - `REQ1-B64-canonical`: decode succeeds only when unpadded re-encoding
//!   reproduces the input exactly — rejects non-zero unused pad bits and any
//!   alternate encoding of the same bytes.

use crate::error::{Invalid, Result};

/// The RFC 4648 §5 base64url alphabet (URL- and filename-safe: `-` and `_`
/// replace `+` and `/`). No padding character is emitted.
const ENCODE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as unpadded base64url (RFC 4648 §5).
///
/// Deterministic and total: every byte sequence maps to exactly one canonical
/// encoding. No padding is emitted.
pub fn base64url_encode(input: &[u8]) -> Vec<u8> {
    // Worst-case output is 4 chars per 3 input bytes; the trailing group emits
    // fewer. `+ 4` covers the partial group without an extra branch.
    let mut out = Vec::with_capacity(input.len() / 3 * 4 + 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ENCODE_ALPHABET[((n >> 18) & 0x3F) as usize]);
        out.push(ENCODE_ALPHABET[((n >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            out.push(ENCODE_ALPHABET[((n >> 6) & 0x3F) as usize]);
        }
        if chunk.len() > 2 {
            out.push(ENCODE_ALPHABET[(n & 0x3F) as usize]);
        }
    }
    out
}

/// Map one base64url character to its 6-bit value.
///
/// Returns `None` for any byte outside `A-Za-z0-9-_`, which covers the `=`
/// padding character (RFC 4648 §5 forbids it in the unpadded variant) and all
/// whitespace / control bytes (`REQ1-B64-alphabet`, `REQ1-B64-no-padding`).
fn decode_char(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    })
}

/// Decode `input` as unpadded canonical base64url.
///
/// Returns `Err(Invalid)` (`REQ1-B64-alphabet` / `-no-padding` /
/// `-length` / `-canonical`) for: any byte outside the alphabet (incl. `=`
/// padding and whitespace), `input.len() % 4 == 1`, or when the decoded bytes
/// do not round-trip through [`base64url_encode`] byte-for-byte (the canonical
/// check that rejects non-zero unused pad bits and alternate encodings).
pub fn base64url_decode(input: &[u8]) -> Result<Vec<u8>> {
    // REQ1-B64-length: a trailing group of one char carries fewer than 8 bits,
    // which is not a whole byte — invalid. After this check the remainder mod 4
    // is 0, 2, or 3, so every group we enter below has at least two chars.
    if input.len() % 4 == 1 {
        return Err(Invalid);
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let mut i = 0;
    while i < input.len() {
        let c0 = decode_char(input[i]).ok_or(Invalid)?;
        let c1 = decode_char(input[i + 1]).ok_or(Invalid)?;
        out.push((((c0 as u32) << 2) | ((c1 as u32) >> 4)) as u8);

        if i + 2 < input.len() {
            let c2 = decode_char(input[i + 2]).ok_or(Invalid)?;
            out.push(((((c1 as u32) & 0x0F) << 4) | ((c2 as u32) >> 2)) as u8);

            if i + 3 < input.len() {
                let c3 = decode_char(input[i + 3]).ok_or(Invalid)?;
                out.push(((((c2 as u32) & 0x03) << 6) | (c3 as u32)) as u8);
            }
        }
        i += 4;
    }

    // REQ1-B64-canonical: decode succeeds only when unpadded re-encoding
    // reproduces the input exactly. This rejects non-zero unused pad bits (the
    // 2-char group has 4 unused bits; the 3-char group has 2) and any alternate
    // encoding of the same bytes.
    if base64url_encode(&out) != input {
        return Err(Invalid);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Encode / decode round-trip
    // ------------------------------------------------------------------

    #[test]
    fn encode_rfc4648_vectors() {
        // RFC 4648 §10 test vectors mapped to base64url (no padding): `+`→`-`,
        // `/`→`_`, padding stripped.
        assert_eq!(base64url_encode(b""), b"");
        assert_eq!(base64url_encode(b"f"), b"Zg");
        assert_eq!(base64url_encode(b"fo"), b"Zm8");
        assert_eq!(base64url_encode(b"foo"), b"Zm9v");
        assert_eq!(base64url_encode(b"foob"), b"Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), b"Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn round_trip_various_byte_sequences() {
        let cases: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\xff",
            b"hello",
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            b"The quick brown fox jumps over the lazy dog.",
        ];
        for &input in cases {
            let encoded = base64url_encode(input);
            let decoded = base64url_decode(&encoded).expect("round-trip decodes");
            assert_eq!(decoded, input, "round-trip mismatch for {input:?}");
        }
    }

    // ------------------------------------------------------------------
    // Rejection classes
    // ------------------------------------------------------------------

    #[test]
    fn rejects_padding() {
        // REQ1-B64-no-padding: `=` is outside the alphabet.
        assert_eq!(base64url_decode(b"AAA="), Err(Invalid));
        assert_eq!(base64url_decode(b"Zm9vYg=="), Err(Invalid));
        assert_eq!(base64url_decode(b"AAAA===="), Err(Invalid));
    }

    #[test]
    fn rejects_standard_base64_alphabet() {
        // REQ1-B64-alphabet: `+` and `/` are standard base64, NOT base64url.
        assert_eq!(base64url_decode(b"a+b"), Err(Invalid));
        assert_eq!(base64url_decode(b"a/b"), Err(Invalid));
    }

    #[test]
    fn rejects_whitespace() {
        // REQ1-B64-no-padding: whitespace of any kind is forbidden.
        assert_eq!(base64url_decode(b"Zm9v "), Err(Invalid)); // trailing space
        assert_eq!(base64url_decode(b"Z m9v"), Err(Invalid)); // embedded space
        assert_eq!(base64url_decode(b"\tZm9v"), Err(Invalid)); // leading tab
        assert_eq!(base64url_decode(b"Zm9v\n"), Err(Invalid)); // trailing LF
        assert_eq!(base64url_decode(b"Zm9v\r\n"), Err(Invalid)); // CRLF
    }

    #[test]
    fn rejects_length_mod_one() {
        // REQ1-B64-length.
        assert_eq!(base64url_decode(b"A"), Err(Invalid));
        assert_eq!(base64url_decode(b"ABCDE"), Err(Invalid));
        assert_eq!(base64url_decode(b"Zm9vYmFyA"), Err(Invalid)); // valid prefix + 1 trailing
    }

    #[test]
    fn rejects_non_canonical_unused_pad_bits() {
        // REQ1-B64-canonical — the rejection class the corpus does NOT cover
        // (the two corpus invalid cases are caught by padding/alphabet rules).
        //
        // `AB` decodes to `[0x00]` but its trailing 4 bits are `0001` (non-zero),
        // so the canonical re-encode is `AA` != `AB`. A permissive decoder that
        // ignores the unused pad bits would wrongly accept this.
        assert_eq!(base64url_decode(b"AB"), Err(Invalid));
        // 3-char group with non-zero unused 2 bits: `AAB` -> trailing `01`.
        // decodes to `[0x00, 0x00]` but re-encodes to `AAA` != `AAB`.
        assert_eq!(base64url_decode(b"AAB"), Err(Invalid));
    }

    #[test]
    fn accepts_canonical_short_groups() {
        // The mirror of the pad-bits rejection: zero pad bits are canonical.
        assert_eq!(base64url_decode(b"AA"), Ok(vec![0x00]));
        assert_eq!(base64url_decode(b"AAA"), Ok(vec![0x00, 0x00]));
    }

    // ------------------------------------------------------------------
    // Corpus: priv/conformance/v1/corpus/cases/base64url/decode.json (3 cases)
    // ------------------------------------------------------------------

    #[test]
    fn corpus_base64url_decode_all_3_cases() {
        let path = format!(
            "{}/../../priv/conformance/v1/corpus/cases/base64url/decode.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read corpus {path}: {e}"));
        let root: serde_json::Value = serde_json::from_str(&content).expect("corpus is valid JSON");
        let cases = root["cases"].as_array().expect("cases array");

        let mut agreed = 0usize;
        let mut disagreed = 0usize;

        for case in cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            let input = case["input"]["base64url"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing input.base64url"));
            let result = base64url_decode(input.as_bytes());
            let actual_ok = result.is_ok();
            let expected_ok = expected_verdict == "valid";

            if actual_ok == expected_ok {
                if expected_ok {
                    let expected_decoded = case["expected"]["decoded"]
                        .as_str()
                        .unwrap_or_else(|| panic!("valid case {id} missing expected.decoded"));
                    let got = result.expect("valid case decodes");
                    assert_eq!(
                        got,
                        expected_decoded.as_bytes(),
                        "case {id}: decoded bytes mismatch"
                    );
                }
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict} actual_ok={actual_ok}");
            }
        }

        assert_eq!(agreed, 3, "agreed (total corpus cases should be 3)");
        assert_eq!(disagreed, 0, "disagreed count");
    }
}
