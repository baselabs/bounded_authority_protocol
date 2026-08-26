//! Duplicate-rejecting, raw-lexeme, single-value, tagged JSON decoder.
//!
//! Hand-rolled per ADR 0014 D6 / design-note decision D5: `serde_json` is
//! last-wins on duplicate members, unordered by default, and collapses the
//! integer/float tag distinction, so it CANNOT back the protocol's tagged JSON
//! algebra. This decoder is permissiveness closures #1/#3/#4/#5 (the JCS encoder
//! owns the `(d)`-class per-node encode-bounds closure #6).
//!
//! Rules enforced (`spec/bap-v1.md` § JSON algebra and decoding, lines 67–95):
//! - `REQ1-JSON-no-duplicate`: a duplicate member name at ANY depth is rejected
//!   before any map conversion.
//! - `REQ1-JSON-single-value`: the input is exactly one RFC 8259 value followed
//!   only by JSON whitespace; trailing non-whitespace is invalid.
//! - `REQ1-JSON-no-normalization`: UTF-8 is mandatory; strings are preserved
//!   without Unicode normalization (lone surrogates rejected — unrepresentable).
//! - `REQ1-JSON-raw-lexeme`: raw RFC 8259 number lexemes are scanned OUTSIDE
//!   strings; the 64-byte ceiling and exact decimal magnitude (no FP rounding)
//!   are enforced BEFORE host conversion.
//! - `REQ1-JSON-number-bounds`: integers and finite floats are bounded
//!   symmetrically to ±9_007_199_254_740_991.
//! - `REQ1-BOUNDS-ordering`: depth / members / items / total-nodes / string /
//!   object-name / lexeme limits are enforced WHILE decoding.

use crate::bounds::Bounds;
use crate::error::{Invalid, Result};

/// The tagged JSON algebra — mirrors `spec/bap-v1.md` § JSON algebra table.
///
/// `Int(i64)` and `Float(f64)` are DISTINCT variants: `1` decodes to `Int(1)`,
/// `1.0` to `Float(1.0)` (permissiveness closure #5 — selector semantic identity
/// and the typed request-digest projection depend on the tag). `Object` is an
/// ordered `Vec<(String, JsonValue)>` (RFC 8785 sorts at JCS encode time, not
/// here) and is duplicate-free by construction.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A JSON integer lexeme (no `.` and no `e`/`E`), value-bounded to ±2^53−1.
    Int(i64),
    /// A JSON non-integer number (lexeme with `.` or `e`/`E`), magnitude-bounded.
    Float(f64),
    /// A JSON string (valid UTF-8, no Unicode normalization).
    String(String),
    /// A JSON array; source order preserved.
    Array(Vec<JsonValue>),
    /// A JSON object; source member order preserved, duplicate-free.
    Object(Vec<(String, JsonValue)>),
}

/// Decode one RFC 8259 value from `text` under the caller's [`Bounds`].
///
/// Enforces every JSON bound WHILE decoding (`REQ1-BOUNDS-ordering`): raw input
/// bytes first, then structure/scalar limits as each value is built. Returns
/// `Err(Invalid)` for any malformed, over-limit, duplicate-bearing, or
/// multi-valued input.
pub fn json_decode(text: &[u8], bounds: &Bounds) -> Result<JsonValue> {
    // REQ1-BOUNDS-ordering: raw/encoded size precedes decoding.
    if text.len() as u64 > bounds.json_bytes() {
        return Err(Invalid);
    }
    let mut d = Decoder {
        input: text,
        pos: 0,
        bounds,
        nodes: 0,
    };
    d.skip_ws();
    let value = d.parse_value(1)?;
    d.skip_ws();
    // REQ1-JSON-single-value: only JSON whitespace may follow the single value.
    if d.pos != d.input.len() {
        return Err(Invalid);
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    bounds: &'a Bounds,
    nodes: u64,
}

impl<'a> Decoder<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: u64) -> Result<JsonValue> {
        // total_nodes counts every value (containers AND scalars).
        self.nodes += 1;
        if self.nodes > self.bounds.total_nodes() {
            return Err(Invalid);
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => {
                let s = self.parse_string(self.bounds.string_bytes())?;
                Ok(JsonValue::String(s))
            }
            Some(b't') => {
                self.expect_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.expect_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.expect_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(Invalid),
        }
    }

    fn expect_literal(&mut self, lit: &[u8]) -> Result<()> {
        if self.input[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(Invalid)
        }
    }

    fn parse_array(&mut self, depth: u64) -> Result<JsonValue> {
        // Depth is measured on containers (arrays/objects); a scalar may sit one
        // level deeper. The depth-exact-bound (32-deep empty `[]`) and the
        // depth-scalar-inner-exact (32-deep wrapping one scalar) corpus cases
        // both pass under this rule; a 33-deep container fails.
        if depth > self.bounds.depth() {
            return Err(Invalid);
        }
        self.pos += 1; // consume '['
        self.skip_ws();
        let mut items: Vec<JsonValue> = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            // array_items limit applies WHILE decoding.
            if items.len() as u64 >= self.bounds.array_items() {
                return Err(Invalid);
            }
            let v = self.parse_value(depth + 1)?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(Invalid),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self, depth: u64) -> Result<JsonValue> {
        if depth > self.bounds.depth() {
            return Err(Invalid);
        }
        self.pos += 1; // consume '{'
        self.skip_ws();
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(members));
        }
        loop {
            // object_members limit applies WHILE decoding.
            if members.len() as u64 >= self.bounds.object_members() {
                return Err(Invalid);
            }
            let name = self.parse_string(self.bounds.key_bytes())?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(Invalid);
            }
            self.pos += 1; // ':'
            self.skip_ws();
            let v = self.parse_value(depth + 1)?;
            // REQ1-JSON-no-duplicate: reject a duplicate name at ANY depth before
            // any map conversion.
            if members.iter().any(|(k, _)| k == &name) {
                return Err(Invalid);
            }
            members.push((name, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(Invalid),
            }
        }
        Ok(JsonValue::Object(members))
    }

    /// Parses a JSON string (value or member name). `byte_limit` is the decoded
    /// UTF-8 content ceiling (`string_bytes` for values, `key_bytes` for names).
    fn parse_string(&mut self, byte_limit: u64) -> Result<String> {
        self.pos += 1; // opening quote
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err(Invalid), // unterminated
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = self.peek().ok_or(Invalid)?;
                    self.pos += 1;
                    match esc {
                        b'"' => buf.push(b'"'),
                        b'\\' => buf.push(b'\\'),
                        b'/' => buf.push(b'/'),
                        b'b' => buf.push(0x08),
                        b'f' => buf.push(0x0c),
                        b'n' => buf.push(b'\n'),
                        b'r' => buf.push(b'\r'),
                        b't' => buf.push(b'\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            self.encode_codepoint(&mut buf, cp)?;
                        }
                        _ => return Err(Invalid),
                    }
                }
                Some(b) if b < 0x20 => return Err(Invalid), // unescaped control char
                Some(b) => {
                    buf.push(b);
                    self.pos += 1;
                }
            }
        }
        if buf.len() as u64 > byte_limit {
            return Err(Invalid);
        }
        // REQ1-JSON-no-normalization: UTF-8 mandatory, no Unicode normalization.
        // from_utf8 rejects malformed sequences (e.g. lone 0xff); the result is
        // stored verbatim (no normalization).
        String::from_utf8(buf).map_err(|_| Invalid)
    }

    fn parse_hex4(&mut self) -> Result<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let c = self.peek().ok_or(Invalid)?;
            self.pos += 1;
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err(Invalid),
            };
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// Encodes a `\uXXXX` code point, handling surrogate pairs. A lone surrogate
    /// (unpaired high/low) is rejected — it is not a Unicode scalar value and so
    /// cannot be represented in the mandatory UTF-8 string.
    fn encode_codepoint(&mut self, buf: &mut Vec<u8>, cp: u32) -> Result<()> {
        if (0xD800..=0xDBFF).contains(&cp) {
            // high surrogate; require an immediately-following `\uXXXX` low surrogate
            if self.peek() != Some(b'\\') {
                return Err(Invalid);
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(Invalid);
            }
            self.pos += 1;
            let lo = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err(Invalid);
            }
            let combined = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            push_utf8(buf, combined);
            Ok(())
        } else if (0xDC00..=0xDFFF).contains(&cp) {
            Err(Invalid) // lone low surrogate
        } else {
            push_utf8(buf, cp);
            Ok(())
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue> {
        let start = self.pos;
        self.scan_number_lexeme()?;
        let lexeme = &self.input[start..self.pos];

        // Closure #5 — int/float tag by lexeme shape: a lexeme containing `.` or
        // `e`/`E` is a non-integer number -> Float; a pure decimal integer lexeme
        // -> Int. `1` -> Int(1), `1.0` -> Float(1.0) (distinct variants). Removing
        // this distinction (forcing Float) collapses selector identity.
        let is_float = lexeme.iter().any(|&b| matches!(b, b'.' | b'e' | b'E'));

        // === REQ1-JSON-raw-lexeme closure (begin) ==============================
        // Scan the raw lexeme OUTSIDE strings; enforce the byte ceiling and exact
        // decimal magnitude BEFORE host conversion. Removing this block lets
        // `9007199254740992` (fits i64), `1e16`, and 65-byte lexemes wrongly decode.
        if lexeme.len() as u64 > self.bounds.number_lexeme_bytes() {
            return Err(Invalid);
        }
        let (digits, frac_count, exp) = decompose_number(lexeme)?;
        let scale = exp - frac_count as i64;
        let stripped = strip_leading_zeros(&digits);
        let bound = if is_float {
            self.bounds.float_magnitude()
        } else {
            self.bounds.integer_magnitude()
        };
        if !magnitude_ok(stripped, scale, bound) {
            return Err(Invalid);
        }
        // === REQ1-JSON-raw-lexeme closure (end) ================================

        if is_float {
            let s = std::str::from_utf8(lexeme).map_err(|_| Invalid)?;
            let f: f64 = s.parse().map_err(|_| Invalid)?;
            if !f.is_finite() {
                return Err(Invalid);
            }
            Ok(JsonValue::Float(f))
        } else {
            let s = std::str::from_utf8(lexeme).map_err(|_| Invalid)?;
            let n: i64 = s.parse().map_err(|_| Invalid)?;
            Ok(JsonValue::Int(n))
        }
    }

    /// Scans a single RFC 8259 number lexeme from `pos`, advancing `pos` to one
    /// past the lexeme. Rejects malformed grammar (bare `-`, `.5`, `1.`, `1e`,
    /// `+5`). Leading-zero forms (`01`) leave the trailing digit for the
    /// structural parser, which rejects it at the value boundary.
    fn scan_number_lexeme(&mut self) -> Result<()> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(Invalid),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Invalid);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Invalid);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Number helpers (raw-lexeme magnitude check — exact decimal, no FP rounding)
// ----------------------------------------------------------------------------

/// Appends the UTF-8 encoding of `cp` (a validated Unicode scalar value) to buf.
fn push_utf8(buf: &mut Vec<u8>, cp: u32) {
    if cp <= 0x7F {
        buf.push(cp as u8);
    } else if cp <= 0x7FF {
        buf.push(0xC0 | (cp >> 6) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    } else if cp <= 0xFFFF {
        buf.push(0xE0 | (cp >> 12) as u8);
        buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    } else {
        buf.push(0xF0 | (cp >> 18) as u8);
        buf.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    }
}

/// Decomposes a grammar-valid number lexeme into (digits, frac_count, exp).
///
/// `digits` is the int+frac digit sequence concatenated (no sign, no point).
/// `frac_count` is the number of fractional digits. `exp` is the signed exponent
/// value, saturated at ±1000 to keep the magnitude check allocation-bomb-free
/// (any |exp| > ~18 forces the verdict by digit-length alone, so saturation at
/// 1000 is exact for the ±9_007_199_254_740_991 bound).
fn decompose_number(lexeme: &[u8]) -> Result<(String, usize, i64)> {
    let mut i = 0;
    if i < lexeme.len() && lexeme[i] == b'-' {
        i += 1;
    }
    let mut digits = String::new();
    let mut frac_count = 0usize;
    while i < lexeme.len() && lexeme[i].is_ascii_digit() {
        digits.push(lexeme[i] as char);
        i += 1;
    }
    if i < lexeme.len() && lexeme[i] == b'.' {
        i += 1;
        while i < lexeme.len() && lexeme[i].is_ascii_digit() {
            digits.push(lexeme[i] as char);
            frac_count += 1;
            i += 1;
        }
    }
    let mut exp = 0i64;
    if i < lexeme.len() && (lexeme[i] == b'e' || lexeme[i] == b'E') {
        i += 1;
        let mut esign: i64 = 1;
        if i < lexeme.len() && (lexeme[i] == b'+' || lexeme[i] == b'-') {
            if lexeme[i] == b'-' {
                esign = -1;
            }
            i += 1;
        }
        let exp_start = i;
        let mut ev: i64 = 0;
        while i < lexeme.len() && lexeme[i].is_ascii_digit() {
            ev = ev * 10 + (lexeme[i] - b'0') as i64;
            i += 1;
        }
        if (i - exp_start) > 3 || ev > 999 {
            ev = 1000;
        }
        exp = esign * ev;
    }
    Ok((digits, frac_count, exp))
}

/// Strips leading zeros from a digit string, leaving "0" if all zeros.
fn strip_leading_zeros(s: &str) -> &str {
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0"
    } else {
        t
    }
}

/// Exact decimal magnitude check (no floating-point rounding).
///
/// `digits` is the unsigned digit sequence (leading zeros stripped), `scale` is
/// the power of ten to apply (exp − frac_count), `bound` is the symmetric
/// magnitude ceiling (9_007_199_254_740_991). Returns true iff |digits × 10^scale|
/// is within the bound. Comparison is by decimal digit length, then byte ordering
/// — exact for the bound's 16-digit width and bomb-free (large |scale| resolves
/// via the length test without materializing zeros).
fn magnitude_ok(digits: &str, scale: i64, bound: u64) -> bool {
    if digits == "0" {
        return true;
    }
    let bound_str = bound.to_string(); // "9007199254740991"
    let blen = bound_str.len() as i64; // 16
    let dlen = digits.len() as i64;
    if scale >= 0 {
        // effective value = digits followed by `scale` zeros (an integer).
        let eff_len = dlen + scale;
        if eff_len > blen {
            return false;
        }
        if eff_len < blen {
            return true;
        }
        // equal length: scale <= blen-1 (since dlen >= 1), so the loop is bounded.
        let mut eff = digits.to_string();
        for _ in 0..scale {
            eff.push('0');
        }
        eff.as_str() <= bound_str.as_str()
    } else {
        // |value| = digits / 10^k; |value| > bound  <=>  digits > bound * 10^k.
        let k = -scale;
        let thresh_len = blen + k;
        if dlen > thresh_len {
            return false;
        }
        if dlen < thresh_len {
            return true;
        }
        // equal length: k = dlen - blen <= lexeme_digits - 16, bounded.
        let mut thresh = bound_str.clone();
        for _ in 0..k {
            thresh.push('0');
        }
        digits <= thresh.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max() -> Bounds {
        Bounds::maximum()
    }

    // ==========================================================================
    // Closure #1 — REQ1-JSON-no-duplicate
    // ==========================================================================

    #[test]
    fn duplicate_member_at_root_is_rejected() {
        // The load-bearing permissiveness case (ADR 0005:240-246): a last-wins
        // host decoder silently accepts `{"a":1,"a":2}` (keeping `a:2`); the
        // dup-rejecting decoder must fail closed.
        let result = json_decode(br#"{"a":1,"a":2}"#, &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn duplicate_member_at_depth_is_rejected() {
        let result = json_decode(br#"{"o":{"x":1,"x":2}}"#, &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn legacy_duplicate_algorithm_swap_is_rejected() {
        // The corpus `json-decode-legacy-duplicate-member` case shape: a
        // last-wins decoder would let `alg:"none"` silently override `alg:"EdDSA"`.
        let result = json_decode(br#"{"alg":"EdDSA","alg":"none"}"#, &max());
        assert_eq!(result, Err(Invalid));
    }

    // ==========================================================================
    // Closure — REQ1-JSON-single-value
    // ==========================================================================

    #[test]
    fn trailing_whitespace_is_accepted() {
        let result = json_decode(b"{}  \t\n\r", &max());
        assert!(result.is_ok());
    }

    #[test]
    fn trailing_non_whitespace_is_rejected() {
        let result = json_decode(b"{} 1", &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn two_values_back_to_back_are_rejected() {
        let result = json_decode(b"1 2", &max());
        assert_eq!(result, Err(Invalid));
    }

    // ==========================================================================
    // Closure — REQ1-JSON-raw-lexeme (byte ceiling + exact magnitude, pre-conversion)
    // ==========================================================================

    #[test]
    fn number_lexeme_at_byte_ceiling_is_accepted() {
        // 64-byte float lexeme (`1.` + 62 zeros) — value 1.0, within magnitude.
        let mut s = String::from("1.");
        s.push_str(&"0".repeat(62));
        let result = json_decode(s.as_bytes(), &max());
        assert!(result.is_ok(), "64-byte lexeme should be valid");
    }

    #[test]
    fn number_lexeme_over_byte_ceiling_is_rejected_before_conversion() {
        // 65-byte float lexeme (`1.` + 63 zeros) — over the 64-byte ceiling.
        let mut s = String::from("1.");
        s.push_str(&"0".repeat(63));
        let result = json_decode(s.as_bytes(), &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn integer_over_magnitude_is_rejected_before_conversion() {
        // 9007199254740992 = 2^53 — fits i64 (a permissive host parse would
        // accept it), but the raw-lexeme magnitude check rejects it pre-conversion.
        let result = json_decode(b"9007199254740992", &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn integer_at_exact_magnitude_is_accepted() {
        let result = json_decode(b"9007199254740991", &max());
        assert!(result.is_ok());
    }

    #[test]
    fn float_over_magnitude_is_rejected_before_conversion() {
        // The corpus `json-decode-float-magnitude` case: `1e16` = 10^16 >
        // 9.007e15. Converting to f64 first would give a representable 1e16 that
        // also compares over the bound, but the exact magnitude check fires on
        // the raw lexeme regardless.
        let result = json_decode(b"1e16", &max());
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn negative_integer_over_magnitude_is_rejected() {
        let result = json_decode(b"-9007199254740992", &max());
        assert_eq!(result, Err(Invalid));
    }

    // ==========================================================================
    // Closure #5 — int/float tag (distinct variants by lexeme shape)
    // ==========================================================================

    #[test]
    fn integer_literal_decodes_to_int_variant() {
        let result = json_decode(b"1", &max()).expect("1 decodes");
        assert_eq!(result, JsonValue::Int(1));
    }

    #[test]
    fn float_literal_decodes_to_float_variant() {
        let result = json_decode(b"1.0", &max()).expect("1.0 decodes");
        assert_eq!(result, JsonValue::Float(1.0));
    }

    #[test]
    fn int_one_and_float_one_are_distinct_variants() {
        let i = json_decode(b"1", &max()).unwrap();
        let f = json_decode(b"1.0", &max()).unwrap();
        assert_ne!(i, f, "Int(1) and Float(1.0) must be distinct");
        assert!(matches!(i, JsonValue::Int(_)));
        assert!(matches!(f, JsonValue::Float(_)));
    }

    #[test]
    fn exponent_lexeme_decodes_to_float_variant() {
        // `1e2` is a non-integer lexeme (has `e`) -> Float; it is NOT Int(100).
        let result = json_decode(b"1e2", &max()).expect("1e2 decodes");
        assert!(
            matches!(result, JsonValue::Float(_)),
            "exponent lexeme is Float"
        );
    }

    // ==========================================================================
    // Structural bounds — exact_bound / maximum_plus_one behavior
    // ==========================================================================

    #[test]
    fn depth_exact_bound_is_accepted() {
        // 32 nested empty arrays (`[`*32 + `]`*32 — the corpus depth-exact shape).
        // 33-deep is rejected. Depth is measured on containers; the innermost
        // empty array sits at depth 32 (== the bound).
        let mut s = String::new();
        for _ in 0..32 {
            s.push('[');
        }
        for _ in 0..32 {
            s.push(']');
        }
        assert!(
            json_decode(s.as_bytes(), &max()).is_ok(),
            "32-deep is valid"
        );
    }

    #[test]
    fn depth_maximum_plus_one_is_rejected() {
        // 33 nested empty arrays (`[`*33 + `]`*33 — the corpus depth-max+1 shape).
        let mut s = String::new();
        for _ in 0..33 {
            s.push('[');
        }
        for _ in 0..33 {
            s.push(']');
        }
        assert_eq!(json_decode(s.as_bytes(), &max()), Err(Invalid));
    }

    #[test]
    fn depth_exact_bound_with_scalar_inner_is_accepted() {
        // The corpus depth-scalar-inner-exact shape: 32 containers wrapping one
        // scalar (the scalar sits one level below the depth-32 container). Depth
        // is measured on containers, so this is valid at the bound.
        let mut s = String::new();
        for _ in 0..31 {
            s.push('[');
        }
        s.push_str("[0]");
        for _ in 0..31 {
            s.push(']');
        }
        assert!(
            json_decode(s.as_bytes(), &max()).is_ok(),
            "32-deep wrapping a scalar is valid"
        );
    }

    #[test]
    fn array_items_maximum_plus_one_is_rejected() {
        let mut s = String::from("[");
        for i in 0..257 {
            if i > 0 {
                s.push(',');
            }
            s.push('0');
        }
        s.push(']');
        assert_eq!(json_decode(s.as_bytes(), &max()), Err(Invalid));
    }

    #[test]
    fn object_members_maximum_plus_one_is_rejected() {
        let mut s = String::from("{");
        for i in 0..65 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("\"k{i}\":0"));
        }
        s.push('}');
        assert_eq!(json_decode(s.as_bytes(), &max()), Err(Invalid));
    }

    #[test]
    fn malformed_member_name_is_rejected() {
        // `{"\xff":1}` — invalid UTF-8 in the member name.
        let result = json_decode(b"{\"\xff\":1}", &max());
        assert_eq!(result, Err(Invalid));
    }

    // ==========================================================================
    // Tagged algebra — valid value shapes + source-order preservation
    // ==========================================================================

    #[test]
    fn valid_basic_values() {
        assert_eq!(json_decode(b"null", &max()).unwrap(), JsonValue::Null);
        assert_eq!(json_decode(b"true", &max()).unwrap(), JsonValue::Bool(true));
        assert_eq!(
            json_decode(b"false", &max()).unwrap(),
            JsonValue::Bool(false)
        );
        assert_eq!(json_decode(b"1.5", &max()).unwrap(), JsonValue::Float(1.5));
        assert_eq!(json_decode(b"42", &max()).unwrap(), JsonValue::Int(42));
        assert_eq!(
            json_decode(b"\"hi\"", &max()).unwrap(),
            JsonValue::String("hi".to_string())
        );
    }

    #[test]
    fn valid_nested_structure() {
        let v = json_decode(br#"{"a":[1,{"b":2}]}"#, &max()).unwrap();
        match v {
            JsonValue::Object(members) => {
                assert_eq!(members.len(), 1);
                assert_eq!(members[0].0, "a");
                match &members[0].1 {
                    JsonValue::Array(items) => {
                        assert_eq!(items.len(), 2);
                        assert_eq!(items[0], JsonValue::Int(1));
                        assert!(matches!(&items[1], JsonValue::Object(_)));
                    }
                    _ => panic!("expected array"),
                }
            }
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn object_source_member_order_is_preserved() {
        // RFC 8785 sorts at JCS encode time; decode preserves source order so the
        // selector-identity / order-preservation closure holds.
        let v = json_decode(br#"{"b":1,"a":2,"c":3}"#, &max()).unwrap();
        match v {
            JsonValue::Object(members) => {
                let names: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(names, vec!["b", "a", "c"]);
            }
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert_eq!(
            json_decode(b"{}", &max()).unwrap(),
            JsonValue::Object(vec![])
        );
        // `{"a":}` — missing value.
        assert_eq!(json_decode(br#"{"a":}"#, &max()), Err(Invalid));
        // `{"a":1}xyz` — trailing non-ws.
        assert_eq!(json_decode(b"{\"a\":1}xyz", &max()), Err(Invalid));
        // first byte tamper.
        assert_eq!(json_decode(b"z\"a\":1}", &max()), Err(Invalid));
        // empty input.
        assert_eq!(json_decode(b"", &max()), Err(Invalid));
    }

    #[test]
    fn surrogate_pair_decodes_to_supplementary_scalar() {
        // U+1F600 grinning face: \uD83D\uDE00
        let v = json_decode(b"\"\\uD83D\\uDE00\"", &max()).unwrap();
        assert_eq!(v, JsonValue::String("\u{1F600}".to_string()));
    }

    #[test]
    fn lone_high_surrogate_is_rejected() {
        let result = json_decode(b"\"\\uD83D\"", &max());
        assert_eq!(result, Err(Invalid));
    }

    // ==========================================================================
    // Corpus: priv/conformance/v1/corpus/cases/json/{decode,magnitude}.json (29)
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

    fn case_input_bytes(
        case: &serde_json::Value,
        root: &std::path::Path,
    ) -> std::result::Result<Vec<u8>, String> {
        let input = &case["input"];
        if let Some(text) = input["text"].as_str() {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(b64) = input["base64url"].as_str() {
            return crate::base64url_decode(b64.as_bytes()).map_err(|e| format!("b64: {e:?}"));
        }
        if let Some(raw) = input["raw_file"].as_str() {
            let p = root.join(raw);
            return std::fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()));
        }
        Err("no input shape".to_string())
    }

    #[test]
    fn corpus_json_decode_all_29_cases() {
        let root = corpus_root();
        let mut cases: Vec<serde_json::Value> = Vec::new();
        for name in ["decode.json", "magnitude.json"] {
            let path = root.join("cases").join("json").join(name);
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
            let bytes =
                case_input_bytes(case, &root).unwrap_or_else(|e| panic!("case {id} input: {e}"));
            let actual_ok = json_decode(&bytes, &max()).is_ok();
            let expected_ok = expected_verdict == "valid";
            if actual_ok == expected_ok {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!(
                    "DISAGREE: id={id} class={class} expected={expected_verdict} actual_ok={actual_ok}"
                );
            }
        }

        eprintln!("applicability: {applicability:?}");
        eprintln!("agreed={agreed} disagreed={disagreed}");
        assert_eq!(agreed, 29, "agreed (json decode + magnitude corpus == 29)");
        assert_eq!(disagreed, 0, "disagreed");
        // Cross-check the per-class applicability the plan pins.
        assert_eq!(applicability["valid"], 6, "valid applicability");
        assert_eq!(applicability["invalid_duplicate"], 2, "invalid_duplicate");
        assert_eq!(applicability["invalid_encoding"], 4, "invalid_encoding");
        assert_eq!(applicability["exact_bound"], 8, "exact_bound");
        assert_eq!(applicability["maximum_plus_one"], 8, "maximum_plus_one");
        assert_eq!(
            applicability["tamper_meaningful_byte"], 1,
            "tamper_meaningful_byte"
        );
    }
}
