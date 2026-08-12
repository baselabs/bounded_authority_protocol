//! Profile maxima + tightening-only overrides.
//!
//! [`Bounds`] carries the immutable v1 maxima from `docs/protocol-v1.md`
//! § Hard maxima, optionally tightened by caller-supplied overrides. The
//! 32-byte Ed25519 public-key/digest widths and the 64-byte signature width
//! are immutable cryptographic constants of the `BAP1-Ed25519-SHA256` suite
//! (`REQ1-BOUNDS-fixed-widths`); they are NOT stored in `Bounds` — they are
//! enforced as the fixed array types `[u8; 32]` / `[u8; 64]` throughout the
//! crate. The overrides map recognizes them only to reject any attempt to
//! change them.
//!
//! Enforcement rules (`docs/protocol-v1.md` § Hard maxima, lines 417–424):
//! - `REQ1-BOUNDS-tighten-only`: callers MAY tighten ceilings with a positive
//!   integer; widening is invalid.
//! - `REQ1-BOUNDS-reject-list`: unknown, non-integer, zero, negative, widening,
//!   or fixed-width-changing limits are invalid.
//! - `REQ1-BOUNDS-fixed-widths`: the 32/64-byte crypto widths are immutable
//!   protocol constants, not `Bounds` fields.
//! - `REQ1-BOUNDS-ordering`: raw/encoded sizes precede decoding; decoded-size
//!   projection precedes allocation; structure/scalar limits apply during
//!   decoding; all precede cryptography.

use crate::error::{Invalid, Result};
use crate::json::JsonValue;

/// The immutable profile maxima plus tightening overrides.
///
/// Construct with [`Bounds::maximum`] (all maxima, no overrides) or
/// [`Bounds::new`] (validate a caller overrides map, tightening-only).
///
/// Fields are private so a `Bounds` value can only be obtained through the
/// validating constructors — callers cannot bypass tighten-only / fixed-width
/// enforcement by assembling a struct literal.
///
/// Derives [`Debug`], [`Clone`], [`Copy`], [`PartialEq`], and [`Eq`] (not
/// `Serialize`/`Display`): a `Bounds` is public configuration of integer
/// ceilings (every field is a `u64`), not a credential — printing, copying, or
/// comparing it leaks no authority-bearing material. `Clone`/`Copy`/`Eq` are
/// required so the input structs that embed a `Bounds` (e.g. `ExpectedGrant`,
/// `ExpectedRequest`) can derive `Clone`/`Eq` themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    compact_bytes: u64,
    encoded_segment_bytes: u64,
    decoded_segment_bytes: u64,
    json_bytes: u64,
    depth: u64,
    object_members: u64,
    array_items: u64,
    total_nodes: u64,
    string_bytes: u64,
    key_bytes: u64,
    number_lexeme_bytes: u64,
    integer_magnitude: u64,
    float_magnitude: u64,
    kid_bytes: u64,
    jcs_bytes: u64,
    uri_bytes: u64,
    identifier_bytes: u64,
    nonce_bytes: u64,
    method_bytes: u64,
    operation_bytes: u64,
    audiences: u64,
    operations: u64,
    selectors: u64,
    path_segments: u64,
    one_of_values: u64,
    clock_skew: u64,
    proof_max_age: u64,
    chain_row_bytes: u64,
    chain_rows: u64,
    anchor_bytes: u64,
    archive_header_bytes: u64,
    key_transitions: u64,
    archive_chunks: u64,
    archive_bytes: u64,
    object_version_bytes: u64,
}

impl Bounds {
    // ------------------------------------------------------------------------
    // Immutable profile maxima — docs/protocol-v1.md § Hard maxima (lines 377–415)
    // ------------------------------------------------------------------------

    const MAX_COMPACT_BYTES: u64 = 65536;
    const MAX_ENCODED_SEGMENT_BYTES: u64 = 32768;
    const MAX_DECODED_SEGMENT_BYTES: u64 = 24576;
    const MAX_JSON_BYTES: u64 = 65536;
    const MAX_DEPTH: u64 = 32;
    const MAX_OBJECT_MEMBERS: u64 = 64;
    const MAX_ARRAY_ITEMS: u64 = 256;
    const MAX_TOTAL_NODES: u64 = 4096;
    const MAX_STRING_BYTES: u64 = 8192;
    const MAX_KEY_BYTES: u64 = 128; // object-name bytes
    const MAX_NUMBER_LEXEME_BYTES: u64 = 64;
    const MAX_INTEGER_MAGNITUDE: u64 = 9007199254740991;
    const MAX_FLOAT_MAGNITUDE: u64 = 9007199254740991;
    const MAX_KID_BYTES: u64 = 128;
    const MAX_JCS_BYTES: u64 = 65536;
    const MAX_URI_BYTES: u64 = 8192;
    const MAX_IDENTIFIER_BYTES: u64 = 512; // issuer / audience / token identifier
    const MAX_NONCE_BYTES: u64 = 512;
    const MAX_METHOD_BYTES: u64 = 32;
    const MAX_OPERATION_BYTES: u64 = 128;
    const MAX_AUDIENCES: u64 = 64;
    const MAX_OPERATIONS: u64 = 64;
    const MAX_SELECTORS: u64 = 64;
    const MAX_PATH_SEGMENTS: u64 = 32;
    const MAX_ONE_OF_VALUES: u64 = 256;
    const MAX_CLOCK_SKEW: u64 = 60;
    const MAX_PROOF_MAX_AGE: u64 = 300;
    const MAX_CHAIN_ROW_BYTES: u64 = 4096;
    const MAX_CHAIN_ROWS: u64 = 65536;
    const MAX_ANCHOR_BYTES: u64 = 8192;
    const MAX_ARCHIVE_HEADER_BYTES: u64 = 8192;
    const MAX_KEY_TRANSITIONS: u64 = 256;
    const MAX_ARCHIVE_CHUNKS: u64 = 65796;
    const MAX_ARCHIVE_BYTES: u64 = 270_820_384;
    const MAX_OBJECT_VERSION_BYTES: u64 = 512;

    // ------------------------------------------------------------------------
    // Fixed cryptographic widths — REQ1-BOUNDS-fixed-widths.
    // NOT stored in Bounds; enforced as [u8; N] array types.
    // Recognized in the overrides map only to reject any attempt to change them.
    // ------------------------------------------------------------------------

    /// SHA-256 digest width in bytes (fixed protocol constant).
    pub const FIXED_DIGEST_BYTES: u64 = 32;
    /// Ed25519 public-key width in bytes (fixed protocol constant).
    pub const FIXED_PUBLIC_KEY_BYTES: u64 = 32;
    /// Ed25519 signature width in bytes (fixed protocol constant).
    pub const FIXED_SIGNATURE_BYTES: u64 = 64;

    // ------------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------------

    /// Returns the full immutable profile maxima with no overrides.
    #[must_use]
    pub fn maximum() -> Self {
        Self {
            compact_bytes: Self::MAX_COMPACT_BYTES,
            encoded_segment_bytes: Self::MAX_ENCODED_SEGMENT_BYTES,
            decoded_segment_bytes: Self::MAX_DECODED_SEGMENT_BYTES,
            json_bytes: Self::MAX_JSON_BYTES,
            depth: Self::MAX_DEPTH,
            object_members: Self::MAX_OBJECT_MEMBERS,
            array_items: Self::MAX_ARRAY_ITEMS,
            total_nodes: Self::MAX_TOTAL_NODES,
            string_bytes: Self::MAX_STRING_BYTES,
            key_bytes: Self::MAX_KEY_BYTES,
            number_lexeme_bytes: Self::MAX_NUMBER_LEXEME_BYTES,
            integer_magnitude: Self::MAX_INTEGER_MAGNITUDE,
            float_magnitude: Self::MAX_FLOAT_MAGNITUDE,
            kid_bytes: Self::MAX_KID_BYTES,
            jcs_bytes: Self::MAX_JCS_BYTES,
            uri_bytes: Self::MAX_URI_BYTES,
            identifier_bytes: Self::MAX_IDENTIFIER_BYTES,
            nonce_bytes: Self::MAX_NONCE_BYTES,
            method_bytes: Self::MAX_METHOD_BYTES,
            operation_bytes: Self::MAX_OPERATION_BYTES,
            audiences: Self::MAX_AUDIENCES,
            operations: Self::MAX_OPERATIONS,
            selectors: Self::MAX_SELECTORS,
            path_segments: Self::MAX_PATH_SEGMENTS,
            one_of_values: Self::MAX_ONE_OF_VALUES,
            clock_skew: Self::MAX_CLOCK_SKEW,
            proof_max_age: Self::MAX_PROOF_MAX_AGE,
            chain_row_bytes: Self::MAX_CHAIN_ROW_BYTES,
            chain_rows: Self::MAX_CHAIN_ROWS,
            anchor_bytes: Self::MAX_ANCHOR_BYTES,
            archive_header_bytes: Self::MAX_ARCHIVE_HEADER_BYTES,
            key_transitions: Self::MAX_KEY_TRANSITIONS,
            archive_chunks: Self::MAX_ARCHIVE_CHUNKS,
            archive_bytes: Self::MAX_ARCHIVE_BYTES,
            object_version_bytes: Self::MAX_OBJECT_VERSION_BYTES,
        }
    }

    /// Validates caller-supplied overrides against tightening-only rules and
    /// returns a [`Bounds`] with the tightened values applied.
    ///
    /// `overrides` is a decoded [`JsonValue::Object`] mapping bound names to
    /// positive integers — e.g. the decoded form of `{"compact_bytes":1000,
    /// "string_bytes":4096}`. `None` or an empty object returns
    /// [`Bounds::maximum`] unchanged.
    ///
    /// Each value MUST be [`JsonValue::Int`] with `n > 0`. A non-object root,
    /// a non-integer value, a non-positive value, an unknown key, a widening
    /// value, or a fixed-width-changing value is `Invalid`
    /// (`REQ1-BOUNDS-tighten-only`, `REQ1-BOUNDS-reject-list`,
    /// `REQ1-BOUNDS-fixed-widths`). The caller decodes the overrides JSON
    /// (through [`crate::json::json_decode`], which itself rejects duplicate
    /// keys), so the members arrive in source order and collision-free.
    pub fn new(overrides: Option<&JsonValue>) -> Result<Self> {
        let mut bounds = Self::maximum();
        let members = match overrides {
            None => return Ok(bounds),
            Some(JsonValue::Object(m)) => m,
            // A non-object overrides root (array / scalar / null) is invalid.
            Some(_) => return Err(Invalid),
        };
        for (key, value) in members {
            let n = match value {
                JsonValue::Int(n) => *n,
                // A float / bool / null / structured value is not a positive integer.
                _ => return Err(Invalid),
            };
            if n <= 0 {
                return Err(Invalid);
            }
            bounds.apply_override(key, n as u64)?;
        }
        Ok(bounds)
    }

    /// Applies a single override: tightening fields accept `0 < value <= max`;
    /// fixed-width keys accept only `value == width`; unknown keys are invalid.
    fn apply_override(&mut self, key: &str, value: u64) -> Result<()> {
        match key {
            // --- JSON / structural bounds ---
            "compact_bytes" => tighten(&mut self.compact_bytes, Self::MAX_COMPACT_BYTES, value),
            "encoded_segment_bytes" => tighten(
                &mut self.encoded_segment_bytes,
                Self::MAX_ENCODED_SEGMENT_BYTES,
                value,
            ),
            "decoded_segment_bytes" => tighten(
                &mut self.decoded_segment_bytes,
                Self::MAX_DECODED_SEGMENT_BYTES,
                value,
            ),
            "json_bytes" => tighten(&mut self.json_bytes, Self::MAX_JSON_BYTES, value),
            "depth" => tighten(&mut self.depth, Self::MAX_DEPTH, value),
            "object_members" => tighten(&mut self.object_members, Self::MAX_OBJECT_MEMBERS, value),
            "array_items" => tighten(&mut self.array_items, Self::MAX_ARRAY_ITEMS, value),
            "total_nodes" => tighten(&mut self.total_nodes, Self::MAX_TOTAL_NODES, value),
            "string_bytes" => tighten(&mut self.string_bytes, Self::MAX_STRING_BYTES, value),
            "key_bytes" => tighten(&mut self.key_bytes, Self::MAX_KEY_BYTES, value),
            "number_lexeme_bytes" => tighten(
                &mut self.number_lexeme_bytes,
                Self::MAX_NUMBER_LEXEME_BYTES,
                value,
            ),
            "integer_magnitude" => tighten(
                &mut self.integer_magnitude,
                Self::MAX_INTEGER_MAGNITUDE,
                value,
            ),
            "float_magnitude" => {
                tighten(&mut self.float_magnitude, Self::MAX_FLOAT_MAGNITUDE, value)
            }
            // --- Header / claim bounds ---
            "kid_bytes" => tighten(&mut self.kid_bytes, Self::MAX_KID_BYTES, value),
            "jcs_bytes" => tighten(&mut self.jcs_bytes, Self::MAX_JCS_BYTES, value),
            "uri_bytes" => tighten(&mut self.uri_bytes, Self::MAX_URI_BYTES, value),
            "identifier_bytes" => tighten(
                &mut self.identifier_bytes,
                Self::MAX_IDENTIFIER_BYTES,
                value,
            ),
            "nonce_bytes" => tighten(&mut self.nonce_bytes, Self::MAX_NONCE_BYTES, value),
            "method_bytes" => tighten(&mut self.method_bytes, Self::MAX_METHOD_BYTES, value),
            "operation_bytes" => {
                tighten(&mut self.operation_bytes, Self::MAX_OPERATION_BYTES, value)
            }
            "audiences" => tighten(&mut self.audiences, Self::MAX_AUDIENCES, value),
            "operations" => tighten(&mut self.operations, Self::MAX_OPERATIONS, value),
            "selectors" => tighten(&mut self.selectors, Self::MAX_SELECTORS, value),
            "path_segments" => tighten(&mut self.path_segments, Self::MAX_PATH_SEGMENTS, value),
            "one_of_values" => tighten(&mut self.one_of_values, Self::MAX_ONE_OF_VALUES, value),
            // --- Time bounds ---
            "clock_skew" => tighten(&mut self.clock_skew, Self::MAX_CLOCK_SKEW, value),
            "proof_max_age" => tighten(&mut self.proof_max_age, Self::MAX_PROOF_MAX_AGE, value),
            // --- Consumption chain / anchored export bounds ---
            "chain_row_bytes" => {
                tighten(&mut self.chain_row_bytes, Self::MAX_CHAIN_ROW_BYTES, value)
            }
            "chain_rows" => tighten(&mut self.chain_rows, Self::MAX_CHAIN_ROWS, value),
            "anchor_bytes" => tighten(&mut self.anchor_bytes, Self::MAX_ANCHOR_BYTES, value),
            "archive_header_bytes" => tighten(
                &mut self.archive_header_bytes,
                Self::MAX_ARCHIVE_HEADER_BYTES,
                value,
            ),
            "key_transitions" => {
                tighten(&mut self.key_transitions, Self::MAX_KEY_TRANSITIONS, value)
            }
            "archive_chunks" => tighten(&mut self.archive_chunks, Self::MAX_ARCHIVE_CHUNKS, value),
            "archive_bytes" => tighten(&mut self.archive_bytes, Self::MAX_ARCHIVE_BYTES, value),
            "object_version_bytes" => tighten(
                &mut self.object_version_bytes,
                Self::MAX_OBJECT_VERSION_BYTES,
                value,
            ),
            // --- Fixed cryptographic widths (REQ1-BOUNDS-fixed-widths) ---
            "digest_bytes" => fixed(Self::FIXED_DIGEST_BYTES, value),
            "public_key_bytes" => fixed(Self::FIXED_PUBLIC_KEY_BYTES, value),
            "signature_bytes" => fixed(Self::FIXED_SIGNATURE_BYTES, value),
            // --- Unknown key (REQ1-BOUNDS-reject-list) ---
            _ => Err(Invalid),
        }
    }

    // ------------------------------------------------------------------------
    // Accessors — each returns the effective value (maximum or tightened).
    // ------------------------------------------------------------------------

    /// Compact input bytes ceiling.
    pub fn compact_bytes(&self) -> u64 {
        self.compact_bytes
    }
    /// Encoded segment bytes ceiling.
    pub fn encoded_segment_bytes(&self) -> u64 {
        self.encoded_segment_bytes
    }
    /// Decoded segment bytes ceiling.
    pub fn decoded_segment_bytes(&self) -> u64 {
        self.decoded_segment_bytes
    }
    /// Raw JSON bytes ceiling.
    pub fn json_bytes(&self) -> u64 {
        self.json_bytes
    }
    /// Nesting depth ceiling.
    pub fn depth(&self) -> u64 {
        self.depth
    }
    /// Members-per-object ceiling.
    pub fn object_members(&self) -> u64 {
        self.object_members
    }
    /// Items-per-array ceiling.
    pub fn array_items(&self) -> u64 {
        self.array_items
    }
    /// Total JSON value nodes ceiling.
    pub fn total_nodes(&self) -> u64 {
        self.total_nodes
    }
    /// String bytes ceiling.
    pub fn string_bytes(&self) -> u64 {
        self.string_bytes
    }
    /// Object-name bytes ceiling.
    pub fn key_bytes(&self) -> u64 {
        self.key_bytes
    }
    /// Numeric lexeme bytes ceiling.
    pub fn number_lexeme_bytes(&self) -> u64 {
        self.number_lexeme_bytes
    }
    /// Integer magnitude ceiling.
    pub fn integer_magnitude(&self) -> u64 {
        self.integer_magnitude
    }
    /// Float magnitude ceiling.
    pub fn float_magnitude(&self) -> u64 {
        self.float_magnitude
    }
    /// `kid` bytes ceiling.
    pub fn kid_bytes(&self) -> u64 {
        self.kid_bytes
    }
    /// JCS output bytes ceiling.
    pub fn jcs_bytes(&self) -> u64 {
        self.jcs_bytes
    }
    /// Normalized target URI bytes ceiling.
    pub fn uri_bytes(&self) -> u64 {
        self.uri_bytes
    }
    /// Issuer / audience / token-identifier bytes ceiling.
    pub fn identifier_bytes(&self) -> u64 {
        self.identifier_bytes
    }
    /// Nonce bytes ceiling.
    pub fn nonce_bytes(&self) -> u64 {
        self.nonce_bytes
    }
    /// HTTP method bytes ceiling.
    pub fn method_bytes(&self) -> u64 {
        self.method_bytes
    }
    /// Operation name bytes ceiling.
    pub fn operation_bytes(&self) -> u64 {
        self.operation_bytes
    }
    /// Audiences-per-grant ceiling.
    pub fn audiences(&self) -> u64 {
        self.audiences
    }
    /// Operations-per-grant ceiling.
    pub fn operations(&self) -> u64 {
        self.operations
    }
    /// Selectors-per-operation ceiling.
    pub fn selectors(&self) -> u64 {
        self.selectors
    }
    /// Selector path segments ceiling.
    pub fn path_segments(&self) -> u64 {
        self.path_segments
    }
    /// Values-in-`one_of` ceiling.
    pub fn one_of_values(&self) -> u64 {
        self.one_of_values
    }
    /// Clock skew seconds ceiling.
    pub fn clock_skew(&self) -> u64 {
        self.clock_skew
    }
    /// Proof maximum age seconds ceiling.
    pub fn proof_max_age(&self) -> u64 {
        self.proof_max_age
    }
    /// Canonical consumption row bytes ceiling.
    pub fn chain_row_bytes(&self) -> u64 {
        self.chain_row_bytes
    }
    /// Consumption-rows-per-range ceiling.
    pub fn chain_rows(&self) -> u64 {
        self.chain_rows
    }
    /// Boundary anchor / key-transition compact bytes ceiling.
    pub fn anchor_bytes(&self) -> u64 {
        self.anchor_bytes
    }
    /// Anchored-export header bytes ceiling.
    pub fn archive_header_bytes(&self) -> u64 {
        self.archive_header_bytes
    }
    /// Historical key transitions ceiling.
    pub fn key_transitions(&self) -> u64 {
        self.key_transitions
    }
    /// Anchored-export chunks ceiling.
    pub fn archive_chunks(&self) -> u64 {
        self.archive_chunks
    }
    /// Anchored-export bytes ceiling.
    pub fn archive_bytes(&self) -> u64 {
        self.archive_bytes
    }
    /// Object-store version bytes ceiling.
    pub fn object_version_bytes(&self) -> u64 {
        self.object_version_bytes
    }
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

/// Tighten-only check: accepts `0 < value <= max`, writes the value on success.
/// Rejects zero, widening, and (after parser rejection) negative / non-integer.
fn tighten(field: &mut u64, max: u64, value: u64) -> Result<()> {
    if value > 0 && value <= max {
        *field = value;
        Ok(())
    } else {
        Err(Invalid)
    }
}

/// Fixed-width check: accepts `value == width` exactly. The crypto widths are
/// immutable protocol constants — any deviation (above or below) is invalid.
fn fixed(width: u64, value: u64) -> Result<()> {
    if value == width {
        Ok(())
    } else {
        Err(Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{json_decode, JsonValue};

    /// Decode an overrides object bytes through the real tagged decoder so the
    /// rewired `Bounds::new(Option<&JsonValue>)` is exercised end-to-end.
    fn ov(bytes: &[u8]) -> JsonValue {
        json_decode(bytes, &Bounds::maximum()).expect("overrides decode")
    }

    // ------------------------------------------------------------------
    // maximum() — every value must match docs/protocol-v1.md § Hard maxima
    // ------------------------------------------------------------------

    #[test]
    fn maximum_carries_every_profile_maximum() {
        let b = Bounds::maximum();
        // JSON / structural bounds.
        assert_eq!(b.compact_bytes(), 65536);
        assert_eq!(b.encoded_segment_bytes(), 32768);
        assert_eq!(b.decoded_segment_bytes(), 24576);
        assert_eq!(b.json_bytes(), 65536);
        assert_eq!(b.depth(), 32);
        assert_eq!(b.object_members(), 64);
        assert_eq!(b.array_items(), 256);
        assert_eq!(b.total_nodes(), 4096);
        assert_eq!(b.string_bytes(), 8192);
        assert_eq!(b.key_bytes(), 128);
        assert_eq!(b.number_lexeme_bytes(), 64);
        assert_eq!(b.integer_magnitude(), 9007199254740991);
        assert_eq!(b.float_magnitude(), 9007199254740991);
        // Header / claim bounds.
        assert_eq!(b.kid_bytes(), 128);
        assert_eq!(b.jcs_bytes(), 65536);
        assert_eq!(b.uri_bytes(), 8192);
        assert_eq!(b.identifier_bytes(), 512);
        assert_eq!(b.nonce_bytes(), 512);
        assert_eq!(b.method_bytes(), 32);
        assert_eq!(b.operation_bytes(), 128);
        assert_eq!(b.audiences(), 64);
        assert_eq!(b.operations(), 64);
        assert_eq!(b.selectors(), 64);
        assert_eq!(b.path_segments(), 32);
        assert_eq!(b.one_of_values(), 256);
        // Time bounds.
        assert_eq!(b.clock_skew(), 60);
        assert_eq!(b.proof_max_age(), 300);
        // Consumption chain / anchored export bounds.
        assert_eq!(b.chain_row_bytes(), 4096);
        assert_eq!(b.chain_rows(), 65536);
        assert_eq!(b.anchor_bytes(), 8192);
        assert_eq!(b.archive_header_bytes(), 8192);
        assert_eq!(b.key_transitions(), 256);
        assert_eq!(b.archive_chunks(), 65796);
        assert_eq!(b.archive_bytes(), 270_820_384);
        assert_eq!(b.object_version_bytes(), 512);
    }

    // ------------------------------------------------------------------
    // new() — no-override cases
    // ------------------------------------------------------------------

    #[test]
    fn new_none_returns_maximum() {
        let b = Bounds::new(None).expect("None overrides");
        let m = Bounds::maximum();
        assert_eq!(b.compact_bytes(), m.compact_bytes());
        assert_eq!(b.archive_bytes(), m.archive_bytes());
        assert_eq!(b.integer_magnitude(), m.integer_magnitude());
    }

    #[test]
    fn new_empty_object_returns_maximum() {
        let b = Bounds::new(Some(&ov(b"{}"))).expect("empty overrides");
        let m = Bounds::maximum();
        assert_eq!(b.compact_bytes(), m.compact_bytes());
        assert_eq!(b.archive_bytes(), m.archive_bytes());
    }

    // ------------------------------------------------------------------
    // new() — tightening accepted
    // ------------------------------------------------------------------

    #[test]
    fn new_accepts_single_tightening() {
        let b = Bounds::new(Some(&ov(br#"{"compact_bytes":1000}"#))).expect("tighten");
        assert_eq!(b.compact_bytes(), 1000);
        // Non-overridden fields remain at maximum.
        assert_eq!(b.string_bytes(), 8192);
    }

    #[test]
    fn new_accepts_multiple_tightening() {
        let b = Bounds::new(Some(&ov(br#"{"compact_bytes":1000,"string_bytes":4096}"#)))
            .expect("multi-tighten");
        assert_eq!(b.compact_bytes(), 1000);
        assert_eq!(b.string_bytes(), 4096);
        assert_eq!(b.depth(), 32);
    }

    #[test]
    fn new_accepts_override_at_exact_maximum() {
        // exact_bound: setting a field to exactly its maximum is accepted.
        let b = Bounds::new(Some(&ov(br#"{"compact_bytes":65536}"#))).expect("exact max");
        assert_eq!(b.compact_bytes(), 65536);
    }

    // ------------------------------------------------------------------
    // new() — REQ1-BOUNDS-reject-list (each → Invalid)
    // ------------------------------------------------------------------

    #[test]
    fn new_rejects_widening_compact_bytes() {
        // maximum_plus_one: 65537 > 65536 → widening → Invalid.
        let result = Bounds::new(Some(&ov(br#"{"compact_bytes":65537}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_unknown_key() {
        let result = Bounds::new(Some(&ov(br#"{"unknown_key":100}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_zero_value() {
        let result = Bounds::new(Some(&ov(br#"{"compact_bytes":0}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_negative_value() {
        let result = Bounds::new(Some(&ov(br#"{"compact_bytes":-1}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_non_integer_float() {
        let result = Bounds::new(Some(&ov(br#"{"compact_bytes":1.5}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_non_integer_exponent() {
        let result = Bounds::new(Some(&ov(br#"{"compact_bytes":1e2}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_malformed_overrides_json() {
        // After the T3 rewire, Bounds::new consumes an already-decoded
        // JsonValue; malformed overrides JSON is therefore rejected by the
        // tagged decoder itself (the end-to-end caller behavior is unchanged).
        let result = json_decode(b"not json", &Bounds::maximum());
        assert_eq!(result.map(|v| Bounds::new(Some(&v))), Err(Invalid));
    }

    #[test]
    fn new_rejects_trailing_bytes_in_overrides_json() {
        let result = json_decode(b"{}  garbage", &Bounds::maximum());
        assert_eq!(result.map(|v| Bounds::new(Some(&v))), Err(Invalid));
    }

    #[test]
    fn new_rejects_non_object_overrides_root() {
        // A non-object overrides root (array / scalar) is invalid per the contract.
        let result = Bounds::new(Some(&ov(b"[]")));
        assert_eq!(result, Err(Invalid));
    }

    // ------------------------------------------------------------------
    // Fixed-width keys — REQ1-BOUNDS-fixed-widths
    // ------------------------------------------------------------------

    #[test]
    fn new_accepts_exact_fixed_width_digest() {
        let result = Bounds::new(Some(&ov(br#"{"digest_bytes":32}"#)));
        assert!(result.is_ok());
    }

    #[test]
    fn new_rejects_fixed_width_digest_below() {
        let result = Bounds::new(Some(&ov(br#"{"digest_bytes":31}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_fixed_width_digest_above() {
        let result = Bounds::new(Some(&ov(br#"{"digest_bytes":33}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_fixed_width_public_key_below() {
        let result = Bounds::new(Some(&ov(br#"{"public_key_bytes":31}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_fixed_width_public_key_above() {
        let result = Bounds::new(Some(&ov(br#"{"public_key_bytes":33}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_fixed_width_signature_below() {
        let result = Bounds::new(Some(&ov(br#"{"signature_bytes":63}"#)));
        assert_eq!(result, Err(Invalid));
    }

    #[test]
    fn new_rejects_fixed_width_signature_above() {
        let result = Bounds::new(Some(&ov(br#"{"signature_bytes":65}"#)));
        assert_eq!(result, Err(Invalid));
    }

    // ------------------------------------------------------------------
    // Corpus: priv/conformance/v1/corpus/cases/bounds/new.json (79 cases)
    // ------------------------------------------------------------------

    #[test]
    fn corpus_bounds_new_all_79_cases() {
        let path = format!(
            "{}/../../priv/conformance/v1/corpus/cases/bounds/new.json",
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
            let overrides = &case["input"]["overrides"];
            // Re-serialize the corpus overrides object to bytes, then decode
            // through the real tagged decoder so the rewired
            // `Bounds::new(Option<&JsonValue>)` path is exercised end-to-end.
            let overrides_bytes = serde_json::to_vec(overrides)
                .unwrap_or_else(|e| panic!("serialize overrides for {id}: {e}"));
            let result = match json_decode(&overrides_bytes, &Bounds::maximum()) {
                Ok(value) => Bounds::new(Some(&value)),
                Err(Invalid) => Err(Invalid),
            };
            let actual_ok = result.is_ok();
            let expected_ok = expected_verdict == "valid";

            if actual_ok == expected_ok {
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict} actual_ok={actual_ok}");
            }
        }

        eprintln!("agreed={agreed} disagreed={disagreed}");
        assert_eq!(agreed, 79, "agreed count (total cases should be 79)");
        assert_eq!(disagreed, 0, "disagreed count");
    }

    #[test]
    fn corpus_valid_tightened_carries_exact_overrides() {
        // Mirrors bounds-new-valid-tightened: two overrides, rest at maximum.
        let b = Bounds::new(Some(&ov(br#"{"compact_bytes":1000,"string_bytes":4096}"#)))
            .expect("tightened overrides accepted");
        assert_eq!(b.compact_bytes(), 1000);
        assert_eq!(b.string_bytes(), 4096);
        // Non-overridden values stay at maximum.
        assert_eq!(b.depth(), 32);
        assert_eq!(b.kid_bytes(), 128);
        assert_eq!(b.archive_bytes(), 270_820_384);
    }
}
