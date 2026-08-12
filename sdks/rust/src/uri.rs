//! HTTPS-only URI normalization (RFC 3986 §3, §6.2; `docs/protocol-v1.md` §URI).
//!
//! Target URIs are bounded ASCII, hierarchical, and HTTPS-only, with a nonempty
//! authority and host and no user information, fragment, or query. This module
//! is a pure byte transform — it performs no DNS, IDNA, or network work
//! (`REQ1-URI-no-network`). Verification is not authority: the normalized string
//! is a comparison key, never an execution credential.
//!
//! Rules enforced (`docs/protocol-v1.md` §URI normalization, lines 226–244):
//! - `REQ1-URI-https-only`: the scheme MUST be exactly `https` (ASCII
//!   case-insensitive; normalized lowercase). HTTP or any other scheme →
//!   [`Invalid`].
//! - `REQ1-URI-reject-list`: HTTP / other scheme, an authority-less form,
//!   malformed percent escapes, ambiguous authority/port syntax, control bytes
//!   (`0x00`–`0x1f` / `0x7f`), non-ASCII bytes (`>= 0x80`), out-of-range port
//!   (`0` or `> 65535`), empty port, user-info (`@` in the authority), fragment
//!   (`#`), or query (`?`) are all [`Invalid`].
//! - `REQ1-URI-no-network`: the host is validated by grammar only.
//! - `REQ1-URI-pre-normalized`: both expected and proof URIs MUST already equal
//!   the normal form; this function produces that form.

use crate::bounds::Bounds;
use crate::error::{Invalid, Result};

// ============================================================================
// Character classes — RFC 3986 §2.2 / §2.3
// ============================================================================

/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` (RFC 3986 §2.3).
fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`
/// (RFC 3986 §2.2).
fn is_sub_delim(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// Map one ASCII hex digit to its 4-bit value. The caller has already confirmed
/// the byte is a hex digit, so the catch-all returns 0 unreachable-in-practice.
fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ============================================================================
// Public entry point
// ============================================================================

/// Normalize a target URI to its canonical HTTPS-only form.
///
/// Returns [`Err`]`(`[`Invalid`]`)` for any byte outside the bounded ASCII
/// grammar, any non-`https` scheme, a missing/empty authority or host, a
/// malformed percent escape, an IPv4/IPv6/IPvFuture literal that violates the
/// exact RFC 3986 grammar, an out-of-range or empty port, user-info, a query, a
/// fragment, or an input/normalized length over `bounds.uri_bytes()`.
pub fn uri_normalize(text: &str, bounds: &Bounds) -> Result<String> {
    // REQ1-BOUNDS-ordering: the raw input ceiling is checked before any
    // structural work.
    if text.len() as u64 > bounds.uri_bytes() {
        return Err(Invalid);
    }
    let bytes = text.as_bytes();

    // REQ1-URI-reject-list (byte-level): reject query (`?`), fragment (`#`),
    // control bytes (0x00–0x1f / 0x7f), and non-ASCII bytes (>= 0x80) anywhere.
    // These have no legal position in a bounded ASCII HTTPS target URI.
    for &b in bytes {
        if b == b'?' || b == b'#' || b < 0x20 || b == 0x7f || b >= 0x80 {
            return Err(Invalid);
        }
    }

    // REQ1-URI-https-only: scheme MUST be exactly `https` (ASCII
    // case-insensitive) followed by `://`. Checking the literal `://` after a
    // 5-byte scheme also rejects longer schemes (`httpsx://`) and the
    // authority-less single-slash form (`https:/path`).
    if bytes.len() < 8
        || bytes[5] != b':'
        || bytes[6] != b'/'
        || bytes[7] != b'/'
        || !bytes[..5]
            .iter()
            .zip(b"https".iter())
            .all(|(&a, &b)| a.to_ascii_lowercase() == b)
    {
        return Err(Invalid);
    }

    // Split authority (up to the first `/`) from the path. `?`/`#` are already
    // rejected globally, so the authority terminates at the first `/` or EOL.
    let rest = &bytes[8..];
    let (authority_bytes, path_bytes) = match rest.iter().position(|&b| b == b'/') {
        None => (rest, &[][..]),
        Some(idx) => (&rest[..idx], &rest[idx..]),
    };

    let (host, port) = parse_authority(authority_bytes)?;
    let path = normalize_path(path_bytes)?;

    // Assemble the canonical form: `https://` + host + [ `:` port ] + path.
    let mut out: Vec<u8> = Vec::with_capacity(8 + host.len() + 6 + path.len());
    out.extend_from_slice(b"https://");
    out.extend_from_slice(&host);
    if let Some(p) = &port {
        out.push(b':');
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&path);

    // All surviving bytes are ASCII (non-ASCII was rejected above), so
    // from_utf8 is infallible; the map_err keeps the failure closed regardless.
    let normalized = String::from_utf8(out).map_err(|_| Invalid)?;

    // Output ceiling is checked against the *normalized* byte length.
    if normalized.len() as u64 > bounds.uri_bytes() {
        return Err(Invalid);
    }
    Ok(normalized)
}

// ============================================================================
// Authority — RFC 3986 §3.2: [ userinfo "@" ] host [ ":" port ]
// ============================================================================

/// Parse the authority byte slice into `(normalized_host, Option<port>)`.
///
/// Rejects an empty authority, any user-info (`@`), a malformed bracketed
/// IP-literal, an out-of-range/empty/non-digit port, and ambiguous
/// authority/port syntax.
fn parse_authority(auth: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    if auth.is_empty() {
        return Err(Invalid);
    }
    // No user information is permitted (`REQ1-URI-reject-list`): an `@` in the
    // authority denotes `[userinfo "@"], so any `@` is invalid.
    if auth.contains(&b'@') {
        return Err(Invalid);
    }

    if auth[0] == b'[' {
        // IP-literal: `[` ( IPv6address / IPvFuture ) `]`.
        let close = auth.iter().position(|&b| b == b']').ok_or(Invalid)?;
        let content = &auth[1..close];
        let normalized_content = validate_ip_literal(content)?;
        let port = parse_port_after_literal(&auth[close + 1..])?;
        let mut host = Vec::with_capacity(normalized_content.len() + 2);
        host.push(b'[');
        host.extend_from_slice(&normalized_content);
        host.push(b']');
        Ok((host, port))
    } else {
        // IPv4address / reg-name. The first `:` (if any) is the port separator:
        // neither IPv4 nor reg-name may contain `:` (`:` is a gen-delim, not a
        // sub-delim), so there is no ambiguity.
        let (host_str, port) = match auth.iter().position(|&b| b == b':') {
            None => (auth, None),
            Some(idx) => (&auth[..idx], parse_port(&auth[idx + 1..])?),
        };
        if host_str.is_empty() {
            return Err(Invalid);
        }
        let host = if is_ipv4_candidate(host_str) {
            // REQ1-URI-reject-list: a dotted-numeric form MUST satisfy the exact
            // `dec-octet` grammar (no leading zeroes, each octet 0–255).
            for part in host_str.split(|&b| b == b'.') {
                if !is_dec_octet(part) {
                    return Err(Invalid);
                }
            }
            host_str.to_vec()
        } else {
            normalize_reg_name(host_str)?
        };
        Ok((host, port))
    }
}

/// Parse the optional `:port` that follows a bracketed IP-literal. Anything
/// other than end-of-authority or a `:`-led digit run is invalid. A dropped
/// default port (443) is reflected as `None`.
fn parse_port_after_literal(after: &[u8]) -> Result<Option<Vec<u8>>> {
    if after.is_empty() {
        Ok(None)
    } else if after[0] == b':' {
        parse_port(&after[1..])
    } else {
        Err(Invalid)
    }
}

/// Validate and canonicalize a port digit run.
///
/// Returns `Ok(None)` for the default port (443, after stripping leading
/// zeroes), `Ok(Some(digits))` for a preserved non-default port, and
/// [`Err`]`(`[`Invalid`]`)` for an empty, non-digit, zero, or `> 65535` port.
fn parse_port(digits: &[u8]) -> Result<Option<Vec<u8>>> {
    if digits.is_empty() {
        return Err(Invalid);
    }
    if !digits.iter().all(|&c| c.is_ascii_digit()) {
        return Err(Invalid);
    }
    // Checked arithmetic rejects absurdly long digit runs via overflow.
    let mut val: u64 = 0;
    for &c in digits {
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(Invalid)?;
    }
    if val == 0 || val > 65535 {
        return Err(Invalid);
    }
    // Canonical: strip leading zeroes (`0443` → `443`); `0` alone was rejected.
    let stripped: Vec<u8> = digits.iter().copied().skip_while(|&c| c == b'0').collect();
    let stripped = if stripped.is_empty() {
        b"0".to_vec()
    } else {
        stripped
    };
    if stripped == b"443" {
        Ok(None)
    } else {
        Ok(Some(stripped))
    }
}

// ============================================================================
// Host — RFC 3986 §3.2.2
// ============================================================================

/// Validate a bracketed IP-literal body and return its lowercased form.
fn validate_ip_literal(content: &[u8]) -> Result<Vec<u8>> {
    if content.is_empty() {
        return Err(Invalid); // `[]`
    }
    // Hex digits and the IPvFuture version flag are case-insensitive; lowercase
    // the whole literal for both validation and output (RFC 3986 §6.2.2.1,
    // RFC 4291 §2.2).
    let lower: Vec<u8> = content.iter().map(|&b| b.to_ascii_lowercase()).collect();
    if is_ipvfuture_shape(&lower) {
        if validate_ipvfuture(&lower) {
            Ok(lower)
        } else {
            Err(Invalid)
        }
    } else {
        validate_ipv6(&lower).ok_or(Invalid)?;
        Ok(lower)
    }
}

/// `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`.
/// Detect the *shape* (leading `v`, then 1+ hex digits, then `.`); a body
/// matching the shape is dispatched to IPvFuture and never falls back to
/// IPv6 (the `.` after the version makes the intent unambiguous).
fn is_ipvfuture_shape(s: &[u8]) -> bool {
    if s.len() < 3 || s[0] != b'v' {
        return false;
    }
    let mut i = 1;
    let mut hex = 0usize;
    while i < s.len() && s[i].is_ascii_hexdigit() {
        hex += 1;
        i += 1;
    }
    hex >= 1 && i < s.len() && s[i] == b'.'
}

/// Full IPvFuture grammar check (shape already confirmed).
fn validate_ipvfuture(s: &[u8]) -> bool {
    // s[0] == b'v'; consume 1+ HEXDIG then '.'.
    let mut i = 1;
    while i < s.len() && s[i].is_ascii_hexdigit() {
        i += 1;
    }
    // i sits at the '.' (guaranteed by is_ipvfuture_shape).
    i += 1; // skip '.'
    let mut tail = 0usize;
    while i < s.len() {
        let c = s[i];
        if is_unreserved(c) || is_sub_delim(c) || c == b':' {
            tail += 1;
            i += 1;
        } else {
            return false;
        }
    }
    tail >= 1
}

/// `IPv6address` (RFC 3986 / RFC 4291): up to 8 hextets of 1–4 hex digits
/// separated by `:`, with at most one `::` elision. Returns `Some(())` for a
/// well-formed literal and `None` otherwise. Embedded IPv4 in `ls32` is NOT
/// supported (a conservative, fail-closed subset — see module risk notes).
fn validate_ipv6(s: &[u8]) -> Option<()> {
    if s.is_empty() {
        return None;
    }
    // Locate the elision (`::`). At most one is permitted, and a run of three
    // or more colons (`:::`) is malformed.
    let mut elision: Option<usize> = None;
    let mut i = 0;
    while i + 1 < s.len() {
        if s[i] == b':' && s[i + 1] == b':' {
            if elision.is_some() {
                return None; // two elisions (e.g. `1::2::3`)
            }
            if i + 2 < s.len() && s[i + 2] == b':' {
                return None; // `:::` or longer run
            }
            elision = Some(i);
            i += 2;
        } else {
            i += 1;
        }
    }

    let (left, right) = match elision {
        None => (s, None),
        Some(p) => (&s[..p], Some(&s[p + 2..])),
    };
    let left_parts: Vec<&[u8]> = if left.is_empty() {
        Vec::new()
    } else {
        left.split(|&b| b == b':').collect()
    };
    let right_parts: Vec<&[u8]> = match right {
        None => Vec::new(),
        Some([]) => Vec::new(),
        Some(r) => r.split(|&b| b == b':').collect(),
    };

    // Every hextet must be 1–4 hex digits. An empty part here (a stray `:`
    // adjacent to the elision or a trailing/leading colon) is malformed.
    for h in left_parts.iter().chain(right_parts.iter()) {
        if h.is_empty() || !is_h16(h) {
            return None;
        }
    }

    let total = left_parts.len() + right_parts.len();
    match elision {
        None if total == 8 => Some(()),
        Some(_) if total <= 7 => Some(()), // elision fills ≥ 1 group up to 8
        _ => None,
    }
}

/// `h16 = 1*4HEXDIG`.
fn is_h16(s: &[u8]) -> bool {
    matches!(s.len(), 1..=4) && s.iter().all(|&c| c.is_ascii_hexdigit())
}

/// A host is an IPv4 *candidate* iff it is exactly four non-empty all-digit
/// dot-separated groups. Such a form MUST be validated against the `dec-octet`
/// grammar; everything else is treated as a reg-name.
fn is_ipv4_candidate(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    let parts: Vec<&[u8]> = s.split(|&b| b == b'.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.iter().all(|&c| c.is_ascii_digit()))
}

/// `dec-octet` without the leading-zero alternatives: `0` alone is allowed, but
/// `00`/`01`/`0443` and any octet `> 255` are not.
fn is_dec_octet(s: &[u8]) -> bool {
    match s.len() {
        1 => s[0].is_ascii_digit(),
        2 => (b'1'..=b'9').contains(&s[0]) && s[1].is_ascii_digit(),
        3 => {
            s[0] != b'0' && {
                let n = u32::from(s[0] - b'0') * 100
                    + u32::from(s[1] - b'0') * 10
                    + u32::from(s[2] - b'0');
                (100..=255).contains(&n)
            }
        }
        _ => false,
    }
}

/// Validate and normalize a reg-name: lowercase, decode percent-encoded
/// unreserved octets (lowercased), and preserve percent-encoded reserved
/// octets with uppercased hex. `reg-name = *( unreserved / pct-encoded /
/// sub-delims )`.
fn normalize_reg_name(s: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if is_unreserved(c) || is_sub_delim(c) {
            out.push(c.to_ascii_lowercase());
            i += 1;
        } else if c == b'%' {
            // Host is lowercased: a decoded unreserved byte (e.g. %45 → 'E') is
            // emitted lowercased ('e'); a reserved escape is preserved as `%HH`
            // with uppercased hex.
            let h1 = s.get(i + 1).copied().ok_or(Invalid)?;
            let h2 = s.get(i + 2).copied().ok_or(Invalid)?;
            if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                return Err(Invalid);
            }
            let decoded = hex_val(h1) * 16 + hex_val(h2);
            if is_unreserved(decoded) {
                out.push(decoded.to_ascii_lowercase());
            } else {
                out.push(b'%');
                out.push(h1.to_ascii_uppercase());
                out.push(h2.to_ascii_uppercase());
            }
            i += 3;
        } else {
            return Err(Invalid);
        }
    }
    Ok(out)
}

// ============================================================================
// Path — RFC 3986 §3.3
// ============================================================================

/// Validate and percent-normalize the path, then apply RFC 3986 §5.2.4
/// `remove_dot_segments`. An empty result maps to `/` (`REQ1-URI` empty-path
/// rule). `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`, joined
/// by `/`. Path bytes are case-sensitive (RFC 3986 §6.2.2.1): decoded
/// unreserved escapes keep their case; only the percent *hex* is uppercased.
fn normalize_path(path: &[u8]) -> Result<Vec<u8>> {
    let mut normalized = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let c = path[i];
        if is_unreserved(c) || is_sub_delim(c) || c == b':' || c == b'@' || c == b'/' {
            normalized.push(c);
            i += 1;
        } else if c == b'%' {
            let h1 = path.get(i + 1).copied().ok_or(Invalid)?;
            let h2 = path.get(i + 2).copied().ok_or(Invalid)?;
            if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                return Err(Invalid);
            }
            let decoded = hex_val(h1) * 16 + hex_val(h2);
            if is_unreserved(decoded) {
                // Decode the unreserved octet to its literal byte (case preserved).
                normalized.push(decoded);
            } else {
                // Reserved escape: keep the 3-byte `%HH` sequence so
                // remove_dot_segments never treats it as a `/` separator
                // (REQ1-URI preserve-reserved-as-path-data).
                normalized.push(b'%');
                normalized.push(h1.to_ascii_uppercase());
                normalized.push(h2.to_ascii_uppercase());
            }
            i += 3;
        } else {
            return Err(Invalid);
        }
    }

    let cleaned = remove_dot_segments(&normalized);
    if cleaned.is_empty() {
        Ok(b"/".to_vec())
    } else {
        Ok(cleaned)
    }
}

/// RFC 3986 §5.2.4 `remove_dot_segments`. Operates on absolute-or-empty paths
/// (path-abempty) only — the sole form produced for an HTTPS authority URI.
fn remove_dot_segments(path: &[u8]) -> Vec<u8> {
    let mut input: Vec<u8> = path.to_vec();
    let mut output: Vec<u8> = Vec::new();

    while !input.is_empty() {
        // A. leading `../` or `./`.
        if input.starts_with(b"../") {
            input.drain(0..3);
        } else if input.starts_with(b"./") {
            input.drain(0..2);
        }
        // B. `/./` or exactly `/.` → replace with `/`.
        else if input.starts_with(b"/./") {
            input.drain(1..3); // drop the `.`, leaving `/` + rest
        } else if input == b"/." {
            input = vec![b'/'];
        }
        // C. `/../` or exactly `/..` → replace with `/` and pop the last output
        // segment.
        else if input.starts_with(b"/../") {
            input.drain(1..4);
            pop_last_segment(&mut output);
        } else if input == b"/.." {
            input = vec![b'/'];
            pop_last_segment(&mut output);
        }
        // D. only `.` or `..`.
        else if input == b"." || input == b".." {
            input.clear();
        }
        // E. move the first segment (its leading `/` if any, up to the next
        // `/`) to the output.
        else {
            let start = usize::from(input[0] == b'/');
            let mut j = start;
            while j < input.len() && input[j] != b'/' {
                j += 1;
            }
            output.extend_from_slice(&input[..j]);
            input.drain(0..j);
        }
    }
    output
}

/// Remove the last segment from `output` together with its preceding `/`.
fn pop_last_segment(output: &mut Vec<u8>) {
    if let Some(idx) = output.iter().rposition(|&b| b == b'/') {
        output.truncate(idx);
    } else {
        output.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;

    const B: fn() -> Bounds = Bounds::maximum;

    // ------------------------------------------------------------------
    // Scheme normalization — REQ1-URI-https-only
    // ------------------------------------------------------------------

    #[test]
    fn https_scheme_preserved_lowercase() {
        assert_eq!(
            uri_normalize("https://example.com/", &B()).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn uppercase_scheme_normalized_to_https() {
        // Scheme is ASCII case-insensitive; normalized lowercase.
        assert_eq!(
            uri_normalize("HTTPS://example.com/", &B()).unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            uri_normalize("HtTpS://example.com/", &B()).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn uppercase_host_normalized() {
        assert_eq!(
            uri_normalize("https://EXAMPLE.com/", &B()).unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            uri_normalize("https://EXAMPLE.test/", &B()).unwrap(),
            "https://example.test/"
        );
    }

    // ------------------------------------------------------------------
    // Normalization rules (exactness)
    // ------------------------------------------------------------------

    #[test]
    fn decode_unreserved_percent_escape() {
        // %7e → ~ (tilde is unreserved). REQ1: decode percent-encoded unreserved.
        assert_eq!(
            uri_normalize("https://example.com/%7e", &B()).unwrap(),
            "https://example.com/~"
        );
        assert_eq!(
            uri_normalize("https://example.com/%7E", &B()).unwrap(),
            "https://example.com/~"
        );
        // %41 → A.
        assert_eq!(
            uri_normalize("https://example.com/%41", &B()).unwrap(),
            "https://example.com/A"
        );
    }

    #[test]
    fn uppercase_percent_hex() {
        // %2f → %2F (reserved `/` preserved as path data, hex uppercased).
        assert_eq!(
            uri_normalize("https://example.com:8443/a%2fb", &B()).unwrap(),
            "https://example.com:8443/a%2Fb"
        );
        assert_eq!(
            uri_normalize("https://example.com:8443/a%2Fb", &B()).unwrap(),
            "https://example.com:8443/a%2Fb"
        );
    }

    #[test]
    fn preserve_reserved_percent_as_path_data() {
        // %2F is encoded `/` (gen-delim, reserved): preserved as %2F, NOT decoded
        // into a path separator.
        assert_eq!(
            uri_normalize("https://example.com:8443/a%2Fb", &B()).unwrap(),
            "https://example.com:8443/a%2Fb"
        );
    }

    #[test]
    fn remove_dot_segments() {
        // RFC 3986 §5.2.4 remove_dot_segments.
        assert_eq!(
            uri_normalize("https://example.com/a/../b", &B()).unwrap(),
            "https://example.com/b"
        );
        assert_eq!(
            uri_normalize("https://example.com/./a", &B()).unwrap(),
            "https://example.com/a"
        );
        assert_eq!(
            uri_normalize("https://example.com/a/b/../../c", &B()).unwrap(),
            "https://example.com/c"
        );
    }

    #[test]
    fn empty_path_maps_to_slash() {
        assert_eq!(
            uri_normalize("https://example.com", &B()).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn drop_default_port_443() {
        assert_eq!(
            uri_normalize("https://example.com:443/", &B()).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn strip_leading_zero_port_then_drop_if_443() {
        // :0443 → strip leading zeroes → 443 → drop.
        assert_eq!(
            uri_normalize("https://example.com:0443/", &B()).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn preserve_nondefault_port() {
        assert_eq!(
            uri_normalize("https://example.com:8443/", &B()).unwrap(),
            "https://example.com:8443/"
        );
        // Leading zeroes stripped on a non-443 port.
        assert_eq!(
            uri_normalize("https://example.com:08443/", &B()).unwrap(),
            "https://example.com:8443/"
        );
    }

    #[test]
    fn tilde_literal_in_path_preserved() {
        assert_eq!(
            uri_normalize("https://example.com/a/~", &B()).unwrap(),
            "https://example.com/a/~"
        );
    }

    // ------------------------------------------------------------------
    // Host grammar — RFC 3986 §3.2.2
    // ------------------------------------------------------------------

    #[test]
    fn ipv4_address_valid() {
        assert_eq!(
            uri_normalize("https://192.0.2.1/", &B()).unwrap(),
            "https://192.0.2.1/"
        );
        assert_eq!(
            uri_normalize("https://0.0.0.0/", &B()).unwrap(),
            "https://0.0.0.0/"
        );
        assert_eq!(
            uri_normalize("https://255.255.255.255/", &B()).unwrap(),
            "https://255.255.255.255/"
        );
    }

    #[test]
    fn ipv6_address_valid() {
        assert_eq!(
            uri_normalize("https://[2001:db8::1]/", &B()).unwrap(),
            "https://[2001:db8::1]/"
        );
        assert_eq!(
            uri_normalize("https://[::1]/", &B()).unwrap(),
            "https://[::1]/"
        );
        assert_eq!(
            uri_normalize("https://[::]/", &B()).unwrap(),
            "https://[::]/"
        );
        // Full 8-hextet form.
        assert_eq!(
            uri_normalize("https://[2001:db8:0:0:0:0:0:1]/", &B()).unwrap(),
            "https://[2001:db8:0:0:0:0:0:1]/"
        );
        // Uppercase hex normalized to lowercase.
        assert_eq!(
            uri_normalize("https://[2001:DB8::1]/", &B()).unwrap(),
            "https://[2001:db8::1]/"
        );
    }

    #[test]
    fn ipvfuture_valid() {
        assert_eq!(
            uri_normalize("https://[v1.a:b]/", &B()).unwrap(),
            "https://[v1.a:b]/"
        );
    }

    #[test]
    fn reg_name_with_sub_delims_valid() {
        // sub-delims `!`, `;`, `=`, etc. are legal in a reg-name.
        assert_eq!(
            uri_normalize("https://a.b.example.com/", &B()).unwrap(),
            "https://a.b.example.com/"
        );
    }

    // ------------------------------------------------------------------
    // REQ1-URI-reject-list — each class → Invalid
    // ------------------------------------------------------------------

    #[test]
    fn reject_http_scheme() {
        assert_eq!(
            uri_normalize("http://example.test/path", &B()),
            Err(Invalid)
        );
        assert_eq!(uri_normalize("http://example.com/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_other_scheme() {
        assert_eq!(uri_normalize("ftp://example.com/", &B()), Err(Invalid));
        assert_eq!(uri_normalize("ittps://example.com/a", &B()), Err(Invalid));
    }

    #[test]
    fn reject_authority_less_form() {
        // `https:/path` (single slash) — empty authority.
        assert_eq!(uri_normalize("https:/path", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https:///path", &B()), Err(Invalid));
    }

    #[test]
    fn reject_control_byte() {
        assert_eq!(
            uri_normalize("https://example.com/\u{0}", &B()),
            Err(Invalid)
        );
        assert_eq!(
            uri_normalize("https://example.com/\u{1f}", &B()),
            Err(Invalid)
        );
        assert_eq!(
            uri_normalize("https://example.com/\u{7f}", &B()),
            Err(Invalid)
        );
        assert_eq!(
            uri_normalize("https://exa\u{0}mple.com/", &B()),
            Err(Invalid)
        );
    }

    #[test]
    fn reject_non_ascii_byte() {
        assert_eq!(
            uri_normalize("https://example.com/\u{80}", &B()),
            Err(Invalid)
        );
        assert_eq!(uri_normalize("https://exämple.com/", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://example.com/é", &B()), Err(Invalid));
    }

    #[test]
    fn reject_query() {
        assert_eq!(
            uri_normalize("https://example.com/?q=1", &B()),
            Err(Invalid)
        );
        assert_eq!(uri_normalize("https://example.com/?", &B()), Err(Invalid));
    }

    #[test]
    fn reject_fragment() {
        assert_eq!(
            uri_normalize("https://example.com/#frag", &B()),
            Err(Invalid)
        );
        assert_eq!(uri_normalize("https://example.com/#", &B()), Err(Invalid));
    }

    #[test]
    fn reject_user_info() {
        assert_eq!(
            uri_normalize("https://user@example.com/", &B()),
            Err(Invalid)
        );
        assert_eq!(
            uri_normalize("https://user:pass@example.com/", &B()),
            Err(Invalid)
        );
    }

    #[test]
    fn reject_port_zero() {
        assert_eq!(uri_normalize("https://example.com:0/", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://example.com:00/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_port_out_of_range() {
        assert_eq!(
            uri_normalize("https://example.com:65536/", &B()),
            Err(Invalid)
        );
        assert_eq!(
            uri_normalize("https://example.com:99999/", &B()),
            Err(Invalid)
        );
    }

    #[test]
    fn reject_empty_port() {
        assert_eq!(uri_normalize("https://example.com:/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_non_digit_port() {
        assert_eq!(
            uri_normalize("https://example.com:abc/", &B()),
            Err(Invalid)
        );
        assert_eq!(uri_normalize("https://example.com:8a/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_malformed_percent_escape() {
        assert_eq!(uri_normalize("https://example.com/%", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://example.com/%2", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://example.com/%GG", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://example.com/%2G", &B()), Err(Invalid));
    }

    // ------------------------------------------------------------------
    // IPv6 reject-list (the falsifier-pinned cases)
    // ------------------------------------------------------------------

    #[test]
    fn reject_ipv6_triple_colon() {
        assert_eq!(uri_normalize("https://[:::]/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipv6_two_elisions() {
        assert_eq!(uri_normalize("https://[1::2::3]/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipv6_bad_hextet() {
        assert_eq!(uri_normalize("https://[gggg]/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipv6_hextet_too_long() {
        // h16 is 1-4 hex digits; 5 is invalid.
        assert_eq!(uri_normalize("https://[12345]/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipv6_too_many_hextets() {
        // 9 hextets without an elision.
        assert_eq!(
            uri_normalize("https://[1:2:3:4:5:6:7:8:9]/", &B()),
            Err(Invalid)
        );
    }

    #[test]
    fn reject_ipv6_unclosed_bracket() {
        assert_eq!(uri_normalize("https://[2001:db8::1/", &B()), Err(Invalid));
    }

    // ------------------------------------------------------------------
    // IPv4 / IPvFuture reject-list
    // ------------------------------------------------------------------

    #[test]
    fn reject_ipv4_leading_zero() {
        assert_eq!(uri_normalize("https://01.2.3.4/", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://1.02.3.4/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipv4_octet_range() {
        assert_eq!(uri_normalize("https://256.2.3.4/", &B()), Err(Invalid));
        assert_eq!(uri_normalize("https://1.2.3.300/", &B()), Err(Invalid));
    }

    #[test]
    fn reject_ipvfuture_malformed() {
        // No hex version before the dot.
        assert_eq!(uri_normalize("https://[v.a]/", &B()), Err(Invalid));
    }

    // ------------------------------------------------------------------
    // Bounds ceiling
    // ------------------------------------------------------------------

    #[test]
    fn reject_input_over_uri_bytes_bound() {
        // Tighten `uri_bytes` to a tiny ceiling and feed an input that exceeds
        // the raw length ceiling (checked before any structural work).
        let overrides = crate::json::json_decode(br#"{"uri_bytes":16}"#, &Bounds::maximum())
            .expect("decode overrides");
        let tight = Bounds::new(Some(&overrides)).expect("tighten");
        // `https://example.com/path` is 24 bytes > 16 → Invalid.
        assert_eq!(
            uri_normalize("https://example.com/path", &tight),
            Err(Invalid)
        );
    }

    #[test]
    fn accept_and_reject_at_uri_bytes_bound() {
        // `https://a.b/c` is 13 bytes (already normalized). The ceiling is
        // inclusive: bound = 13 accepts, bound = 12 rejects on the raw length.
        let input = "https://a.b/c";
        assert_eq!(input.len(), 13);
        let ok = Bounds::new(Some(
            &crate::json::json_decode(br#"{"uri_bytes":13}"#, &Bounds::maximum()).expect("dec"),
        ))
        .expect("tighten");
        assert_eq!(uri_normalize(input, &ok).unwrap(), input);
        let bad = Bounds::new(Some(
            &crate::json::json_decode(br#"{"uri_bytes":12}"#, &Bounds::maximum()).expect("dec"),
        ))
        .expect("tighten");
        assert_eq!(uri_normalize(input, &bad), Err(Invalid));
    }

    // ------------------------------------------------------------------
    // Corpus: priv/conformance/v1/corpus/cases/uri/normalize.json (26 cases)
    // ------------------------------------------------------------------

    #[test]
    fn corpus_uri_normalize_all_26_cases() {
        let path = format!(
            "{}/../../priv/conformance/v1/corpus/cases/uri/normalize.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read corpus {path}: {e}"));
        let root: serde_json::Value = serde_json::from_str(&content).expect("corpus is valid JSON");
        let cases = root["cases"].as_array().expect("cases array");

        let mut agreed = 0usize;
        let mut disagreed = 0usize;
        let bounds = Bounds::maximum();

        for case in cases {
            let id = case["id"].as_str().unwrap_or("<no id>");
            let expected_verdict = case["expected"]["verdict"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing expected.verdict"));
            let input = case["input"]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("case {id} missing input.text"));
            let result = uri_normalize(input, &bounds);
            let actual_ok = result.is_ok();
            let expected_ok = expected_verdict == "valid";

            if actual_ok == expected_ok {
                if expected_ok {
                    let expected_normalized = case["expected"]["normalized"]
                        .as_str()
                        .unwrap_or_else(|| panic!("valid case {id} missing expected.normalized"));
                    let got = result.expect("valid case normalizes");
                    assert_eq!(
                        got, expected_normalized,
                        "case {id}: normalized string mismatch"
                    );
                }
                agreed += 1;
            } else {
                disagreed += 1;
                eprintln!("DISAGREE: id={id} expected={expected_verdict} actual_ok={actual_ok}");
            }
        }

        assert_eq!(agreed, 26, "agreed (total corpus cases should be 26)");
        assert_eq!(disagreed, 0, "disagreed count");
    }
}
