package verifier

import "strings"

// Claim-shape validators transcribed from spec/bap-v1.md § Claims and
// § Protected headers. All are fail-closed and value-free on rejection.

// allZeroHashB64 is the all-zero SHA-256 digest in canonical base64url: the
// genesis predecessor / chain-hash sentinel (ADR 0004).
const allZeroHashB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// validKid: case-sensitive 1..bound bytes of ASCII letters, digits, '-', '.',
// '_', '~' (REQ1-HEADER-kid-bytes). An untrusted hint, never a selector.
func validKid(kid string, byteCeiling int) bool {
	if len(kid) == 0 || len(kid) > byteCeiling {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// validHTM: 1..bound byte case-sensitive RFC 9110 method token; compared
// byte-for-byte, never case-normalized (REQ1-CLAIM-htm-bytes,
// REQ1-CLAIM-htm-no-case-normalize).
func validHTM(method string, byteCeiling int) bool {
	if len(method) == 0 || len(method) > byteCeiling {
		return false
	}
	for i := 0; i < len(method); i++ {
		if !isTchar(method[i]) {
			return false
		}
	}
	return true
}

func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// validStringOrURI: non-empty, at most byteCeiling UTF-8 bytes. When the
// value contains ":" it must be a structurally valid RFC 3986 URI — scheme
// grammar, ASCII-only, and a grammar-valid authority when "//" is present
// (the corpus pins "ht tp://x" and "http://a:b" invalid). Case-sensitive;
// never normalized.
func validStringOrURI(s string, byteCeiling int) bool {
	if len(s) == 0 || len(s) > byteCeiling {
		return false
	}
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return true // plain case-sensitive string
	}
	if !validScheme(s[:colon]) {
		return false
	}
	rest := s[colon+1:]
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	if strings.HasPrefix(rest, "//") {
		authority := rest[2:]
		if i := strings.IndexAny(authority, "/?#"); i >= 0 {
			authority = authority[:i]
		}
		if authority == "" || strings.Contains(authority, "@") {
			return false
		}
		host, port := splitHostPort(authority)
		if _, err := normalizeHost(host); err != nil {
			return false
		}
		if _, err := normalizePort(port); err != nil {
			return false
		}
	}
	return true
}

func validScheme(s string) bool {
	if len(s) == 0 {
		return false
	}
	if !(s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '-' || c == '.':
		default:
			return false
		}
	}
	return true
}

// validUUID: lowercase RFC 4122 textual form (8-4-4-4-12 lowercase hex with
// RFC 4122 version and variant nibbles).
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	version := s[14]
	if version < '1' || version > '5' {
		return false
	}
	variant := s[19]
	if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
		return false
	}
	return true
}

// canonicalDigestString decodes an unpadded base64url SHA-256 (ath, ba_req,
// jkt, chain hashes, fingerprints).
func canonicalDigestString(s string) ([32]byte, bool) {
	var out [32]byte
	raw, err := Base64urlDecode(s)
	if err != nil || len(raw) != 32 {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// integralTime extracts an integral NumericDate with the profile magnitude
// bound.
func integralTime(v Value, b Bounds) (int64, bool) {
	i, ok := v.(Int)
	if !ok || int64(i) > int64(b.IntegerMagnitude) || int64(i) < -int64(b.IntegerMagnitude) {
		return 0, false
	}
	return int64(i), true
}
