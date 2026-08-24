package verifier

import "strings"

// URI normalization (docs/protocol-v1.md § URI normalization; RFC 3986).
//
// Targets are bounded ASCII, hierarchical, HTTPS-only, with a nonempty
// authority and host, no user information, fragment, or query. Normalization
// lowercases scheme and host; uppercases percent hex; decodes only
// percent-encoded unreserved octets; preserves percent-encoded reserved
// octets as data; removes complete dot segments; maps an empty path to "/";
// drops port 443; and preserves a valid nondefault port and all other path
// bytes. No DNS, IDNA, or network work happens here (REQ1-URI-no-network).
//
// Host grammar is exact RFC 3986: reg-name over unreserved/sub-delim/valid
// percent escapes; all-numeric dotted hosts must be exact IPv4 dec-octets
// without leading-zero alternatives (the corpus pins 01.2.3.4 and 256.2.3.4
// invalid); bracketed literals are complete IPv6address or IPvFuture. A
// present port is 1..65535, canonical form strips leading zeroes and omits
// 443 (REQ1-URI-reject-list).

const unreservedBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
const subDelimBytes = "!$&'()*+,;="

// UriNormalize parses and normalizes a bounded target URI. It returns the
// normal form or ErrInvalid.
func UriNormalize(uri string, bounds *Bounds) (string, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return "", ErrInvalid
	}
	if len(uri) == 0 || len(uri) > b.URIBYtes {
		return "", ErrInvalid
	}
	for i := 0; i < len(uri); i++ {
		if uri[i] < 0x21 || uri[i] > 0x7e {
			return "", ErrInvalid // control, space, DEL, non-ASCII
		}
	}
	// scheme match is case-insensitive (RFC 3986 §3.1); output lowercased
	if len(uri) < 8 || strings.ToLower(uri[:8]) != "https://" {
		return "", ErrInvalid // wrong or non-hierarchical scheme
	}
	schemeRest := uri[8:]
	if strings.Contains(uri, "?") || strings.Contains(uri, "#") {
		return "", ErrInvalid // query/fragment forbidden
	}
	auth, path := "", ""
	if i := strings.IndexAny(schemeRest, "/"); i >= 0 {
		auth = schemeRest[:i]
		path = schemeRest[i:]
	} else {
		auth = schemeRest
	}
	if auth == "" {
		return "", ErrInvalid // empty authority
	}
	if strings.Contains(auth, "@") {
		return "", ErrInvalid // userinfo forbidden
	}
	hostRaw, portRaw := splitHostPort(auth)
	host, err := normalizeHost(hostRaw)
	if err != nil {
		return "", ErrInvalid
	}
	port, err := normalizePort(portRaw)
	if err != nil {
		return "", ErrInvalid
	}
	normPath, err := normalizePath(path)
	if err != nil {
		return "", ErrInvalid
	}
	out := "https://" + host
	if port != "" {
		out += ":" + port
	}
	out += normPath
	if len(out) > b.URIBYtes {
		return "", ErrInvalid
	}
	return out, nil
}

// uriNormalized is the verification-side gate: both expected and proof URIs
// MUST already equal the normal form (REQ1-URI-pre-normalized).
func uriNormalized(uri string, b Bounds) (string, error) {
	n, err := UriNormalize(uri, &b)
	if err != nil {
		return "", ErrInvalid
	}
	if n != uri {
		return "", ErrInvalid
	}
	return n, nil
}

// splitHostPort splits the authority into host and optional port, rejecting
// ambiguous colon syntax outside IP-literal brackets.
func splitHostPort(auth string) (string, string) {
	if strings.HasPrefix(auth, "[") {
		end := strings.Index(auth, "]")
		if end < 0 {
			return auth, "" // malformed; rejected later in normalizeHost
		}
		host := auth[:end+1]
		rest := auth[end+1:]
		if rest == "" {
			return host, ""
		}
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:]
		}
		return host, "\x00invalid" // trailing junk after bracket
	}
	if i := strings.LastIndex(auth, ":"); i >= 0 {
		if auth[i+1:] == "" {
			return auth, "\x00invalid" // present-but-empty port is invalid
		}
		return auth[:i], auth[i+1:]
	}
	return auth, ""
}

func normalizeHost(host string) (string, error) {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		if end < 0 || end != len(host)-1 {
			return "", ErrInvalid
		}
		literal := host[1 : len(host)-1]
		if literal == "" {
			return "", ErrInvalid
		}
		var norm string
		var err error
		if strings.HasPrefix(literal, "v") || strings.HasPrefix(literal, "V") {
			norm, err = normalizeIPvFuture(literal)
		} else {
			norm, err = normalizeIPv6(literal)
		}
		if err != nil {
			return "", ErrInvalid
		}
		return "[" + norm + "]", nil
	}
	if host == "" {
		return "", ErrInvalid // nonempty host required
	}
	// reg-name: unreserved / sub-delim / valid pct-encoded, with unreserved
	// escapes decoded. All-numeric dotted hosts must be exact IPv4.
	if isNumericDotted(host) {
		if !validIPv4(host) {
			return "", ErrInvalid
		}
		return host, nil
	}
	var out strings.Builder
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c == '%' {
			dec, n, err := decodeEscape(host, i)
			if err != nil {
				return "", ErrInvalid
			}
			i += n - 1
			if strings.IndexByte(unreservedBytes, dec) >= 0 {
				out.WriteByte(dec)
			} else {
				out.WriteByte('%')
				out.WriteByte(upperHex(dec >> 4))
				out.WriteByte(upperHex(dec & 0xf))
			}
			continue
		}
		if strings.IndexByte(unreservedBytes, c) < 0 && strings.IndexByte(subDelimBytes, c) < 0 {
			return "", ErrInvalid
		}
		out.WriteByte(lowerByte(c))
	}
	return out.String(), nil
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func upperHex(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'A' + v - 10
}

// isNumericDotted reports whether the host consists solely of digits and
// dots with at least one dot and no empty label: the shape that demands exact
// IPv4 interpretation.
func isNumericDotted(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	allDigits := true
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c != '.' && (c < '0' || c > '9') {
			allDigits = false
			break
		}
	}
	return allDigits
}

// validIPv4 enforces exact dec-octet forms: four labels, 0..255, no leading
// zeros except the single digit zero.
func validIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		v := 0
		for i := 0; i < len(p); i++ {
			v = v*10 + int(p[i]-'0')
		}
		if v > 255 {
			return false
		}
	}
	return true
}

func normalizePort(port string) (string, error) {
	if port == "" {
		return "", nil
	}
	v := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return "", ErrInvalid
		}
		v = v*10 + int(c-'0')
	}
	if v < 1 || v > 65535 {
		return "", ErrInvalid
	}
	if v == 443 {
		return "", nil
	}
	dec := []byte{}
	started := false
	for i := 0; i < len(port); i++ {
		if port[i] != '0' {
			started = true
		}
		if started {
			dec = append(dec, port[i])
		}
	}
	if len(dec) == 0 {
		return "0", nil // unreachable (v>=1); fail-closed default
	}
	return string(dec), nil
}

// normalizePath applies percent rules and RFC 3986 §5.2.4 dot-segment
// removal; the empty path maps to "/".
func normalizePath(path string) (string, error) {
	if path == "" {
		return "/", nil
	}
	var norm strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '%' {
			dec, n, err := decodeEscape(path, i)
			if err != nil {
				return "", ErrInvalid
			}
			i += n - 1
			if strings.IndexByte(unreservedBytes, dec) >= 0 {
				norm.WriteByte(dec)
			} else {
				norm.WriteByte('%')
				norm.WriteByte(upperHex(dec >> 4))
				norm.WriteByte(upperHex(dec & 0xf))
			}
			continue
		}
		if !pathChar(c) {
			return "", ErrInvalid
		}
		norm.WriteByte(c)
	}
	out := removeDotSegments(norm.String())
	if out == "" {
		out = "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out, nil
}

// pathChar: pchar and "/" — unreserved, sub-delims, ":", "@".
func pathChar(c byte) bool {
	return c == '/' ||
		strings.IndexByte(unreservedBytes, c) >= 0 ||
		strings.IndexByte(subDelimBytes+":@", c) >= 0
}

// decodeEscape decodes a %HH escape at offset i, returning the octet and the
// bytes consumed.
func decodeEscape(s string, i int) (byte, int, error) {
	if i+2 >= len(s) {
		return 0, 0, ErrInvalid
	}
	hi := hexVal(s[i+1])
	lo := hexVal(s[i+2])
	if hi < 0 || lo < 0 {
		return 0, 0, ErrInvalid
	}
	return byte(hi<<4 | lo), 3, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// removeDotSegments implements RFC 3986 §5.2.4.
func removeDotSegments(path string) string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case ".":
			// drop
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	res := strings.Join(out, "/")
	// join preserves a trailing slash when the final segment was . or ..
	if strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") ||
		path == "." || path == ".." {
		if !strings.HasSuffix(res, "/") {
			res += "/"
		}
	}
	return res
}

// normalizeIPv6 validates a complete RFC 4291-style IPv6address (8 groups or
// one "::" elision; optional embedded trailing IPv4) and returns the
// structure-preserving normal form: lowercase hex, per-group leading zeros
// stripped, elision kept as written. The corpus pins [2001:db8::1] as its own
// normal form (no expansion, no recompression).
func normalizeIPv6(lit string) (string, error) {
	if !strings.Contains(lit, ":") {
		return "", ErrInvalid
	}
	head, tail, hasElision := strings.Cut(lit, "::")
	if hasElision && strings.Contains(tail, "::") {
		return "", ErrInvalid // two elisions
	}
	parseSide := func(side string, allowIPv4 bool) ([]string, error) {
		if side == "" {
			return nil, nil
		}
		var groups []string
		for _, part := range strings.Split(side, ":") {
			if part == "" {
				return nil, ErrInvalid // empty group outside the elision
			}
			groups = append(groups, part)
		}
		// the LAST group may be an embedded IPv4
		last := groups[len(groups)-1]
		if strings.Contains(last, ".") {
			if !allowIPv4 || !validIPv4(last) {
				return nil, ErrInvalid
			}
		} else {
			for _, g := range groups {
				if len(g) > 4 {
					return nil, ErrInvalid
				}
				for i := 0; i < len(g); i++ {
					if hexVal(g[i]) < 0 {
						return nil, ErrInvalid
					}
				}
			}
		}
		return groups, nil
	}
	headGroups, err := parseSide(head, !hasElision || tail != "")
	if err != nil {
		return "", ErrInvalid
	}
	tailGroups, err := parseSide(tail, true)
	if err != nil {
		return "", ErrInvalid
	}
	total := len(headGroups) + len(tailGroups)
	if hasElision {
		if total > 7 {
			return "", ErrInvalid
		}
	} else if total != 8 || strings.Count(lit, ":") != 7 {
		return "", ErrInvalid
	}
	normalizeGroup := func(g string) string {
		if strings.Contains(g, ".") {
			return g // embedded IPv4 kept in dotted form
		}
		s := lowerHexStr(g)
		i := 0
		for i < len(s)-1 && s[i] == '0' {
			i++
		}
		return s[i:]
	}
	var out strings.Builder
	for i, g := range headGroups {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(normalizeGroup(g))
	}
	if hasElision {
		out.WriteString("::")
	}
	for i, g := range tailGroups {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(normalizeGroup(g))
	}
	return out.String(), nil
}

func lowerHexGroup(v int) string {
	s := ""
	for i := 3; i >= 0; i-- {
		d := (v >> (4 * i)) & 0xf
		if d < 10 {
			s += string(rune('0' + d))
		} else {
			s += string(rune('a' + d - 10))
		}
	}
	return s
}

func lowerHexStr(g string) string {
	out := []byte(g)
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c >= 'A' && c <= 'F' {
			out[i] = c + 32
		}
	}
	return string(out)
}

func stripLeadingZerosHex(g string) string {
	i := 0
	for i < len(g)-1 && g[i] == '0' {
		i++
	}
	return g[i:]
}

// normalizeIPvFuture parses "v" 1*HEXDIG "." 1*(unreserved / sub-delims / ":").
func normalizeIPvFuture(lit string) (string, error) {
	if len(lit) < 2 || (lit[0] != 'v' && lit[0] != 'V') || lit[1] == '.' {
		return "", ErrInvalid
	}
	dot := strings.Index(lit, ".")
	if dot < 0 {
		return "", ErrInvalid
	}
	ver := lit[1:dot]
	rest := lit[dot+1:]
	if ver == "" || rest == "" {
		return "", ErrInvalid
	}
	for i := 0; i < len(ver); i++ {
		if hexVal(ver[i]) < 0 {
			return "", ErrInvalid
		}
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if strings.IndexByte(unreservedBytes, c) < 0 && strings.IndexByte(subDelimBytes+":", c) < 0 {
			return "", ErrInvalid
		}
	}
	return "v" + lowerHexStr(ver) + "." + rest, nil
}
