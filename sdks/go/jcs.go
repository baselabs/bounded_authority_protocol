package verifier

import (
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// JcsEncode serializes a tagged JSON value to exact RFC 8785 (JCS) bytes as
// transcribed by spec/bap-v1.md (REQ1-JSON-jcs-exact):
//
//   - exact string escaping: \b\t\n\f\r, lowercase \u00xx for the remaining
//     U+0000..U+001F controls, every other code point raw UTF-8 except the
//     escaped backslash and double quote; U+007F is emitted raw;
//   - lone surrogates and malformed UTF-8 rejected;
//   - object member names sorted by unsigned UTF-16 code units at every depth;
//   - array order preserved;
//   - numbers by ECMAScript Number::toString (see floatToECMAScript);
//   - every bound revalidated per node on caller-constructed values (the
//     per-node encode-bounds closure): depth, nodes, members, items, string
//     and name bytes, integer/float magnitude, duplicate keys, and the output
//     byte ceiling.
func JcsEncode(v Value, bounds *Bounds) ([]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	e := &jcsEncoder{b: b}
	out, err := e.encode(v, 1)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(out) > b.JCSBytes {
		return nil, ErrInvalid
	}
	return out, nil
}

type jcsEncoder struct {
	b     Bounds
	nodes int
}

func (e *jcsEncoder) encode(v Value, depth int) ([]byte, error) {
	e.nodes++
	if e.nodes > e.b.TotalNodes {
		return nil, ErrInvalid
	}
	if _, isArr := v.(Arr); isArr {
		if depth > e.b.Depth {
			return nil, ErrInvalid
		}
	} else if _, isObj := v.(Obj); isObj {
		if depth > e.b.Depth {
			return nil, ErrInvalid
		}
	}
	switch val := v.(type) {
	case Null:
		return []byte("null"), nil
	case Bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case Int:
		if val > Int(e.b.IntegerMagnitude) || val < Int(-e.b.IntegerMagnitude) {
			return nil, ErrInvalid
		}
		return []byte(strconv.FormatInt(int64(val), 10)), nil
	case Float:
		s, err := floatToECMAScript(float64(val), e.b.FloatMagnitude)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	case Str:
		return encodeJcsString(string(val), e.b.StringBytes)
	case Arr:
		if len(val) > e.b.ArrayItems {
			return nil, ErrInvalid
		}
		out := []byte{'['}
		for i, item := range val {
			if i > 0 {
				out = append(out, ',')
			}
			enc, err := e.encode(item, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return append(out, ']'), nil
	case Obj:
		if len(val) > e.b.ObjectMembers {
			return nil, ErrInvalid
		}
		seen := make(map[string]struct{}, len(val)) // membership only
		for _, m := range val {
			if _, dup := seen[m.Key]; dup {
				return nil, ErrInvalid // duplicate key at encode
			}
			seen[m.Key] = struct{}{}
		}
		sorted := make(Obj, len(val))
		copy(sorted, val)
		sort.SliceStable(sorted, func(i, j int) bool {
			return utf16Less(sorted[i].Key, sorted[j].Key)
		})
		out := []byte{'{'}
		for i, m := range sorted {
			if i > 0 {
				out = append(out, ',')
			}
			key, err := encodeJcsString(m.Key, objectNameBytes)
			if err != nil {
				return nil, err
			}
			out = append(out, key...)
			out = append(out, ':')
			enc, err := e.encode(m.Val, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return append(out, '}'), nil
	}
	return nil, ErrInvalid // unknown Value implementation
}

// encodeJcsString applies RFC 8785 §3.2.2.2 escaping under a byte ceiling.
func encodeJcsString(s string, byteCeiling int) ([]byte, error) {
	if len(s) > byteCeiling {
		return nil, ErrInvalid
	}
	if !utf8.ValidString(s) {
		return nil, ErrInvalid // includes CESU-8 surrogate encodings
	}
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return nil, ErrInvalid // unreachable after ValidString; fail closed
		}
		switch {
		case r == '"':
			out = append(out, '\\', '"')
		case r == '\\':
			out = append(out, '\\', '\\')
		case r == '\b':
			out = append(out, '\\', 'b')
		case r == '\t':
			out = append(out, '\\', 't')
		case r == '\n':
			out = append(out, '\\', 'n')
		case r == '\f':
			out = append(out, '\\', 'f')
		case r == '\r':
			out = append(out, '\\', 'r')
		case r < 0x20:
			out = append(out, '\\', 'u', '0', '0', hexDigit(byte(r)>>4), hexDigit(byte(r)&0xf))
		default:
			// every other code point, U+007F included, is emitted raw
			out = append(out, s[i:i+size]...)
		}
		i += size
	}
	return append(out, '"'), nil
}

func hexDigit(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}

// utf16Less compares two strings by their unsigned UTF-16 code unit sequences
// (RFC 8785 §3.2.3 sorted keys). Inputs are valid UTF-8 by construction.
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// floatToECMAScript formats a finite float64 per ECMA-262 §7.1.12.1
// (Number::toString), which RFC 8785 §3.2.2.3 delegates to: shortest
// round-trip digits, fixed notation for -6 <= e <= 20 (decimal exponent of
// the leading digit), scientific otherwise, lowercase 'e' with a mandatory
// sign, no leading '.' zeros, and -0 collapsed to "0".
func floatToECMAScript(f float64, magnitudeBound int) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", ErrInvalid
	}
	if f == 0 {
		return "0", nil // covers +0 and -0
	}
	if math.Abs(f) > float64(magnitudeBound) {
		return "", ErrInvalid
	}
	neg := f < 0 // -0 collapsed above; only true negatives carry the sign
	abs := f
	if neg {
		abs = -f
	}
	// Shortest round-trip digits plus decimal exponent: strconv 'e' form is
	// d[.ddd]e±X with value = d.ddd × 10^X.
	mant := strconv.FormatFloat(abs, 'e', -1, 64)
	epos := -1
	for i := 0; i < len(mant); i++ {
		if mant[i] == 'e' {
			epos = i
			break
		}
	}
	if epos < 0 {
		return "", ErrInvalid // unreachable for finite floats; fail closed
	}
	digits := mant[0:epos]
	exp10, err := strconv.Atoi(mant[epos+1:])
	if err != nil {
		return "", ErrInvalid
	}
	// strip the '.' between the first digit and the fraction (absent when the
	// mantissa is a single digit, e.g. "1e+20")
	if len(digits) > 1 {
		digits = digits[:1] + digits[2:]
	}
	// value = 0.digits × 10^n with n = exp10 + 1 (leading-digit exponent + 1)
	n := exp10 + 1
	k := len(digits)
	var body string
	switch {
	case k <= n && n <= 21:
		body = digits + stringsRepeat("0", n-k)
	case 0 < n && n <= 21:
		body = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		body = "0." + stringsRepeat("0", -n) + digits
	case k == 1:
		body = digits + "e" + exponentString(n-1)
	default:
		body = digits[:1] + "." + digits[1:] + "e" + exponentString(n-1)
	}
	if neg {
		return "-" + body, nil
	}
	return body, nil
}

// exponentString formats an ECMAScript exponent: mandatory '+' or '-' and no
// leading zeros.
func exponentString(e int) string {
	if e < 0 {
		return "-" + strconv.Itoa(-e)
	}
	return "+" + strconv.Itoa(e)
}

func stringsRepeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
