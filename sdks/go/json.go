package verifier

import (
	"math/big"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// The tagged JSON algebra (docs/protocol-v1.md § JSON algebra and decoding):
// the protocol preserves the integer/float distinction, source member order,
// and exact bounds that host JSON decoders erase.

// Value is a decoded tagged JSON value. The concrete types are Null, Bool,
// Int, Float, Str, Arr, and Obj. The unexported marker method keeps the algebra
// closed: no caller-defined type can masquerade as a JSON value inside the
// verification path.
type Value interface {
	isValue()
}

// Null is the JSON null value.
type Null struct{}

// Bool is a JSON boolean.
type Bool bool

// Int is a JSON number whose lexeme is an integer.
type Int int64

// Float is a JSON number whose lexeme is a non-integer. Only finite values
// within the profile magnitude bound can occur.
type Float float64

// Str is a JSON string; the payload is its UTF-8 bytes, never normalized.
type Str string

// Arr is a JSON array; order is positional.
type Arr []Value

// Member is one object member. Key is the raw (unnormalized) member name.
type Member struct {
	Key string
	Val Value
}

// Obj is a JSON object retaining source member order. Duplicate member names
// cannot occur: the decoder rejects them at every depth before construction
// (REQ1-JSON-no-duplicate), so a decoded Obj is duplicate-free by type.
type Obj []Member

func (Null) isValue()  {}
func (Bool) isValue()  {}
func (Int) isValue()   {}
func (Float) isValue() {}
func (Str) isValue()   {}
func (Arr) isValue()   {}
func (Obj) isValue()   {}

// objectNameBytes is the fixed member-name UTF-8 byte ceiling. It is a
// profile constant, not a caller-tightenable bound (it is absent from the
// bounds surface).
const objectNameBytes = 128

type jsonDecoder struct {
	data  []byte
	pos   int
	b     Bounds
	depth int
	nodes int
}

// JsonDecode decodes exactly one complete RFC 8259 value followed only by
// JSON whitespace (REQ1-JSON-single-value). Duplicate member names at any
// depth, malformed or non-mandatory UTF-8, raw number lexemes over the
// ceiling, magnitudes over the symmetric bound, and every structural bound
// violation return ErrInvalid (fail closed, REQ1-JSON-*).
func JsonDecode(data []byte, bounds *Bounds) (Value, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(data) > b.JSONBytes {
		return nil, ErrInvalid
	}
	d := &jsonDecoder{data: data, b: b}
	d.skipWS()
	v, err := d.parseValue()
	if err != nil {
		return nil, ErrInvalid
	}
	d.skipWS()
	if d.pos != len(d.data) {
		return nil, ErrInvalid // trailing bytes (REQ1-JSON-single-value)
	}
	return v, nil
}

func (d *jsonDecoder) skipWS() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\n', '\r':
			d.pos++
		default:
			return
		}
	}
}

func (d *jsonDecoder) parseValue() (Value, error) {
	d.nodes++
	if d.nodes > d.b.TotalNodes {
		return nil, ErrInvalid
	}
	if d.pos >= len(d.data) {
		return nil, ErrInvalid
	}
	if c := d.data[d.pos]; c == '[' || c == '{' {
		// depth counts containers only: 32 nested arrays with an inner
		// scalar are valid at the depth bound (corpus calibration)
		d.depth++
		defer func() { d.depth-- }()
		if d.depth > d.b.Depth {
			return nil, ErrInvalid
		}
	}
	switch c := d.data[d.pos]; {
	case c == 'n':
		return Null{}, d.literal("null")
	case c == 't':
		return Bool(true), d.literal("true")
	case c == 'f':
		return Bool(false), d.literal("false")
	case c == '"':
		s, err := d.parseString(false)
		if err != nil {
			return nil, err
		}
		return Str(s), nil
	case c == '[':
		return d.parseArray()
	case c == '{':
		return d.parseObject()
	case c == '-' || (c >= '0' && c <= '9'):
		return d.parseNumber()
	}
	return nil, ErrInvalid
}

func (d *jsonDecoder) literal(want string) error {
	if d.pos+len(want) > len(d.data) || string(d.data[d.pos:d.pos+len(want)]) != want {
		return ErrInvalid
	}
	d.pos += len(want)
	return nil
}

func (d *jsonDecoder) parseArray() (Value, error) {
	d.pos++ // '['
	arr := Arr{}
	d.skipWS()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		return arr, nil
	}
	for {
		d.skipWS()
		v, err := d.parseValue()
		if err != nil {
			return nil, err
		}
		if len(arr) >= d.b.ArrayItems {
			return nil, ErrInvalid
		}
		arr = append(arr, v)
		d.skipWS()
		if d.pos >= len(d.data) {
			return nil, ErrInvalid
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
		case ']':
			d.pos++
			return arr, nil
		default:
			return nil, ErrInvalid
		}
	}
}

func (d *jsonDecoder) parseObject() (Value, error) {
	d.pos++ // '{'
	obj := Obj{}
	seen := make(map[string]struct{}, 8) // membership only; never iterated for output
	d.skipWS()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return obj, nil
	}
	for {
		d.skipWS()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, ErrInvalid
		}
		key, err := d.parseString(true)
		if err != nil {
			return nil, err
		}
		if len(key) > objectNameBytes {
			return nil, ErrInvalid
		}
		if _, dup := seen[key]; dup {
			return nil, ErrInvalid // REQ1-JSON-no-duplicate
		}
		seen[key] = struct{}{}
		d.skipWS()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, ErrInvalid
		}
		d.pos++
		d.skipWS()
		v, err := d.parseValue()
		if err != nil {
			return nil, err
		}
		if len(obj) >= d.b.ObjectMembers {
			return nil, ErrInvalid
		}
		obj = append(obj, Member{Key: key, Val: v})
		d.skipWS()
		if d.pos >= len(d.data) {
			return nil, ErrInvalid
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
		case '}':
			d.pos++
			return obj, nil
		default:
			return nil, ErrInvalid
		}
	}
}

// parseString parses a JSON string literal. isName is advisory only (names
// carry the fixed 128-byte ceiling; values the bounds ceiling).
func (d *jsonDecoder) parseString(isName bool) (string, error) {
	d.pos++ // opening '"'
	var out []byte
	for {
		if d.pos >= len(d.data) {
			return "", ErrInvalid // unterminated
		}
		c := d.data[d.pos]
		switch {
		case c == '"':
			d.pos++
			if !utf8.Valid(out) {
				return "", ErrInvalid // REQ1-JSON-no-normalization: UTF-8 is mandatory
			}
			if utf8.RuneCount(out) == 0 && len(out) != 0 {
				return "", ErrInvalid
			}
			if !isName && len(out) > d.b.StringBytes {
				return "", ErrInvalid
			}
			return string(out), nil
		case c == '\\':
			d.pos++
			if d.pos >= len(d.data) {
				return "", ErrInvalid
			}
			e := d.data[d.pos]
			d.pos++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := d.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", ErrInvalid
			}
		case c < 0x20:
			return "", ErrInvalid // unescaped control character
		default:
			out = append(out, c)
			d.pos++
		}
	}
}

// parseUnicodeEscape parses \uXXXX with RFC 8259 surrogate pair joining.
// Lone surrogates are rejected (I-JSON / RFC 8785 string model).
func (d *jsonDecoder) parseUnicodeEscape() (rune, error) {
	hi, err := d.hex4()
	if err != nil {
		return 0, err
	}
	if utf16.IsSurrogate(rune(hi)) {
		if hi < 0xDC00 { // high surrogate: require a following \uDC00..\uDFFF
			if d.pos+1 < len(d.data) && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u' {
				save := d.pos
				d.pos += 2
				lo, err := d.hex4()
				if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
					return utf16.DecodeRune(rune(hi), rune(lo)), nil
				}
				d.pos = save
			}
			return 0, ErrInvalid // lone high surrogate
		}
		return 0, ErrInvalid // lone low surrogate
	}
	return rune(hi), nil
}

func (d *jsonDecoder) hex4() (int, error) {
	if d.pos+4 > len(d.data) {
		return 0, ErrInvalid
	}
	v := 0
	for i := 0; i < 4; i++ {
		c := d.data[d.pos+i]
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, ErrInvalid
		}
	}
	d.pos += 4
	return v, nil
}

// parseNumber scans the raw RFC 8259 number lexeme, enforces the lexeme byte
// ceiling and the exact decimal magnitude bound before any host conversion
// (REQ1-JSON-raw-lexeme), and returns the tagged value: Int for integer
// lexemes, Float for non-integer lexemes.
func (d *jsonDecoder) parseNumber() (Value, error) {
	start := d.pos
	if d.pos < len(d.data) && d.data[d.pos] == '-' {
		d.pos++
	}
	// int part: 0 | [1-9][0-9]*
	if d.pos >= len(d.data) {
		return nil, ErrInvalid
	}
	if d.data[d.pos] == '0' {
		d.pos++
	} else if d.data[d.pos] >= '1' && d.data[d.pos] <= '9' {
		d.pos++
		for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
			d.pos++
		}
	} else {
		return nil, ErrInvalid
	}
	isFloat := false
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		isFloat = true
		d.pos++
		if d.pos >= len(d.data) || d.data[d.pos] < '0' || d.data[d.pos] > '9' {
			return nil, ErrInvalid
		}
		for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
			d.pos++
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		isFloat = true
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		if d.pos >= len(d.data) || d.data[d.pos] < '0' || d.data[d.pos] > '9' {
			return nil, ErrInvalid
		}
		for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
			d.pos++
		}
	}
	lexeme := d.data[start:d.pos]
	if len(lexeme) > d.b.NumberLexemeBytes {
		return nil, ErrInvalid
	}
	if !isFloat {
		// exact integer magnitude: compare digit strings against the bound
		digits := lexeme
		if digits[0] == '-' {
			digits = digits[1:]
		}
		if cmpDigits(string(digits), "9007199254740991") > 0 {
			return nil, ErrInvalid
		}
		// safe: |v| <= 2^53-1
		var v int64
		neg := lexeme[0] == '-'
		for _, c := range lexeme {
			if c == '-' {
				continue
			}
			v = v*10 + int64(c-'0')
		}
		if neg {
			v = -v
		}
		return Int(v), nil
	}
	// exact float magnitude via rational comparison of the decimal lexeme
	r, ok := new(big.Rat).SetString(string(lexeme))
	if !ok {
		return nil, ErrInvalid
	}
	limit := new(big.Rat).SetInt64(int64(d.b.FloatMagnitude))
	if r.Abs(r).Cmp(limit) > 0 {
		return nil, ErrInvalid
	}
	f, err := strconv.ParseFloat(string(lexeme), 64)
	if err != nil {
		return nil, ErrInvalid
	}
	return Float(f), nil
}

// cmpDigits compares two non-negative decimal digit strings of equal-or-not
// length numerically (no leading zeros per the RFC grammar except "0").
func cmpDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) > len(b) {
			return 1
		}
		return -1
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}
