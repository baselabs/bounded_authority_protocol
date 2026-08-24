package verifier

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// JCS encode (RFC 8785 as transcribed in docs/protocol-v1.md § JCS string and
// number serialization). Spec worked examples + threshold + sort legs; the
// corpus jcs-encode-* cases run in the conformance runner.
func TestJcsEncodeBasics(t *testing.T) {
	cases := []struct {
		in   Value
		want string
	}{
		{Null{}, "null"},
		{Bool(true), "true"},
		{Bool(false), "false"},
		{Int(0), "0"},
		{Int(-1), "-1"},
		{Int(9007199254740991), "9007199254740991"},
		{Int(-9007199254740991), "-9007199254740991"},
		{Str(""), `""`},
		{Str("a"), `"a"`},
		{Str("Aé"), `"Aé"`},                        // non-ASCII emitted raw
		{Str("\x7f"), "\"\x7f\""},                  // U+007F raw, NOT \u007f
		{Str("\x01"), "\"\\u0001\""},               // control: lowercase hex
		{Str("\x1f"), "\"\\u001f\""},               // last control
		{Str("\b\t\n\f\r"), "\"\\b\\t\\n\\f\\r\""}, // named escapes
		{Str("a\"b\\c"), `"a\"b\\c"`},              // escaped quote + backslash
		{Str("\U0001F600"), "\"\U0001F600\""},      // astral raw (corpus astral-raw)
		{Arr{}, "[]"},
		{Obj{}, "{}"},
		{Arr{Int(1), Int(2)}, "[1,2]"}, // array order preserved
		{Obj{{Key: "a", Val: Int(1)}, {Key: "b", Val: Int(2)}}, `{"a":1,"b":2}`},
		// member sorting at every depth: input order irrelevant, output sorted
		{Obj{{Key: "b", Val: Int(2)}, {Key: "a", Val: Int(1)}}, `{"a":1,"b":2}`},
		{Obj{{Key: "\U00010000", Val: Null{}}, {Key: "￿", Val: Null{}}}, "{\"𐀀\":null,\"￿\":null}"}, // UTF-16 unit order: U+10000 (D800) < U+FFFF
		// nested objects sorted at every depth
		{Obj{{Key: "z", Val: Obj{{Key: "b", Val: Int(1)}, {Key: "a", Val: Int(2)}}}}, `{"z":{"a":2,"b":1}}`},
	}
	for _, c := range cases {
		got, err := JcsEncode(c.in, nil)
		if err != nil {
			t.Fatalf("JcsEncode(%#v) unexpected error %v", c.in, err)
		}
		if string(got) != c.want {
			t.Fatalf("JcsEncode(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ECMAScript Number::toString thresholds (spec worked examples; corpus pins
// jcs-encode-float-* on the reachable e<-6 side). The e>=21 side is
// unreachable from magnitude-bound-compliant floats (the largest allowed
// float has decimal exponent ~15.95) — the branch exists because the spec
// documents both thresholds, matching the reference.
func TestJcsEncodeFloats(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{1.5, "1.5"},
		{0.0, "0"},
		{math.Copysign(0, -1), "0"}, // -0 -> "0"
		{-1.5, "-1.5"},
		{1e-6, "0.000001"}, // e = -6, fixed
		{1e-7, "1e-7"},     // e = -7, scientific
		{-1e-7, "-1e-7"},
		{1.25e-7, "1.25e-7"},
		{5e-324, "5e-324"}, // subnormal, smallest magnitude
		{333333333.3333333, "333333333.3333333"},
		{9007199254740991, "9007199254740991"}, // the bound itself, exactly representable
		{2.5, "2.5"},
		{100, "100"},
	}
	for _, c := range cases {
		got, err := JcsEncode(Float(c.in), nil)
		if err != nil {
			t.Fatalf("JcsEncode(Float(%v)) unexpected error %v", c.in, err)
		}
		if string(got) != c.want {
			t.Fatalf("JcsEncode(Float(%v)) = %q, want %q", c.in, got, c.want)
		}
	}
	// per-node magnitude closure on caller-built Floats: the formatting
	// examples 1e16..1e21 live ABOVE the magnitude bound and are rejected
	for _, over := range []float64{1e16, 1e20, 1e21, -1e16, 123456789012345678901} {
		if got, err := JcsEncode(Float(over), nil); err == nil {
			t.Fatalf("JcsEncode(Float(%v)) = %q, want ErrInvalid (magnitude bound)", over, got)
		}
	}
	// non-finite floats are rejected even though the Go type allows constructing them
	for _, bad := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if got, err := JcsEncode(Float(bad), nil); err == nil {
			t.Fatalf("JcsEncode(Float(%v)) = %q, want ErrInvalid", bad, got)
		}
	}
}

// Per-node encode-bounds closure (the (d)-class battery): the encoder
// revalidates every bound on CALLER-CONSTRUCTED values, not just decoded ones.
func TestJcsEncodeBoundsClosure(t *testing.T) {
	// duplicate key in a caller-built object
	dup := Obj{{Key: "a", Val: Int(1)}, {Key: "a", Val: Int(2)}}
	if _, err := JcsEncode(dup, nil); err == nil {
		t.Fatal("duplicate object key must be rejected at encode")
	}
	// integer magnitude over the bound on a caller-built Int
	if _, err := JcsEncode(Int(9007199254740992), nil); err == nil {
		t.Fatal("Int over magnitude bound must be rejected at encode")
	}
	if _, err := JcsEncode(Int(-9007199254740992), nil); err == nil {
		t.Fatal("Int under magnitude bound must be rejected at encode")
	}
	// float magnitude over the bound on a caller-built Float
	if _, err := JcsEncode(Float(9007199254740992), nil); err == nil {
		t.Fatal("Float over magnitude bound must be rejected at encode")
	}
	// string over the byte bound
	if _, err := JcsEncode(Str(strings.Repeat("x", 8193)), nil); err == nil {
		t.Fatal("8193-byte string must be rejected at encode")
	}
	// name over the byte bound
	if _, err := JcsEncode(Obj{{Key: strings.Repeat("n", 129), Val: Null{}}}, nil); err == nil {
		t.Fatal("129-byte name must be rejected at encode")
	}
	// members over the bound
	over := Obj{}
	for i := 0; i < 65; i++ {
		over = append(over, Member{Key: "k" + strconv.Itoa(i), Val: Null{}})
	}
	if _, err := JcsEncode(over, nil); err == nil {
		t.Fatal("65 members must be rejected at encode")
	}
	// items over the bound
	items := Arr{}
	for i := 0; i < 257; i++ {
		items = append(items, Null{})
	}
	if _, err := JcsEncode(items, nil); err == nil {
		t.Fatal("257 items must be rejected at encode")
	}
	// depth over the bound (33 nested caller-built arrays)
	deep := Value(Arr{})
	for i := 0; i < 32; i++ {
		deep = Arr{deep}
	}
	if _, err := JcsEncode(deep, nil); err == nil {
		t.Fatal("33-deep nesting must be rejected at encode")
	}
	// nodes over the bound (4097 values)
	many := Arr{}
	for i := 0; i < 4097; i++ {
		many = append(many, Null{})
	}
	if _, err := JcsEncode(many, nil); err == nil {
		t.Fatal("4097 nodes must be rejected at encode")
	}
	// output ceiling: tightened jcs_bytes
	tight, err := BoundsNew(map[string]int{"jcs_bytes": 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := JcsEncode(Obj{{Key: "a", Val: Int(1)}}, &tight); err == nil {
		t.Fatal(`tightened jcs_bytes=4 must reject {"a":1} (7 bytes)`)
	}
	// invalid Unicode in a caller-built string (malformed UTF-8)
	if _, err := JcsEncode(Str("a\xffb"), nil); err == nil {
		t.Fatal("malformed UTF-8 string must be rejected at encode")
	}
	// a caller-built object key that is malformed UTF-8
	if _, err := JcsEncode(Obj{{Key: "a\xff", Val: Null{}}}, nil); err == nil {
		t.Fatal("malformed UTF-8 key must be rejected at encode")
	}
}
