package verifier

import (
	"strconv"
	"strings"
	"testing"
)

// JSON tagged algebra (spec § JSON algebra and decoding; RFC 8259/8785 as
// transcribed). These legs pin the decode closures; the full corpus surface
// runs in the conformance runner.
func TestJsonDecodeValid(t *testing.T) {
	cases := []struct {
		in   string
		want Value
	}{
		{`null`, Null{}},
		{`true`, Bool(true)},
		{`false`, Bool(false)},
		{`0`, Int(0)},
		{`-0`, Int(0)}, // integer lexeme -0 is the integer zero
		{`9007199254740991`, Int(9007199254740991)},
		{`-9007199254740991`, Int(-9007199254740991)},
		{`1.5`, Float(1.5)},
		{`1e-7`, Float(1e-7)},
		{`""`, Str("")},
		{`"a"`, Str("a")},
		{`[]`, Arr{}},
		{`{}`, Obj{}},
		{`[1,[2]]`, Arr{Int(1), Arr{Int(2)}}},
		{`{"a":1}`, Obj{{Key: "a", Val: Int(1)}}},
		// tagged distinction: 1 is Int, 1.0 is Float, 1e0 is Float
		{`1`, Int(1)},
		{`1.0`, Float(1)},
		{`1e0`, Float(1)},
		// source member order is preserved in Obj (the algebra is ordered)
		{`{"b":1,"a":2}`, Obj{{Key: "b", Val: Int(1)}, {Key: "a", Val: Int(2)}}},
		// escapes
		{`"Aé"`, Str("Aé")},
		{`"\uD83D\uDE00"`, Str("\U0001F600")}, // valid surrogate pair
		{`""`, Str("\x7f")},                  // raw DEL is valid JSON string data
	}
	for _, c := range cases {
		got, err := JsonDecode([]byte(c.in), nil)
		if err != nil {
			t.Fatalf("JsonDecode(%s) unexpected error %v", c.in, err)
		}
		if !valueEqual(got, c.want) {
			t.Fatalf("JsonDecode(%s) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestJsonDecodeInvalid(t *testing.T) {
	invalid := []string{
		// REQ1-JSON-single-value: one complete value, trailing only ws
		`1 2`,
		`{} {}`,
		`nullnull`,
		`[1]x`,
		``,
		`   `,
		// REQ1-JSON-no-duplicate at every depth
		`{"a":1,"a":2}`,
		`{"o":{"x":1,"x":2}}`,
		`[{"k":1,"k":2}]`,
		// REQ1-JSON-raw-lexeme: 64-byte ceiling (65-digit integer)
		`12345678901234567890123456789012345678901234567890123456789012345`,
		// magnitude: symmetric ±9007199254740991
		`9007199254740992`,
		`-9007199254740992`,
		`9007199254740991.5`, // float above the bound (exact decimal compare)
		`1e16`,               // float above the bound via exponent
		// grammar
		`01`,       // leading zero
		`-`,        // bare minus
		`1.`,       // frac must have digits
		`.5`,       // leading dot
		`1e`,       // exp must have digits
		`1e+`,      // exp sign without digits
		`+1`,       // plus not allowed
		`0x10`,     // hex
		`Infinity`, // not JSON
		`NaN`,
		`'a'`,        // single quotes
		`"a`,         // unterminated
		`"a\q"`,      // bad escape
		`"\u00"`,     // short \u
		`"\uD800"`,   // lone high surrogate (I-JSON rejects)
		`"\uDC00"A"`, // lone low surrogate
		// raw control byte in string
		"\"a\x01b\"",
		// malformed UTF-8 in string data
		"\"a\xffb\"",
		// structural: trailing comma, missing colon/value
		`[1,]`,
		`{"a":}`,
		`{"a" 1}`,
		`{a:1}`,
		// unbalanced
		`[1`,
		`{"a":1`,
	}
	for _, in := range invalid {
		if got, err := JsonDecode([]byte(in), nil); err == nil {
			t.Fatalf("JsonDecode(%s) = %#v, want ErrInvalid", in, got)
		}
	}
}

// Bounds enforcement during decode: depth 32, members 64, items 256, nodes
// 4096, string bytes 8192, name bytes 128, raw bytes 65536 — all
// tightening-capable through *Bounds.
func TestJsonDecodeBounds(t *testing.T) {
	// depth: 32 nested arrays is valid, 33 is not.
	// Counting convention (corpus-calibrated): containers count toward
	// depth, scalars do not; 32 nested arrays + inner scalar is valid.
	ok := []byte(strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32))
	if _, err := JsonDecode(ok, nil); err != nil {
		t.Fatalf("depth-32 nested arrays with inner scalar should be within the bound: %v", err)
	}
	deep := []byte(strings.Repeat("[", 33) + strings.Repeat("]", 33))
	if _, err := JsonDecode(deep, nil); err == nil {
		t.Fatal("depth-33 nested arrays must be rejected")
	}
	// members per object: 64 ok, 65 rejected (distinct keys).
	var b strings.Builder
	writeMembers := func(n int) string {
		b.Reset()
		b.WriteByte('{')
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`"k`)
			b.WriteString(strconv.Itoa(i))
			b.WriteString(`":1`)
		}
		b.WriteByte('}')
		return b.String()
	}
	if _, err := JsonDecode([]byte(writeMembers(64)), nil); err != nil {
		t.Fatalf("64 members should be within the bound: %v", err)
	}
	if _, err := JsonDecode([]byte(writeMembers(65)), nil); err == nil {
		t.Fatal("65 members must be rejected")
	}
	// items per array: 256 ok, 257 rejected.
	b.Reset()
	b.WriteByte('[')
	for i := 0; i < 256; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('0')
	}
	b.WriteByte(']')
	if _, err := JsonDecode([]byte(b.String()), nil); err != nil {
		t.Fatalf("256 items should be within the bound: %v", err)
	}
	b.Reset()
	b.WriteByte('[')
	for i := 0; i < 257; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('0')
	}
	b.WriteByte(']')
	if _, err := JsonDecode([]byte(b.String()), nil); err == nil {
		t.Fatal("257 items must be rejected")
	}
	// string bytes: 8192 ok, 8193 rejected (multi-byte counts as bytes).
	s8192 := `"` + strings.Repeat("a", 8192) + `"`
	if _, err := JsonDecode([]byte(s8192), nil); err != nil {
		t.Fatalf("8192-byte string should be within the bound: %v", err)
	}
	s8193 := `"` + strings.Repeat("a", 8193) + `"`
	if _, err := JsonDecode([]byte(s8193), nil); err == nil {
		t.Fatal("8193-byte string must be rejected")
	}
	// name bytes: 128 ok, 129 rejected.
	n128 := `{"` + strings.Repeat("n", 128) + `":1}`
	if _, err := JsonDecode([]byte(n128), nil); err != nil {
		t.Fatalf("128-byte name should be within the bound: %v", err)
	}
	n129 := `{"` + strings.Repeat("n", 129) + `":1}`
	if _, err := JsonDecode([]byte(n129), nil); err == nil {
		t.Fatal("129-byte name must be rejected")
	}
	// raw bytes: 65536 ok, 65537 rejected (whitespace padding isolates the
	// raw-byte ceiling from every other bound).
	big := append([]byte("1"), []byte(strings.Repeat(" ", 65535))...)
	if len(big) != 65536 {
		t.Fatalf("fixture length %d", len(big))
	}
	if _, err := JsonDecode(big, nil); err != nil {
		t.Fatalf("65536 raw bytes should be within the bound: %v", err)
	}
	tooBig := append([]byte("1"), []byte(strings.Repeat(" ", 65536))...)
	if _, err := JsonDecode(tooBig, nil); err == nil {
		t.Fatal("65537 raw bytes must be rejected")
	}
	// tightening: a caller bound tighter than profile max is enforced.
	tight := &Bounds{JSONBytes: 10}
	if _, err := JsonDecode([]byte(`[1,2,3,4,5,6,7,8,9,0]`), tight); err == nil {
		t.Fatal("tightened json_bytes bound must reject an 20-byte input")
	}
}

// valueEqual is the test-side deep equality over the tagged algebra: the
// integer/float tag distinction is structural (Int(1) != Float(1)), arrays
// compare positionally, objects compare as unordered key/value sets (the
// selector semantic-identity rule the library implements on its own).
func valueEqual(a, b Value) bool {
	switch av := a.(type) {
	case Null:
		_, ok := b.(Null)
		return ok
	case Bool:
		bv, ok := b.(Bool)
		return ok && av == bv
	case Int:
		bv, ok := b.(Int)
		return ok && av == bv
	case Float:
		bv, ok := b.(Float)
		return ok && av == bv
	case Str:
		bv, ok := b.(Str)
		return ok && av == bv
	case Arr:
		bv, ok := b.(Arr)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valueEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case Obj:
		bv, ok := b.(Obj)
		if !ok || len(av) != len(bv) {
			return false
		}
		index := make(map[string]Value, len(bv))
		for _, m := range bv {
			index[m.Key] = m.Val
		}
		for _, m := range av {
			other, present := index[m.Key]
			if !present || !valueEqual(m.Val, other) {
				return false
			}
		}
		return true
	}
	return false
}
