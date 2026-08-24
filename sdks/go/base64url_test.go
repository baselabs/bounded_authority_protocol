package verifier

import "testing"

// base64url: REQ1-B64-alphabet / -no-padding / -length / -canonical.
// Corpus cases (cases/base64url/decode.json) + corpus-blind canonicality legs.
func TestBase64urlDecode(t *testing.T) {
	valid := map[string]string{
		"aGVsbG8": "hello", // corpus base64url-decode-valid
		"":        "",      // empty is a complete, canonical encoding of zero bytes
		"AA":      "\x00",  // 2 chars -> 1 byte, leftover bits zero (canonical)
		"AAA":     "\x00\x00",
		"_-8":     "\xff\xef", // alphabet edge: highest symbols
	}
	for in, want := range valid {
		got, err := Base64urlDecode(in)
		if err != nil {
			t.Fatalf("Base64urlDecode(%q) unexpected error %v", in, err)
		}
		if string(got) != want {
			t.Fatalf("Base64urlDecode(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"AAA=",      // corpus: padding forbidden (REQ1-B64-no-padding)
		"a+b",       // corpus: bad alphabet char
		"A",         // len % 4 == 1 (REQ1-B64-length)
		"AAAAA",     // len % 4 == 1
		"AB",        // non-zero unused pad bits (REQ1-B64-canonical)
		"QB",        // non-zero unused pad bits, other bit position
		"ABCDx",     // bad char plus bad length
		"a GVsbG8",  // whitespace forbidden
		"aGVsbG8\n", // newline forbidden (host decoders that skip \n are permissive)
		"aGVsbG8\r", // CR forbidden
		"\taGVsbG8", // leading tab forbidden
		"YWJjZA==",  // padded form forbidden
		"YWJj-Zh",   // '-' at a position requiring standard alphabet is fine; stray char check via re-encode
		"éé",        // non-ASCII bytes forbidden
	}
	for _, in := range invalid {
		if got, err := Base64urlDecode(in); err == nil {
			t.Fatalf("Base64urlDecode(%q) = %q, want ErrInvalid", in, got)
		}
	}
}

func TestBase64urlEncode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},                  // ""
		{"hello", "aGVsbG8"},      // corpus-verified
		{"\x00", "AA"},            // canonical 2-char form round-trips
		{"\x00\x00\x00", "AAAA"},  // 3-char form, zero leftover
		{"\xff\xef", "_-8"},       // alphabet edge
		{"abcde\x00", "YWJjZGUA"}, // 4-char groups, zero leftover
	}
	for _, c := range cases {
		if got := Base64urlEncode([]byte(c.in)); got != c.want {
			t.Fatalf("Base64urlEncode(%q) = %q, want %q", c.in, got, c.want)
		}
		// Round-trip: every encoding decodes back and re-encodes identically.
		if dec, err := Base64urlDecode(c.want); err != nil || string(dec) != c.in {
			t.Fatalf("round-trip failed for %q: %q, %v", c.in, dec, err)
		}
	}
}
