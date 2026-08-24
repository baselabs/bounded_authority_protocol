package verifier

import "testing"

// URI normalization (docs/protocol-v1.md § URI normalization; RFC 3986).
// Representative legs; the full 26-case corpus surface runs in the
// conformance runner (including the malformed-IPv6 corpus class).
func TestUriNormalizeValid(t *testing.T) {
	cases := []struct{ in, want string }{
		// already normal: identity
		{"https://example.test/path", "https://example.test/path"},
		// scheme + host lowercased
		{"HTTPS://EXAMPLE.TEST/path", "https://example.test/path"},
		// empty path maps to /
		{"https://example.test", "https://example.test/"},
		{"https://example.test/", "https://example.test/"},
		// default port dropped; nondefault kept (leading zeros stripped)
		{"https://example.test:443/path", "https://example.test/path"},
		{"https://example.test:8443/path", "https://example.test:8443/path"},
		{"https://example.test:0443/path", "https://example.test/path"},
		{"https://example.test:008443/path", "https://example.test:8443/path"},
		// percent hex uppercased; unreserved decoded; reserved preserved
		{"https://example.test/%7euser", "https://example.test/~user"}, // unreserved decoded
		{"https://example.test/~user", "https://example.test/~user"},   // stays
		{"https://example.test/a%2fb", "https://example.test/a%2Fb"},   // reserved kept, hex upper
		{"https://example.test/%41", "https://example.test/A"},         // decoded unreserved
		{"https://EXAMPLE.test/%7E", "https://example.test/~"},         // both rules together
		// dot segments removed
		{"https://example.test/a/./b", "https://example.test/a/b"},
		{"https://example.test/a/../b", "https://example.test/b"},
		{"https://example.test/a/b/..", "https://example.test/a/"},
		{"https://example.test/a/b/.", "https://example.test/a/b/"},
		{"https://example.test/..", "https://example.test/"},
		// IPv4 host, exact dec-octets
		{"https://192.0.2.1/x", "https://192.0.2.1/x"},
		// reg-name with sub-delims
		{"https://a--b.example.test/x", "https://a--b.example.test/x"},
		// bracketed IPv6
		{"https://[2001:db8::1]/x", "https://[2001:db8::1]/x"},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]/x", "https://[2001:0db8:0000:0000:0000:0000:0000:0001]/x"}, // downcase-only: digit width preserved
		{"https://[::1]/x", "https://[::1]/x"},
		{"https://[2001:db8::192.0.2.1]/x", "https://[2001:db8::192.0.2.1]/x"}, // embedded IPv4
		// IPvFuture
		{"https://[v1.a:b]/x", "https://[v1.a:b]/x"},
		// IPv6 host hex lowercased
		{"https://[2001:DB8::1]/x", "https://[2001:db8::1]/x"},
	}
	for _, c := range cases {
		got, err := UriNormalize(c.in, nil)
		if err != nil {
			t.Fatalf("UriNormalize(%s) unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("UriNormalize(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestUriNormalizeInvalid(t *testing.T) {
	invalid := []string{
		// REQ1-URI-reject-list
		"http://example.test/path",       // wrong scheme
		"ftp://example.test/path",        // other scheme
		"https:///path",                  // empty authority
		"https://user@example.test/path", // userinfo forbidden
		"https://user:pw@example.test/",  // userinfo with password
		"https://example.test/path?q=1",  // query forbidden
		"https://example.test/path#frag", // fragment forbidden
		// malformed percent escapes
		"https://example.test/a%2",  // truncated
		"https://example.test/a%zz", // non-hex
		"https://example.test/a%",   // dangling
		// control / non-ASCII
		"https://example.test/a\x01b",
		"https://exa\x7fmple.test/",
		"https://example.test/é", // non-ASCII
		// ports
		"https://example.test:/path",   // empty port
		"https://example.test:0/path",  // port 0 out of range (1..65535)
		"https://example.test:65536/x", // out of range
		"https://example.test:99999/x", // out of range
		// ambiguous authority/port syntax
		"https://a:b@example.test/", // handled as userinfo — invalid
		// IPv4 exactness: all-digit last label must be exact IPv4
		"https://1.2.3.4.5/x",   // five labels, not IPv4, all-digits tail
		"https://999.1.1.1/x",   // dec-octet over 255
		"https://01.2.3.4/x",    // leading-zero dec-octet (corpus uri-legacy-invalid-ipv4-leading-zero)
		"https://256.2.3.4/x",   // dec-octet over 255 (corpus uri-legacy-invalid-ipv4-octet-range)
		"https://192.000.2.1/x", // all-numeric labels, leading zero
		// IPv6 malformed
		"https://[2001:db8/x",           // unterminated bracket
		"https://[gg::1]/x",             // non-hex hextet
		"https://[1:2:3:4:5:6:7:8:9]/x", // too many hextets
		"https://[1::2::3]/x",           // two elisions
		"https://[]/x",                  // empty literal
		"https://[v]/x",                 // bad IPvFuture
		"https://[v1.]/x",               // empty IPvFuture tail
		// bare IPv6-shaped host without brackets is a reg-name with colons — ambiguous
		"https://2001:db8::1/x", // colons outside brackets
		// no authority at all
		"https:/path",
		"/path",
		"",
		"example.test/path",
	}
	for _, in := range invalid {
		if got, err := UriNormalize(in, nil); err == nil {
			t.Fatalf("UriNormalize(%s) = %s, want ErrInvalid", in, got)
		}
	}
}
