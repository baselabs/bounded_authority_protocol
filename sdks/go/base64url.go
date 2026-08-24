package verifier

// base64url, protocol profile (RFC 4648 §5 as transcribed by
// docs/protocol-v1.md § Base64url):
//
//   - alphabet A-Z a-z 0-9 '-' '_' only (REQ1-B64-alphabet);
//   - padding and whitespace forbidden (REQ1-B64-no-padding);
//   - length modulo four equal to one is invalid (REQ1-B64-length);
//   - decoding succeeds only when unpadded re-encoding reproduces the input
//     exactly — non-zero unused pad bits and alternate encodings are rejected
//     (REQ1-B64-canonical).
//
// Hand-rolled rather than encoding/base64: the stdlib decoder silently skips
// \r and \n, which violates the whitespace prohibition, and owning the table
// makes the canonicality closure provable at this library's boundary.

const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var b64urlDecodeTable = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b64urlAlphabet); i++ {
		t[b64urlAlphabet[i]] = int8(i)
	}
	return t
}()

// Base64urlDecode decodes an unpadded base64url string under the profile's
// closed rules. It returns ErrInvalid for any alphabet, padding, whitespace,
// length, or canonicality violation.
func Base64urlDecode(s string) ([]byte, error) {
	n := len(s)
	if n%4 == 1 {
		return nil, ErrInvalid // REQ1-B64-length
	}
	// Table lookup doubles as the alphabet + ASCII-only + no-whitespace gate:
	// every byte outside A-Za-z0-9-_ (including '=', space, \r, \n, and every
	// non-ASCII byte) maps to -1.
	for i := 0; i < n; i++ {
		if b64urlDecodeTable[s[i]] < 0 {
			return nil, ErrInvalid // REQ1-B64-alphabet / -no-padding
		}
	}
	// Unused pad bits must be zero: the re-encode comparison below is exactly
	// that check in canonical form, so decode first, then compare.
	out := make([]byte, 0, 3*n/4+3)
	var buf [4]int
	for i := 0; i < n; i += 4 {
		rem := n - i
		if rem >= 4 {
			buf[0] = int(b64urlDecodeTable[s[i]])
			buf[1] = int(b64urlDecodeTable[s[i+1]])
			buf[2] = int(b64urlDecodeTable[s[i+2]])
			buf[3] = int(b64urlDecodeTable[s[i+3]])
			out = append(out, byte(buf[0]<<2|buf[1]>>4), byte(buf[1]<<4|buf[2]>>2), byte(buf[2]<<6|buf[3]))
			continue
		}
		if rem == 2 {
			b0 := int(b64urlDecodeTable[s[i]])
			b1 := int(b64urlDecodeTable[s[i+1]])
			out = append(out, byte(b0<<2|b1>>4))
		} else { // rem == 3
			b0 := int(b64urlDecodeTable[s[i]])
			b1 := int(b64urlDecodeTable[s[i+1]])
			b2 := int(b64urlDecodeTable[s[i+2]])
			out = append(out, byte(b0<<2|b1>>4), byte(b1<<4|b2>>2))
		}
	}
	// REQ1-B64-canonical: the input must be the exact unpadded encoding.
	if Base64urlEncode(out) != s {
		return nil, ErrInvalid
	}
	return out, nil
}

// Base64urlEncode encodes bytes as unpadded base64url. It is total: every
// byte sequence has exactly one canonical encoding.
func Base64urlEncode(b []byte) string {
	n := len(b)
	out := make([]byte, 0, (n+2)/3*4)
	for i := 0; i < n; i += 3 {
		rem := n - i
		b0, b1, b2 := b[i], byte(0), byte(0)
		if rem > 1 {
			b1 = b[i+1]
		}
		if rem > 2 {
			b2 = b[i+2]
		}
		out = append(out, b64urlAlphabet[b0>>2])
		out = append(out, b64urlAlphabet[(b0&0x03)<<4|b1>>4])
		if rem > 1 {
			out = append(out, b64urlAlphabet[(b1&0x0f)<<2|b2>>6])
		}
		if rem > 2 {
			out = append(out, b64urlAlphabet[b2&0x3f])
		}
	}
	return string(out)
}
