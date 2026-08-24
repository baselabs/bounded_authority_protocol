package verifier

import "testing"

// JWK public-key surfaces (spec § Protected headers, REQ1-HEADER-proof-jwk /
// -no-private-jwk / -thumbprint / -digest-width / -issuer-fingerprint).
// Corpus-verified values: key "YXgT52I83qBmbNzq_RMxiYT1T_EELrAj9rUkjCaSkP4"
// thumbprints to "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8" (pinned
// numerically at authoring).
const (
	testRawKey   = "YXgT52I83qBmbNzq_RMxiYT1T_EELrAj9rUkjCaSkP4"
	testX        = testRawKey // x is the base64url of the raw key
	testThumb    = "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8"
	testJwkAny   = `{"x":"` + testX + `","kty":"OKP","crv":"Ed25519"}` // member order insignificant
	testJwkCanon = `{"crv":"Ed25519","kty":"OKP","x":"` + testX + `"}`
)

func TestJwkDecodePublic(t *testing.T) {
	key, err := JwkDecodePublic([]byte(testJwkAny), nil)
	if err != nil {
		t.Fatalf("JwkDecodePublic(any order) unexpected error %v", err)
	}
	if Base64urlEncode(key) != testX {
		t.Fatalf("JwkDecodePublic returned key %s", Base64urlEncode(key))
	}
	invalid := []string{
		`{"crv":"Ed25519","kty":"OKP","x":"` + testX + `","d":"AAA"}`,       // private member
		`{"crv":"Ed25519","kty":"OKP"}`,                                     // missing x
		`{"crv":"Ed25519","kty":"EC","x":"` + testX + `"}`,                  // wrong kty
		`{"crv":"P-256","kty":"OKP","x":"` + testX + `"}`,                   // wrong crv
		`{"crv":"Ed25519","kty":"OKP","x":123}`,                             // non-string x
		`{"crv":"Ed25519","kty":"OKP","x":"AA"}`,                            // wrong width (canonical but 1 byte)
		`{"crv":"Ed25519","kty":"OKP","x":"A"}`,                             // length%4==1
		`{"crv":"Ed25519","kty":"OKP","x":"AB"}`,                            // non-canonical pad bits
		`{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","x":"` + testX + `"}`,   // unlisted member
		`{"crv":"Ed25519","crv":"Ed25519","kty":"OKP","x":"` + testX + `"}`, // duplicate
		`not-json`,
		`{"crv":"Ed25519","kty":"OKP","x":"` + testX + `"} trailing`,
	}
	for _, in := range invalid {
		if got, err := JwkDecodePublic([]byte(in), nil); err == nil {
			t.Fatalf("JwkDecodePublic(%s) = %s, want ErrInvalid", in, Base64urlEncode(got))
		}
	}
}

func TestJwkEncodePublic(t *testing.T) {
	raw, err := Base64urlDecode(testRawKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := JwkEncodePublic(raw, nil)
	if err != nil {
		t.Fatalf("JwkEncodePublic unexpected error %v", err)
	}
	if string(enc) != testJwkCanon {
		t.Fatalf("JwkEncodePublic = %s, want %s", enc, testJwkCanon)
	}
	for _, bad := range [][]byte{nil, raw[:31], append(raw, 0)} {
		if _, err := JwkEncodePublic(bad, nil); err == nil {
			t.Fatalf("JwkEncodePublic(len %d) must be rejected", len(bad))
		}
	}
}

func TestJwkThumbprintFamily(t *testing.T) {
	pre, err := JwkThumbprintPreimage([]byte(testJwkAny), nil)
	if err != nil || string(pre) != testJwkCanon {
		t.Fatalf("JwkThumbprintPreimage = %s %v, want %s", pre, err, testJwkCanon)
	}
	th, err := JwkThumbprint([]byte(testJwkAny), nil)
	if err != nil || th != testThumb {
		t.Fatalf("JwkThumbprint = %s %v, want %s", th, err, testThumb)
	}
	raw, err := JwkThumbprintRaw([]byte(testJwkAny), nil)
	if err != nil || Base64urlEncode(raw[:]) != testThumb {
		t.Fatalf("JwkThumbprintRaw = %s %v", Base64urlEncode(raw[:]), err)
	}
	pk, err := PublicKeyThumbprintRaw(rawKeyBytes(t), nil)
	if err != nil || Base64urlEncode(pk[:]) != testThumb {
		t.Fatalf("PublicKeyThumbprintRaw = %s %v, want %s", Base64urlEncode(pk[:]), err, testThumb)
	}
	// the preimage construction is exactly the same over the raw key's x
	if _, err := PublicKeyThumbprintRaw([]byte("short"), nil); err == nil {
		t.Fatal("PublicKeyThumbprintRaw on a non-32-byte key must be rejected")
	}
}

func rawKeyBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := Base64urlDecode(testRawKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
