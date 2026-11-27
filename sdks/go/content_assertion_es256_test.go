package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
)

func TestES256ContentAssertionSignatureAndSuite(t *testing.T) {
	b := BoundsMaximum()
	es := ContentAssertionES256{}
	content := ContentAssertion{AttestorKeyID: "k", Jti: "j", Iss: "i", Aud: "a", Sub: "s", Profile: "p", Gen: 1, Iat: 1, Nbf: 1, Exp: 5}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	si, err := es.AssertionSigningInput(content, &b)
	if err != nil {
		t.Fatal(err)
	}
	input := sha256.Sum256(signingInputMessage(si))
	r, s, err := ecdsa.Sign(rand.Reader, key, input[:])
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	twin := new(big.Int).Sub(n, s)
	if s.Cmp(twin) > 0 {
		s, twin = twin, s
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	compact, err := es.AssembleCompact(si, raw, &b)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	expected := ExpectedContentAssertion{
		Attestor: HistoricalPublicKey{KeyID: "k", PublicKey: public, ValidBeforeUnbounded: true},
		Issuer:   "i", Audience: "a", Subject: "s", Profile: "p", Now: 2, Bounds: &b,
	}
	if _, err := es.VerifyAssertion(compact, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentAssertion(compact, &b); err != ErrInvalid {
		t.Fatal("accepted ES256 as EdDSA")
	}
	if _, err := AssembleContentAssertionCompact(si, raw, &b); err != ErrInvalid {
		t.Fatal("accepted ES256 signing kind in EdDSA assembly")
	}
	high := append([]byte(nil), raw...)
	twin.FillBytes(high[32:])
	der, err := ecdsa.SignASN1(rand.Reader, key, input[:])
	if err != nil {
		t.Fatal(err)
	}
	for name, signature := range map[string][]byte{"high-S": high, "DER": der} {
		t.Run(name, func(t *testing.T) {
			if _, err := es.AssembleCompact(si, signature, &b); err != ErrInvalid {
				t.Fatal("assembled disallowed signature")
			}
			received := compact[:strings.LastIndexByte(compact, '.')+1] + Base64urlEncode(signature)
			if _, err := es.VerifyAssertion(received, expected); err != ErrInvalid {
				t.Fatal("verified disallowed signature")
			}
		})
	}
}

func TestES256ContentAssertionIPvFutureIdentifier(t *testing.T) {
	es := ContentAssertionES256{}
	assertion := ContentAssertion{AttestorKeyID: "k", Jti: "https://[::1]/", Iss: "i", Aud: "a", Sub: "s", Profile: "p", Gen: 1, Iat: 1, Nbf: 1, Exp: 5}
	if _, err := es.AssertionSigningInput(assertion, nil); err != nil {
		t.Fatal(err)
	}
	assertion.Jti = "https://[v1.a]/"
	if _, err := es.AssertionSigningInput(assertion, nil); err != ErrInvalid {
		t.Fatal("accepted an IPvFuture identifier")
	}
}
