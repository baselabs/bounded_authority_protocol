package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func contentAssertionFixture(t *testing.T, keyID string, gen int64, prev [32]byte, iat, nbf, exp int64) (ContentAssertion, ExpectedContentAssertion, ed25519.PrivateKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest := sha256.Sum256([]byte("content-profile-v1"))
	contentDigest, err := ContentDigest([]byte(`{"value":"one"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := ContentAssertion{
		AttestorKeyID: keyID,
		Jti:           "urn:assertion:" + keyID,
		Iss:           "https://issuer.example",
		Aud:           "urn:example:audience:1",
		Sub:           "urn:lineage:installation-1",
		Profile:       "urn:example:content-profile:1",
		ProfileDigest: profileDigest,
		ContentDigest: contentDigest,
		Gen:           gen,
		Prev:          prev,
		Iat:           iat,
		Nbf:           nbf,
		Exp:           exp,
	}
	bounds := BoundsMaximum()
	expected := ExpectedContentAssertion{
		Attestor:      HistoricalPublicKey{KeyID: keyID, PublicKey: pub, ValidFrom: iat - 10, ValidBefore: exp + 10},
		Issuer:        a.Iss,
		Audience:      a.Aud,
		Subject:       a.Sub,
		Profile:       a.Profile,
		ProfileDigest: profileDigest,
		ContentDigest: contentDigest,
		Now:           nbf,
		Bounds:        &bounds,
	}
	return a, expected, private
}

func signContentAssertion(t *testing.T, a ContentAssertion, private ed25519.PrivateKey, bounds *Bounds) string {
	t.Helper()
	si, err := AssertionSigningInput(a, bounds)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	signature := ed25519.Sign(private, signingInputMessage(si))
	compact, err := AssembleContentAssertionCompact(si, signature, bounds)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return compact
}

func TestContentDigestExactDomainAndBounds(t *testing.T) {
	content := []byte("exact content bytes")
	want := sha256.Sum256(append([]byte("BAP1-CONTENT\x00"), content...))
	got, err := ContentDigest(content, nil)
	if err != nil || got != want {
		t.Fatalf("ContentDigest = %x, %v; want %x", got, err, want)
	}
	if _, err := ContentDigest(nil, nil); err != ErrInvalid {
		t.Fatalf("empty content error = %v, want ErrInvalid", err)
	}
	if _, err := ContentDigest(make([]byte, 65536), nil); err != nil {
		t.Fatalf("maximum content rejected: %v", err)
	}
	if _, err := ContentDigest(make([]byte, 65537), nil); err != ErrInvalid {
		t.Fatalf("maximum+1 error = %v, want ErrInvalid", err)
	}
	tight, err := BoundsNew(map[string]int{"content_bytes": 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ContentDigest([]byte("four"), &tight); err != ErrInvalid {
		t.Fatalf("tightened bound error = %v, want ErrInvalid", err)
	}
}

func TestContentAssertionProducerDecodeVerifyAndDigest(t *testing.T) {
	a, expected, private := contentAssertionFixture(t, "attestor-1", 1, [32]byte{}, 100, 110, 200)
	compact := signContentAssertion(t, a, private, nil)
	decoded, err := DecodeContentAssertion(compact, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verification != DecodeVerificationNotEvaluated || decoded.ContentDigest != a.ContentDigest || decoded.Gen != 1 {
		t.Fatalf("decoded mismatch: %#v", decoded)
	}
	facts, err := VerifyContentAssertion(compact, expected)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte(compact))
	if facts.Digest != wantDigest || facts.Verification != AttestationVerificationSignatureAndWindow || facts.Trust != TrustNotEvaluated {
		t.Fatalf("facts mismatch: %#v", facts)
	}
	if got, err := AssertionDigest(compact, nil); err != nil || got != wantDigest {
		t.Fatalf("AssertionDigest = %x, %v; want %x", got, err, wantDigest)
	}
	wrong := expected
	wrong.ContentDigest[0] ^= 1
	if _, err := VerifyContentAssertion(compact, wrong); err != ErrInvalid {
		t.Fatalf("wrong expected content digest error = %v", err)
	}
	missingBounds := expected
	missingBounds.Bounds = nil
	if _, err := VerifyContentAssertion(compact, missingBounds); err != ErrInvalid {
		t.Fatalf("missing expected bounds error = %v", err)
	}
	parts, err := splitContentAssertionCompact(compact, BoundsMaximum())
	if err != nil {
		t.Fatal(err)
	}
	parts.Signature[7] ^= 1
	tampered := parts.ProtectedSeg + "." + parts.PayloadSeg + "." + Base64urlEncode(parts.Signature)
	if _, err := VerifyContentAssertion(tampered, expected); err != ErrInvalid {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestContentAssertionRejectsStructuralProducerDefects(t *testing.T) {
	a, _, _ := contentAssertionFixture(t, "attestor-1", 1, [32]byte{}, 100, 110, 200)
	bad := a
	bad.Gen = 2
	if _, err := AssertionSigningInput(bad, nil); err != ErrInvalid {
		t.Fatalf("non-genesis zero prev error = %v", err)
	}
	bad = a
	bad.Gen = 1
	bad.Prev[0] = 1
	if _, err := AssertionSigningInput(bad, nil); err != ErrInvalid {
		t.Fatalf("genesis nonzero prev error = %v", err)
	}
	bad = a
	bad.Iat = bad.Nbf + 1
	if _, err := AssertionSigningInput(bad, nil); err != ErrInvalid {
		t.Fatalf("iat > nbf error = %v", err)
	}
	bad = a
	bad.Nbf = bad.Exp
	if _, err := AssertionSigningInput(bad, nil); err != ErrInvalid {
		t.Fatalf("nbf == exp error = %v", err)
	}
}

func TestContentAssertionSuccessorAllowsRotationAndExpiredPredecessor(t *testing.T) {
	predInput, predExpected, predPrivate := contentAssertionFixture(t, "attestor-old", 1, [32]byte{}, 100, 110, 120)
	predCompact := signContentAssertion(t, predInput, predPrivate, nil)
	predFacts, err := VerifyContentAssertion(predCompact, predExpected)
	if err != nil {
		t.Fatal(err)
	}
	succInput, succExpected, succPrivate := contentAssertionFixture(t, "attestor-new", 2, predFacts.Digest, 200, 210, 300)
	succInput.Iss, succInput.Aud, succInput.Sub, succInput.Profile, succInput.ProfileDigest = predFacts.Iss, predFacts.Aud, predFacts.Sub, predFacts.Profile, predFacts.ProfileDigest
	succExpected.Issuer, succExpected.Audience, succExpected.Subject, succExpected.Profile, succExpected.ProfileDigest = succInput.Iss, succInput.Aud, succInput.Sub, succInput.Profile, succInput.ProfileDigest
	succCompact := signContentAssertion(t, succInput, succPrivate, nil)
	succFacts, err := VerifyContentAssertion(succCompact, succExpected)
	if err != nil {
		t.Fatal(err)
	}
	bounds := BoundsMaximum()
	if err := VerifyContentAssertionSuccessor(predFacts, succFacts, &bounds); err != nil {
		t.Fatalf("rotated successor rejected: %v", err)
	}
	if err := VerifyContentAssertionSuccessor(predFacts, succFacts, nil); err != ErrInvalid {
		t.Fatalf("missing successor bounds error = %v", err)
	}
	bad := succFacts
	bad.Jti = predFacts.Jti
	if err := VerifyContentAssertionSuccessor(predFacts, bad, &bounds); err != ErrInvalid {
		t.Fatalf("same jti error = %v", err)
	}
	bad = succFacts
	bad.Verification = AttestationVerification(99)
	if err := VerifyContentAssertionSuccessor(predFacts, bad, &bounds); err != ErrInvalid {
		t.Fatalf("malformed marker error = %v", err)
	}
	if bytes.Equal(predFacts.AttestorKeyFingerprint[:], succFacts.AttestorKeyFingerprint[:]) {
		t.Fatal("fixture did not rotate signing keys")
	}
}
