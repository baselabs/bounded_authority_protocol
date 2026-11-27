package verifier_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	verifier "github.com/baselabs/bounded_authority_protocol_go"
)

func TestApprovalAssertionSuccessors(t *testing.T) {
	b := verifier.BoundsMaximum()
	revision := sha256.Sum256([]byte("revision-1"))
	record := verifier.NewApprovalRecord("article", "publish", "request-1", "editor", []string{"catalog"}, revision)
	wire, err := verifier.EncodeApprovalRecord(record, &b, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest, err := verifier.ContentDigest(wire, &b)
	if err != nil {
		t.Fatal(err)
	}
	genesis := verifier.ContentAssertion{
		AttestorKeyID: "editor-1", Jti: "approval-1", Iss: "issuer", Aud: "publisher",
		Sub: record.RequestID(), Profile: verifier.ApprovalProfile,
		ProfileDigest: verifier.ApprovalProfileDigest(), ContentDigest: contentDigest,
		Gen: 1, Iat: 10, Nbf: 10, Exp: 60,
	}
	verify := func(t *testing.T, suite verifier.ApprovalSuite, claims verifier.ContentAssertion) verifier.VerifiedApprovalFacts {
		t.Helper()
		public, compact := signApprovalAssertion(t, suite, claims, &b)
		ctx := verifier.ApprovalContext{
			TrustDomain: "editorial", Audience: claims.Aud, RequestID: record.RequestID(),
			RevisionDigest: revision[:], Subject: record.Subject(), Action: record.Action(),
			Resources: record.Resources(), Roles: []string{record.ApproverRole()},
			Now: 20, MaxStaleness: 5, MaxLifetime: 50, Bounds: &b,
			Snapshot: &verifier.ApprovalTrustSnapshot{
				Suite: suite, TrustDomain: "editorial", Provenance: "test", AsOf: 15,
				Entries: []verifier.ApprovalTrustEntry{{
					Issuer: claims.Iss, Roles: []string{record.ApproverRole()},
					Key: verifier.HistoricalPublicKey{
						KeyID: claims.AttestorKeyID, PublicKey: public, ValidBefore: 60,
					},
				}},
			},
		}
		verifyApproval := verifier.VerifyApprovalEdDSA
		if suite == verifier.ApprovalSuiteES256 {
			verifyApproval = verifier.VerifyApprovalES256
		}
		facts, diagnostic := verifyApproval(wire, compact, ctx)
		if diagnostic != verifier.ApprovalNoDiagnostic {
			t.Fatalf("verify %s approval: %v", suite, diagnostic)
		}
		return facts
	}
	successor := genesis
	successor.AttestorKeyID, successor.Jti, successor.Gen = "editor-2", "approval-2", 2

	t.Run("ES256", func(t *testing.T) {
		first := verify(t, verifier.ApprovalSuiteES256, genesis)
		predecessor, ok := first.AssertionES256()
		if !ok {
			t.Fatal("ES256 approval did not expose ES256 assertion facts")
		}
		claims := successor
		claims.Prev = predecessor.Digest()
		second := verify(t, verifier.ApprovalSuiteES256, claims)
		next, ok := second.AssertionES256()
		if !ok {
			t.Fatal("successor approval did not expose ES256 assertion facts")
		}
		if err := (verifier.ContentAssertionES256{}).VerifySuccessor(predecessor, next, &b); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("EdDSA", func(t *testing.T) {
		first := verify(t, verifier.ApprovalSuiteEdDSA, genesis)
		predecessor, ok := first.AssertionEdDSA()
		if !ok {
			t.Fatal("EdDSA approval did not expose EdDSA assertion facts")
		}
		claims := successor
		claims.Prev = predecessor.Digest()
		second := verify(t, verifier.ApprovalSuiteEdDSA, claims)
		next, ok := second.AssertionEdDSA()
		if !ok {
			t.Fatal("successor approval did not expose EdDSA assertion facts")
		}
		if err := verifier.VerifyContentAssertionSuccessor(predecessor, next, &b); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("mixed suites", func(t *testing.T) {
		first := verify(t, verifier.ApprovalSuiteES256, genesis)
		if facts, ok := first.AssertionEdDSA(); ok || facts.Version() != 0 {
			t.Fatal("EdDSA accessor exposed ES256 assertion facts")
		}
		claims := successor
		claims.Prev = first.Assertion().Digest()
		second := verify(t, verifier.ApprovalSuiteEdDSA, claims)
		if facts, ok := second.AssertionES256(); ok || facts.Version() != 0 {
			t.Fatal("ES256 accessor exposed EdDSA assertion facts")
		}
		if err := verifier.VerifyContentAssertionSuccessor(first.Assertion(), second.Assertion(), &b); err != verifier.ErrInvalid {
			t.Fatalf("mixed-suite successor: got %v, want ErrInvalid", err)
		}
	})
}

func signApprovalAssertion(t *testing.T, suite verifier.ApprovalSuite, claims verifier.ContentAssertion, b *verifier.Bounds) ([]byte, string) {
	t.Helper()
	message := func(si verifier.SigningInput) []byte {
		return []byte(verifier.Base64urlEncode(si.Protected) + "." + verifier.Base64urlEncode(si.Payload))
	}
	if suite == verifier.ApprovalSuiteEdDSA {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		si, err := verifier.AssertionSigningInput(claims, b)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := verifier.AssembleContentAssertionCompact(si, ed25519.Sign(key, message(si)), b)
		if err != nil {
			t.Fatal(err)
		}
		return public, compact
	}

	es := verifier.ContentAssertionES256{}
	curve := elliptic.P256()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	si, err := es.AssertionSigningInput(claims, b)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message(si))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if lowS := new(big.Int).Sub(curve.Params().N, s); s.Cmp(lowS) > 0 {
		s = lowS
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	compact, err := es.AssembleCompact(si, signature[:], b)
	if err != nil {
		t.Fatal(err)
	}
	return public, compact
}
