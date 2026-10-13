package verifier

// End-to-end strict-Ed25519 tests: the public verify APIs must reject a forgery under a weak key.
//
// A small-order public key (the identity point, 01 00..00) lets anyone forge an Ed25519 signature
// without a private key: R = identity, S = 0 satisfies the cofactorless equation for every message.
// The forged artifacts are built by hand (JSON plus the raw JWS framing), deliberately NOT through the
// SDK's producers where those touch the weak key, so the setup keeps working after the SDK refuses to
// produce artifacts under a weak key and a rejection here can only come from the verifier.
//
// Each forged test has a positive control built the same way with a real key, so a failure to build
// the artifact cannot masquerade as a rejection.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

var (
	identityKey     = append([]byte{1}, make([]byte, 31)...)
	forgedSignature = append(append([]byte(nil), identityKey...), make([]byte, 32)...) // R = identity, S = 0
)

const (
	e2eIssuer     = "https://issuer.example.test"
	e2eAudience   = "https://resource.example.test"
	e2eTarget     = "https://resource.example.test/invoke"
	e2eInvocation = "550e8400-e29b-41d4-a716-446655440000"
)

func realKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func jcsJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v) // sorted map keys, compact, ASCII only here: equals JCS
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func e2eCompact(protected, payload, signature []byte) string {
	return Base64urlEncode(protected) + "." + Base64urlEncode(payload) + "." + Base64urlEncode(signature)
}

func e2eMessage(protected, payload []byte) []byte {
	return []byte(Base64urlEncode(protected) + "." + Base64urlEncode(payload))
}

func okpThumbprint(raw []byte) [32]byte {
	preimage, _ := json.Marshal(map[string]string{"crv": "Ed25519", "kty": "OKP", "x": Base64urlEncode(raw)})
	return sha256.Sum256(preimage)
}

func e2eGrantHeader(t *testing.T) []byte {
	return jcsJSON(t, map[string]any{"alg": "EdDSA", "kid": "issuer", "typ": "ba+cap"})
}

func e2eGrantPayload(t *testing.T, version int, holderThumbprint [32]byte) []byte {
	return jcsJSON(t, map[string]any{
		"aud": []string{e2eAudience}, "cnf": map[string]string{"jkt": Base64urlEncode(holderThumbprint[:])},
		"exp": 2000, "iat": 1000, "iss": e2eIssuer, "jti": "urn:example:grant:1", "nbf": 1000,
		"operations": []any{map[string]any{"name": "read", "selectors": []any{map[string]string{"kind": "all"}}}},
		"v":          version,
	})
}

func e2eExpectedGrant() ExpectedGrant {
	return ExpectedGrant{Issuer: e2eIssuer, Audience: e2eAudience, EvaluationTime: 1500, ClockSkew: 60}
}

func TestStrictEndToEndVerifyGrantRejectsIdentityKeyForgeryFirstMajor(t *testing.T) {
	holderPub, _ := realKey(t)
	thumb := okpThumbprint(holderPub)
	issuerPub, issuerPriv := realKey(t)
	header, payload := e2eGrantHeader(t), e2eGrantPayload(t, 1, thumb)
	honest := e2eCompact(header, payload, ed25519.Sign(issuerPriv, e2eMessage(header, payload)))
	if _, err := VerifyGrant(honest, TrustedIssuer{KeyID: "issuer", PublicKey: issuerPub}, e2eExpectedGrant()); err != nil {
		t.Fatalf("positive control: honest grant rejected: %v", err)
	}
	forged := e2eCompact(header, payload, forgedSignature)
	if _, err := VerifyGrant(forged, TrustedIssuer{KeyID: "issuer", PublicKey: identityKey}, e2eExpectedGrant()); err == nil {
		t.Fatal("a grant forged under the identity issuer key must be rejected")
	}
}

func TestStrictEndToEndVerifyGrantRejectsIdentityKeyForgerySecondMajor(t *testing.T) {
	holderPub, _ := realKey(t)
	thumb := okpThumbprint(holderPub)
	issuerPub, issuerPriv := realKey(t)
	header, payload := e2eGrantHeader(t), e2eGrantPayload(t, 2, thumb)
	honest := e2eCompact(header, payload, ed25519.Sign(issuerPriv, e2eMessage(header, payload)))
	if _, err := (Profile{}).VerifyGrant(honest, TrustedIssuer{KeyID: "issuer", PublicKey: issuerPub}, e2eExpectedGrant()); err != nil {
		t.Fatalf("positive control: honest v2 grant rejected: %v", err)
	}
	forged := e2eCompact(header, payload, forgedSignature)
	if _, err := (Profile{}).VerifyGrant(forged, TrustedIssuer{KeyID: "issuer", PublicKey: identityKey}, e2eExpectedGrant()); err == nil {
		t.Fatal("a v2 grant forged under the identity issuer key must be rejected")
	}
}

// e2eEnvelope builds a grant bound to holderKey plus a proof whose header carries that key's JWK,
// signed by sign. The proof payload is borrowed from the SDK producer under an honest holder key (the
// payload does not carry the key).
func e2eEnvelope(t *testing.T, version int, holderKey []byte, sign func(msg []byte) []byte) (Credentials, ed25519.PublicKey) {
	t.Helper()
	issuerPub, issuerPriv := realKey(t)
	gHeader, gPayload := e2eGrantHeader(t), e2eGrantPayload(t, version, okpThumbprint(holderKey))
	grant := e2eCompact(gHeader, gPayload, ed25519.Sign(issuerPriv, e2eMessage(gHeader, gPayload)))
	honestHolder, _ := realKey(t)
	producer := Proof{
		ProofID: "urn:example:proof:1", HolderPublicKey: honestHolder, InvocationID: e2eInvocation,
		Operation: "read", Method: "POST", TargetURI: e2eTarget, IssuedAt: 1400, GrantCompact: grant,
		CastArguments: Null{},
	}
	var si SigningInput
	var err error
	if version == 1 {
		si, err = ProofSigningInput(producer, nil)
	} else {
		si, err = (Profile{}).ProofSigningInput(producer, nil)
	}
	if err != nil {
		t.Fatalf("proof signing input: %v", err)
	}
	header := jcsJSON(t, map[string]any{
		"alg": "EdDSA", "typ": "dpop+jwt",
		"jwk": map[string]string{"crv": "Ed25519", "kty": "OKP", "x": Base64urlEncode(holderKey)},
	})
	proof := e2eCompact(header, si.Payload, sign(e2eMessage(header, si.Payload)))
	return Credentials{Grant: grant, Proof: proof}, issuerPub
}

func e2eExpectedRequest(issuerPub []byte) ExpectedRequest {
	return ExpectedRequest{
		TrustedIssuer: TrustedIssuer{KeyID: "issuer", PublicKey: issuerPub},
		Issuer:        e2eIssuer, Audience: e2eAudience, EvaluationTime: 1500, ClockSkew: 60,
		Method: "POST", TargetURI: e2eTarget, InvocationID: e2eInvocation, Operation: "read",
		CastArguments: Null{}, ProofMaxAge: 300, Nonce: NonceNotRequired(),
	}
}

func TestStrictEndToEndCheckEnvelopeRejectsIdentityHolderKeyForgery(t *testing.T) {
	for _, version := range []int{1, 2} {
		check := CheckEnvelope
		if version == 2 {
			check = (Profile{}).CheckEnvelope
		}
		holderPub, holderPriv := realKey(t)
		creds, issuerPub := e2eEnvelope(t, version, holderPub, func(msg []byte) []byte { return ed25519.Sign(holderPriv, msg) })
		if _, err := check(creds, e2eExpectedRequest(issuerPub)); err != nil {
			t.Fatalf("v%d positive control: honest envelope rejected: %v", version, err)
		}
		creds, issuerPub = e2eEnvelope(t, version, identityKey, func([]byte) []byte { return forgedSignature })
		if _, err := check(creds, e2eExpectedRequest(issuerPub)); err == nil {
			t.Fatalf("v%d: a proof forged under the identity holder key must be rejected", version)
		}
	}
}

// The gate at the choke point rejects what a key check alone cannot: the issuer key is REAL, so key
// acceptance passes; only the R clause rejects this key-holder signature (R = identity, S = k*a).
func TestStrictEndToEndVerifyGrantRejectsKeyHolderSignatureWithSmallOrderR(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	issuerPub := refPublicKey(seed)
	holderPub, _ := realKey(t)
	header, payload := e2eGrantHeader(t), e2eGrantPayload(t, 1, okpThumbprint(holderPub))
	message := e2eMessage(header, payload)
	sig := refIdentityRSignature(seed, message)
	if !ed25519.Verify(ed25519.PublicKey(issuerPub), message, sig) {
		t.Fatal("the bare backend must accept this signature (that is the bug the gate closes)")
	}
	trusted := TrustedIssuer{KeyID: "issuer", PublicKey: issuerPub}
	honest := e2eCompact(header, payload, refSignFor(seed, issuerPub, message, nil))
	if _, err := VerifyGrant(honest, trusted, e2eExpectedGrant()); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if _, err := VerifyGrant(e2eCompact(header, payload, sig), trusted, e2eExpectedGrant()); err == nil {
		t.Fatal("small-order R accepted")
	}
}

func TestStrictEndToEndContentAssertionRejectsIdentityAttestorForgery(t *testing.T) {
	a, expected, private := contentAssertionFixture(t, "attestor-1", 1, [32]byte{}, 100, 110, 200)
	compact := signContentAssertion(t, a, private, expected.Bounds)
	if _, err := VerifyContentAssertion(compact, expected); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	si, err := AssertionSigningInput(a, expected.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := AssembleContentAssertionCompact(si, forgedSignature, expected.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	expected.Attestor.PublicKey = identityKey
	if _, err := VerifyContentAssertion(forged, expected); err == nil {
		t.Fatal("assertion forged under the identity attestor key accepted")
	}
}

func roleAttestationFixture(t *testing.T, subject [32]byte) (Attestation, ExpectedAttestation, ed25519.PrivateKey) {
	t.Helper()
	attestorPub, attestorPriv := realKey(t)
	a := Attestation{AttestorKeyID: "attestor-ra-1", Jti: "urn:example:attestation:ra-1", KeyID: "subject-key-1",
		PublicKey: subject, Role: "issuer", Nbf: 1735689600, Exp: 1735693200}
	expected := ExpectedAttestation{
		Attestor:     TrustedAttestor{KeyID: "attestor-ra-1", ValidFrom: 1735689000, ValidBefore: 1735694000},
		SubjectKeyID: "subject-key-1", SubjectPublicKey: subject, Now: 1735691000,
	}
	copy(expected.Attestor.PublicKey[:], attestorPub)
	return a, expected, attestorPriv
}

func TestStrictEndToEndRoleAttestationRejectsIdentityAttestorForgery(t *testing.T) {
	subjectPub, _ := realKey(t)
	var subject [32]byte
	copy(subject[:], subjectPub)
	a, expected, private := roleAttestationFixture(t, subject)
	si, err := AttestationSigningInput(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := AssembleAttestationCompact(si, ed25519.Sign(private, signingInputMessage(si)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(honest, expected); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	forged, err := AssembleAttestationCompact(si, forgedSignature, nil)
	if err != nil {
		t.Fatal(err)
	}
	copy(expected.Attestor.PublicKey[:], identityKey)
	if _, err := VerifyAttestation(forged, expected); err == nil {
		t.Fatal("attestation forged under the identity attestor key accepted")
	}
}

func TestStrictEndToEndRoleAttestationRefusesAWeakSubjectKey(t *testing.T) {
	good, _ := realKey(t)
	var goodKey [32]byte
	copy(goodKey[:], good)
	// Positive controls: a real subject key decodes, produces and verifies.
	a, expected, private := roleAttestationFixture(t, goodKey)
	si, err := AttestationSigningInput(a, nil)
	if err != nil {
		t.Fatalf("positive control producer: %v", err)
	}
	compact, err := AssembleAttestationCompact(si, ed25519.Sign(private, signingInputMessage(si)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAttestation(compact, nil); err != nil {
		t.Fatalf("positive control decode: %v", err)
	}
	if _, err := VerifyAttestation(compact, expected); err != nil {
		t.Fatalf("positive control verify: %v", err)
	}

	for _, weak := range [][]byte{identityKey, make([]byte, 32), append(append([]byte{1}, make([]byte, 30)...), 0x80)} {
		var key [32]byte
		copy(key[:], weak)
		wa, wexpected, wprivate := roleAttestationFixture(t, key)
		header := jcsJSON(t, map[string]any{"alg": "EdDSA", "kid": "attestor-ra-1", "typ": "ba+role-attestation"})
		payload := jcsJSON(t, map[string]any{"exp": wa.Exp, "jti": wa.Jti, "key_id": wa.KeyID, "nbf": wa.Nbf,
			"public_key": Base64urlEncode(weak), "role": "issuer", "v": 1})
		hand := e2eCompact(header, payload, ed25519.Sign(wprivate, e2eMessage(header, payload)))
		if _, err := DecodeAttestation(hand, nil); err == nil {
			t.Errorf("decode accepted a weak subject key %x in the payload", weak)
		}
		if _, err := VerifyAttestation(hand, wexpected); err == nil {
			t.Errorf("verify accepted a weak subject key %x", weak)
		}
		if _, err := AttestationSigningInput(wa, nil); err == nil {
			t.Errorf("producer accepted a weak subject key %x", weak)
		}
	}
}
