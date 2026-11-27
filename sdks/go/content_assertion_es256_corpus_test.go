package verifier

import (
	"encoding/json"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baselabs/bounded_authority_protocol_go/internal/corpuscheck"
)

const es256Corpus = "attestation-profiles/content-assertion-es256/v1"

var candidateSourceRoot = flag.String("candidate-source", "", "checkout containing the source-only candidate corpora")

func candidateSource(t *testing.T, path string) string {
	t.Helper()
	if *candidateSourceRoot == "" {
		t.Skip("pass -candidate-source to run source-only conformance")
	}
	return filepath.Join(*candidateSourceRoot, "priv", "conformance", path)
}

func candidateRead[T any](v any) (T, error) {
	var out T
	wire, err := json.Marshal(v)
	if err == nil {
		err = json.Unmarshal(wire, &out)
	}
	return out, err
}

func candidateRequire[T any](t *testing.T, v any) T {
	t.Helper()
	out, err := candidateRead[T](v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func candidateBytes(encoded string) []byte {
	raw, err := Base64urlDecode(encoded)
	if err != nil {
		panic("invalid fixture byte encoding")
	}
	return raw
}

func candidateDigest(encoded string) [32]byte {
	d, err := corpusFixedDigest(encoded)
	if err != nil {
		panic("invalid fixture digest")
	}
	return d
}

func candidateEncoded(digest [32]byte) string { return Base64urlEncode(digest[:]) }

func candidateBounds(raw any) (Bounds, error) {
	m, err := candidateRead[map[string]int](raw)
	if err != nil {
		return Bounds{}, err
	}
	return BoundsNew(m)
}

type candidateKey struct {
	KeyID       string          `json:"key_id"`
	PublicKey   string          `json:"public_key"`
	ValidFrom   *int64          `json:"valid_from"`
	ValidBefore json.RawMessage `json:"valid_before"`
}

func (k candidateKey) historicalKey() HistoricalPublicKey {
	if k.ValidFrom == nil || k.ValidBefore == nil || k.PublicKey == "" {
		return HistoricalPublicKey{}
	}
	h := HistoricalPublicKey{KeyID: k.KeyID, PublicKey: candidateBytes(k.PublicKey), ValidFrom: *k.ValidFrom}
	if string(k.ValidBefore) == `"unbounded"` {
		h.ValidBeforeUnbounded = true
	} else if string(k.ValidBefore) == "null" || json.Unmarshal(k.ValidBefore, &h.ValidBefore) != nil {
		return HistoricalPublicKey{}
	}
	return h
}

type candidateClaims struct {
	Version       int    `json:"v"`
	JTI           string `json:"jti"`
	ISS           string `json:"iss"`
	AUD           string `json:"aud"`
	SUB           string `json:"sub"`
	Profile       string `json:"profile"`
	ProfileDigest string `json:"profile_digest"`
	ContentDigest string `json:"content_digest"`
	Gen           int64  `json:"gen"`
	Prev          string `json:"prev"`
	IAT           int64  `json:"iat"`
	NBF           int64  `json:"nbf"`
	EXP           int64  `json:"exp"`
}

func (a candidateClaims) producer(kid string) ContentAssertion {
	return ContentAssertion{
		AttestorKeyID: kid, Jti: a.JTI, Iss: a.ISS, Aud: a.AUD, Sub: a.SUB, Profile: a.Profile,
		ProfileDigest: candidateDigest(a.ProfileDigest), ContentDigest: candidateDigest(a.ContentDigest),
		Gen: a.Gen, Prev: candidateDigest(a.Prev), Iat: a.IAT, Nbf: a.NBF, Exp: a.EXP,
	}
}

type candidateVerifiedAssertion struct {
	candidateClaims
	Version      int    `json:"version"`
	Kid          string `json:"attestor_key_id"`
	Fingerprint  string `json:"attestor_key_fingerprint"`
	Digest       string `json:"digest"`
	Trust        string `json:"trust"`
	Verification string `json:"verification"`
}

func (a candidateVerifiedAssertion) facts(suite string) ES256ContentAssertionFacts {
	p := a.producer(a.Kid)
	kind := KindContentAssertionES256
	if suite == "eddsa" {
		kind = KindContentAssertion
	}
	var trust Trust = -1
	if a.Trust == "not_evaluated" {
		trust = TrustNotEvaluated
	}
	var verification AttestationVerification = -1
	if a.Verification == "signature_and_window" {
		verification = AttestationVerificationSignatureAndWindow
	}
	return ES256ContentAssertionFacts{ContentAssertionFacts{kind: kind, data: privateValue(&contentAssertionFactsData{
		Version: a.Version, AttestorKeyID: p.AttestorKeyID,
		AttestorKeyFingerprint: candidateDigest(a.Fingerprint), Jti: p.Jti, Iss: p.Iss, Aud: p.Aud,
		Sub: p.Sub, Profile: p.Profile, ProfileDigest: p.ProfileDigest, ContentDigest: p.ContentDigest,
		Gen: p.Gen, Prev: p.Prev, Iat: p.Iat, Nbf: p.Nbf, Exp: p.Exp,
		Digest: candidateDigest(a.Digest), Verification: verification, Trust: trust,
	})}}
}

type assertionProjection interface {
	Version() int
	AttestorKeyID() string
	Jti() string
	Iss() string
	Aud() string
	Sub() string
	Profile() string
	ProfileDigest() [32]byte
	ContentDigest() [32]byte
	Gen() int64
	Prev() [32]byte
	Iat() int64
	Nbf() int64
	Exp() int64
}

func candidateAssertionValues(a assertionProjection) map[string]any {
	return map[string]any{
		"v": a.Version(), "attestor_key_id": a.AttestorKeyID(), "jti": a.Jti(), "iss": a.Iss(),
		"aud": a.Aud(), "sub": a.Sub(), "profile": a.Profile(), "profile_digest": candidateEncoded(a.ProfileDigest()),
		"content_digest": candidateEncoded(a.ContentDigest()), "gen": a.Gen(), "prev": candidateEncoded(a.Prev()),
		"iat": a.Iat(), "nbf": a.Nbf(), "exp": a.Exp(),
	}
}

func candidateVerifiedValues(a ContentAssertionFacts) map[string]any {
	out := candidateAssertionValues(a)
	out["version"] = out["v"]
	delete(out, "v")
	out["attestor_key_fingerprint"] = candidateEncoded(a.AttestorKeyFingerprint())
	out["digest"] = candidateEncoded(a.Digest())
	if a.Trust() == TrustNotEvaluated {
		out["trust"] = "not_evaluated"
	}
	if a.Verification() == AttestationVerificationSignatureAndWindow {
		out["verification"] = "signature_and_window"
	}
	return out
}

func TestCandidateES256ContentAssertionCorpus(t *testing.T) {
	root := candidateSource(t, es256Corpus)
	corpuscheck.Candidate(t, root, "2bb41b8fbc9fbdc0267f72976d56280be0541420e4c14241ca622f1dd071d0cb", es256CandidateOutcome)
}

func es256CandidateOutcome(t *testing.T, entry corpuscheck.Case, profile, _ map[string]any) any {
	c := entry.Value
	es := ContentAssertionES256{}
	b := BoundsMaximum()
	if raw, ok := c["bounds"]; ok {
		var err error
		b, err = candidateBounds(raw)
		if err != nil {
			return "invalid"
		}
	}
	switch entry.File {
	case "digest-cases.json":
		d, err := es.ContentDigest(candidateBytes(c["input"].(string)), &b)
		if err != nil {
			return "invalid"
		}
		return candidateEncoded(d)
	case "assembly-cases.json":
		signing := profile["signing"].(map[string]any)
		claims := candidateRequire[candidateClaims](t, signing["payload"])
		si, err := es.AssertionSigningInput(claims.producer(signing["kid"].(string)), &b)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := es.AssembleCompact(si, candidateBytes(c["signature"].(string)), &b)
		if err != nil {
			return "invalid"
		}
		return compact
	case "assertion-structure-cases.json":
		compact := c["compact"].(string)
		decoded, err := es.DecodeAssertion(compact, &b)
		digest, digestErr := es.AssertionDigest(compact, &b)
		if (err == nil) != (digestErr == nil) {
			t.Fatal("decoder and digest disagree")
		}
		if err != nil {
			return "invalid"
		}
		if decoded.Verification() != DecodeVerificationNotEvaluated {
			t.Fatal("decoder marked unverified claims as verified")
		}
		out := candidateAssertionValues(decoded)
		out["digest"] = candidateEncoded(digest)
		return out
	case "assertion-verification-cases.json":
		input := candidateRequire[struct {
			Attestor      candidateKey `json:"attestor"`
			Issuer        string       `json:"issuer"`
			Audience      string       `json:"audience"`
			Subject       string       `json:"subject"`
			Profile       string       `json:"profile"`
			ProfileDigest string       `json:"profile_digest"`
			ContentDigest string       `json:"content_digest"`
			Now           int64        `json:"now"`
		}](t, c["context"])
		expected := ExpectedContentAssertion{Attestor: input.Attestor.historicalKey(), Issuer: input.Issuer,
			Audience: input.Audience, Subject: input.Subject, Profile: input.Profile,
			ProfileDigest: candidateDigest(input.ProfileDigest), ContentDigest: candidateDigest(input.ContentDigest),
			Now: input.Now, Bounds: &b}
		facts, err := es.VerifyAssertion(c["compact"].(string), expected)
		if err != nil {
			return "invalid"
		}
		return candidateVerifiedValues(facts.assertionFacts)
	case "successor-cases.json":
		prev := candidateRequire[candidateVerifiedAssertion](t, c["predecessor"]).facts(c["previous_suite"].(string))
		next := candidateRequire[candidateVerifiedAssertion](t, c["successor"]).facts(c["next_suite"].(string))
		if es.VerifySuccessor(prev, next, &b) != nil {
			return "invalid"
		}
		return "ok"
	case "separation-cases.json":
		candidate, foreign := c["candidate"].(string), c["foreign"].(string)
		id := c["id"].(string)
		_, candidateAccepted := es.DecodeAssertion(candidate, &b)
		_, foreignRejected := es.DecodeAssertion(foreign, &b)
		if candidateAccepted != nil || !foreignAssertionAccepts(id, foreign, b) {
			t.Fatal("separation rejected a same-profile control")
		}
		if foreignRejected != ErrInvalid || foreignAssertionAccepts(id, candidate, b) {
			t.Fatal("separation accepted the other profile")
		}
		return "both_reject"
	}
	t.Fatal("unknown candidate case file")
	return nil
}

func foreignAssertionAccepts(id, compact string, b Bounds) bool {
	switch id {
	case "ca1":
		_, err := DecodeContentAssertion(compact, &b)
		return err == nil
	case "loopback":
		_, err := DecodeLocalLoopbackHTTPProof(compact, &b)
		return err == nil
	case "role-attestation":
		_, err := DecodeAttestation(compact, &b)
		return err == nil
	}
	major, kind, _ := strings.Cut(id, "-")
	switch kind {
	case "grant":
		switch major {
		case "v1":
			_, err := DecodeGrant(compact, &b)
			return err == nil
		case "v2":
			_, err := (Profile{}).DecodeGrant(compact, &b)
			return err == nil
		case "v3":
			_, err := (EcdsaProfile{}).DecodeGrant(compact, &b)
			return err == nil
		}
	case "proof":
		switch major {
		case "v1":
			_, err := DecodeProof(compact, &b)
			return err == nil
		case "v2":
			_, err := (Profile{}).DecodeProof(compact, &b)
			return err == nil
		case "v3":
			_, err := (EcdsaProfile{}).DecodeProof(compact, &b)
			return err == nil
		}
	case "anchor":
		switch major {
		case "v1":
			return archiveAssertionAccepts(compact, b, KindBoundaryAnchor)
		case "v2":
			_, err := (Profile{}).parseAnchorCompactGated(compact, b)
			return err == nil
		case "v3":
			_, err := (EcdsaProfile{}).parseAnchorCompactGated(compact, b)
			return err == nil
		}
	case "transition":
		switch major {
		case "v1":
			return archiveAssertionAccepts(compact, b, KindKeyTransition)
		case "v2":
			_, err := (Profile{}).parseTransitionCompactGated(compact, b)
			return err == nil
		case "v3":
			_, err := (EcdsaProfile{}).parseTransitionCompactGated(compact, b)
			return err == nil
		}
	}
	panic("unknown foreign assertion profile")
}

func archiveAssertionAccepts(compact string, b Bounds, kind Kind) bool {
	p, err := splitCompact(compact, b)
	if err != nil || canonicalSegment(p.ProtectedSeg, p.Protected, b) != nil ||
		canonicalSegment(p.PayloadSeg, p.Payload, b) != nil {
		return false
	}
	v, err := JsonDecode(p.Payload, &b)
	obj, ok := v.(Obj)
	if err != nil || !ok {
		return false
	}
	if kind == KindBoundaryAnchor {
		_, err := decodeAnchorHeader(p.Protected, b)
		claims, ok := decodeAnchorClaims(obj, b)
		return err == nil && ok && enforceAnchorGenesis(claims) == nil
	}
	_, err = decodeTransitionHeader(p.Protected, b)
	_, ok = decodeTransitionClaims(obj, b)
	return err == nil && ok
}
