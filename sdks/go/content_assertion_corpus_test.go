package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const certifiedContentAssertionIndexSHA256 = "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"

type contentCorpusAttestor struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	ValidFrom   int64  `json:"valid_from"`
	ValidBefore int64  `json:"valid_before"`
}

type contentCorpusOverrides struct {
	Issuer              *string `json:"issuer"`
	Audience            *string `json:"audience"`
	Subject             *string `json:"subject"`
	Profile             *string `json:"profile"`
	ProfileDigest       *string `json:"profile_digest"`
	ContentDigest       *string `json:"content_digest"`
	Now                 *int64  `json:"now"`
	AttestorKeyID       *string `json:"attestor_key_id"`
	AttestorPublicKey   *string `json:"attestor_public_key"`
	AttestorValidFrom   *int64  `json:"attestor_valid_from"`
	AttestorValidBefore *int64  `json:"attestor_valid_before"`
}

type contentCorpusCase struct {
	ID                string                  `json:"id"`
	Compact           string                  `json:"compact"`
	Attestor          string                  `json:"attestor"`
	Bounds            map[string]int          `json:"bounds"`
	ExpectedOverrides *contentCorpusOverrides `json:"expected_overrides"`
	Expected          struct {
		Decode string `json:"decode"`
		Verify string `json:"verify"`
	} `json:"expected"`
}

type contentCorpusProfile struct {
	Attestors map[string]contentCorpusAttestor `json:"attestors"`
	Expected  struct {
		Issuer        string `json:"issuer"`
		Audience      string `json:"audience"`
		Subject       string `json:"subject"`
		Profile       string `json:"profile"`
		ProfileDigest string `json:"profile_digest"`
		ContentDigest string `json:"content_digest"`
		Now           int64  `json:"now"`
	} `json:"expected"`
}

func contentCorpusRoot() string {
	return filepath.Join("..", "..", "priv", "conformance", "attestation-profiles", "content-assertion", "v1")
}

func readContentCorpus(t *testing.T, name string, into any) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(contentCorpusRoot(), name))
	if err != nil {
		t.Fatal(err)
	}
	if into != nil {
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatalf("invalid JSON %s: %v", name, err)
		}
	}
	return b
}

func corpusFixedDigest(encoded string) ([32]byte, error) {
	var out [32]byte
	raw, err := Base64urlDecode(encoded)
	if err != nil || len(raw) != 32 {
		return out, ErrInvalid
	}
	copy(out[:], raw)
	return out, nil
}

func corpusExpected(profile contentCorpusProfile, attestorName string, overrides *contentCorpusOverrides, bounds *Bounds) (ExpectedContentAssertion, error) {
	if attestorName == "" {
		attestorName = "primary"
	}
	a, ok := profile.Attestors[attestorName]
	if !ok {
		return ExpectedContentAssertion{}, ErrInvalid
	}
	public, err := Base64urlDecode(a.PublicKey)
	if err != nil || len(public) != 32 {
		return ExpectedContentAssertion{}, ErrInvalid
	}
	profileDigest, err := corpusFixedDigest(profile.Expected.ProfileDigest)
	if err != nil {
		return ExpectedContentAssertion{}, ErrInvalid
	}
	contentDigest, err := corpusFixedDigest(profile.Expected.ContentDigest)
	if err != nil {
		return ExpectedContentAssertion{}, ErrInvalid
	}
	e := ExpectedContentAssertion{
		Attestor: HistoricalPublicKey{KeyID: a.KeyID, PublicKey: public, ValidFrom: a.ValidFrom, ValidBefore: a.ValidBefore},
		Issuer:   profile.Expected.Issuer, Audience: profile.Expected.Audience, Subject: profile.Expected.Subject,
		Profile: profile.Expected.Profile, ProfileDigest: profileDigest, ContentDigest: contentDigest,
		Now: profile.Expected.Now, Bounds: bounds,
	}
	if overrides == nil {
		return e, nil
	}
	if overrides.Issuer != nil {
		e.Issuer = *overrides.Issuer
	}
	if overrides.Audience != nil {
		e.Audience = *overrides.Audience
	}
	if overrides.Subject != nil {
		e.Subject = *overrides.Subject
	}
	if overrides.Profile != nil {
		e.Profile = *overrides.Profile
	}
	if overrides.Now != nil {
		e.Now = *overrides.Now
	}
	if overrides.AttestorKeyID != nil {
		e.Attestor.KeyID = *overrides.AttestorKeyID
	}
	if overrides.AttestorPublicKey != nil {
		raw, err := Base64urlDecode(*overrides.AttestorPublicKey)
		if err != nil || len(raw) != 32 {
			return ExpectedContentAssertion{}, ErrInvalid
		}
		e.Attestor.PublicKey = raw
	}
	if overrides.AttestorValidFrom != nil {
		e.Attestor.ValidFrom = *overrides.AttestorValidFrom
	}
	if overrides.AttestorValidBefore != nil {
		e.Attestor.ValidBefore = *overrides.AttestorValidBefore
		e.Attestor.ValidBeforeUnbounded = false
	}
	if overrides.ProfileDigest != nil {
		e.ProfileDigest, err = corpusFixedDigest(*overrides.ProfileDigest)
		if err != nil {
			return ExpectedContentAssertion{}, ErrInvalid
		}
	}
	if overrides.ContentDigest != nil {
		e.ContentDigest, err = corpusFixedDigest(*overrides.ContentDigest)
		if err != nil {
			return ExpectedContentAssertion{}, ErrInvalid
		}
	}
	return e, nil
}

func TestCertifiedContentAssertionCorpusIntegrityAndVerdicts(t *testing.T) {
	var index struct {
		Profile        string `json:"profile"`
		Revision       int    `json:"revision"`
		AssertionCases int    `json:"assertion_cases"`
		DigestCases    int    `json:"digest_cases"`
		SuccessorCases int    `json:"successor_cases"`
		Files          []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	indexBytes := readContentCorpus(t, "index.json", &index)
	actualIndex := sha256.Sum256(indexBytes)
	if hex.EncodeToString(actualIndex[:]) != certifiedContentAssertionIndexSHA256 {
		t.Fatal("content assertion index digest mismatch")
	}
	if index.Profile != "bap-content-assertion/1" || index.Revision != 1 || index.AssertionCases != 131 || index.DigestCases != 9 || index.SuccessorCases != 14 || len(index.Files) != 8 {
		t.Fatal("content assertion index metadata mismatch")
	}
	for _, file := range index.Files {
		digest := sha256.Sum256(readContentCorpus(t, file.Path, nil))
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			t.Fatalf("%s digest mismatch", file.Path)
		}
	}

	var profile contentCorpusProfile
	readContentCorpus(t, "profile.json", &profile)
	var digestCases []struct {
		ID    string `json:"id"`
		Input struct {
			Bounds           map[string]int `json:"bounds"`
			ContentBase64url string         `json:"content_base64url"`
			ContentFile      string         `json:"content_file"`
		} `json:"input"`
		Expected struct {
			Verdict string `json:"verdict"`
			Digest  string `json:"digest"`
		} `json:"expected"`
	}
	readContentCorpus(t, "digest-cases.json", &digestCases)
	if len(digestCases) != index.DigestCases {
		t.Fatal("digest case count mismatch")
	}
	for _, c := range digestCases {
		var content []byte
		var err error
		if c.Input.ContentFile != "" {
			content = readContentCorpus(t, c.Input.ContentFile, nil)
		} else {
			content, err = Base64urlDecode(c.Input.ContentBase64url)
		}
		bounds, boundsErr := BoundsNew(c.Input.Bounds)
		var got [32]byte
		if err == nil && boundsErr == nil {
			got, err = ContentDigest(content, &bounds)
		} else {
			err = ErrInvalid
		}
		if (err == nil) != (c.Expected.Verdict == "valid") {
			t.Errorf("%s digest verdict mismatch", c.ID)
			continue
		}
		if err == nil {
			want, parseErr := corpusFixedDigest(c.Expected.Digest)
			if parseErr != nil || got != want {
				t.Errorf("%s digest bytes mismatch", c.ID)
			}
		}
	}

	var cases []contentCorpusCase
	for _, name := range []string{"assertion-structure-cases.json", "assertion-verification-cases.json"} {
		var batch []contentCorpusCase
		readContentCorpus(t, name, &batch)
		cases = append(cases, batch...)
	}
	if len(cases) != index.AssertionCases {
		t.Fatal("assertion case count mismatch")
	}
	producerCases := 0
	for _, c := range cases {
		bounds, boundsErr := BoundsNew(c.Bounds)
		decodeOK, verifyOK := false, false
		if boundsErr == nil {
			decoded, decodeErr := DecodeContentAssertion(c.Compact, &bounds)
			decodeOK = decodeErr == nil
			if decodeOK {
				producerCases++
				si, producerErr := AssertionSigningInput(ContentAssertion{AttestorKeyID: decoded.AttestorKeyID, Jti: decoded.Jti, Iss: decoded.Iss, Aud: decoded.Aud, Sub: decoded.Sub, Profile: decoded.Profile, ProfileDigest: decoded.ProfileDigest, ContentDigest: decoded.ContentDigest, Gen: decoded.Gen, Prev: decoded.Prev, Iat: decoded.Iat, Nbf: decoded.Nbf, Exp: decoded.Exp}, &bounds)
				if producerErr != nil || Base64urlEncode(si.Protected) != strings.Split(c.Compact, ".")[0] || Base64urlEncode(si.Payload) != strings.Split(c.Compact, ".")[1] {
					t.Errorf("%s producer bytes mismatch", c.ID)
				}
				if digest, digestErr := AssertionDigest(c.Compact, &bounds); digestErr != nil || digest != sha256.Sum256([]byte(c.Compact)) {
					t.Errorf("%s assertion digest mismatch", c.ID)
				}
			}
			expected, expectedErr := corpusExpected(profile, c.Attestor, c.ExpectedOverrides, &bounds)
			if expectedErr == nil {
				_, err := VerifyContentAssertion(c.Compact, expected)
				verifyOK = err == nil
			}
		}
		if decodeOK != (c.Expected.Decode == "valid") {
			t.Errorf("%s decode=%t want=%s", c.ID, decodeOK, c.Expected.Decode)
		}
		if verifyOK != (c.Expected.Verify == "valid") {
			t.Errorf("%s verify=%t want=%s", c.ID, verifyOK, c.Expected.Verify)
		}
	}
	if producerCases != 38 {
		t.Fatalf("producer case count = %d, want 38", producerCases)
	}
}

func TestCertifiedContentAssertionSuccessorCorpus(t *testing.T) {
	var profile contentCorpusProfile
	readContentCorpus(t, "profile.json", &profile)
	type artifact struct {
		Attestor          string                  `json:"attestor"`
		Compact           string                  `json:"compact"`
		ExpectedOverrides *contentCorpusOverrides `json:"expected_overrides"`
		FactsOverrides    map[string]string       `json:"facts_overrides"`
	}
	var cases []struct {
		ID          string   `json:"id"`
		Predecessor artifact `json:"predecessor"`
		Successor   artifact `json:"successor"`
		Expected    struct {
			Predecessor string `json:"predecessor"`
			Successor   string `json:"successor"`
			Relation    string `json:"relation"`
		} `json:"expected"`
	}
	readContentCorpus(t, "successor-cases.json", &cases)
	if len(cases) != 14 {
		t.Fatal("successor case count mismatch")
	}
	for _, c := range cases {
		verify := func(a artifact) (ContentAssertionFacts, bool) {
			bounds := BoundsMaximum()
			e, err := corpusExpected(profile, a.Attestor, a.ExpectedOverrides, &bounds)
			if err != nil {
				return ContentAssertionFacts{}, false
			}
			facts, err := VerifyContentAssertion(a.Compact, e)
			return facts, err == nil
		}
		predecessor, predecessorOK := verify(c.Predecessor)
		successor, successorOK := verify(c.Successor)
		if predecessorOK != (c.Expected.Predecessor == "valid") || successorOK != (c.Expected.Successor == "valid") {
			t.Errorf("%s artifact verdict mismatch", c.ID)
			continue
		}
		if c.Expected.Relation == "not_run" {
			continue
		}
		overridesOK := true
		for name, value := range c.Successor.FactsOverrides {
			switch name {
			case "verification":
				successor.Verification = AttestationVerification(99)
			case "trust":
				successor.Trust = Trust(99)
			case "digest":
				parsed, err := corpusFixedDigest(value)
				if err != nil {
					overridesOK = false
				} else {
					successor.Digest = parsed
				}
			default:
				overridesOK = false
			}
		}
		bounds := BoundsMaximum()
		relationOK := overridesOK && VerifyContentAssertionSuccessor(predecessor, successor, &bounds) == nil
		if relationOK != (c.Expected.Relation == "valid") {
			t.Errorf("%s relation=%t want=%s", c.ID, relationOK, c.Expected.Relation)
		}
	}
}

func TestContentAssertionIsRejectedByEveryLegacyDecoder(t *testing.T) {
	var cases []contentCorpusCase
	readContentCorpus(t, "assertion-structure-cases.json", &cases)
	compact := cases[0].Compact
	if _, err := DecodeGrant(compact, nil); err != ErrInvalid {
		t.Fatal("v1 grant accepted content assertion")
	}
	if _, err := DecodeProof(compact, nil); err != ErrInvalid {
		t.Fatal("v1 proof accepted content assertion")
	}
	if _, err := DecodeLocalLoopbackHTTPProof(compact, nil); err != ErrInvalid {
		t.Fatal("loopback accepted content assertion")
	}
	if _, err := DecodeAttestation(compact, nil); err != ErrInvalid {
		t.Fatal("role attestation accepted content assertion")
	}
	if _, err := (Profile{}).DecodeGrant(compact, nil); err != ErrInvalid {
		t.Fatal("v2 accepted content assertion")
	}
	if _, err := (Profile{}).DecodeProof(compact, nil); err != ErrInvalid {
		t.Fatal("v2 proof decoder accepted content assertion")
	}
	if _, err := (EcdsaProfile{}).DecodeGrant(compact, nil); err != ErrInvalid {
		t.Fatal("v3 accepted content assertion")
	}
	if _, err := (EcdsaProfile{}).DecodeProof(compact, nil); err != ErrInvalid {
		t.Fatal("v3 proof decoder accepted content assertion")
	}
	input := SigningInput{Kind: KindContentAssertion, Protected: []byte(`{}`), Payload: []byte(`{}`)}
	if _, err := AssembleCompact(input, make([]byte, 64), nil); err != ErrInvalid {
		t.Fatal("v1 generic assembler accepted content assertion kind")
	}
	if _, err := (Profile{}).AssembleCompact(input, make([]byte, 64), nil); err != ErrInvalid {
		t.Fatal("v2 generic assembler accepted content assertion kind")
	}
	if _, err := (EcdsaProfile{}).AssembleCompact(input, make([]byte, 64), nil); err != ErrInvalid {
		t.Fatal("v3 generic assembler accepted content assertion kind")
	}
}
