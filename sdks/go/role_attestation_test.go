package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const certifiedRoleAttestationIndexSHA256 = "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

func TestCertifiedRoleAttestationCorpusDrivesGoVerdicts(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "priv", "conformance", "attestation-profiles", "role-attestation", "v1")
	read := func(name string, into any) []byte {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if into != nil {
			if err := json.Unmarshal(bytes, into); err != nil {
				t.Fatal(err)
			}
		}
		return bytes
	}
	var index struct {
		Profile          string `json:"profile"`
		Revision         int    `json:"revision"`
		AttestationCases int    `json:"attestation_cases"`
		Files            []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	indexBytes := read("index.json", &index)
	indexDigest := sha256.Sum256(indexBytes)
	if hex.EncodeToString(indexDigest[:]) != certifiedRoleAttestationIndexSHA256 {
		t.Fatal("certified role-attestation index digest mismatch")
	}
	if index.Profile != "bap-role-attestation/1" || index.Revision != 1 || index.AttestationCases != 40 {
		t.Fatal("certified role-attestation index metadata mismatch")
	}
	if len(index.Files) != 2 || index.Files[0].Path != "profile.json" || index.Files[1].Path != "attestation-cases.json" {
		t.Fatal("certified role-attestation index file set mismatch")
	}
	for _, file := range index.Files {
		digest := sha256.Sum256(read(file.Path, nil))
		if actual := hex.EncodeToString(digest[:]); actual != file.SHA256 {
			t.Fatalf("%s sha256 = %s, want %s", file.Path, actual, file.SHA256)
		}
	}

	var profile struct {
		Attestor struct {
			KeyID       string `json:"key_id"`
			PublicKey   string `json:"public_key"`
			ValidFrom   int64  `json:"valid_from"`
			ValidBefore int64  `json:"valid_before"`
		} `json:"attestor"`
		Now     int64 `json:"now"`
		Subject struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"subject"`
	}
	read("profile.json", &profile)
	var attestorKey [32]byte
	if raw, err := Base64urlDecode(profile.Attestor.PublicKey); err != nil || len(raw) != 32 {
		t.Fatal("invalid corpus attestor public key")
	} else {
		copy(attestorKey[:], raw)
	}
	var subjectKey [32]byte
	if raw, err := Base64urlDecode(profile.Subject.PublicKey); err != nil || len(raw) != 32 {
		t.Fatal("invalid corpus subject public key")
	} else {
		copy(subjectKey[:], raw)
	}
	expected := ExpectedAttestation{
		Attestor: TrustedAttestor{
			KeyID:       profile.Attestor.KeyID,
			PublicKey:   attestorKey,
			ValidFrom:   profile.Attestor.ValidFrom,
			ValidBefore: profile.Attestor.ValidBefore,
		},
		SubjectKeyID:     profile.Subject.KeyID,
		SubjectPublicKey: subjectKey,
		Now:              profile.Now,
	}

	var cases []struct {
		ID                string         `json:"id"`
		Compact           string         `json:"compact"`
		Decode            bool           `json:"decode"`
		Verify            bool           `json:"verify"`
		V1Grant           bool           `json:"v1_grant"`
		ExpectedOverrides map[string]any `json:"expected_overrides"`
	}
	read("attestation-cases.json", &cases)
	if len(cases) != index.AttestationCases {
		t.Fatal("certified role-attestation case count mismatch")
	}
	for _, attestationCase := range cases {
		caseExpected := expected
		switch len(attestationCase.ExpectedOverrides) {
		case 0:
		case 1:
			for name, value := range attestationCase.ExpectedOverrides {
				switch name {
				case "now":
					now, ok := value.(float64)
					if !ok || now != float64(int64(now)) {
						t.Fatalf("%s has invalid now override", attestationCase.ID)
					}
					caseExpected.Now = int64(now)
				case "subject_key_id":
					keyID, ok := value.(string)
					if !ok {
						t.Fatalf("%s has invalid subject_key_id override", attestationCase.ID)
					}
					caseExpected.SubjectKeyID = keyID
				case "subject_public_key":
					overrideRoleAttestationKey(t, attestationCase.ID, value, &caseExpected.SubjectPublicKey)
				case "attestor_public_key":
					overrideRoleAttestationKey(t, attestationCase.ID, value, &caseExpected.Attestor.PublicKey)
				default:
					t.Fatalf("%s has unknown expected override %q", attestationCase.ID, name)
				}
			}
		case 2:
			// the single sanctioned two-key form: the same-material
			// self-attestation case overrides the whole subject binding
			keyID, hasKeyID := attestationCase.ExpectedOverrides["subject_key_id"]
			publicKey, hasPublicKey := attestationCase.ExpectedOverrides["subject_public_key"]
			if !hasKeyID || !hasPublicKey {
				t.Fatalf("%s has combined expected overrides", attestationCase.ID)
			}
			id, ok := keyID.(string)
			if !ok {
				t.Fatalf("%s has invalid subject_key_id override", attestationCase.ID)
			}
			caseExpected.SubjectKeyID = id
			overrideRoleAttestationKey(t, attestationCase.ID, publicKey, &caseExpected.SubjectPublicKey)
		default:
			t.Fatalf("%s has combined expected overrides", attestationCase.ID)
		}
		if _, err := DecodeAttestation(attestationCase.Compact, nil); (err == nil) != attestationCase.Decode {
			t.Fatalf("%s decode mismatch: %v", attestationCase.ID, err)
		}
		_, err := VerifyAttestation(attestationCase.Compact, caseExpected)
		if (err == nil) != attestationCase.Verify {
			t.Fatalf("%s verify mismatch: %v", attestationCase.ID, err)
		}
		if _, err := DecodeGrant(attestationCase.Compact, nil); (err == nil) != attestationCase.V1Grant {
			t.Fatalf("%s v1 grant decode mismatch: %v", attestationCase.ID, err)
		}
	}

	// facts shape: the valid corpus cases return the exact redacted facts
	facts, err := VerifyAttestation(cases[0].Compact, expected)
	if err != nil {
		t.Fatal(err)
	}
	wantFacts := AttestationFacts{
		AttestorKeyID:          profile.Attestor.KeyID,
		AttestorKeyFingerprint: jwkThumbprintOfKey(attestorKey[:]),
		SubjectKeyID:           profile.Subject.KeyID,
		SubjectKeyFingerprint:  jwkThumbprintOfKey(subjectKey[:]),
		Role:                   "issuer",
		Jti:                    "urn:example:attestation:ra-1",
		Nbf:                    1735689600,
		Exp:                    1735693200,
		Verification:           AttestationVerificationSignatureAndWindow,
		Trust:                  TrustNotEvaluated,
	}
	if facts != wantFacts {
		t.Fatalf("issuer-valid facts = %+v, want %+v", facts, wantFacts)
	}
	holderFacts, err := VerifyAttestation(cases[1].Compact, expected)
	if err != nil || holderFacts.Role != "holder" {
		t.Fatalf("holder-valid facts role = %q, %v", holderFacts.Role, err)
	}

	// producer/assembly over the corpus key material: a test-generated
	// attestor key signs; the library accepts only external signature bytes
	generatedPublic, generatedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var generatedKey [32]byte
	copy(generatedKey[:], generatedPublic)
	base := Attestation{
		AttestorKeyID: "attestor-generated-1",
		Jti:           "urn:example:attestation:generated-1",
		KeyID:         profile.Subject.KeyID,
		PublicKey:     subjectKey,
		Nbf:           profile.Attestor.ValidFrom,
		Exp:           profile.Attestor.ValidBefore,
	}
	generatedExpected := ExpectedAttestation{
		Attestor: TrustedAttestor{
			KeyID:       "attestor-generated-1",
			PublicKey:   generatedKey,
			ValidFrom:   profile.Attestor.ValidFrom,
			ValidBefore: profile.Attestor.ValidBefore,
		},
		SubjectKeyID:     profile.Subject.KeyID,
		SubjectPublicKey: subjectKey,
		Now:              profile.Now,
	}
	wantPayload := `{"exp":` + strconv.FormatInt(profile.Attestor.ValidBefore, 10) +
		`,"jti":"urn:example:attestation:generated-1","key_id":"` + profile.Subject.KeyID +
		`","nbf":` + strconv.FormatInt(profile.Attestor.ValidFrom, 10) +
		`,"public_key":"` + profile.Subject.PublicKey + `","role":"`
	for _, role := range []string{"issuer", "holder"} {
		produced := base
		produced.Role = role
		input, err := AttestationSigningInput(produced, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(input.Protected) != `{"alg":"EdDSA","kid":"attestor-generated-1","typ":"ba+role-attestation"}` {
			t.Fatalf("%s producer header = %s", role, input.Protected)
		}
		if string(input.Payload) != wantPayload+role+`","v":1}` {
			t.Fatalf("%s producer payload = %s", role, input.Payload)
		}
		signature := ed25519.Sign(generatedPrivate, signingInputMessage(input))
		assembled, err := AssembleAttestationCompact(input, signature, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAttestation(assembled, nil)
		if err != nil || decoded.Role != role || decoded.AttestorKeyID != "attestor-generated-1" ||
			decoded.Jti != "urn:example:attestation:generated-1" || decoded.KeyID != profile.Subject.KeyID ||
			decoded.PublicKey != subjectKey || decoded.Nbf != profile.Attestor.ValidFrom ||
			decoded.Exp != profile.Attestor.ValidBefore || decoded.Version != 1 ||
			decoded.Verification != DecodeVerificationNotEvaluated {
			t.Fatalf("%s decode of assembled attestation mismatch: %+v, %v", role, decoded, err)
		}
		if _, err := DecodeGrant(assembled, nil); err == nil {
			t.Fatalf("%s v1 grant decoder accepted attestation bytes", role)
		}
		producedFacts, err := VerifyAttestation(assembled, generatedExpected)
		if err != nil || producedFacts.Role != role || producedFacts.AttestorKeyFingerprint != jwkThumbprintOfKey(generatedKey[:]) {
			t.Fatalf("%s verify of assembled attestation mismatch: %+v, %v", role, producedFacts, err)
		}
	}
}

func overrideRoleAttestationKey(t *testing.T, id string, value any, into *[32]byte) {
	t.Helper()
	encoded, ok := value.(string)
	if !ok {
		t.Fatalf("%s has invalid public key override", id)
	}
	raw, err := Base64urlDecode(encoded)
	if err != nil || len(raw) != 32 {
		t.Fatalf("%s has invalid public key override", id)
	}
	copy(into[:], raw)
}

func TestRoleAttestationFailClosedProducerAndAssembly(t *testing.T) {
	t.Parallel()
	attestorPublic, attestorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var attestorKey [32]byte
	copy(attestorKey[:], attestorPublic)
	subjectPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var subjectKey [32]byte
	copy(subjectKey[:], subjectPublic)
	valid := Attestation{
		AttestorKeyID: "attestor-defect-1",
		Jti:           "urn:example:attestation:defect-1",
		KeyID:         "subject-defect-1",
		PublicKey:     subjectKey,
		Role:          "issuer",
		Nbf:           1000,
		Exp:           2000,
	}
	input, err := AttestationSigningInput(valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(attestorPrivate, signingInputMessage(input))
	assembled, err := AssembleAttestationCompact(input, signature, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := ExpectedAttestation{
		Attestor: TrustedAttestor{
			KeyID:       "attestor-defect-1",
			PublicKey:   attestorKey,
			ValidFrom:   1000,
			ValidBefore: 2000,
		},
		SubjectKeyID:     "subject-defect-1",
		SubjectPublicKey: subjectKey,
		Now:              1500,
	}
	if _, err := VerifyAttestation(assembled, expected); err != nil {
		t.Fatal(err)
	}

	// producer fail-closed matrix (the [32]byte key field makes a wrong key
	// width unrepresentable at the producer; that family lives in the payload
	// legs below and the certified corpus)
	roleOutside := valid
	roleOutside.Role = "admin"
	roleEmpty := valid
	roleEmpty.Role = ""
	emptyWindow := valid
	emptyWindow.Exp = valid.Nbf
	invertedWindow := valid
	invertedWindow.Nbf = valid.Exp + 1
	emptyAttestor := valid
	emptyAttestor.AttestorKeyID = ""
	emptySubject := valid
	emptySubject.KeyID = ""
	emptyJti := valid
	emptyJti.Jti = ""
	for _, c := range []struct {
		name string
		att  Attestation
	}{
		{"role outside closed set", roleOutside},
		{"role empty", roleEmpty},
		{"nbf equals exp", emptyWindow},
		{"nbf after exp", invertedWindow},
		{"empty attestor key id", emptyAttestor},
		{"empty subject key id", emptySubject},
		{"empty jti", emptyJti},
	} {
		if _, err := AttestationSigningInput(c.att, nil); err == nil {
			t.Fatalf("producer accepted %s", c.name)
		}
	}

	// assembly defects: the revalidating assembler rejects every malformed
	// payload byte form and both wrong signature widths
	subjectKeyB64 := Base64urlEncode(subjectKey[:])
	narrowKeyB64 := Base64urlEncode(subjectKey[:31])
	for _, c := range []struct {
		name    string
		payload string
	}{
		{"float nbf date", `{"exp":2000,"jti":"urn:example:attestation:defect-1","key_id":"subject-defect-1","nbf":1000.5,"public_key":"` + subjectKeyB64 + `","role":"issuer","v":1}`},
		{"float exp date", `{"exp":2000.5,"jti":"urn:example:attestation:defect-1","key_id":"subject-defect-1","nbf":1000,"public_key":"` + subjectKeyB64 + `","role":"issuer","v":1}`},
		{"wrong key width", `{"exp":2000,"jti":"urn:example:attestation:defect-1","key_id":"subject-defect-1","nbf":1000,"public_key":"` + narrowKeyB64 + `","role":"issuer","v":1}`},
		{"non-canonical payload order", `{"v":1,"exp":2000,"jti":"urn:example:attestation:defect-1","key_id":"subject-defect-1","nbf":1000,"public_key":"` + subjectKeyB64 + `","role":"issuer"}`},
		{"duplicate member", `{"exp":2000,"jti":"urn:example:attestation:defect-1","key_id":"subject-defect-1","nbf":1000,"public_key":"` + subjectKeyB64 + `","role":"issuer","role":"issuer","v":1}`},
	} {
		defect := SigningInput{Kind: KindRoleAttestation, Protected: input.Protected, Payload: []byte(c.payload)}
		if _, err := AssembleAttestationCompact(defect, signature, nil); err == nil {
			t.Fatalf("assembler accepted %s", c.name)
		}
	}
	wideSignature := append(append([]byte(nil), signature...), 0)
	for _, c := range []struct {
		name      string
		signature []byte
	}{
		{"63-byte signature", signature[:63]},
		{"65-byte signature", wideSignature},
	} {
		if _, err := AssembleAttestationCompact(input, c.signature, nil); err == nil {
			t.Fatalf("assembler accepted %s", c.name)
		}
	}
	wrongKind := SigningInput{Kind: KindGrant, Protected: input.Protected, Payload: input.Payload}
	if _, err := AssembleAttestationCompact(wrongKind, signature, nil); err == nil {
		t.Fatal("attestation assembler accepted a grant kind")
	}
	if _, err := AssembleCompact(input, signature, nil); err == nil {
		t.Fatal("standard assembler accepted an attestation kind")
	}

	// self-attestation rejection in all three material forms
	selfSame := valid
	selfSame.KeyID = valid.AttestorKeyID
	selfSame.PublicKey = attestorKey
	sameKeyID := valid
	sameKeyID.KeyID = valid.AttestorKeyID
	sameKey := valid
	sameKey.PublicKey = attestorKey
	for _, c := range []struct {
		name             string
		att              Attestation
		subjectKeyID     string
		subjectPublicKey [32]byte
	}{
		{"identical key and key id", selfSame, selfSame.AttestorKeyID, attestorKey},
		{"same key id, different key", sameKeyID, sameKeyID.AttestorKeyID, subjectKey},
		{"same key, different key id", sameKey, sameKey.KeyID, attestorKey},
	} {
		selfInput, err := AttestationSigningInput(c.att, nil)
		if err != nil {
			t.Fatal(err)
		}
		selfSignature := ed25519.Sign(attestorPrivate, signingInputMessage(selfInput))
		selfCompact, err := AssembleAttestationCompact(selfInput, selfSignature, nil)
		if err != nil {
			t.Fatal(err)
		}
		selfExpected := expected
		selfExpected.SubjectKeyID = c.subjectKeyID
		selfExpected.SubjectPublicKey = c.subjectPublicKey
		if _, err := VerifyAttestation(selfCompact, selfExpected); err == nil {
			t.Fatalf("verifier accepted self-attestation with %s", c.name)
		}
	}

	// attestor-window containment and the unbounded representation
	outliving := valid
	outliving.Exp = 2001
	premature := valid
	premature.Nbf = 999
	farFuture := valid
	farFuture.Exp = 999999999999
	for _, c := range []struct {
		name      string
		att       Attestation
		unbounded bool
		want      bool
	}{
		{"exp outliving the bounded attestor window", outliving, false, false},
		{"nbf before the attestor window", premature, false, false},
		{"exp at the attestor valid_before is containment", valid, false, true},
		{"exp far beyond an unbounded attestor window", farFuture, true, true},
	} {
		windowInput, err := AttestationSigningInput(c.att, nil)
		if err != nil {
			t.Fatal(err)
		}
		windowSignature := ed25519.Sign(attestorPrivate, signingInputMessage(windowInput))
		windowCompact, err := AssembleAttestationCompact(windowInput, windowSignature, nil)
		if err != nil {
			t.Fatal(err)
		}
		windowExpected := expected
		windowExpected.Attestor.ValidBeforeUnbounded = c.unbounded
		_, err = VerifyAttestation(windowCompact, windowExpected)
		if (err == nil) != c.want {
			t.Fatalf("%s: verify = %v", c.name, err)
		}
	}

	// the caller's now window [nbf, exp)
	for _, c := range []struct {
		name string
		now  int64
		want bool
	}{
		{"now before the window", 999, false},
		{"now at nbf", 1000, true},
		{"now inside the window", 1999, true},
		{"now at exp", 2000, false},
	} {
		nowExpected := expected
		nowExpected.Now = c.now
		if _, err := VerifyAttestation(assembled, nowExpected); (err == nil) != c.want {
			t.Fatalf("%s: verify = %v", c.name, err)
		}
	}
}
