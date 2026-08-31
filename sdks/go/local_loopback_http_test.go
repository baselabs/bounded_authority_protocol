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

const certifiedLocalLoopbackIndexSHA256 = "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4"

func TestLocalLoopbackHTTPURIProfileAcceptsOnlyExactLoopbackLiterals(t *testing.T) {
	valid := []struct{ in, want string }{
		{"HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"},
		{"http://127.0.0.1:4000/invoke", "http://127.0.0.1:4000/invoke"},
		{"HTTP://[::1]:80/invoke", "http://[::1]/invoke"},
		{"http://127.0.0.1:443/invoke", "http://127.0.0.1:443/invoke"},
	}

	for _, c := range valid {
		got, err := LocalLoopbackHTTPUriNormalize(c.in, nil)
		if err != nil || got != c.want {
			t.Fatalf("LocalLoopbackHTTPUriNormalize(%s) = %s, %v; want %s", c.in, got, err, c.want)
		}
	}

	for _, invalid := range []string{
		"https://127.0.0.1/invoke",
		"http://localhost/invoke",
		"http://127.0.0.2/invoke",
		"http://127.1/invoke",
		"http://2130706433/invoke",
		"http://[::ffff:127.0.0.1]/invoke",
		"http://[::1%25lo0]/invoke",
		"http://user@127.0.0.1/invoke",
		"http://127.0.0.1/invoke?query=true",
		"http://127.0.0.1/invoke#fragment",
		"http://127.0.0.1/[]",
	} {
		if got, err := LocalLoopbackHTTPUriNormalize(invalid, nil); err == nil {
			t.Fatalf("LocalLoopbackHTTPUriNormalize(%s) = %s, want ErrInvalid", invalid, got)
		}
	}
}

func TestCertifiedLocalLoopbackCorpusDrivesGoVerdicts(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "priv", "conformance", "application-profiles", "local-loopback-http", "v1")
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
		Profile    string `json:"profile"`
		Revision   int    `json:"revision"`
		ProofCases int    `json:"proof_cases"`
		URICases   int    `json:"uri_cases"`
		Files      []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	indexBytes := read("index.json", &index)
	indexDigest := sha256.Sum256(indexBytes)
	if hex.EncodeToString(indexDigest[:]) != certifiedLocalLoopbackIndexSHA256 {
		t.Fatal("certified local-loopback index digest mismatch")
	}
	if index.Profile != "bap-application-proof/local-loopback-http/1" || index.Revision != 1 || index.ProofCases != 8 || index.URICases != 36 {
		t.Fatal("certified local-loopback index metadata mismatch")
	}
	if len(index.Files) != 2 || index.Files[0].Path != "profile.json" || index.Files[1].Path != "proof-cases.json" {
		t.Fatal("certified local-loopback index file set mismatch")
	}
	for _, file := range index.Files {
		digest := sha256.Sum256(read(file.Path, nil))
		if actual := hex.EncodeToString(digest[:]); actual != file.SHA256 {
			t.Fatalf("%s sha256 = %s, want %s", file.Path, actual, file.SHA256)
		}
	}

	var profile struct {
		GrantCompact    string `json:"grant_compact"`
		HolderPublicKey string `json:"holder_public_key"`
		Issuer          struct {
			Audience  string `json:"audience"`
			Issuer    string `json:"issuer"`
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"issuer"`
		Request struct {
			Method         string `json:"method"`
			InvocationID   string `json:"invocation_id"`
			Operation      string `json:"operation"`
			EvaluationTime int64  `json:"evaluation_time"`
			ClockSkew      int64  `json:"clock_skew"`
			ProofMaxAge    int64  `json:"proof_max_age"`
		} `json:"request"`
		Proofs struct {
			IPv4 struct {
				TargetURI string `json:"target_uri"`
				Nonce     string `json:"nonce"`
				Compact   string `json:"compact"`
				ProofID   string `json:"proof_id"`
			} `json:"ipv4"`
			IPv6 struct {
				TargetURI string `json:"target_uri"`
				Nonce     string `json:"nonce"`
				Compact   string `json:"compact"`
				ProofID   string `json:"proof_id"`
			} `json:"ipv6"`
		} `json:"proofs"`
		URICases []struct {
			ID         string `json:"id"`
			Input      string `json:"input"`
			Valid      bool   `json:"valid"`
			Normalized string `json:"normalized"`
		} `json:"uri_cases"`
	}
	read("profile.json", &profile)
	if len(profile.URICases) != index.URICases {
		t.Fatal("certified local-loopback URI case count mismatch")
	}
	for _, uriCase := range profile.URICases {
		actual, err := LocalLoopbackHTTPUriNormalize(uriCase.Input, nil)
		if (err == nil) != uriCase.Valid {
			t.Fatalf("%s validity mismatch: %v", uriCase.ID, err)
		}
		if err == nil && actual != uriCase.Normalized {
			t.Fatalf("%s normalized = %s, want %s", uriCase.ID, actual, uriCase.Normalized)
		}
	}
	issuerKey, err := Base64urlDecode(profile.Issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := Base64urlDecode(profile.HolderPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(profile.Proofs.IPv4.Compact, ".")
	if len(segments) != 3 {
		t.Fatal("invalid corpus compact")
	}
	protected, err := Base64urlDecode(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Base64urlDecode(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := Base64urlDecode(segments[2])
	if err != nil {
		t.Fatal(err)
	}
	proof := Proof{
		ProofID:         profile.Proofs.IPv4.ProofID,
		HolderPublicKey: holderKey,
		InvocationID:    profile.Request.InvocationID,
		Operation:       profile.Request.Operation,
		Method:          profile.Request.Method,
		TargetURI:       profile.Proofs.IPv4.TargetURI,
		IssuedAt:        profile.Request.EvaluationTime,
		GrantCompact:    profile.GrantCompact,
		CastArguments:   Obj{{Key: "record_id", Val: Str("record-1")}},
		HasNonce:        true,
		Nonce:           profile.Proofs.IPv4.Nonce,
	}
	produced, err := LocalLoopbackHTTPProofSigningInput(proof, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(produced.Protected) != string(protected) || string(produced.Payload) != string(payload) {
		t.Fatal("producer bytes differ from certified corpus")
	}
	assembled, err := AssembleLocalLoopbackHTTPCompact(produced, signature, nil)
	if err != nil || assembled != profile.Proofs.IPv4.Compact {
		t.Fatalf("assembly mismatch: %v", err)
	}
	if _, err := AssembleCompact(produced, signature, nil); err == nil {
		t.Fatal("standard assembler accepted loopback kind")
	}
	wrongKind := produced
	wrongKind.Kind = KindGrant
	if _, err := AssembleLocalLoopbackHTTPCompact(wrongKind, signature, nil); err == nil {
		t.Fatal("local assembler accepted a non-local kind")
	}
	nonCanonical := proof
	nonCanonical.TargetURI = "HTTP://127.0.0.1:4000/invoke"
	if _, err := LocalLoopbackHTTPProofSigningInput(nonCanonical, nil); err == nil {
		t.Fatal("local producer accepted a noncanonical target URI")
	}
	malformedGrant := proof
	malformedGrant.GrantCompact = "not-a-compact"
	if _, err := LocalLoopbackHTTPProofSigningInput(malformedGrant, nil); err == nil {
		t.Fatal("local producer hashed a malformed grant compact")
	}
	standardProof := proof
	standardProof.TargetURI = "https://resource.example.test/invoke"
	standardProof.GrantCompact = "not-a-compact"
	if _, err := ProofSigningInput(standardProof, nil); err != nil {
		t.Fatal("local profile changed the standard producer's bounded opaque grant behavior")
	}
	standardProof.GrantCompact = proof.GrantCompact
	standardInput, err := ProofSigningInput(standardProof, nil)
	if err != nil {
		t.Fatal(err)
	}
	standardInput.Payload = []byte("{}")
	if _, err := AssembleCompact(standardInput, signature, nil); err != nil {
		t.Fatal("standard assembler no longer preserves its header-plus-JSON payload contract")
	}
	if _, err := ProofSigningInput(proof, nil); err == nil {
		t.Fatal("standard producer accepted loopback HTTP target")
	}
	expected := ExpectedRequest{
		TrustedIssuer:  TrustedIssuer{KeyID: profile.Issuer.KeyID, PublicKey: issuerKey},
		Issuer:         profile.Issuer.Issuer,
		Audience:       profile.Issuer.Audience,
		EvaluationTime: profile.Request.EvaluationTime,
		ClockSkew:      profile.Request.ClockSkew,
		Method:         profile.Request.Method,
		TargetURI:      profile.Proofs.IPv4.TargetURI,
		InvocationID:   profile.Request.InvocationID,
		Operation:      profile.Request.Operation,
		CastArguments:  Obj{{Key: "record_id", Val: Str("record-1")}},
		ProofMaxAge:    profile.Request.ProofMaxAge,
		Nonce:          NonceRequired(profile.Proofs.IPv4.Nonce),
	}
	ipv6Proof := proof
	ipv6Proof.ProofID = profile.Proofs.IPv6.ProofID
	ipv6Proof.TargetURI = profile.Proofs.IPv6.TargetURI
	ipv6Proof.Nonce = profile.Proofs.IPv6.Nonce
	ipv6Produced, err := LocalLoopbackHTTPProofSigningInput(ipv6Proof, nil)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Segments := strings.Split(profile.Proofs.IPv6.Compact, ".")
	if len(ipv6Segments) != 3 || string(ipv6Produced.Protected) != mustDecodeLocal(t, ipv6Segments[0]) || string(ipv6Produced.Payload) != mustDecodeLocal(t, ipv6Segments[1]) {
		t.Fatal("IPv6 producer bytes differ from certified corpus")
	}
	ipv6Assembled, err := AssembleLocalLoopbackHTTPCompact(ipv6Produced, []byte(mustDecodeLocal(t, ipv6Segments[2])), nil)
	if err != nil || ipv6Assembled != profile.Proofs.IPv6.Compact {
		t.Fatalf("IPv6 assembly mismatch: %v", err)
	}
	if _, err := DecodeLocalLoopbackHTTPProof(ipv6Assembled, nil); err != nil {
		t.Fatal(err)
	}
	ipv6Expected := expected
	ipv6Expected.TargetURI = profile.Proofs.IPv6.TargetURI
	ipv6Expected.Nonce = NonceRequired(profile.Proofs.IPv6.Nonce)
	if _, err := CheckLocalLoopbackHTTPEnvelope(
		Credentials{Grant: profile.GrantCompact, Proof: ipv6Assembled}, ipv6Expected,
	); err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID                string            `json:"id"`
		Compact           string            `json:"compact"`
		DecodeLocal       bool              `json:"decode_local"`
		DecodeStandard    bool              `json:"decode_standard"`
		EnvelopeLocal     bool              `json:"envelope_local"`
		ExpectedOverrides map[string]string `json:"expected_overrides"`
	}
	read("proof-cases.json", &cases)
	if len(cases) != index.ProofCases {
		t.Fatal("certified local-loopback proof case count mismatch")
	}
	for _, proofCase := range cases {
		caseExpected := expected
		trustedIssuerPublicKey := ""
		invocationID := ""
		for name, value := range proofCase.ExpectedOverrides {
			switch name {
			case "trusted_issuer_public_key":
				trustedIssuerPublicKey = value
			case "invocation_id":
				invocationID = value
			default:
				t.Fatalf("%s has unknown expected override %q", proofCase.ID, name)
			}
		}
		if trustedIssuerPublicKey != "" && invocationID != "" {
			t.Fatalf("%s has ambiguous expected overrides", proofCase.ID)
		}
		if trustedIssuerPublicKey != "" {
			publicKey, err := Base64urlDecode(trustedIssuerPublicKey)
			if err != nil || len(publicKey) != len(caseExpected.TrustedIssuer.PublicKey) {
				t.Fatalf("%s has invalid trusted issuer override", proofCase.ID)
			}
			caseExpected.TrustedIssuer.PublicKey = append([]byte(nil), expected.TrustedIssuer.PublicKey...)
			copy(caseExpected.TrustedIssuer.PublicKey, publicKey)
		}
		if invocationID != "" {
			caseExpected.InvocationID = invocationID
		}
		if _, err := DecodeLocalLoopbackHTTPProof(proofCase.Compact, nil); (err == nil) != proofCase.DecodeLocal {
			t.Fatalf("%s local decode mismatch: %v", proofCase.ID, err)
		}
		if _, err := DecodeProof(proofCase.Compact, nil); (err == nil) != proofCase.DecodeStandard {
			t.Fatalf("%s standard decode mismatch: %v", proofCase.ID, err)
		}
		_, err := CheckLocalLoopbackHTTPEnvelope(
			Credentials{Grant: profile.GrantCompact, Proof: proofCase.Compact}, caseExpected,
		)
		if (err == nil) != proofCase.EnvelopeLocal {
			t.Fatalf("%s envelope mismatch: %v", proofCase.ID, err)
		}
	}
	wrongNonce := expected
	wrongNonce.Nonce = NonceRequired("wrong-nonce")
	if _, err := CheckLocalLoopbackHTTPEnvelope(
		Credentials{Grant: profile.GrantCompact, Proof: profile.Proofs.IPv4.Compact}, wrongNonce,
	); err == nil {
		t.Fatal("valid local proof accepted under the wrong expected nonce")
	}
	wrongTrust := expected
	wrongTrust.TrustedIssuer.PublicKey = append([]byte(nil), expected.TrustedIssuer.PublicKey...)
	wrongTrust.TrustedIssuer.PublicKey[0] ^= 1
	if _, err := CheckLocalLoopbackHTTPEnvelope(
		Credentials{Grant: profile.GrantCompact, Proof: profile.Proofs.IPv4.Compact}, wrongTrust,
	); err == nil {
		t.Fatal("valid local proof accepted under the wrong issuer key")
	}
	wrongBinding := expected
	wrongBinding.InvocationID = "550e8400-e29b-41d4-a716-446655440001"
	if _, err := CheckLocalLoopbackHTTPEnvelope(
		Credentials{Grant: profile.GrantCompact, Proof: profile.Proofs.IPv4.Compact}, wrongBinding,
	); err == nil {
		t.Fatal("valid local proof accepted under the wrong invocation binding")
	}
}

func mustDecodeLocal(t *testing.T, value string) string {
	t.Helper()
	decoded, err := Base64urlDecode(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}
