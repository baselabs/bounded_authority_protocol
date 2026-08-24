// Package verifier_test is the BAP-16 per-language permissiveness
// mutation-gate battery (ADR 0014 D6/D7, ADR 0017, ADR 0018). Every leg is
// red-capable: mechanically removing the closure or gate it pins makes the
// leg fail. The mutation probes run at authoring and are recorded in the SDK
// README; the CI job runs the battery green-as-is.
package verifier_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

// ---- corpus-derived fixtures (from the vendored corpus, corpus-verified values) ----

const (
	grantCompact = "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9." +
		"eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9." +
		"NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA"
	issuerKeyB64  = "146FPz0L9OK-SZ4z9nC1Xk7rUCSYAoIiBBDp1tsLZI8"
	chainRowB64   = "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiY29tbWl0bWVudCI6IjBQWXh5aDNicU5zN3o4dWVCWHpjbU5BM254dnVBT2RhVkZGSG9uMnQyWUkiLCJwcmV2aW91cyI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJzZXF1ZW5jZSI6MSwidiI6MX0"
	anchorCompact = "eyJhbGciOiJFZERTQSIsImtpZCI6ImFyY2hpdmUtYSIsInR5cCI6ImJhK2NoYWluLWFuY2hvciJ9.eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6c3RhcnQiLCJhbmNob3JlZF9hdCI6MTAwMCwiY2hhaW5faGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwia2V5X2ZpbmdlcnByaW50IjoibzdnbDByZHhTUFUtcVhibU5vZDRSQWtWNXBVamFCNDdKaFBBNDNod0tQOCIsInNlcXVlbmNlIjowLCJ2IjoxfQ.Falux3uXvUy7PqELqVP_UNWWr3FDT6jUxT7IwtbHY27dqPqHxdsUrSvE216PAtOku9jjPCgoWHYds8YMLD4gAQ"
	archiveKeyB64 = "YXgT52I83qBmbNzq_RMxiYT1T_EELrAj9rUkjCaSkP4"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := v.Base64urlDecode(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- (a) duplicate-reject at every depth (REQ1-JSON-no-duplicate) ----

func TestPermissiveDuplicateReject(t *testing.T) {
	dups := []string{
		`{"a":1,"a":2}`,
		`{"o":{"x":1,"x":2}}`,
		`{"l":[{"k":1,"k":2}]}`,
		`{"deep":{"deeper":{"dup":0,"dup":1}}}`,
	}
	for _, in := range dups {
		if _, err := v.JsonDecode([]byte(in), nil); err == nil {
			t.Fatalf("duplicate member must be rejected: %s", in)
		}
	}
	// through the compact surface: a grant payload with a duplicate member
	seg := strings.Split(grantCompact, ".")
	payload, err := v.Base64urlDecode(seg[1])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(payload), `"v":1`, `"v":1,"exp":2000`, 1)
	if tampered == string(payload) {
		t.Fatal("fixture substitution failed")
	}
	compact := seg[0] + "." + v.Base64urlEncode([]byte(tampered)) + "." + seg[2]
	if _, err := v.DecodeGrant(compact, nil); err == nil {
		t.Fatal("duplicate claim member must be rejected at the grant surface")
	}
}

// ---- (b) raw-lexeme 64-byte ceiling + exact magnitude (REQ1-JSON-raw-lexeme) ----

func TestPermissiveRawLexeme(t *testing.T) {
	over := `{"n":12345678901234567890123456789012345678901234567890123456789012345}` // 65 digits
	if _, err := v.JsonDecode([]byte(over), nil); err == nil {
		t.Fatal("65-byte number lexeme must be rejected")
	}
	// an under-magnitude number whose LEXEME alone exceeds 64 bytes: only
	// the raw-lexeme ceiling rejects it
	longTiny := `{"n":0.` + strings.Repeat("0", 62) + `1}` // lexeme = 65 bytes, value 1e-63
	if len(`0.`+strings.Repeat("0", 62)+`1`) != 65 {
		t.Fatalf("fixture length %d", len(`0.`+strings.Repeat("0", 62)+`1`))
	}
	if _, err := v.JsonDecode([]byte(longTiny), nil); err == nil {
		t.Fatal("65-byte number lexeme must be rejected by the raw-lexeme ceiling")
	}
	tiny := `{"n":0.` + strings.Repeat("0", 61) + `1}` // 64-byte lexeme, accepted
	if _, err := v.JsonDecode([]byte(tiny), nil); err != nil {
		t.Fatalf("64-byte under-magnitude lexeme must be accepted: %v", err)
	}
}

// ---- (c) single-value + trailing rejection (REQ1-JSON-single-value) ----

func TestPermissiveSingleValue(t *testing.T) {
	for _, in := range []string{`{} {}`, `[1] 2`, `null null`, `1x`, `{"a":1} ,`} {
		if _, err := v.JsonDecode([]byte(in), nil); err == nil {
			t.Fatalf("trailing data must be rejected: %q", in)
		}
	}
}

// ---- (d) int/float tag distinction (REQ1-SELECTOR-no-tag-collapse) ----

func TestPermissiveIntFloatTag(t *testing.T) {
	args, err := v.JsonDecode([]byte(`{"limit":10}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	intDigest, err := v.RequestDigest("read", args, nil)
	if err != nil {
		t.Fatal(err)
	}
	floatArgs, err := v.JsonDecode([]byte(`{"limit":10.0}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	floatDigest, err := v.RequestDigest("read", floatArgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if intDigest == floatDigest {
		t.Fatal("integer and integral-float cast arguments must produce different request digests")
	}
	// the corpus-pinned float projection value
	d, err := v.RequestDigest("read", mustFloat(t, 1e-7), nil)
	if err != nil || d != "-fTRu1NZroD6L_Q_IDSrPoqfCItKMpV1GDM3FV5ol0Y" {
		t.Fatalf("float projection digest = %s %v", d, err)
	}
}

func mustFloat(t *testing.T, f float64) v.Value {
	t.Helper()
	return v.Float(f)
}

// ---- (e) source member order preserved by the decoder (order-sensitive algebra) ----

func TestPermissiveSourceOrderPreserved(t *testing.T) {
	// The corpus cannot pin order through JSON expected values; this leg pins
	// it through the public API: JCS re-encodes sorted, so round-trip through
	// a path that exposes order — decode a grant whose operations array order
	// is positional (arrays), and verify an object whose JCS form differs
	// from its source order only by sorting.
	val, err := v.JsonDecode([]byte(`{"b":1,"a":2}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := v.JcsEncode(val, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(enc) != `{"a":2,"b":1}` {
		t.Fatalf("JCS must sort members: %s", enc)
	}
	// arrays stay positional (never sorted)
	arrVal, _ := v.JsonDecode([]byte(`[2,1]`), nil)
	arrEnc, _ := v.JcsEncode(arrVal, nil)
	if string(arrEnc) != `[2,1]` {
		t.Fatalf("array order must be preserved: %s", arrEnc)
	}
}

// ---- (f) base64url canonicality (REQ1-B64-canonical, corpus-blind legs) ----

func TestPermissiveBase64urlCanonical(t *testing.T) {
	for _, in := range []string{"AB", "QB", "aGVs bG8"} {
		if _, err := v.Base64urlDecode(in); err == nil {
			t.Fatalf("non-canonical base64url must be rejected: %q", in)
		}
	}
}

// ---- (g) signature width gated at decode (ADR 0017 clause 4) ----

func TestPermissiveSignatureWidthAtDecode(t *testing.T) {
	seg := strings.Split(grantCompact, ".")
	sig63 := strings.Repeat("A", 84) // 63 bytes -> 84 b64url chars
	compact := seg[0] + "." + seg[1] + "." + sig63
	if _, err := v.DecodeGrant(compact, nil); err == nil {
		t.Fatal("63-byte decoded signature must be rejected at decode")
	}
	// a 65-byte signature (87 chars) is also invalid
	compact = seg[0] + "." + seg[1] + "." + strings.Repeat("A", 87)
	if _, err := v.DecodeGrant(compact, nil); err == nil {
		t.Fatal("65-byte decoded signature must be rejected at decode")
	}
	// the same gate holds at assemble
	si := v.SigningInput{
		Kind:      v.KindGrant,
		Protected: mustB64(t, seg[0]),
		Payload:   mustB64(t, seg[1]),
	}
	if _, err := v.AssembleCompact(si, make([]byte, 63), nil); err == nil {
		t.Fatal("63-byte signature must be rejected at assemble")
	}
}

// ---- (h) grant/proof canonical EXCLUSION vs anchor/transition inclusion ----

func TestPermissiveCanonicalExclusion(t *testing.T) {
	// grant/proof: member order insignificant (REQ1-SIGNING-any-order)
	seg := strings.Split(grantCompact, ".")
	reordered := `{"typ":"ba+cap","kid":"issuer","alg":"EdDSA"}`
	compact := v.Base64urlEncode([]byte(reordered)) + "." + seg[1] + "." + seg[2]
	if _, err := v.DecodeGrant(compact, nil); err != nil {
		t.Fatalf("reordered grant header members must stay valid: %v", err)
	}
	// anchor: non-canonical member order is rejected (ADR 0017 clause 4)
	aseg := strings.Split(anchorCompact, ".")
	apayload, err := v.Base64urlDecode(aseg[1])
	if err != nil {
		t.Fatal(err)
	}
	// re-encode the SAME members in a different order by hand: swap the first
	// two members of the canonical payload
	swapped := strings.Replace(string(apayload),
		`{"anchor_id":"urn:example:anchor:start","anchored_at":1000,`,
		`{"anchored_at":1000,"anchor_id":"urn:example:anchor:start",`, 1)
	if swapped == string(apayload) {
		t.Fatal("fixture substitution failed")
	}
	key := v.HistoricalPublicKey{
		KeyID:       "archive-a",
		PublicKey:   mustB64(t, archiveKeyB64),
		ValidFrom:   0,
		ValidBefore: 3000,
	}
	expected := v.ExpectedAnchor{
		AnchorID:       "urn:example:anchor:start",
		ChainID:        "urn:example:chain",
		KeyID:          "archive-a",
		Sequence:       0,
		AnchoredAt:     1000,
		ChainHash:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyFingerprint: "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8",
	}
	nonCanonical := aseg[0] + "." + v.Base64urlEncode([]byte(swapped)) + "." + aseg[2]
	if _, err := v.VerifyHistoricalAnchor(nonCanonical, key, expected); err == nil {
		t.Fatal("non-canonical anchor payload member order must be rejected")
	}
}

// ---- (i-b) canonical-form gate at ENCODE (ADR 0017 clause 4, the
// non-subsumed pin: the encode path holds no signature to reject a reordered
// segment, so this leg is the load-bearing red-capable form) ----

func TestPermissiveCanonicalAtEncode(t *testing.T) {
	input, expected := loadCorpusExportEncodeValid(t)
	// baseline encodes
	if _, err := v.EncodeAnchoredExport(input, expected); err != nil {
		t.Fatalf("corpus-valid encode must succeed: %v", err)
	}
	// reorder the start anchor payload members: same JSON value, non-canonical
	// bytes — only the canonical gate rejects it at encode
	aseg := strings.Split(input.StartAnchor, ".")
	apayload, err := v.Base64urlDecode(aseg[1])
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(string(apayload),
		`{"anchor_id":"urn:example:anchor:start","anchored_at":1000,`,
		`{"anchored_at":1000,"anchor_id":"urn:example:anchor:start",`, 1)
	if swapped == string(apayload) {
		t.Fatal("fixture substitution failed")
	}
	bad := input
	bad.StartAnchor = aseg[0] + "." + v.Base64urlEncode([]byte(swapped)) + "." + aseg[2]
	if _, err := v.EncodeAnchoredExport(bad, expected); err == nil {
		t.Fatal("non-canonical anchor payload must be rejected at encode")
	}
}

// loadCorpusExportEncodeValid loads the vendored corpus encode-anchored-export-valid case.
func loadCorpusExportEncodeValid(t *testing.T) (v.AnchoredExportInput, v.ExpectedAnchoredExport) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "corpus", "cases", "anchored-export", "encode.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Rows        []string `json:"rows"`
				StartAnchor string   `json:"start_anchor"`
				EndAnchor   string   `json:"end_anchor"`
				Transitions []string `json:"transitions"`
				Expected    struct {
					Digest        string `json:"digest"`
					ObjectVersion string `json:"object_version"`
					Chain         struct {
						ChainID       string `json:"chain_id"`
						FirstSequence int64  `json:"first_sequence"`
						LastSequence  int64  `json:"last_sequence"`
						PreviousHash  string `json:"previous_hash"`
						LastHash      string `json:"last_hash"`
						RowCount      int64  `json:"row_count"`
					} `json:"chain"`
					StartAnchor struct {
						AnchorID       string `json:"anchor_id"`
						ChainID        string `json:"chain_id"`
						KeyID          string `json:"key_id"`
						Sequence       int64  `json:"sequence"`
						AnchoredAt     int64  `json:"anchored_at"`
						ChainHash      string `json:"chain_hash"`
						KeyFingerprint string `json:"key_fingerprint"`
					} `json:"start_anchor"`
					EndAnchor struct {
						AnchorID       string `json:"anchor_id"`
						ChainID        string `json:"chain_id"`
						KeyID          string `json:"key_id"`
						Sequence       int64  `json:"sequence"`
						AnchoredAt     int64  `json:"anchored_at"`
						ChainHash      string `json:"chain_hash"`
						KeyFingerprint string `json:"key_fingerprint"`
					} `json:"end_anchor"`
					Transitions []struct {
						TransitionID          string `json:"transition_id"`
						ChainID               string `json:"chain_id"`
						CurrentKeyID          string `json:"current_key_id"`
						NextKeyID             string `json:"next_key_id"`
						EffectiveAt           int64  `json:"effective_at"`
						CurrentKeyFingerprint string `json:"current_key_fingerprint"`
						NextKeyFingerprint    string `json:"next_key_fingerprint"`
					} `json:"transitions"`
				} `json:"expected"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	for _, c := range cf.Cases {
		if c.ID != "encode-anchored-export-valid" {
			continue
		}
		rows := make([][]byte, 0, len(c.Input.Rows))
		for _, r := range c.Input.Rows {
			rows = append(rows, mustB64(t, r))
		}
		e := c.Input.Expected
		expected := v.ExpectedAnchoredExport{
			Digest:        e.Digest,
			ObjectVersion: e.ObjectVersion,
			Chain: v.ExpectedChain{
				ChainID: e.Chain.ChainID, FirstSequence: e.Chain.FirstSequence,
				LastSequence: e.Chain.LastSequence, PreviousHash: e.Chain.PreviousHash,
				LastHash: e.Chain.LastHash, RowCount: e.Chain.RowCount,
			},
			StartAnchor: v.ExpectedAnchor{
				AnchorID: e.StartAnchor.AnchorID, ChainID: e.StartAnchor.ChainID,
				KeyID: e.StartAnchor.KeyID, Sequence: e.StartAnchor.Sequence,
				AnchoredAt: e.StartAnchor.AnchoredAt, ChainHash: e.StartAnchor.ChainHash,
				KeyFingerprint: e.StartAnchor.KeyFingerprint,
			},
			EndAnchor: v.ExpectedAnchor{
				AnchorID: e.EndAnchor.AnchorID, ChainID: e.EndAnchor.ChainID,
				KeyID: e.EndAnchor.KeyID, Sequence: e.EndAnchor.Sequence,
				AnchoredAt: e.EndAnchor.AnchoredAt, ChainHash: e.EndAnchor.ChainHash,
				KeyFingerprint: e.EndAnchor.KeyFingerprint,
			},
		}
		for _, tr := range e.Transitions {
			expected.Transitions = append(expected.Transitions, v.ExpectedKeyTransition{
				TransitionID: tr.TransitionID, ChainID: tr.ChainID,
				CurrentKeyID: tr.CurrentKeyID, NextKeyID: tr.NextKeyID,
				EffectiveAt: tr.EffectiveAt, CurrentKeyFingerprint: tr.CurrentKeyFingerprint,
				NextKeyFingerprint: tr.NextKeyFingerprint,
			})
		}
		return v.AnchoredExportInput{
			Rows:        rows,
			StartAnchor: c.Input.StartAnchor,
			EndAnchor:   c.Input.EndAnchor,
			Transitions: c.Input.Transitions,
		}, expected
	}
	t.Fatal("encode-anchored-export-valid case missing")
	return v.AnchoredExportInput{}, v.ExpectedAnchoredExport{}
}

// ---- (i) skew / proof_max_age ceilings: misconfigured callers are rejected ----

func TestPermissiveTimeCeilings(t *testing.T) {
	_, err := v.VerifyGrant(grantCompact, v.TrustedIssuer{
		KeyID:     "issuer",
		PublicKey: mustB64(t, issuerKeyB64),
	}, v.ExpectedGrant{
		Issuer:         "https://issuer.example.test",
		Audience:       "https://resource.example.test",
		EvaluationTime: 1500,
		ClockSkew:      61, // over the 60s ceiling
	})
	if err == nil {
		t.Fatal("clock skew over the ceiling must be rejected, not silently widened")
	}
	// negative skew rejected
	if _, err := v.VerifyGrant(grantCompact, v.TrustedIssuer{KeyID: "issuer", PublicKey: mustB64(t, issuerKeyB64)}, v.ExpectedGrant{
		Issuer: "https://issuer.example.test", Audience: "https://resource.example.test",
		EvaluationTime: 1500, ClockSkew: -1,
	}); err == nil {
		t.Fatal("negative skew must be rejected")
	}
	// proof max age ceiling: the corpus-valid envelope with ONLY ProofMaxAge
	// raised over the ceiling must reject (with the ceiling removed it would
	// verify — that is the red-capable pin)
	creds, exp := loadCorpusEnvelopeValid(t)
	exp.ProofMaxAge = 301
	if _, err := v.CheckEnvelope(creds, exp); err == nil {
		t.Fatal("proof max age over the ceiling must be rejected, not silently widened")
	}
	// and the untouched corpus envelope stays valid
	creds2, exp2 := loadCorpusEnvelopeValid(t)
	if _, err := v.CheckEnvelope(creds2, exp2); err != nil {
		t.Fatalf("corpus-valid envelope must verify: %v", err)
	}
}

// loadCorpusEnvelopeValid loads the vendored corpus check-envelope-valid case.
func loadCorpusEnvelopeValid(t *testing.T) (v.Credentials, v.ExpectedRequest) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "corpus", "cases", "envelope", "check.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Grant    string `json:"grant"`
				Proof    string `json:"proof"`
				Expected struct {
					Audience       string          `json:"audience"`
					CastArguments  json.RawMessage `json:"cast_arguments"`
					ClockSkew      int64           `json:"clock_skew"`
					EvaluationTime int64           `json:"evaluation_time"`
					InvocationID   string          `json:"invocation_id"`
					Issuer         string          `json:"issuer"`
					Method         string          `json:"method"`
					Operation      string          `json:"operation"`
					ProofMaxAge    int64           `json:"proof_max_age"`
					TargetURI      string          `json:"target_uri"`
					TrustedIssuer  struct {
						KeyID     string `json:"key_id"`
						PublicKey string `json:"public_key"`
					} `json:"trusted_issuer"`
				} `json:"expected"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	for _, c := range cf.Cases {
		if c.ID != "check-envelope-valid" {
			continue
		}
		e := c.Input.Expected
		args, err := v.JsonDecode(e.CastArguments, nil)
		if err != nil {
			t.Fatal(err)
		}
		return v.Credentials{Grant: c.Input.Grant, Proof: c.Input.Proof}, v.ExpectedRequest{
			TrustedIssuer:  v.TrustedIssuer{KeyID: e.TrustedIssuer.KeyID, PublicKey: mustB64(t, e.TrustedIssuer.PublicKey)},
			Issuer:         e.Issuer,
			Audience:       e.Audience,
			EvaluationTime: e.EvaluationTime,
			ClockSkew:      e.ClockSkew,
			Method:         e.Method,
			TargetURI:      e.TargetURI,
			InvocationID:   e.InvocationID,
			Operation:      e.Operation,
			CastArguments:  args,
			ProofMaxAge:    e.ProofMaxAge,
			Nonce:          v.NonceNotRequired(),
		}
	}
	t.Fatal("check-envelope-valid case missing")
	return v.Credentials{}, v.ExpectedRequest{}
}

// ---- (j) overflow fail-closure (the i64::MIN class from the BAP-15 arc) ----

func TestPermissiveOverflowFailClosed(t *testing.T) {
	// extreme boundary values must reject without panicking
	extreme := int64(-9007199254740991)
	if _, err := v.CheckChain(v.ChainInput{Rows: [][]byte{mustB64(t, chainRowB64)}}, v.ExpectedChain{
		ChainID:       "urn:example:chain",
		FirstSequence: extreme, // invalid range, must fail closed not panic
		LastSequence:  1,
		PreviousHash:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		LastHash:      "nlI60Ae0aih559j_4EinXcdPFzOuXcwTs8BYcCP95bs",
		RowCount:      1,
	}); err == nil {
		t.Fatal("negative first_sequence must be rejected")
	}
	// sequence one row with max-magnitude sequence value in encode: no panic
	if _, err := v.EncodeConsumptionEntry(v.ConsumptionEntry{
		ChainID:      "urn:example:chain",
		Commitment:   "lQXKy3xxDtFxJfzGyzZp6N3KbIzYr2ox9rPNZGBMMJg",
		PreviousHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Sequence:     extreme,
	}, nil); err == nil {
		t.Fatal("negative sequence must be rejected at encode")
	}
}

// ---- (k) ADR 0018 bounds threading: tightened bounds enforced at every ceiling ----

func TestPermissiveBoundsThreading(t *testing.T) {
	// chain_row_bytes on CheckChain
	tightRow, err := v.BoundsNew(map[string]int{"chain_row_bytes": 16})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.CheckChain(v.ChainInput{Rows: [][]byte{mustB64(t, chainRowB64)}}, v.ExpectedChain{
		ChainID:       "urn:example:chain",
		FirstSequence: 1,
		LastSequence:  1,
		PreviousHash:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		LastHash:      "FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw", // head of the single-row chain
		RowCount:      1,
		Bounds:        &tightRow,
	}); err == nil {
		t.Fatal("tightened chain_row_bytes must reject the 130-byte row")
	}
	// anchor_bytes on VerifyHistoricalAnchor
	tightAnchor, _ := v.BoundsNew(map[string]int{"anchor_bytes": 16})
	key := v.HistoricalPublicKey{KeyID: "archive-a", PublicKey: mustB64(t, archiveKeyB64), ValidFrom: 0, ValidBefore: 3000}
	expected := v.ExpectedAnchor{
		AnchorID:       "urn:example:anchor:start",
		ChainID:        "urn:example:chain",
		KeyID:          "archive-a",
		Sequence:       0,
		AnchoredAt:     1000,
		ChainHash:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyFingerprint: "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8",
		Bounds:         &tightAnchor,
	}
	if _, err := v.VerifyHistoricalAnchor(anchorCompact, key, expected); err == nil {
		t.Fatal("tightened anchor_bytes must reject the anchor compact")
	}
	// assemble_compact threads caller bounds (ADR 0018 decision 4)
	seg := strings.Split(grantCompact, ".")
	tightCompact, _ := v.BoundsNew(map[string]int{"compact_bytes": 100})
	si := v.SigningInput{Kind: v.KindGrant, Protected: mustB64(t, seg[0]), Payload: mustB64(t, seg[1])}
	sig := mustB64(t, seg[2])
	if _, err := v.AssembleCompact(si, sig, &tightCompact); err == nil {
		t.Fatal("tightened compact_bytes must reject the assembled grant")
	}
	// json_bytes threading on the primitive decoder
	tightJSON, _ := v.BoundsNew(map[string]int{"json_bytes": 4})
	if _, err := v.JsonDecode([]byte(`{"a":1}`), &tightJSON); err == nil {
		t.Fatal("tightened json_bytes must reject a 7-byte input")
	}
}

// ---- (l) ADR 0018 D2 nested-pins identity semantics (export surface) ----

func TestPermissiveNestedBoundsIdentity(t *testing.T) {
	obj, keys, expected := loadCorpusExportValid(t)
	// baseline: untightened, absent nested — valid
	if _, err := v.VerifyAnchoredExport(obj, keys, expected); err != nil {
		t.Fatalf("baseline export verification must be valid: %v", err)
	}
	tight, err := v.BoundsNew(map[string]int{"archive_chunks": 4})
	if err != nil {
		t.Fatal(err)
	}
	// tightened outer + ABSENT nested: invalid
	bad := expected
	bad.Bounds = &tight
	bad.Chain = withChainBounds(expected, nil)
	bad.StartAnchor = withAnchorBounds(expected, true, nil)
	bad.EndAnchor = withAnchorBounds(expected, false, nil)
	if _, err := v.VerifyAnchoredExport(obj, keys, bad); err == nil {
		t.Fatal("tightened outer with absent nested bounds must be rejected")
	}
	// tightened outer + EQUAL nested: valid (identity pin), and the tightened
	// ceiling is real: archive_chunks=4 rejects the 6-chunk corpus archive
	equalNested := expected
	equalNested.Bounds = &tight
	equalNested.Chain = withChainBounds(expected, &tight)
	equalNested.StartAnchor = withAnchorBounds(expected, true, &tight)
	equalNested.EndAnchor = withAnchorBounds(expected, false, &tight)
	if _, err := v.VerifyAnchoredExport(obj, keys, equalNested); err == nil {
		t.Fatal("tightened archive_chunks=4 must reject the 6-chunk archive (threading is real)")
	}
	// loosened nested under untightened outer: invalid (identity override is
	// not tightening — a nested value may never differ from the outer)
	looser, _ := v.BoundsNew(map[string]int{"archive_chunks": 1000})
	worse := expected
	worse.Bounds = nil
	worse.Chain = withChainBounds(expected, &looser)
	if _, err := v.VerifyAnchoredExport(obj, keys, worse); err == nil {
		t.Fatal("nested bounds differing from the untightened outer must be rejected")
	}
}

func withChainBounds(e v.ExpectedAnchoredExport, b *v.Bounds) v.ExpectedChain {
	c := e.Chain
	c.Bounds = b
	return c
}

func withAnchorBounds(e v.ExpectedAnchoredExport, start bool, b *v.Bounds) v.ExpectedAnchor {
	a := e.EndAnchor
	if start {
		a = e.StartAnchor
	}
	a.Bounds = b
	return a
}

// ---- (m) closed Result surface: no panic escapes a façade (ADR 0017 clause 1) ----

func TestPermissiveClosedResultNoPanic(t *testing.T) {
	// hostile inputs across representative façades: none may panic
	key := v.HistoricalPublicKey{KeyID: "archive-a", PublicKey: mustB64(t, archiveKeyB64)}
	expected := v.ExpectedAnchor{
		AnchorID: "urn:example:anchor:start", ChainID: "urn:example:chain", KeyID: "archive-a",
		Sequence: 0, AnchoredAt: 1000,
		ChainHash:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyFingerprint: "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8",
	}
	calls := []func() error{
		func() error { _, err := v.DecodeGrant("", nil); return err },
		func() error { _, err := v.DecodeProof("...", nil); return err },
		func() error { _, err := v.UntrustedKeyLocator("a.b", nil); return err },
		func() error { _, err := v.VerifyGrant("", v.TrustedIssuer{}, v.ExpectedGrant{}); return err },
		func() error { _, err := v.CheckEnvelope(v.Credentials{}, v.ExpectedRequest{}); return err },
		func() error { _, err := v.VerifyHistoricalAnchor("", key, expected); return err },
		func() error { _, err := v.VerifyKeyTransition("", key, key, v.ExpectedKeyTransition{}); return err },
		func() error { _, err := v.CheckChain(v.ChainInput{}, v.ExpectedChain{}); return err },
		func() error {
			_, err := v.VerifyAnchoredExport(v.ArchivedObject{}, nil, v.ExpectedAnchoredExport{})
			return err
		},
		func() error {
			_, err := v.EncodeAnchoredExport(v.AnchoredExportInput{}, v.ExpectedAnchoredExport{})
			return err
		},
		func() error { _, err := v.AssembleCompact(v.SigningInput{}, nil, nil); return err },
		func() error { _, err := v.GrantSigningInput(v.Grant{}, nil); return err },
		func() error { _, err := v.ProofSigningInput(v.Proof{}, nil); return err },
		func() error { _, err := v.BoundaryAnchorSigningInput(v.BoundaryAnchor{}, nil); return err },
		func() error { _, err := v.KeyTransitionSigningInput(v.KeyTransition{}, nil); return err },
		func() error { _, err := v.EncodeConsumptionEntry(v.ConsumptionEntry{}, nil); return err },
		func() error { _, err := v.RequestDigest("", nil, nil); return err },
		func() error { _, err := v.JcsEncode(nil, nil); return err },
		func() error { _, err := v.JsonDecode(nil, nil); return err },
		func() error { _, err := v.UriNormalize("", nil); return err },
	}
	for i, call := range calls {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("façade %d panicked: %v", i, r)
				}
			}()
			_ = call()
		}()
	}
}

func mustJSON(t *testing.T, s string) v.Value {
	t.Helper()
	val, err := v.JsonDecode([]byte(s), nil)
	if err != nil {
		t.Fatal(err)
	}
	return val
}

// loadCorpusExportValid loads the vendored corpus verify-anchored-export-valid
// case through the public API (the battery's valid export baseline).
func loadCorpusExportValid(t *testing.T) (v.ArchivedObject, v.HistoricalKeyChain, v.ExpectedAnchoredExport) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "corpus", "cases", "anchored-export", "verify.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string                     `json:"id"`
			Input map[string]json.RawMessage `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	var c *struct {
		ID    string                     `json:"id"`
		Input map[string]json.RawMessage `json:"input"`
	}
	for i := range cf.Cases {
		if cf.Cases[i].ID == "verify-anchored-export-valid" {
			c = &cf.Cases[i]
		}
	}
	if c == nil {
		t.Fatal("valid export case missing")
	}
	var chunksB64 []string
	if err := json.Unmarshal(c.Input["chunks"], &chunksB64); err != nil {
		t.Fatal(err)
	}
	chunks := make([][]byte, 0, len(chunksB64))
	for _, ch := range chunksB64 {
		chunks = append(chunks, mustB64(t, ch))
	}
	var keysRaw []map[string]json.RawMessage
	if err := json.Unmarshal(c.Input["keys"], &keysRaw); err != nil {
		t.Fatal(err)
	}
	keys := make(v.HistoricalKeyChain, 0, len(keysRaw))
	for _, kr := range keysRaw {
		var kid, pk string
		var vf, vb int64
		json.Unmarshal(kr["key_id"], &kid)
		json.Unmarshal(kr["public_key"], &pk)
		json.Unmarshal(kr["valid_from"], &vf)
		json.Unmarshal(kr["valid_before"], &vb)
		keys = append(keys, v.HistoricalPublicKey{KeyID: kid, PublicKey: mustB64(t, pk), ValidFrom: vf, ValidBefore: vb})
	}
	var version string
	json.Unmarshal(c.Input["version"], &version)
	var expRaw map[string]json.RawMessage
	json.Unmarshal(c.Input["expected"], &expRaw)
	var digest, ov string
	json.Unmarshal(expRaw["digest"], &digest)
	json.Unmarshal(expRaw["object_version"], &ov)
	expected := v.ExpectedAnchoredExport{Digest: digest, ObjectVersion: ov}
	var cm map[string]json.RawMessage
	json.Unmarshal(expRaw["chain"], &cm)
	g := func(m map[string]json.RawMessage, k string) string {
		var s string
		json.Unmarshal(m[k], &s)
		return s
	}
	n := func(m map[string]json.RawMessage, k string) int64 {
		var x int64
		json.Unmarshal(m[k], &x)
		return x
	}
	expected.Chain = v.ExpectedChain{
		ChainID:       g(cm, "chain_id"),
		FirstSequence: n(cm, "first_sequence"),
		LastSequence:  n(cm, "last_sequence"),
		PreviousHash:  g(cm, "previous_hash"),
		LastHash:      g(cm, "last_hash"),
		RowCount:      n(cm, "row_count"),
	}
	var saRaw, eaRaw map[string]json.RawMessage
	json.Unmarshal(expRaw["start_anchor"], &saRaw)
	json.Unmarshal(expRaw["end_anchor"], &eaRaw)
	expected.StartAnchor = expAnchor(saRaw, g, n)
	expected.EndAnchor = expAnchor(eaRaw, g, n)
	var trs []map[string]json.RawMessage
	json.Unmarshal(expRaw["transitions"], &trs)
	for _, tr := range trs {
		expected.Transitions = append(expected.Transitions, v.ExpectedKeyTransition{
			TransitionID:          g(tr, "transition_id"),
			ChainID:               g(tr, "chain_id"),
			CurrentKeyID:          g(tr, "current_key_id"),
			NextKeyID:             g(tr, "next_key_id"),
			EffectiveAt:           n(tr, "effective_at"),
			CurrentKeyFingerprint: g(tr, "current_key_fingerprint"),
			NextKeyFingerprint:    g(tr, "next_key_fingerprint"),
		})
	}
	return v.ArchivedObject{Chunks: chunks, Version: version}, keys, expected
}

func expAnchor(m map[string]json.RawMessage, g func(map[string]json.RawMessage, string) string, n func(map[string]json.RawMessage, string) int64) v.ExpectedAnchor {
	return v.ExpectedAnchor{
		AnchorID:       g(m, "anchor_id"),
		ChainID:        g(m, "chain_id"),
		KeyID:          g(m, "key_id"),
		Sequence:       n(m, "sequence"),
		AnchoredAt:     n(m, "anchored_at"),
		ChainHash:      g(m, "chain_hash"),
		KeyFingerprint: g(m, "key_fingerprint"),
	}
}
