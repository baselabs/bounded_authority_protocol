package conformance_test

// The strict-Ed25519 acceptance runner (profile bap-strict-ed25519/1): it executes the vendored
// additive corpus (corpus-strict, a byte-identical snapshot of priv/conformance/strict-ed25519/)
// against the public SDK surface only, SHA-binds the vendored index.json at startup, verifies every
// listed file against the index's per-file SHA-256 and case count, and requires every case to agree.
//
// Earlier corpora (v1, v2, v3, loopback, role attestation, content assertion) stay byte identical and
// keep their own runners; this leg adds the cases that pin rule S1 and key acceptance. The v1/v2
// shaped families reuse the v2 runner's input builders (same package) and dispatch to the contract
// major named by each case.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

// strictCertifiedIndexSHA256 is the SHA-256 (hex) of the certified strict corpus index.json. A
// vendored corpus that hashes to anything else fails closed here — silent drift is impossible.
const strictCertifiedIndexSHA256 = "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9"

const (
	strictCorpusDir  = "corpus-strict"
	strictProfile    = "bap-strict-ed25519/1"
	strictTotalCases = 2410
)

type strictIndex struct {
	Profile    string         `json:"profile"`
	Revision   int            `json:"revision"`
	TotalCases int            `json:"total_cases"`
	Families   map[string]int `json:"families"`
	Files      []struct {
		Cases  int    `json:"cases"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

type strictFile struct {
	Family string            `json:"family"`
	Cases  []json.RawMessage `json:"cases"`
}

type strictHead struct {
	ID      string `json:"id"`
	Surface string `json:"surface"`
	Major   int    `json:"major"`
}

func loadStrictCorpus(t *testing.T) []strictCaseRef {
	t.Helper()
	indexBytes, err := os.ReadFile(filepath.Join(strictCorpusDir, "index.json"))
	if err != nil {
		t.Fatalf("vendored strict index.json: %v", err)
	}
	sum := sha256.Sum256(indexBytes)
	if got := hex.EncodeToString(sum[:]); got != strictCertifiedIndexSHA256 {
		t.Fatalf("vendored strict corpus index.json SHA-256 mismatch: got %s want %s — fail closed on corpus drift",
			got, strictCertifiedIndexSHA256)
	}
	var idx strictIndex
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		t.Fatalf("strict index.json parse: %v", err)
	}
	if idx.Profile != strictProfile || idx.Revision != 1 || idx.TotalCases != strictTotalCases {
		t.Fatalf("strict index header: profile=%s revision=%d total=%d", idx.Profile, idx.Revision, idx.TotalCases)
	}
	var refs []strictCaseRef
	families := map[string]int{}
	seen := map[string]bool{}
	for _, f := range idx.Files {
		body, err := os.ReadFile(filepath.Join(strictCorpusDir, f.Path))
		if err != nil {
			t.Fatalf("strict corpus file %s: %v", f.Path, err)
		}
		fileSum := sha256.Sum256(body)
		if hex.EncodeToString(fileSum[:]) != f.SHA256 {
			t.Fatalf("strict corpus file %s: SHA-256 mismatch", f.Path)
		}
		if f.Path == "profile.json" || f.Path == "revision.json" {
			if f.Cases != 0 {
				t.Fatalf("%s declares cases", f.Path)
			}
			continue
		}
		var sf strictFile
		if err := json.Unmarshal(body, &sf); err != nil {
			t.Fatalf("strict corpus file %s parse: %v", f.Path, err)
		}
		if len(sf.Cases) != f.Cases {
			t.Fatalf("strict corpus file %s: %d cases, index says %d", f.Path, len(sf.Cases), f.Cases)
		}
		families[sf.Family] += len(sf.Cases)
		for _, raw := range sf.Cases {
			var head strictHead
			if err := json.Unmarshal(raw, &head); err != nil {
				t.Fatalf("strict case head: %v", err)
			}
			if seen[head.ID] {
				t.Fatalf("duplicate strict case id %s", head.ID)
			}
			seen[head.ID] = true
			refs = append(refs, strictCaseRef{head: head, raw: raw})
		}
	}
	if len(families) != len(idx.Families) {
		t.Fatalf("family set differs from the index: %v vs %v", families, idx.Families)
	}
	for fam, n := range idx.Families {
		if families[fam] != n {
			t.Fatalf("family %s: %d cases, index says %d", fam, families[fam], n)
		}
	}
	if len(refs) != strictTotalCases {
		t.Fatalf("loaded %d strict cases, want %d", len(refs), strictTotalCases)
	}
	return refs
}

type strictCaseRef struct {
	head strictHead
	raw  json.RawMessage
}

func TestStrictEd25519Corpus(t *testing.T) {
	refs := loadStrictCorpus(t)
	agreed := 0
	for _, ref := range refs {
		ref := ref
		if t.Run(ref.head.ID, func(t *testing.T) { runStrictCase(t, ref) }) {
			agreed++
		}
	}
	if agreed != strictTotalCases {
		t.Fatalf("strict corpus: %d/%d cases agree", agreed, strictTotalCases)
	}
	t.Logf("strict corpus: agreed=%d/%d", agreed, strictTotalCases)
}

func strictB64(t *testing.T, id, s string) []byte {
	t.Helper()
	raw, err := v.Base64urlDecode(s)
	if err != nil {
		t.Fatalf("case %s: bad base64url %q", id, s)
	}
	return raw
}

type strictMajor struct {
	verifyGrant   func(string, v.TrustedIssuer, v.ExpectedGrant) (v.GrantFacts, error)
	checkEnvelope func(v.Credentials, v.ExpectedRequest) (v.EnvelopeFacts, error)
	anchor        func(string, v.HistoricalPublicKey, v.ExpectedAnchor) (v.AnchorFacts, error)
	transition    func(string, v.HistoricalPublicKey, v.HistoricalPublicKey, v.ExpectedKeyTransition) (v.KeyTransitionFacts, error)
	export        func(v.ArchivedObject, v.HistoricalKeyChain, v.ExpectedAnchoredExport) (v.AnchoredExportFacts, error)
	digest        func(string, v.Value, *v.Bounds) (string, error)
}

func strictAPI(major int) strictMajor {
	if major == 2 {
		p := v.Profile{}
		return strictMajor{p.VerifyGrant, p.CheckEnvelope, p.VerifyHistoricalAnchor, p.VerifyKeyTransition, p.VerifyAnchoredExport, p.RequestDigest}
	}
	return strictMajor{v.VerifyGrant, v.CheckEnvelope, v.VerifyHistoricalAnchor, v.VerifyKeyTransition, v.VerifyAnchoredExport, v.RequestDigest}
}

func runStrictCase(t *testing.T, ref strictCaseRef) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("case %s (%s): runner panic: %v", ref.head.ID, ref.head.Surface, r)
		}
	}()
	switch ref.head.Surface {
	case "ed25519.verify_strict", "ed25519.acceptable_public_key", "ed25519.torsion_free":
		runStrictPrimitive(t, ref)
	case "local_loopback_http":
		runStrictLoopback(t, ref)
	case "role_attestation":
		runStrictRoleAttestation(t, ref)
	case "content_assertion":
		runStrictContentAssertion(t, ref)
	default:
		runStrictShaped(t, ref)
	}
}

func strictVerdict(t *testing.T, id string, expected map[string]json.RawMessage, accepted bool) {
	t.Helper()
	var verdict string
	if err := json.Unmarshal(expected["verdict"], &verdict); err != nil {
		t.Fatalf("case %s: verdict: %v", id, err)
	}
	if accepted != (verdict == "valid") {
		t.Fatalf("case %s: accepted=%v want verdict=%s", id, accepted, verdict)
	}
}

func runStrictPrimitive(t *testing.T, ref strictCaseRef) {
	t.Helper()
	var c struct {
		Input    map[string]string          `json:"input"`
		Expected map[string]json.RawMessage `json:"expected"`
	}
	if err := json.Unmarshal(ref.raw, &c); err != nil {
		t.Fatal(err)
	}
	id := ref.head.ID
	var accepted bool
	switch ref.head.Surface {
	case "ed25519.verify_strict":
		var msg []byte
		if c.Input["message"] != "" {
			msg = strictB64(t, id, c.Input["message"])
		}
		accepted = v.VerifyStrict(msg, strictB64(t, id, c.Input["signature"]), strictB64(t, id, c.Input["public_key"]))
	case "ed25519.acceptable_public_key":
		accepted = v.AcceptablePublicKey(strictB64(t, id, c.Input["public_key"]))
	case "ed25519.torsion_free":
		accepted = v.TorsionFree(strictB64(t, id, c.Input["public_key"]))
	}
	strictVerdict(t, id, c.Expected, accepted)
}

// runStrictShaped dispatches the v1/v2-shaped families, reusing the v2 runner's input builders.
func runStrictShaped(t *testing.T, ref strictCaseRef) {
	t.Helper()
	var c corpusCase
	if err := json.Unmarshal(ref.raw, &c); err != nil {
		t.Fatal(err)
	}
	api := strictAPI(ref.head.Major)
	switch c.Surface {
	case "json.decode":
		var text []byte
		if c.Input["base64url"] != nil {
			text = decodeB64(t, c, rawString(t, c.Input, "base64url"))
		} else {
			text = []byte(rawString(t, c.Input, "text"))
		}
		_, err := v.JsonDecode(text, nil)
		checkVerdict(t, c, err)
	case "jcs.encode":
		var text []byte
		if c.Input["base64url"] != nil {
			text = decodeB64(t, c, rawString(t, c.Input, "base64url"))
		} else {
			text = []byte(rawString(t, c.Input, "text"))
		}
		val, err := v.JsonDecode(text, nil)
		if err != nil {
			checkInvalid(t, c, "decode")
			return
		}
		enc, err := v.JcsEncode(val, nil)
		checkVerdict(t, c, err)
		if c.Expected["encoded"] != nil && string(enc) != rawString(t, c.Expected, "encoded") {
			t.Fatalf("case %s: encoded %s", c.ID, enc)
		}
	case "request_digest":
		got, err := api.digest(rawString(t, c.Input, "operation"), rawValue(t, c.Input["cast_arguments"]), nil)
		checkVerdict(t, c, err)
		if c.Expected["digest"] != nil && got != rawString(t, c.Expected, "digest") {
			t.Fatalf("case %s: digest %s", c.ID, got)
		}
	case "jwk.decode_public":
		got, err := v.JwkDecodePublic([]byte(rawString(t, c.Input, "text")), nil)
		checkVerdict(t, c, err)
		if c.Expected["public_key"] != nil && v.Base64urlEncode(got) != rawString(t, c.Expected, "public_key") {
			t.Fatalf("case %s: key mismatch", c.ID)
		}
	case "jwk.encode_public":
		got, err := v.JwkEncodePublic(decodeB64(t, c, rawString(t, c.Input, "public_key")), nil)
		checkVerdict(t, c, err)
		if c.Expected["encoded"] != nil && string(got) != rawString(t, c.Expected, "encoded") {
			t.Fatalf("case %s: encoded %s", c.ID, got)
		}
	case "jwk.thumbprint_preimage":
		got, err := v.JwkThumbprintPreimage([]byte(rawString(t, c.Input, "text")), nil)
		checkVerdict(t, c, err)
		if c.Expected["preimage"] != nil && string(got) != rawString(t, c.Expected, "preimage") {
			t.Fatalf("case %s: preimage %s", c.ID, got)
		}
	case "jwk.thumbprint":
		got, err := v.JwkThumbprint([]byte(rawString(t, c.Input, "text")), nil)
		checkVerdict(t, c, err)
		if c.Expected["thumbprint"] != nil && got != rawString(t, c.Expected, "thumbprint") {
			t.Fatalf("case %s: thumbprint %s", c.ID, got)
		}
	case "jwk.thumbprint_raw":
		_, err := v.JwkThumbprintRaw([]byte(rawString(t, c.Input, "text")), nil)
		checkVerdict(t, c, err)
	case "jwk.public_key_thumbprint_raw":
		_, err := v.PublicKeyThumbprintRaw(decodeB64(t, c, rawString(t, c.Input, "public_key")), nil)
		checkVerdict(t, c, err)
	case "verify_grant":
		got, err := api.verifyGrant(rawString(t, c.Input, "compact"), v.TrustedIssuer{
			KeyID:     rawString(t, c.Input, "key_id"),
			PublicKey: decodeB64(t, c, rawString(t, c.Input, "public_key")),
		}, v.ExpectedGrant{
			Issuer:         rawString(t, c.Input, "issuer"),
			Audience:       rawString(t, c.Input, "audience"),
			EvaluationTime: rawInt(t, c.Input, "evaluation_time"),
			ClockSkew:      rawInt(t, c.Input, "clock_skew"),
		})
		checkVerdict(t, c, err)
		if c.Expected["grant_id"] != nil && got.GrantID != rawString(t, c.Expected, "grant_id") {
			t.Fatalf("case %s: grant id %s", c.ID, got.GrantID)
		}
		if c.Expected["issuer"] != nil && got.Issuer != rawString(t, c.Expected, "issuer") {
			t.Fatalf("case %s: issuer %s", c.ID, got.Issuer)
		}
	case "check_envelope":
		exp := subObject(t, c.Input, "expected")
		ti := subObject(t, exp, "trusted_issuer")
		_, err := api.checkEnvelope(v.Credentials{
			Grant: rawString(t, c.Input, "grant"),
			Proof: rawString(t, c.Input, "proof"),
		}, v.ExpectedRequest{
			TrustedIssuer: v.TrustedIssuer{
				KeyID:     rawString(t, ti, "key_id"),
				PublicKey: decodeB64(t, c, rawString(t, ti, "public_key")),
			},
			Issuer:         rawString(t, exp, "issuer"),
			Audience:       rawString(t, exp, "audience"),
			EvaluationTime: rawInt(t, exp, "evaluation_time"),
			ClockSkew:      rawInt(t, exp, "clock_skew"),
			Method:         rawString(t, exp, "method"),
			TargetURI:      rawString(t, exp, "target_uri"),
			InvocationID:   rawString(t, exp, "invocation_id"),
			Operation:      rawString(t, exp, "operation"),
			CastArguments:  rawValue(t, exp["cast_arguments"]),
			ProofMaxAge:    rawInt(t, exp, "proof_max_age"),
			Nonce:          nonceMode(t, exp),
		})
		checkVerdict(t, c, err)
	case "verify_historical_anchor":
		key := subObject(t, c.Input, "key")
		_, err := api.anchor(rawString(t, c.Input, "compact"),
			historicalKey(t, key, rawString(t, key, "public_key")),
			expectedAnchor(t, subObject(t, c.Input, "expected")))
		checkVerdict(t, c, err)
	case "verify_key_transition":
		cur := subObject(t, c.Input, "current_key")
		next := subObject(t, c.Input, "next_key")
		_, err := api.transition(rawString(t, c.Input, "compact"),
			historicalKey(t, cur, rawString(t, cur, "public_key")),
			historicalKey(t, next, rawString(t, next, "public_key")),
			expectedTransition(t, subObject(t, c.Input, "expected")))
		checkVerdict(t, c, err)
	case "verify_anchored_export":
		obj, keys, expected := exportVerifyInput(t, c)
		_, err := api.export(obj, keys, expected)
		checkVerdict(t, c, err)
	default:
		t.Fatalf("case %s: unknown strict surface %s", c.ID, c.Surface)
	}
}

type strictWindowKey struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	ValidFrom   int64  `json:"valid_from"`
	ValidBefore int64  `json:"valid_before"`
}

func runStrictLoopback(t *testing.T, ref strictCaseRef) {
	t.Helper()
	var c struct {
		Compact        string `json:"compact"`
		Grant          string `json:"grant"`
		DecodeLocal    bool   `json:"decode_local"`
		DecodeStandard bool   `json:"decode_standard"`
		EnvelopeLocal  bool   `json:"envelope_local"`
		Nonce          string `json:"nonce"`
		TargetURI      string `json:"target_uri"`
		Issuer         struct {
			Audience  string `json:"audience"`
			Issuer    string `json:"issuer"`
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"issuer"`
		Request struct {
			CastArguments  json.RawMessage `json:"cast_arguments"`
			ClockSkew      int64           `json:"clock_skew"`
			EvaluationTime int64           `json:"evaluation_time"`
			InvocationID   string          `json:"invocation_id"`
			Method         string          `json:"method"`
			Operation      string          `json:"operation"`
			ProofMaxAge    int64           `json:"proof_max_age"`
		} `json:"request"`
	}
	if err := json.Unmarshal(ref.raw, &c); err != nil {
		t.Fatal(err)
	}
	id := ref.head.ID
	cast, err := v.JsonDecode(c.Request.CastArguments, nil)
	if err != nil {
		t.Fatalf("case %s cast_arguments: %v", id, err)
	}
	expected := v.ExpectedRequest{
		TrustedIssuer:  v.TrustedIssuer{KeyID: c.Issuer.KeyID, PublicKey: strictB64(t, id, c.Issuer.PublicKey)},
		Issuer:         c.Issuer.Issuer,
		Audience:       c.Issuer.Audience,
		EvaluationTime: c.Request.EvaluationTime,
		ClockSkew:      c.Request.ClockSkew,
		Method:         c.Request.Method,
		TargetURI:      c.TargetURI,
		InvocationID:   c.Request.InvocationID,
		Operation:      c.Request.Operation,
		CastArguments:  cast,
		ProofMaxAge:    c.Request.ProofMaxAge,
		Nonce:          v.NonceRequired(c.Nonce),
	}
	_, localErr := v.DecodeLocalLoopbackHTTPProof(c.Compact, nil)
	_, standardErr := v.DecodeProof(c.Compact, nil)
	_, envErr := v.CheckLocalLoopbackHTTPEnvelope(v.Credentials{Grant: c.Grant, Proof: c.Compact}, expected)
	if (localErr == nil) != c.DecodeLocal || (standardErr == nil) != c.DecodeStandard || (envErr == nil) != c.EnvelopeLocal {
		t.Fatalf("case %s: decode_local=%v decode_standard=%v envelope_local=%v, want %v/%v/%v", id,
			localErr == nil, standardErr == nil, envErr == nil, c.DecodeLocal, c.DecodeStandard, c.EnvelopeLocal)
	}
}

func runStrictRoleAttestation(t *testing.T, ref strictCaseRef) {
	t.Helper()
	var c struct {
		Attestor strictWindowKey `json:"attestor"`
		Subject  struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"subject"`
		Compact string `json:"compact"`
		Now     int64  `json:"now"`
		Decode  bool   `json:"decode"`
		Verify  bool   `json:"verify"`
	}
	if err := json.Unmarshal(ref.raw, &c); err != nil {
		t.Fatal(err)
	}
	id := ref.head.ID
	expected := v.ExpectedAttestation{
		Attestor:     v.TrustedAttestor{KeyID: c.Attestor.KeyID, ValidFrom: c.Attestor.ValidFrom, ValidBefore: c.Attestor.ValidBefore},
		SubjectKeyID: c.Subject.KeyID,
		Now:          c.Now,
	}
	copy(expected.Attestor.PublicKey[:], strictB64(t, id, c.Attestor.PublicKey))
	copy(expected.SubjectPublicKey[:], strictB64(t, id, c.Subject.PublicKey))
	_, decodeErr := v.DecodeAttestation(c.Compact, nil)
	_, verifyErr := v.VerifyAttestation(c.Compact, expected)
	if (decodeErr == nil) != c.Decode || (verifyErr == nil) != c.Verify {
		t.Fatalf("case %s: decode=%v verify=%v, want %v/%v", id, decodeErr == nil, verifyErr == nil, c.Decode, c.Verify)
	}
}

func runStrictContentAssertion(t *testing.T, ref strictCaseRef) {
	t.Helper()
	var c struct {
		Attestor strictWindowKey `json:"attestor"`
		Compact  string          `json:"compact"`
		Expected struct {
			Decode string `json:"decode"`
			Verify string `json:"verify"`
		} `json:"expected"`
		Context struct {
			Audience      string `json:"audience"`
			ContentDigest string `json:"content_digest"`
			Issuer        string `json:"issuer"`
			Now           int64  `json:"now"`
			Profile       string `json:"profile"`
			ProfileDigest string `json:"profile_digest"`
			Subject       string `json:"subject"`
		} `json:"expected_context"`
	}
	if err := json.Unmarshal(ref.raw, &c); err != nil {
		t.Fatal(err)
	}
	id := ref.head.ID
	bounds := v.BoundsMaximum()
	expected := v.ExpectedContentAssertion{
		Attestor: v.HistoricalPublicKey{
			KeyID: c.Attestor.KeyID, PublicKey: strictB64(t, id, c.Attestor.PublicKey),
			ValidFrom: c.Attestor.ValidFrom, ValidBefore: c.Attestor.ValidBefore,
		},
		Issuer: c.Context.Issuer, Audience: c.Context.Audience, Subject: c.Context.Subject,
		Profile: c.Context.Profile, Now: c.Context.Now, Bounds: &bounds,
	}
	copy(expected.ProfileDigest[:], strictB64(t, id, c.Context.ProfileDigest))
	copy(expected.ContentDigest[:], strictB64(t, id, c.Context.ContentDigest))
	_, decodeErr := v.DecodeContentAssertion(c.Compact, &bounds)
	_, verifyErr := v.VerifyContentAssertion(c.Compact, expected)
	if (decodeErr == nil) != (c.Expected.Decode == "valid") || (verifyErr == nil) != (c.Expected.Verify == "valid") {
		t.Fatalf("case %s: %s", id, fmt.Sprintf("decode=%v verify=%v, want %s/%s", decodeErr == nil, verifyErr == nil, c.Expected.Decode, c.Expected.Verify))
	}
}
