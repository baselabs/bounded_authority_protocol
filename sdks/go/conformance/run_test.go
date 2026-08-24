// Package conformance is the BAP-16 acceptance runner: it executes the
// vendored 283-case corpus against the public SDK surface only (the Rust
// run.rs pattern — no internal library symbols), SHA-binds the vendored
// index.json at startup, verifies every case file against the index's
// per-file SHA-256, and asserts the two-boundary key census against the
// index's public_key_fingerprints.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

// certifiedIndexSHA256 is the SHA-256 of the certified corpus index.json this
// SDK was conformed against (base64url). A vendored corpus that hashes to
// anything else fails closed here — silent drift is impossible.
const certifiedIndexSHA256 = "paxzYcUI0rtVxsowRaXMBuxKP2T2WQQhQQjG8QxwTcw"

const corpusDir = "corpus"

type caseFile struct {
	Format     string          `json:"format"`
	Provenance json.RawMessage `json:"provenance"`
	Cases      []corpusCase    `json:"cases"`
}

type corpusCase struct {
	ID       string                     `json:"id"`
	Surface  string                     `json:"surface"`
	Class    string                     `json:"class"`
	Input    map[string]json.RawMessage `json:"input"`
	Expected map[string]json.RawMessage `json:"expected"`
}

// census records every public key handed to the SDK at this runner's import
// boundary, keyed by RFC 7638 thumbprint.
var census = map[string]bool{}

func censusKey(b64 string) {
	raw, err := v.Base64urlDecode(b64)
	if err != nil {
		return // never imported at the boundary
	}
	tp, err := v.PublicKeyThumbprintRaw(raw, nil)
	if err != nil {
		return // rejected before the crypto boundary (e.g. short key)
	}
	census[v.Base64urlEncode(tp[:])] = true
}

func rawString(t *testing.T, m map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		t.Fatalf("case field %s: %v", key, err)
	}
	return s
}

func rawInt(t *testing.T, m map[string]json.RawMessage, key string) int64 {
	t.Helper()
	var n json.Number
	if err := json.Unmarshal(m[key], &n); err != nil {
		t.Fatalf("case field %s: %v", key, err)
	}
	i, err := n.Int64()
	if err != nil {
		t.Fatalf("case field %s not integral: %v", key, err)
	}
	return i
}

// rawValue SDK-decodes a raw JSON value from the case file. Number tags are
// preserved because the SDK's own decoder parses the raw lexeme bytes.
func rawValue(t *testing.T, raw json.RawMessage) v.Value {
	t.Helper()
	val, err := v.JsonDecode(raw, nil)
	if err != nil {
		t.Fatalf("case value not decodable: %s", raw)
	}
	return val
}

func subObject(t *testing.T, m map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	var sub map[string]json.RawMessage
	if err := json.Unmarshal(m[key], &sub); err != nil {
		t.Fatalf("case field %s: %v", key, err)
	}
	return sub
}

func loadCorpus(t *testing.T) (*corpusIndex, []loadedFile) {
	t.Helper()
	indexBytes, err := os.ReadFile(filepath.Join(corpusDir, "index.json"))
	if err != nil {
		t.Fatalf("vendored index.json: %v", err)
	}
	sum := sha256.Sum256(indexBytes)
	if v.Base64urlEncode(sum[:]) != certifiedIndexSHA256 {
		t.Fatalf("vendored corpus index.json SHA-256 mismatch: got %s want %s — fail closed on corpus drift",
			v.Base64urlEncode(sum[:]), certifiedIndexSHA256)
	}
	var idx corpusIndex
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		t.Fatalf("index.json parse: %v", err)
	}
	if idx.TotalCases != 283 {
		t.Fatalf("index total_cases = %d, want 283", idx.TotalCases)
	}
	files := make([]loadedFile, 0, len(idx.Files))
	for _, f := range idx.Files {
		raw, err := os.ReadFile(filepath.Join(corpusDir, f.Path))
		if err != nil {
			t.Fatalf("corpus file %s: %v", f.Path, err)
		}
		s := sha256.Sum256(raw)
		if v.Base64urlEncode(s[:]) != f.SHA256Base64url {
			t.Fatalf("corpus file %s SHA-256 mismatch", f.Path)
		}
		if f.Cases == 0 && strings.HasSuffix(f.Path, ".raw") {
			continue // integrity-verified sidecar blob, not a case file
		}
		var cf caseFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			t.Fatalf("corpus file %s parse: %v", f.Path, err)
		}
		if len(cf.Cases) != f.Cases {
			t.Fatalf("corpus file %s: %d cases, index says %d", f.Path, len(cf.Cases), f.Cases)
		}
		files = append(files, loadedFile{path: f.Path, cf: cf})
	}
	return &idx, files
}

type corpusIndex struct {
	Format                string      `json:"format"`
	TotalCases            int         `json:"total_cases"`
	PublicKeyFingerprints []string    `json:"public_key_fingerprints"`
	Files                 []indexFile `json:"files"`
}

type indexFile struct {
	Path            string `json:"path"`
	Cases           int    `json:"cases"`
	SHA256Base64url string `json:"sha256_base64url"`
}

type loadedFile struct {
	path string
	cf   caseFile
}

func TestConformance(t *testing.T) {
	idx, files := loadCorpus(t)
	agreed := 0
	for _, lf := range files {
		for _, c := range lf.cf.Cases {
			censusFile = lf.path
			if os.Getenv("BAP_TRACE") != "" {
				fmt.Fprintf(os.Stderr, "TRACE2 %s %s (%s)\n", lf.path, c.ID, c.Surface)
			}
			c := c
			t.Run(c.ID, func(t *testing.T) {
				runCase(t, c)
			})
			agreed++
		}
	}
	// Two-boundary key census: observed import-boundary set == index set.
	if len(census) != len(idx.PublicKeyFingerprints) {
		t.Fatalf("key census: observed %d keys, index declares %d", len(census), len(idx.PublicKeyFingerprints))
	}
	for _, fp := range idx.PublicKeyFingerprints {
		if !census[fp] {
			t.Fatalf("key census: index fingerprint %s never imported at the SDK boundary", fp)
		}
	}
	t.Logf("agreed=%d disagreed=0 census=%d", agreed, len(census))
}

var censusFile string

// runCase dispatches one corpus case to its public-surface driver. Any
// disagreement is fatal; agreed cases fall through.
func runCase(t *testing.T, c corpusCase) {
	t.Helper()
	if os.Getenv("BAP_TRACE") != "" {
		fmt.Fprintf(os.Stderr, "TRACE case %s (%s)\n", c.ID, c.Surface)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("case %s (%s): runner panic: %v", c.ID, c.Surface, r)
		}
	}()
	// .raw sidecar substitution: input.raw_file replaces the surface's
	// primary bytes input.
	rawBytes := maybeRaw(t, c)
	switch c.Surface {
	case "base64url.decode":
		b64 := rawString(t, c.Input, "base64url")
		got, err := v.Base64urlDecode(b64)
		checkVerdict(t, c, err)
		want := ""
		if c.Expected["decoded"] != nil {
			want = rawString(t, c.Expected, "decoded")
		}
		if string(got) != want {
			t.Fatalf("case %s: decoded %q want %q", c.ID, got, want)
		}
	case "jcs.encode":
		text := rawString(t, c.Input, "text")
		val, err := v.JsonDecode([]byte(text), nil)
		if err != nil {
			checkInvalid(t, c, "decode")
			return
		}
		enc, err := v.JcsEncode(val, nil)
		checkVerdict(t, c, err)
		if c.Expected["encoded"] != nil && string(enc) != rawString(t, c.Expected, "encoded") {
			t.Fatalf("case %s: encoded %s", c.ID, enc)
		}
	case "json.decode":
		var text []byte
		switch {
		case rawBytes != nil:
			text = rawBytes
		case c.Input["base64url"] != nil:
			text = decodeB64(t, c, rawString(t, c.Input, "base64url"))
		default:
			text = []byte(rawString(t, c.Input, "text"))
		}
		got, err := v.JsonDecode(text, nil)
		checkVerdict(t, c, err)
		if c.Expected["value"] != nil {
			want := rawValue(t, c.Expected["value"])
			gotJCS, err1 := v.JcsEncode(got, nil)
			wantJCS, err2 := v.JcsEncode(want, nil)
			if err1 != nil || err2 != nil || !bytes.Equal(gotJCS, wantJCS) {
				t.Fatalf("case %s: value mismatch (%s vs %s)", c.ID, gotJCS, wantJCS)
			}
		}
	case "uri.normalize":
		got, err := v.UriNormalize(rawString(t, c.Input, "text"), nil)
		checkVerdict(t, c, err)
		if c.Expected["normalized"] != nil && got != rawString(t, c.Expected, "normalized") {
			t.Fatalf("case %s: normalized %s", c.ID, got)
		}
	case "jwk.decode_public":
		got, err := v.JwkDecodePublic([]byte(rawString(t, c.Input, "text")), nil)
		checkVerdict(t, c, err)
		if c.Expected["public_key"] != nil && v.Base64urlEncode(got) != rawString(t, c.Expected, "public_key") {
			t.Fatalf("case %s: key mismatch", c.ID)
		}
	case "jwk.encode_public":
		key := decodeB64(t, c, rawString(t, c.Input, "public_key"))
		censusKey(rawString(t, c.Input, "public_key"))
		got, err := v.JwkEncodePublic(key, nil)
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
		key := decodeB64(t, c, rawString(t, c.Input, "public_key"))
		censusKey(rawString(t, c.Input, "public_key"))
		_, err := v.PublicKeyThumbprintRaw(key, nil)
		checkVerdict(t, c, err)
	case "bounds.new":
		var overrides map[string]int64
		if err := json.Unmarshal(c.Input["overrides"], &overrides); err != nil {
			// non-integer or otherwise malformed override values are invalid
			checkInvalid(t, c, "overrides")
			return
		}
		conv := make(map[string]int, len(overrides))
		for k, val := range overrides {
			conv[k] = int(val)
		}
		_, err := v.BoundsNew(conv)
		checkVerdict(t, c, err)
	case "assemble_compact":
		si := v.SigningInput{
			Kind:      kindOf(rawString(t, c.Input, "kind")),
			Protected: decodeB64(t, c, rawString(t, c.Input, "protected_segment")),
			Payload:   decodeB64(t, c, rawString(t, c.Input, "payload_segment")),
		}
		sig := decodeB64(t, c, rawString(t, c.Input, "signature"))
		got, err := v.AssembleCompact(si, sig, nil)
		checkVerdict(t, c, err)
		if c.Expected["compact"] != nil && got != rawString(t, c.Expected, "compact") {
			t.Fatalf("case %s: compact %s", c.ID, got)
		}
	case "grant_signing_input":
		si, err := v.GrantSigningInput(grantFrom(t, c), nil)
		checkVerdict(t, c, err)
		checkSigningInput(t, c, si)
	case "proof_signing_input":
		p := v.Proof{
			ProofID:         rawString(t, c.Input, "proof_id"),
			HolderPublicKey: decodeB64(t, c, rawString(t, c.Input, "holder_public_key")),
			InvocationID:    rawString(t, c.Input, "invocation_id"),
			Operation:       rawString(t, c.Input, "operation"),
			Method:          rawString(t, c.Input, "method"),
			TargetURI:       rawString(t, c.Input, "target_uri"),
			IssuedAt:        rawInt(t, c.Input, "issued_at"),
			GrantCompact:    rawString(t, c.Input, "grant_compact"),
			CastArguments:   rawValue(t, c.Input["cast_arguments"]),
		}
		censusKey(rawString(t, c.Input, "holder_public_key"))
		si, err := v.ProofSigningInput(p, nil)
		checkVerdict(t, c, err)
		checkSigningInput(t, c, si)
	case "boundary_anchor_signing_input":
		a := v.BoundaryAnchor{
			AnchorID:   rawString(t, c.Input, "anchor_id"),
			ChainID:    rawString(t, c.Input, "chain_id"),
			KeyID:      rawString(t, c.Input, "key_id"),
			AnchoredAt: rawInt(t, c.Input, "anchored_at"),
			Sequence:   rawInt(t, c.Input, "sequence"),
			ChainHash:  rawString(t, c.Input, "chain_hash"),
			PublicKey:  decodeB64(t, c, rawString(t, c.Input, "public_key")),
		}
		censusKey(rawString(t, c.Input, "public_key"))
		si, err := v.BoundaryAnchorSigningInput(a, nil)
		checkVerdict(t, c, err)
		checkSigningInput(t, c, si)
	case "key_transition_signing_input":
		kt := v.KeyTransition{
			TransitionID:     rawString(t, c.Input, "transition_id"),
			ChainID:          rawString(t, c.Input, "chain_id"),
			CurrentKeyID:     rawString(t, c.Input, "current_key_id"),
			NextKeyID:        rawString(t, c.Input, "next_key_id"),
			EffectiveAt:      rawInt(t, c.Input, "effective_at"),
			CurrentPublicKey: decodeB64(t, c, rawString(t, c.Input, "current_public_key")),
			NextPublicKey:    decodeB64(t, c, rawString(t, c.Input, "next_public_key")),
		}
		censusKey(rawString(t, c.Input, "current_public_key"))
		censusKey(rawString(t, c.Input, "next_public_key"))
		si, err := v.KeyTransitionSigningInput(kt, nil)
		checkVerdict(t, c, err)
		checkSigningInput(t, c, si)
	case "request_digest":
		got, err := v.RequestDigest(rawString(t, c.Input, "operation"), rawValue(t, c.Input["cast_arguments"]), nil)
		checkVerdict(t, c, err)
		var want string
		if c.Expected["digest"] != nil {
			want = rawString(t, c.Expected, "digest")
		}
		if got != want {
			t.Fatalf("case %s: digest %s want %s", c.ID, got, want)
		}
	case "decode_grant":
		got, err := v.DecodeGrant(rawString(t, c.Input, "compact"), nil)
		checkVerdict(t, c, err)
		if c.Expected["key_id"] != nil && got.KeyID != rawString(t, c.Expected, "key_id") {
			t.Fatalf("case %s: kid %s", c.ID, got.KeyID)
		}
	case "decode_proof":
		got, err := v.DecodeProof(rawString(t, c.Input, "compact"), nil)
		checkVerdict(t, c, err)
		if c.Expected["proof_id"] != nil && got.ProofID != rawString(t, c.Expected, "proof_id") {
			t.Fatalf("case %s: proof id %s", c.ID, got.ProofID)
		}
	case "untrusted_key_locator":
		got, err := v.UntrustedKeyLocator(rawString(t, c.Input, "compact"), nil)
		checkVerdict(t, c, err)
		if c.Expected["kid"] != nil && got.KeyID != rawString(t, c.Expected, "kid") {
			t.Fatalf("case %s: kid %s", c.ID, got.KeyID)
		}
	case "verify_grant":
		pk := rawString(t, c.Input, "public_key")
		censusKey(pk)
		got, err := v.VerifyGrant(rawString(t, c.Input, "compact"), v.TrustedIssuer{
			KeyID:     rawString(t, c.Input, "key_id"),
			PublicKey: decodeB64(t, c, pk),
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
		pk := rawString(t, ti, "public_key")
		censusKey(pk)
		got, err := v.CheckEnvelope(v.Credentials{
			Grant: rawString(t, c.Input, "grant"),
			Proof: rawString(t, c.Input, "proof"),
		}, v.ExpectedRequest{
			TrustedIssuer: v.TrustedIssuer{
				KeyID:     rawString(t, ti, "key_id"),
				PublicKey: decodeB64(t, c, pk),
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
		_ = got
	case "encode_consumption_entry":
		got, err := v.EncodeConsumptionEntry(v.ConsumptionEntry{
			ChainID:      rawString(t, c.Input, "chain_id"),
			Commitment:   rawString(t, c.Input, "commitment"),
			PreviousHash: rawString(t, c.Input, "previous_hash"),
			Sequence:     rawInt(t, c.Input, "sequence"),
		}, nil)
		checkVerdict(t, c, err)
		if c.Expected["bytes"] != nil && string(got.Row) != rawString(t, c.Expected, "bytes") {
			t.Fatalf("case %s: row %s", c.ID, got.Row)
		}
		if c.Expected["hash"] != nil && v.Base64urlEncode(got.Hash[:]) != rawString(t, c.Expected, "hash") {
			t.Fatalf("case %s: hash mismatch", c.ID)
		}
	case "check_chain":
		var rowsB64 []string
		if err := json.Unmarshal(c.Input["rows"], &rowsB64); err != nil {
			t.Fatalf("case %s rows: %v", c.ID, err)
		}
		rows := make([][]byte, 0, len(rowsB64))
		for _, r := range rowsB64 {
			raw, err := v.Base64urlDecode(r)
			if err != nil {
				t.Fatalf("case %s row: %v", c.ID, err)
			}
			rows = append(rows, raw)
		}
		_, err := v.CheckChain(v.ChainInput{Rows: rows}, v.ExpectedChain{
			ChainID:       rawString(t, c.Input, "chain_id"),
			FirstSequence: rawInt(t, c.Input, "first_sequence"),
			LastSequence:  rawInt(t, c.Input, "last_sequence"),
			PreviousHash:  rawString(t, c.Input, "previous_hash"),
			LastHash:      rawString(t, c.Input, "last_hash"),
			RowCount:      rawInt(t, c.Input, "row_count"),
		})
		checkVerdict(t, c, err)
	case "verify_historical_anchor":
		key := subObject(t, c.Input, "key")
		pk := rawString(t, key, "public_key")
		censusKey(pk)
		_, err := v.VerifyHistoricalAnchor(rawString(t, c.Input, "compact"), historicalKey(t, key, pk), expectedAnchor(t, subObject(t, c.Input, "expected")))
		checkVerdict(t, c, err)
	case "verify_key_transition":
		cur := subObject(t, c.Input, "current_key")
		next := subObject(t, c.Input, "next_key")
		censusKey(rawString(t, cur, "public_key"))
		censusKey(rawString(t, next, "public_key"))
		_, err := v.VerifyKeyTransition(rawString(t, c.Input, "compact"),
			historicalKey(t, cur, rawString(t, cur, "public_key")),
			historicalKey(t, next, rawString(t, next, "public_key")),
			expectedTransition(t, subObject(t, c.Input, "expected")))
		checkVerdict(t, c, err)
	case "encode_anchored_export":
		input, expected := exportEncodeInput(t, c)
		got, err := v.EncodeAnchoredExport(input, expected)
		checkVerdict(t, c, err)
		if c.Expected["byte_count"] != nil {
			if got.ByteCount != rawInt(t, c.Expected, "byte_count") {
				t.Fatalf("case %s: byte_count %d", c.ID, got.ByteCount)
			}
		}
		if c.Expected["digest"] != nil {
			if v.Base64urlEncode(got.Digest[:]) != rawString(t, c.Expected, "digest") {
				t.Fatalf("case %s: digest mismatch", c.ID)
			}
		}
	case "verify_anchored_export":
		obj, keys, expected := exportVerifyInput(t, c)
		_, err := v.VerifyAnchoredExport(obj, keys, expected)
		checkVerdict(t, c, err)
	default:
		t.Fatalf("case %s: unknown surface %s", c.ID, c.Surface)
	}
}

func nonceMode(t *testing.T, exp map[string]json.RawMessage) v.NonceMode {
	t.Helper()
	if exp["nonce"] == nil {
		return v.NonceNotRequired()
	}
	var m struct {
		Required string `json:"required"`
	}
	if err := json.Unmarshal(exp["nonce"], &m); err != nil {
		t.Fatalf("case nonce: %v", err)
	}
	return v.NonceRequired(m.Required)
}

func maybeRaw(t *testing.T, c corpusCase) []byte {
	t.Helper()
	if c.Input["raw_file"] == nil {
		return nil
	}
	var path, wantSHA string
	if err := json.Unmarshal(c.Input["raw_file"], &path); err != nil {
		t.Fatalf("case %s raw_file: %v", c.ID, err)
	}
	if err := json.Unmarshal(c.Input["sha256_base64url"], &wantSHA); err != nil {
		t.Fatalf("case %s sha256_base64url: %v", c.ID, err)
	}
	raw, err := os.ReadFile(filepath.Join(corpusDir, path))
	if err != nil {
		t.Fatalf("case %s raw file: %v", c.ID, err)
	}
	s := sha256.Sum256(raw)
	if v.Base64urlEncode(s[:]) != wantSHA {
		t.Fatalf("case %s: raw file SHA mismatch", c.ID)
	}
	return raw
}

func checkVerdict(t *testing.T, c corpusCase, err error) {
	t.Helper()
	if c.Expected["verdict"] == nil {
		t.Fatalf("case %s: no verdict", c.ID)
	}
	want := rawString(t, c.Expected, "verdict")
	if want == "valid" && err != nil {
		t.Fatalf("case %s (%s): expected valid, got %v", c.ID, c.Class, err)
	}
	if want != "valid" && err == nil {
		t.Fatalf("case %s (%s): expected invalid, got valid", c.ID, c.Class)
	}
}

func checkInvalid(t *testing.T, c corpusCase, stage string) {
	t.Helper()
	if rawString(t, c.Expected, "verdict") == "valid" {
		t.Fatalf("case %s: expected valid but rejected at %s", c.ID, stage)
	}
}

func decodeB64(t *testing.T, c corpusCase, s string) []byte {
	t.Helper()
	raw, err := v.Base64urlDecode(s)
	if err != nil {
		t.Fatalf("case %s: bad base64url %q", c.ID, s)
	}
	return raw
}

func kindOf(k string) v.Kind {
	switch k {
	case "grant":
		return v.KindGrant
	case "proof":
		return v.KindProof
	case "boundary_anchor":
		return v.KindBoundaryAnchor
	case "key_transition":
		return v.KindKeyTransition
	}
	return v.Kind("")
}

func checkSigningInput(t *testing.T, c corpusCase, si v.SigningInput) {
	t.Helper()
	if c.Expected["message"] == nil {
		return // invalid cases carry only the verdict
	}
	msg := v.Base64urlEncode(si.Protected) + "." + v.Base64urlEncode(si.Payload)
	if msg != rawString(t, c.Expected, "message") {
		t.Fatalf("case %s: message %s", c.ID, msg)
	}
	if v.Base64urlEncode(si.Protected) != rawString(t, c.Expected, "protected_segment") {
		t.Fatalf("case %s: protected segment mismatch", c.ID)
	}
	if v.Base64urlEncode(si.Payload) != rawString(t, c.Expected, "payload_segment") {
		t.Fatalf("case %s: payload segment mismatch", c.ID)
	}
}

func grantFrom(t *testing.T, c corpusCase) v.Grant {
	t.Helper()
	var ops []struct {
		Name      string            `json:"name"`
		Selectors []json.RawMessage `json:"selectors"`
	}
	if err := json.Unmarshal(c.Input["operations"], &ops); err != nil {
		t.Fatalf("case %s operations: %v", c.ID, err)
	}
	out := v.Grant{
		KeyID:            rawString(t, c.Input, "key_id"),
		Issuer:           rawString(t, c.Input, "issuer"),
		GrantID:          rawString(t, c.Input, "grant_id"),
		IssuedAt:         rawInt(t, c.Input, "issued_at"),
		NotBefore:        rawInt(t, c.Input, "not_before"),
		ExpiresAt:        rawInt(t, c.Input, "expires_at"),
		HolderThumbprint: rawString(t, c.Input, "holder_thumbprint"),
	}
	var auds []string
	if err := json.Unmarshal(c.Input["audiences"], &auds); err != nil {
		t.Fatalf("case %s audiences: %v", c.ID, err)
	}
	out.Audiences = auds
	for _, op := range ops {
		def := v.OperationDef{Name: op.Name}
		for _, s := range op.Selectors {
			var sel v.Value
			var str string
			if err := json.Unmarshal(s, &str); err == nil && str == "all" {
				sel = mustAllSelector()
			} else {
				sel = rawValue(t, s)
			}
			def.Selectors = append(def.Selectors, sel)
		}
		out.Operations = append(out.Operations, def)
	}
	return out
}

func mustAllSelector() v.Value {
	val, err := v.JsonDecode([]byte(`{"kind":"all"}`), nil)
	if err != nil {
		panic(err)
	}
	return val
}

func historicalKey(t *testing.T, m map[string]json.RawMessage, pk string) v.HistoricalPublicKey {
	t.Helper()
	k := v.HistoricalPublicKey{
		KeyID:       rawString(t, m, "key_id"),
		PublicKey:   decodeB64(t, corpusCase{}, pk),
		ValidFrom:   rawInt(t, m, "valid_from"),
		ValidBefore: rawInt(t, m, "valid_before"),
	}
	return k
}

func expectedAnchor(t *testing.T, m map[string]json.RawMessage) v.ExpectedAnchor {
	t.Helper()
	return v.ExpectedAnchor{
		AnchorID:       rawString(t, m, "anchor_id"),
		ChainID:        rawString(t, m, "chain_id"),
		KeyID:          rawString(t, m, "key_id"),
		Sequence:       rawInt(t, m, "sequence"),
		AnchoredAt:     rawInt(t, m, "anchored_at"),
		ChainHash:      rawString(t, m, "chain_hash"),
		KeyFingerprint: rawString(t, m, "key_fingerprint"),
	}
}

func expectedTransition(t *testing.T, m map[string]json.RawMessage) v.ExpectedKeyTransition {
	t.Helper()
	return v.ExpectedKeyTransition{
		TransitionID:          rawString(t, m, "transition_id"),
		ChainID:               rawString(t, m, "chain_id"),
		CurrentKeyID:          rawString(t, m, "current_key_id"),
		NextKeyID:             rawString(t, m, "next_key_id"),
		EffectiveAt:           rawInt(t, m, "effective_at"),
		CurrentKeyFingerprint: rawString(t, m, "current_key_fingerprint"),
		NextKeyFingerprint:    rawString(t, m, "next_key_fingerprint"),
	}
}

func exportEncodeInput(t *testing.T, c corpusCase) (v.AnchoredExportInput, v.ExpectedAnchoredExport) {
	t.Helper()
	exp := subObject(t, c.Input, "expected")
	expected := expectedExport(t, exp)
	var rowsB64 []string
	if err := json.Unmarshal(c.Input["rows"], &rowsB64); err != nil {
		t.Fatalf("case %s rows: %v", c.ID, err)
	}
	rows := make([][]byte, 0, len(rowsB64))
	for _, r := range rowsB64 {
		rows = append(rows, decodeB64(t, c, r))
	}
	var transitions []string
	if c.Input["transitions"] != nil {
		if err := json.Unmarshal(c.Input["transitions"], &transitions); err != nil {
			t.Fatalf("case %s transitions: %v", c.ID, err)
		}
	}
	censusExportKeys(t, exp)
	return v.AnchoredExportInput{
		Rows:        rows,
		StartAnchor: rawString(t, c.Input, "start_anchor"),
		EndAnchor:   rawString(t, c.Input, "end_anchor"),
		Transitions: transitions,
	}, expected
}

func exportVerifyInput(t *testing.T, c corpusCase) (v.ArchivedObject, v.HistoricalKeyChain, v.ExpectedAnchoredExport) {
	t.Helper()
	var chunksB64 []string
	if err := json.Unmarshal(c.Input["chunks"], &chunksB64); err != nil {
		t.Fatalf("case %s chunks: %v", c.ID, err)
	}
	chunks := make([][]byte, 0, len(chunksB64))
	for _, ch := range chunksB64 {
		chunks = append(chunks, decodeB64(t, c, ch))
	}
	var rawKeys []map[string]json.RawMessage
	if err := json.Unmarshal(c.Input["keys"], &rawKeys); err != nil {
		t.Fatalf("case %s keys: %v", c.ID, err)
	}
	keys := make(v.HistoricalKeyChain, 0, len(rawKeys))
	for _, rk := range rawKeys {
		pk := rawString(t, rk, "public_key")
		censusKey(pk)
		keys = append(keys, historicalKey(t, rk, pk))
	}
	exp := subObject(t, c.Input, "expected")
	censusExportKeys(t, exp)
	return v.ArchivedObject{
		Chunks:  chunks,
		Version: rawString(t, c.Input, "version"),
	}, keys, expectedExport(t, exp)
}

func censusExportKeys(t *testing.T, exp map[string]json.RawMessage) {
	t.Helper()
	// fingerprints in the expected context identify the archive keys; the
	// census keys themselves are imported from the `keys` list in verify cases
	// (verify) or from the anchor/transition producer inputs (encode cases do
	// not carry raw keys — their fingerprints are textual).
	_ = exp
}

func expectedExport(t *testing.T, exp map[string]json.RawMessage) v.ExpectedAnchoredExport {
	t.Helper()
	out := v.ExpectedAnchoredExport{
		Digest:        rawString(t, exp, "digest"),
		ObjectVersion: rawString(t, exp, "object_version"),
	}
	if chain := exp["chain"]; chain != nil {
		cm := subObject(t, exp, "chain")
		out.Chain = v.ExpectedChain{
			ChainID:       rawString(t, cm, "chain_id"),
			FirstSequence: rawInt(t, cm, "first_sequence"),
			LastSequence:  rawInt(t, cm, "last_sequence"),
			PreviousHash:  rawString(t, cm, "previous_hash"),
			LastHash:      rawString(t, cm, "last_hash"),
			RowCount:      rawInt(t, cm, "row_count"),
		}
	}
	if sa := exp["start_anchor"]; sa != nil {
		out.StartAnchor = expectedAnchor(t, subObject(t, exp, "start_anchor"))
	}
	if ea := exp["end_anchor"]; ea != nil {
		out.EndAnchor = expectedAnchor(t, subObject(t, exp, "end_anchor"))
	}
	if trs := exp["transitions"]; trs != nil {
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(trs, &list); err != nil {
			t.Fatalf("case transitions: %v", err)
		}
		for _, tm := range list {
			out.Transitions = append(out.Transitions, expectedTransition(t, tm))
		}
	}
	return out
}
