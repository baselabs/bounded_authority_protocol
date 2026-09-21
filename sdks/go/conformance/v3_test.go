// Package conformance_test additionally carries the v3-profile (ES256,
// contract-major 3) acceptance runner: it executes the vendored 292-case
// corpus-v3 snapshot against the public EcdsaProfile SDK surface and the shared
// version-neutral primitives exactly as the v1/v2 runners do, SHA-binds the
// vendored index.json at startup, verifies every case file against the
// index's per-file SHA-256, and asserts the two-boundary key census against
// the index's public_key_fingerprints (EC P-256 RFC 7638 thumbprints over
// the 65-byte SEC1 keys). Version-neutral primitive surfaces (json, jcs,
// base64url, uri, bounds) dispatch to the shared surface; every other
// surface — the EC JWK surfaces included, since the JWK member set is
// suite-bound — dispatches to the EcdsaProfile facade.
package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	v "github.com/baselabs/bounded_authority_protocol_go"
)

// The certified pin is declared at function scope inside es256LoadCorpus: the
// frozen v1/v2 runners already declare the package-level
// `certifiedIndexSHA256` in this package and in the internal test package,
// and the corpus rotation script (scripts/regen_corpus_digests.exs) anchors
// on the exact line prefix `const certifiedIndexSHA256 = "` in THIS file —
// the local declaration satisfies both (the anchor strips leading
// whitespace, matches exactly one line, and preserves indentation on
// rewrite).

const es256CorpusDir = "corpus-v3"

const es256TotalCases = 292

// es256Profile is the contract-major-3 ES256 facade under test.
var es256Profile = v.EcdsaProfile{}

var es256Census = map[string]bool{}

func es256CensusKey(b64 string) {
	raw, err := v.Base64urlDecode(b64)
	if err != nil {
		return // never imported at the boundary
	}
	tp, err := es256Profile.PublicKeyThumbprintRaw(raw, nil)
	if err != nil {
		return // rejected before the crypto boundary (e.g. wrong width/form)
	}
	es256Census[v.Base64urlEncode(tp[:])] = true
}

func rawStringField(t *testing.T, m map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		t.Fatalf("case field %s: %v", key, err)
	}
	return s
}

func es256RawInt(t *testing.T, m map[string]json.RawMessage, key string) int64 {
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

// es256RawValue SDK-decodes a raw JSON value from the case file. Number tags are
// preserved because the SDK's own decoder parses the raw lexeme bytes.
func es256RawValue(t *testing.T, raw json.RawMessage) v.Value {
	t.Helper()
	val, err := v.JsonDecode(raw, nil)
	if err != nil {
		t.Fatalf("case value not decodable: %s", raw)
	}
	return val
}

func es256SubObject(t *testing.T, m map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	var sub map[string]json.RawMessage
	if err := json.Unmarshal(m[key], &sub); err != nil {
		t.Fatalf("case field %s: %v", key, err)
	}
	return sub
}

func es256LoadCorpus(t *testing.T) (*es256CorpusIndex, []es256LoadedFile) {
	t.Helper()
	// certifiedIndexSHA256 is the SHA-256 of the certified v3 corpus
	// index.json this SDK was conformed against (base64url). A vendored
	// corpus that hashes to anything else fails closed here — silent drift
	// is impossible.
	const certifiedIndexSHA256 = "pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw"
	indexBytes, err := os.ReadFile(filepath.Join(es256CorpusDir, "index.json"))
	if err != nil {
		t.Fatalf("vendored index.json: %v", err)
	}
	sum := sha256.Sum256(indexBytes)
	if v.Base64urlEncode(sum[:]) != certifiedIndexSHA256 {
		t.Fatalf("vendored corpus index.json SHA-256 mismatch — fail closed on corpus drift")
	}
	var idx es256CorpusIndex
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		t.Fatalf("index.json parse: %v", err)
	}
	if idx.TotalCases != es256TotalCases {
		t.Fatalf("index total_cases = %d, want %d", idx.TotalCases, es256TotalCases)
	}
	files := make([]es256LoadedFile, 0, len(idx.Files))
	for _, f := range idx.Files {
		raw, err := os.ReadFile(filepath.Join(es256CorpusDir, f.Path))
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
		// The revision sidecar occupies the one reserved non-case JSON path: closed 3-member
		// shape, case-free. Its SHA-256 was verified generically above.
		if f.Path == "revision.json" && f.Cases == 0 {
			var members map[string]json.RawMessage
			if err := json.Unmarshal(raw, &members); err != nil {
				t.Fatalf("revision.json parse: %v", err)
			}
			if len(members) != 3 || members["format"] == nil ||
				members["revision"] == nil || members["generated_from"] == nil {
				t.Fatalf("revision.json: closed member set")
			}
			var format string
			if err := json.Unmarshal(members["format"], &format); err != nil {
				t.Fatalf("revision.json: format: %v", err)
			}
			if format != "bounded-authority-protocol-v3-conformance-corpus-revision" {
				t.Fatalf("revision.json: format const")
			}
			var revision int
			if err := json.Unmarshal(members["revision"], &revision); err != nil || revision < 1 {
				t.Fatalf("revision.json: monotone integer revision")
			}
			var generatedFrom string
			if err := json.Unmarshal(members["generated_from"], &generatedFrom); err != nil ||
				len(generatedFrom) < 1 || len(generatedFrom) > 256 {
				t.Fatalf("revision.json: generated_from provenance string")
			}
			continue
		}
		var cf es256CaseFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			t.Fatalf("corpus file %s parse: %v", f.Path, err)
		}
		if len(cf.Cases) != f.Cases {
			t.Fatalf("corpus file %s: %d cases, index says %d", f.Path, len(cf.Cases), f.Cases)
		}
		files = append(files, es256LoadedFile{path: f.Path, cf: cf})
	}
	return &idx, files
}

type es256CorpusIndex struct {
	Format                string           `json:"format"`
	TotalCases            int              `json:"total_cases"`
	PublicKeyFingerprints []string         `json:"public_key_fingerprints"`
	Files                 []es256IndexFile `json:"files"`
}

type es256IndexFile struct {
	Path            string `json:"path"`
	Cases           int    `json:"cases"`
	SHA256Base64url string `json:"sha256_base64url"`
}

type es256LoadedFile struct {
	path string
	cf   es256CaseFile
}

type es256CaseFile struct {
	Format     string            `json:"format"`
	Provenance json.RawMessage   `json:"provenance"`
	Cases      []es256CorpusCase `json:"cases"`
}

type es256CorpusCase struct {
	ID       string                     `json:"id"`
	Surface  string                     `json:"surface"`
	Class    string                     `json:"class"`
	Input    map[string]json.RawMessage `json:"input"`
	Expected map[string]json.RawMessage `json:"expected"`
}

func TestEcdsaConformance(t *testing.T) {
	idx, files := es256LoadCorpus(t)
	agreed := 0
	for _, lf := range files {
		for _, c := range lf.cf.Cases {
			if os.Getenv("BAP_TRACE_ES256") != "" {
				fmt.Fprintf(os.Stderr, "TRACE3 %s %s (%s)\n", lf.path, c.ID, c.Surface)
			}
			c := c
			if t.Run(c.ID, func(t *testing.T) {
				es256RunCase(t, c)
			}) {
				agreed++ // counts AGREED subtests, not merely executed ones
			}
		}
	}
	// v3 key census (the v1/v2 runners' census adapted to the EC suite): the
	// DECLARED census is an index input from the curated generator, and keys
	// may emit no case — the case-byte discovery is a strict subset by design.
	// The two-way equality leg is curated == index (both directions); the
	// case-byte walk is the fail-closed subset leg; and every key a VALID
	// verification-surface case declares must be imported at the SDK verify
	// boundary.
	declared := idx.PublicKeyFingerprints
	if !es256SortedUniqueStrings(declared) {
		t.Fatalf("census: index public_key_fingerprints not sorted/unique")
	}
	curatedRaw, err := os.ReadFile(es256CuratedCensusPath)
	if err != nil {
		t.Fatalf("census: curated inputs: %v", err)
	}
	var curatedDoc struct {
		PublicKeyFingerprints []string `json:"public_key_fingerprints"`
	}
	if err := json.Unmarshal(curatedRaw, &curatedDoc); err != nil {
		t.Fatalf("census: curated inputs parse: %v", err)
	}
	curated := curatedDoc.PublicKeyFingerprints
	if !es256SortedUniqueStrings(curated) {
		t.Fatalf("census: curated public_key_fingerprints not sorted/unique")
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, fp := range declared {
		declaredSet[fp] = true
	}
	curatedSet := make(map[string]bool, len(curated))
	for _, fp := range curated {
		curatedSet[fp] = true
	}
	for _, fp := range declared {
		if !curatedSet[fp] {
			t.Fatalf("census: index fingerprint %s missing from the curated census", fp)
		}
	}
	for _, fp := range curated {
		if !declaredSet[fp] {
			t.Fatalf("census: curated fingerprint %s missing from the index census", fp)
		}
	}
	// subset leg: every key embedded in a case input must be declared
	discovery := map[string]bool{}
	for _, lf := range files {
		for _, c := range lf.cf.Cases {
			es256CollectCaseKeys(t, c.Input, discovery)
		}
	}
	for fp := range discovery {
		if !declaredSet[fp] {
			t.Fatalf("census: case inputs carry undeclared key %s", fp)
		}
	}
	// verify-import leg: every key declared by a valid verification-surface
	// case must have been imported at the SDK boundary
	verifyExpected := map[string]bool{}
	for _, lf := range files {
		for _, c := range lf.cf.Cases {
			if c.Class == "valid" {
				es256CollectCaseKeys(t, c.Input, verifyExpected)
			}
		}
	}
	if len(verifyExpected) == 0 {
		t.Fatalf("census: no valid-case keys discovered (corpus lost its verify cases)")
	}
	for fp := range verifyExpected {
		if !es256Census[fp] {
			t.Fatalf("census: key %s declared by a valid case but never imported at the SDK boundary", fp)
		}
	}
	t.Logf("agreed=%d disagreed=0 census=%d declared=%d", agreed, len(es256Census), len(declared))
}

// es256CuratedCensusPath is the monorepo's curated generator directory — the
// declared census input the index was built from (facts the generator ships
// that are not derivable from case bytes).
const es256CuratedCensusPath = "../../../conformance/generators/curated-inputs-v3.json"

// The v3 census key-label heuristic: a member named like a public key
// carrying an 87-char base64url (65-byte uncompressed SEC1) value;
// fingerprint/thumbprint/digest/hash members are value facts, never
// import-boundary keys.
var es256CensusKeyLabel = regexp.MustCompile(`(?i)public.*key|key.*public|verification.*key|holder.*key|issuer.*key`)
var es256CensusKeyDeny = regexp.MustCompile(`(?i)fingerprint|thumbprint|digest|hash`)
var es256CensusRawKey = regexp.MustCompile(`^[A-Za-z0-9_-]{87}$`)

func es256SortedUniqueStrings(list []string) bool {
	for i := 1; i < len(list); i++ {
		if list[i-1] >= list[i] {
			return false
		}
	}
	return true
}

// es256CollectCaseKeys walks one case input tree and records the EC thumbprint
// of every public-key-labeled raw key member.
func es256CollectCaseKeys(t *testing.T, m map[string]json.RawMessage, target map[string]bool) {
	t.Helper()
	for key, raw := range m {
		if es256CensusKeyDeny.MatchString(key) {
			continue
		}
		if es256CensusKeyLabel.MatchString(key) {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && es256CensusRawKey.MatchString(s) {
				keyBytes, err := v.Base64urlDecode(s)
				if err == nil && len(keyBytes) == 65 {
					if tp, err := es256Profile.PublicKeyThumbprintRaw(keyBytes, nil); err == nil {
						target[v.Base64urlEncode(tp[:])] = true
					}
				}
			}
		}
		var sub map[string]json.RawMessage
		if err := json.Unmarshal(raw, &sub); err == nil {
			es256CollectCaseKeys(t, sub, target)
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err == nil {
			for _, item := range arr {
				var elem map[string]json.RawMessage
				if err := json.Unmarshal(item, &elem); err == nil {
					es256CollectCaseKeys(t, elem, target)
				}
			}
		}
	}
}

// es256RunCase dispatches one corpus case to its surface driver. Version-neutral
// primitive surfaces dispatch to the shared surface; every suite-bound
// surface (wire artifacts and the EC JWK surfaces) dispatches to the EcdsaProfile
// facade. Any disagreement is fatal.
func es256RunCase(t *testing.T, c es256CorpusCase) {
	t.Helper()
	if os.Getenv("BAP_TRACE_ES256") != "" {
		fmt.Fprintf(os.Stderr, "TRACE v3 case %s (%s)\n", c.ID, c.Surface)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("case %s (%s): runner panic: %v", c.ID, c.Surface, r)
		}
	}()
	// .raw sidecar substitution: input.raw_file replaces the surface's
	// primary bytes input.
	rawBytes := es256MaybeRaw(t, c)
	switch c.Surface {
	case "base64url.decode":
		b64 := rawStringField(t, c.Input, "base64url")
		got, err := v.Base64urlDecode(b64)
		es256CheckVerdict(t, c, err)
		want := ""
		if c.Expected["decoded"] != nil {
			want = rawStringField(t, c.Expected, "decoded")
		}
		if string(got) != want {
			t.Fatalf("case %s: decoded %q want %q", c.ID, got, want)
		}
	case "jcs.encode":
		text := rawStringField(t, c.Input, "text")
		val, err := v.JsonDecode([]byte(text), nil)
		if err != nil {
			es256CheckInvalid(t, c, "decode")
			return
		}
		enc, err := v.JcsEncode(val, nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["encoded"] != nil && string(enc) != rawStringField(t, c.Expected, "encoded") {
			t.Fatalf("case %s: encoded %s", c.ID, enc)
		}
	case "json.decode":
		var text []byte
		switch {
		case rawBytes != nil:
			text = rawBytes
		case c.Input["base64url"] != nil:
			text = es256DecodeB64(t, c, rawStringField(t, c.Input, "base64url"))
		default:
			text = []byte(rawStringField(t, c.Input, "text"))
		}
		got, err := v.JsonDecode(text, nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["value"] != nil {
			want := es256RawValue(t, c.Expected["value"])
			gotJCS, err1 := v.JcsEncode(got, nil)
			wantJCS, err2 := v.JcsEncode(want, nil)
			if err1 != nil || err2 != nil || !bytes.Equal(gotJCS, wantJCS) {
				t.Fatalf("case %s: value mismatch (%s vs %s)", c.ID, gotJCS, wantJCS)
			}
		}
	case "uri.normalize":
		got, err := v.UriNormalize(rawStringField(t, c.Input, "text"), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["normalized"] != nil && got != rawStringField(t, c.Expected, "normalized") {
			t.Fatalf("case %s: normalized %s", c.ID, got)
		}
	case "jwk.decode_public":
		got, err := es256Profile.JwkDecodePublic([]byte(rawStringField(t, c.Input, "text")), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["public_key"] != nil && v.Base64urlEncode(got) != rawStringField(t, c.Expected, "public_key") {
			t.Fatalf("case %s: key mismatch", c.ID)
		}
	case "jwk.encode_public":
		key := es256DecodeB64(t, c, rawStringField(t, c.Input, "public_key"))
		es256CensusKey(rawStringField(t, c.Input, "public_key"))
		got, err := es256Profile.JwkEncodePublic(key, nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["encoded"] != nil && string(got) != rawStringField(t, c.Expected, "encoded") {
			t.Fatalf("case %s: encoded %s", c.ID, got)
		}
	case "jwk.thumbprint_preimage":
		got, err := es256Profile.JwkThumbprintPreimage([]byte(rawStringField(t, c.Input, "text")), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["preimage"] != nil && string(got) != rawStringField(t, c.Expected, "preimage") {
			t.Fatalf("case %s: preimage %s", c.ID, got)
		}
	case "jwk.thumbprint":
		got, err := es256Profile.JwkThumbprint([]byte(rawStringField(t, c.Input, "text")), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["thumbprint"] != nil && got != rawStringField(t, c.Expected, "thumbprint") {
			t.Fatalf("case %s: thumbprint %s", c.ID, got)
		}
	case "jwk.thumbprint_raw":
		got, err := es256Profile.JwkThumbprintRaw([]byte(rawStringField(t, c.Input, "text")), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["thumbprint_raw"] != nil && v.Base64urlEncode(got[:]) != rawStringField(t, c.Expected, "thumbprint_raw") {
			t.Fatalf("case %s: thumbprint_raw mismatch", c.ID)
		}
	case "jwk.public_key_thumbprint_raw":
		key := es256DecodeB64(t, c, rawStringField(t, c.Input, "public_key"))
		es256CensusKey(rawStringField(t, c.Input, "public_key"))
		got, err := es256Profile.PublicKeyThumbprintRaw(key, nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["thumbprint_raw"] != nil && v.Base64urlEncode(got[:]) != rawStringField(t, c.Expected, "thumbprint_raw") {
			t.Fatalf("case %s: thumbprint_raw mismatch", c.ID)
		}
	case "bounds.new":
		var overrides map[string]int64
		if err := json.Unmarshal(c.Input["overrides"], &overrides); err != nil {
			// non-integer or otherwise malformed override values are invalid
			es256CheckInvalid(t, c, "overrides")
			return
		}
		conv := make(map[string]int, len(overrides))
		for k, val := range overrides {
			conv[k] = int(val)
		}
		_, err := v.BoundsNew(conv)
		es256CheckVerdict(t, c, err)
	case "assemble_compact":
		si := v.SigningInput{
			Kind:      es256KindOf(rawStringField(t, c.Input, "kind")),
			Protected: es256DecodeB64(t, c, rawStringField(t, c.Input, "protected_segment")),
			Payload:   es256DecodeB64(t, c, rawStringField(t, c.Input, "payload_segment")),
		}
		sig := es256DecodeB64(t, c, rawStringField(t, c.Input, "signature"))
		got, err := es256Profile.AssembleCompact(si, sig, nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["compact"] != nil && got != rawStringField(t, c.Expected, "compact") {
			t.Fatalf("case %s: compact %s", c.ID, got)
		}
	case "grant_signing_input":
		si, err := es256Profile.GrantSigningInput(es256GrantFrom(t, c), nil)
		es256CheckVerdict(t, c, err)
		es256CheckSigningInput(t, c, si)
	case "proof_signing_input":
		p := v.Proof{
			ProofID:         rawStringField(t, c.Input, "proof_id"),
			HolderPublicKey: es256DecodeB64(t, c, rawStringField(t, c.Input, "holder_public_key")),
			InvocationID:    rawStringField(t, c.Input, "invocation_id"),
			Operation:       rawStringField(t, c.Input, "operation"),
			Method:          rawStringField(t, c.Input, "method"),
			TargetURI:       rawStringField(t, c.Input, "target_uri"),
			IssuedAt:        es256RawInt(t, c.Input, "issued_at"),
			GrantCompact:    rawStringField(t, c.Input, "grant_compact"),
			CastArguments:   es256RawValue(t, c.Input["cast_arguments"]),
		}
		es256CensusKey(rawStringField(t, c.Input, "holder_public_key"))
		si, err := es256Profile.ProofSigningInput(p, nil)
		es256CheckVerdict(t, c, err)
		es256CheckSigningInput(t, c, si)
	case "boundary_anchor_signing_input":
		a := v.BoundaryAnchor{
			AnchorID:   rawStringField(t, c.Input, "anchor_id"),
			ChainID:    rawStringField(t, c.Input, "chain_id"),
			KeyID:      rawStringField(t, c.Input, "key_id"),
			AnchoredAt: es256RawInt(t, c.Input, "anchored_at"),
			Sequence:   es256RawInt(t, c.Input, "sequence"),
			ChainHash:  rawStringField(t, c.Input, "chain_hash"),
			PublicKey:  es256DecodeB64(t, c, rawStringField(t, c.Input, "public_key")),
		}
		es256CensusKey(rawStringField(t, c.Input, "public_key"))
		si, err := es256Profile.BoundaryAnchorSigningInput(a, nil)
		es256CheckVerdict(t, c, err)
		es256CheckSigningInput(t, c, si)
	case "key_transition_signing_input":
		kt := v.KeyTransition{
			TransitionID:     rawStringField(t, c.Input, "transition_id"),
			ChainID:          rawStringField(t, c.Input, "chain_id"),
			CurrentKeyID:     rawStringField(t, c.Input, "current_key_id"),
			NextKeyID:        rawStringField(t, c.Input, "next_key_id"),
			EffectiveAt:      es256RawInt(t, c.Input, "effective_at"),
			CurrentPublicKey: es256DecodeB64(t, c, rawStringField(t, c.Input, "current_public_key")),
			NextPublicKey:    es256DecodeB64(t, c, rawStringField(t, c.Input, "next_public_key")),
		}
		es256CensusKey(rawStringField(t, c.Input, "current_public_key"))
		es256CensusKey(rawStringField(t, c.Input, "next_public_key"))
		si, err := es256Profile.KeyTransitionSigningInput(kt, nil)
		es256CheckVerdict(t, c, err)
		es256CheckSigningInput(t, c, si)
	case "request_digest":
		got, err := es256Profile.RequestDigest(rawStringField(t, c.Input, "operation"), es256RawValue(t, c.Input["cast_arguments"]), nil)
		es256CheckVerdict(t, c, err)
		var want string
		if c.Expected["digest"] != nil {
			want = rawStringField(t, c.Expected, "digest")
		}
		if got != want {
			t.Fatalf("case %s: digest %s want %s", c.ID, got, want)
		}
	case "decode_grant":
		got, err := es256Profile.DecodeGrant(rawStringField(t, c.Input, "compact"), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["key_id"] != nil && got.KeyID != rawStringField(t, c.Expected, "key_id") {
			t.Fatalf("case %s: kid %s", c.ID, got.KeyID)
		}
	case "decode_proof":
		got, err := es256Profile.DecodeProof(rawStringField(t, c.Input, "compact"), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["proof_id"] != nil && got.ProofID != rawStringField(t, c.Expected, "proof_id") {
			t.Fatalf("case %s: proof id %s", c.ID, got.ProofID)
		}
	case "untrusted_key_locator":
		got, err := es256Profile.UntrustedKeyLocator(rawStringField(t, c.Input, "compact"), nil)
		es256CheckVerdict(t, c, err)
		if c.Expected["kid"] != nil && got.KeyID != rawStringField(t, c.Expected, "kid") {
			t.Fatalf("case %s: kid %s", c.ID, got.KeyID)
		}
	case "verify_grant":
		pk := rawStringField(t, c.Input, "public_key")
		es256CensusKey(pk)
		got, err := es256Profile.VerifyGrant(rawStringField(t, c.Input, "compact"), v.TrustedIssuer{
			KeyID:     rawStringField(t, c.Input, "key_id"),
			PublicKey: es256DecodeB64(t, c, pk),
		}, v.ExpectedGrant{
			Issuer:         rawStringField(t, c.Input, "issuer"),
			Audience:       rawStringField(t, c.Input, "audience"),
			EvaluationTime: es256RawInt(t, c.Input, "evaluation_time"),
			ClockSkew:      es256RawInt(t, c.Input, "clock_skew"),
		})
		es256CheckVerdict(t, c, err)
		if c.Expected["grant_id"] != nil && got.GrantID != rawStringField(t, c.Expected, "grant_id") {
			t.Fatalf("case %s: grant id %s", c.ID, got.GrantID)
		}
		if c.Expected["issuer"] != nil && got.Issuer != rawStringField(t, c.Expected, "issuer") {
			t.Fatalf("case %s: issuer %s", c.ID, got.Issuer)
		}
	case "check_envelope":
		exp := es256SubObject(t, c.Input, "expected")
		ti := es256SubObject(t, exp, "trusted_issuer")
		pk := rawStringField(t, ti, "public_key")
		es256CensusKey(pk)
		got, err := es256Profile.CheckEnvelope(v.Credentials{
			Grant: rawStringField(t, c.Input, "grant"),
			Proof: rawStringField(t, c.Input, "proof"),
		}, v.ExpectedRequest{
			TrustedIssuer: v.TrustedIssuer{
				KeyID:     rawStringField(t, ti, "key_id"),
				PublicKey: es256DecodeB64(t, c, pk),
			},
			Issuer:         rawStringField(t, exp, "issuer"),
			Audience:       rawStringField(t, exp, "audience"),
			EvaluationTime: es256RawInt(t, exp, "evaluation_time"),
			ClockSkew:      es256RawInt(t, exp, "clock_skew"),
			Method:         rawStringField(t, exp, "method"),
			TargetURI:      rawStringField(t, exp, "target_uri"),
			InvocationID:   rawStringField(t, exp, "invocation_id"),
			Operation:      rawStringField(t, exp, "operation"),
			CastArguments:  es256RawValue(t, exp["cast_arguments"]),
			ProofMaxAge:    es256RawInt(t, exp, "proof_max_age"),
			Nonce:          es256NonceMode(t, exp),
		})
		es256CheckVerdict(t, c, err)
		_ = got
	case "encode_consumption_entry":
		got, err := es256Profile.EncodeConsumptionEntry(v.ConsumptionEntry{
			ChainID:      rawStringField(t, c.Input, "chain_id"),
			Commitment:   rawStringField(t, c.Input, "commitment"),
			PreviousHash: rawStringField(t, c.Input, "previous_hash"),
			Sequence:     es256RawInt(t, c.Input, "sequence"),
		}, nil)
		es256CheckVerdict(t, c, err)
		// the v3 corpus carries the canonical row base64url-encoded in
		// "bytes" (the v1/v2 corpora carried the raw text; the corpus is the
		// certified authority, the runner adapts)
		if c.Expected["bytes"] != nil && string(got.Row) != string(es256DecodeB64(t, c, rawStringField(t, c.Expected, "bytes"))) {
			t.Fatalf("case %s: row %s", c.ID, got.Row)
		}
		if c.Expected["hash"] != nil && v.Base64urlEncode(got.Hash[:]) != rawStringField(t, c.Expected, "hash") {
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
		got, err := es256Profile.CheckChain(v.ChainInput{Rows: rows}, v.ExpectedChain{
			ChainID:       rawStringField(t, c.Input, "chain_id"),
			FirstSequence: es256RawInt(t, c.Input, "first_sequence"),
			LastSequence:  es256RawInt(t, c.Input, "last_sequence"),
			PreviousHash:  rawStringField(t, c.Input, "previous_hash"),
			LastHash:      rawStringField(t, c.Input, "last_hash"),
			RowCount:      es256RawInt(t, c.Input, "row_count"),
		})
		es256CheckVerdict(t, c, err)
		if c.Expected["chain_id"] != nil && got.ChainID != rawStringField(t, c.Expected, "chain_id") {
			t.Fatalf("case %s: chain id %s", c.ID, got.ChainID)
		}
	case "verify_historical_anchor":
		key := es256SubObject(t, c.Input, "key")
		pk := rawStringField(t, key, "public_key")
		es256CensusKey(pk)
		got, err := es256Profile.VerifyHistoricalAnchor(rawStringField(t, c.Input, "compact"), es256HistoricalKey(t, key, pk), es256ExpectedAnchor(t, es256SubObject(t, c.Input, "expected")))
		es256CheckVerdict(t, c, err)
		if c.Expected["anchor_id"] != nil && got.AnchorID != rawStringField(t, c.Expected, "anchor_id") {
			t.Fatalf("case %s: anchor id %s", c.ID, got.AnchorID)
		}
	case "verify_key_transition":
		cur := es256SubObject(t, c.Input, "current_key")
		next := es256SubObject(t, c.Input, "next_key")
		es256CensusKey(rawStringField(t, cur, "public_key"))
		es256CensusKey(rawStringField(t, next, "public_key"))
		got, err := es256Profile.VerifyKeyTransition(rawStringField(t, c.Input, "compact"),
			es256HistoricalKey(t, cur, rawStringField(t, cur, "public_key")),
			es256HistoricalKey(t, next, rawStringField(t, next, "public_key")),
			es256ExpectedTransition(t, es256SubObject(t, c.Input, "expected")))
		es256CheckVerdict(t, c, err)
		if c.Expected["transition_id"] != nil && got.TransitionID != rawStringField(t, c.Expected, "transition_id") {
			t.Fatalf("case %s: transition id %s", c.ID, got.TransitionID)
		}
	case "encode_anchored_export":
		input, expected := es256ExportEncodeInput(t, c)
		got, err := es256Profile.EncodeAnchoredExport(input, expected)
		es256CheckVerdict(t, c, err)
		if c.Expected["byte_count"] != nil {
			if got.ByteCount != es256RawInt(t, c.Expected, "byte_count") {
				t.Fatalf("case %s: byte_count %d", c.ID, got.ByteCount)
			}
		}
		if c.Expected["digest"] != nil {
			if v.Base64urlEncode(got.Digest[:]) != rawStringField(t, c.Expected, "digest") {
				t.Fatalf("case %s: digest mismatch", c.ID)
			}
		}
	case "verify_anchored_export":
		obj, keys, expected := es256ExportVerifyInput(t, c)
		got, err := es256Profile.VerifyAnchoredExport(obj, keys, expected)
		es256CheckVerdict(t, c, err)
		if c.Expected["chain_id"] != nil && got.ChainID != rawStringField(t, c.Expected, "chain_id") {
			t.Fatalf("case %s: chain id %s", c.ID, got.ChainID)
		}
	default:
		t.Fatalf("case %s: unknown surface %s", c.ID, c.Surface)
	}
}

func es256NonceMode(t *testing.T, exp map[string]json.RawMessage) v.NonceMode {
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

func es256MaybeRaw(t *testing.T, c es256CorpusCase) []byte {
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
	raw, err := os.ReadFile(filepath.Join(es256CorpusDir, path))
	if err != nil {
		t.Fatalf("case %s raw file: %v", c.ID, err)
	}
	s := sha256.Sum256(raw)
	if v.Base64urlEncode(s[:]) != wantSHA {
		t.Fatalf("case %s: raw file SHA mismatch", c.ID)
	}
	return raw
}

func es256CheckVerdict(t *testing.T, c es256CorpusCase, err error) {
	t.Helper()
	if c.Expected["verdict"] == nil {
		t.Fatalf("case %s: no verdict", c.ID)
	}
	want := rawStringField(t, c.Expected, "verdict")
	if want == "valid" && err != nil {
		t.Fatalf("case %s (%s): expected valid, got %v", c.ID, c.Class, err)
	}
	if want != "valid" && err == nil {
		t.Fatalf("case %s (%s): expected invalid, got valid", c.ID, c.Class)
	}
}

func es256CheckInvalid(t *testing.T, c es256CorpusCase, stage string) {
	t.Helper()
	if rawStringField(t, c.Expected, "verdict") == "valid" {
		t.Fatalf("case %s: expected valid but rejected at %s", c.ID, stage)
	}
}

func es256DecodeB64(t *testing.T, c es256CorpusCase, s string) []byte {
	t.Helper()
	raw, err := v.Base64urlDecode(s)
	if err != nil {
		t.Fatalf("case %s: bad base64url %q", c.ID, s)
	}
	return raw
}

func es256KindOf(k string) v.Kind {
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

func es256CheckSigningInput(t *testing.T, c es256CorpusCase, si v.SigningInput) {
	t.Helper()
	if c.Expected["message"] == nil {
		return // invalid cases carry only the verdict
	}
	msg := v.Base64urlEncode(si.Protected) + "." + v.Base64urlEncode(si.Payload)
	if msg != rawStringField(t, c.Expected, "message") {
		t.Fatalf("case %s: message %s", c.ID, msg)
	}
	if v.Base64urlEncode(si.Protected) != rawStringField(t, c.Expected, "protected_segment") {
		t.Fatalf("case %s: protected segment mismatch", c.ID)
	}
	if v.Base64urlEncode(si.Payload) != rawStringField(t, c.Expected, "payload_segment") {
		t.Fatalf("case %s: payload segment mismatch", c.ID)
	}
}

func es256GrantFrom(t *testing.T, c es256CorpusCase) v.Grant {
	t.Helper()
	var ops []struct {
		Name      string            `json:"name"`
		Selectors []json.RawMessage `json:"selectors"`
	}
	if err := json.Unmarshal(c.Input["operations"], &ops); err != nil {
		t.Fatalf("case %s operations: %v", c.ID, err)
	}
	out := v.Grant{
		KeyID:            rawStringField(t, c.Input, "key_id"),
		Issuer:           rawStringField(t, c.Input, "issuer"),
		GrantID:          rawStringField(t, c.Input, "grant_id"),
		IssuedAt:         es256RawInt(t, c.Input, "issued_at"),
		NotBefore:        es256RawInt(t, c.Input, "not_before"),
		ExpiresAt:        es256RawInt(t, c.Input, "expires_at"),
		HolderThumbprint: rawStringField(t, c.Input, "holder_thumbprint"),
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
				sel = es256MustAllSelector()
			} else {
				sel = es256RawValue(t, s)
			}
			def.Selectors = append(def.Selectors, sel)
		}
		out.Operations = append(out.Operations, def)
	}
	return out
}

func es256MustAllSelector() v.Value {
	val, err := v.JsonDecode([]byte(`{"kind":"all"}`), nil)
	if err != nil {
		panic(err)
	}
	return val
}

func es256HistoricalKey(t *testing.T, m map[string]json.RawMessage, pk string) v.HistoricalPublicKey {
	t.Helper()
	k := v.HistoricalPublicKey{
		KeyID:     rawStringField(t, m, "key_id"),
		PublicKey: es256DecodeB64(t, es256CorpusCase{}, pk),
		ValidFrom: es256RawInt(t, m, "valid_from"),
	}
	// a null (or absent) valid_before is the unbounded upper validity — the
	// same mapping the v2 runner makes.
	if raw, ok := m["valid_before"]; ok && string(raw) != "null" {
		k.ValidBefore = es256RawInt(t, m, "valid_before")
	} else {
		k.ValidBeforeUnbounded = true
	}
	return k
}

func es256ExpectedAnchor(t *testing.T, m map[string]json.RawMessage) v.ExpectedAnchor {
	t.Helper()
	return v.ExpectedAnchor{
		AnchorID:       rawStringField(t, m, "anchor_id"),
		ChainID:        rawStringField(t, m, "chain_id"),
		KeyID:          rawStringField(t, m, "key_id"),
		Sequence:       es256RawInt(t, m, "sequence"),
		AnchoredAt:     es256RawInt(t, m, "anchored_at"),
		ChainHash:      rawStringField(t, m, "chain_hash"),
		KeyFingerprint: rawStringField(t, m, "key_fingerprint"),
	}
}

func es256ExpectedTransition(t *testing.T, m map[string]json.RawMessage) v.ExpectedKeyTransition {
	t.Helper()
	return v.ExpectedKeyTransition{
		TransitionID:          rawStringField(t, m, "transition_id"),
		ChainID:               rawStringField(t, m, "chain_id"),
		CurrentKeyID:          rawStringField(t, m, "current_key_id"),
		NextKeyID:             rawStringField(t, m, "next_key_id"),
		EffectiveAt:           es256RawInt(t, m, "effective_at"),
		CurrentKeyFingerprint: rawStringField(t, m, "current_key_fingerprint"),
		NextKeyFingerprint:    rawStringField(t, m, "next_key_fingerprint"),
	}
}

func es256ExportEncodeInput(t *testing.T, c es256CorpusCase) (v.AnchoredExportInput, v.ExpectedAnchoredExport) {
	t.Helper()
	exp := es256SubObject(t, c.Input, "expected")
	expected := es256ExpectedExport(t, exp)
	var rowsB64 []string
	if err := json.Unmarshal(c.Input["rows"], &rowsB64); err != nil {
		t.Fatalf("case %s rows: %v", c.ID, err)
	}
	rows := make([][]byte, 0, len(rowsB64))
	for _, r := range rowsB64 {
		rows = append(rows, es256DecodeB64(t, c, r))
	}
	var transitions []string
	if c.Input["transitions"] != nil {
		if err := json.Unmarshal(c.Input["transitions"], &transitions); err != nil {
			t.Fatalf("case %s transitions: %v", c.ID, err)
		}
	}
	return v.AnchoredExportInput{
		Rows:        rows,
		StartAnchor: rawStringField(t, c.Input, "start_anchor"),
		EndAnchor:   rawStringField(t, c.Input, "end_anchor"),
		Transitions: transitions,
	}, expected
}

func es256ExportVerifyInput(t *testing.T, c es256CorpusCase) (v.ArchivedObject, v.HistoricalKeyChain, v.ExpectedAnchoredExport) {
	t.Helper()
	var chunksB64 []string
	if err := json.Unmarshal(c.Input["chunks"], &chunksB64); err != nil {
		t.Fatalf("case %s chunks: %v", c.ID, err)
	}
	chunks := make([][]byte, 0, len(chunksB64))
	for _, ch := range chunksB64 {
		chunks = append(chunks, es256DecodeB64(t, c, ch))
	}
	var rawKeys []map[string]json.RawMessage
	if err := json.Unmarshal(c.Input["keys"], &rawKeys); err != nil {
		t.Fatalf("case %s keys: %v", c.ID, err)
	}
	keys := make(v.HistoricalKeyChain, 0, len(rawKeys))
	for _, rk := range rawKeys {
		pk := rawStringField(t, rk, "public_key")
		es256CensusKey(pk)
		keys = append(keys, es256HistoricalKey(t, rk, pk))
	}
	exp := es256SubObject(t, c.Input, "expected")
	return v.ArchivedObject{
		Chunks:  chunks,
		Version: rawStringField(t, c.Input, "version"),
	}, keys, es256ExpectedExport(t, exp)
}

func es256ExpectedExport(t *testing.T, exp map[string]json.RawMessage) v.ExpectedAnchoredExport {
	t.Helper()
	// digest/object_version are verify-path expected context; the encode
	// cases carry neither (the producer derives its own digest), so both
	// reads are optional at the runner boundary
	out := v.ExpectedAnchoredExport{}
	if exp["digest"] != nil {
		out.Digest = rawStringField(t, exp, "digest")
	}
	if exp["object_version"] != nil {
		out.ObjectVersion = rawStringField(t, exp, "object_version")
	}
	if chain := exp["chain"]; chain != nil {
		cm := es256SubObject(t, exp, "chain")
		out.Chain = v.ExpectedChain{
			ChainID:       rawStringField(t, cm, "chain_id"),
			FirstSequence: es256RawInt(t, cm, "first_sequence"),
			LastSequence:  es256RawInt(t, cm, "last_sequence"),
			PreviousHash:  rawStringField(t, cm, "previous_hash"),
			LastHash:      rawStringField(t, cm, "last_hash"),
			RowCount:      es256RawInt(t, cm, "row_count"),
		}
	}
	if sa := exp["start_anchor"]; sa != nil {
		out.StartAnchor = es256ExpectedAnchor(t, es256SubObject(t, exp, "start_anchor"))
	}
	if ea := exp["end_anchor"]; ea != nil {
		out.EndAnchor = es256ExpectedAnchor(t, es256SubObject(t, exp, "end_anchor"))
	}
	if trs := exp["transitions"]; trs != nil {
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(trs, &list); err != nil {
			t.Fatalf("case transitions: %v", err)
		}
		for _, tm := range list {
			out.Transitions = append(out.Transitions, es256ExpectedTransition(t, tm))
		}
	}
	return out
}
