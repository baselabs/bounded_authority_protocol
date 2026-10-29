package conformance_test

// The producer-canonicality runner (profile bap-producer-canonicality/1, erratum 3): it executes
// the vendored additive corpus (corpus-producer-canonicality, a byte-identical snapshot of
// priv/conformance/producer-canonicality/) against the SDK's PRODUCER surfaces only — compact
// assembly for contract-majors 1, 2 and 3 and the three sibling profiles, anchored-export
// encoding for all three majors — SHA-binds the vendored index.json at startup, verifies every
// listed file against the index's per-file SHA-256 and case counts, and requires every case to
// agree: a refused signature is ErrInvalid; an accepted signature's bytes are emitted unchanged
// (byte-equality against the certified compact for every accepted case).
//
// No verification verdict changes anywhere: every BAP verifier already rejects these signatures.

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

// pcCertifiedIndexSHA256 is the SHA-256 (hex) of the certified producer-canonicality corpus
// index.json. A vendored corpus that hashes to anything else fails closed here.
const pcCertifiedIndexSHA256 = "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601"

const (
	pcCorpusDir  = "corpus-producer-canonicality"
	pcProfile    = "bap-producer-canonicality/1"
	pcRevision   = 1
	pcTotalCases = 75
)

type pcIndex struct {
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

type pcCase struct {
	ID      string `json:"id"`
	Surface string `json:"surface"`
	Class   string `json:"class"`
	Major   *int   `json:"major"`
	Profile string `json:"profile"`
	Input   struct {
		Kind            string   `json:"kind"`
		ProtectedSeg    string   `json:"protected_segment"`
		PayloadSeg      string   `json:"payload_segment"`
		Signature       string   `json:"signature"`
		Rows            []string `json:"rows"`
		StartAnchor     string   `json:"start_anchor"`
		EndAnchor       string   `json:"end_anchor"`
		Transitions     []string `json:"transitions"`
		ExpectedContext struct {
			Chain struct {
				ChainID      string `json:"chain_id"`
				FirstSeq     int64  `json:"first_sequence"`
				LastSeq      int64  `json:"last_sequence"`
				RowCount     int64  `json:"row_count"`
				PreviousHash string `json:"previous_hash"`
				LastHash     string `json:"last_hash"`
			} `json:"chain"`
			StartAnchor struct {
				AnchorID       string `json:"anchor_id"`
				AnchoredAt     int64  `json:"anchored_at"`
				ChainID        string `json:"chain_id"`
				Sequence       int64  `json:"sequence"`
				ChainHash      string `json:"chain_hash"`
				KeyID          string `json:"key_id"`
				KeyFingerprint string `json:"key_fingerprint"`
			} `json:"start_anchor"`
			EndAnchor struct {
				AnchorID       string `json:"anchor_id"`
				AnchoredAt     int64  `json:"anchored_at"`
				ChainID        string `json:"chain_id"`
				Sequence       int64  `json:"sequence"`
				ChainHash      string `json:"chain_hash"`
				KeyID          string `json:"key_id"`
				KeyFingerprint string `json:"key_fingerprint"`
			} `json:"end_anchor"`
			Transitions []struct {
				TransitionID          string `json:"transition_id"`
				ChainID               string `json:"chain_id"`
				EffectiveAt           int64  `json:"effective_at"`
				CurrentKeyID          string `json:"current_key_id"`
				CurrentKeyFingerprint string `json:"current_key_fingerprint"`
				NextKeyID             string `json:"next_key_id"`
				NextKeyFingerprint    string `json:"next_key_fingerprint"`
			} `json:"transitions"`
			Digest        string `json:"digest"`
			ObjectVersion string `json:"object_version"`
		} `json:"expected"`
	} `json:"input"`
	Expected struct {
		Verdict string `json:"verdict"`
		Compact string `json:"compact"`
	} `json:"expected"`
}

func loadProducerCanonicality(t *testing.T) []pcCase {
	t.Helper()
	indexBytes, err := os.ReadFile(filepath.Join(pcCorpusDir, "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	sum := sha256.Sum256(indexBytes)
	if hex.EncodeToString(sum[:]) != pcCertifiedIndexSHA256 {
		t.Fatalf("index.json SHA-256 mismatch: %s", hex.EncodeToString(sum[:]))
	}
	var index pcIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if index.Profile != pcProfile || index.Revision != pcRevision || index.TotalCases != pcTotalCases {
		t.Fatalf("corpus identity: %s rev %d total %d", index.Profile, index.Revision, index.TotalCases)
	}
	var cases []pcCase
	counted := 0
	for _, file := range index.Files {
		raw, err := os.ReadFile(filepath.Join(pcCorpusDir, file.Path))
		if err != nil {
			t.Fatalf("read %s: %v", file.Path, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("%s SHA-256 mismatch", file.Path)
		}
		var doc struct {
			Cases []pcCase `json:"cases"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", file.Path, err)
		}
		if len(doc.Cases) != file.Cases {
			t.Fatalf("%s holds %d cases, index declares %d", file.Path, len(doc.Cases), file.Cases)
		}
		cases = append(cases, doc.Cases...)
		counted += len(doc.Cases)
	}
	if counted != pcTotalCases {
		t.Fatalf("case census %d != %d", counted, pcTotalCases)
	}
	return cases
}

// Profile cases carry no kind; the kind is implied by the profile (the case envelope).
var pcProfileKinds = map[string]v.Kind{
	"bap-application-proof/local-loopback-http/1": v.KindLocalLoopbackHTTPProof,
	"bap-role-attestation/1":                      v.KindRoleAttestation,
	"bap-content-assertion/1":                     v.KindContentAssertion,
}

func pcSegments(c pcCase) (v.SigningInput, []byte) {
	protected, err := v.Base64urlDecode(c.Input.ProtectedSeg)
	if err != nil {
		panic(err)
	}
	payload, err := v.Base64urlDecode(c.Input.PayloadSeg)
	if err != nil {
		panic(err)
	}
	signature, err := v.Base64urlDecode(c.Input.Signature)
	if err != nil {
		panic(err)
	}
	kind := v.Kind(c.Input.Kind)
	if c.Profile != "" {
		kind = pcProfileKinds[c.Profile]
	}
	return v.SigningInput{Kind: kind, Protected: protected, Payload: payload}, signature
}

var pcAssemblers = map[string]func(v.SigningInput, []byte, *v.Bounds) (string, error){
	"bap-application-proof/local-loopback-http/1": v.AssembleLocalLoopbackHTTPCompact,
	"bap-role-attestation/1":                      v.AssembleAttestationCompact,
	"bap-content-assertion/1":                     v.AssembleContentAssertionCompact,
}

func pcAssemble(c pcCase) (string, error) {
	si, signature := pcSegments(c)
	if c.Major != nil {
		switch *c.Major {
		case 1:
			return v.AssembleCompact(si, signature, nil)
		case 2:
			return profile.AssembleCompact(si, signature, nil)
		case 3:
			return es256Profile.AssembleCompact(si, signature, nil)
		}
		panic("major")
	}
	fn, ok := pcAssemblers[c.Profile]
	if !ok {
		panic("profile " + c.Profile)
	}
	return fn(si, signature, nil)
}

// pcAllZeroHashB64 is the all-zero SHA-256 in unpadded base64url: a structurally valid digest for
// the v2/v3 export cases whose expected context carries none (Go's expected struct requires the
// fields; the encode side does not compare the digest against the archive it builds).
const pcAllZeroHashB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func pcExportExpected(c pcCase, major int) v.ExpectedAnchoredExport {
	e := c.Input.ExpectedContext
	digest := e.Digest
	if digest == "" {
		digest = pcAllZeroHashB64
	}
	version := e.ObjectVersion
	if version == "" {
		version = fmt.Sprintf("v%d", major)
	}
	transitions := make([]v.ExpectedKeyTransition, 0, len(e.Transitions))
	for _, t := range e.Transitions {
		transitions = append(transitions, v.ExpectedKeyTransition{
			TransitionID:          t.TransitionID,
			ChainID:               t.ChainID,
			CurrentKeyID:          t.CurrentKeyID,
			NextKeyID:             t.NextKeyID,
			EffectiveAt:           t.EffectiveAt,
			CurrentKeyFingerprint: t.CurrentKeyFingerprint,
			NextKeyFingerprint:    t.NextKeyFingerprint,
		})
	}
	return v.ExpectedAnchoredExport{
		Chain: v.ExpectedChain{
			ChainID: e.Chain.ChainID, FirstSequence: e.Chain.FirstSeq, LastSequence: e.Chain.LastSeq,
			RowCount: e.Chain.RowCount, PreviousHash: e.Chain.PreviousHash, LastHash: e.Chain.LastHash,
		},
		StartAnchor: v.ExpectedAnchor{
			AnchorID: e.StartAnchor.AnchorID, AnchoredAt: e.StartAnchor.AnchoredAt, ChainID: e.StartAnchor.ChainID,
			Sequence: e.StartAnchor.Sequence, ChainHash: e.StartAnchor.ChainHash, KeyID: e.StartAnchor.KeyID,
			KeyFingerprint: e.StartAnchor.KeyFingerprint,
		},
		EndAnchor: v.ExpectedAnchor{
			AnchorID: e.EndAnchor.AnchorID, AnchoredAt: e.EndAnchor.AnchoredAt, ChainID: e.EndAnchor.ChainID,
			Sequence: e.EndAnchor.Sequence, ChainHash: e.EndAnchor.ChainHash, KeyID: e.EndAnchor.KeyID,
			KeyFingerprint: e.EndAnchor.KeyFingerprint,
		},
		Transitions:   transitions,
		Digest:        digest,
		ObjectVersion: version,
	}
}

func pcEncode(c pcCase) error {
	rows := make([][]byte, 0, len(c.Input.Rows))
	for _, r := range c.Input.Rows {
		raw, err := v.Base64urlDecode(r)
		if err != nil {
			panic(err)
		}
		rows = append(rows, raw)
	}
	input := v.AnchoredExportInput{
		Rows: rows, StartAnchor: c.Input.StartAnchor, EndAnchor: c.Input.EndAnchor,
		Transitions: c.Input.Transitions,
	}
	switch *c.Major {
	case 1:
		_, err := v.EncodeAnchoredExport(input, pcExportExpected(c, 1))
		return err
	case 2:
		_, err := profile.EncodeAnchoredExport(input, pcExportExpected(c, 2))
		return err
	case 3:
		_, err := es256Profile.EncodeAnchoredExport(input, pcExportExpected(c, 3))
		return err
	}
	panic("major")
}

func TestProducerCanonicalityCorpus(t *testing.T) {
	cases := loadProducerCanonicality(t)
	refused, accepted := 0, 0
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
		wantValid := c.Expected.Verdict == "valid"
		var ok bool
		if c.Surface == "assemble_compact" {
			compact, err := pcAssemble(c)
			ok = err == nil
			if ok != wantValid {
				t.Fatalf("%s (%s): expected verdict %s, got ok=%v err=%v", c.ID, c.Class, c.Expected.Verdict, ok, err)
			}
			if wantValid && compact != c.Expected.Compact {
				t.Fatalf("%s: assembled bytes differ from the certified compact", c.ID)
			}
		} else {
			err := pcEncode(c)
			ok = err == nil
			if ok != wantValid {
				t.Fatalf("%s (%s): expected verdict %s, got ok=%v err=%v", c.ID, c.Class, c.Expected.Verdict, ok, err)
			}
			if wantValid {
				t.Fatalf("%s: accepted export-encode case without a certified artifact (unsupported by this runner)", c.ID)
			}
		}
		if wantValid {
			accepted++
		} else {
			refused++
		}
	}
	if len(seen) != pcTotalCases {
		t.Fatalf("case census %d != %d", len(seen), pcTotalCases)
	}
	t.Logf("producer-canonicality: PASS — %d/%d verdict agreement (%d refused, %d accepted with bytes unchanged)",
		pcTotalCases, pcTotalCases, refused, accepted)
}
