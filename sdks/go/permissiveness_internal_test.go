package verifier

// White-box permissiveness legs: the work-observation seams the closed
// library cannot expose publicly. The hasher seam (verifyAnchoredExportCore's
// digest parameter) gives Go the runtime work-observation channel the
// Python battery gets from monkeypatching; the member-order leg reads the
// ordered Obj algebra directly.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countingDigest wraps defaultArchiveDigest and counts calls.
type countingDigest struct {
	calls int
}

func (c *countingDigest) digest(chunks [][]byte, limit int64) ([32]byte, int64, error) {
	c.calls++
	return defaultArchiveDigest(chunks, limit)
}

// panickingDigest exercises the closed-Result guard (ADR 0017 clause 1): a
// panic anywhere under a public façade must surface as ErrInvalid, never as
// an escaping host panic.
type panickingDigest struct{}

func (panickingDigest) digest([][]byte, int64) ([32]byte, int64, error) {
	panic("injected mid-verify failure")
}

func loadExportCase(t *testing.T) (ArchivedObject, HistoricalKeyChain, ExpectedAnchoredExport) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("conformance", "corpus", "cases", "anchored-export", "verify.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	obj, keys, expected, err := parseExportCase(raw)
	if err != nil {
		t.Fatal(err)
	}
	return obj, keys, expected
}

// TestWorkPinPreDigestHoist is the clause-3 work pin: malformed caller
// metadata rejects with ZERO archive-hash calls. Removing the hoist (the
// 2026-08-18 resolution) reddens exactly these assertions (1+ calls).
func TestWorkPinPreDigestHoist(t *testing.T) {
	obj, keys, expected := loadExportCase(t)

	// malformed variants, each of which must reject with zero hash work
	mutations := []func(*ExpectedAnchoredExport){
		func(e *ExpectedAnchoredExport) { e.Chain.ChainID = "not a uri:" },        // malformed chain identifier
		func(e *ExpectedAnchoredExport) { e.Chain.RowCount = -5 },                 // incoherent count
		func(e *ExpectedAnchoredExport) { e.StartAnchor.KeyFingerprint = "AAAA" }, // wrong width
		func(e *ExpectedAnchoredExport) { e.ObjectVersion = "" },                  // empty version
		func(e *ExpectedAnchoredExport) { e.Digest = "AAAA" },                     // wrong digest width
	}
	c0 := &countingDigest{}
	swapDigest(t, c0.digest) // replaced per mutation below
	for i, mutate := range mutations {
		bad := expected
		mutate(&bad)
		counter := &countingDigest{}
		swapDigest(t, counter.digest)
		if _, err := VerifyAnchoredExport(obj, keys, bad); err == nil {
			t.Fatalf("mutation %d: expected rejection", i)
		}
		if counter.calls != 0 {
			t.Fatalf("mutation %d: rejected AFTER %d hash call(s) — pre-digest hoist violated", i, counter.calls)
		}
	}
	// the valid path performs exactly one archive digest
	counter := &countingDigest{}
	swapDigest(t, counter.digest)
	defer swapDigest(t, nil)
	if _, err := VerifyAnchoredExport(obj, keys, expected); err != nil {
		t.Fatalf("valid case rejected: %v", err)
	}
	if counter.calls != 1 {
		t.Fatalf("valid path digest calls = %d, want 1", counter.calls)
	}
	// version mismatch is caller-context: also zero hash work
	badVersion := obj
	badVersion.Version = "v2"
	counter = &countingDigest{}
	swapDigest(t, counter.digest)
	if _, err := VerifyAnchoredExport(badVersion, keys, expected); err == nil {
		t.Fatal("version mismatch must reject")
	}
	if counter.calls != 0 {
		t.Fatalf("version mismatch rejected after %d hash call(s)", counter.calls)
	}
}

// swapDigest installs a test digest seam and returns the restore function.
func swapDigest(t *testing.T, fn archiveDigestFn) {
	t.Helper()
	if fn == nil {
		archiveDigest = defaultArchiveDigest
		return
	}
	archiveDigest = fn
}

// TestClosedResultPanicThrough pins the recover guard end-to-end through a
// public façade: removing the guard reddens this leg (the panic escapes).
func TestClosedResultPanicThrough(t *testing.T) {
	obj, keys, expected := loadExportCase(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped VerifyAnchoredExport: %v", r)
		}
	}()
	swapDigest(t, panickingDigest{}.digest)
	defer swapDigest(t, nil)
	if _, err := VerifyAnchoredExport(obj, keys, expected); err != ErrInvalid {
		t.Fatalf("injected mid-verify panic must surface as ErrInvalid, got %v", err)
	}
}

// TestMemberOrderPreservedInternal pins the ordered-algebra property the
// corpus cannot express through JSON expected values.
func TestMemberOrderPreservedInternal(t *testing.T) {
	val, err := JsonDecode([]byte(`{"z":1,"a":2,"m":3}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, ok := val.(Obj)
	if !ok {
		t.Fatal("not an object")
	}
	want := []string{"z", "a", "m"}
	for i, m := range obj {
		if m.Key != want[i] {
			t.Fatalf("member %d = %s, want %s (source order must be preserved)", i, m.Key, want[i])
		}
	}
}

// parseExportCase extracts the verify-anchored-export-valid case into the
// internal input structs (white-box loader for the work-pin legs).
func parseExportCase(raw []byte) (ArchivedObject, HistoricalKeyChain, ExpectedAnchoredExport, error) {
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Chunks []string `json:"chunks"`
				Keys   []struct {
					KeyID       string `json:"key_id"`
					PublicKey   string `json:"public_key"`
					ValidFrom   int64  `json:"valid_from"`
					ValidBefore int64  `json:"valid_before"`
				} `json:"keys"`
				Version  string `json:"version"`
				Expected struct {
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
		return ArchivedObject{}, nil, ExpectedAnchoredExport{}, err
	}
	for _, c := range cf.Cases {
		if c.ID != "verify-anchored-export-valid" {
			continue
		}
		chunks := make([][]byte, 0, len(c.Input.Chunks))
		for _, ch := range c.Input.Chunks {
			raw, err := Base64urlDecode(ch)
			if err != nil {
				return ArchivedObject{}, nil, ExpectedAnchoredExport{}, err
			}
			chunks = append(chunks, raw)
		}
		keys := make(HistoricalKeyChain, 0, len(c.Input.Keys))
		for _, k := range c.Input.Keys {
			pk, err := Base64urlDecode(k.PublicKey)
			if err != nil {
				return ArchivedObject{}, nil, ExpectedAnchoredExport{}, err
			}
			keys = append(keys, HistoricalPublicKey{KeyID: k.KeyID, PublicKey: pk, ValidFrom: k.ValidFrom, ValidBefore: k.ValidBefore})
		}
		e := c.Input.Expected
		expected := ExpectedAnchoredExport{
			Digest:        e.Digest,
			ObjectVersion: e.ObjectVersion,
			Chain: ExpectedChain{
				ChainID: e.Chain.ChainID, FirstSequence: e.Chain.FirstSequence,
				LastSequence: e.Chain.LastSequence, PreviousHash: e.Chain.PreviousHash,
				LastHash: e.Chain.LastHash, RowCount: e.Chain.RowCount,
			},
			StartAnchor: ExpectedAnchor{
				AnchorID: e.StartAnchor.AnchorID, ChainID: e.StartAnchor.ChainID,
				KeyID: e.StartAnchor.KeyID, Sequence: e.StartAnchor.Sequence,
				AnchoredAt: e.StartAnchor.AnchoredAt, ChainHash: e.StartAnchor.ChainHash,
				KeyFingerprint: e.StartAnchor.KeyFingerprint,
			},
			EndAnchor: ExpectedAnchor{
				AnchorID: e.EndAnchor.AnchorID, ChainID: e.EndAnchor.ChainID,
				KeyID: e.EndAnchor.KeyID, Sequence: e.EndAnchor.Sequence,
				AnchoredAt: e.EndAnchor.AnchoredAt, ChainHash: e.EndAnchor.ChainHash,
				KeyFingerprint: e.EndAnchor.KeyFingerprint,
			},
		}
		for _, tr := range e.Transitions {
			expected.Transitions = append(expected.Transitions, ExpectedKeyTransition{
				TransitionID: tr.TransitionID, ChainID: tr.ChainID,
				CurrentKeyID: tr.CurrentKeyID, NextKeyID: tr.NextKeyID,
				EffectiveAt: tr.EffectiveAt, CurrentKeyFingerprint: tr.CurrentKeyFingerprint,
				NextKeyFingerprint: tr.NextKeyFingerprint,
			})
		}
		return ArchivedObject{Chunks: chunks, Version: c.Input.Version}, keys, expected, nil
	}
	return ArchivedObject{}, nil, ExpectedAnchoredExport{}, ErrInvalid
}

// TestCanonicalGateUnit pins the anchor canonical-form gate at the unit
// level: on both macro paths (verify: Ed25519; encode: archive digest) the
// gate's verdict is subsumed by a later check — the ADR 0017 subsumption
// pattern — so the per-clause red-capable form is this direct unit leg.
// Removing the canonicalSegment calls from parseAnchorCompactGated reddens
// exactly the non-canonical assertion.
func TestCanonicalGateUnit(t *testing.T) {
	compact := anchorCompactCorpus
	parts := strings.Split(compact, ".")
	payload, err := Base64urlDecode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	b := BoundsMaximum()
	// canonical corpus anchor parses through the gated codec
	if _, err := parseAnchorCompactGated(compact, b); err != nil {
		t.Fatalf("canonical corpus anchor must parse: %v", err)
	}
	// same members, non-canonical order: rejected by the gate alone
	swapped := strings.Replace(string(payload),
		`{"anchor_id":"urn:example:anchor:start","anchored_at":1000,`,
		`{"anchored_at":1000,"anchor_id":"urn:example:anchor:start",`, 1)
	if swapped == string(payload) {
		t.Fatal("fixture substitution failed")
	}
	nonCanonical := parts[0] + "." + Base64urlEncode([]byte(swapped)) + "." + parts[2]
	if _, err := parseAnchorCompactGated(nonCanonical, b); err == nil {
		t.Fatal("non-canonical anchor payload must be rejected by the gated parse")
	}
}

const anchorCompactCorpus = "eyJhbGciOiJFZERTQSIsImtpZCI6ImFyY2hpdmUtYSIsInR5cCI6ImJhK2NoYWluLWFuY2hvciJ9.eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6c3RhcnQiLCJhbmNob3JlZF9hdCI6MTAwMCwiY2hhaW5faGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwia2V5X2ZpbmdlcnByaW50IjoibzdnbDByZHhTUFUtcVhibU5vZDRSQWtWNXBVamFCNDdKaFBBNDNod0tQOCIsInNlcXVlbmNlIjowLCJ2IjoxfQ.Falux3uXvUy7PqELqVP_UNWWr3FDT6jUxT7IwtbHY27dqPqHxdsUrSvE216PAtOku9jjPCgoWHYds8YMLD4gAQ"
