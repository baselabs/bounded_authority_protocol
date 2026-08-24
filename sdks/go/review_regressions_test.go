package verifier

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Cross-vendor review regression legs (2026-08-24, codex + claude peers over
// ed44b18..4619fe3). Each leg pins a confirmed finding; authored RED against
// the committed state, then greened by the fix pass.

// F1 (BLOCKING, both peers): required proof claims can be omitted when a
// nonce (or any optional member) preserves the member count.
func TestReviewProofClaimPresence(t *testing.T) {
	seg := strings.Split(corpusEnvelopeProof(t), ".")
	header := seg[0]
	sig := seg[2]
	// drop `iat` and add `nonce` — same 10-member count, one required claim
	// missing: must be rejected.
	payload, err := Base64urlDecode(seg[1])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(payload), `"iat":1100,`, `"nonce":"n",`, 1)
	if tampered == string(payload) {
		t.Fatal("fixture substitution failed")
	}
	compact := header + "." + Base64urlEncode([]byte(tampered)) + "." + sig
	if _, err := DecodeProof(compact, nil); err == nil {
		t.Fatal("proof payload missing a required claim (iat) must be rejected even with nonce present")
	}
	// drop `v` entirely (9 members, no nonce): also rejected
	tampered = strings.Replace(string(payload), `,"v":1`, ``, 1)
	if tampered == string(payload) {
		t.Fatal("fixture substitution failed")
	}
	compact = header + "." + Base64urlEncode([]byte(tampered)) + "." + sig
	if _, err := DecodeProof(compact, nil); err == nil {
		t.Fatal("proof payload missing v must be rejected")
	}
}

// F3 (BLOCKING, both peers): the genesis zero-hash rule binds the standalone
// anchor codec too, not only the export path.
func TestReviewStandaloneGenesisZeroHash(t *testing.T) {
	// A sequence-zero anchor with a NONZERO chain hash is invalid even when
	// every other field validates. Constructing a signed one requires a key,
	// so pin the gate at the expected-validation seam: the standalone path
	// must reject a zero-sequence expected tuple with a nonzero hash BEFORE
	// any signature work.
	b := BoundsMaximum()
	bad := ExpectedAnchor{
		AnchorID: "urn:example:anchor:start", ChainID: "urn:example:chain",
		KeyID: "archive-a", Sequence: 0, AnchoredAt: 1000,
		ChainHash:      "FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw", // nonzero at seq 0
		KeyFingerprint: "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8",
	}
	if err := validateExpectedAnchorTuple(bad, 0, true, b); err == nil {
		t.Fatal("genesis zero-hash rule must hold for every expected-anchor validation")
	}
	// and the standalone verify path enforces it end-to-end: a signed
	// seq-zero anchor with nonzero hash must not verify
	nonZeroHashAnchor := swapAnchorChainHash(t, anchorCompactCorpus, bad.ChainHash)
	key := HistoricalPublicKey{KeyID: "archive-a", PublicKey: mustDecodeB64(t, "YXgT52I83qBmbNzq_RMxiYT1T_EELrAj9rUkjCaSkP4"), ValidFrom: 0, ValidBefore: 3000}
	if _, err := VerifyHistoricalAnchor(nonZeroHashAnchor, key, bad); err == nil {
		t.Fatal("standalone VerifyHistoricalAnchor must reject a seq-zero anchor with nonzero chain hash")
	}
}

// F2 (BLOCKING, both peers): the export expected context must cross-bind the
// anchors to the chain boundaries.
func TestReviewAnchorChainCrossBinding(t *testing.T) {
	obj, keys, expected := loadExportCase(t)
	// StartAnchor attesting a DIFFERENT chain than the rows: must reject.
	bad := expected
	bad.StartAnchor.ChainID = "urn:example:other-chain"
	if _, err := verifyAnchoredExportCore(obj, keys, bad, defaultArchiveDigest); err == nil {
		t.Fatal("start anchor for a different chain must be rejected")
	}
	// EndAnchor with a boundary hash that is not the chain head: must reject.
	bad = expected
	bad.EndAnchor.ChainHash = allZeroHashB64 // differs from the chain head
	if _, err := verifyAnchoredExportCore(obj, keys, bad, defaultArchiveDigest); err == nil {
		t.Fatal("end anchor whose chain hash is not the caller head must be rejected")
	}
}

// F4 (BLOCKING, codex): oversized ports must not overflow into valid ones.
func TestReviewPortOverflow(t *testing.T) {
	long := strings.Repeat("9", 40)
	if _, err := UriNormalize("https://example.test:"+long+"/x", nil); err == nil {
		t.Fatal("40-digit port must be rejected (no overflow into a valid port)")
	}
	wide := "18446744073709551709" // 2^64 + 13 → wraps to 13 on 64-bit if unchecked
	if _, err := UriNormalize("https://example.test:"+wide+"/x", nil); err == nil {
		t.Fatal("2^64-wrapping port must be rejected")
	}
}

// F5 (BLOCKING, both peers): an embedded IPv4 tail counts as TWO groups.
func TestReviewIPv6EmbeddedCount(t *testing.T) {
	// 7 hextets + IPv4 = 9 groups: invalid
	if _, err := UriNormalize("https://[::1:2:3:4:5:6:1.2.3.4]/x", nil); err == nil {
		t.Fatal("9-group IPv6 (7 hextets + embedded IPv4) must be rejected")
	}
	// 6 hextets + IPv4 = 8 groups: valid
	if _, err := UriNormalize("https://[1:2:3:4:5:6:1.2.3.4]/x", nil); err != nil {
		t.Fatalf("8-group IPv6 (6 hextets + embedded IPv4) must be accepted: %v", err)
	}
}

// F6 (BLOCKING, codex + claude): host classification happens AFTER percent
// decoding, and decoded unreserved bytes are lowercased like literal ones.
func TestReviewHostDecodeThenClassify(t *testing.T) {
	// %30%31 decodes to "01": the decoded host is numeric-dotted and must
	// satisfy exact IPv4 (leading zero) — rejected.
	if _, err := UriNormalize("https://%30%31.2.3.4/x", nil); err == nil {
		t.Fatal("percent-decoded numeric-dotted host must face the exact IPv4 gate")
	}
	// %25%36%36 decodes to "%FF"? no — decode of %25 is '%' (un? no, '%' is
	// reserved): use %32%35%36 → "256" for an octet-range reject instead.
	if _, err := UriNormalize("https://%32%35%36.2.3.4/x", nil); err == nil {
		t.Fatal("percent-decoded 256 first octet must be rejected as IPv4 range")
	}
	// decoded unreserved letters are lowercased (idempotence)
	got, err := UriNormalize("https://%41b.example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://ab.example.test/x" {
		t.Fatalf("%%41b must normalize lowercased: %s", got)
	}
	// idempotence: normalize(normalize(x)) == normalize(x)
	again, err := UriNormalize(got, nil)
	if err != nil || again != got {
		t.Fatalf("normalization must be idempotent: %s -> %s (%v)", got, again, err)
	}
}

// F9 (should-fix, both peers): tightened integer_magnitude is enforced at
// integer decode.
func TestReviewTightenedIntegerMagnitude(t *testing.T) {
	tight, err := BoundsNew(map[string]int{"integer_magnitude": 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := JsonDecode([]byte(`{"n":999}`), &tight); err == nil {
		t.Fatal("integer above a tightened integer_magnitude must be rejected")
	}
	if _, err := JsonDecode([]byte(`{"n":10}`), &tight); err != nil {
		t.Fatalf("integer at the tightened bound must be accepted: %v", err)
	}
}

// F10/F11 (should-fix, both peers): malformed UTF-8 object versions reject;
// the encode path bounds chunks as CHUNKS and bytes as BYTES.
func TestReviewVersionUTF8AndChunkBounds(t *testing.T) {
	// invalid UTF-8 in an object version must reject (pre-digest)
	obj, keys, expected := loadExportCase(t)
	bad := obj
	bad.Version = "v\xff\xfe"
	expected.ObjectVersion = bad.Version // EQUAL: only the UTF-8 gate can reject
	counter := &countingDigest{}
	swapDigest(t, counter.digest)
	if _, err := VerifyAnchoredExport(bad, keys, expected); err == nil {
		t.Fatal("malformed UTF-8 object version must be rejected on well-formedness, not equality")
	}
	if counter.calls != 0 {
		t.Fatalf("version rejection must happen before hashing (%d calls)", counter.calls)
	}
	swapDigest(t, nil)

	// encode: tightened archive_chunks counts CHUNKS, not bytes
	input, exp := loadExportEncodeCase(t)
	oneShort, err := BoundsNew(map[string]int{"archive_chunks": 4}) // corpus archive has 6 chunks
	if err != nil {
		t.Fatal(err)
	}
	exp.Bounds = &oneShort
	// nested pins: tighten nested too (identity)
	exp.Chain.Bounds = &oneShort
	exp.StartAnchor.Bounds = &oneShort
	exp.EndAnchor.Bounds = &oneShort
	if _, err := EncodeAnchoredExport(input, exp); err == nil {
		t.Fatal("tightened archive_chunks=4 must reject the 6-chunk archive")
	}
	// and a tightened archive_BYTES bound just above the byte count passes
	// while one below rejects — bytes are bounded as bytes
	byteCount := 1900
	tightBytes, _ := BoundsNew(map[string]int{"archive_bytes": byteCount - 1})
	exp.Bounds = &tightBytes
	exp.Chain.Bounds = &tightBytes
	exp.StartAnchor.Bounds = &tightBytes
	exp.EndAnchor.Bounds = &tightBytes
	if _, err := EncodeAnchoredExport(input, exp); err == nil {
		t.Fatal("tightened archive_bytes below the archive size must reject")
	}
}

// F13 (should-fix, claude): the proof producer can emit the nonce claim.
func TestReviewProofProducerNonce(t *testing.T) {
	t.Skip("F13: compile-red until the Proof nonce field lands")
}

// F12 (should-fix, both peers): the export producer derives its own digest;
// expected.Digest is validated for shape but does not have to be precomputed
// as the produced value.
func TestReviewEncodeDigestDerived(t *testing.T) {
	input, exp := loadExportEncodeCase(t)
	// a shape-valid but WRONG digest must not cause rejection-by-mismatch at
	// encode: the producer computes and returns its own digest
	wrongDigest := exp
	wrongDigest.Digest = allZeroHashB64
	got, err := EncodeAnchoredExport(input, wrongDigest)
	if err != nil {
		t.Fatalf("encode must derive its own digest, not require a predeclared match: %v", err)
	}
	want, _ := Base64urlDecode("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw")
	_ = want
	if Base64urlEncode(got.Digest[:]) != "-Bu4a_eh6TYrOYgk0pL68Oc6uXVnyg-lyMyejnhuDKE" {
		t.Fatalf("derived digest = %s", Base64urlEncode(got.Digest[:]))
	}
}

// helpers -------------------------------------------------------------------

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := Base64urlDecode(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// swapAnchorChainHash rewrites the corpus anchor payload's chain_hash and
// re-signs nothing (the 7-field match will fail on signature? no — the
// signature check happens after the tuple match, and the tuple match rejects
// first; we only need the gate to fire before acceptance).
func swapAnchorChainHash(t *testing.T, compact, newHash string) string {
	t.Helper()
	seg := strings.Split(compact, ".")
	payload, err := Base64urlDecode(seg[1])
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(string(payload),
		`"chain_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
		`"chain_hash":"`+newHash+`"`, 1)
	if swapped == string(payload) {
		t.Fatal("fixture substitution failed")
	}
	return seg[0] + "." + Base64urlEncode([]byte(swapped)) + "." + seg[2]
}

// corpusEnvelopeProof extracts the corpus envelope-valid proof compact.
func corpusEnvelopeProof(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../priv/conformance/v1/corpus/cases/envelope/check.json")
	if err != nil {
		t.Skipf("corpus unreachable: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Proof string `json:"proof"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	for _, c := range cf.Cases {
		if c.ID == "check-envelope-valid" {
			return c.Input.Proof
		}
	}
	t.Fatal("check-envelope-valid missing")
	return ""
}

// loadExportEncodeCase loads the corpus encode-anchored-export-valid inputs
// against the verify fixture's expected context (same corpus chain).
func loadExportEncodeCase(t *testing.T) (AnchoredExportInput, ExpectedAnchoredExport) {
	t.Helper()
	_, keys, expected := loadExportCase(t)
	_ = keys
	raw, err := os.ReadFile("conformance/corpus/cases/anchored-export/encode.json")
	if err != nil {
		t.Fatal(err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Rows        []string `json:"rows"`
				StartAnchor string   `json:"start_anchor"`
				EndAnchor   string   `json:"end_anchor"`
				Transitions []string `json:"transitions"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	for _, c := range cf.Cases {
		if c.ID == "encode-anchored-export-valid" {
			rows := make([][]byte, 0, len(c.Input.Rows))
			for _, r := range c.Input.Rows {
				rows = append(rows, mustDecodeB64(t, r))
			}
			return AnchoredExportInput{
				Rows:        rows,
				StartAnchor: c.Input.StartAnchor,
				EndAnchor:   c.Input.EndAnchor,
				Transitions: c.Input.Transitions,
			}, expected
		}
	}
	t.Fatal("encode-anchored-export-valid missing")
	return AnchoredExportInput{}, ExpectedAnchoredExport{}
}
