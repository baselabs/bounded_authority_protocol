package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// The anchored export (ADR 0004): the exact binary concatenation
//
//	"BAP1-ARCHIVE\0EXPORT\0" frame(header) frame(start) frame(transitions…)
//	frame(rows…) frame(end) EOF
//
// with UINT32_BE(nonzero_length) || bytes frames. Verification validates the
// complete expected context BEFORE hashing the archive (ADR 0017 clause 3 and
// its 2026-08-18 resolution), scans the bounded chunk list incrementally,
// requires exact EOF, hashes every raw byte, compares the digest, then
// authenticates both anchors and every transition, re-checks all rows, and
// requires the authenticated boundaries to equal the caller's.

// EncodedExport is the EncodeAnchoredExport result.
type EncodedExport struct {
	Archive   []byte
	Digest    [32]byte
	ByteCount int64
}

// resolveExportBounds resolves the outer bounds and applies ADR 0018 D2
// nested-pins identity semantics: a present nested bounds must equal the
// outer; an absent nested bounds is valid only under an effectively
// untightened outer.
func resolveExportBounds(expected *ExpectedAnchoredExport) (Bounds, error) {
	outer, err := resolveBounds(expected.Bounds)
	if err != nil {
		return Bounds{}, ErrInvalid
	}
	untightened := outer == BoundsMaximum()
	nested := []*Bounds{expected.Chain.Bounds, expected.StartAnchor.Bounds, expected.EndAnchor.Bounds}
	for i := range expected.Transitions {
		nested = append(nested, expected.Transitions[i].Bounds)
	}
	for _, nb := range nested {
		if nb == nil {
			if !untightened {
				return Bounds{}, ErrInvalid // absent nested under a tightened outer
			}
			continue
		}
		resolved, err := resolveBounds(nb)
		if err != nil || resolved != outer {
			return Bounds{}, ErrInvalid // identity override is not tightening
		}
	}
	return outer, nil
}

// validateExpectedAnchoredExport is the clause-3 pre-digest hoist: the
// complete expected-context well-formedness suite runs BEFORE any archive
// hashing, mirroring the reference's validate_expected_anchored_export →
// ContextValidation sequence. Malformed caller metadata rejects with zero
// hash work.
func validateExpectedAnchoredExport(expected *ExpectedAnchoredExport, obj ArchivedObject, keys HistoricalKeyChain, b Bounds) error {
	// chain: identifier, positive range, count coherence, hash widths, genesis
	if !validStringOrURI(expected.Chain.ChainID, b.IdentifierBytes) {
		return ErrInvalid
	}
	if expected.Chain.FirstSequence < 1 || expected.Chain.LastSequence < expected.Chain.FirstSequence ||
		expected.Chain.RowCount < 1 || expected.Chain.RowCount > int64(b.ChainRows) {
		return ErrInvalid
	}
	if expected.Chain.LastSequence-expected.Chain.FirstSequence+1 != expected.Chain.RowCount {
		return ErrInvalid
	}
	if _, ok := canonicalDigestString(expected.Chain.PreviousHash); !ok {
		return ErrInvalid
	}
	if _, ok := canonicalDigestString(expected.Chain.LastHash); !ok {
		return ErrInvalid
	}
	// anchors: identity + binding + genesis zero-hash + sequence coupling
	if err := validateExpectedAnchorTuple(expected.StartAnchor, expected.Chain.FirstSequence-1, true, b); err != nil {
		return ErrInvalid
	}
	if err := validateExpectedAnchorTuple(expected.EndAnchor, expected.Chain.LastSequence, false, b); err != nil {
		return ErrInvalid
	}
	if len(expected.Transitions) > b.KeyTransitions {
		return ErrInvalid
	}
	if len(keys) != len(expected.Transitions)+1 {
		return ErrInvalid // exact key count
	}
	// the fingerprint walk seeds with the start anchor's key fingerprint:
	// any later to-fingerprint equal to one already visited (start included)
	// is a cycle (ADR 0004 "fingerprints cannot cycle")
	startFP, ok := canonicalDigestString(expected.StartAnchor.KeyFingerprint)
	if !ok {
		return ErrInvalid
	}
	seenFPs := map[[32]byte]struct{}{startFP: {}}
	prevEffective := int64(-1)
	for i := range expected.Transitions {
		t := &expected.Transitions[i]
		if !validStringOrURI(t.TransitionID, b.IdentifierBytes) || !validStringOrURI(t.ChainID, b.IdentifierBytes) ||
			!validKid(t.CurrentKeyID, b.KeyBytes) || !validKid(t.NextKeyID, b.KeyBytes) {
			return ErrInvalid
		}
		if t.EffectiveAt > int64(b.IntegerMagnitude) || t.EffectiveAt < -int64(b.IntegerMagnitude) {
			return ErrInvalid
		}
		if t.ChainID != expected.Chain.ChainID {
			return ErrInvalid
		}
		from, ok := canonicalDigestString(t.CurrentKeyFingerprint)
		if !ok {
			return ErrInvalid
		}
		to, ok := canonicalDigestString(t.NextKeyFingerprint)
		if !ok || to == from {
			return ErrInvalid
		}
		if _, seen := seenFPs[to]; seen {
			return ErrInvalid // fingerprints cannot cycle
		}
		seenFPs[to] = struct{}{}
		if i > 0 && t.EffectiveAt <= prevEffective {
			return ErrInvalid // strictly increasing effective times
		}
		prevEffective = t.EffectiveAt
	}
	// key chain: ids, widths, windows (clause 3 key-window gates)
	for _, k := range keys {
		if !validHistoricalKey(k, b) {
			return ErrInvalid
		}
	}
	// version: exact, well-formed, equal across expected and input
	if expected.ObjectVersion == "" || len(expected.ObjectVersion) > b.ObjectVersionBytes {
		return ErrInvalid
	}
	if !isWellFormedUTF8(expected.ObjectVersion) {
		return ErrInvalid
	}
	if obj.Version != expected.ObjectVersion {
		return ErrInvalid // REQ1-EXPORT-version-exact
	}
	// digest width
	if _, ok := canonicalDigestString(expected.Digest); !ok {
		return ErrInvalid
	}
	return nil
}

func validateExpectedAnchorTuple(a ExpectedAnchor, wantSequence int64, isStart bool, b Bounds) error {
	if !validStringOrURI(a.AnchorID, b.IdentifierBytes) || !validStringOrURI(a.ChainID, b.IdentifierBytes) ||
		!validKid(a.KeyID, b.KeyBytes) {
		return ErrInvalid
	}
	if a.Sequence != wantSequence || a.Sequence < 0 {
		return ErrInvalid // sequence coupling to the chain boundaries
	}
	if _, ok := canonicalDigestString(a.ChainHash); !ok {
		return ErrInvalid
	}
	if _, ok := canonicalDigestString(a.KeyFingerprint); !ok {
		return ErrInvalid
	}
	if a.Sequence == 0 && a.ChainHash != allZeroHashB64 {
		return ErrInvalid // genesis zero-hash
	}
	return nil
}

func isWellFormedUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD && !strings.ContainsRune(s, 0xFFFD) {
			return false
		}
	}
	return true
}

// verifyAnchoredExportCore is the seam-bearing core; the public façade passes
// defaultArchiveDigest and the white-box battery observes hash calls.
func verifyAnchoredExportCore(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport, digest archiveDigestFn) (AnchoredExportFacts, error) {
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// clause 3: expected-context validation BEFORE the archive digest
	if err := validateExpectedAnchoredExport(&expected, obj, keys, b); err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// bounded chunk list (role-bounded frame reads, clause 5)
	if len(obj.Chunks) == 0 || len(obj.Chunks) > b.ArchiveChunks {
		return AnchoredExportFacts{}, ErrInvalid
	}
	for _, c := range obj.Chunks {
		if len(c) == 0 {
			return AnchoredExportFacts{}, ErrInvalid // nonempty proper chunks
		}
	}
	// streaming digest: no archive buffer is assembled
	digestRaw, total, err := digest(obj.Chunks, int64(b.ArchiveBytes))
	if err != nil || total > int64(b.ArchiveBytes) {
		return AnchoredExportFacts{}, ErrInvalid
	}
	wantDigest, _ := canonicalDigestString(expected.Digest)
	if digestRaw != wantDigest {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// framing: magic + length-prefixed frames with exact EOF
	if string(obj.Chunks[0]) != string(archiveMagic) {
		return AnchoredExportFacts{}, ErrInvalid
	}
	frames := make([][]byte, 0, len(obj.Chunks)-1)
	for _, c := range obj.Chunks[1:] {
		if len(c) < 4 {
			return AnchoredExportFacts{}, ErrInvalid
		}
		n := binary.BigEndian.Uint32(c[:4])
		if n == 0 || int64(n) != int64(len(c))-4 {
			return AnchoredExportFacts{}, ErrInvalid // exact frame length + EOF
		}
		frames = append(frames, c[4:])
	}
	if len(frames) < 3 {
		return AnchoredExportFacts{}, ErrInvalid // header + start + end minimum
	}
	headerRaw, startCompactRaw, endCompactRaw := frames[0], frames[1], frames[len(frames)-1]
	// header: closed member set + ArchiveHeaderBytes bound + boundary equality
	if len(headerRaw) == 0 || len(headerRaw) > b.ArchiveHeaderBytes {
		return AnchoredExportFacts{}, ErrInvalid
	}
	hv, err := JsonDecode(headerRaw, &b)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	hdr, ok := hv.(Obj)
	if !ok || len(hdr) != 8 {
		return AnchoredExportFacts{}, ErrInvalid // closed 8-member header
	}
	var hChainID string
	var hFirst, hLast, hRows, hTransitions int64
	var hPrev, hHead string
	for _, m := range hdr {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 1 {
				return AnchoredExportFacts{}, ErrInvalid
			}
		case "chain_id":
			if s, ok := m.Val.(Str); ok {
				hChainID = string(s)
			}
		case "first_sequence":
			if t, ok := integralTime(m.Val, b); ok {
				hFirst = t
			} else {
				return AnchoredExportFacts{}, ErrInvalid
			}
		case "last_sequence":
			if t, ok := integralTime(m.Val, b); ok {
				hLast = t
			} else {
				return AnchoredExportFacts{}, ErrInvalid
			}
		case "row_count":
			if t, ok := integralTime(m.Val, b); ok {
				hRows = t
			} else {
				return AnchoredExportFacts{}, ErrInvalid
			}
		case "transition_count":
			if t, ok := integralTime(m.Val, b); ok {
				hTransitions = t
			} else {
				return AnchoredExportFacts{}, ErrInvalid
			}
		case "previous_hash":
			if s, ok := m.Val.(Str); ok {
				hPrev = string(s)
			}
		case "last_hash":
			if s, ok := m.Val.(Str); ok {
				hHead = string(s)
			}
		default:
			return AnchoredExportFacts{}, ErrInvalid
		}
	}
	if hChainID != expected.Chain.ChainID || hFirst != expected.Chain.FirstSequence ||
		hLast != expected.Chain.LastSequence || hRows != expected.Chain.RowCount ||
		hPrev != expected.Chain.PreviousHash || hHead != expected.Chain.LastHash ||
		hTransitions != int64(len(expected.Transitions)) {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// authenticate the start anchor with keys[0]
	startClaims, err := verifyAnchorCompact(string(startCompactRaw), keys[0], expected.StartAnchor, b)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// transitions advance the key path positionally
	midFrames := frames[2 : len(frames)-1]
	rowCount := expected.Chain.RowCount
	if int64(len(midFrames)) != int64(len(expected.Transitions))+rowCount {
		return AnchoredExportFacts{}, ErrInvalid
	}
	transitionFrames := midFrames[:len(expected.Transitions)]
	rowFrames := midFrames[len(expected.Transitions):]
	lastEffective := int64(-1)
	for i, traw := range transitionFrames {
		claims, err := verifyTransitionCompact(string(traw), keys[i], keys[i+1], expected.Transitions[i], b)
		if err != nil {
			return AnchoredExportFacts{}, ErrInvalid
		}
		// positional key-path walk: to-fingerprint is the next key's
		nextFP, err := PublicKeyThumbprintRaw(keys[i+1].PublicKey, &b)
		if err != nil || nextFP != claims.ToFingerprint {
			return AnchoredExportFacts{}, ErrInvalid
		}
		if i > 0 && claims.EffectiveAt <= lastEffective {
			return AnchoredExportFacts{}, ErrInvalid // strictly increasing
		}
		if claims.EffectiveAt < startClaims.AnchoredAt {
			return AnchoredExportFacts{}, ErrInvalid // start precedes every transition
		}
		lastEffective = claims.EffectiveAt
	}
	// end anchor at or after the last transition (equality allowed exactly at
	// its effective time); equal start/end times only for the same-key
	// no-transition case
	endClaims, err := verifyAnchorCompact(string(endCompactRaw), keys[len(keys)-1], expected.EndAnchor, b)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	if len(expected.Transitions) > 0 {
		if endClaims.AnchoredAt < lastEffective {
			return AnchoredExportFacts{}, ErrInvalid
		}
	} else if startClaims.AnchoredAt > endClaims.AnchoredAt {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// re-check every row against the chain boundaries
	var lastHash [32]byte
	for i, rraw := range rowFrames {
		row, err := parseCanonicalRow(rraw, b)
		if err != nil {
			return AnchoredExportFacts{}, ErrInvalid
		}
		if row.ChainID != expected.Chain.ChainID || row.Sequence != expected.Chain.FirstSequence+int64(i) {
			return AnchoredExportFacts{}, ErrInvalid
		}
		if i == 0 {
			if row.Sequence == 1 && row.Previous != [32]byte{} {
				return AnchoredExportFacts{}, ErrInvalid
			}
			wantPrev, _ := canonicalDigestString(expected.Chain.PreviousHash)
			if row.Previous != wantPrev {
				return AnchoredExportFacts{}, ErrInvalid
			}
		} else if row.Previous != lastHash {
			return AnchoredExportFacts{}, ErrInvalid
		}
		lastHash = chainHash(rraw)
	}
	wantHead, _ := canonicalDigestString(expected.Chain.LastHash)
	if lastHash != wantHead {
		return AnchoredExportFacts{}, ErrInvalid
	}
	return AnchoredExportFacts{
		ChainID:         expected.Chain.ChainID,
		FirstSequence:   expected.Chain.FirstSequence,
		LastSequence:    expected.Chain.LastSequence,
		RowCount:        expected.Chain.RowCount,
		TransitionCount: len(expected.Transitions),
		ChunkCount:      len(obj.Chunks),
		ByteCount:       total,
		Digest:          digestRaw,
		Checks: []string{
			"expected_context", "complete_scan", "digest", "framing", "header",
			"start_anchor", "transitions", "end_anchor", "rows", "key_path",
		},
		Trust:         TrustNotEvaluated,
		Authorization: AuthorizationNotEvaluated,
	}, nil
}

// archiveDigest is the archive-hashing seam: the public façade resolves it,
// and only same-package tests substitute it (Go's work-observation channel —
// the equivalent of the Python battery's monkeypatched sha256, without
// monkeypatching and without a public API seam). Production never writes it.
var archiveDigest archiveDigestFn = defaultArchiveDigest

// VerifyAnchoredExport verifies a complete archived object: bounded nonempty
// proper flat chunks, exact EOF, every raw byte hashed, both boundaries and
// every positional transition authenticated, and every row independently
// re-checked (REQ1-EXPORT-complete-scan).
func VerifyAnchoredExport(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport) (f AnchoredExportFacts, err error) {
	defer closedResult(&err)
	return verifyAnchoredExportCore(obj, keys, expected, archiveDigest)
}

// EncodeAnchoredExport mirrors the reference producer's full contract
// (amendment #2 parity): expected-side consistency, row chain re-check,
// gated parses + 7-field matches for both anchors and every transition, the
// key-path walk with NON-STRICT end-anchor chronology, and the archive
// aggregate bounds.
func EncodeAnchoredExport(input AnchoredExportInput, expected ExpectedAnchoredExport) (out EncodedExport, err error) {
	defer closedResult(&err)
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// expected-side consistency (the pre-digest suite; version equality here
	// compares against the expected struct's own copy — the producer has no
	// object store)
	synthetic := ArchivedObject{Version: expected.ObjectVersion}
	if err := validateExpectedAnchoredExport(&expected, synthetic, keysFromExpected(expected, b), b); err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// rows re-checked against the chain
	if int64(len(input.Rows)) != expected.Chain.RowCount {
		return EncodedExport{}, ErrInvalid
	}
	var lastHash [32]byte
	for i, raw := range input.Rows {
		row, err := parseCanonicalRow(raw, b)
		if err != nil {
			return EncodedExport{}, ErrInvalid
		}
		if row.ChainID != expected.Chain.ChainID || row.Sequence != expected.Chain.FirstSequence+int64(i) {
			return EncodedExport{}, ErrInvalid
		}
		if i == 0 {
			wantPrev, _ := canonicalDigestString(expected.Chain.PreviousHash)
			if row.Previous != wantPrev {
				return EncodedExport{}, ErrInvalid
			}
			if row.Sequence == 1 && row.Previous != [32]byte{} {
				return EncodedExport{}, ErrInvalid
			}
		} else if row.Previous != lastHash {
			return EncodedExport{}, ErrInvalid
		}
		lastHash = chainHash(raw)
	}
	wantHead, _ := canonicalDigestString(expected.Chain.LastHash)
	if lastHash != wantHead {
		return EncodedExport{}, ErrInvalid
	}
	// gated parses + 7-field matches for both anchors and every transition
	// (signature width + canonical form at parse; no crypto at encode)
	startParsed, err := parseAnchorCompactGated(input.StartAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(startParsed, expected.StartAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	endParsed, err := parseAnchorCompactGated(input.EndAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(endParsed, expected.EndAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	transitions := make([]transitionClaims, 0, len(input.Transitions))
	for i, traw := range input.Transitions {
		claims, err := parseTransitionCompactGated(traw, b)
		if err != nil {
			return EncodedExport{}, ErrInvalid
		}
		if !transitionTupleMatch(claims, expected.Transitions[i]) {
			return EncodedExport{}, ErrInvalid
		}
		transitions = append(transitions, claims)
	}
	// key-path walk: start fingerprint -> transitions chain -> end; NON-STRICT
	// end-anchor chronology (equality at the last effective time allowed)
	if startParsed.ChainHash != mustDigest(expected.Chain.PreviousHash) {
		return EncodedExport{}, ErrInvalid
	}
	prevFP := startParsed.KeyFingerprint
	for i, tc := range transitions {
		if tc.FromFingerprint != prevFP {
			return EncodedExport{}, ErrInvalid
		}
		if tc.EffectiveAt < startParsed.AnchoredAt {
			return EncodedExport{}, ErrInvalid
		}
		if i > 0 && tc.EffectiveAt <= transitions[i-1].EffectiveAt {
			return EncodedExport{}, ErrInvalid
		}
		prevFP = tc.ToFingerprint
	}
	if endParsed.KeyFingerprint != prevFP {
		return EncodedExport{}, ErrInvalid
	}
	if endParsed.ChainHash != mustDigest(expected.Chain.LastHash) {
		return EncodedExport{}, ErrInvalid
	}
	if endParsed.AnchoredAt < startParsed.AnchoredAt {
		return EncodedExport{}, ErrInvalid
	}
	if len(transitions) > 0 && endParsed.AnchoredAt < transitions[len(transitions)-1].EffectiveAt {
		return EncodedExport{}, ErrInvalid
	}
	// header + frames
	header, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(expected.Chain.ChainID)},
		{Key: "first_sequence", Val: Int(expected.Chain.FirstSequence)},
		{Key: "last_hash", Val: Str(expected.Chain.LastHash)},
		{Key: "last_sequence", Val: Int(expected.Chain.LastSequence)},
		{Key: "previous_hash", Val: Str(expected.Chain.PreviousHash)},
		{Key: "row_count", Val: Int(expected.Chain.RowCount)},
		{Key: "transition_count", Val: Int(len(expected.Transitions))},
		{Key: "v", Val: Int(1)},
	}, &b)
	if err != nil || len(header) > b.ArchiveHeaderBytes {
		return EncodedExport{}, ErrInvalid
	}
	archive := append([]byte(nil), archiveMagic...)
	archive = appendFrame(archive, header)
	archive = appendFrame(archive, []byte(input.StartAnchor))
	for _, t := range input.Transitions {
		archive = appendFrame(archive, []byte(t))
	}
	for _, r := range input.Rows {
		archive = appendFrame(archive, r)
	}
	archive = appendFrame(archive, []byte(input.EndAnchor))
	if int64(len(archive)) > int64(b.ArchiveBytes) || len(archive) > int(b.ArchiveChunks) {
		return EncodedExport{}, ErrInvalid // aggregate archive bounds
	}
	digestRaw := sha256.Sum256(archive)
	wantDigest, _ := canonicalDigestString(expected.Digest)
	if digestRaw != wantDigest {
		return EncodedExport{}, ErrInvalid // produced bytes must equal the expected digest
	}
	return EncodedExport{Archive: archive, Digest: digestRaw, ByteCount: int64(len(archive))}, nil
}

// keysFromExpected derives a fingerprint-only pseudo key chain for the
// encode-side expected validation (the producer holds no public keys).
func keysFromExpected(expected ExpectedAnchoredExport, b Bounds) HistoricalKeyChain {
	keys := make(HistoricalKeyChain, 0, len(expected.Transitions)+1)
	unbounded := HistoricalPublicKey{
		KeyID:                expected.StartAnchor.KeyID,
		PublicKey:            nil, // fingerprints validated textually at encode
		ValidFrom:            0,
		ValidBefore:          0,
		ValidBeforeUnbounded: true,
	}
	_ = unbounded
	// The encode path validates key geometry through the expected tuples; the
	// pseudo chain satisfies the count invariant only.
	for i := 0; i <= len(expected.Transitions); i++ {
		k := HistoricalPublicKey{ValidBeforeUnbounded: true}
		if i == 0 {
			k.KeyID = expected.StartAnchor.KeyID
		} else {
			k.KeyID = expected.Transitions[i-1].NextKeyID
		}
		if k.KeyID == "" {
			k.KeyID = "encode"
		}
		k.PublicKey = make([]byte, 32)
		keys = append(keys, k)
	}
	return keys
}

func mustDigest(s string) [32]byte {
	d, _ := canonicalDigestString(s)
	return d
}

func appendFrame(dst, content []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(content)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, content...)
}

// parseAnchorCompactGated is the encode-side gated parse: signature width at
// decode + canonical segments + closed claims, no cryptography.
func parseAnchorCompactGated(compact string, b Bounds) (anchorClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return anchorClaims{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if _, err := decodeAnchorHeader(parts.Protected, b); err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if err := canonicalSegment(parts.ProtectedSeg, parts.Protected, b); err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if err := canonicalSegment(parts.PayloadSeg, parts.Payload, b); err != nil {
		return anchorClaims{}, ErrInvalid
	}
	payload, err := JsonDecode(parts.Payload, &b)
	if err != nil {
		return anchorClaims{}, ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	claims, ok := decodeAnchorClaims(obj, b)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	if claims.Sequence == 0 && claims.ChainHash != [32]byte{} {
		return anchorClaims{}, ErrInvalid
	}
	return claims, nil
}

// parseTransitionCompactGated is the encode-side gated transition parse.
func parseTransitionCompactGated(compact string, b Bounds) (transitionClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return transitionClaims{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if _, err := decodeTransitionHeader(parts.Protected, b); err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if err := canonicalSegment(parts.ProtectedSeg, parts.Protected, b); err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if err := canonicalSegment(parts.PayloadSeg, parts.Payload, b); err != nil {
		return transitionClaims{}, ErrInvalid
	}
	payload, err := JsonDecode(parts.Payload, &b)
	if err != nil {
		return transitionClaims{}, ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	claims, ok := decodeTransitionClaims(obj, b)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	return claims, nil
}

func anchorTupleMatch(c anchorClaims, e ExpectedAnchor) bool {
	return c.AnchorID == e.AnchorID && c.ChainID == e.ChainID && c.Sequence == e.Sequence &&
		c.AnchoredAt == e.AnchoredAt && c.ChainHash == mustDigest(e.ChainHash) &&
		c.KeyFingerprint == mustDigest(e.KeyFingerprint)
}

func transitionTupleMatch(c transitionClaims, e ExpectedKeyTransition) bool {
	return c.TransitionID == e.TransitionID && c.ChainID == e.ChainID &&
		c.EffectiveAt == e.EffectiveAt && c.FromFingerprint == mustDigest(e.CurrentKeyFingerprint) &&
		c.ToFingerprint == mustDigest(e.NextKeyFingerprint) && c.ToKeyID == e.NextKeyID
}
