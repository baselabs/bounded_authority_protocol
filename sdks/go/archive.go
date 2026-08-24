package verifier

import "crypto/sha256"

// The anchored-export surface (ADR 0004 + ADR 0017 + ADR 0018): boundary
// anchors and key transitions as canonically-encoded compact JWS objects, the
// framed archive, expected-struct validation BEFORE any archive hashing
// (clause 3 + its 2026-08-18 resolution), role-bounded frame reads (clause 5),
// canonical byte-equality for anchor/transition segments (clause 4), and
// caller-tightenable bounds threaded through every ceiling.

var archiveMagic = []byte("BAP1-ARCHIVE\x00EXPORT\x00")

// archiveDigestFn hashes the complete chunk stream; the seam exists so the
// battery can observe (and reject with zero) hash calls.
type archiveDigestFn func(chunks [][]byte, limit int64) ([32]byte, int64, error)

func defaultArchiveDigest(chunks [][]byte, limit int64) ([32]byte, int64, error) {
	var out [32]byte
	h := sha256.New()
	var total int64
	for _, c := range chunks {
		if total+int64(len(c)) > limit {
			return out, 0, ErrInvalid
		}
		h.Write(c)
		total += int64(len(c))
	}
	copy(out[:], h.Sum(nil))
	return out, total, nil
}

// decodeAnchorHeader validates {alg:"EdDSA", kid, typ:"ba+chain-anchor"}.
func decodeAnchorHeader(protected []byte, b Bounds) (string, error) {
	v, err := JsonDecode(protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid
	}
	var kid *Str
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return "", ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != "ba+chain-anchor" {
				return "", ErrInvalid
			}
		case "kid":
			if s, ok := m.Val.(Str); ok {
				kid = &s
			}
		default:
			return "", ErrInvalid
		}
	}
	if kid == nil || !validKid(string(*kid), b.KeyBytes) {
		return "", ErrInvalid
	}
	return string(*kid), nil
}

// decodeTransitionHeader validates {alg:"EdDSA", kid, typ:"ba+key-transition"}.
func decodeTransitionHeader(protected []byte, b Bounds) (string, error) {
	v, err := JsonDecode(protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid
	}
	var kid *Str
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return "", ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != "ba+key-transition" {
				return "", ErrInvalid
			}
		case "kid":
			if s, ok := m.Val.(Str); ok {
				kid = &s
			}
		default:
			return "", ErrInvalid
		}
	}
	if kid == nil || !validKid(string(*kid), b.KeyBytes) {
		return "", ErrInvalid
	}
	return string(*kid), nil
}

// canonicalSegment enforces ADR 0017 clause 4 for anchor/transition compacts:
// the received segment bytes must equal the canonical re-encoding of the
// decoded value (a reordered or non-canonical member order is rejected).
func canonicalSegment(seg string, decoded []byte, b Bounds) error {
	v, err := JsonDecode(decoded, &b)
	if err != nil {
		return ErrInvalid
	}
	enc, err := JcsEncode(v, &b)
	if err != nil {
		return ErrInvalid
	}
	if Base64urlEncode(enc) != seg {
		return ErrInvalid
	}
	return nil
}

// anchorClaims is the closed 7-member anchor payload.
type anchorClaims struct {
	AnchorID       string
	AnchoredAt     int64
	ChainHash      [32]byte
	ChainID        string
	KeyFingerprint [32]byte
	Sequence       int64
}

func decodeAnchorClaims(obj Obj, b Bounds) (anchorClaims, bool) {
	var out anchorClaims
	if len(obj) != 7 {
		return out, false
	}
	var chainHash, fingerprint string
	for _, m := range obj {
		var ok bool
		switch m.Key {
		case "anchor_id":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			out.AnchorID = string(s)
			if !validStringOrURI(out.AnchorID, b.IdentifierBytes) {
				return out, false
			}
		case "anchored_at":
			out.AnchoredAt, ok = integralTime(m.Val, b)
			if !ok {
				return out, false
			}
		case "chain_hash":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			chainHash = string(s)
		case "chain_id":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			out.ChainID = string(s)
			if !validStringOrURI(out.ChainID, b.IdentifierBytes) {
				return out, false
			}
		case "key_fingerprint":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			fingerprint = string(s)
		case "sequence":
			out.Sequence, ok = integralTime(m.Val, b)
			if !ok || out.Sequence < 0 {
				return out, false
			}
		case "v":
			if i, isInt := m.Val.(Int); !isInt || i != 1 {
				return out, false
			}
		default:
			return out, false
		}
	}
	ch, ok := canonicalDigestString(chainHash)
	if !ok {
		return out, false
	}
	out.ChainHash = ch
	fp, ok := canonicalDigestString(fingerprint)
	if !ok {
		return out, false
	}
	out.KeyFingerprint = fp
	return out, true
}

// transitionClaims is the closed 7-member transition payload.
type transitionClaims struct {
	ChainID         string
	EffectiveAt     int64
	FromFingerprint [32]byte
	ToFingerprint   [32]byte
	ToKeyID         string
	TransitionID    string
}

func decodeTransitionClaims(obj Obj, b Bounds) (transitionClaims, bool) {
	var out transitionClaims
	if len(obj) != 7 {
		return out, false
	}
	var from, to string
	for _, m := range obj {
		var ok bool
		switch m.Key {
		case "chain_id":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			out.ChainID = string(s)
			if !validStringOrURI(out.ChainID, b.IdentifierBytes) {
				return out, false
			}
		case "effective_at":
			out.EffectiveAt, ok = integralTime(m.Val, b)
			if !ok {
				return out, false
			}
		case "from_key_fingerprint":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			from = string(s)
		case "to_key_fingerprint":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			to = string(s)
		case "to_key_id":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			out.ToKeyID = string(s)
			if !validKid(out.ToKeyID, b.KeyBytes) {
				return out, false
			}
		case "transition_id":
			s, isStr := m.Val.(Str)
			if !isStr {
				return out, false
			}
			out.TransitionID = string(s)
			if !validStringOrURI(out.TransitionID, b.IdentifierBytes) {
				return out, false
			}
		case "v":
			if i, isInt := m.Val.(Int); !isInt || i != 1 {
				return out, false
			}
		default:
			return out, false
		}
	}
	f, ok := canonicalDigestString(from)
	if !ok {
		return out, false
	}
	out.FromFingerprint = f
	t, ok := canonicalDigestString(to)
	if !ok {
		return out, false
	}
	out.ToFingerprint = t
	return out, true
}

// validHistoricalKey revalidates one historical key (clause 2/3): key-id
// class and width, raw key width, integral endpoints within the magnitude
// bound, and valid_before > valid_from ordering.
func validHistoricalKey(k HistoricalPublicKey, b Bounds) bool {
	if !validKid(k.KeyID, b.KeyBytes) || len(k.PublicKey) != b.PublicKeyBytes {
		return false
	}
	if k.ValidFrom > int64(b.IntegerMagnitude) || k.ValidFrom < -int64(b.IntegerMagnitude) {
		return false
	}
	if k.ValidBefore > int64(b.IntegerMagnitude) || k.ValidBefore < -int64(b.IntegerMagnitude) {
		return false
	}
	if k.ValidBeforeUnbounded {
		return true // the only open upper interval
	}
	return k.ValidBefore > k.ValidFrom
}

func keyCovers(k HistoricalPublicKey, t int64) bool {
	if t < k.ValidFrom {
		return false
	}
	if !k.ValidBeforeUnbounded && t >= k.ValidBefore {
		return false
	}
	return true
}

// VerifyHistoricalAnchor verifies a boundary-anchor compact against one exact
// historical key and expected anchor tuple (ADR 0004): signed values, key ID,
// derived fingerprint, Ed25519 signature, and
// valid_from <= anchored_at < valid_before.
func VerifyHistoricalAnchor(compact string, key HistoricalPublicKey, expected ExpectedAnchor) (f AnchorFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return AnchorFacts{}, ErrInvalid
	}
	claims, err := verifyAnchorCompact(compact, key, expected, b)
	if err != nil {
		return AnchorFacts{}, ErrInvalid
	}
	return AnchorFacts{
		AnchorID:   claims.AnchorID,
		ChainID:    claims.ChainID,
		KeyID:      key.KeyID,
		Sequence:   claims.Sequence,
		AnchoredAt: claims.AnchoredAt,
		Trust:      TrustNotEvaluated,
	}, nil
}

// verifyAnchorCompact is the shared anchor primitive: role-bounded frame
// read, canonical segments, closed claims, 7-field expected match, derived
// fingerprint, signature, key window.
func verifyAnchorCompact(compact string, key HistoricalPublicKey, expected ExpectedAnchor, b Bounds) (anchorClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return anchorClaims{}, ErrInvalid // clause 5: role-bounded frame read
	}
	if !validHistoricalKey(key, b) {
		return anchorClaims{}, ErrInvalid
	}
	if !validStringOrURI(expected.AnchorID, b.IdentifierBytes) || !validStringOrURI(expected.ChainID, b.IdentifierBytes) ||
		!validKid(expected.KeyID, b.KeyBytes) || !validStringOrURI(expected.ChainID, b.IdentifierBytes) {
		return anchorClaims{}, ErrInvalid
	}
	if expected.Sequence < 0 {
		return anchorClaims{}, ErrInvalid
	}
	wantChainHash, ok := canonicalDigestString(expected.ChainHash)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	wantFP, ok := canonicalDigestString(expected.KeyFingerprint)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return anchorClaims{}, ErrInvalid
	}
	kid, err := decodeAnchorHeader(parts.Protected, b)
	if err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if err := canonicalSegment(parts.ProtectedSeg, parts.Protected, b); err != nil {
		return anchorClaims{}, ErrInvalid // clause 4
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
	// 7-field expected match
	if claims.AnchorID != expected.AnchorID || claims.ChainID != expected.ChainID ||
		claims.Sequence != expected.Sequence || claims.AnchoredAt != expected.AnchoredAt ||
		claims.ChainHash != wantChainHash || claims.KeyFingerprint != wantFP {
		return anchorClaims{}, ErrInvalid
	}
	if kid != key.KeyID || kid != expected.KeyID {
		return anchorClaims{}, ErrInvalid
	}
	derived, err := PublicKeyThumbprintRaw(key.PublicKey, &b)
	if err != nil || derived != claims.KeyFingerprint {
		return anchorClaims{}, ErrInvalid
	}
	si := SigningInput{Kind: KindBoundaryAnchor, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(key.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if !keyCovers(key, claims.AnchoredAt) {
		return anchorClaims{}, ErrInvalid
	}
	return claims, nil
}

// VerifyKeyTransition verifies a transition compact: the CURRENT key signs;
// current and next keys/fingerprints must differ while key IDs may equal; the
// effective time must lie in both historical intervals (ADR 0004).
func VerifyKeyTransition(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition) (f KeyTransitionFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return KeyTransitionFacts{}, ErrInvalid
	}
	claims, err := verifyTransitionCompact(compact, currentKey, nextKey, expected, b)
	if err != nil {
		return KeyTransitionFacts{}, ErrInvalid
	}
	return KeyTransitionFacts{
		TransitionID:    claims.TransitionID,
		ChainID:         claims.ChainID,
		EffectiveAt:     claims.EffectiveAt,
		FromFingerprint: claims.FromFingerprint,
		ToFingerprint:   claims.ToFingerprint,
		ToKeyID:         claims.ToKeyID,
		Trust:           TrustNotEvaluated,
	}, nil
}

func verifyTransitionCompact(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition, b Bounds) (transitionClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return transitionClaims{}, ErrInvalid
	}
	if !validHistoricalKey(currentKey, b) || !validHistoricalKey(nextKey, b) {
		return transitionClaims{}, ErrInvalid
	}
	if !validStringOrURI(expected.TransitionID, b.IdentifierBytes) || !validStringOrURI(expected.ChainID, b.IdentifierBytes) ||
		!validKid(expected.CurrentKeyID, b.KeyBytes) || !validKid(expected.NextKeyID, b.KeyBytes) {
		return transitionClaims{}, ErrInvalid
	}
	wantFrom, ok := canonicalDigestString(expected.CurrentKeyFingerprint)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	wantTo, ok := canonicalDigestString(expected.NextKeyFingerprint)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	if wantFrom == wantTo {
		return transitionClaims{}, ErrInvalid // fingerprints must differ
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return transitionClaims{}, ErrInvalid
	}
	kid, err := decodeTransitionHeader(parts.Protected, b)
	if err != nil {
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
	if claims.TransitionID != expected.TransitionID || claims.ChainID != expected.ChainID ||
		claims.EffectiveAt != expected.EffectiveAt || claims.FromFingerprint != wantFrom ||
		claims.ToFingerprint != wantTo || claims.ToKeyID != expected.NextKeyID {
		return transitionClaims{}, ErrInvalid
	}
	if kid != currentKey.KeyID || kid != expected.CurrentKeyID {
		return transitionClaims{}, ErrInvalid
	}
	fromFP, err := PublicKeyThumbprintRaw(currentKey.PublicKey, &b)
	if err != nil || fromFP != claims.FromFingerprint {
		return transitionClaims{}, ErrInvalid
	}
	toFP, err := PublicKeyThumbprintRaw(nextKey.PublicKey, &b)
	if err != nil || toFP != claims.ToFingerprint || toFP == fromFP {
		return transitionClaims{}, ErrInvalid
	}
	si := SigningInput{Kind: KindKeyTransition, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(currentKey.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if !keyCovers(currentKey, claims.EffectiveAt) || !keyCovers(nextKey, claims.EffectiveAt) {
		return transitionClaims{}, ErrInvalid
	}
	return claims, nil
}
