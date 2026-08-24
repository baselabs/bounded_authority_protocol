package verifier

import (
	"crypto/sha256"
	"strings"
)

// Compact-JWS machinery: deterministic producers, the bounded assembler, and
// the shared split. Grant and proof signatures use the exact RFC 7515 signing
// input with no domain prefix (ADR 0003, REQ1-SIGNING-exact-input); the
// retired BAP1-GRANT\0 / BAP1-PROOF\0 prefixes are invalid signing prefixes.

// signingInputMessage builds ASCII(BASE64URL(protected) || '.' ||
// BASE64URL(payload)) from the exact canonical segment bytes.
func signingInputMessage(si SigningInput) []byte {
	msg := make([]byte, 0, len(si.Protected)+len(si.Payload)+3)
	msg = append(msg, Base64urlEncode(si.Protected)...)
	msg = append(msg, '.')
	msg = append(msg, Base64urlEncode(si.Payload)...)
	return msg
}

// compactParts is a split compact JWS. The signature is width-gated at decode
// time (ADR 0017 clause 4): a decoded signature that is not exactly 64 bytes
// never reaches cryptography.
type compactParts struct {
	ProtectedSeg string
	PayloadSeg   string
	Protected    []byte
	Payload      []byte
	Signature    []byte
}

// splitCompact enforces the compact bound, exact three segments, per-segment
// encoded and decoded ceilings, strict base64url, and the decode-time
// signature width gate.
func splitCompact(compact string, b Bounds) (compactParts, error) {
	if len(compact) == 0 || len(compact) > b.CompactBytes {
		return compactParts{}, ErrInvalid
	}
	first := strings.IndexByte(compact, '.')
	last := strings.LastIndexByte(compact, '.')
	if first <= 0 || last <= first+1 || last >= len(compact)-1 || strings.Count(compact, ".") != 2 {
		return compactParts{}, ErrInvalid // exactly three nonempty segments
	}
	protectedSeg := compact[:first]
	payloadSeg := compact[first+1 : last]
	signatureSeg := compact[last+1:]
	if len(protectedSeg) > b.EncodedSegmentBytes || len(payloadSeg) > b.EncodedSegmentBytes || len(signatureSeg) > b.EncodedSegmentBytes {
		return compactParts{}, ErrInvalid
	}
	protected, err := Base64urlDecode(protectedSeg)
	if err != nil {
		return compactParts{}, ErrInvalid
	}
	payload, err := Base64urlDecode(payloadSeg)
	if err != nil {
		return compactParts{}, ErrInvalid
	}
	signature, err := Base64urlDecode(signatureSeg)
	if err != nil || len(signature) != b.SignatureBytes {
		return compactParts{}, ErrInvalid // width gate at decode
	}
	if len(protected) > b.DecodedSegmentBytes || len(payload) > b.DecodedSegmentBytes {
		return compactParts{}, ErrInvalid
	}
	return compactParts{
		ProtectedSeg: protectedSeg,
		PayloadSeg:   payloadSeg,
		Protected:    protected,
		Payload:      payload,
		Signature:    signature,
	}, nil
}

// GrantSigningInput composes the deterministic canonical grant signing input
// (REQ1-SIGNING-deterministic-produce). It accepts no private key, signer, or
// callback (REQ1-VERIFY-no-signer-callback).
func GrantSigningInput(g Grant, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validKid(g.KeyID, b.KidBytes) || !validStringOrURI(g.Issuer, b.IdentifierBytes) ||
		!validStringOrURI(g.GrantID, b.IdentifierBytes) {
		return SigningInput{}, ErrInvalid
	}
	if len(g.Audiences) == 0 || len(g.Audiences) > b.Audiences {
		return SigningInput{}, ErrInvalid
	}
	seen := map[string]struct{}{}
	auds := make(Arr, 0, len(g.Audiences))
	for _, a := range g.Audiences {
		if _, dup := seen[a]; dup || !validStringOrURI(a, b.IdentifierBytes) {
			return SigningInput{}, ErrInvalid
		}
		seen[a] = struct{}{}
		auds = append(auds, Str(a))
	}
	if _, ok := canonicalDigestString(g.HolderThumbprint); !ok {
		return SigningInput{}, ErrInvalid
	}
	if len(g.Operations) == 0 || len(g.Operations) > b.Operations {
		return SigningInput{}, ErrInvalid
	}
	opNames := map[string]struct{}{}
	ops := make(Arr, 0, len(g.Operations))
	for _, op := range g.Operations {
		if _, dup := opNames[op.Name]; dup || !validOperationName(op.Name, b.OperationBytes) {
			return SigningInput{}, ErrInvalid
		}
		opNames[op.Name] = struct{}{}
		if len(op.Selectors) == 0 || len(op.Selectors) > b.Selectors {
			return SigningInput{}, ErrInvalid
		}
		sels := make(Arr, 0, len(op.Selectors))
		for _, sel := range op.Selectors {
			if validateSelector(sel, &b) != nil {
				return SigningInput{}, ErrInvalid
			}
			sels = append(sels, sel)
		}
		ops = append(ops, Obj{{Key: "name", Val: Str(op.Name)}, {Key: "selectors", Val: sels}})
	}
	protected, perr := JcsEncode(Obj{{Key: "alg", Val: Str("EdDSA")}, {Key: "kid", Val: Str(g.KeyID)}, {Key: "typ", Val: Str("ba+cap")}}, &b)
	if perr != nil {
		return SigningInput{}, ErrInvalid
	}
	payload, perr := JcsEncode(Obj{
		{Key: "aud", Val: auds},
		{Key: "cnf", Val: Obj{{Key: "jkt", Val: Str(g.HolderThumbprint)}}},
		{Key: "exp", Val: Int(g.ExpiresAt)},
		{Key: "iat", Val: Int(g.IssuedAt)},
		{Key: "iss", Val: Str(g.Issuer)},
		{Key: "jti", Val: Str(g.GrantID)},
		{Key: "nbf", Val: Int(g.NotBefore)},
		{Key: "operations", Val: ops},
		{Key: "v", Val: Int(1)},
	}, &b)
	if perr != nil {
		return SigningInput{}, ErrInvalid
	}
	if g.IssuedAt >= g.ExpiresAt || g.NotBefore >= g.ExpiresAt {
		return SigningInput{}, ErrInvalid // coherent signed times
	}
	return SigningInput{Kind: KindGrant, Protected: protected, Payload: payload}, nil
}

// ProofSigningInput composes the deterministic canonical holder-proof signing
// input. ath is SHA-256 over the ASCII bytes of the complete received grant
// compact value (REQ1-CLAIM-ath); ba_req is the BAP1-REQUEST\0 request digest.
func ProofSigningInput(p Proof, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validStringOrURI(p.ProofID, b.IdentifierBytes) || !validUUID(p.InvocationID) ||
		!validOperationName(p.Operation, b.OperationBytes) || !validHTM(p.Method, b.MethodBytes) {
		return SigningInput{}, ErrInvalid
	}
	htu, err := uriNormalized(p.TargetURI, b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if len(p.HolderPublicKey) != b.PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	if len(p.GrantCompact) == 0 || len(p.GrantCompact) > b.CompactBytes {
		return SigningInput{}, ErrInvalid // producer ath compact-bytes bound
	}
	athRaw := sha256.Sum256([]byte(p.GrantCompact))
	baReqRaw, err := requestDigestRaw(p.Operation, p.CastArguments, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	jwk, err := JwkEncodePublic(p.HolderPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	jwkValue, err := JsonDecode(jwk, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("EdDSA")}, {Key: "jwk", Val: jwkValue}, {Key: "typ", Val: Str("dpop+jwt")}}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	members := Obj{
		{Key: "ath", Val: Str(Base64urlEncode(athRaw[:]))},
		{Key: "ba_inv", Val: Str(p.InvocationID)},
		{Key: "ba_op", Val: Str(p.Operation)},
		{Key: "ba_req", Val: Str(Base64urlEncode(baReqRaw[:]))},
		{Key: "htm", Val: Str(p.Method)},
		{Key: "htu", Val: Str(htu)},
		{Key: "iat", Val: Int(p.IssuedAt)},
		{Key: "jti", Val: Str(p.ProofID)},
		{Key: "v", Val: Int(1)},
	}
	if p.HasNonce {
		if len(p.Nonce) == 0 || len(p.Nonce) > b.NonceBytes {
			return SigningInput{}, ErrInvalid
		}
		// JCS orders members, so appending here cannot change the output
		members = append(members, Member{Key: "nonce", Val: Str(p.Nonce)})
	}
	payload, err := JcsEncode(members, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindProof, Protected: protected, Payload: payload}, nil
}

// BoundaryAnchorSigningInput composes the deterministic anchor signing input
// (ADR 0004: header {alg,kid,typ:"ba+chain-anchor"}; payload binding v,
// anchor identity/time, chain identity, sequence, chain hash, and the raw-key
// fingerprint). Sequence zero requires the all-zero hash.
func BoundaryAnchorSigningInput(a BoundaryAnchor, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validKid(a.KeyID, b.KeyBytes) || !validStringOrURI(a.ChainID, b.IdentifierBytes) ||
		!validStringOrURI(a.AnchorID, b.IdentifierBytes) {
		return SigningInput{}, ErrInvalid
	}
	chainHash, ok := canonicalDigestString(a.ChainHash)
	if !ok {
		return SigningInput{}, ErrInvalid
	}
	if len(a.PublicKey) != b.PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	fingerprint, err := PublicKeyThumbprintRaw(a.PublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if a.Sequence == 0 {
		if a.ChainHash != allZeroHashB64 {
			return SigningInput{}, ErrInvalid // genesis requires the all-zero hash
		}
	} else if a.Sequence < 0 {
		return SigningInput{}, ErrInvalid
	}
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("EdDSA")}, {Key: "kid", Val: Str(a.KeyID)}, {Key: "typ", Val: Str("ba+chain-anchor")}}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	payload, err := JcsEncode(Obj{
		{Key: "anchor_id", Val: Str(a.AnchorID)},
		{Key: "anchored_at", Val: Int(a.AnchoredAt)},
		{Key: "chain_hash", Val: Str(Base64urlEncode(chainHash[:]))},
		{Key: "chain_id", Val: Str(a.ChainID)},
		{Key: "key_fingerprint", Val: Str(Base64urlEncode(fingerprint[:]))},
		{Key: "sequence", Val: Int(a.Sequence)},
		{Key: "v", Val: Int(1)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindBoundaryAnchor, Protected: protected, Payload: payload}, nil
}

// KeyTransitionSigningInput composes the deterministic transition signing
// input (ADR 0004: typ ba+key-transition; the CURRENT key signs; the payload
// binds transition+chain identities, effective time, current and next
// fingerprints, and the next key id). Fingerprints must differ; key IDs may
// be equal.
func KeyTransitionSigningInput(t KeyTransition, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validKid(t.CurrentKeyID, b.KeyBytes) || !validKid(t.NextKeyID, b.KeyBytes) ||
		!validStringOrURI(t.ChainID, b.IdentifierBytes) || !validStringOrURI(t.TransitionID, b.IdentifierBytes) {
		return SigningInput{}, ErrInvalid
	}
	if len(t.CurrentPublicKey) != b.PublicKeyBytes || len(t.NextPublicKey) != b.PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	fromFP, err := PublicKeyThumbprintRaw(t.CurrentPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	toFP, err := PublicKeyThumbprintRaw(t.NextPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if fromFP == toFP {
		return SigningInput{}, ErrInvalid // fingerprints cannot repeat
	}
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("EdDSA")}, {Key: "kid", Val: Str(t.CurrentKeyID)}, {Key: "typ", Val: Str("ba+key-transition")}}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	payload, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(t.ChainID)},
		{Key: "effective_at", Val: Int(t.EffectiveAt)},
		{Key: "from_key_fingerprint", Val: Str(Base64urlEncode(fromFP[:]))},
		{Key: "to_key_fingerprint", Val: Str(Base64urlEncode(toFP[:]))},
		{Key: "to_key_id", Val: Str(t.NextKeyID)},
		{Key: "transition_id", Val: Str(t.TransitionID)},
		{Key: "v", Val: Int(1)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindKeyTransition, Protected: protected, Payload: payload}, nil
}

// AssembleCompact assembles a compact JWS from a signing input and a 64-byte
// signature, threading the caller's tightening-only bounds through the
// reference's assemble gates: encoded-segment bounds on both segments, the
// compact-bytes ceiling on the assembled output, and the kind-specific
// re-parse (ADR 0018 decision 4). A nil bounds is the profile maximum.
func AssembleCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return "", ErrInvalid
	}
	if len(signature) != b.SignatureBytes {
		return "", ErrInvalid
	}
	protectedSeg := Base64urlEncode(si.Protected)
	payloadSeg := Base64urlEncode(si.Payload)
	if len(protectedSeg) > b.EncodedSegmentBytes || len(payloadSeg) > b.EncodedSegmentBytes {
		return "", ErrInvalid
	}
	compact = protectedSeg + "." + payloadSeg + "." + Base64urlEncode(signature)
	if len(compact) > b.CompactBytes {
		return "", ErrInvalid
	}
	// kind-specific re-parse: the assembled compact must decode and satisfy
	// its kind's closed header set and bounded payload
	parts, err := splitCompact(compact, b)
	if err != nil {
		return "", ErrInvalid
	}
	switch si.Kind {
	case KindGrant:
		if _, err := decodeGrantHeader(parts, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := JsonDecode(parts.Payload, &b); err != nil {
			return "", ErrInvalid
		}
	case KindProof:
		if _, err := decodeProofHeader(parts, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := JsonDecode(parts.Payload, &b); err != nil {
			return "", ErrInvalid
		}
	case KindBoundaryAnchor:
		if _, err := decodeAnchorHeader(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := JsonDecode(parts.Payload, &b); err != nil {
			return "", ErrInvalid
		}
	case KindKeyTransition:
		if _, err := decodeTransitionHeader(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := JsonDecode(parts.Payload, &b); err != nil {
			return "", ErrInvalid
		}
	default:
		return "", ErrInvalid
	}
	return compact, nil
}

// closedResult is the ADR 0017 clause-1 closure in Go: no panic — however
// unexpected — may escape a public façade; it fails closed to ErrInvalid.
func closedResult(err *error) {
	if r := recover(); r != nil {
		*err = ErrInvalid
	}
}
