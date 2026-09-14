package verifier

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

// The successor contract-major profile. This file carries the major, so every
// member mirrors its v1 counterpart's name exactly (the namespace-type pattern
// the sibling SDKs get from their module systems). The profile is byte-honest
// with the frozen v1 surface except: (1) every versioned payload carries
// "v":2 and this major rejects v1 bytes (and vice versa), (2) the domain
// separators below are the BAP2 forms — the v1 constants in
// selector.go/chain.go/archive.go are untouched — and (3) the selector
// algebra additionally admits the two inclusive one-sided range kinds lte/gte
// on the existing {kind, path, value} member set: same-tag numeric operands
// only, comparison by numeric value, cross-tag never matches, and a
// non-numeric bound is rejected at decode (ADR 0028 §1-§3). The shared json
// algebra, JCS, base64url, JWK, URI, and bounds modules are reused unchanged;
// only wire-version, domain-separator, and selector-kind decisions live here.

// successorRequestPrefix is the successor-major request-digest domain
// separator, exact ASCII including its final zero byte.
var successorRequestPrefix = []byte("BAP2-REQUEST\x00")

// successorChainPrefix is the successor-major consumption-chain domain
// separator.
var successorChainPrefix = []byte("BAP2-CHAIN\x00")

// successorArchiveMagic is the successor-major archive framing magic.
var successorArchiveMagic = []byte("BAP2-ARCHIVE\x00EXPORT\x00")

// Profile is the successor contract-major facade: a stateless namespace type
// whose method set mirrors the v1 public entry names (DecodeGrant,
// VerifyGrant, CheckEnvelope, ...). Construct as the zero value; it holds no
// state and grants nothing.
type Profile struct{}

// successor is the zero-value facade used for internal dispatch; Profile
// holds no state, so this is the same namespace as any Profile{} value.
var successor = Profile{}

// ---- selector algebra (ADR 0028) ----

// validateSelector closed-set-validates one selector value: the v1 kind set
// plus lte/gte on the same {kind, path, value} member set. An lte/gte bound
// must be numeric (Int or Float) — a non-numeric bound is malformed and fails
// the whole grant at decode (ADR 0028 §7).
func (Profile) validateSelector(v Value, bounds *Bounds) error {
	b, err := resolveBounds(bounds)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok {
		return ErrInvalid // closed selector set
	}
	var kind *Str
	var path Arr
	var pathPresent bool
	var pathValid bool
	var value Value
	var hasValue bool
	var values Arr
	var valuesPresent bool
	var valuesValid bool
	seen := make(map[string]struct{}, 4)
	for _, m := range obj {
		if _, duplicate := seen[m.Key]; duplicate {
			return ErrInvalid
		}
		seen[m.Key] = struct{}{}
		switch m.Key {
		case "kind":
			if s, ok := m.Val.(Str); ok {
				kind = &s
			}
		case "path":
			pathPresent = true
			path, pathValid = m.Val.(Arr)
		case "value":
			value, hasValue = m.Val, true
		case "values":
			valuesPresent = true
			values, valuesValid = m.Val.(Arr)
		default:
			return ErrInvalid // unlisted member
		}
	}
	if kind == nil {
		return ErrInvalid
	}
	recognizedMembers := len(obj) == 1 ||
		(len(obj) == 3 && pathPresent && (hasValue != valuesPresent))
	if !recognizedMembers {
		return ErrInvalid
	}
	switch *kind {
	case "all":
		// The profile recognizes the same three member sets; on either
		// three-member set, path/value(s) are inert for all.
		return nil
	case "equals":
		if len(obj) != 3 || !pathValid || !hasValue {
			return ErrInvalid
		}
	case "one_of":
		if len(obj) != 3 || !pathValid || !valuesValid {
			return ErrInvalid
		}
		if len(values) == 0 || len(values) > b.OneOfValues {
			return ErrInvalid // one-of size ceiling
		}
	case "lte", "gte":
		// ADR 0028 §3: the second recognized member set, value carries the
		// bound. A non-numeric bound is malformed, not a non-match.
		if len(obj) != 3 || !pathValid || !hasValue {
			return ErrInvalid
		}
		switch value.(type) {
		case Int, Float:
		default:
			return ErrInvalid // non-numeric bound rejected at decode
		}
	default:
		return ErrInvalid // unknown kind
	}
	if len(path) == 0 || len(path) > b.PathSegments {
		return ErrInvalid // path shape
	}
	for _, seg := range path {
		s, ok := seg.(Str)
		if !ok || len(s) == 0 || len(s) > objectNameBytes {
			return ErrInvalid
		}
	}
	// selector values live inside the same JSON bounds and must be
	// prototype-safe (same rule as the v1 validator)
	if hasValue {
		if _, err := JcsEncode(value, &b); err != nil {
			return ErrInvalid
		}
		if hasProtoMember(value) {
			return ErrInvalid
		}
	}
	if valuesPresent {
		for _, item := range values {
			if _, err := JcsEncode(item, &b); err != nil {
				return ErrInvalid
			}
			if hasProtoMember(item) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// applySelectors applies every selector conjunctively; nil means every
// selector matched, ErrInvalid means one did not.
func (Profile) applySelectors(selectors []Value, args Value) error {
	for _, sel := range selectors {
		obj, ok := sel.(Obj)
		if !ok {
			return ErrInvalid
		}
		var kind Str
		var path []string
		var target Value
		var candidates Arr
		for _, m := range obj {
			switch m.Key {
			case "kind":
				if k, ok := m.Val.(Str); ok {
					kind = k
				}
			case "path":
				if p, ok := m.Val.(Arr); ok {
					for _, seg := range p {
						if s, ok := seg.(Str); ok {
							path = append(path, string(s))
						}
					}
				}
			case "value":
				target = m.Val
			case "values":
				if vs, ok := m.Val.(Arr); ok {
					candidates = vs
				}
			}
		}
		switch kind {
		case "all":
			continue
		case "equals":
			found, ok := walkPath(args, path)
			if !ok || !semanticEqual(found, target) {
				return ErrInvalid // path required
			}
		case "one_of":
			found, ok := walkPath(args, path)
			if !ok {
				return ErrInvalid
			}
			matched := false
			for _, cand := range candidates {
				if semanticEqual(found, cand) {
					matched = true
					break
				}
			}
			if !matched {
				return ErrInvalid
			}
		case "lte", "gte":
			found, ok := walkPath(args, path)
			if !ok || !rangeMatch(kind, found, target) {
				return ErrInvalid // missing path or non-match: fail closed
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

// rangeMatch applies the ADR 0028 §2 operand domain: the traversed value and
// the bound must carry the SAME numeric tag (both integer-tagged or both
// float-tagged — cross-tag never matches); comparison is by numeric value on
// the finite binary64 domain (IEEE 754 ordering, −0.0 = 0.0); lte is
// inclusive ≤, gte is inclusive ≥. A non-numeric operand never matches. No
// new bound exists: both operands are already inside the decoder's closed
// numeric domain (ADR 0028 §4).
func rangeMatch(kind Str, found, bound Value) bool {
	switch f := found.(type) {
	case Int:
		b, ok := bound.(Int)
		if !ok {
			return false // cross-tag or non-numeric bound never matches
		}
		if kind == "lte" {
			return int64(f) <= int64(b)
		}
		return int64(f) >= int64(b)
	case Float:
		b, ok := bound.(Float)
		if !ok {
			return false // cross-tag or non-numeric bound never matches
		}
		if kind == "lte" {
			return float64(f) <= float64(b)
		}
		return float64(f) >= float64(b)
	default:
		return false // non-numeric operand never matches
	}
}

// ---- grant/proof decode ----

// decodeGrantPayload validates every grant claim: identical to the v1 closed
// set with "v":2 and this profile's selector validator.
func (Profile) decodeGrantPayload(p compactParts, b Bounds) (grantClaimsData, error) {
	var out grantClaimsData
	v, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 9 {
		return out, ErrInvalid // exact member set
	}
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 2 {
				return out, ErrInvalid // this major rejects v1 bytes
			}
		case "iss":
			if s, ok := m.Val.(Str); ok {
				out.Issuer = string(s)
			}
		case "jti":
			if s, ok := m.Val.(Str); ok {
				out.GrantID = string(s)
			}
		case "aud":
			switch a := m.Val.(type) {
			case Str:
				out.Audiences = []string{string(a)}
			case Arr:
				if len(a) == 0 || len(a) > b.Audiences {
					return out, ErrInvalid
				}
				seen := map[string]struct{}{}
				for _, item := range a {
					s, ok := item.(Str)
					if !ok {
						return out, ErrInvalid
					}
					if _, dup := seen[string(s)]; dup {
						return out, ErrInvalid // unique audiences
					}
					seen[string(s)] = struct{}{}
					out.Audiences = append(out.Audiences, string(s))
				}
			default:
				return out, ErrInvalid
			}
		case "iat":
			if t, ok := integralTime(m.Val, b); ok {
				out.IssuedAt = t
			} else {
				return out, ErrInvalid
			}
		case "nbf":
			if t, ok := integralTime(m.Val, b); ok {
				out.NotBefore = t
			} else {
				return out, ErrInvalid
			}
		case "exp":
			if t, ok := integralTime(m.Val, b); ok {
				out.ExpiresAt = t
			} else {
				return out, ErrInvalid
			}
		case "cnf":
			cnf, ok := m.Val.(Obj)
			if !ok || len(cnf) != 1 {
				return out, ErrInvalid
			}
			if cnf[0].Key != "jkt" {
				return out, ErrInvalid
			}
			s, ok := cnf[0].Val.(Str)
			if !ok {
				return out, ErrInvalid
			}
			raw, ok := canonicalDigestString(string(s))
			if !ok {
				return out, ErrInvalid
			}
			out.JktRaw = raw
		case "operations":
			ops, ok := m.Val.(Arr)
			if !ok || len(ops) == 0 || len(ops) > b.Operations {
				return out, ErrInvalid
			}
			names := map[string]struct{}{}
			for _, item := range ops {
				op, ok := item.(Obj)
				if !ok || len(op) != 2 {
					return out, ErrInvalid
				}
				var name *Str
				var selectors Arr
				for _, om := range op {
					switch om.Key {
					case "name":
						if s, ok := om.Val.(Str); ok {
							name = &s
						}
					case "selectors":
						if ss, ok := om.Val.(Arr); ok {
							selectors = ss
						}
					default:
						return out, ErrInvalid
					}
				}
				if name == nil || selectors == nil {
					return out, ErrInvalid
				}
				if _, dup := names[string(*name)]; dup || !validOperationName(string(*name), b.OperationBytes) {
					return out, ErrInvalid
				}
				names[string(*name)] = struct{}{}
				if len(selectors) == 0 || len(selectors) > b.Selectors {
					return out, ErrInvalid
				}
				for _, sel := range selectors {
					if successor.validateSelector(sel, &b) != nil {
						return out, ErrInvalid
					}
				}
				out.Operations = append(out.Operations, OperationDef{Name: string(*name), Selectors: selectors})
			}
		default:
			return out, ErrInvalid // unlisted claim
		}
	}
	if !validStringOrURI(out.Issuer, b.IdentifierBytes) || !validStringOrURI(out.GrantID, b.IdentifierBytes) {
		return out, ErrInvalid
	}
	for _, a := range out.Audiences {
		if !validStringOrURI(a, b.IdentifierBytes) {
			return out, ErrInvalid
		}
	}
	if out.IssuedAt >= out.ExpiresAt || out.NotBefore >= out.ExpiresAt {
		return out, ErrInvalid // coherent signed times
	}
	return out, nil
}

// decodeProofPayload validates every proof claim: identical to the v1
// standard-profile closed set with "v":2.
func (Profile) decodeProofPayload(p compactParts, b Bounds) (proofClaimsData, error) {
	var out proofClaimsData
	v, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) < 9 || len(obj) > 10 {
		return out, ErrInvalid
	}
	present := map[string]bool{}
	for _, m := range obj {
		present[m.Key] = true
	}
	for _, required := range []string{"v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"} {
		if !present[required] {
			return out, ErrInvalid // missing required claim
		}
	}
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 2 {
				return out, ErrInvalid // this major rejects v1 bytes
			}
		case "jti":
			if s, ok := m.Val.(Str); ok {
				out.ProofID = string(s)
			}
		case "htm":
			if s, ok := m.Val.(Str); ok {
				out.Method = string(s)
			}
		case "htu":
			if s, ok := m.Val.(Str); ok {
				out.TargetURI = string(s)
			}
		case "iat":
			if t, ok := integralTime(m.Val, b); ok {
				out.IssuedAt = t
			} else {
				return out, ErrInvalid
			}
		case "nonce":
			s, ok := m.Val.(Str)
			if !ok || len(s) == 0 || len(s) > b.NonceBytes {
				return out, ErrInvalid
			}
			n := string(s)
			out.Nonce = &n
		case "ba_inv":
			if s, ok := m.Val.(Str); ok {
				out.Invocation = string(s)
			}
		case "ba_op":
			if s, ok := m.Val.(Str); ok {
				out.Operation = string(s)
			}
		case "ath":
			s, ok := m.Val.(Str)
			if !ok {
				return out, ErrInvalid
			}
			raw, ok := canonicalDigestString(string(s))
			if !ok {
				return out, ErrInvalid
			}
			out.AthRaw = raw
		case "ba_req":
			s, ok := m.Val.(Str)
			if !ok {
				return out, ErrInvalid
			}
			raw, ok := canonicalDigestString(string(s))
			if !ok {
				return out, ErrInvalid
			}
			out.BaReqRaw = raw
		default:
			return out, ErrInvalid // unlisted claim
		}
	}
	if !validStringOrURI(out.ProofID, b.IdentifierBytes) || !validHTM(out.Method, b.MethodBytes) ||
		!validUUID(out.Invocation) || !validOperationName(out.Operation, b.OperationBytes) {
		return out, ErrInvalid
	}
	normalized, err := uriNormalized(out.TargetURI, b)
	if err != nil || normalized != out.TargetURI {
		return out, ErrInvalid // pre-normalized
	}
	return out, nil
}

// ---- request digest ----

// RequestDigest computes this major's request digest:
//
//	base64url(SHA-256("BAP2-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
func (Profile) RequestDigest(operation string, castArguments Value, bounds *Bounds) (string, error) {
	raw, err := successor.requestDigestRaw(operation, castArguments, bounds)
	if err != nil {
		return "", ErrInvalid
	}
	return Base64urlEncode(raw[:]), nil
}

func (Profile) requestDigestRaw(operation string, castArguments Value, bounds *Bounds) ([32]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	if !validOperationName(operation, b.OperationBytes) {
		return [32]byte{}, ErrInvalid
	}
	projected := typedProjection(castArguments)
	body, err := JcsEncode(Arr{Str(operation), projected}, &b)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	h := sha256.New()
	h.Write(successorRequestPrefix)
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ---- decode/verify façades ----

// DecodeGrant decodes and closed-set-validates a raw grant compact of this
// major. It performs no signature verification and rejects v1 bytes.
func (Profile) DecodeGrant(compact string, bounds *Bounds) (d GrantDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	kid, err := decodeGrantHeader(parts, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	claims, err := successor.decodeGrantPayload(parts, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	return GrantDecoded{
		KeyID:            kid,
		Version:          2,
		Issuer:           claims.Issuer,
		GrantID:          claims.GrantID,
		Audiences:        claims.Audiences,
		IssuedAt:         claims.IssuedAt,
		NotBefore:        claims.NotBefore,
		ExpiresAt:        claims.ExpiresAt,
		HolderThumbprint: claims.JktRaw,
		Operations:       claims.Operations,
		Verification:     DecodeVerificationNotEvaluated,
	}, nil
}

// DecodeProof decodes and closed-set-validates a raw proof compact of this
// major.
func (Profile) DecodeProof(compact string, bounds *Bounds) (d ProofDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	if _, err := decodeProofHeaderFor(parts, b, proofProfileStandard); err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	claims, err := successor.decodeProofPayload(parts, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	out := ProofDecoded{
		ProofID:      claims.ProofID,
		Version:      2,
		Method:       claims.Method,
		TargetURI:    claims.TargetURI,
		IssuedAt:     claims.IssuedAt,
		InvocationID: claims.Invocation,
		Operation:    claims.Operation,
		Verification: DecodeVerificationNotEvaluated,
	}
	if claims.Nonce != nil {
		out.HasNonce = true
		out.Nonce = *claims.Nonce
	}
	return out, nil
}

// UntrustedKeyLocator bounds the complete compact input and validates ONLY
// the protected grant header (the closed header is identical in this major);
// payload and signature stay opaque.
func (Profile) UntrustedKeyLocator(compact string, bounds *Bounds) (loc KeyLocator, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return KeyLocator{}, ErrInvalid
	}
	if len(compact) == 0 || len(compact) > b.CompactBytes {
		return KeyLocator{}, ErrInvalid
	}
	if stringsCount(compact, '.') != 2 {
		return KeyLocator{}, ErrInvalid // three segments
	}
	first := indexByte(compact, '.')
	headerSeg := compact[:first]
	if len(headerSeg) == 0 || len(headerSeg) > b.EncodedSegmentBytes {
		return KeyLocator{}, ErrInvalid
	}
	header, err := Base64urlDecode(headerSeg)
	if err != nil || len(header) > b.DecodedSegmentBytes {
		return KeyLocator{}, ErrInvalid
	}
	parts := compactParts{Protected: header}
	kid, err := decodeGrantHeader(parts, b)
	if err != nil {
		return KeyLocator{}, ErrInvalid
	}
	return KeyLocator{KeyID: kid, Trust: TrustNotEvaluated}, nil
}

// verifyGrantCore is this major's shared pure raw-grant verification
// primitive (CheckEnvelope re-verifies the raw grant through it).
func (Profile) verifyGrantCore(compact string, issuer TrustedIssuer, exp ExpectedGrant, b Bounds) (grantClaimsData, GrantFacts, error) {
	if !validKid(issuer.KeyID, b.KidBytes) || len(issuer.PublicKey) != b.PublicKeyBytes {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	if !validStringOrURI(exp.Issuer, b.IdentifierBytes) || !validStringOrURI(exp.Audience, b.IdentifierBytes) {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	if exp.ClockSkew < 0 || exp.ClockSkew > int64(b.ClockSkew) {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid // ceiling, not silent widening
	}
	if exp.EvaluationTime > int64(b.IntegerMagnitude) || exp.EvaluationTime < -int64(b.IntegerMagnitude) {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	kid, err := decodeGrantHeader(parts, b)
	if err != nil || kid != issuer.KeyID {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid // exact key ID
	}
	claims, err := successor.decodeGrantPayload(parts, b)
	if err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	if claims.Issuer != exp.Issuer {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	matched := ""
	for _, a := range claims.Audiences {
		if a == exp.Audience {
			matched = a
			break
		}
	}
	if matched == "" {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid // audience must match
	}
	if claims.IssuedAt > exp.EvaluationTime+exp.ClockSkew ||
		claims.NotBefore > exp.EvaluationTime+exp.ClockSkew ||
		claims.ExpiresAt <= exp.EvaluationTime-exp.ClockSkew {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	si := SigningInput{Kind: KindGrant, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(issuer.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	issuerFP, err := PublicKeyThumbprintRaw(issuer.PublicKey, &b)
	if err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	return claims, GrantFacts{
		Version:              2,
		Issuer:               claims.Issuer,
		GrantID:              claims.GrantID,
		IssuerKeyFingerprint: issuerFP,
		HolderThumbprint:     claims.JktRaw,
		MatchedAudience:      matched,
		IssuedAt:             claims.IssuedAt,
		NotBefore:            claims.NotBefore,
		ExpiresAt:            claims.ExpiresAt,
		Authorization:        AuthorizationNotEvaluated,
	}, nil
}

// VerifyGrant verifies a raw grant compact of this major against an exact
// trusted issuer and expected grant context. The result is non-authorizing
// facts.
func (Profile) VerifyGrant(compact string, issuer TrustedIssuer, expected ExpectedGrant) (f GrantFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	_, facts, err := successor.verifyGrantCore(compact, issuer, expected, b)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	return facts, nil
}

// CheckEnvelope performs combined verification of this major: the raw-grant
// primitive, the holder proof, thumbprint binding, context bindings, the
// BAP2-REQUEST digest, time window, nonce mode, and the selector algebra with
// lte/gte admitted.
func (Profile) CheckEnvelope(creds Credentials, expected ExpectedRequest) (f EnvelopeFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// caller-context revalidation before any credential work
	if !validHTM(expected.Method, b.MethodBytes) {
		return EnvelopeFacts{}, ErrInvalid
	}
	normalizedTarget, err := uriNormalized(expected.TargetURI, b)
	if err != nil || normalizedTarget != expected.TargetURI {
		return EnvelopeFacts{}, ErrInvalid
	}
	if !validUUID(expected.InvocationID) || !validOperationName(expected.Operation, b.OperationBytes) {
		return EnvelopeFacts{}, ErrInvalid
	}
	if expected.ProofMaxAge <= 0 || expected.ProofMaxAge > int64(b.ProofMaxAge) {
		return EnvelopeFacts{}, ErrInvalid // ceiling, not silent widening
	}
	if expected.ClockSkew < 0 || expected.ClockSkew > int64(b.ClockSkew) {
		return EnvelopeFacts{}, ErrInvalid
	}
	if _, err := JcsEncode(expected.CastArguments, &b); err != nil {
		return EnvelopeFacts{}, ErrInvalid // tagged, bounded cast arguments
	}
	// 1. re-verify the raw grant
	claims, gfacts, err := successor.verifyGrantCore(creds.Grant, expected.TrustedIssuer, ExpectedGrant{
		Issuer:         expected.Issuer,
		Audience:       expected.Audience,
		EvaluationTime: expected.EvaluationTime,
		ClockSkew:      expected.ClockSkew,
		Bounds:         &b,
	}, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 2. holder proof: header JWK, closed claims, signature
	parts, err := splitCompact(creds.Proof, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	holderKey, err := decodeProofHeaderFor(parts, b, proofProfileStandard)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	proof, err := successor.decodeProofPayload(parts, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	si := SigningInput{Kind: KindProof, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(holderKey, signingInputMessage(si), parts.Signature); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 3. holder thumbprint binding
	if jwkThumbprintOfKey(holderKey) != claims.JktRaw {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 4. context bindings
	athRaw := sha256.Sum256([]byte(creds.Grant))
	if athRaw != proof.AthRaw {
		return EnvelopeFacts{}, ErrInvalid
	}
	if proof.Method != expected.Method || proof.TargetURI != expected.TargetURI ||
		proof.Invocation != expected.InvocationID || proof.Operation != expected.Operation {
		return EnvelopeFacts{}, ErrInvalid
	}
	baReqRaw, err := successor.requestDigestRaw(expected.Operation, expected.CastArguments, &b)
	if err != nil || baReqRaw != proof.BaReqRaw {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 5. proof time window (inclusive)
	if proof.IssuedAt < expected.EvaluationTime-expected.ProofMaxAge-expected.ClockSkew ||
		proof.IssuedAt > expected.EvaluationTime+expected.ClockSkew {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 6. nonce mode
	if expected.Nonce.required {
		if proof.Nonce == nil || subtle.ConstantTimeCompare([]byte(*proof.Nonce), []byte(expected.Nonce.nonce)) != 1 {
			return EnvelopeFacts{}, ErrInvalid // constant-time
		}
	} else if proof.Nonce != nil {
		return EnvelopeFacts{}, ErrInvalid // must be absent
	}
	// 7. selectors of the matching operation apply conjunctively
	var ops []Value
	for _, op := range claims.Operations {
		if op.Name == expected.Operation {
			ops = op.Selectors
			break
		}
	}
	if ops == nil {
		return EnvelopeFacts{}, ErrInvalid // operation must exist in the grant
	}
	if err := successor.applySelectors(ops, expected.CastArguments); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	return EnvelopeFacts{
		Version:              2,
		Issuer:               gfacts.Issuer,
		GrantID:              gfacts.GrantID,
		IssuerKeyFingerprint: gfacts.IssuerKeyFingerprint,
		HolderThumbprint:     gfacts.HolderThumbprint,
		MatchedAudience:      gfacts.MatchedAudience,
		IssuedAt:             gfacts.IssuedAt,
		NotBefore:            gfacts.NotBefore,
		ExpiresAt:            gfacts.ExpiresAt,
		ProofID:              proof.ProofID,
		InvocationID:         proof.Invocation,
		Operation:            proof.Operation,
		TargetURI:            proof.TargetURI,
		GrantHash:            athRaw,
		RequestHash:          baReqRaw,
		ProofIssuedAt:        proof.IssuedAt,
		Authorization:        AuthorizationNotEvaluated,
	}, nil
}

// ---- deterministic producers ----

// GrantSigningInput composes the deterministic canonical grant signing input
// ("v":2 payload; this profile's selector validator admits lte/gte).
func (Profile) GrantSigningInput(g Grant, bounds *Bounds) (si SigningInput, err error) {
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
			if successor.validateSelector(sel, &b) != nil {
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
		{Key: "v", Val: Int(2)},
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
// input ("v":2 payload; ba_req carries the BAP2-REQUEST digest).
func (Profile) ProofSigningInput(p Proof, bounds *Bounds) (si SigningInput, err error) {
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
	if htu != p.TargetURI {
		return SigningInput{}, ErrInvalid
	}
	if len(p.HolderPublicKey) != b.PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	if len(p.GrantCompact) == 0 || len(p.GrantCompact) > b.CompactBytes {
		return SigningInput{}, ErrInvalid // producer ath compact-bytes bound
	}
	if err := scanCompact(p.GrantCompact, b); err != nil {
		return SigningInput{}, ErrInvalid
	}
	athRaw := sha256.Sum256([]byte(p.GrantCompact))
	baReqRaw, err := successor.requestDigestRaw(p.Operation, p.CastArguments, &b)
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
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("EdDSA")}, {Key: "jwk", Val: jwkValue}, {Key: "typ", Val: Str(proofTyp(proofProfileStandard))}}, &b)
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
		{Key: "v", Val: Int(2)},
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
// ("v":2 payload; typs and headers unchanged).
func (Profile) BoundaryAnchorSigningInput(a BoundaryAnchor, bounds *Bounds) (si SigningInput, err error) {
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
		{Key: "v", Val: Int(2)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindBoundaryAnchor, Protected: protected, Payload: payload}, nil
}

// KeyTransitionSigningInput composes the deterministic transition signing
// input ("v":2 payload).
func (Profile) KeyTransitionSigningInput(t KeyTransition, bounds *Bounds) (si SigningInput, err error) {
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
		{Key: "v", Val: Int(2)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindKeyTransition, Protected: protected, Payload: payload}, nil
}

// AssembleCompact assembles a compact JWS from a signing input and a 64-byte
// signature. The kind-specific re-parse uses this major's decoders; the
// byte-distinct local-loopback proof profile is a v1 surface and its kind is
// rejected here.
func (Profile) AssembleCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
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
	// kind-specific re-parse with this major's closed decoders
	parts, err := splitCompact(compact, b)
	if err != nil {
		return "", ErrInvalid
	}
	switch si.Kind {
	case KindGrant:
		if _, err := decodeGrantHeader(parts, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := successor.decodeGrantPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindProof:
		if _, err := decodeProofHeaderFor(parts, b, proofProfileStandard); err != nil {
			return "", ErrInvalid
		}
		if _, err := successor.decodeProofPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindBoundaryAnchor:
		if _, err := decodeAnchorHeader(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if err := successor.reparseAnchorPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindKeyTransition:
		if _, err := decodeTransitionHeader(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if err := successor.reparseTransitionPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	default:
		return "", ErrInvalid
	}
	return compact, nil
}

// reparseAnchorPayload runs the full closed anchor-claims decode on an
// assembled payload — assembly must reject a well-formed signing input whose
// payload members violate this major's profile, not merely decode as JSON.
// It mirrors BoundaryAnchorCodec.parse: the closed member set, the genesis
// rule (sequence 0 carries the all-zero chain hash), and the canonical-payload
// check (the received segment is the JCS re-encoding of the decoded value).
func (Profile) reparseAnchorPayload(p compactParts, b Bounds) error {
	payload, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return ErrInvalid
	}
	claims, ok := successor.decodeAnchorClaims(obj, b)
	if !ok {
		return ErrInvalid
	}
	if claims.Sequence == 0 && claims.ChainHash != [32]byte{} {
		return ErrInvalid
	}
	if err := canonicalSegment(p.PayloadSeg, p.Payload, b); err != nil {
		return ErrInvalid
	}
	return nil
}

// reparseTransitionPayload is the transition counterpart of
// reparseAnchorPayload (member set + canonical payload; transitions carry no
// genesis rule).
func (Profile) reparseTransitionPayload(p compactParts, b Bounds) error {
	payload, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return ErrInvalid
	}
	if _, ok := successor.decodeTransitionClaims(obj, b); !ok {
		return ErrInvalid
	}
	if err := canonicalSegment(p.PayloadSeg, p.Payload, b); err != nil {
		return ErrInvalid
	}
	return nil
}

// ---- consumption chain ----

// chainHash is this major's BAP2-CHAIN domain hash.
func (Profile) chainHash(row []byte) [32]byte {
	hh := sha256.New()
	hh.Write(successorChainPrefix)
	hh.Write(row)
	var out [32]byte
	copy(out[:], hh.Sum(nil))
	return out
}

// EncodeConsumptionEntry produces the canonical row bytes and domain hash
// ("v":2 row, BAP2-CHAIN\0 domain). Sequence one requires the all-zero
// predecessor.
func (Profile) EncodeConsumptionEntry(e ConsumptionEntry, bounds *Bounds) (out ConsumedEntry, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return ConsumedEntry{}, ErrInvalid
	}
	if !validStringOrURI(e.ChainID, b.IdentifierBytes) {
		return ConsumedEntry{}, ErrInvalid
	}
	if _, ok := canonicalDigestString(e.Commitment); !ok {
		return ConsumedEntry{}, ErrInvalid
	}
	if _, ok := canonicalDigestString(e.PreviousHash); !ok {
		return ConsumedEntry{}, ErrInvalid
	}
	if e.Sequence < 1 {
		return ConsumedEntry{}, ErrInvalid // sequence zero is invalid on rows
	}
	if e.Sequence == 1 && e.PreviousHash != allZeroHashB64 {
		return ConsumedEntry{}, ErrInvalid // genesis row binds the zero predecessor
	}
	row, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(e.ChainID)},
		{Key: "commitment", Val: Str(e.Commitment)},
		{Key: "previous", Val: Str(e.PreviousHash)},
		{Key: "sequence", Val: Int(e.Sequence)},
		{Key: "v", Val: Int(2)},
	}, &b)
	if err != nil {
		return ConsumedEntry{}, ErrInvalid
	}
	if len(row) > b.ChainRowBytes {
		return ConsumedEntry{}, ErrInvalid
	}
	return ConsumedEntry{Row: row, Hash: successor.chainHash(row)}, nil
}

// parseCanonicalRow requires exact canonical bytes, the closed member set,
// and "v":2.
func (Profile) parseCanonicalRow(raw []byte, b Bounds) (chainRowData, error) {
	var out chainRowData
	if len(raw) == 0 || len(raw) > b.ChainRowBytes {
		return out, ErrInvalid
	}
	v, err := JsonDecode(raw, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 5 {
		return out, ErrInvalid
	}
	commitment, previous := "", ""
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 2 {
				return out, ErrInvalid // this major rejects v1 rows
			}
		case "chain_id":
			if s, ok := m.Val.(Str); ok {
				out.ChainID = string(s)
			}
		case "commitment":
			if s, ok := m.Val.(Str); ok {
				commitment = string(s)
			}
		case "previous":
			if s, ok := m.Val.(Str); ok {
				previous = string(s)
			}
		case "sequence":
			if t, ok := integralTime(m.Val, b); ok {
				out.Sequence = t
			} else {
				return out, ErrInvalid
			}
		default:
			return out, ErrInvalid
		}
	}
	if !validStringOrURI(out.ChainID, b.IdentifierBytes) {
		return out, ErrInvalid
	}
	c, ok := canonicalDigestString(commitment)
	if !ok {
		return out, ErrInvalid
	}
	out.Commitment = c
	p, ok := canonicalDigestString(previous)
	if !ok {
		return out, ErrInvalid
	}
	out.Previous = p
	// canonical re-encode equality
	reenc, err := JcsEncode(obj, &b)
	if err != nil || string(reenc) != string(raw) {
		return out, ErrInvalid
	}
	return out, nil
}

// CheckChain verifies a consumption range: raw canonical rows of this major
// against mandatory caller boundaries, with the BAP2-CHAIN domain hash.
func (Profile) CheckChain(input ChainInput, expected ExpectedChain) (f ChainFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return ChainFacts{}, ErrInvalid
	}
	if !validStringOrURI(expected.ChainID, b.IdentifierBytes) {
		return ChainFacts{}, ErrInvalid
	}
	if expected.FirstSequence < 1 || expected.LastSequence < expected.FirstSequence ||
		expected.RowCount < 1 || expected.RowCount > int64(b.ChainRows) {
		return ChainFacts{}, ErrInvalid
	}
	if expected.LastSequence-expected.FirstSequence+1 != expected.RowCount {
		return ChainFacts{}, ErrInvalid // range/count coherence
	}
	wantPrev, ok := canonicalDigestString(expected.PreviousHash)
	if !ok {
		return ChainFacts{}, ErrInvalid
	}
	wantHead, ok := canonicalDigestString(expected.LastHash)
	if !ok {
		return ChainFacts{}, ErrInvalid
	}
	if len(input.Rows) == 0 || int64(len(input.Rows)) > int64(b.ChainRows) {
		return ChainFacts{}, ErrInvalid
	}
	if int64(len(input.Rows)) != expected.RowCount {
		return ChainFacts{}, ErrInvalid
	}
	var lastHash [32]byte
	for i, raw := range input.Rows {
		row, err := successor.parseCanonicalRow(raw, b)
		if err != nil {
			return ChainFacts{}, ErrInvalid
		}
		if row.ChainID != expected.ChainID {
			return ChainFacts{}, ErrInvalid
		}
		if row.Sequence != expected.FirstSequence+int64(i) {
			return ChainFacts{}, ErrInvalid // consecutive sequence
		}
		if i == 0 {
			if row.Sequence == 1 {
				if row.Previous != [32]byte{} {
					return ChainFacts{}, ErrInvalid
				}
			}
			if row.Previous != wantPrev {
				return ChainFacts{}, ErrInvalid // caller predecessor binding
			}
		} else {
			if row.Previous != lastHash {
				return ChainFacts{}, ErrInvalid // predecessor link
			}
		}
		lastHash = successor.chainHash(raw)
	}
	if lastHash != wantHead {
		return ChainFacts{}, ErrInvalid // caller head binding
	}
	return ChainFacts{
		ChainID:       expected.ChainID,
		FirstSequence: expected.FirstSequence,
		LastSequence:  expected.LastSequence,
		RowCount:      expected.RowCount,
		LastHash:      lastHash,
		Checks: []string{
			"canonical_rows", "chain_identity", "consecutive_sequence",
			"predecessor_links", "row_count", "caller_boundaries",
		},
		Trust: TrustNotEvaluated,
	}, nil
}

// ---- anchors and transitions ----

// decodeAnchorClaims is the closed 7-member anchor payload ("v":2).
func (Profile) decodeAnchorClaims(obj Obj, b Bounds) (anchorClaims, bool) {
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
			if i, isInt := m.Val.(Int); !isInt || i != 2 {
				return out, false // this major rejects v1 bytes
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

// decodeTransitionClaims is the closed 7-member transition payload ("v":2).
func (Profile) decodeTransitionClaims(obj Obj, b Bounds) (transitionClaims, bool) {
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
			if i, isInt := m.Val.(Int); !isInt || i != 2 {
				return out, false // this major rejects v1 bytes
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

// verifyAnchorCompact is this major's anchor primitive: shared headers,
// segments, windows, and gates; the "v":2 claims decoder.
func (Profile) verifyAnchorCompact(compact string, key HistoricalPublicKey, expected ExpectedAnchor, b Bounds) (anchorClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return anchorClaims{}, ErrInvalid // role-bounded frame read
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
	claims, ok := successor.decodeAnchorClaims(obj, b)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	// the genesis rule binds every anchor validation of this major too
	if err := enforceAnchorGenesis(claims); err != nil {
		return anchorClaims{}, ErrInvalid
	}
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

// VerifyHistoricalAnchor verifies a boundary-anchor compact of this major
// against one exact historical key and expected anchor tuple.
func (Profile) VerifyHistoricalAnchor(compact string, key HistoricalPublicKey, expected ExpectedAnchor) (f AnchorFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return AnchorFacts{}, ErrInvalid
	}
	claims, err := successor.verifyAnchorCompact(compact, key, expected, b)
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

// verifyTransitionCompact is this major's transition primitive.
func (Profile) verifyTransitionCompact(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition, b Bounds) (transitionClaims, error) {
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
	claims, ok := successor.decodeTransitionClaims(obj, b)
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

// VerifyKeyTransition verifies a transition compact of this major.
func (Profile) VerifyKeyTransition(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition) (f KeyTransitionFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return KeyTransitionFacts{}, ErrInvalid
	}
	claims, err := successor.verifyTransitionCompact(compact, currentKey, nextKey, expected, b)
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

// ---- anchored export ----

// verifyAnchoredExportCore is this major's export core: the shared
// expected-context hoist, digest seam, and framing walk; the BAP2 magic, the
// "v":2 header, rows, and anchor/transition decoders.
func (Profile) verifyAnchoredExportCore(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport, digest archiveDigestFn) (AnchoredExportFacts, error) {
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// expected-context validation BEFORE the archive digest
	if err := validateExpectedAnchoredExport(&expected, obj, keys, b); err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	if len(obj.Chunks) == 0 || len(obj.Chunks) > b.ArchiveChunks {
		return AnchoredExportFacts{}, ErrInvalid
	}
	for _, c := range obj.Chunks {
		if len(c) == 0 {
			return AnchoredExportFacts{}, ErrInvalid // nonempty proper chunks
		}
	}
	digestRaw, total, err := digest(obj.Chunks, int64(b.ArchiveBytes))
	if err != nil || total > int64(b.ArchiveBytes) {
		return AnchoredExportFacts{}, ErrInvalid
	}
	wantDigest, _ := canonicalDigestString(expected.Digest)
	if digestRaw != wantDigest {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// framing: the BAP2 magic + length-prefixed frames with exact EOF
	if string(obj.Chunks[0]) != string(successorArchiveMagic) {
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
			if i, ok := m.Val.(Int); !ok || i != 2 {
				return AnchoredExportFacts{}, ErrInvalid // this major rejects v1 headers
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
	startClaims, err := successor.verifyAnchorCompact(string(startCompactRaw), keys[0], expected.StartAnchor, b)
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
		claims, err := successor.verifyTransitionCompact(string(traw), keys[i], keys[i+1], expected.Transitions[i], b)
		if err != nil {
			return AnchoredExportFacts{}, ErrInvalid
		}
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
	endClaims, err := successor.verifyAnchorCompact(string(endCompactRaw), keys[len(keys)-1], expected.EndAnchor, b)
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
	// re-check every row of this major against the chain boundaries
	var lastHash [32]byte
	for i, rraw := range rowFrames {
		row, err := successor.parseCanonicalRow(rraw, b)
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
		lastHash = successor.chainHash(rraw)
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

// VerifyAnchoredExport verifies a complete archived object of this major
// through the same archive-digest seam as the v1 façade.
func (Profile) VerifyAnchoredExport(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport) (f AnchoredExportFacts, err error) {
	defer closedResult(&err)
	return successor.verifyAnchoredExportCore(obj, keys, expected, archiveDigest)
}

// validateExpectedExport is the encode-side expected-context suite: the
// verify-path hoist minus its verify-only legs — no archive-digest width and
// no object-store version (this producer derives its own digest and holds no
// object store) and no key-chain shapes (the encode path holds no public
// keys; the expected tuples carry the key identities).
func (Profile) validateExpectedExport(expected *ExpectedAnchoredExport, b Bounds) error {
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
	// cross-binding: the anchors attest THE chain's boundaries
	if expected.StartAnchor.ChainID != expected.Chain.ChainID || expected.EndAnchor.ChainID != expected.Chain.ChainID ||
		expected.StartAnchor.ChainHash != expected.Chain.PreviousHash || expected.EndAnchor.ChainHash != expected.Chain.LastHash {
		return ErrInvalid
	}
	if len(expected.Transitions) > b.KeyTransitions {
		return ErrInvalid
	}
	// the fingerprint walk seeds with the start anchor's key fingerprint:
	// any later to-fingerprint equal to one already visited is a cycle
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
	return nil
}

// EncodeAnchoredExport mirrors the v1 producer's full contract over this
// major: the shared expected-side consistency suite, the row re-check, gated
// parses, the key-path walk, the BAP2 magic, and the "v":2 header.
func (Profile) EncodeAnchoredExport(input AnchoredExportInput, expected ExpectedAnchoredExport) (out EncodedExport, err error) {
	defer closedResult(&err)
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// expected-side consistency: the encode-side suite — the verify-path hoist
	// minus the verify-only digest and object-store-version contracts (this
	// producer derives its own digest and holds no object store, so the
	// ExpectedAnchoredExport digest/object-version fields are not read here)
	if err := successor.validateExpectedExport(&expected, b); err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// rows re-checked against the chain
	if int64(len(input.Rows)) != expected.Chain.RowCount {
		return EncodedExport{}, ErrInvalid
	}
	var lastHash [32]byte
	for i, raw := range input.Rows {
		row, err := successor.parseCanonicalRow(raw, b)
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
		lastHash = successor.chainHash(raw)
	}
	wantHead, _ := canonicalDigestString(expected.Chain.LastHash)
	if lastHash != wantHead {
		return EncodedExport{}, ErrInvalid
	}
	// gated parses + 7-field matches for both anchors and every transition
	startParsed, err := successor.parseAnchorCompactGated(input.StartAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(startParsed, expected.StartAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	endParsed, err := successor.parseAnchorCompactGated(input.EndAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(endParsed, expected.EndAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	transitions := make([]transitionClaims, 0, len(input.Transitions))
	for i, traw := range input.Transitions {
		claims, err := successor.parseTransitionCompactGated(traw, b)
		if err != nil {
			return EncodedExport{}, ErrInvalid
		}
		if !transitionTupleMatch(claims, expected.Transitions[i]) {
			return EncodedExport{}, ErrInvalid
		}
		transitions = append(transitions, claims)
	}
	// key-path walk: NON-STRICT end-anchor chronology
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
	// header + BAP2 magic frames
	header, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(expected.Chain.ChainID)},
		{Key: "first_sequence", Val: Int(expected.Chain.FirstSequence)},
		{Key: "last_hash", Val: Str(expected.Chain.LastHash)},
		{Key: "last_sequence", Val: Int(expected.Chain.LastSequence)},
		{Key: "previous_hash", Val: Str(expected.Chain.PreviousHash)},
		{Key: "row_count", Val: Int(expected.Chain.RowCount)},
		{Key: "transition_count", Val: Int(len(expected.Transitions))},
		{Key: "v", Val: Int(2)},
	}, &b)
	if err != nil || len(header) > b.ArchiveHeaderBytes {
		return EncodedExport{}, ErrInvalid
	}
	archive := append([]byte(nil), successorArchiveMagic...)
	archive = appendFrame(archive, header)
	archive = appendFrame(archive, []byte(input.StartAnchor))
	for _, t := range input.Transitions {
		archive = appendFrame(archive, []byte(t))
	}
	for _, r := range input.Rows {
		archive = appendFrame(archive, r)
	}
	archive = appendFrame(archive, []byte(input.EndAnchor))
	chunkCount := 1 + 1 + 1 + len(input.Transitions) + len(input.Rows) + 1
	if int64(len(archive)) > int64(b.ArchiveBytes) || chunkCount > b.ArchiveChunks {
		return EncodedExport{}, ErrInvalid
	}
	digestRaw := sha256.Sum256(archive)
	return EncodedExport{Archive: archive, Digest: digestRaw, ByteCount: int64(len(archive))}, nil
}

// parseAnchorCompactGated is this major's encode-side gated anchor parse.
func (Profile) parseAnchorCompactGated(compact string, b Bounds) (anchorClaims, error) {
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
	claims, ok := successor.decodeAnchorClaims(obj, b)
	if !ok {
		return anchorClaims{}, ErrInvalid
	}
	if claims.Sequence == 0 && claims.ChainHash != [32]byte{} {
		return anchorClaims{}, ErrInvalid
	}
	return claims, nil
}

// parseTransitionCompactGated is this major's encode-side gated transition
// parse.
func (Profile) parseTransitionCompactGated(compact string, b Bounds) (transitionClaims, error) {
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
	claims, ok := successor.decodeTransitionClaims(obj, b)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	return claims, nil
}
