package verifier

import "crypto/sha256"

// The grant/proof verification core (docs/protocol-v1.md § Claims, § Public
// verification contract). Correctly signed closed JSON objects may use ANY
// member order — verification uses the exact received segments
// (REQ1-SIGNING-any-order); canonical byte-equality applies only to the
// anchor/transition compacts (ADR 0017 clause 4).

// decodeGrantHeader validates the exact grant protected header
// {alg:"EdDSA", kid, typ:"ba+cap"} and returns the kid.
func decodeGrantHeader(p compactParts, b Bounds) (string, error) {
	v, err := JsonDecode(p.Protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid // REQ1-HEADER-closed-set
	}
	var kid *Str
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return "", ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != "ba+cap" {
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
	if kid == nil || !validKid(string(*kid), b.KidBytes) {
		return "", ErrInvalid
	}
	return string(*kid), nil
}

// decodeProofHeader validates the exact proof protected header
// {alg:"EdDSA", jwk:public-OKP-JWK, typ:"dpop+jwt"} and returns the raw
// holder public key. Every additional JWK member — private `d` included — is
// invalid (REQ1-HEADER-no-private-jwk).
func decodeProofHeader(p compactParts, b Bounds) ([]byte, error) {
	v, err := JsonDecode(p.Protected, &b)
	if err != nil {
		return nil, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return nil, ErrInvalid
	}
	var jwkBytes []byte
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return nil, ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != "dpop+jwt" {
				return nil, ErrInvalid
			}
		case "jwk":
			enc, err := JcsEncode(m.Val, &b)
			if err != nil {
				return nil, ErrInvalid
			}
			jwkBytes = enc
		default:
			return nil, ErrInvalid
		}
	}
	if jwkBytes == nil {
		return nil, ErrInvalid
	}
	return JwkDecodePublic(jwkBytes, &b)
}

// grantClaimsData is the validated closed grant payload.
type grantClaimsData struct {
	Issuer     string
	GrantID    string
	Audiences  []string
	IssuedAt   int64
	NotBefore  int64
	ExpiresAt  int64
	JktRaw     [32]byte
	Operations []OperationDef
}

// decodeGrantPayload validates every grant claim (REQ1-CLAIM-closed-set,
// REQ1-CLAIM-proof-required analog, REQ1-CLAIM-operation-shape).
func decodeGrantPayload(p compactParts, b Bounds) (grantClaimsData, error) {
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
			if i, ok := m.Val.(Int); !ok || i != 1 {
				return out, ErrInvalid // REQ1-CLAIM-v
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
					if validateSelector(sel, &b) != nil {
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
		return out, ErrInvalid // coherent signed times: iat < exp, nbf < exp
	}
	return out, nil
}

// proofClaimsData is the validated closed proof payload.
type proofClaimsData struct {
	ProofID    string
	Method     string
	TargetURI  string
	IssuedAt   int64
	Nonce      *string
	Invocation string
	Operation  string
	AthRaw     [32]byte
	BaReqRaw   [32]byte
}

// decodeProofPayload validates every proof claim: every row except nonce is
// required and no other claim is accepted (REQ1-CLAIM-proof-required,
// REQ1-CLAIM-no-extra).
func decodeProofPayload(p compactParts, b Bounds) (proofClaimsData, error) {
	var out proofClaimsData
	v, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) < 9 || len(obj) > 10 {
		return out, ErrInvalid
	}
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 1 {
				return out, ErrInvalid // REQ1-CLAIM-proof-v
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
	if _, err := uriNormalized(out.TargetURI, b); err != nil {
		return out, ErrInvalid // REQ1-URI-pre-normalized
	}
	return out, nil
}

// DecodeStatus is the fixed decode marker: successful decode proves shape
// only (REQ1-VERIFY-decode-not-evaluated).
type DecodeStatus int

const (
	DecodeVerificationNotEvaluated DecodeStatus = iota
)

// GrantDecoded is the decode_grant result: validated closed claims plus the
// header kid, with verification not evaluated.
type GrantDecoded struct {
	KeyID            string
	Version          int
	Issuer           string
	GrantID          string
	Audiences        []string
	IssuedAt         int64
	NotBefore        int64
	ExpiresAt        int64
	HolderThumbprint [32]byte
	Operations       []OperationDef
	Verification     DecodeStatus
}

// ProofDecoded is the decode_proof result.
type ProofDecoded struct {
	ProofID      string
	Version      int
	Method       string
	TargetURI    string
	IssuedAt     int64
	InvocationID string
	Operation    string
	Nonce        string
	HasNonce     bool
	Verification DecodeStatus
}

// DecodeGrant decodes and closed-set-validates a raw grant compact. It
// performs no signature verification (REQ1-VERIFY-decode-not-evaluated).
func DecodeGrant(compact string, bounds *Bounds) (d GrantDecoded, err error) {
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
	claims, err := decodeGrantPayload(parts, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	return GrantDecoded{
		KeyID:            kid,
		Version:          1,
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

// DecodeProof decodes and closed-set-validates a raw proof compact.
func DecodeProof(compact string, bounds *Bounds) (d ProofDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	if _, err := decodeProofHeader(parts, b); err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	claims, err := decodeProofPayload(parts, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	out := ProofDecoded{
		ProofID:      claims.ProofID,
		Version:      1,
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

// UntrustedKeyLocator bounds the complete compact input, requires exactly
// three segments, then bounds, decodes, and validates ONLY the protected
// grant header; payload and signature stay opaque. It never selects a key,
// verifies, or evaluates trust (REQ1-LOCATOR-not-authority,
// REQ1-LOCATOR-opaque-payload).
func UntrustedKeyLocator(compact string, bounds *Bounds) (loc KeyLocator, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return KeyLocator{}, ErrInvalid
	}
	if len(compact) == 0 || len(compact) > b.CompactBytes {
		return KeyLocator{}, ErrInvalid
	}
	if stringsCount(compact, '.') != 2 {
		return KeyLocator{}, ErrInvalid // REQ1-LOCATOR-three-segments
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

// verifyGrantCore is the shared pure raw-grant verification primitive
// (check_envelope re-verifies the raw grant through it; ADR 0003 D6).
func verifyGrantCore(compact string, issuer TrustedIssuer, exp ExpectedGrant, b Bounds) (grantClaimsData, GrantFacts, error) {
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
	claims, err := decodeGrantPayload(parts, b)
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
	// time invariants: iat/nbf/exp coherence held at decode; the window:
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
		Version:              1,
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

// VerifyGrant verifies a raw grant compact against an exact trusted issuer
// and expected grant context. The result is non-authorizing facts.
func VerifyGrant(compact string, issuer TrustedIssuer, expected ExpectedGrant) (f GrantFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	_, facts, err := verifyGrantCore(compact, issuer, expected, b)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	return facts, nil
}

// CheckEnvelope performs combined verification: it re-verifies the raw grant
// through the same pure primitive, verifies the holder signature and
// thumbprint, and binds ath, method, URI, invocation, operation, ba_req,
// time, nonce, and every selector (REQ1-VERIFY-envelope-binding).
func CheckEnvelope(creds Credentials, expected ExpectedRequest) (f EnvelopeFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// caller-context revalidation before any credential work
	if !validHTM(expected.Method, b.MethodBytes) {
		return EnvelopeFacts{}, ErrInvalid
	}
	if _, err := uriNormalized(expected.TargetURI, b); err != nil {
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
	claims, gfacts, err := verifyGrantCore(creds.Grant, expected.TrustedIssuer, ExpectedGrant{
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
	holderKey, err := decodeProofHeader(parts, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	proof, err := decodeProofPayload(parts, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	si := SigningInput{Kind: KindProof, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(holderKey, signingInputMessage(si), parts.Signature); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 3. holder thumbprint binding: cnf.jkt is the proof JWK's thumbprint
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
	baReqRaw, err := requestDigestRaw(expected.Operation, expected.CastArguments, &b)
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
		if proof.Nonce == nil || *proof.Nonce != expected.Nonce.nonce {
			return EnvelopeFacts{}, ErrInvalid
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
	if err := applySelectors(ops, expected.CastArguments); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	return EnvelopeFacts{
		Version:              1,
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

// jwkThumbprintOfKey is the RFC 7638 thumbprint of a raw public key's JWK.
func jwkThumbprintOfKey(raw []byte) [32]byte {
	pre := []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + Base64urlEncode(raw) + `"}`)
	return sha256.Sum256(pre)
}

func stringsCount(s string, c byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			n++
		}
	}
	return n
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
