package verifier

import (
	"crypto/sha256"
	"strings"
)

const contentAssertionType = "ba+content-assertion"

type ContentAssertion struct {
	AttestorKeyID string
	Jti           string
	Iss           string
	Aud           string
	Sub           string
	Profile       string
	ProfileDigest [32]byte
	ContentDigest [32]byte
	Gen           int64
	Prev          [32]byte
	Iat           int64
	Nbf           int64
	Exp           int64
}

// ExpectedContentAssertion is the complete caller-supplied verification
// context. Bounds is required; nil is invalid rather than an implicit default.
type ExpectedContentAssertion struct {
	Attestor      HistoricalPublicKey
	Issuer        string
	Audience      string
	Subject       string
	Profile       string
	ProfileDigest [32]byte
	ContentDigest [32]byte
	Now           int64
	Bounds        *Bounds
}

type DecodedContentAssertion struct {
	Version       int
	AttestorKeyID string
	Jti           string
	Iss           string
	Aud           string
	Sub           string
	Profile       string
	ProfileDigest [32]byte
	ContentDigest [32]byte
	Gen           int64
	Prev          [32]byte
	Iat           int64
	Nbf           int64
	Exp           int64
	Verification  DecodeStatus
}

// ContentAssertionFacts is redacted evidence of signature and window checks,
// never an authorization decision.
type ContentAssertionFacts struct {
	Version                int
	AttestorKeyID          string
	AttestorKeyFingerprint [32]byte
	Jti                    string
	Iss                    string
	Aud                    string
	Sub                    string
	Profile                string
	ProfileDigest          [32]byte
	ContentDigest          [32]byte
	Gen                    int64
	Prev                   [32]byte
	Iat                    int64
	Nbf                    int64
	Exp                    int64
	Digest                 [32]byte
	Verification           AttestationVerification
	Trust                  Trust
}

type contentAssertionClaims struct {
	Jti           string
	Iss           string
	Aud           string
	Sub           string
	Profile       string
	ProfileDigest [32]byte
	ContentDigest [32]byte
	Gen           int64
	Prev          [32]byte
	Iat           int64
	Nbf           int64
	Exp           int64
}

func ContentDigest(content []byte, bounds *Bounds) (digest [32]byte, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil || len(content) == 0 || len(content) > b.ContentBytes {
		return [32]byte{}, ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("BAP1-CONTENT\x00"))
	_, _ = h.Write(content)
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func AssertionSigningInput(a ContentAssertion, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil || !validKid(a.AttestorKeyID, b.KidBytes) ||
		!validContentAssertionIdentifier(a.Jti, b) || !validContentAssertionIdentifier(a.Iss, b) ||
		!validContentAssertionIdentifier(a.Aud, b) || !validContentAssertionIdentifier(a.Sub, b) ||
		!validContentAssertionIdentifier(a.Profile, b) || !validContentAssertionNumbers(a.Gen, a.Iat, a.Nbf, a.Exp, a.Prev, b) {
		return SigningInput{}, ErrInvalid
	}
	protected, err := JcsEncode(Obj{
		{Key: "alg", Val: Str("EdDSA")}, {Key: "kid", Val: Str(a.AttestorKeyID)}, {Key: "typ", Val: Str(contentAssertionType)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	payload, err := JcsEncode(Obj{
		{Key: "aud", Val: Str(a.Aud)},
		{Key: "content_digest", Val: Str(Base64urlEncode(a.ContentDigest[:]))},
		{Key: "exp", Val: Int(a.Exp)}, {Key: "gen", Val: Int(a.Gen)}, {Key: "iat", Val: Int(a.Iat)},
		{Key: "iss", Val: Str(a.Iss)}, {Key: "jti", Val: Str(a.Jti)}, {Key: "nbf", Val: Int(a.Nbf)},
		{Key: "prev", Val: Str(Base64urlEncode(a.Prev[:]))}, {Key: "profile", Val: Str(a.Profile)},
		{Key: "profile_digest", Val: Str(Base64urlEncode(a.ProfileDigest[:]))}, {Key: "sub", Val: Str(a.Sub)}, {Key: "v", Val: Int(1)},
	}, &b)
	if err != nil || validateProducedContentAssertion(protected, payload, b) != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindContentAssertion, Protected: protected, Payload: payload}, nil
}

func AssembleContentAssertionCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
	defer closedResult(&err)
	if si.Kind != KindContentAssertion {
		return "", ErrInvalid
	}
	b, err := resolveBounds(bounds)
	if err != nil || len(signature) != b.SignatureBytes {
		return "", ErrInvalid
	}
	protectedSeg, payloadSeg, signatureSeg := Base64urlEncode(si.Protected), Base64urlEncode(si.Payload), Base64urlEncode(signature)
	if len(protectedSeg) > b.EncodedSegmentBytes || len(payloadSeg) > b.EncodedSegmentBytes || len(signatureSeg) > b.EncodedSegmentBytes {
		return "", ErrInvalid
	}
	compact = protectedSeg + "." + payloadSeg + "." + signatureSeg
	if _, err := decodeContentAssertionParts(compact, b); err != nil {
		return "", ErrInvalid
	}
	return compact, nil
}

func DecodeContentAssertion(compact string, bounds *Bounds) (decoded DecodedContentAssertion, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return DecodedContentAssertion{}, ErrInvalid
	}
	parts, err := decodeContentAssertionParts(compact, b)
	if err != nil {
		return DecodedContentAssertion{}, ErrInvalid
	}
	c := parts.Claims
	return DecodedContentAssertion{Version: 1, AttestorKeyID: parts.KeyID, Jti: c.Jti, Iss: c.Iss, Aud: c.Aud, Sub: c.Sub,
		Profile: c.Profile, ProfileDigest: c.ProfileDigest, ContentDigest: c.ContentDigest, Gen: c.Gen, Prev: c.Prev,
		Iat: c.Iat, Nbf: c.Nbf, Exp: c.Exp, Verification: DecodeVerificationNotEvaluated}, nil
}

func AssertionDigest(compact string, bounds *Bounds) (digest [32]byte, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	if _, err := decodeContentAssertionParts(compact, b); err != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256([]byte(compact)), nil
}

func VerifyContentAssertion(compact string, expected ExpectedContentAssertion) (facts ContentAssertionFacts, err error) {
	defer closedResult(&err)
	if expected.Bounds == nil {
		return ContentAssertionFacts{}, ErrInvalid
	}
	b, err := resolveBounds(expected.Bounds)
	if err != nil || validateExpectedContentAssertion(expected, b) != nil {
		return ContentAssertionFacts{}, ErrInvalid
	}
	parts, err := decodeContentAssertionParts(compact, b)
	if err != nil || parts.KeyID != expected.Attestor.KeyID {
		return ContentAssertionFacts{}, ErrInvalid
	}
	c := parts.Claims
	if c.Iss != expected.Issuer || c.Aud != expected.Audience || c.Sub != expected.Subject || c.Profile != expected.Profile || c.ProfileDigest != expected.ProfileDigest || c.ContentDigest != expected.ContentDigest {
		return ContentAssertionFacts{}, ErrInvalid
	}
	if c.Iat < expected.Attestor.ValidFrom || c.Nbf < expected.Attestor.ValidFrom || (!expected.Attestor.ValidBeforeUnbounded && c.Exp > expected.Attestor.ValidBefore) {
		return ContentAssertionFacts{}, ErrInvalid
	}
	if expected.Now < c.Nbf || expected.Now >= c.Exp {
		return ContentAssertionFacts{}, ErrInvalid
	}
	si := SigningInput{Kind: KindContentAssertion, Protected: parts.Compact.Protected, Payload: parts.Compact.Payload}
	if verifyEd25519(expected.Attestor.PublicKey, signingInputMessage(si), parts.Compact.Signature) != nil {
		return ContentAssertionFacts{}, ErrInvalid
	}
	return ContentAssertionFacts{
		Version: 1, AttestorKeyID: parts.KeyID, AttestorKeyFingerprint: jwkThumbprintOfKey(expected.Attestor.PublicKey),
		Jti: c.Jti, Iss: c.Iss, Aud: c.Aud, Sub: c.Sub, Profile: c.Profile, ProfileDigest: c.ProfileDigest,
		ContentDigest: c.ContentDigest, Gen: c.Gen, Prev: c.Prev, Iat: c.Iat, Nbf: c.Nbf, Exp: c.Exp,
		Digest: sha256.Sum256([]byte(compact)), Verification: AttestationVerificationSignatureAndWindow, Trust: TrustNotEvaluated,
	}, nil
}

func VerifyContentAssertionSuccessor(predecessor, successor ContentAssertionFacts, bounds *Bounds) (err error) {
	defer closedResult(&err)
	if bounds == nil {
		return ErrInvalid
	}
	b, err := resolveBounds(bounds)
	if err != nil || validateContentAssertionFacts(predecessor, b) != nil || validateContentAssertionFacts(successor, b) != nil {
		return ErrInvalid
	}
	if predecessor.Iss != successor.Iss || predecessor.Aud != successor.Aud || predecessor.Sub != successor.Sub || predecessor.Profile != successor.Profile || predecessor.ProfileDigest != successor.ProfileDigest {
		return ErrInvalid
	}
	if predecessor.Gen >= int64(b.IntegerMagnitude) || successor.Gen != predecessor.Gen+1 || successor.Prev != predecessor.Digest || successor.Iat < predecessor.Iat || successor.Jti == predecessor.Jti {
		return ErrInvalid
	}
	return nil
}

type decodedContentAssertion struct {
	Compact compactParts
	KeyID   string
	Claims  contentAssertionClaims
}

func splitContentAssertionCompact(compact string, b Bounds) (compactParts, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes || scanCompact(compact, b) != nil {
		return compactParts{}, ErrInvalid
	}
	first, last := strings.IndexByte(compact, '.'), strings.LastIndexByte(compact, '.')
	for _, n := range []int{first, last - first - 1, len(compact) - last - 1} {
		decoded, ok := roleAttestationDecodedSegmentLength(n)
		if !ok || decoded > b.DecodedSegmentBytes {
			return compactParts{}, ErrInvalid
		}
	}
	return splitCompact(compact, b)
}

func decodeContentAssertionParts(compact string, b Bounds) (decodedContentAssertion, error) {
	p, err := splitContentAssertionCompact(compact, b)
	if err != nil {
		return decodedContentAssertion{}, ErrInvalid
	}
	kid, err := decodeContentAssertionHeader(p, b)
	if err != nil {
		return decodedContentAssertion{}, ErrInvalid
	}
	claims, err := decodeContentAssertionPayload(p, b)
	if err != nil {
		return decodedContentAssertion{}, ErrInvalid
	}
	return decodedContentAssertion{Compact: p, KeyID: kid, Claims: claims}, nil
}

func decodeContentAssertionHeader(p compactParts, b Bounds) (string, error) {
	v, err := JsonDecode(p.Protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid
	}
	var kid string
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return "", ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != contentAssertionType {
				return "", ErrInvalid
			}
		case "kid":
			s, ok := m.Val.(Str)
			if !ok {
				return "", ErrInvalid
			}
			kid = string(s)
		default:
			return "", ErrInvalid
		}
	}
	if !validKid(kid, b.KidBytes) {
		return "", ErrInvalid
	}
	canonical, err := JcsEncode(obj, &b)
	if err != nil || string(canonical) != string(p.Protected) {
		return "", ErrInvalid
	}
	return kid, nil
}

func decodeContentAssertionPayload(p compactParts, b Bounds) (contentAssertionClaims, error) {
	var out contentAssertionClaims
	v, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 13 {
		return out, ErrInvalid
	}
	seenVersion := false
	for _, m := range obj {
		switch m.Key {
		case "v":
			i, ok := m.Val.(Int)
			if !ok || i != 1 {
				return out, ErrInvalid
			}
			seenVersion = true
		case "jti":
			out.Jti, ok = contentString(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "iss":
			out.Iss, ok = contentString(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "aud":
			out.Aud, ok = contentString(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "sub":
			out.Sub, ok = contentString(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "profile":
			out.Profile, ok = contentString(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "profile_digest":
			out.ProfileDigest, ok = contentDigestValue(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "content_digest":
			out.ContentDigest, ok = contentDigestValue(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "prev":
			out.Prev, ok = contentDigestValue(m.Val)
			if !ok {
				return out, ErrInvalid
			}
		case "gen":
			out.Gen, ok = integralTime(m.Val, b)
			if !ok {
				return out, ErrInvalid
			}
		case "iat":
			out.Iat, ok = integralTime(m.Val, b)
			if !ok {
				return out, ErrInvalid
			}
		case "nbf":
			out.Nbf, ok = integralTime(m.Val, b)
			if !ok {
				return out, ErrInvalid
			}
		case "exp":
			out.Exp, ok = integralTime(m.Val, b)
			if !ok {
				return out, ErrInvalid
			}
		default:
			return out, ErrInvalid
		}
	}
	if !seenVersion || !validContentAssertionIdentifier(out.Jti, b) || !validContentAssertionIdentifier(out.Iss, b) || !validContentAssertionIdentifier(out.Aud, b) || !validContentAssertionIdentifier(out.Sub, b) || !validContentAssertionIdentifier(out.Profile, b) || !validContentAssertionNumbers(out.Gen, out.Iat, out.Nbf, out.Exp, out.Prev, b) {
		return out, ErrInvalid
	}
	canonical, err := JcsEncode(obj, &b)
	if err != nil || string(canonical) != string(p.Payload) {
		return out, ErrInvalid
	}
	return out, nil
}

func contentString(v Value) (string, bool) { s, ok := v.(Str); return string(s), ok }
func contentDigestValue(v Value) ([32]byte, bool) {
	s, ok := v.(Str)
	if !ok {
		return [32]byte{}, false
	}
	return canonicalDigestString(string(s))
}
func validContentAssertionIdentifier(s string, b Bounds) bool {
	return validRoleAttestationStringOrURI(s, b.IdentifierBytes)
}
func validContentAssertionNumbers(gen, iat, nbf, exp int64, prev [32]byte, b Bounds) bool {
	if gen < 1 || gen > int64(b.IntegerMagnitude) || iat > int64(b.IntegerMagnitude) || iat < -int64(b.IntegerMagnitude) || nbf > int64(b.IntegerMagnitude) || nbf < -int64(b.IntegerMagnitude) || exp > int64(b.IntegerMagnitude) || exp < -int64(b.IntegerMagnitude) || iat > nbf || nbf >= exp {
		return false
	}
	return (gen == 1) == (prev == [32]byte{})
}

func validateProducedContentAssertion(protected, payload []byte, b Bounds) error {
	if len(protected) > b.DecodedSegmentBytes || len(payload) > b.DecodedSegmentBytes || b.SignatureBytes > b.DecodedSegmentBytes {
		return ErrInvalid
	}
	p := compactParts{Protected: protected, Payload: payload}
	if _, err := decodeContentAssertionHeader(p, b); err != nil {
		return ErrInvalid
	}
	if _, err := decodeContentAssertionPayload(p, b); err != nil {
		return ErrInvalid
	}
	projected := len(Base64urlEncode(protected)) + len(Base64urlEncode(payload)) + len(Base64urlEncode(make([]byte, b.SignatureBytes))) + 2
	if projected > b.CompactBytes || projected > b.AnchorBytes {
		return ErrInvalid
	}
	return nil
}

func validateExpectedContentAssertion(e ExpectedContentAssertion, b Bounds) error {
	if !validKid(e.Attestor.KeyID, b.KidBytes) || len(e.Attestor.PublicKey) != b.PublicKeyBytes || !validContentAssertionIdentifier(e.Issuer, b) || !validContentAssertionIdentifier(e.Audience, b) || !validContentAssertionIdentifier(e.Subject, b) || !validContentAssertionIdentifier(e.Profile, b) || e.Now > int64(b.IntegerMagnitude) || e.Now < -int64(b.IntegerMagnitude) || e.Attestor.ValidFrom > int64(b.IntegerMagnitude) || e.Attestor.ValidFrom < -int64(b.IntegerMagnitude) {
		return ErrInvalid
	}
	if !e.Attestor.ValidBeforeUnbounded && (e.Attestor.ValidBefore > int64(b.IntegerMagnitude) || e.Attestor.ValidBefore < -int64(b.IntegerMagnitude) || e.Attestor.ValidBefore <= e.Attestor.ValidFrom) {
		return ErrInvalid
	}
	return nil
}

func validateContentAssertionFacts(f ContentAssertionFacts, b Bounds) error {
	if f.Version != 1 || f.Verification != AttestationVerificationSignatureAndWindow || f.Trust != TrustNotEvaluated || !validKid(f.AttestorKeyID, b.KidBytes) || !validContentAssertionIdentifier(f.Jti, b) || !validContentAssertionIdentifier(f.Iss, b) || !validContentAssertionIdentifier(f.Aud, b) || !validContentAssertionIdentifier(f.Sub, b) || !validContentAssertionIdentifier(f.Profile, b) || !validContentAssertionNumbers(f.Gen, f.Iat, f.Nbf, f.Exp, f.Prev, b) {
		return ErrInvalid
	}
	return nil
}
