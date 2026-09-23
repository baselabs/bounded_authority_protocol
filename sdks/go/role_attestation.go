package verifier

import (
	"strings"
	"unicode/utf8"
)

// The standalone role-attestation sibling profile `bap-role-attestation/1`
// (spec/bap-role-attestation-v1.md, ADR 0036): a compact JWS in which an
// attestor key binds a subject key to a role for a bounded window. It
// single-sources the contract-major 1 primitives — Ed25519/EdDSA under
// BAP1-Ed25519-SHA256 and the bounded JSON/JCS/base64url/JWK machinery — and
// is parsed by no contract-major profile: this profile rejects every
// contract-major typ and every contract-major decoder rejects
// `ba+role-attestation` (REQ-RA1-CORE-cross-profile-reject).
//
// Unlike the grant, whose closed objects may use any member order, BOTH
// attestation segments must equal their RFC 8785 canonical re-encoding
// (REQ-RA1-CLAIM-canonical). The artifact is grant-unbound and carries no
// authorization; the package owns no signer and accepts only external
// signature bytes (REQ-RA1-API-no-signer).

// Attestation is the producer-side attestation structure for
// AttestationSigningInput: the attestor key id, the audit and
// revocation-reference jti, the attested subject key id and raw 32-byte
// Ed25519 public key, the closed role, and the bounded [Nbf, Exp) window.
type Attestation struct {
	AttestorKeyID string
	Jti           string
	KeyID         string
	PublicKey     [32]byte
	Role          string // exactly "issuer" or "holder"
	Nbf           int64
	Exp           int64
}

// TrustedAttestor is the exact caller-trusted attestor key with its own
// [ValidFrom, ValidBefore) validity window. ValidBeforeUnbounded is the only
// open upper interval — the HistoricalPublicKey convention; a configured
// unbounded window admits unbounded attestation lifetimes by that choice
// (REQ-RA1-SECURITY-trust-scope).
type TrustedAttestor struct {
	KeyID                string
	PublicKey            [32]byte
	ValidFrom            int64
	ValidBefore          int64
	ValidBeforeUnbounded bool
}

// ExpectedAttestation is the complete verification context: the trusted
// attestor key and window, the expected subject binding (key id and raw
// 32-byte public key), the caller's now, and tightening bounds
// (REQ-RA1-VERIFY-caller-supplied).
type ExpectedAttestation struct {
	Attestor         TrustedAttestor
	SubjectKeyID     string
	SubjectPublicKey [32]byte
	Now              int64
	Bounds           *Bounds
}

// AttestationDecoded is the decode_attestation result: the validated closed
// header and payload with verification not evaluated.
type AttestationDecoded struct {
	AttestorKeyID string
	Version       int
	Jti           string
	KeyID         string
	PublicKey     [32]byte
	Role          string
	Nbf           int64
	Exp           int64
	Verification  DecodeStatus
}

// AttestationVerification is the fixed performed-checks marker on
// AttestationFacts: the signature and the windows were proven. Only
// SignatureAndWindow exists.
type AttestationVerification int

const (
	AttestationVerificationSignatureAndWindow AttestationVerification = iota
)

// AttestationFacts is the attestation verification result: redacted,
// value-bearing, non-authorizing — the attestor and subject key ids with
// their RFC 7638 thumbprints, the role, the jti, and the window
// (REQ-RA1-VERIFY-facts). Facts carry no raw key material, no signature, and
// no decision (REQ-RA1-VERIFY-facts-non-authorizing).
type AttestationFacts struct {
	AttestorKeyID          string
	AttestorKeyFingerprint [32]byte
	SubjectKeyID           string
	SubjectKeyFingerprint  [32]byte
	Role                   string
	Jti                    string
	Nbf                    int64
	Exp                    int64
	Verification           AttestationVerification
	Trust                  Trust
}

// attestationClaimsData is the validated closed attestation payload.
type attestationClaimsData struct {
	Jti       string
	KeyID     string
	PublicKey [32]byte
	Role      string
	Nbf       int64
	Exp       int64
}

// validRoleAttestationStringOrURI applies the settled BAP1 StringOrUri rules
// without changing the legacy contract-major helper. Plain strings are valid
// when nonempty and bounded. A colon-bearing value must have a valid scheme,
// valid URI punctuation and percent escapes. Hierarchical authority syntax
// closes malformed IP literals, brackets, and alphabetic ports while
// retaining valid userinfo and the generic StringOrUri port forms.
func validRoleAttestationStringOrURI(s string, byteCeiling int) bool {
	if len(s) == 0 || len(s) > byteCeiling || !utf8.ValidString(s) {
		return false
	}
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return true
	}
	if !validScheme(s[:colon]) || !validRoleAttestationURIBytes(s) {
		return false
	}
	rest := s[colon+1:]
	if strings.Count(rest, "#") > 1 {
		return false
	}
	if strings.HasPrefix(rest, "//") {
		authority := rest[2:]
		tail := ""
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			tail = authority[end:]
			authority = authority[:end]
		}
		return !strings.ContainsAny(tail, "[]") && validRoleAttestationAuthority(authority)
	}
	return !strings.ContainsAny(rest, "[]")
}

func validRoleAttestationAuthority(authority string) bool {
	if strings.Count(authority, "@") > 1 {
		return false
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		if strings.ContainsAny(authority[:at], "[]") {
			return false
		}
		authority = authority[at+1:]
	}
	if strings.HasPrefix(authority, "[") {
		close := strings.IndexByte(authority, ']')
		if close < 0 || strings.ContainsAny(authority[close+1:], "[]") {
			return false
		}
		if _, err := normalizeIPv6(authority[1:close]); err != nil {
			return false
		}
		suffix := authority[close+1:]
		if suffix == "" {
			return true
		}
		if !strings.HasPrefix(suffix, ":") {
			return false
		}
		return decimalPortOrEmpty(suffix[1:])
	}
	if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
		return false
	}
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		return decimalPortOrEmpty(authority[colon+1:])
	}
	return true
}

func decimalPortOrEmpty(port string) bool {
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	return true
}

func validRoleAttestationURIBytes(s string) bool {
	const punctuation = "-._~:/?#[]@!$&'()*+,;="
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '%':
			if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return false
			}
			i += 2
		case strings.IndexByte(punctuation, c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f'
}

func splitRoleAttestationCompact(compact string, b Bounds) (compactParts, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return compactParts{}, ErrInvalid
	}
	if err := scanCompact(compact, b); err != nil {
		return compactParts{}, ErrInvalid
	}
	first := strings.IndexByte(compact, '.')
	last := strings.LastIndexByte(compact, '.')
	for _, encodedBytes := range []int{first, last - first - 1, len(compact) - last - 1} {
		decodedBytes, valid := roleAttestationDecodedSegmentLength(encodedBytes)
		if !valid || decodedBytes > b.DecodedSegmentBytes {
			return compactParts{}, ErrInvalid
		}
	}
	return splitCompact(compact, b)
}

func roleAttestationDecodedSegmentLength(encodedBytes int) (int, bool) {
	if encodedBytes < 0 || encodedBytes%4 == 1 {
		return 0, false
	}
	decodedBytes := encodedBytes / 4 * 3
	switch encodedBytes % 4 {
	case 2:
		decodedBytes++
	case 3:
		decodedBytes += 2
	}
	return decodedBytes, true
}

func validateProducedAttestation(protected, payload []byte, b Bounds) error {
	if len(protected) > b.DecodedSegmentBytes || len(payload) > b.DecodedSegmentBytes || b.SignatureBytes > b.DecodedSegmentBytes {
		return ErrInvalid
	}
	parts := compactParts{Protected: protected, Payload: payload}
	if _, err := decodeAttestationHeader(parts, b); err != nil {
		return ErrInvalid
	}
	if _, err := decodeAttestationPayload(parts, b); err != nil {
		return ErrInvalid
	}
	protectedSeg := Base64urlEncode(protected)
	payloadSeg := Base64urlEncode(payload)
	signatureSeg := Base64urlEncode(make([]byte, b.SignatureBytes))
	if len(protectedSeg) > b.EncodedSegmentBytes || len(payloadSeg) > b.EncodedSegmentBytes || len(signatureSeg) > b.EncodedSegmentBytes {
		return ErrInvalid
	}
	compactBytes := len(protectedSeg) + len(payloadSeg) + len(signatureSeg) + 2
	if compactBytes > b.CompactBytes || compactBytes > b.AnchorBytes {
		return ErrInvalid
	}
	return nil
}

// decodeAttestationHeader validates the exact protected header
// {alg:"EdDSA", kid, typ:"ba+role-attestation"} — every unlisted member or
// value is invalid — and its canonical bytes, returning the attestor kid
// (REQ-RA1-HEADER-closed-set, REQ-RA1-CORE-typ, REQ-RA1-CLAIM-canonical).
func decodeAttestationHeader(p compactParts, b Bounds) (string, error) {
	v, err := JsonDecode(p.Protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid // REQ-RA1-HEADER-closed-set
	}
	var kid *Str
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "EdDSA" {
				return "", ErrInvalid
			}
		case "typ":
			if s, ok := m.Val.(Str); !ok || s != "ba+role-attestation" {
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
	if canonical, err := JcsEncode(obj, &b); err != nil || string(canonical) != string(p.Protected) {
		return "", ErrInvalid // REQ-RA1-CLAIM-canonical (header segment)
	}
	return string(*kid), nil
}

// decodeAttestationPayload validates every claim of the closed seven-member
// payload set and its canonical bytes: every listed member is required,
// every unlisted member is invalid, numeric members must be integral, and
// nbf < exp (REQ-RA1-CLAIM-closed-required, REQ-RA1-CLAIM-window,
// REQ-RA1-CLAIM-canonical).
func decodeAttestationPayload(p compactParts, b Bounds) (attestationClaimsData, error) {
	var out attestationClaimsData
	v, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return out, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 7 {
		return out, ErrInvalid // exact member set: seven distinct closed names
	}
	for _, m := range obj {
		switch m.Key {
		case "v":
			if i, ok := m.Val.(Int); !ok || i != 1 {
				return out, ErrInvalid // REQ-RA1-CLAIM-v
			}
		case "jti":
			if s, ok := m.Val.(Str); ok {
				out.Jti = string(s)
			}
		case "key_id":
			if s, ok := m.Val.(Str); ok {
				out.KeyID = string(s)
			}
		case "public_key":
			s, ok := m.Val.(Str)
			if !ok {
				return out, ErrInvalid
			}
			raw, err := Base64urlDecode(string(s))
			if err != nil || len(raw) != b.PublicKeyBytes {
				return out, ErrInvalid // REQ-RA1-CLAIM-public-key
			}
			copy(out.PublicKey[:], raw)
		case "role":
			s, ok := m.Val.(Str)
			if !ok || (s != "issuer" && s != "holder") {
				return out, ErrInvalid // REQ-RA1-CLAIM-role-closed-set
			}
			out.Role = string(s)
		case "nbf":
			if t, ok := integralTime(m.Val, b); ok {
				out.Nbf = t
			} else {
				return out, ErrInvalid
			}
		case "exp":
			if t, ok := integralTime(m.Val, b); ok {
				out.Exp = t
			} else {
				return out, ErrInvalid
			}
		default:
			return out, ErrInvalid // unlisted claim
		}
	}
	if !validRoleAttestationStringOrURI(out.Jti, b.IdentifierBytes) {
		return out, ErrInvalid // REQ-RA1-CLAIM-jti
	}
	if !validKid(out.KeyID, b.KidBytes) {
		return out, ErrInvalid // REQ-RA1-CLAIM-key-id
	}
	if out.Nbf >= out.Exp {
		return out, ErrInvalid // REQ-RA1-CLAIM-window
	}
	if canonical, err := JcsEncode(obj, &b); err != nil || string(canonical) != string(p.Payload) {
		return out, ErrInvalid // REQ-RA1-CLAIM-canonical (payload segment)
	}
	return out, nil
}

// AttestationSigningInput composes the deterministic canonical attestation
// signing input (REQ-RA1-API-complete surface 1). It accepts no private key,
// signer, or callback (REQ-RA1-API-no-signer).
func AttestationSigningInput(a Attestation, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validKid(a.AttestorKeyID, b.KidBytes) || !validKid(a.KeyID, b.KidBytes) {
		return SigningInput{}, ErrInvalid // header kid / REQ-RA1-CLAIM-key-id rules
	}
	if !validRoleAttestationStringOrURI(a.Jti, b.IdentifierBytes) {
		return SigningInput{}, ErrInvalid // REQ-RA1-CLAIM-jti
	}
	if a.Role != "issuer" && a.Role != "holder" {
		return SigningInput{}, ErrInvalid // REQ-RA1-CLAIM-role-closed-set
	}
	if a.Nbf >= a.Exp {
		return SigningInput{}, ErrInvalid // REQ-RA1-CLAIM-window
	}
	protected, err := JcsEncode(Obj{
		{Key: "alg", Val: Str("EdDSA")},
		{Key: "kid", Val: Str(a.AttestorKeyID)},
		{Key: "typ", Val: Str("ba+role-attestation")},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	payload, err := JcsEncode(Obj{
		{Key: "exp", Val: Int(a.Exp)},
		{Key: "jti", Val: Str(a.Jti)},
		{Key: "key_id", Val: Str(a.KeyID)},
		{Key: "nbf", Val: Int(a.Nbf)},
		{Key: "public_key", Val: Str(Base64urlEncode(a.PublicKey[:]))},
		{Key: "role", Val: Str(a.Role)},
		{Key: "v", Val: Int(1)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if err := validateProducedAttestation(protected, payload, b); err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindRoleAttestation, Protected: protected, Payload: payload}, nil
}

// AssembleAttestationCompact assembles an attestation compact JWS from a
// signing input and a 64-byte external signature. It revalidates the
// protected header, payload member rules, segment bounds, and signature
// width under this profile before returning a compact artifact
// (REQ-RA1-API-assembly-revalidate); the standard AssembleCompact rejects
// the attestation kind and this assembler rejects every other kind
// (REQ-RA1-CORE-cross-profile-reject).
func AssembleAttestationCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
	defer closedResult(&err)
	if si.Kind != KindRoleAttestation {
		return "", ErrInvalid
	}
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
	if len(compact) > b.CompactBytes || len(compact) > b.AnchorBytes {
		return "", ErrInvalid
	}
	parts, err := splitRoleAttestationCompact(compact, b)
	if err != nil {
		return "", ErrInvalid
	}
	if _, err := decodeAttestationHeader(parts, b); err != nil {
		return "", ErrInvalid
	}
	if _, err := decodeAttestationPayload(parts, b); err != nil {
		return "", ErrInvalid
	}
	return compact, nil
}

// DecodeAttestation decodes and closed-set-validates a raw attestation
// compact, enforcing canonical bytes on both segments. It performs no
// signature verification; a successful decode proves shape only.
func DecodeAttestation(compact string, bounds *Bounds) (d AttestationDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return AttestationDecoded{}, ErrInvalid
	}
	parts, err := splitRoleAttestationCompact(compact, b)
	if err != nil {
		return AttestationDecoded{}, ErrInvalid
	}
	kid, err := decodeAttestationHeader(parts, b)
	if err != nil {
		return AttestationDecoded{}, ErrInvalid
	}
	claims, err := decodeAttestationPayload(parts, b)
	if err != nil {
		return AttestationDecoded{}, ErrInvalid
	}
	return AttestationDecoded{
		AttestorKeyID: kid,
		Version:       1,
		Jti:           claims.Jti,
		KeyID:         claims.KeyID,
		PublicKey:     claims.PublicKey,
		Role:          claims.Role,
		Nbf:           claims.Nbf,
		Exp:           claims.Exp,
		Verification:  DecodeVerificationNotEvaluated,
	}, nil
}

// VerifyAttestation verifies a raw attestation compact against the exact
// trusted attestor and expected context (the Go spelling of the citation
// symbol BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2,
// REQ-RA1-API-namespace). It proves the closed sets and canonical bytes, the
// header kid match and the Ed25519 signature under the attestor public key,
// the expected subject binding, non-self-attestation, attestor-window
// containment, and the caller's now within [nbf, exp); any failure is
// exactly ErrInvalid (REQ-RA1-VERIFY-fail-closed). The result is closed,
// value-bearing, redacted, non-authorizing facts.
func VerifyAttestation(compact string, expected ExpectedAttestation) (f AttestationFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return AttestationFacts{}, ErrInvalid
	}
	// caller-context revalidation before any credential work
	if !validKid(expected.Attestor.KeyID, b.KidBytes) || !validKid(expected.SubjectKeyID, b.KidBytes) {
		return AttestationFacts{}, ErrInvalid
	}
	if expected.Now > int64(b.IntegerMagnitude) || expected.Now < -int64(b.IntegerMagnitude) {
		return AttestationFacts{}, ErrInvalid
	}
	// Attestor-window endpoints are magnitude-bounded caller input — the same
	// HistoricalPublicKey gates the Elixir reference and the Rust leg apply.
	// Containment alone is trivially satisfied by an out-of-magnitude window,
	// so nothing downstream rejects it (cross-vendor review 2026-09-22).
	if expected.Attestor.ValidFrom > int64(b.IntegerMagnitude) || expected.Attestor.ValidFrom < -int64(b.IntegerMagnitude) {
		return AttestationFacts{}, ErrInvalid
	}
	if !expected.Attestor.ValidBeforeUnbounded &&
		(expected.Attestor.ValidBefore > int64(b.IntegerMagnitude) || expected.Attestor.ValidBefore < -int64(b.IntegerMagnitude)) {
		return AttestationFacts{}, ErrInvalid
	}
	parts, err := splitRoleAttestationCompact(compact, b)
	if err != nil {
		return AttestationFacts{}, ErrInvalid
	}
	kid, err := decodeAttestationHeader(parts, b)
	if err != nil || kid != expected.Attestor.KeyID {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-attestor-signature (kid leg)
	}
	claims, err := decodeAttestationPayload(parts, b)
	if err != nil {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-closed-sets
	}
	si := SigningInput{Kind: KindRoleAttestation, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyEd25519(expected.Attestor.PublicKey[:], signingInputMessage(si), parts.Signature); err != nil {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-attestor-signature
	}
	if claims.KeyID != expected.SubjectKeyID || claims.PublicKey != expected.SubjectPublicKey {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-subject-binding
	}
	attestorFP := jwkThumbprintOfKey(expected.Attestor.PublicKey[:])
	subjectFP := jwkThumbprintOfKey(claims.PublicKey[:])
	if attestorFP == subjectFP || expected.Attestor.KeyID == claims.KeyID {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-no-self-attestation
	}
	if claims.Nbf < expected.Attestor.ValidFrom {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-window-containment
	}
	if !expected.Attestor.ValidBeforeUnbounded && claims.Exp > expected.Attestor.ValidBefore {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-window-containment (exp == valid_before is containment)
	}
	if expected.Now < claims.Nbf || expected.Now >= claims.Exp {
		return AttestationFacts{}, ErrInvalid // REQ-RA1-VERIFY-now-window
	}
	return AttestationFacts{
		AttestorKeyID:          kid,
		AttestorKeyFingerprint: attestorFP,
		SubjectKeyID:           claims.KeyID,
		SubjectKeyFingerprint:  subjectFP,
		Role:                   claims.Role,
		Jti:                    claims.Jti,
		Nbf:                    claims.Nbf,
		Exp:                    claims.Exp,
		Verification:           AttestationVerificationSignatureAndWindow,
		Trust:                  TrustNotEvaluated,
	}, nil
}
