package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
)

// The contract-major-3 ES256 profile (spec/bap-v3.md, suite BAP3-ES256-SHA256,
// activated by ADR 0035). Re-derived from the normative sources alone —
// spec/bap-v3.md, the v1 sections it incorporates with the §2 substitutions,
// and the v2 §4 selector algebra — with no reading of the Elixir v3
// implementation (ADR 0014 D5). Structurally this file mirrors its v1/v2
// counterparts member for member; the profile differences are exactly:
//
//   - every versioned payload carries "v":3 and this major rejects v1/v2
//     bytes (and vice versa) with the single closed error;
//   - the domain separators below are the BAP3 forms;
//   - the signature family is ECDSA over NIST P-256 with SHA-256 (RFC 7518
//     §3.4 "ES256"): protected alg is exactly "ES256", the proof JWK is
//     exactly {crv:"P-256", kty:"EC", x, y}, the RFC 7638 thumbprint preimage
//     is that member set in lexicographic order, raw public keys are 65-byte
//     uncompressed SEC1 points 0x04||x||y, and wire signatures are the raw
//     64-byte r||s fixed-width form with 0 < r < n and 0 < s <= n/2 (low-S
//     required, one conditional subtraction at production);
//   - the selector algebra is the v2 algebra unchanged (five kinds: the three
//     v1 kinds plus lte/gte on the same {kind, path, value} member set,
//     same-tag numeric operands only, inclusive comparison);
//   - the v1-carrying local-loopback proof profile pairs with no v3 grant and
//     this facade exposes no loopback functions.
//
// The shared json algebra, JCS, base64url, URI, and bounds modules are reused
// unchanged. The suite's fixed widths live here as immutable constants: the
// shared Bounds struct keeps certifying the version-neutral bounds surface
// (its public_key_bytes stays the shared 32-byte fixed width of the v1
// suite's raw keys), and no v3 code path may read b.PublicKeyBytes for the
// key width — the SEC1 width below is the profile's own constant
// (REQ3-BOUNDS-fixed-widths).

// es256RequestPrefix is the contract-major-3 request-digest domain
// separator, exact ASCII including its final zero byte.
var es256RequestPrefix = []byte("BAP3-REQUEST\x00")

// es256ChainPrefix is the contract-major-3 consumption-chain domain
// separator.
var es256ChainPrefix = []byte("BAP3-CHAIN\x00")

// es256ArchiveMagic is the contract-major-3 archive framing magic.
var es256ArchiveMagic = []byte("BAP3-ARCHIVE\x00EXPORT\x00")

// The suite's immutable cryptographic constants (spec/bap-v3.md §5).
const (
	// es256CoordinateBytes is the fixed width of each P-256 coordinate in the
	// JWK and the raw key (RFC 7518 §6.2.1.2/§6.2.1.3 fixed-width spelling).
	es256CoordinateBytes = 32
	// es256PublicKeyBytes is the raw public key width: the uncompressed SEC1
	// point 0x04 || x || y (REQ3-KEY-uncompressed-sec1).
	es256PublicKeyBytes = 65
	// es256SignatureBytes is the raw signature width: r || s as two fixed-width
	// 32-byte unsigned big-endian integers (REQ3-SIGNING-raw-rs).
	es256SignatureBytes = 64
)

// p256Params holds the P-256 domain parameters (field prime, curve coefficient,
// group order) for the pure-arithmetic gates; elliptic.P256 is the documented
// non-deprecated way to obtain them for use with crypto/ecdsa.
var p256Params = elliptic.P256().Params()

// p256HalfOrder is floor(n/2): the low-S ceiling (REQ3-SIGNING-low-s).
var p256HalfOrder = new(big.Int).Rsh(p256Params.N, 1)

// EcdsaProfile is the contract-major-3 facade: a stateless namespace type whose
// method set mirrors the v1 public entry names (DecodeGrant, VerifyGrant,
// CheckEnvelope, ...). Construct as the zero value; it holds no state and
// grants nothing.
type EcdsaProfile struct{}

// ecdsaSuite is the zero-value facade used for internal dispatch; EcdsaProfile
// holds no state, so this is the same namespace as any EcdsaProfile{} value.
var ecdsaSuite = EcdsaProfile{}

// ---- the ES256 signature suite (spec/bap-v3.md §3) ----

// p256OnCurve is the pure-arithmetic point check: both coordinates in
// [0, p) and on the short-Weierstrass curve y^2 = x^3 - 3x + b over the P-256
// prime field. It precedes the crypto backend, whose off-curve behavior is
// backend-specific and never load-bearing (REQ3-KEY-point-on-curve).
func p256OnCurve(x, y *big.Int) bool {
	p := p256Params.P
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return false // each coordinate MUST be less than the field prime
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x) // x^3
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x) // 3x
	rhs.Sub(rhs, threeX)  // x^3 - 3x
	rhs.Add(rhs, p256Params.B)
	rhs.Mod(rhs, p) // Euclidean modulus: result in [0, p)
	return lhs.Cmp(rhs) == 0
}

// p256CoordinatesOnCurve is the byte-spelling of p256OnCurve for two
// fixed-width coordinates.
func p256CoordinatesOnCurve(xb, yb []byte) bool {
	if len(xb) != es256CoordinateBytes || len(yb) != es256CoordinateBytes {
		return false
	}
	return p256OnCurve(new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb))
}

// validateRawRS is the signature encoding gate: exactly 64 bytes as two
// fixed-width 32-byte unsigned big-endian integers, rejected unless
// 0 < r < n and 0 < s <= n/2 (low-S) — all before any backend call
// (REQ3-SIGNING-raw-rs, REQ3-SIGNING-range, REQ3-SIGNING-low-s). DER is
// never a v3 wire spelling and no other width is admitted.
func validateRawRS(signature []byte) error {
	if len(signature) != es256SignatureBytes {
		return ErrInvalid
	}
	r := new(big.Int).SetBytes(signature[:es256CoordinateBytes])
	s := new(big.Int).SetBytes(signature[es256CoordinateBytes:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return ErrInvalid
	}
	if r.Cmp(p256Params.N) >= 0 || s.Cmp(p256Params.N) >= 0 {
		return ErrInvalid
	}
	if s.Cmp(p256HalfOrder) > 0 {
		return ErrInvalid // high-S half: malleable counterpart encoding
	}
	return nil
}

// verifyECDSA verifies one ES256 signature over the exact RFC 7515 signing
// input. The verification order is the v1 bounds-ordering discipline
// (REQ3-BOUNDS-ordering): key form and width; JCS-independent pure point
// arithmetic (< p, on-curve); the raw-r||s width and integer-range gates;
// then the backend verification. A backend rejection or exception is exactly
// ErrInvalid (REQ3-SIGNING-backend-reject). Public keys are caller-supplied
// trusted inputs — never discovered here.
func verifyECDSA(publicKey, message, signature []byte) error {
	if len(publicKey) != es256PublicKeyBytes || publicKey[0] != 0x04 {
		return ErrInvalid // uncompressed SEC1 form only; compressed is invalid
	}
	x := new(big.Int).SetBytes(publicKey[1 : 1+es256CoordinateBytes])
	y := new(big.Int).SetBytes(publicKey[1+es256CoordinateBytes:])
	if !p256OnCurve(x, y) {
		return ErrInvalid
	}
	if err := validateRawRS(signature); err != nil {
		return err
	}
	r := new(big.Int).SetBytes(signature[:es256CoordinateBytes])
	s := new(big.Int).SetBytes(signature[es256CoordinateBytes:])
	hash := sha256.Sum256(message) // ES256 hashes the JWS signing input with SHA-256
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash[:], r, s) {
		return ErrInvalid
	}
	return nil
}

// ecThumbprintPreimage is the exact RFC 7638 preimage for a raw P-256 public
// key: the required EC members in lexicographic order
// ({"crv":"P-256","kty":"EC","x":X,"y":Y}) with canonical unpadded
// base64url coordinates (REQ3-HEADER-thumbprint). BAP cnf.jkt and AP2
// cnf.jwk are two spellings of this one key identity.
func ecThumbprintPreimage(raw []byte) []byte {
	out := []byte(`{"crv":"P-256","kty":"EC","x":"`)
	out = append(out, Base64urlEncode(raw[1:1+es256CoordinateBytes])...)
	out = append(out, `","y":"`...)
	out = append(out, Base64urlEncode(raw[1+es256CoordinateBytes:es256PublicKeyBytes])...)
	out = append(out, '"', '}')
	return out
}

// jwkThumbprintOfKeyEC is the RFC 7638 thumbprint of a raw (already
// width-gated) v3 public key — the cnf.jkt binding check's construction.
func jwkThumbprintOfKeyEC(raw []byte) [32]byte {
	return sha256.Sum256(ecThumbprintPreimage(raw))
}

// ---- the v3 public JWK surface ----

// JwkDecodePublic decodes a public EC P-256 JWK (JSON bytes) under the closed
// member set {crv:"P-256", kty:"EC", x, y} in any member order and returns
// the raw 65-byte uncompressed SEC1 public key. Coordinates are canonical
// unpadded base64url of exactly 32 bytes each, MUST be less than the field
// prime, and MUST form a point on the curve; every additional member —
// private d included — is invalid (REQ3-HEADER-proof-jwk,
// REQ3-HEADER-no-private-jwk, REQ3-KEY-point-on-curve).
func (EcdsaProfile) JwkDecodePublic(data []byte, bounds *Bounds) ([]byte, error) {
	raw, err := ecdsaSuite.decodePublicJwk(data, bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	return raw, nil
}

// JwkEncodePublic emits the canonical JCS bytes of the public EC JWK for a
// raw 65-byte uncompressed SEC1 P-256 public key.
func (EcdsaProfile) JwkEncodePublic(key []byte, bounds *Bounds) ([]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	_ = b
	if len(key) != es256PublicKeyBytes || key[0] != 0x04 {
		return nil, ErrInvalid // SEC1 uncompressed form only
	}
	out := []byte(`{"crv":"P-256","kty":"EC","x":"`)
	out = append(out, Base64urlEncode(key[1:1+es256CoordinateBytes])...)
	out = append(out, `","y":"`...)
	out = append(out, Base64urlEncode(key[1+es256CoordinateBytes:es256PublicKeyBytes])...)
	out = append(out, '"', '}')
	return out, nil
}

// JwkThumbprintPreimage returns the exact RFC 7638 preimage bytes for a
// public EC P-256 JWK.
func (EcdsaProfile) JwkThumbprintPreimage(data []byte, bounds *Bounds) ([]byte, error) {
	raw, err := ecdsaSuite.decodePublicJwk(data, bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	return ecThumbprintPreimage(raw), nil
}

// JwkThumbprint returns the unpadded base64url SHA-256 RFC 7638 thumbprint
// of a public EC P-256 JWK.
func (EcdsaProfile) JwkThumbprint(data []byte, bounds *Bounds) (string, error) {
	raw, err := ecdsaSuite.JwkThumbprintRaw(data, bounds)
	if err != nil {
		return "", ErrInvalid
	}
	return Base64urlEncode(raw[:]), nil
}

// JwkThumbprintRaw returns the raw 32-byte SHA-256 RFC 7638 thumbprint of a
// public EC P-256 JWK (REQ3-HEADER-digest-width).
func (EcdsaProfile) JwkThumbprintRaw(data []byte, bounds *Bounds) ([32]byte, error) {
	pre, err := ecdsaSuite.JwkThumbprintPreimage(data, bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(pre), nil
}

// PublicKeyThumbprintRaw is the issuer-key fingerprint of this suite: the
// RFC 7638 EC thumbprint construction applied to the caller's raw 65-byte
// SEC1 public key.
func (EcdsaProfile) PublicKeyThumbprintRaw(key []byte, bounds *Bounds) ([32]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	_ = b
	if len(key) != es256PublicKeyBytes || key[0] != 0x04 {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(ecThumbprintPreimage(key)), nil
}

// decodePublicJwk parses and closed-set-validates a public EC P-256 JWK,
// returning the raw 65-byte SEC1 key.
func (EcdsaProfile) decodePublicJwk(data []byte, bounds *Bounds) ([]byte, error) {
	b, err := resolveBounds(bounds)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(data) > b.JSONBytes {
		return nil, ErrInvalid
	}
	v, err := JsonDecode(data, &b)
	if err != nil {
		return nil, ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 4 {
		return nil, ErrInvalid // exact four-member set
	}
	var crv, kty, x, y *Str
	for _, m := range obj {
		switch m.Key {
		case "crv":
			if s, ok := m.Val.(Str); ok {
				crv = &s
			}
		case "kty":
			if s, ok := m.Val.(Str); ok {
				kty = &s
			}
		case "x":
			if s, ok := m.Val.(Str); ok {
				x = &s
			}
		case "y":
			if s, ok := m.Val.(Str); ok {
				y = &s
			}
		default:
			return nil, ErrInvalid // unlisted member (REQ3-HEADER-closed-set)
		}
	}
	if crv == nil || kty == nil || x == nil || y == nil {
		return nil, ErrInvalid
	}
	if *crv != "P-256" || *kty != "EC" {
		return nil, ErrInvalid
	}
	xb, err := Base64urlDecode(string(*x))
	if err != nil || len(xb) != es256CoordinateBytes {
		return nil, ErrInvalid // canonical fixed-width coordinate
	}
	yb, err := Base64urlDecode(string(*y))
	if err != nil || len(yb) != es256CoordinateBytes {
		return nil, ErrInvalid
	}
	if !p256CoordinatesOnCurve(xb, yb) {
		return nil, ErrInvalid // < p and on-curve, pure arithmetic
	}
	raw := make([]byte, es256PublicKeyBytes)
	raw[0] = 0x04
	copy(raw[1:], xb)
	copy(raw[1+es256CoordinateBytes:], yb)
	return raw, nil
}

// ---- selector algebra (v2 §4 incorporated as REQ3-SELECTOR-*) ----

// validateSelector closed-set-validates one selector value: the v1 kind set
// plus lte/gte on the same {kind, path, value} member set. An lte/gte bound
// must be numeric (Int or Float) — a non-numeric bound is malformed and fails
// the whole grant at decode (the ADR 0028 §7 rule, carried as v3).
func (EcdsaProfile) validateSelector(v Value, bounds *Bounds) error {
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
		// The second recognized member set; value carries the bound. A
		// non-numeric bound is malformed, not a non-match.
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
func (EcdsaProfile) applySelectors(selectors []Value, args Value) error {
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

// ---- protected headers of this major ----

// decodeGrantHeaderES validates the exact grant protected header
// {alg:"ES256", kid, typ:"ba+cap"} and returns the kid.
func decodeGrantHeaderES(p compactParts, b Bounds) (string, error) {
	v, err := JsonDecode(p.Protected, &b)
	if err != nil {
		return "", ErrInvalid
	}
	obj, ok := v.(Obj)
	if !ok || len(obj) != 3 {
		return "", ErrInvalid // REQ3-HEADER-closed-set
	}
	var kid *Str
	for _, m := range obj {
		switch m.Key {
		case "alg":
			if s, ok := m.Val.(Str); !ok || s != "ES256" {
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

// decodeProofHeaderES validates the exact proof protected header
// {alg:"ES256", jwk:public_EC_JWK, typ:"dpop+jwt"} and returns the raw
// 65-byte holder public key. Every additional JWK member — private d
// included — is invalid (REQ3-HEADER-no-private-jwk).
func decodeProofHeaderES(p compactParts, b Bounds) ([]byte, error) {
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
			if s, ok := m.Val.(Str); !ok || s != "ES256" {
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
	return ecdsaSuite.decodePublicJwk(jwkBytes, &b)
}

// decodeAnchorHeaderES validates {alg:"ES256", kid, typ:"ba+chain-anchor"}.
func decodeAnchorHeaderES(protected []byte, b Bounds) (string, error) {
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
			if s, ok := m.Val.(Str); !ok || s != "ES256" {
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

// decodeTransitionHeaderES validates {alg:"ES256", kid, typ:"ba+key-transition"}.
func decodeTransitionHeaderES(protected []byte, b Bounds) (string, error) {
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
			if s, ok := m.Val.(Str); !ok || s != "ES256" {
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

// ---- grant/proof decode ----

// decodeGrantPayload validates every grant claim: identical to the v1
// closed set with "v":3 and this profile's selector validator.
func (EcdsaProfile) decodeGrantPayload(p compactParts, b Bounds) (grantClaimsData, error) {
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
			if i, ok := m.Val.(Int); !ok || i != 3 {
				return out, ErrInvalid // this major rejects v1/v2 bytes
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
					if ecdsaSuite.validateSelector(sel, &b) != nil {
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
// standard-profile closed set with "v":3.
func (EcdsaProfile) decodeProofPayload(p compactParts, b Bounds) (proofClaimsData, error) {
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
			if i, ok := m.Val.(Int); !ok || i != 3 {
				return out, ErrInvalid // this major rejects v1/v2 bytes
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
//	base64url(SHA-256("BAP3-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
func (EcdsaProfile) RequestDigest(operation string, castArguments Value, bounds *Bounds) (string, error) {
	raw, err := ecdsaSuite.requestDigestRaw(operation, castArguments, bounds)
	if err != nil {
		return "", ErrInvalid
	}
	return Base64urlEncode(raw[:]), nil
}

func (EcdsaProfile) requestDigestRaw(operation string, castArguments Value, bounds *Bounds) ([32]byte, error) {
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
	h.Write(es256RequestPrefix)
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ---- decode/verify façades ----

// DecodeGrant decodes and closed-set-validates a raw grant compact of this
// major. It performs no signature verification and rejects v1/v2 bytes.
func (EcdsaProfile) DecodeGrant(compact string, bounds *Bounds) (d GrantDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	kid, err := decodeGrantHeaderES(parts, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	claims, err := ecdsaSuite.decodeGrantPayload(parts, b)
	if err != nil {
		return GrantDecoded{}, ErrInvalid
	}
	return GrantDecoded{
		KeyID:            kid,
		Version:          3,
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
func (EcdsaProfile) DecodeProof(compact string, bounds *Bounds) (d ProofDecoded, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	if _, err := decodeProofHeaderES(parts, b); err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	claims, err := ecdsaSuite.decodeProofPayload(parts, b)
	if err != nil {
		return ProofDecoded{}, ErrInvalid
	}
	out := ProofDecoded{
		ProofID:      claims.ProofID,
		Version:      3,
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
// the protected grant header (the closed header of this major); payload and
// signature stay opaque.
func (EcdsaProfile) UntrustedKeyLocator(compact string, bounds *Bounds) (loc KeyLocator, err error) {
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
	kid, err := decodeGrantHeaderES(parts, b)
	if err != nil {
		return KeyLocator{}, ErrInvalid
	}
	return KeyLocator{KeyID: kid, Trust: TrustNotEvaluated}, nil
}

// verifyGrantCore is this major's shared pure raw-grant verification
// primitive (CheckEnvelope re-verifies the raw grant through it).
func (EcdsaProfile) verifyGrantCore(compact string, issuer TrustedIssuer, exp ExpectedGrant, b Bounds) (grantClaimsData, GrantFacts, error) {
	if !validKid(issuer.KeyID, b.KidBytes) || len(issuer.PublicKey) != es256PublicKeyBytes {
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
	kid, err := decodeGrantHeaderES(parts, b)
	if err != nil || kid != issuer.KeyID {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid // exact key ID
	}
	claims, err := ecdsaSuite.decodeGrantPayload(parts, b)
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
	if err := verifyECDSA(issuer.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	issuerFP, err := ecdsaSuite.PublicKeyThumbprintRaw(issuer.PublicKey, &b)
	if err != nil {
		return grantClaimsData{}, GrantFacts{}, ErrInvalid
	}
	return claims, GrantFacts{
		Version:              3,
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
func (EcdsaProfile) VerifyGrant(compact string, issuer TrustedIssuer, expected ExpectedGrant) (f GrantFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	_, facts, err := ecdsaSuite.verifyGrantCore(compact, issuer, expected, b)
	if err != nil {
		return GrantFacts{}, ErrInvalid
	}
	return facts, nil
}

// CheckEnvelope performs combined verification of this major: the raw-grant
// primitive, the holder proof, thumbprint binding, context bindings, the
// BAP3-REQUEST digest, time window, nonce mode, and the selector algebra with
// lte/gte admitted.
func (EcdsaProfile) CheckEnvelope(creds Credentials, expected ExpectedRequest) (f EnvelopeFacts, err error) {
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
	claims, gfacts, err := ecdsaSuite.verifyGrantCore(creds.Grant, expected.TrustedIssuer, ExpectedGrant{
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
	holderKey, err := decodeProofHeaderES(parts, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	proof, err := ecdsaSuite.decodeProofPayload(parts, b)
	if err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	si := SigningInput{Kind: KindProof, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyECDSA(holderKey, signingInputMessage(si), parts.Signature); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	// 3. holder thumbprint binding
	if jwkThumbprintOfKeyEC(holderKey) != claims.JktRaw {
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
	baReqRaw, err := ecdsaSuite.requestDigestRaw(expected.Operation, expected.CastArguments, &b)
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
	if err := ecdsaSuite.applySelectors(ops, expected.CastArguments); err != nil {
		return EnvelopeFacts{}, ErrInvalid
	}
	return EnvelopeFacts{
		Version:              3,
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
// ("v":3 payload, ES256 header; this profile's selector validator admits
// lte/gte).
func (EcdsaProfile) GrantSigningInput(g Grant, bounds *Bounds) (si SigningInput, err error) {
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
			if ecdsaSuite.validateSelector(sel, &b) != nil {
				return SigningInput{}, ErrInvalid
			}
			sels = append(sels, sel)
		}
		ops = append(ops, Obj{{Key: "name", Val: Str(op.Name)}, {Key: "selectors", Val: sels}})
	}
	protected, perr := JcsEncode(Obj{{Key: "alg", Val: Str("ES256")}, {Key: "kid", Val: Str(g.KeyID)}, {Key: "typ", Val: Str("ba+cap")}}, &b)
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
		{Key: "v", Val: Int(3)},
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
// input ("v":3 payload; ES256 header over this suite's EC JWK; ba_req carries
// the BAP3-REQUEST digest; the holder key is the raw 65-byte SEC1 point).
func (EcdsaProfile) ProofSigningInput(p Proof, bounds *Bounds) (si SigningInput, err error) {
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
	if len(p.HolderPublicKey) != es256PublicKeyBytes {
		return SigningInput{}, ErrInvalid // this suite's raw key width
	}
	if len(p.GrantCompact) == 0 || len(p.GrantCompact) > b.CompactBytes {
		return SigningInput{}, ErrInvalid // producer ath compact-bytes bound
	}
	if err := scanCompact(p.GrantCompact, b); err != nil {
		return SigningInput{}, ErrInvalid
	}
	athRaw := sha256.Sum256([]byte(p.GrantCompact))
	baReqRaw, err := ecdsaSuite.requestDigestRaw(p.Operation, p.CastArguments, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	jwk, err := ecdsaSuite.JwkEncodePublic(p.HolderPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	jwkValue, err := JsonDecode(jwk, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("ES256")}, {Key: "jwk", Val: jwkValue}, {Key: "typ", Val: Str("dpop+jwt")}}, &b)
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
		{Key: "v", Val: Int(3)},
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
// ("v":3 payload, ES256 header; the fingerprint is this suite's EC
// thumbprint).
func (EcdsaProfile) BoundaryAnchorSigningInput(a BoundaryAnchor, bounds *Bounds) (si SigningInput, err error) {
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
	if len(a.PublicKey) != es256PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	fingerprint, err := ecdsaSuite.PublicKeyThumbprintRaw(a.PublicKey, &b)
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
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("ES256")}, {Key: "kid", Val: Str(a.KeyID)}, {Key: "typ", Val: Str("ba+chain-anchor")}}, &b)
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
		{Key: "v", Val: Int(3)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindBoundaryAnchor, Protected: protected, Payload: payload}, nil
}

// KeyTransitionSigningInput composes the deterministic transition signing
// input ("v":3 payload, ES256 header).
func (EcdsaProfile) KeyTransitionSigningInput(t KeyTransition, bounds *Bounds) (si SigningInput, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(bounds)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if !validKid(t.CurrentKeyID, b.KeyBytes) || !validKid(t.NextKeyID, b.KeyBytes) ||
		!validStringOrURI(t.ChainID, b.IdentifierBytes) || !validStringOrURI(t.TransitionID, b.IdentifierBytes) {
		return SigningInput{}, ErrInvalid
	}
	if len(t.CurrentPublicKey) != es256PublicKeyBytes || len(t.NextPublicKey) != es256PublicKeyBytes {
		return SigningInput{}, ErrInvalid
	}
	fromFP, err := ecdsaSuite.PublicKeyThumbprintRaw(t.CurrentPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	toFP, err := ecdsaSuite.PublicKeyThumbprintRaw(t.NextPublicKey, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	if fromFP == toFP {
		return SigningInput{}, ErrInvalid // fingerprints cannot repeat
	}
	protected, err := JcsEncode(Obj{{Key: "alg", Val: Str("ES256")}, {Key: "kid", Val: Str(t.CurrentKeyID)}, {Key: "typ", Val: Str("ba+key-transition")}}, &b)
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
		{Key: "v", Val: Int(3)},
	}, &b)
	if err != nil {
		return SigningInput{}, ErrInvalid
	}
	return SigningInput{Kind: KindKeyTransition, Protected: protected, Payload: payload}, nil
}

// AssembleCompact assembles a compact JWS from a signing input and a 64-byte
// raw r||s signature. The kind-specific re-parse uses this major's decoders;
// the local-loopback proof profile is bound to contract-major 1 and its kind
// is rejected here.
func (EcdsaProfile) AssembleCompact(si SigningInput, signature []byte, bounds *Bounds) (compact string, err error) {
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
		if _, err := decodeGrantHeaderES(parts, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := ecdsaSuite.decodeGrantPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindProof:
		if _, err := decodeProofHeaderES(parts, b); err != nil {
			return "", ErrInvalid
		}
		if _, err := ecdsaSuite.decodeProofPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindBoundaryAnchor:
		if _, err := decodeAnchorHeaderES(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if err := ecdsaSuite.reparseAnchorPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	case KindKeyTransition:
		if _, err := decodeTransitionHeaderES(parts.Protected, b); err != nil {
			return "", ErrInvalid
		}
		if err := ecdsaSuite.reparseTransitionPayload(parts, b); err != nil {
			return "", ErrInvalid
		}
	default:
		return "", ErrInvalid // no loopback or unknown kind in this major
	}
	return compact, nil
}

// reparseAnchorPayload runs the full closed anchor-claims decode on an
// assembled payload — assembly must reject a well-formed signing input whose
// payload members violate this major's profile, not merely decode as JSON.
// It mirrors the v1 BoundaryAnchorCodec.parse: the closed member set, the
// genesis rule (sequence 0 carries the all-zero chain hash), and the
// canonical-payload check (the received segment is the JCS re-encoding of
// the decoded value).
func (EcdsaProfile) reparseAnchorPayload(p compactParts, b Bounds) error {
	payload, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return ErrInvalid
	}
	claims, ok := ecdsaSuite.decodeAnchorClaims(obj, b)
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
func (EcdsaProfile) reparseTransitionPayload(p compactParts, b Bounds) error {
	payload, err := JsonDecode(p.Payload, &b)
	if err != nil {
		return ErrInvalid
	}
	obj, ok := payload.(Obj)
	if !ok {
		return ErrInvalid
	}
	if _, ok := ecdsaSuite.decodeTransitionClaims(obj, b); !ok {
		return ErrInvalid
	}
	if err := canonicalSegment(p.PayloadSeg, p.Payload, b); err != nil {
		return ErrInvalid
	}
	return nil
}

// ---- consumption chain ----

// chainHash is this major's BAP3-CHAIN domain hash.
func (EcdsaProfile) chainHash(row []byte) [32]byte {
	hh := sha256.New()
	hh.Write(es256ChainPrefix)
	hh.Write(row)
	var out [32]byte
	copy(out[:], hh.Sum(nil))
	return out
}

// EncodeConsumptionEntry produces the canonical row bytes and domain hash
// ("v":3 row, BAP3-CHAIN\0 domain). Sequence one requires the all-zero
// predecessor.
func (EcdsaProfile) EncodeConsumptionEntry(e ConsumptionEntry, bounds *Bounds) (out ConsumedEntry, err error) {
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
		{Key: "v", Val: Int(3)},
	}, &b)
	if err != nil {
		return ConsumedEntry{}, ErrInvalid
	}
	if len(row) > b.ChainRowBytes {
		return ConsumedEntry{}, ErrInvalid
	}
	return ConsumedEntry{Row: row, Hash: ecdsaSuite.chainHash(row)}, nil
}

// parseCanonicalRow requires exact canonical bytes, the closed member set,
// and "v":3.
func (EcdsaProfile) parseCanonicalRow(raw []byte, b Bounds) (chainRowData, error) {
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
			if i, ok := m.Val.(Int); !ok || i != 3 {
				return out, ErrInvalid // this major rejects v1/v2 rows
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
// against mandatory caller boundaries, with the BAP3-CHAIN domain hash.
func (EcdsaProfile) CheckChain(input ChainInput, expected ExpectedChain) (f ChainFacts, err error) {
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
		row, err := ecdsaSuite.parseCanonicalRow(raw, b)
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
		lastHash = ecdsaSuite.chainHash(raw)
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

// decodeAnchorClaims is the closed 7-member anchor payload ("v":3).
func (EcdsaProfile) decodeAnchorClaims(obj Obj, b Bounds) (anchorClaims, bool) {
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
			if i, isInt := m.Val.(Int); !isInt || i != 3 {
				return out, false // this major rejects v1/v2 bytes
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

// decodeTransitionClaims is the closed 7-member transition payload ("v":3).
func (EcdsaProfile) decodeTransitionClaims(obj Obj, b Bounds) (transitionClaims, bool) {
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
			if i, isInt := m.Val.(Int); !isInt || i != 3 {
				return out, false // this major rejects v1/v2 bytes
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

// validHistoricalKeyES is this suite's historical-key revalidation: identical
// to the shared validator except the raw-key width, which here is the 65-byte
// SEC1 constant (the shared bounds' public_key_bytes stays the version-
// neutral 32 of the v1 suite).
func validHistoricalKeyES(k HistoricalPublicKey, b Bounds) bool {
	if !validKid(k.KeyID, b.KeyBytes) || len(k.PublicKey) != es256PublicKeyBytes {
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

// verifyAnchorCompact is this major's anchor primitive: shared headers,
// segments, windows, and gates; the ES256 header and the "v":3 claims decoder.
func (EcdsaProfile) verifyAnchorCompact(compact string, key HistoricalPublicKey, expected ExpectedAnchor, b Bounds) (anchorClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return anchorClaims{}, ErrInvalid // role-bounded frame read
	}
	if !validHistoricalKeyES(key, b) {
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
	kid, err := decodeAnchorHeaderES(parts.Protected, b)
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
	claims, ok := ecdsaSuite.decodeAnchorClaims(obj, b)
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
	derived, err := ecdsaSuite.PublicKeyThumbprintRaw(key.PublicKey, &b)
	if err != nil || derived != claims.KeyFingerprint {
		return anchorClaims{}, ErrInvalid
	}
	si := SigningInput{Kind: KindBoundaryAnchor, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyECDSA(key.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if !keyCovers(key, claims.AnchoredAt) {
		return anchorClaims{}, ErrInvalid
	}
	return claims, nil
}

// VerifyHistoricalAnchor verifies a boundary-anchor compact of this major
// against one exact historical key and expected anchor tuple.
func (EcdsaProfile) VerifyHistoricalAnchor(compact string, key HistoricalPublicKey, expected ExpectedAnchor) (f AnchorFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return AnchorFacts{}, ErrInvalid
	}
	claims, err := ecdsaSuite.verifyAnchorCompact(compact, key, expected, b)
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
func (EcdsaProfile) verifyTransitionCompact(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition, b Bounds) (transitionClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return transitionClaims{}, ErrInvalid
	}
	if !validHistoricalKeyES(currentKey, b) || !validHistoricalKeyES(nextKey, b) {
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
	kid, err := decodeTransitionHeaderES(parts.Protected, b)
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
	claims, ok := ecdsaSuite.decodeTransitionClaims(obj, b)
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
	fromFP, err := ecdsaSuite.PublicKeyThumbprintRaw(currentKey.PublicKey, &b)
	if err != nil || fromFP != claims.FromFingerprint {
		return transitionClaims{}, ErrInvalid
	}
	toFP, err := ecdsaSuite.PublicKeyThumbprintRaw(nextKey.PublicKey, &b)
	if err != nil || toFP != claims.ToFingerprint || toFP == fromFP {
		return transitionClaims{}, ErrInvalid
	}
	si := SigningInput{Kind: KindKeyTransition, Protected: parts.Protected, Payload: parts.Payload}
	if err := verifyECDSA(currentKey.PublicKey, signingInputMessage(si), parts.Signature); err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if !keyCovers(currentKey, claims.EffectiveAt) || !keyCovers(nextKey, claims.EffectiveAt) {
		return transitionClaims{}, ErrInvalid
	}
	return claims, nil
}

// VerifyKeyTransition verifies a transition compact of this major.
func (EcdsaProfile) VerifyKeyTransition(compact string, currentKey, nextKey HistoricalPublicKey, expected ExpectedKeyTransition) (f KeyTransitionFacts, err error) {
	defer closedResult(&err)
	b, err := resolveBounds(expected.Bounds)
	if err != nil {
		return KeyTransitionFacts{}, ErrInvalid
	}
	claims, err := ecdsaSuite.verifyTransitionCompact(compact, currentKey, nextKey, expected, b)
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

// validateExpectedAnchoredExportES is this major's clause-3 pre-digest hoist:
// the complete expected-context well-formedness suite of the shared
// validator, with this suite's 65-byte historical-key width (the shared
// validator pins the version-neutral 32 of the v1 suite).
func validateExpectedAnchoredExportES(expected *ExpectedAnchoredExport, obj ArchivedObject, keys HistoricalKeyChain, b Bounds) error {
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
	if len(keys) != len(expected.Transitions)+1 {
		return ErrInvalid // exact key count
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
	// key chain: ids, widths (this suite's 65-byte SEC1), windows
	for _, k := range keys {
		if !validHistoricalKeyES(k, b) {
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
		return ErrInvalid // REQ1-EXPORT-version-exact (incorporated)
	}
	// digest width
	if _, ok := canonicalDigestString(expected.Digest); !ok {
		return ErrInvalid
	}
	return nil
}

// verifyAnchoredExportCore is this major's export core: the shared
// expected-context hoist, digest seam, and framing walk; the BAP3 magic, the
// "v":3 header, rows, and anchor/transition decoders.
func (EcdsaProfile) verifyAnchoredExportCore(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport, digest archiveDigestFn) (AnchoredExportFacts, error) {
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return AnchoredExportFacts{}, ErrInvalid
	}
	// expected-context validation BEFORE the archive digest
	if err := validateExpectedAnchoredExportES(&expected, obj, keys, b); err != nil {
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
	// framing: the BAP3 magic + length-prefixed frames with exact EOF
	if string(obj.Chunks[0]) != string(es256ArchiveMagic) {
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
			if i, ok := m.Val.(Int); !ok || i != 3 {
				return AnchoredExportFacts{}, ErrInvalid // this major rejects v1/v2 headers
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
	startClaims, err := ecdsaSuite.verifyAnchorCompact(string(startCompactRaw), keys[0], expected.StartAnchor, b)
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
		claims, err := ecdsaSuite.verifyTransitionCompact(string(traw), keys[i], keys[i+1], expected.Transitions[i], b)
		if err != nil {
			return AnchoredExportFacts{}, ErrInvalid
		}
		nextFP, err := ecdsaSuite.PublicKeyThumbprintRaw(keys[i+1].PublicKey, &b)
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
	endClaims, err := ecdsaSuite.verifyAnchorCompact(string(endCompactRaw), keys[len(keys)-1], expected.EndAnchor, b)
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
		row, err := ecdsaSuite.parseCanonicalRow(rraw, b)
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
		lastHash = ecdsaSuite.chainHash(rraw)
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
// through the same archive-digest seam as the v1 facade.
func (EcdsaProfile) VerifyAnchoredExport(obj ArchivedObject, keys HistoricalKeyChain, expected ExpectedAnchoredExport) (f AnchoredExportFacts, err error) {
	defer closedResult(&err)
	return ecdsaSuite.verifyAnchoredExportCore(obj, keys, expected, archiveDigest)
}

// validateExpectedExport is the encode-side expected-context suite: the
// verify-path hoist minus its verify-only legs — no archive-digest width and
// no object-store version (this producer derives its own digest and holds no
// object store) and no key-chain shapes (the encode path holds no public
// keys; the expected tuples carry the key identities).
func (EcdsaProfile) validateExpectedExport(expected *ExpectedAnchoredExport, b Bounds) error {
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
// parses, the key-path walk, the BAP3 magic, and the "v":3 header.
func (EcdsaProfile) EncodeAnchoredExport(input AnchoredExportInput, expected ExpectedAnchoredExport) (out EncodedExport, err error) {
	defer closedResult(&err)
	b, err := resolveExportBounds(&expected)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// expected-side consistency: the encode-side suite
	if err := ecdsaSuite.validateExpectedExport(&expected, b); err != nil {
		return EncodedExport{}, ErrInvalid
	}
	// rows re-checked against the chain
	if int64(len(input.Rows)) != expected.Chain.RowCount {
		return EncodedExport{}, ErrInvalid
	}
	var lastHash [32]byte
	for i, raw := range input.Rows {
		row, err := ecdsaSuite.parseCanonicalRow(raw, b)
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
		lastHash = ecdsaSuite.chainHash(raw)
	}
	wantHead, _ := canonicalDigestString(expected.Chain.LastHash)
	if lastHash != wantHead {
		return EncodedExport{}, ErrInvalid
	}
	// gated parses + 7-field matches for both anchors and every transition
	startParsed, err := ecdsaSuite.parseAnchorCompactGated(input.StartAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(startParsed, expected.StartAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	endParsed, err := ecdsaSuite.parseAnchorCompactGated(input.EndAnchor, b)
	if err != nil {
		return EncodedExport{}, ErrInvalid
	}
	if !anchorTupleMatch(endParsed, expected.EndAnchor) {
		return EncodedExport{}, ErrInvalid
	}
	transitions := make([]transitionClaims, 0, len(input.Transitions))
	for i, traw := range input.Transitions {
		claims, err := ecdsaSuite.parseTransitionCompactGated(traw, b)
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
	// header + BAP3 magic frames
	header, err := JcsEncode(Obj{
		{Key: "chain_id", Val: Str(expected.Chain.ChainID)},
		{Key: "first_sequence", Val: Int(expected.Chain.FirstSequence)},
		{Key: "last_hash", Val: Str(expected.Chain.LastHash)},
		{Key: "last_sequence", Val: Int(expected.Chain.LastSequence)},
		{Key: "previous_hash", Val: Str(expected.Chain.PreviousHash)},
		{Key: "row_count", Val: Int(expected.Chain.RowCount)},
		{Key: "transition_count", Val: Int(len(expected.Transitions))},
		{Key: "v", Val: Int(3)},
	}, &b)
	if err != nil || len(header) > b.ArchiveHeaderBytes {
		return EncodedExport{}, ErrInvalid
	}
	archive := append([]byte(nil), es256ArchiveMagic...)
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
func (EcdsaProfile) parseAnchorCompactGated(compact string, b Bounds) (anchorClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return anchorClaims{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return anchorClaims{}, ErrInvalid
	}
	if _, err := decodeAnchorHeaderES(parts.Protected, b); err != nil {
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
	claims, ok := ecdsaSuite.decodeAnchorClaims(obj, b)
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
func (EcdsaProfile) parseTransitionCompactGated(compact string, b Bounds) (transitionClaims, error) {
	if len(compact) == 0 || len(compact) > b.AnchorBytes {
		return transitionClaims{}, ErrInvalid
	}
	parts, err := splitCompact(compact, b)
	if err != nil {
		return transitionClaims{}, ErrInvalid
	}
	if _, err := decodeTransitionHeaderES(parts.Protected, b); err != nil {
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
	claims, ok := ecdsaSuite.decodeTransitionClaims(obj, b)
	if !ok {
		return transitionClaims{}, ErrInvalid
	}
	return claims, nil
}
