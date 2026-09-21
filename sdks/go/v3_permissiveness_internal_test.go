package verifier

// White-box permissiveness legs for the contract-major-3 ES256 profile. Every
// leg is red-capable: the mechanical break named in its header comment makes
// exactly that leg fail. The red observations recorded below were produced by
// applying each break to v3.go, running this file's tests, capturing the
// failure, and reverting (the ADR 0014 D6/D7 mutation-gate discipline the
// v1/v2 batteries follow). Where the Go stdlib backend already subsumes a
// gate, the per-clause red-capable form is the direct unit leg on the pure
// profile validator (the ADR 0017 subsumption pattern the v1 battery uses for
// the canonical-form gate).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- corpus-derived fixtures (loaded from the vendored corpus-v3 snapshot) ----

// es256LoadVerifyGrantCase loads one grant-verify case from the vendored v3
// corpus (compact plus the trusted-issuer inputs).
func es256LoadVerifyGrantCase(t *testing.T, id string) (compact string, issuer TrustedIssuer, exp ExpectedGrant) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("conformance", "corpus-v3", "cases", "grant-verify", "verify.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Audience       string `json:"audience"`
				ClockSkew      int64  `json:"clock_skew"`
				Compact        string `json:"compact"`
				EvaluationTime int64  `json:"evaluation_time"`
				Issuer         string `json:"issuer"`
				KeyID          string `json:"key_id"`
				PublicKey      string `json:"public_key"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("corpus parse: %v", err)
	}
	for _, c := range cf.Cases {
		if c.ID != id {
			continue
		}
		pk, err := Base64urlDecode(c.Input.PublicKey)
		if err != nil {
			t.Fatalf("case %s public key: %v", id, err)
		}
		return c.Input.Compact, TrustedIssuer{KeyID: c.Input.KeyID, PublicKey: pk},
			ExpectedGrant{
				Issuer:         c.Input.Issuer,
				Audience:       c.Input.Audience,
				EvaluationTime: c.Input.EvaluationTime,
				ClockSkew:      c.Input.ClockSkew,
			}
	}
	t.Fatalf("corpus-v3 case %s missing", id)
	return "", TrustedIssuer{}, ExpectedGrant{}
}

// es256LoadCompact loads one case compact from a vendored corpus-v3 surface file.
func es256LoadCompact(t *testing.T, surfaceDir, file, id string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("conformance", "corpus-v3", "cases", surfaceDir, file))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Compact string `json:"compact"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("corpus parse: %v", err)
	}
	for _, c := range cf.Cases {
		if c.ID == id {
			return c.Input.Compact
		}
	}
	t.Fatalf("corpus-v3 case %s missing", id)
	return ""
}

// es256LoadJwkInput loads one jwk-surface case's text or public_key input.
func es256LoadJwkInput(t *testing.T, id, field string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("conformance", "corpus-v3", "cases", "jwk", "jwk.json"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	var cf struct {
		Cases []struct {
			ID    string                 `json:"id"`
			Input map[string]interface{} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("corpus parse: %v", err)
	}
	for _, c := range cf.Cases {
		if c.ID == id {
			s, ok := c.Input[field].(string)
			if !ok {
				t.Fatalf("case %s: field %s missing", id, field)
			}
			return s
		}
	}
	t.Fatalf("corpus-v3 case %s missing", id)
	return ""
}

// ---- (a) low-S malleability gate (REQ3-SIGNING-low-s) ----
//
// RED OBSERVATION (2026-09-21, Go 1.25.14): deleting the
// `s.Cmp(p256HalfOrder) > 0` clause from validateRawRS in v3.go reddens exactly
// this leg — the high-S corpus compact then VERIFIES (Go's crypto/ecdsa
// backend accepts the malleable (r, n-s) counterpart, so the profile gate is
// the only closure) — observed: `go test -run TestEcdsaPermissiveLowS ./...`
// failed with "verify-grant-v3-invalid-signature-high-s: high-S signature
// must be rejected (malleable counterpart)", and the full corpus under the
// same break failed exactly that one case (agreed=291).
func TestEcdsaPermissiveLowS(t *testing.T) {
	for _, id := range []string{
		"verify-grant-v3-invalid-signature-high-s",
	} {
		compact, issuer, exp := es256LoadVerifyGrantCase(t, id)
		if _, err := ecdsaSuite.VerifyGrant(compact, issuer, exp); err == nil {
			t.Fatalf("%s: high-S signature must be rejected (malleable counterpart)", id)
		}
	}
	// the low-S ceiling itself: s = n/2 + 1 rejects, and the boundary value
	// s = floor(n/2) admits (the inclusive spelling of "0 < s <= n/2")
	es256AssertRawRS(t, es256RawRS("valid", "half-order-plus-one"), ErrInvalid)
	es256AssertRawRS(t, es256RawRS("valid", "half-order-exactly"), nil)
}

// ---- (b) raw r||s integer-range gates (REQ3-SIGNING-range) ----
//
// Go's crypto/ecdsa backend (fips140 verifyGeneric: bigmod SetBytes under the
// curve order plus the zero checks) already rejects r=0, s=0, r>=n, and s>=n,
// so those public-path rejections are SUBSUMED by the backend — the
// per-clause red-capable form is this direct unit leg on the profile's pure
// validator, exactly the subsumption pattern of TestCanonicalGateUnit.
//
// RED OBSERVATION (2026-09-21, Go 1.25.14): deleting the zero and
// `Cmp(p256Params.N) >= 0` clauses from validateRawRS in v3.go reddens exactly
// the zero/at-n assertions of this leg (validateRawRS returns nil for them)
// while the corpus r-at-n/s-at-n/zero cases stay rejected through backend
// subsumption — observed: `go test -run TestEcdsaPermissiveRawRS ./...` failed
// with "validateRawRS(64 bytes) = <nil>, want invalid" (the r=0 spelling,
// first assertion) and the full corpus stayed at agreed=292 under the same
// break (the subsumption, observed live).
func TestEcdsaPermissiveRawRS(t *testing.T) {
	// zero integers
	es256AssertRawRS(t, es256RawRS("zero", "valid"), ErrInvalid)
	es256AssertRawRS(t, es256RawRS("valid", "zero"), ErrInvalid)
	// at and over the group order
	es256AssertRawRS(t, es256RawRS("n", "valid"), ErrInvalid)
	es256AssertRawRS(t, es256RawRS("valid", "n"), ErrInvalid)
	es256AssertRawRS(t, es256RawRS("n-plus-one", "valid"), ErrInvalid)
	// width is part of the encoding gate
	es256AssertRawRS(t, make([]byte, 63), ErrInvalid)
	es256AssertRawRS(t, make([]byte, 65), ErrInvalid)
	// a well-formed low-S pair passes the pure gate
	es256AssertRawRS(t, es256RawRS("valid", "valid"), nil)
	// the corpus spelling through the public path: each must reject
	for _, id := range []string{
		"verify-grant-v3-invalid-signature-zero-r",
		"verify-grant-v3-invalid-signature-zero-s",
		"verify-grant-v3-invalid-signature-r-at-n",
		"verify-grant-v3-invalid-signature-s-at-n",
	} {
		compact, issuer, exp := es256LoadVerifyGrantCase(t, id)
		if _, err := ecdsaSuite.VerifyGrant(compact, issuer, exp); err == nil {
			t.Fatalf("%s: out-of-range raw r||s must be rejected", id)
		}
	}
}

// ---- (c) EC JWK closed member set (REQ3-HEADER-proof-jwk, no-private-jwk) ----
//
// The member-set closure is LAYERED in decodePublicJwk — the exact-four
// count gate, the per-member allowlist default arm, and the nil-presence
// check each independently close the corpus fixtures — so no single-layer
// removal reddens the extra-member/missing-y assertions.
//
// RED OBSERVATIONS (2026-09-21, Go 1.25.14):
//   - break 1: replacing the `*crv != "P-256" || *kty != "EC"` rejection
//     with `false` reddened exactly the wrong-crv assertion first —
//     `go test -run TestEcdsaPermissiveJwkMemberSet ./...` failed with
//     "jwk-decode-public-invalid-crv-p384: wrong crv must be rejected"
//     (wrong-kty reddens under the same break on the next assertion);
//   - break 2 (count gate alone removed): observed GREEN — the extra-member
//     fixture was still closed by the per-member allowlist arm (the layered
//     closure, recorded as an observation, not a gap);
//   - break 3 (count + allowlist + presence removed together): reddened the
//     extra-member assertion — the same run failed with
//     "jwk-decode-public-invalid-extra-member-d: extra member d must be
//     rejected". All breaks reverted; the v3.go hash returned to baseline.
func TestEcdsaPermissiveJwkMemberSet(t *testing.T) {
	reject := map[string]string{
		"jwk-decode-public-invalid-crv-p384":                  "wrong crv must be rejected",
		"jwk-decode-public-invalid-kty-okp":                   "kty OKP must be rejected",
		"jwk-decode-public-invalid-extra-member-d":            "extra member d must be rejected",
		"jwk-decode-public-invalid-missing-y":                 "missing y must be rejected",
		"jwk-decode-public-invalid-member-order-okp-preimage": "the OKP preimage spelling must be rejected",
		"jwk-decode-public-invalid-malformed":                 "malformed JWK text must be rejected",
	}
	for id, why := range reject {
		if _, err := ecdsaSuite.JwkDecodePublic([]byte(es256LoadJwkInput(t, id, "text")), nil); err == nil {
			t.Fatalf("%s: %s", id, why)
		}
	}
	// the valid EC JWK decodes (the byte-exact raw-key comparison is the
	// corpus runner's job)
	if _, err := ecdsaSuite.JwkDecodePublic([]byte(es256LoadJwkInput(t, "jwk-decode-public-valid-ec", "text")), nil); err != nil {
		t.Fatalf("valid EC JWK must decode: %v", err)
	}
}

// ---- (d) coordinate and raw-key width + canonicality ----
//
// RED OBSERVATION (2026-09-21, Go 1.25.14): replacing the
// `len(key) != es256PublicKeyBytes || key[0] != 0x04` gate in
// (EcdsaProfile).JwkEncodePublic and (EcdsaProfile).PublicKeyThumbprintRaw with
// `false` reddens exactly the raw-key assertions below (the 64-byte, short,
// and compressed-form keys then encode/fingerprint). The JWK-coordinate
// width assertions are observed SUBSUMED by the on-curve arithmetic (with
// the decodePublicJwk width gate deleted, the corpus short-coordinate case
// still rejects through the curve equation), and the padded-coordinate
// assertion is SUBSUMED by the shared Base64urlDecode canonicality gate
// (pinned red-capable in the v1 battery) — the raw-key leg is this class's
// per-clause red-capable form. Observed:
// `go test -run TestEcdsaPermissiveWidths ./...` failed with
// "jwk-encode-public-invalid-length-64: non-65-byte/compressed raw key must
// be rejected"; under the same break the corpus jwk-encode/thumbprint width
// cases failed too. Subsumption observed in isolation: with ONLY the
// decodePublicJwk coordinate-width gate removed, the full corpus stayed at
// agreed=292 (the short-coordinate case closed by the curve equation, the
// padded case by the shared base64url canonicality gate).
func TestEcdsaPermissiveWidths(t *testing.T) {
	// raw-key surface: only the 65-byte uncompressed SEC1 form is valid
	valid := es256LoadJwkInput(t, "jwk-encode-public-valid-ec", "public_key")
	validRaw, err := Base64urlDecode(valid)
	if err != nil || len(validRaw) != 65 {
		t.Fatalf("fixture: %d bytes", len(validRaw))
	}
	if _, err := ecdsaSuite.JwkEncodePublic(validRaw, nil); err != nil {
		t.Fatalf("65-byte SEC1 key must encode: %v", err)
	}
	for _, id := range []string{
		"jwk-encode-public-invalid-length-64",
		"jwk-encode-public-invalid-compressed-form",
	} {
		raw, err := Base64urlDecode(es256LoadJwkInput(t, id, "public_key"))
		if err != nil {
			t.Fatalf("fixture %s: %v", id, err)
		}
		if _, err := ecdsaSuite.JwkEncodePublic(raw, nil); err == nil {
			t.Fatalf("%s: non-65-byte/compressed raw key must be rejected", id)
		}
	}
	if _, err := ecdsaSuite.PublicKeyThumbprintRaw([]byte{0x04}, nil); err == nil {
		t.Fatal("short raw key must not fingerprint")
	}
	// JWK-coordinate width and canonicality through the decode surface
	for _, id := range []string{
		"jwk-decode-public-invalid-short-coordinate",
		"jwk-decode-public-invalid-padded-coordinate",
	} {
		if _, err := ecdsaSuite.JwkDecodePublic([]byte(es256LoadJwkInput(t, id, "text")), nil); err == nil {
			t.Fatalf("%s: wrong-width/non-canonical coordinate must be rejected", id)
		}
	}
}

// ---- (e) pure-arithmetic point validation (REQ3-KEY-point-on-curve) ----
//
// RED OBSERVATION (2026-09-21, Go 1.25.14): replacing p256OnCurve's body
// with `return true` reddens exactly this leg — the off-curve and
// at-field-prime corpus JWKs then decode, and the off-curve 65-byte key then
// passes verifyECDSA's point gate (the corpus off-curve case and this leg
// both fail) — observed:
// `go test -run TestEcdsaPermissiveOnCurve ./...` failed with
// "jwk-decode-public-invalid-off-curve: off-curve/coordinate-at-prime point
// must be rejected at decode", and the full corpus under the same break fell
// to agreed=290 failing exactly the two point-validation cases (off-curve,
// coordinate-at-field-prime).
func TestEcdsaPermissiveOnCurve(t *testing.T) {
	for _, id := range []string{
		"jwk-decode-public-invalid-off-curve",
		"jwk-decode-public-invalid-coordinate-at-field-prime",
	} {
		if _, err := ecdsaSuite.JwkDecodePublic([]byte(es256LoadJwkInput(t, id, "text")), nil); err == nil {
			t.Fatalf("%s: off-curve/coordinate-at-prime point must be rejected at decode", id)
		}
	}
	// the pure arithmetic itself: p is not a valid coordinate
	pBytes := p256Params.P.FillBytes(make([]byte, 32))
	if p256OnCurve(new(big.Int).SetBytes(pBytes), new(big.Int).SetBytes(pBytes)) {
		t.Fatal("coordinate >= p must be rejected by the arithmetic")
	}
	// a corpus-valid point passes
	valid := es256LoadJwkInput(t, "jwk-decode-public-valid-ec", "text")
	if _, err := ecdsaSuite.JwkDecodePublic([]byte(valid), nil); err != nil {
		t.Fatalf("on-curve corpus point must decode: %v", err)
	}
}

// ---- (f) cross-major v acceptance (REQ3-CORE-cross-major-reject) ----
//
// RED OBSERVATION (2026-09-21, Go 1.25.14): widening the payload v-check in
// (EcdsaProfile).decodeGrantPayload and decodeProofPayload (replacing
// `i != 3` with a tautology) reddens exactly the forged-v assertions below —
// the v:1 and v:2 spellings of an otherwise-valid ES256 artifact then
// decode (DecodeGrant performs no signature check, so the v gate is the only
// closure for the forged fixtures) — observed:
// `go test -run TestEcdsaPermissiveCrossMajor ./...` failed with
// 'forged "v":1 payload must be rejected by the v gate' (the v:2 spelling
// reddens on the next loop iteration); the full corpus stayed at agreed=292
// under the same break — the real v1/v2 corpus bytes are double-gated by the
// ES256 alg header, exactly the isolation the forged fixtures provide. The
// real v1/v2 corpus bytes stay rejected through the independent alg-header
// gate under this break (double-gated by construction); the symmetric
// assertions (v1/v2 facades rejecting v3 bytes) redden against the v1/v2
// v-checks, which are frozen here.
func TestEcdsaPermissiveCrossMajor(t *testing.T) {
	// real v1/v2 artifact bytes are rejected by this major
	for _, id := range []string{
		"grant-decode-v3-invalid-cross-major-v1-bytes",
		"grant-decode-v3-invalid-cross-major-v2-bytes",
	} {
		if _, err := ecdsaSuite.DecodeGrant(es256LoadCompact(t, "grant-decode", "decode.json", id), nil); err == nil {
			t.Fatalf("%s: this major must reject other-major bytes", id)
		}
	}
	for _, id := range []string{
		"proof-decode-v3-invalid-cross-major-v1-proof",
		"proof-decode-v3-invalid-cross-major-v2-bytes",
	} {
		if _, err := ecdsaSuite.DecodeProof(es256LoadCompact(t, "proof-decode", "decode.json", id), nil); err == nil {
			t.Fatalf("%s: this major must reject other-major proof bytes", id)
		}
	}
	// forged fixtures isolate the payload v gate: an otherwise-valid v3
	// artifact whose payload v claim is 1 (then 2) must be rejected by the v
	// check alone
	valid := es256LoadCompact(t, "grant-decode", "decode.json", "grant-decode-v3-valid")
	for _, forged := range []string{`"v":1`, `"v":2`} {
		seg := strings.Split(valid, ".")
		payload, err := Base64urlDecode(seg[1])
		if err != nil {
			t.Fatal(err)
		}
		tampered := strings.Replace(string(payload), `"v":3`, forged, 1)
		if tampered == string(payload) {
			t.Fatalf("fixture substitution failed for %s", forged)
		}
		compact := seg[0] + "." + Base64urlEncode([]byte(tampered)) + "." + seg[2]
		if _, err := ecdsaSuite.DecodeGrant(compact, nil); err == nil {
			t.Fatalf("forged %s payload must be rejected by the v gate", forged)
		}
	}
	// symmetric: the frozen v1 and v2 facades reject v3 bytes
	if _, err := DecodeGrant(es256LoadCompact(t, "grant-decode", "decode.json", "grant-decode-v3-valid"), nil); err == nil {
		t.Fatal("v1 DecodeGrant must reject a v3 grant")
	}
	if _, err := successor.DecodeGrant(es256LoadCompact(t, "grant-decode", "decode.json", "grant-decode-v3-valid"), nil); err == nil {
		t.Fatal("v2 DecodeGrant must reject a v3 grant")
	}
}

// ---- helpers: raw r||s constructions over fixed-width big-endian halves ----

// es256RawRS builds a 64-byte raw signature from named integer spellings for
// the r and s halves.
func es256RawRS(rName, sName string) []byte {
	out := make([]byte, 64)
	copy(out[:32], es256IntSpelling(rName))
	copy(out[32:], es256IntSpelling(sName))
	return out
}

// es256IntSpelling materializes one named 32-byte integer: "zero", "valid" (a
// fixed small in-range value), "n", "n-plus-one", "half-order-plus-one",
// "half-order-exactly".
func es256IntSpelling(name string) []byte {
	switch name {
	case "zero":
		return make([]byte, 32)
	case "n":
		return p256Params.N.FillBytes(make([]byte, 32))
	case "n-plus-one":
		np := new(big.Int).Add(p256Params.N, big.NewInt(1))
		return np.FillBytes(make([]byte, 33))[1:]
	case "half-order-plus-one":
		hp := new(big.Int).Add(p256HalfOrder, big.NewInt(1))
		return hp.FillBytes(make([]byte, 32))
	case "half-order-exactly":
		return p256HalfOrder.FillBytes(make([]byte, 32))
	default: // "valid": a fixed small in-range integer
		out := make([]byte, 32)
		out[31] = 0x2a
		return out
	}
}

func es256AssertRawRS(t *testing.T, sig []byte, want error) {
	t.Helper()
	if err := validateRawRS(sig); err != want {
		t.Fatalf("validateRawRS(%d bytes) = %v, want %v", len(sig), err, want)
	}
}
