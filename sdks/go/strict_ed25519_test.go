package verifier

// Unit tests for rule S1 (strict Ed25519 verification) and key acceptance.
//
// Rule S1, checked in this order before any backend call: exact widths; A and R canonical; neither A
// nor R of small order (one table serves both); S < L; then the cofactorless equation.
//
// Every expectation about WHICH encodings are small-order or canonical is derived by curve
// arithmetic in strict_ed25519_reference_test.go (finding 12), never copied from the SDK, so a wrong
// table entry in the SDK goes red here. Backend-redundant clauses (R canonical, S < L, widths) are
// tested directly on the byte-level gate, because the cofactorless backend would reject those inputs
// anyway and only a gate test can show the clause exists.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var strictMessage = []byte("strict ed25519 message")

func strictHonest(t *testing.T) (seed, pub, sig []byte) {
	t.Helper()
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	return seed, []byte(private.Public().(ed25519.PublicKey)), ed25519.Sign(private, strictMessage)
}

func withS(sig []byte, s *big.Int) []byte {
	return append(append([]byte(nil), sig[:32]...), refToLittleEndian(s, 32)...)
}

func TestStrictReferenceAgreesWithTheBackend(t *testing.T) {
	small := refSmallOrderEncodings()
	seen := map[string]bool{}
	for _, e := range small {
		seen[string(e)] = true
	}
	if len(small) != 8 || len(seen) != 8 {
		t.Fatalf("reference must derive 8 distinct small-order points, got %d/%d", len(small), len(seen))
	}
	if n := len(refNoncanonicalAliases()); n != 40 {
		t.Fatalf("40 non-canonical aliases expected, got %d", n)
	}
	seed, pub, sig := strictHonest(t)
	if !bytes.Equal(refPublicKey(seed), pub) {
		t.Fatal("reference public key differs from the backend's")
	}
	if !bytes.Equal(refSignFor(seed, pub, strictMessage, nil), sig) {
		t.Fatal("reference signature differs from the backend's")
	}
	if !refVerifies(sig, pub, strictMessage) {
		t.Fatal("reference rejects an honest signature")
	}
}

func TestStrictWidthsAreExact(t *testing.T) {
	_, pub, sig := strictHonest(t)
	for _, keyLen := range []int{0, 1, 31, 33, 64} {
		key := append(append([]byte(nil), pub...), make([]byte, 64)...)[:keyLen]
		if VerifyStrict(strictMessage, sig, key) || AcceptablePublicKey(key) || TorsionFree(key) {
			t.Errorf("key width %d must be refused everywhere", keyLen)
		}
		if strictGate(sig, key) {
			t.Errorf("gate must own the key-width clause (width %d)", keyLen)
		}
	}
	for _, sigLen := range []int{0, 32, 63, 65, 128} {
		bad := append(append([]byte(nil), sig...), make([]byte, 64)...)[:sigLen]
		if VerifyStrict(strictMessage, bad, pub) {
			t.Errorf("signature width %d must be refused", sigLen)
		}
		if strictGate(bad, pub) {
			t.Errorf("gate must own the signature-width clause (width %d)", sigLen)
		}
	}
	if !strictGate(sig, pub) {
		t.Fatal("positive control: an honest signature passes the gate")
	}
}

func TestStrictHonestAcceptedTamperRejected(t *testing.T) {
	for i := 0; i < 8; i++ {
		_, pub, sig := strictHonest(t)
		if !VerifyStrict(strictMessage, sig, pub) {
			t.Fatal("honest signature rejected")
		}
		if VerifyStrict(append(append([]byte(nil), strictMessage...), '!'), sig, pub) {
			t.Fatal("tampered message accepted")
		}
		flipped := append([]byte(nil), sig...)
		flipped[0] ^= 1
		if VerifyStrict(strictMessage, flipped, pub) {
			t.Fatal("tampered signature accepted")
		}
	}
}

func TestStrictRFC8032FirstVector(t *testing.T) {
	pub := mustHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := mustHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"+
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if !VerifyStrict(nil, sig, pub) || !AcceptablePublicKey(pub) || !TorsionFree(pub) {
		t.Fatal("RFC 8032 TEST 1 must be accepted, acceptable and torsion free")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, len(s)/2)
	for i := range out {
		var b byte
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b); err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

// Clause: A is not small-order (each of the 8, derived by arithmetic).
func TestStrictSmallOrderKeyRejected(t *testing.T) {
	_, _, sig := strictHonest(t)
	for i, weak := range refSmallOrderEncodings() {
		if strictGate(sig, weak) || AcceptablePublicKey(weak) || TorsionFree(weak) || VerifyStrict(strictMessage, sig, weak) {
			t.Errorf("small-order key #%d (%x) must be refused", i, weak)
		}
	}
}

func TestStrictIdentityKeyForgeryRejected(t *testing.T) {
	identity := refEncode(refIdentity())
	forged := append(append([]byte(nil), identity...), make([]byte, 32)...)
	if !refVerifies(forged, identity, strictMessage) {
		t.Fatal("the forgery satisfies the bare equation")
	}
	for _, weak := range refSmallOrderEncodings() {
		if VerifyStrict(strictMessage, forged, weak) {
			t.Fatalf("forgery under %x accepted", weak)
		}
	}
}

// Clause: R is not small-order (the same table serves R).
func TestStrictSmallOrderRRejectedByTheGate(t *testing.T) {
	_, pub, sig := strictHonest(t)
	for i, weak := range refSmallOrderEncodings() {
		forged := append(append([]byte(nil), weak...), sig[32:]...)
		if strictGate(forged, pub) {
			t.Errorf("small-order R #%d must be refused by the gate", i)
		}
	}
}

func TestStrictHonestAWithIdentityRRejectedThoughTheEquationHolds(t *testing.T) {
	seed, _, _ := strictHonest(t)
	pub := refPublicKey(seed)
	sig := refIdentityRSignature(seed, strictMessage)
	if !refVerifies(sig, pub, strictMessage) {
		t.Fatal("key-holder construction is unsound")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), strictMessage, sig) {
		t.Fatal("the bare backend must accept this signature (that is the bug the gate closes)")
	}
	if VerifyStrict(strictMessage, sig, pub) {
		t.Fatal("identity R accepted")
	}
}

// mixedA-smallR-{0..7}: the key holder builds R = e_j so the bare equation holds under A + T.
func TestStrictMixedOrderAWithEachSmallOrderRRejected(t *testing.T) {
	seed, _, _ := strictHonest(t)
	torsion := refTorsionSubgroup()[1]
	a := refMul(refSecretScalar(seed), refBase)
	keyEnc := refEncode(refAdd(a, torsion))
	for j, rEnc := range refSmallOrderEncodings() {
		found := false
		for counter := 0; counter < 4000 && !found; counter++ {
			msg := append(append([]byte(nil), strictMessage...), byte(counter>>8), byte(counter))
			k := refChallenge(rEnc, keyEnc, msg)
			s := new(big.Int).Mul(k, refSecretScalar(seed))
			s.Mod(s, refL)
			sig := append(append([]byte(nil), rEnc...), refToLittleEndian(s, 32)...)
			if !refVerifies(sig, keyEnc, msg) {
				continue
			}
			found = true
			if VerifyStrict(msg, sig, keyEnc) || strictGate(sig, keyEnc) {
				t.Errorf("mixedA-smallR-%d accepted", j)
			}
		}
		if !found {
			t.Fatalf("no message cancels the torsion for R #%d (construction bug)", j)
		}
	}
}

// Clause: canonical encodings of A and R.
func TestStrictNoncanonicalAliasesRejectedAsKeyAndAsR(t *testing.T) {
	_, pub, sig := strictHonest(t)
	for _, alias := range refNoncanonicalAliases() {
		if AcceptablePublicKey(alias) || TorsionFree(alias) || strictGate(sig, alias) {
			t.Errorf("non-canonical key %x accepted", alias)
		}
		if strictGate(append(append([]byte(nil), alias...), sig[32:]...), pub) {
			t.Errorf("non-canonical R %x accepted", alias)
		}
	}
}

func TestStrictCanonicalClauseIsolatedByAliasesThatAreNotSmallOrder(t *testing.T) {
	table := map[string]bool{}
	for _, e := range refSmallOrderEncodings() {
		table[string(e)] = true
	}
	_, pub, sig := strictHonest(t)
	isolating := 0
	for _, alias := range refNoncanonicalAliases() {
		if table[string(alias)] {
			t.Fatalf("an alias equals a canonical small-order encoding: %x", alias)
		}
		v := refLittleEndian(alias)
		sign := v.Bit(255)
		y := new(big.Int).SetBit(v, 255, 0)
		y.Mod(y, refP)
		reduced := new(big.Int).SetBit(y, 255, sign)
		pt, ok := refDecode(refToLittleEndian(reduced, 32))
		if !ok || refIsIdentity(refMul(big.NewInt(8), pt)) {
			continue
		}
		isolating++
		if strictGate(sig, alias) || strictGate(append(append([]byte(nil), alias...), sig[32:]...), pub) {
			t.Errorf("alias %x slipped past the canonical clause", alias)
		}
	}
	if isolating < 10 {
		t.Fatalf("only %d aliases isolate the canonical clause", isolating)
	}
}

func TestStrictXZeroWithSignBitIsNoncanonical(t *testing.T) {
	_, pub, sig := strictHonest(t)
	identitySigned := refToLittleEndian(new(big.Int).SetBit(big.NewInt(1), 255, 1), 32)
	order2Signed := refToLittleEndian(new(big.Int).SetBit(new(big.Int).Sub(refP, big.NewInt(1)), 255, 1), 32)
	for _, enc := range [][]byte{identitySigned, order2Signed} {
		if AcceptablePublicKey(enc) || strictGate(sig, enc) || strictGate(append(append([]byte(nil), enc...), sig[32:]...), pub) {
			t.Errorf("x = 0 with the sign bit (%x) accepted", enc)
		}
	}
}

func TestStrictYEqualPBoundary(t *testing.T) {
	_, pub, sig := strictHonest(t)
	yEqP := refToLittleEndian(refP, 32)
	if strictGate(sig, yEqP) || strictGate(append(append([]byte(nil), yEqP...), sig[32:]...), pub) {
		t.Fatal("y = p must be non-canonical")
	}
	below := refToLittleEndian(new(big.Int).Sub(refP, big.NewInt(2)), 32)
	if !strictGate(sig, below) || !strictGate(append(append([]byte(nil), below...), sig[32:]...), pub) {
		t.Fatal("y = p - 2 is canonical and not small-order: the gate must not reject it")
	}
}

// Clause: S < L.
func TestStrictScalarAtOrAboveLRejectedByTheGate(t *testing.T) {
	_, pub, sig := strictHonest(t)
	one := big.NewInt(1)
	cases := []*big.Int{
		new(big.Int).Set(refL),
		new(big.Int).Add(refL, one),
		new(big.Int).Add(refL, big.NewInt(12345)),
		new(big.Int).Lsh(refL, 1),
		new(big.Int).Sub(new(big.Int).Lsh(one, 256), one),
		new(big.Int).Lsh(one, 255),
		new(big.Int).Lsh(one, 253),
	}
	for _, s := range cases {
		if strictGate(withS(sig, s), pub) || VerifyStrict(strictMessage, withS(sig, s), pub) {
			t.Errorf("S = %v accepted", s)
		}
	}
	for _, s := range []*big.Int{new(big.Int).Sub(refL, one), big.NewInt(0)} {
		if !strictGate(withS(sig, s), pub) {
			t.Errorf("S = %v < L must pass the gate", s)
		}
	}
	if !strictGate(sig, pub) {
		t.Fatal("positive control")
	}
}

func TestStrictSPlusLMalleabilityRejected(t *testing.T) {
	_, pub, sig := strictHonest(t)
	s := refLittleEndian(sig[32:])
	malleated := withS(sig, new(big.Int).Add(s, refL))
	if !VerifyStrict(strictMessage, sig, pub) {
		t.Fatal("positive control")
	}
	if VerifyStrict(strictMessage, malleated, pub) {
		t.Fatal("S + L accepted")
	}
}

func TestStrictGateRejectsOnlyTheDerivedSmallOrderSet(t *testing.T) {
	seed, _, _ := strictHonest(t)
	a := refMul(refSecretScalar(seed), refBase)
	_, _, sig := strictHonest(t)
	table := map[string]bool{}
	for _, e := range refSmallOrderEncodings() {
		table[string(e)] = true
	}
	for _, torsion := range refTorsionSubgroup()[1:] {
		variant := refEncode(refAdd(a, torsion))
		if table[string(variant)] {
			t.Fatal("a mixed-order key must not be in the small-order set")
		}
		if !strictGate(sig, variant) || !strictGate(append(append([]byte(nil), variant...), sig[32:]...), refPublicKey(seed)) {
			t.Errorf("a mixed-order encoding %x is not small-order and must pass the gate", variant)
		}
	}
}

// Torsion variants: acceptable passes, torsion_free fails; verify accepts (R2 pin).
func TestStrictTorsionVariantsAcceptableButNotTorsionFree(t *testing.T) {
	for i := 1; i < 8; i++ {
		seed, _, _ := strictHonest(t)
		torsion := refTorsionSubgroup()[i]
		keyEnc, sig := refSignUnderTorsion(seed, torsion, strictMessage)
		if bytes.Equal(keyEnc, refPublicKey(seed)) {
			t.Fatal("variant equals the honest key")
		}
		if !AcceptablePublicKey(keyEnc) {
			t.Errorf("variant %d must be acceptable", i)
		}
		if TorsionFree(keyEnc) {
			t.Errorf("variant %d must not be torsion free", i)
		}
		if !VerifyStrict(strictMessage, sig, keyEnc) {
			t.Errorf("variant %d: accepted at verify, rejected by the host check", i)
		}
		honest := refSignFor(seed, refPublicKey(seed), strictMessage, nil)
		if VerifyStrict(strictMessage, honest, keyEnc) {
			t.Errorf("variant %d: key substitution (honest signature verified)", i)
		}
	}
}

func TestStrictPrimeOrderKeyAcceptableAndTorsionFree(t *testing.T) {
	for i := 0; i < 6; i++ {
		_, pub, _ := strictHonest(t)
		if !AcceptablePublicKey(pub) || !TorsionFree(pub) {
			t.Fatalf("honest key %x must be acceptable and torsion free", pub)
		}
	}
}

func TestStrictOffCurveKeyRefused(t *testing.T) {
	off := refOffCurve()
	if _, ok := refDecode(off); ok {
		t.Fatal("reference says the encoding is on the curve")
	}
	_, _, sig := strictHonest(t)
	if AcceptablePublicKey(off) || TorsionFree(off) || VerifyStrict(strictMessage, sig, off) {
		t.Fatal("an off-curve key must be refused")
	}
}

func TestStrictNeverPanicsOnArbitraryInput(t *testing.T) {
	for i := 0; i < 64; i++ {
		junk := make([]byte, i)
		_, _ = rand.Read(junk)
		_ = VerifyStrict(junk, junk, junk)
		_ = AcceptablePublicKey(junk)
		_ = TorsionFree(junk)
	}
	if VerifyStrict(nil, nil, nil) || AcceptablePublicKey(nil) || TorsionFree(nil) {
		t.Fatal("nil input must be refused")
	}
}

// Differential property: VerifyStrict equals the pure reference rule (no table, no backend).
func TestStrictMatchesThePureReferenceOnADifferentialSet(t *testing.T) {
	var total, accepted int
	check := func(msg, sig, key []byte) {
		t.Helper()
		want := refStrictVerdict(msg, sig, key)
		if got := VerifyStrict(msg, sig, key); got != want {
			t.Fatalf("VerifyStrict=%v reference=%v for key %x sig %x", got, want, key, sig)
		}
		total++
		if want {
			accepted++
		}
	}
	aliases := refNoncanonicalAliases()
	for round := 0; round < 4; round++ {
		sum := sha256.Sum256([]byte{byte(round), 'd', 'i', 'f', 'f'})
		seed := sum[:]
		msg := append(append([]byte(nil), strictMessage...), byte(round))
		pub := refPublicKey(seed)
		honest := refSignFor(seed, pub, msg, nil)
		check(msg, honest, pub)
		check(msg, withS(honest, new(big.Int).Add(refLittleEndian(honest[32:]), refL)), pub)
		check(msg, refIdentityRSignature(seed, msg), pub)
		for _, tor := range refTorsionSubgroup()[1:] {
			keyEnc, sig := refSignUnderTorsion(seed, tor, msg)
			check(msg, sig, keyEnc)
			check(msg, honest, keyEnc)
		}
		for _, weak := range refSmallOrderEncodings() {
			check(msg, append(refEncode(refIdentity()), make([]byte, 32)...), weak)
			check(msg, append(append([]byte(nil), weak...), honest[32:]...), pub)
		}
		for _, alias := range aliases[:12] {
			check(msg, honest, alias)
			check(msg, append(append([]byte(nil), alias...), honest[32:]...), pub)
		}
	}
	if total < 200 || accepted < 10 || accepted >= total {
		t.Fatalf("the set must exercise both verdicts: total=%d accepted=%d", total, accepted)
	}
}

// The fallible set: JWK encode/decode and every public thumbprint function.
func strictWeakKeys() [][]byte {
	weak := append(refSmallOrderEncodings(), refNoncanonicalAliases()...)
	return append(weak, refOffCurve())
}

func jwkText(key []byte) []byte {
	return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + Base64urlEncode(key) + `"}`)
}

func TestStrictKeyFunctionsRejectWeakKeysAndAcceptAnHonestKey(t *testing.T) {
	_, honest, _ := strictHonest(t)
	// Positive controls: every function works on an honest key.
	if enc, err := JwkEncodePublic(honest, nil); err != nil || !bytes.Equal(enc, jwkText(honest)) {
		t.Fatalf("encode honest: %v", err)
	}
	if got, err := JwkDecodePublic(jwkText(honest), nil); err != nil || !bytes.Equal(got, honest) {
		t.Fatalf("decode honest: %v", err)
	}
	if _, err := PublicKeyThumbprintRaw(honest, nil); err != nil {
		t.Fatalf("thumbprint honest: %v", err)
	}
	if _, err := JwkThumbprintPreimage(jwkText(honest), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := JwkThumbprint(jwkText(honest), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := JwkThumbprintRaw(jwkText(honest), nil); err != nil {
		t.Fatal(err)
	}
	for _, weak := range strictWeakKeys() {
		if _, err := JwkEncodePublic(weak, nil); err != ErrInvalid {
			t.Errorf("JwkEncodePublic(%x) = %v", weak, err)
		}
		if _, err := JwkDecodePublic(jwkText(weak), nil); err != ErrInvalid {
			t.Errorf("JwkDecodePublic(%x) = %v", weak, err)
		}
		if _, err := PublicKeyThumbprintRaw(weak, nil); err != ErrInvalid {
			t.Errorf("PublicKeyThumbprintRaw(%x) = %v", weak, err)
		}
		if _, err := JwkThumbprintPreimage(jwkText(weak), nil); err != ErrInvalid {
			t.Errorf("JwkThumbprintPreimage(%x) = %v", weak, err)
		}
		if _, err := JwkThumbprint(jwkText(weak), nil); err != ErrInvalid {
			t.Errorf("JwkThumbprint(%x) = %v", weak, err)
		}
		if _, err := JwkThumbprintRaw(jwkText(weak), nil); err != ErrInvalid {
			t.Errorf("JwkThumbprintRaw(%x) = %v", weak, err)
		}
	}
}

func TestStrictUncheckedThumbprintIsAPureHashForWeakKeys(t *testing.T) {
	_, honest, _ := strictHonest(t)
	for _, raw := range [][]byte{honest, refSmallOrderEncodings()[0], refNoncanonicalAliases()[0]} {
		want := sha256.Sum256(jwkText(raw))
		if got := jwkThumbprintOfKey(raw); got != want {
			t.Errorf("jwkThumbprintOfKey(%x) differs from the plain SHA-256 of the preimage", raw)
		}
	}
	checked, err := PublicKeyThumbprintRaw(honest, nil)
	if err != nil || checked != jwkThumbprintOfKey(honest) {
		t.Fatal("the checked and unchecked thumbprints must agree on an honest key")
	}
}

// Architecture pin (finding 10a): the raw hash-only thumbprint path has a closed caller set. Every
// caller runs after the key was accepted (verified or decoded); a new caller must be reviewed.
func TestStrictUncheckedThumbprintCallerSetIsPinned(t *testing.T) {
	allowed := map[string]bool{
		"content_assertion.go:VerifyContentAssertion": true, // after verifyEd25519 under the attestor key
		"role_attestation.go:VerifyAttestation":       true, // after verifyEd25519 and the subject binding
		"v1.go:checkEnvelopeFor":                      true, // holder key decoded through JwkDecodePublic
		"v2.go:CheckEnvelope":                         true, // holder key decoded through JwkDecodePublic
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "jwkThumbprintOfKey" {
					found[name+":"+fn.Name.Name] = true
				}
				return true
			})
		}
	}
	for site := range found {
		if !allowed[site] {
			t.Errorf("new caller of jwkThumbprintOfKey (the unchecked thumbprint): %s", site)
		}
	}
	for site := range allowed {
		if !found[site] {
			t.Errorf("pinned caller %s no longer calls jwkThumbprintOfKey; update the pin", site)
		}
	}
	if _, err := os.Stat("v1.go"); err != nil {
		t.Fatal(err)
	}
}
