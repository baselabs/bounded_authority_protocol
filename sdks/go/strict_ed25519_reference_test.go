package verifier

// Test-only Ed25519 reference arithmetic (affine Edwards coordinates over math/big).
//
// It exists so the strict-Ed25519 tests derive their expectations by curve arithmetic instead of
// copying the SDK's own small-order table (finding 12), and can build the key-holder constructions
// (mixed-order keys, identity-R signatures) no honest signer emits. It is deliberately a different
// formulation from ed25519_strict.go (affine points with modular inverses, versus extended
// coordinates there), so the two do not share a defect. It is compiled only into tests.

import (
	"crypto/sha512"
	"math/big"
	"sync"
)

type refPoint struct{ x, y *big.Int }

var (
	refP     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	refL, _  = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	refD     = refComputeD()
	refSqrtM = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(refP, big.NewInt(1)), 2), refP)
)

func refComputeD() *big.Int {
	num := new(big.Int).Neg(big.NewInt(121665))
	num.Mod(num, refP)
	den := new(big.Int).ModInverse(big.NewInt(121666), refP)
	return num.Mul(num, den).Mod(num, refP)
}

func refIdentity() refPoint { return refPoint{big.NewInt(0), big.NewInt(1)} }

func refMod(v *big.Int) *big.Int { return v.Mod(v, refP) }

func refAdd(p, q refPoint) refPoint {
	x1y2 := new(big.Int).Mul(p.x, q.y)
	x2y1 := new(big.Int).Mul(q.x, p.y)
	y1y2 := new(big.Int).Mul(p.y, q.y)
	x1x2 := new(big.Int).Mul(p.x, q.x)
	t := new(big.Int).Mul(x1x2, y1y2)
	t.Mul(t, refD)
	refMod(t)
	denX := new(big.Int).Add(big.NewInt(1), t)
	denY := new(big.Int).Sub(big.NewInt(1), t)
	x3 := new(big.Int).Add(x1y2, x2y1)
	x3.Mul(x3, new(big.Int).ModInverse(refMod(denX), refP))
	y3 := new(big.Int).Add(y1y2, x1x2)
	y3.Mul(y3, new(big.Int).ModInverse(refMod(denY), refP))
	return refPoint{refMod(x3), refMod(y3)}
}

func refMul(k *big.Int, p refPoint) refPoint {
	acc := refIdentity()
	addend := p
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			acc = refAdd(acc, addend)
		}
		addend = refAdd(addend, addend)
	}
	return acc
}

func refEqual(p, q refPoint) bool { return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0 }

func refIsIdentity(p refPoint) bool { return refEqual(p, refIdentity()) }

func refLittleEndian(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func refToLittleEndian(v *big.Int, n int) []byte {
	be := v.FillBytes(make([]byte, n))
	out := make([]byte, n)
	for i := range be {
		out[n-1-i] = be[i]
	}
	return out
}

func refEncode(p refPoint) []byte {
	v := new(big.Int).Set(p.y)
	if p.x.Bit(0) == 1 {
		v.SetBit(v, 255, 1)
	}
	return refToLittleEndian(v, 32)
}

// refDecode is the strict RFC 8032 section 5.1.3 decode; ok is false for a non-canonical or
// off-curve encoding.
func refDecode(enc []byte) (refPoint, bool) {
	if len(enc) != 32 {
		return refPoint{}, false
	}
	v := refLittleEndian(enc)
	sign := v.Bit(255)
	y := new(big.Int).SetBit(v, 255, 0)
	if y.Cmp(refP) >= 0 {
		return refPoint{}, false
	}
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(y2, refD)
	den.Add(den, big.NewInt(1))
	x2 := refMod(num.Mul(num, new(big.Int).ModInverse(refMod(den), refP)))
	exp := new(big.Int).Add(refP, big.NewInt(3))
	exp.Rsh(exp, 3)
	x := new(big.Int).Exp(x2, exp, refP)
	check := func(c *big.Int) bool {
		sq := new(big.Int).Mul(c, c)
		return refMod(sq.Sub(sq, x2)).Sign() == 0
	}
	if !check(x) {
		x.Mul(x, refSqrtM)
		refMod(x)
		if !check(x) {
			return refPoint{}, false
		}
	}
	if x.Sign() == 0 && sign == 1 {
		return refPoint{}, false
	}
	if x.Bit(0) != sign {
		x.Sub(refP, x)
		refMod(x)
	}
	return refPoint{x, y}, true
}

var refBase = func() refPoint {
	y := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), refP))
	y.Mod(y, refP)
	p, ok := refDecode(refToLittleEndian(y, 32))
	if !ok {
		panic("reference base point does not decode")
	}
	return p
}()

var (
	refTorsionOnce sync.Once
	refTorsion     []refPoint
)

// refTorsionSubgroup derives E[8] by arithmetic: the curve has order 8L, so [L]Q lies in E[8] for
// any point Q; a point whose image has order 8 generates the subgroup.
func refTorsionSubgroup() []refPoint {
	refTorsionOnce.Do(func() {
		for y := int64(2); ; y++ {
			q, ok := refDecode(refToLittleEndian(big.NewInt(y), 32))
			if !ok {
				continue
			}
			t := refMul(refL, q)
			if refIsIdentity(refMul(big.NewInt(4), t)) {
				continue
			}
			pts := make([]refPoint, 8)
			for i := range pts {
				pts[i] = refMul(big.NewInt(int64(i)), t)
			}
			refTorsion = pts
			return
		}
	})
	return refTorsion
}

func refSmallOrderEncodings() [][]byte {
	var out [][]byte
	for _, p := range refTorsionSubgroup() {
		out = append(out, refEncode(p))
	}
	return out
}

func refSecretScalar(seed []byte) *big.Int {
	h := sha512.Sum512(seed)
	a := append([]byte(nil), h[:32]...)
	a[0] &= 248
	a[31] &= 127
	a[31] |= 64
	return refLittleEndian(a)
}

func refPublicKey(seed []byte) []byte { return refEncode(refMul(refSecretScalar(seed), refBase)) }

func refChallenge(rEnc, aEnc, msg []byte) *big.Int {
	h := sha512.New()
	h.Write(rEnc)
	h.Write(aEnc)
	h.Write(msg)
	k := refLittleEndian(h.Sum(nil))
	return k.Mod(k, refL)
}

// refSignFor signs as the holder of seed while binding the challenge to keyEnc, with the nonce
// scalar r (the honest nonce when r is nil).
func refSignFor(seed, keyEnc, msg []byte, r *big.Int) []byte {
	if r == nil {
		h := sha512.New()
		d := sha512.Sum512(seed)
		h.Write(d[32:])
		h.Write(msg)
		r = refLittleEndian(h.Sum(nil))
		r.Mod(r, refL)
	}
	rEnc := refEncode(refMul(r, refBase))
	k := refChallenge(rEnc, keyEnc, msg)
	s := new(big.Int).Mul(k, refSecretScalar(seed))
	s.Add(s, r)
	s.Mod(s, refL)
	return append(rEnc, refToLittleEndian(s, 32)...)
}

// refVerifies is the cofactorless equation [S]B == R + [k]A by this file's arithmetic only.
func refVerifies(sig, keyEnc, msg []byte) bool {
	a, okA := refDecode(keyEnc)
	r, okR := refDecode(sig[:32])
	s := refLittleEndian(sig[32:])
	if !okA || !okR || s.Cmp(refL) >= 0 {
		return false
	}
	k := refChallenge(sig[:32], keyEnc, msg)
	return refEqual(refMul(s, refBase), refAdd(r, refMul(k, a)))
}

// refSignUnderTorsion returns the key A + T (encoded) and a signature that verifies under it,
// found by trying nonces until k annihilates T.
func refSignUnderTorsion(seed []byte, torsion refPoint, msg []byte) ([]byte, []byte) {
	a := refMul(refSecretScalar(seed), refBase)
	keyEnc := refEncode(refAdd(a, torsion))
	for r := int64(1); r < 400; r++ {
		sig := refSignFor(seed, keyEnc, msg, big.NewInt(r))
		if refVerifies(sig, keyEnc, msg) {
			return keyEnc, sig
		}
	}
	panic("no nonce found within 400 tries")
}

// refIdentityRSignature is a key-holder signature with R = identity: S = k * a mod L.
func refIdentityRSignature(seed, msg []byte) []byte {
	rEnc := refEncode(refIdentity())
	k := refChallenge(rEnc, refPublicKey(seed), msg)
	s := new(big.Int).Mul(k, refSecretScalar(seed))
	s.Mod(s, refL)
	return append(rEnc, refToLittleEndian(s, 32)...)
}

// refNoncanonicalAliases are the 40 non-canonical encodings: y in [p, 2^255) with either sign
// bit, plus the two x = 0 sign-bit encodings (y = 1 and y = p - 1).
func refNoncanonicalAliases() [][]byte {
	var out [][]byte
	top := new(big.Int).Lsh(big.NewInt(1), 255)
	for y := new(big.Int).Set(refP); y.Cmp(top) < 0; y.Add(y, big.NewInt(1)) {
		out = append(out, refToLittleEndian(y, 32))
		signed := new(big.Int).SetBit(y, 255, 1)
		out = append(out, refToLittleEndian(signed, 32))
	}
	one := new(big.Int).SetBit(big.NewInt(1), 255, 1)
	pm1 := new(big.Int).SetBit(new(big.Int).Sub(refP, big.NewInt(1)), 255, 1)
	return append(out, refToLittleEndian(one, 32), refToLittleEndian(pm1, 32))
}

// refOffCurve is a canonical encoding whose y has no x.
func refOffCurve() []byte {
	for y := int64(2); ; y++ {
		enc := refToLittleEndian(big.NewInt(y), 32)
		if _, ok := refDecode(enc); !ok {
			return enc
		}
	}
}

// refStrictVerdict is the S1 rule by reference arithmetic only (no table, no backend): strict
// decode of A and R, neither of small order ([8]P != O), S < L, then the equation.
func refStrictVerdict(msg, sig, key []byte) bool {
	if len(key) != 32 || len(sig) != 64 {
		return false
	}
	a, okA := refDecode(key)
	r, okR := refDecode(sig[:32])
	if !okA || !okR {
		return false
	}
	eight := big.NewInt(8)
	if refIsIdentity(refMul(eight, a)) || refIsIdentity(refMul(eight, r)) {
		return false
	}
	return refVerifies(sig, key, msg)
}
