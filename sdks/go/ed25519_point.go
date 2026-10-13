package verifier

import "math/big"

// Pure-Go Edwards25519 point arithmetic over math/big, used only by the key checks
// (AcceptablePublicKey, TorsionFree): decode a canonical encoding to a curve point and test
// [L]A = O. It never runs on the per-signature verification path. The standard library keeps its
// edwards25519 implementation internal, and this SDK takes no dependencies, so the few operations
// needed are written out here (RFC 8032 sections 5.1.3 and 5.1.4, extended coordinates, a = -1).

var (
	curveP   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveL   = bigFromDecimal("7237005577332262213973186563042994240857116359379907606001950938285454250989")
	curveD   = bigFromHex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")
	sqrtM1   = bigFromHex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0")
	pPlus3D8 = new(big.Int).Rsh(new(big.Int).Add(curveP, big.NewInt(3)), 3)
	bigOne   = big.NewInt(1)
)

func bigFromDecimal(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("ed25519: bad decimal constant")
	}
	return v
}

func bigFromHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("ed25519: bad hex constant")
	}
	return v
}

// edwardsPoint is an extended-coordinate point (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z.
type edwardsPoint struct{ x, y, z, t *big.Int }

func fieldMod(v *big.Int) *big.Int { return v.Mod(v, curveP) }

// decodeEdwardsPoint is the strict RFC 8032 section 5.1.3 decode: ok is false for a non-canonical
// encoding (y >= p, or x = 0 with the sign bit set) and when no x exists for the y. The key checks
// rely on this strictness for the canonical rule, so it is pinned by tests rather than repeated.
func decodeEdwardsPoint(enc []byte) (edwardsPoint, bool) {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[31-i] = enc[i]
	}
	v := new(big.Int).SetBytes(be)
	sign := v.Bit(255)
	y := new(big.Int).SetBit(v, 255, 0)
	if y.Cmp(curveP) >= 0 {
		return edwardsPoint{}, false
	}
	y2 := new(big.Int).Mul(y, y)
	u := fieldMod(new(big.Int).Sub(y2, bigOne))
	w := fieldMod(new(big.Int).Add(new(big.Int).Mul(curveD, y2), bigOne))
	x2 := fieldMod(new(big.Int).Mul(u, new(big.Int).ModInverse(w, curveP)))
	root := new(big.Int).Exp(x2, pPlus3D8, curveP)
	matches := func(c *big.Int) bool {
		sq := new(big.Int).Mul(c, c)
		return fieldMod(sq.Sub(sq, x2)).Sign() == 0
	}
	if !matches(root) {
		root = fieldMod(root.Mul(root, sqrtM1))
		if !matches(root) {
			return edwardsPoint{}, false
		}
	}
	if root.Sign() == 0 && sign == 1 {
		return edwardsPoint{}, false
	}
	if root.Bit(0) != sign {
		root = fieldMod(root.Sub(curveP, root))
	}
	return edwardsPoint{x: root, y: y, z: big.NewInt(1), t: fieldMod(new(big.Int).Mul(root, y))}, true
}

func (p edwardsPoint) add(q edwardsPoint) edwardsPoint {
	a := fieldMod(new(big.Int).Mul(new(big.Int).Sub(p.y, p.x), new(big.Int).Sub(q.y, q.x)))
	b := fieldMod(new(big.Int).Mul(new(big.Int).Add(p.y, p.x), new(big.Int).Add(q.y, q.x)))
	c := new(big.Int).Mul(p.t, q.t)
	c.Mul(c, curveD).Lsh(c, 1)
	fieldMod(c)
	d := fieldMod(new(big.Int).Lsh(new(big.Int).Mul(p.z, q.z), 1))
	e := new(big.Int).Sub(b, a)
	f := new(big.Int).Sub(d, c)
	g := new(big.Int).Add(d, c)
	h := new(big.Int).Add(b, a)
	return edwardsPoint{
		x: fieldMod(new(big.Int).Mul(e, f)),
		y: fieldMod(new(big.Int).Mul(g, h)),
		z: fieldMod(new(big.Int).Mul(f, g)),
		t: fieldMod(new(big.Int).Mul(e, h)),
	}
}

func (p edwardsPoint) double() edwardsPoint { return p.add(p) }

func identityPoint() edwardsPoint {
	return edwardsPoint{x: big.NewInt(0), y: big.NewInt(1), z: big.NewInt(1), t: big.NewInt(0)}
}

func (p edwardsPoint) isIdentity() bool {
	return fieldMod(new(big.Int).Set(p.x)).Sign() == 0 &&
		fieldMod(new(big.Int).Sub(p.y, p.z)).Sign() == 0
}

// timesGroupOrderIsIdentity reports [L]P = O.
func (p edwardsPoint) timesGroupOrderIsIdentity() bool {
	acc := identityPoint()
	addend := p
	for i := 0; i < curveL.BitLen(); i++ {
		if curveL.Bit(i) == 1 {
			acc = acc.add(addend)
		}
		addend = addend.double()
	}
	return acc.isIdentity()
}
