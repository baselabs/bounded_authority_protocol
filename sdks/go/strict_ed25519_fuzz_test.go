package verifier

import (
	"crypto/ed25519"
	"math/big"
	"testing"
)

// refGate is the byte-level part of rule S1 (clauses 1 to 4) written against the arithmetic
// reference: canonical by big-integer comparison, small-order by the arithmetic-derived E[8] set,
// S < L by big-integer comparison. It shares no code with strictGate.
func refGate(sig, key []byte, small map[string]bool) bool {
	if len(key) != 32 || len(sig) != 64 {
		return false
	}
	canonical := func(enc []byte) bool {
		v := refLittleEndian(enc)
		sign := v.Bit(255)
		y := new(big.Int).SetBit(v, 255, 0)
		if y.Cmp(refP) >= 0 {
			return false
		}
		pm1 := new(big.Int).Sub(refP, big.NewInt(1))
		if sign == 1 && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(pm1) == 0) {
			return false
		}
		return true
	}
	return canonical(key) && canonical(sig[:32]) &&
		!small[string(key)] && !small[string(sig[:32])] &&
		refLittleEndian(sig[32:]).Cmp(refL) < 0
}

// FuzzEd25519Gate checks the byte-level gate against the arithmetic reference on arbitrary
// (signature, key) pairs. The seed corpus covers every clause boundary, so a plain `go test` run
// exercises each of them; `go test -fuzz=FuzzEd25519Gate` explores beyond.
func FuzzEd25519Gate(f *testing.F) {
	small := map[string]bool{}
	for _, e := range refSmallOrderEncodings() {
		small[string(e)] = true
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	honest := ed25519.Sign(priv, []byte("fuzz seed"))
	f.Add(honest, []byte(pub))
	for _, e := range refSmallOrderEncodings() {
		f.Add(honest, e)
		f.Add(append(append([]byte(nil), e...), honest[32:]...), []byte(pub))
	}
	for _, e := range refNoncanonicalAliases() {
		f.Add(honest, e)
		f.Add(append(append([]byte(nil), e...), honest[32:]...), []byte(pub))
	}
	for _, s := range []*big.Int{refL, new(big.Int).Sub(refL, big.NewInt(1)), new(big.Int).Add(refL, big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), big.NewInt(0)} {
		f.Add(withS(honest, s), []byte(pub))
	}
	f.Add([]byte{}, []byte{})
	f.Add(honest[:63], []byte(pub))
	f.Add(honest, []byte(pub)[:31])
	f.Fuzz(func(t *testing.T, sig, key []byte) {
		if got, want := strictGate(sig, key), refGate(sig, key, small); got != want {
			t.Fatalf("strictGate=%v reference=%v for key %x sig %x", got, want, key, sig)
		}
		// The public verify can accept only what the gate accepts.
		if VerifyStrict([]byte("fuzz seed"), sig, key) && !strictGate(sig, key) {
			t.Fatalf("VerifyStrict accepted past the gate: key %x sig %x", key, sig)
		}
	})
}
