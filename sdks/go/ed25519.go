package verifier

import "crypto/ed25519"

// Strict Ed25519 verification (rule S1). This file is the single owner of the Ed25519 point and
// scalar rules for the SDK; every signature check (grant, proof, anchor, transition, role
// attestation, content assertion; contract-majors 1 and 2) goes through verifyEd25519.
//
// S1 accepts a signature R || S over a message under a public key A only if all of these hold,
// checked in this order before any backend call:
//
//  1. the key is exactly 32 bytes and the signature exactly 64 bytes;
//  2. A and R are canonical encodings: the encoded y is below p = 2^255 - 19, and the sign bit is
//     clear whenever x = 0 (RFC 8032 section 5.1.3);
//  3. neither A nor R is one of the eight small-order encodings (one shared table serves both);
//  4. S < L, the prime order of the base point (RFC 8032 section 5.1.7);
//  5. the cofactorless equation encode([S]B - [k]A) == R holds, computed by the standard library
//     backend.
//
// Curve membership of A is left to the backend at verification (it rejects off-curve keys). There
// is no subgroup check at verification: a key with a small torsion component passes S1 if its
// signature satisfies the cofactorless equation. Hosts close that gap once per key with
// TorsionFree. A true result proves only that the bytes satisfy the rule; it never selects trusted
// keys or grants authority.

// smallOrderEncodings are the eight small-order encodings (the points of E[8]) in canonical form.
// One table serves both the key A and the signature's R.
var smallOrderEncodings = [8][32]byte{
	// order 1 (identity)
	hex32("0100000000000000000000000000000000000000000000000000000000000000"),
	// order 2
	hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	// order 4
	hex32("0000000000000000000000000000000000000000000000000000000000000000"),
	hex32("0000000000000000000000000000000000000000000000000000000000000080"),
	// order 8
	hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
}

// groupOrderLE is L = 2^252 + 27742317777372353535851937790883648493, little-endian.
var groupOrderLE = hex32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

func hex32(s string) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = hexNibble(s[2*i])<<4 | hexNibble(s[2*i+1])
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	panic("ed25519: bad hex constant")
}

func isSmallOrder(enc []byte) bool {
	for i := range smallOrderEncodings {
		if string(enc) == string(smallOrderEncodings[i][:]) {
			return true
		}
	}
	return false
}

func allByte(b []byte, v byte) bool {
	for _, c := range b {
		if c != v {
			return false
		}
	}
	return true
}

// canonicalEncoding reports whether a 32-byte point encoding is canonical: y < p, and the sign bit
// is clear on the two x = 0 points (y = 1 and y = p - 1).
func canonicalEncoding(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	// y >= p  <=>  the low 255 bits are 0x7f ff..ff followed by a low byte >= 0xed.
	if b[31]&0x7f == 0x7f && allByte(b[1:31], 0xff) && b[0] >= 0xed {
		return false
	}
	if b[31]&0x80 != 0 {
		if b[0] == 0x01 && allByte(b[1:31], 0x00) && b[31] == 0x80 {
			return false // y = 1, x = 0, sign bit set
		}
		if b[0] == 0xec && allByte(b[1:31], 0xff) && b[31] == 0xff {
			return false // y = p - 1, x = 0, sign bit set
		}
	}
	return true
}

// scalarBelowL reports S < L for a 32-byte little-endian scalar.
func scalarBelowL(s []byte) bool {
	for i := 31; i >= 0; i-- {
		if s[i] != groupOrderLE[i] {
			return s[i] < groupOrderLE[i]
		}
	}
	return false // S == L
}

// strictGate is the byte-level part of rule S1 (clauses 1 to 4), separate from the backend so each
// clause stays testable on its own: a cofactorless backend already refuses a non-canonical R and
// S >= L, so only a direct test of the gate can show those two clauses are present.
func strictGate(signature, publicKey []byte) bool {
	if len(publicKey) != 32 || len(signature) != 64 {
		return false
	}
	r, s := signature[:32], signature[32:]
	return canonicalEncoding(publicKey) &&
		canonicalEncoding(r) &&
		!isSmallOrder(publicKey) &&
		!isSmallOrder(r) &&
		scalarBelowL(s)
}

// verifyEd25519 verifies over the exact received signing input under rule S1. Width gates are the
// immutable suite constants; a backend rejection or exception is exactly ErrInvalid
// (REQ1-SIGNING-backend-reject). Public keys are caller-supplied trusted inputs — never discovered
// here.
func verifyEd25519(publicKey []byte, message, signature []byte) error {
	if !strictGate(signature, publicKey) {
		return ErrInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return ErrInvalid
	}
	return nil
}

// VerifyStrict is the public mirror of rule S1 over raw bytes. It never panics: any input that is
// not a 32-byte key and a 64-byte signature passing the gate and the cofactorless equation returns
// false.
func VerifyStrict(message, signature, publicKey []byte) bool {
	return verifyEd25519(publicKey, message, signature) == nil
}

// AcceptablePublicKey reports whether a raw 32-byte Ed25519 public key may enter a verification
// input: canonical, not one of the eight small-order encodings, and on the curve (the RFC 8032
// section 5.1.3 decoding succeeds). Any other input returns false.
func AcceptablePublicKey(key []byte) bool {
	if len(key) != 32 || isSmallOrder(key) {
		return false
	}
	_, ok := decodeEdwardsPoint(key) // strict: refuses y >= p and x = 0 with the sign bit
	return ok
}

// TorsionFree reports whether a raw 32-byte key is acceptable and torsion free ([L]A = O).
//
// A host calls this at key enrollment, at trust install, and before any deny-list or revocation
// comparison. It runs one full scalar multiplication in pure integer arithmetic, so it never
// belongs on the per-signature verification path. A canonical, torsion-free key has exactly one
// encoding per secret, so key equality is identity equality.
func TorsionFree(key []byte) bool {
	if len(key) != 32 || isSmallOrder(key) {
		return false
	}
	point, ok := decodeEdwardsPoint(key) // strict: refuses y >= p and x = 0 with the sign bit
	return ok && point.timesGroupOrderIsIdentity()
}
