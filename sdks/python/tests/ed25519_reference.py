"""Test-only Ed25519 reference arithmetic (affine Edwards coordinates, Python integers).

This module exists so the strict-Ed25519 tests can derive their expectations by curve arithmetic
instead of copying the SDK's own small-order table (finding 12), and can build the key-holder
constructions (mixed-order keys, identity-R signatures) that no honest signer emits. It is
deliberately a different formulation from ``bounded_authority_verifier.ed25519`` (affine points with
modular inverses, versus extended coordinates there), so the two do not share a defect. It is never
imported by ``src/``.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int]
IDENTITY: Point = (0, 1)


def add(p: Point, q: Point) -> Point:
    """Complete twisted-Edwards addition for a = -1 (RFC 8032 section 5.1.4, affine form)."""
    x1, y1 = p
    x2, y2 = q
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P
    return (x3, y3)


def neg(p: Point) -> Point:
    return ((-p[0]) % P, p[1])


def mul(k: int, p: Point) -> Point:
    acc = IDENTITY
    addend = p
    while k > 0:
        if k & 1:
            acc = add(acc, addend)
        addend = add(addend, addend)
        k >>= 1
    return acc


def encode(p: Point) -> bytes:
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode(enc: bytes) -> Point | None:
    """Strict RFC 8032 section 5.1.3 decode; ``None`` for a non-canonical or off-curve encoding."""
    if len(enc) != 32:
        return None
    v = int.from_bytes(enc, "little")
    sign = v >> 255
    y = v & ((1 << 255) - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = (-x) % P
    return (x, y)


BASE: Point = decode((4 * pow(5, -1, P) % P).to_bytes(32, "little")) or IDENTITY


def torsion_subgroup() -> list[Point]:
    """The eight points of E[8], derived by arithmetic: [L]Q for a point Q of order 8 times L.

    The curve has order 8L, so [L]Q lies in E[8]; a point whose image has order 8 generates it.
    """
    y = 2
    while True:
        enc = y.to_bytes(32, "little")
        q = decode(enc)
        y += 1
        if q is None:
            continue
        t = mul(L, q)
        if mul(4, t) != IDENTITY:
            return [mul(i, t) for i in range(8)]


def small_order_encodings() -> list[bytes]:
    return [encode(t) for t in torsion_subgroup()]


def order_8_point() -> Point:
    return torsion_subgroup()[1]


def secret_scalar(seed: bytes) -> int:
    """RFC 8032 section 5.1.5: the clamped scalar ``a`` of a 32-byte seed."""
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(h, "little")


def prefix(seed: bytes) -> bytes:
    return hashlib.sha512(seed).digest()[32:]


def challenge(r_enc: bytes, a_enc: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r_enc + a_enc + message).digest(), "little") % L


def public_key(seed: bytes) -> bytes:
    return encode(mul(secret_scalar(seed), BASE))


def sign_for_encoded_key(
    seed: bytes, key_encoding: bytes, message: bytes, r_scalar: int | None = None
) -> bytes:
    """Sign as the holder of ``seed`` while binding the challenge to ``key_encoding``.

    With ``key_encoding`` equal to the honest public key this is plain Ed25519. With a torsion
    variant ``A + T`` the signature verifies only when ``k`` annihilates ``T`` (k = 0 mod 8), so
    callers loop over ``r_scalar`` until the cofactorless equation holds (``verifies``).
    """
    a = secret_scalar(seed)
    r = r_scalar if r_scalar is not None else int.from_bytes(
        hashlib.sha512(prefix(seed) + message).digest(), "little"
    ) % L
    r_enc = encode(mul(r, BASE))
    k = challenge(r_enc, key_encoding, message)
    s = (r + k * a) % L
    return r_enc + s.to_bytes(32, "little")


def verifies(signature: bytes, key_encoding: bytes, message: bytes) -> bool:
    """The cofactorless equation encode([S]B - [k]A) == R, by this module's arithmetic only."""
    a = decode(key_encoding)
    r_pt = decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r_pt is None or s >= L:
        return False
    k = challenge(signature[:32], key_encoding, message)
    lhs = mul(s, BASE)
    rhs = add(r_pt, mul(k, a))
    return lhs == rhs


def sign_under_torsion_variant(seed: bytes, torsion: Point, message: bytes) -> tuple[bytes, bytes]:
    """Return (key_encoding, signature) for the key A + T, found by trying nonces until k = 0 mod 8."""
    a_pt = mul(secret_scalar(seed), BASE)
    key_enc = encode(add(a_pt, torsion))
    for r in range(1, 400):
        sig = sign_for_encoded_key(seed, key_enc, message, r_scalar=r)
        if verifies(sig, key_enc, message):
            return key_enc, sig
    raise AssertionError("no nonce found within 400 tries")  # pragma: no cover


def identity_r_signature(seed: bytes, message: bytes) -> bytes:
    """A key-holder signature with R = identity: S = k * a mod L (honest key, small-order R)."""
    a = secret_scalar(seed)
    r_enc = encode(IDENTITY)
    k = challenge(r_enc, public_key(seed), message)
    return r_enc + ((k * a) % L).to_bytes(32, "little")


def noncanonical_aliases() -> list[bytes]:
    """The 40 non-canonical encodings: y in [p, 2^255) with either sign bit, plus the two x = 0
    sign-bit encodings (y = 1 and y = p - 1)."""
    out = []
    for y in range(P, 1 << 255):
        out.append(y.to_bytes(32, "little"))
        out.append((y | (1 << 255)).to_bytes(32, "little"))
    out.append((1 | (1 << 255)).to_bytes(32, "little"))
    out.append(((P - 1) | (1 << 255)).to_bytes(32, "little"))
    return out


def off_curve_encoding() -> bytes:
    """A canonical encoding whose y has no x (not on the curve)."""
    y = 2
    while True:
        enc = y.to_bytes(32, "little")
        if decode(enc) is None:
            return enc
        y += 1
