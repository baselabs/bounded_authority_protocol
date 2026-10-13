"""Strict Ed25519 verification (rule S1) via the ``cryptography`` package (the crypto import boundary
the two-boundary census tracks) + SHA-256 via ``hashlib``.

Per spec/bap-v1.md § Signing and digest inputs + RFC 8032. This module is the single owner of the
Ed25519 point and scalar rules for the SDK. ``verify_strict`` accepts a signature ``R || S`` over a
message under a public key ``A`` only if all of these hold, checked in this order before any backend
call:

1. the key is exactly 32 bytes and the signature exactly 64 bytes;
2. ``A`` and ``R`` are canonical encodings: the encoded ``y`` is below ``p = 2^255 - 19``, and the sign
   bit is clear whenever ``x = 0`` (RFC 8032 section 5.1.3);
3. neither ``A`` nor ``R`` is one of the eight small-order encodings (one shared table serves both);
4. ``S < L``, the prime order of the base point (RFC 8032 section 5.1.7);
5. the cofactorless equation ``encode([S]B - [k]A) == R`` holds, computed by the backend.

Curve membership of ``A`` is left to the backend at verification (it rejects off-curve keys). There is
no subgroup check at verification: a key with a small torsion component passes S1 if its signature
satisfies the cofactorless equation. Hosts close that gap once per key with ``torsion_free``.

``acceptable_public_key`` is the check for a key entering any verification input: canonical, not
small-order, and on the curve. ``torsion_free`` additionally requires ``[L]A = O``; it costs one full
scalar multiplication and never runs on the verification path. A ``True`` result proves only that the
bytes satisfy the rule; it never selects trusted keys or grants authority.

A backend rejection or exception returns exactly Invalid (REQ1-SIGNING-backend-reject).

Purity note: ``hashlib`` and ``cryptography`` primitives are pure transformations (no I/O, clock,
RNG, or network) — the purity gate's ban list targets ``datetime.now``/``time.time``/``random.*``/
``open``/``socket``/``subprocess``/``os.environ``/``urllib.request``/``http.client``, none of which
appear here.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .error import fail, require

# --- rule S1 constants ---------------------------------------------------------------------------
# The field prime p = 2^255 - 19, the base-point order L, the curve constant d = -121665/121666 mod p,
# and sqrt(-1) = 2^((p - 1) / 4) mod p (RFC 8032 section 5.1).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
_SQRT_M1 = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0
_Y_MASK = (1 << 255) - 1
_SIGN_BIT = 1 << 255

# The eight small-order encodings (the points of E[8]) in canonical form. One table serves both the
# key A and the signature's R.
_SMALL_ORDER: frozenset[bytes] = frozenset(
    bytes.fromhex(h)
    for h in (
        # order 1 (identity)
        "0100000000000000000000000000000000000000000000000000000000000000",
        # order 2
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # order 4
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        # order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
)

_Extended = tuple[int, int, int, int]


def _is_bytes(value: object) -> bool:
    return isinstance(value, (bytes, bytearray))


def _canonical(encoding: bytes) -> bool:
    """Canonical: y < p, and the sign bit is clear on the two x = 0 points (y = 1 and y = p - 1)."""
    v = int.from_bytes(encoding, "little")
    y = v & _Y_MASK
    return y < _P and (v < _SIGN_BIT or y not in (1, _P - 1))


def strict_gate(signature: bytes, public_key: bytes) -> bool:
    """The byte-level part of rule S1 (clauses 1 to 4), separate from the backend so each clause stays
    testable on its own: a cofactorless backend already refuses a non-canonical R and S >= L, so only a
    direct test of the gate can show those two clauses are present."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    r = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    return (
        _canonical(public_key)
        and _canonical(r)
        and public_key not in _SMALL_ORDER
        and r not in _SMALL_ORDER
        and s < _L
    )


def _decode_point(encoding: bytes) -> _Extended | None:
    """RFC 8032 section 5.1.3 decoding of a canonical encoding; ``None`` when no x exists."""
    v = int.from_bytes(encoding, "little")
    y = v & _Y_MASK
    u = (y * y - 1) % _P
    w = (_D * y * y + 1) % _P
    x = (u * pow(w, _P - 2, _P)) % _P  # x^2 candidate = u / w
    root = pow(x, (_P + 3) // 8, _P)
    if (root * root - x) % _P != 0:
        root = (root * _SQRT_M1) % _P
        if (root * root - x) % _P != 0:
            return None
    if root == 0 and v >= _SIGN_BIT:
        return None
    if (root & 1) != (v >> 255):
        root = (-root) % _P
    return (root, y, 1, (root * y) % _P)


def _add(p: _Extended, q: _Extended) -> _Extended:
    """Extended twisted Edwards addition, a = -1 (RFC 8032 section 5.1.4)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    lhs = ((y1 - x1) * (y2 - x2)) % _P
    rhs = ((y1 + x1) * (y2 + x2)) % _P
    cross = (2 * _D * t1 * t2) % _P
    zz = (2 * z1 * z2) % _P
    e, f, g, h = rhs - lhs, zz - cross, zz + cross, rhs + lhs
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _multiply(scalar: int, point: _Extended) -> _Extended:
    acc: _Extended = (0, 1, 1, 0)
    addend = point
    while scalar > 0:
        if scalar & 1:
            acc = _add(acc, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return acc


def _is_identity(point: _Extended) -> bool:
    x, y, z, _t = point
    return x % _P == 0 and (y - z) % _P == 0


def acceptable_public_key(raw_key: bytes) -> bool:
    """Whether a raw 32-byte Ed25519 public key may enter a verification input: canonical, not one of
    the eight small-order encodings, and on the curve. Any other input returns ``False``."""
    if not _is_bytes(raw_key) or len(raw_key) != 32:
        return False
    key = bytes(raw_key)
    return _canonical(key) and key not in _SMALL_ORDER and _decode_point(key) is not None


def torsion_free(raw_key: bytes) -> bool:
    """Whether a raw 32-byte key is acceptable and torsion free (``[L]A = O``).

    A host calls this at key enrollment, at trust install, and before any deny-list or revocation
    comparison. It runs one full scalar multiplication, so it never belongs on the per-signature
    verification path. A canonical, torsion-free key has exactly one encoding per secret."""
    if not acceptable_public_key(raw_key):
        return False
    point = _decode_point(bytes(raw_key))
    return point is not None and _is_identity(_multiply(_L, point))

# Census tracking: every key imported via import_public_key is recorded here, so the conformance
# runner can assert discovery == verify-import == index public_key_fingerprints (both directions).
_imported_fingerprints: set[str] = set()


def imported_fingerprints() -> frozenset[str]:
    return frozenset(_imported_fingerprints)


def reset_census() -> None:
    _imported_fingerprints.clear()


def import_public_key(raw_key: bytes, fingerprint: str) -> Ed25519PublicKey:
    """Import a raw 32-byte Ed25519 public key, recording the fingerprint for the census.

    Throws InvalidError on a malformed key. Mirrors the TS ``createPublicKey`` boundary.
    """
    require(len(raw_key) == 32, "ed25519: public key must be 32 bytes")
    require(acceptable_public_key(raw_key), "ed25519: public key not acceptable")
    try:
        key = Ed25519PublicKey.from_public_bytes(raw_key)
    except Exception:
        # Any backend rejection (malformed encoding) is a closed Invalid — not a verdict-bearing
        # agreement. Mirrors the whitelist discipline.
        fail("ed25519: invalid public key")
    _imported_fingerprints.add(fingerprint)
    return key


def ed25519_verify(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature under rule S1. Returns True if valid, False otherwise.

    This is the SDK's single verify choke point: every grant, proof, anchor, transition, role
    attestation and content assertion signature goes through it. The byte-level gate runs before the
    backend. Maps backend exceptions (other than InvalidSignature, which is a normal False) to
    InvalidError (REQ1-SIGNING-backend-reject).
    """
    require(len(signature) == 64, "ed25519: signature must be 64 bytes")
    raw_key = public_key.public_bytes_raw()
    if not strict_gate(signature, raw_key):
        return False
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        fail("ed25519: backend rejected")


def verify_strict(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Public mirror of rule S1 over raw bytes. Never raises: any input that is not a 32-byte key and a
    64-byte signature passing the gate and the cofactorless equation returns ``False``."""
    if not (_is_bytes(message) and _is_bytes(signature) and _is_bytes(public_key)):
        return False
    if not strict_gate(bytes(signature), bytes(public_key)):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes(public_key))
        return ed25519_verify(bytes(message), bytes(signature), key)
    except Exception:
        return False


def sha256(*parts: bytes) -> bytes:
    """SHA-256 (FIPS 180-4) over the concatenation of parts. Returns the raw 32-byte digest."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()
