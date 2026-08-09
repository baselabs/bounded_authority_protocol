"""Ed25519 verification via the ``cryptography`` package (the crypto import boundary the two-boundary
census tracks) + SHA-256 via ``hashlib``.

Per protocol-v1.md § Signing and digest inputs + RFC 8032. The verifier validates the fixed 32-byte
public-key and 64-byte signature encodings, then delegates Ed25519 verification to the backend. A
backend rejection or exception returns exactly Invalid (REQ1-SIGNING-backend-reject).

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
    try:
        key = Ed25519PublicKey.from_public_bytes(raw_key)
    except Exception:
        # Any backend rejection (malformed encoding) is a closed Invalid — not a verdict-bearing
        # agreement. Mirrors the whitelist discipline.
        fail("ed25519: invalid public key")
    _imported_fingerprints.add(fingerprint)
    return key


def ed25519_verify(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise.

    Maps backend exceptions (other than InvalidSignature, which is a normal False) to InvalidError
    (REQ1-SIGNING-backend-reject).
    """
    require(len(signature) == 64, "ed25519: signature must be 64 bytes")
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        fail("ed25519: backend rejected")


def sha256(*parts: bytes) -> bytes:
    """SHA-256 (FIPS 180-4) over the concatenation of parts. Returns the raw 32-byte digest."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()
