"""RFC 7638 JWK thumbprint for OKP Ed25519 public keys (spec/bap-v1.md § Public verification contract).

The public OKP JWK has exactly three members — ``crv="Ed25519"``, ``kty="OKP"``, ``x=<base64url
raw 32 bytes>`` — in RFC 7638 lexicographic order (crv, kty, x). The thumbprint preimage is the JCS
of that object; the thumbprint is SHA-256 of the preimage (base64url); the raw thumbprint is the
32-byte digest.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds
from .ed25519 import sha256
from .error import Ok, Result, err, fail, require
from .jcs import jcs_encode
from .json_alg import JObject, JString, Tagged, json_decode, str_utf8, utf8_str


@dataclass(frozen=True)
class OkpPublic:
    crv: str  # always "Ed25519"
    kty: str  # always "OKP"
    x: str    # base64url of the 32 raw bytes


def jwk_encode_public(raw_key: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> bytes:
    """Encode a raw 32-byte Ed25519 public key as the canonical OKP JCS JSON bytes."""
    require(len(raw_key) == 32, "jwk.encode_public: public key width must be 32")
    jwk = jwk_from_public_key(raw_key)
    members: dict[str, Tagged] = {
        "crv": JString(str_utf8(jwk.crv)),
        "kty": JString(str_utf8(jwk.kty)),
        "x": JString(str_utf8(jwk.x)),
    }
    return jcs_encode(JObject(members), bounds)


def jwk_decode_public(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    """Decode an OKP public JWK from JSON bytes. Returns ``Ok(raw32)`` or ``Err``."""
    try:
        value = json_decode(data, bounds)
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise
    try:
        if not isinstance(value, JObject):
            fail("jwk.decode_public: not an object")
        obj = value.v
        if len(obj) != 3:
            fail("jwk.decode_public: closed members")
        crv = obj.get("crv")
        kty = obj.get("kty")
        x = obj.get("x")
        if crv is None or kty is None or x is None:
            fail("jwk.decode_public: missing member")
        if not isinstance(crv, JString) or utf8_str(crv.v) != "Ed25519":
            fail("jwk.decode_public: crv")
        if not isinstance(kty, JString) or utf8_str(kty.v) != "OKP":
            fail("jwk.decode_public: kty")
        if not isinstance(x, JString):
            fail("jwk.decode_public: x")
        raw = base64url_decode(x.v)
        if len(raw) != 32:
            fail("jwk.decode_public: x width")
        return Ok(raw)
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def jwk_from_public_key(raw_key: bytes) -> OkpPublic:
    require(len(raw_key) == 32, "jwk: public key width")
    return OkpPublic(
        crv="Ed25519", kty="OKP", x=utf8_str(base64url_encode(raw_key))
    )


def thumbprint_preimage(jwk: OkpPublic) -> bytes:
    """RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x} (lexicographic order)."""
    members: dict[str, Tagged] = {
        "crv": JString(str_utf8(jwk.crv)),
        "kty": JString(str_utf8(jwk.kty)),
        "x": JString(str_utf8(jwk.x)),
    }
    return jcs_encode(JObject(members))


def thumbprint(jwk: OkpPublic) -> str:
    """Thumbprint as base64url SHA-256 of the preimage."""
    return utf8_str(base64url_encode(sha256(thumbprint_preimage(jwk))))


def thumbprint_raw(jwk: OkpPublic) -> bytes:
    """Raw 32-byte thumbprint."""
    return sha256(thumbprint_preimage(jwk))


def public_key_thumbprint_raw(raw_key: bytes) -> bytes:
    """Raw 32-byte thumbprint directly from a raw 32-byte public key."""
    return thumbprint_raw(jwk_from_public_key(raw_key))


def _is_invalid(e: BaseException) -> bool:
    from .error import InvalidError

    return isinstance(e, InvalidError)
