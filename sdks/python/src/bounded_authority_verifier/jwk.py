"""RFC 7638 JWK thumbprint for OKP Ed25519 public keys (spec/bap-v1.md § Public verification contract).

The public OKP JWK has exactly three members — ``crv="Ed25519"``, ``kty="OKP"``, ``x=<base64url
raw 32 bytes>`` — in RFC 7638 lexicographic order (crv, kty, x). The thumbprint preimage is the JCS
of that object; the thumbprint is SHA-256 of the preimage (base64url); the raw thumbprint is the
32-byte digest.

Key acceptance (rule S1): every function here that takes or yields a key
(JWK encode and decode, ``jwk_from_public_key``, ``public_key_thumbprint_raw``, ``thumbprint``,
``thumbprint_raw``, ``thumbprint_preimage``) returns the closed invalid value for a key that fails
``acceptable_public_key``. ``thumbprint_digest_unchecked`` is the one raw hash-only path: it exists for
censuses and corpus generators, is never called from ``src/`` (a test pins that), and must not be used
on any verify or key-import path.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds
from .ed25519 import acceptable_public_key, sha256
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
        if not acceptable_public_key(raw):
            fail("jwk.decode_public: key not acceptable")
        return Ok(raw)
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def jwk_from_public_key(raw_key: bytes) -> OkpPublic:
    require(len(raw_key) == 32, "jwk: public key width")
    require(acceptable_public_key(raw_key), "jwk: key not acceptable")
    return OkpPublic(
        crv="Ed25519", kty="OKP", x=utf8_str(base64url_encode(raw_key))
    )


def thumbprint_preimage(jwk: OkpPublic) -> bytes:
    """RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x} (lexicographic order).

    Fallible: an ``x`` that does not decode to an acceptable key is the closed invalid value."""
    require(acceptable_public_key(base64url_decode(str_utf8(jwk.x))), "jwk: key not acceptable")
    return _thumbprint_preimage_unchecked(jwk)


def _thumbprint_preimage_unchecked(jwk: OkpPublic) -> bytes:
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


def thumbprint_digest_unchecked(raw_key: bytes) -> bytes:
    """Raw 32-byte thumbprint of a 32-byte key with NO key acceptance: a pure hash.

    For censuses and corpus generators only (it must hash weak keys too). Never call it on a verify
    or key-import path; ``public_key_thumbprint_raw`` is the checked form."""
    require(len(raw_key) == 32, "jwk: public key width")
    jwk = OkpPublic(crv="Ed25519", kty="OKP", x=utf8_str(base64url_encode(raw_key)))
    return sha256(_thumbprint_preimage_unchecked(jwk))


def _is_invalid(e: BaseException) -> bool:
    from .error import InvalidError

    return isinstance(e, InvalidError)
