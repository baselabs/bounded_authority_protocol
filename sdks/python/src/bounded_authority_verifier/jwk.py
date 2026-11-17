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
from .error import InvalidError, Ok, Result, _fail, _require, _unwrap, err
from .jcs import jcs_encode
from .json_alg import JObject, JString, Tagged, json_decode, str_utf8, utf8_str


@dataclass(frozen=True)
class OkpPublic:
    crv: str  # always "Ed25519"
    kty: str  # always "OKP"
    x: str    # base64url of the 32 raw bytes


def jwk_encode_public(raw_key: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    """Encode a raw 32-byte Ed25519 public key as the canonical OKP JCS JSON bytes."""
    try:
        _require(len(raw_key) == 32, "jwk.encode_public: public key width must be 32")
        jwk = _unwrap(jwk_from_public_key(raw_key))
        members: dict[str, Tagged] = {
            "crv": JString(_unwrap(str_utf8(jwk.crv))),
            "kty": JString(_unwrap(str_utf8(jwk.kty))),
            "x": JString(_unwrap(str_utf8(jwk.x))),
        }
        return Ok(_unwrap(jcs_encode(JObject(members), bounds)))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def jwk_decode_public(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    """Decode an OKP public JWK from JSON bytes. Returns ``Ok(raw32)`` or ``Err``."""
    try:
        value = _unwrap(json_decode(data, bounds))
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise
    try:
        if not isinstance(value, JObject):
            _fail("jwk.decode_public: not an object")
        obj = value.v
        if len(obj) != 3:
            _fail("jwk.decode_public: closed members")
        crv = obj.get("crv")
        kty = obj.get("kty")
        x = obj.get("x")
        if crv is None or kty is None or x is None:
            _fail("jwk.decode_public: missing member")
        if not isinstance(crv, JString) or _unwrap(utf8_str(crv.v)) != "Ed25519":
            _fail("jwk.decode_public: crv")
        if not isinstance(kty, JString) or _unwrap(utf8_str(kty.v)) != "OKP":
            _fail("jwk.decode_public: kty")
        if not isinstance(x, JString):
            _fail("jwk.decode_public: x")
        raw = _unwrap(base64url_decode(x.v))
        if len(raw) != 32:
            _fail("jwk.decode_public: x width")
        if not _unwrap(acceptable_public_key(raw)):
            _fail("jwk.decode_public: key not acceptable")
        return Ok(raw)
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def jwk_from_public_key(raw_key: bytes) -> Result[OkpPublic]:
    try:
        _require(len(raw_key) == 32, "jwk: public key width")
        _require(_unwrap(acceptable_public_key(raw_key)), "jwk: key not acceptable")
        return Ok(OkpPublic(
            crv="Ed25519", kty="OKP", x=_unwrap(utf8_str(_unwrap(base64url_encode(raw_key))))
        ))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def thumbprint_preimage(jwk: OkpPublic) -> Result[bytes]:
    """RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x} (lexicographic order).

    Fallible: an ``x`` that does not decode to an acceptable key is the closed invalid value."""
    try:
        _require(_unwrap(acceptable_public_key(_unwrap(base64url_decode(_unwrap(str_utf8(jwk.x)))))), "jwk: key not acceptable")
        return Ok(_thumbprint_preimage_unchecked(jwk))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def _thumbprint_preimage_unchecked(jwk: OkpPublic) -> bytes:
    members: dict[str, Tagged] = {
        "crv": JString(_unwrap(str_utf8(jwk.crv))),
        "kty": JString(_unwrap(str_utf8(jwk.kty))),
        "x": JString(_unwrap(str_utf8(jwk.x))),
    }
    return _unwrap(jcs_encode(JObject(members)))


def thumbprint(jwk: OkpPublic) -> Result[str]:
    """Thumbprint as base64url SHA-256 of the preimage."""
    try:
        return Ok(_unwrap(utf8_str(_unwrap(base64url_encode(_unwrap(sha256(_unwrap(thumbprint_preimage(jwk)))))))))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def thumbprint_raw(jwk: OkpPublic) -> Result[bytes]:
    """Raw 32-byte thumbprint."""
    try:
        return Ok(_unwrap(sha256(_unwrap(thumbprint_preimage(jwk)))))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def public_key_thumbprint_raw(raw_key: bytes) -> Result[bytes]:
    """Raw 32-byte thumbprint directly from a raw 32-byte public key."""
    try:
        return Ok(_unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(raw_key)))))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def thumbprint_digest_unchecked(raw_key: bytes) -> Result[bytes]:
    """Raw 32-byte thumbprint of a 32-byte key with NO key acceptance: a pure hash.

    For censuses and corpus generators only (it must hash weak keys too). Never call it on a verify
    or key-import path; ``public_key_thumbprint_raw`` is the checked form."""
    try:
        _require(len(raw_key) == 32, "jwk: public key width")
        jwk = OkpPublic(crv="Ed25519", kty="OKP", x=_unwrap(utf8_str(_unwrap(base64url_encode(raw_key)))))
        return Ok(_unwrap(sha256(_thumbprint_preimage_unchecked(jwk))))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def _is_invalid(e: BaseException) -> bool:
    from .error import InvalidError

    return isinstance(e, InvalidError)
