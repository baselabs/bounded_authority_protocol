"""Independent Python implementation of ``bap-content-assertion/1``.

The wire and verification behavior in this module is derived from
``spec/bap-content-assertion-v1.md``. The profile is explicitly selected, pure, and
non-authorizing. Private keys and signer callbacks never enter this package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from .compact import CompactSegments, SigningInput, assemble_segments, parse_compact
from .ed25519 import ed25519_verify, import_public_key, sha256
from .error import Ok, Result, fail
from .facts import ContentAssertionDecoded, ContentAssertionFacts
from .jcs import jcs_encode
from .json_alg import JInt, JObject, JString, Tagged, json_decode, str_utf8, utf8_str
from .jwk import jwk_from_public_key, thumbprint_raw
from .role_attestation import (
    _bytes_equal,
    _closed_shape,
    _is_int,
    _is_string_or_uri,
    _is_well_formed,
    _project_base64url_decoded_size,
    _trying,
)
from .v1 import HistoricalPublicKey

ALG = "EdDSA"
CONTENT_ASSERTION_TYP = "ba+content-assertion"
CONTENT_ASSERTION_PROFILE = "bap-content-assertion/1"
CONTENT_PREFIX = b"BAP1-CONTENT\x00"
VERSION = 1
ZERO_DIGEST = bytes(32)

_KID_CHARSET = re.compile(r"[A-Za-z0-9._~-]+")
_SIGNATURE_BYTES = 64
_SIGNATURE_SEGMENT_BYTES = len(base64url_encode(bytes(_SIGNATURE_BYTES)))
_PAYLOAD_KEYS = {
    "aud",
    "content_digest",
    "exp",
    "gen",
    "iat",
    "iss",
    "jti",
    "nbf",
    "prev",
    "profile",
    "profile_digest",
    "sub",
    "v",
}


@dataclass(frozen=True)
class ContentAssertion:
    attestor_key_id: str
    jti: str
    iss: str
    aud: str
    sub: str
    profile: str
    profile_digest: bytes
    content_digest: bytes
    gen: int
    prev: bytes
    iat: int
    nbf: int
    exp: int


@dataclass(frozen=True)
class ExpectedContentAssertion:
    attestor: HistoricalPublicKey
    issuer: str
    audience: str
    subject: str
    profile: str
    profile_digest: bytes
    content_digest: bytes
    now: int
    bounds: Bounds


def _bounds(value: Bounds | None) -> Bounds:
    return coerce_bounds(value if value is not None else MAXIMUM_BOUNDS)


def _compact_bounds(value: Bounds | None) -> Bounds:
    b = _bounds(value)
    if bounds_resolve(b, "decoded_segment_bytes") < _SIGNATURE_BYTES:
        fail("content assertion: decoded signature bound")
    if bounds_resolve(b, "encoded_segment_bytes") < _SIGNATURE_SEGMENT_BYTES:
        fail("content assertion: encoded signature bound")
    return b


def _kid(value: str, bounds: Bounds) -> str:
    if not _is_well_formed(value):
        fail("content assertion: kid Unicode")
    raw = str_utf8(value)
    if not (1 <= len(raw) <= bounds_resolve(bounds, "kid_bytes")):
        fail("content assertion: kid bytes")
    if _KID_CHARSET.fullmatch(value) is None:
        fail("content assertion: kid charset")
    return value


def _identifier(value: str, bounds: Bounds) -> str:
    if not _is_well_formed(value) or not _is_string_or_uri(value):
        fail("content assertion: StringOrUri")
    raw = str_utf8(value)
    if not (1 <= len(raw) <= bounds_resolve(bounds, "identifier_bytes")):
        fail("content assertion: identifier bytes")
    return value


def _integer(value: object, bounds: Bounds) -> int:
    if not _is_int(value):
        fail("content assertion: integer")
    assert isinstance(value, int)
    if abs(value) > bounds_resolve(bounds, "integer_magnitude"):
        fail("content assertion: integer magnitude")
    return value


def _digest(value: bytes) -> bytes:
    if len(value) != 32:
        fail("content assertion: digest width")
    return value


def _json_digest(value: Tagged | None) -> bytes:
    if not isinstance(value, JString):
        fail("content assertion: digest string")
    raw = base64url_decode(value.v)
    return _digest(raw)


def _json_identifier(value: Tagged | None, bounds: Bounds) -> str:
    if not isinstance(value, JString):
        fail("content assertion: identifier string")
    return _identifier(utf8_str(value.v), bounds)


def _json_integer(value: Tagged | None, bounds: Bounds) -> int:
    if not isinstance(value, JInt):
        fail("content assertion: integer claim")
    return _integer(value.v, bounds)


def _preflight(compact: bytes, bounds: Bounds) -> None:
    if len(compact) > bounds_resolve(bounds, "anchor_bytes"):
        fail("content assertion: anchor_bytes")
    if len(compact) > bounds_resolve(bounds, "compact_bytes"):
        fail("content assertion: compact_bytes")
    segments = compact.split(b".")
    if len(segments) != 3 or any(len(segment) == 0 for segment in segments):
        fail("content assertion: compact shape")
    encoded_limit = bounds_resolve(bounds, "encoded_segment_bytes")
    decoded_limit = bounds_resolve(bounds, "decoded_segment_bytes")
    for segment in segments:
        if len(segment) > encoded_limit:
            fail("content assertion: encoded segment")
        if _project_base64url_decoded_size(len(segment)) > decoded_limit:
            fail("content assertion: decoded segment")


def _header(segments: CompactSegments, bounds: Bounds) -> str:
    value = json_decode(segments.protected_bytes, bounds)
    if not isinstance(value, JObject) or set(value.v) != {"alg", "kid", "typ"}:
        fail("content assertion: header members")
    alg = value.v.get("alg")
    typ = value.v.get("typ")
    kid = value.v.get("kid")
    if not isinstance(alg, JString) or utf8_str(alg.v) != ALG:
        fail("content assertion: alg")
    if not isinstance(typ, JString) or utf8_str(typ.v) != CONTENT_ASSERTION_TYP:
        fail("content assertion: typ")
    if not isinstance(kid, JString):
        fail("content assertion: kid")
    result = _kid(utf8_str(kid.v), bounds)
    if not _bytes_equal(jcs_encode(value, bounds), segments.protected_bytes):
        fail("content assertion: canonical header")
    return result


def _payload(segments: CompactSegments, bounds: Bounds) -> JObject:
    value = json_decode(segments.payload_bytes, bounds)
    if not isinstance(value, JObject) or set(value.v) != _PAYLOAD_KEYS:
        fail("content assertion: payload members")
    version = value.v.get("v")
    if not isinstance(version, JInt) or version.v != VERSION:
        fail("content assertion: version")
    for key in ("jti", "iss", "aud", "sub", "profile"):
        _json_identifier(value.v.get(key), bounds)
    for key in ("profile_digest", "content_digest", "prev"):
        _json_digest(value.v.get(key))
    gen = _json_integer(value.v.get("gen"), bounds)
    iat = _json_integer(value.v.get("iat"), bounds)
    nbf = _json_integer(value.v.get("nbf"), bounds)
    exp = _json_integer(value.v.get("exp"), bounds)
    prev = _json_digest(value.v.get("prev"))
    _structure(gen, prev, iat, nbf, exp, bounds)
    if not _bytes_equal(jcs_encode(value, bounds), segments.payload_bytes):
        fail("content assertion: canonical payload")
    return value


def _structure(gen: int, prev: bytes, iat: int, nbf: int, exp: int, bounds: Bounds) -> None:
    if not (1 <= gen <= bounds_resolve(bounds, "integer_magnitude")):
        fail("content assertion: generation")
    if (gen == 1) != _bytes_equal(prev, ZERO_DIGEST):
        fail("content assertion: genesis")
    if not (iat <= nbf < exp):
        fail("content assertion: time structure")


def _parse(compact: bytes, bounds: Bounds) -> tuple[CompactSegments, str, JObject]:
    _preflight(compact, bounds)
    segments = parse_compact(compact, bounds)
    kid = _header(segments, bounds)
    payload = _payload(segments, bounds)
    return segments, kid, payload


def _projected_compact_bounds(signing: SigningInput, bounds: Bounds) -> None:
    if len(signing.protected_segment) > bounds_resolve(bounds, "encoded_segment_bytes"):
        fail("content assertion: protected segment")
    if len(signing.payload_segment) > bounds_resolve(bounds, "encoded_segment_bytes"):
        fail("content assertion: payload segment")
    decoded_limit = bounds_resolve(bounds, "decoded_segment_bytes")
    if _project_base64url_decoded_size(len(signing.protected_segment)) > decoded_limit:
        fail("content assertion: decoded protected segment")
    if _project_base64url_decoded_size(len(signing.payload_segment)) > decoded_limit:
        fail("content assertion: decoded payload segment")
    projected = (
        len(signing.protected_segment)
        + 1
        + len(signing.payload_segment)
        + 1
        + _SIGNATURE_SEGMENT_BYTES
    )
    if projected > bounds_resolve(bounds, "compact_bytes"):
        fail("content assertion: projected compact")
    if projected > bounds_resolve(bounds, "anchor_bytes"):
        fail("content assertion: projected anchor")


@_closed_shape
def content_digest(content: bytes, bounds: Bounds | None = None) -> Result[bytes]:
    def body() -> bytes:
        b = _bounds(bounds)
        if not (1 <= len(content) <= bounds_resolve(b, "content_bytes")):
            fail("content assertion: content_bytes")
        return sha256(CONTENT_PREFIX, content)

    return _trying(body)


@_closed_shape
def assertion_signing_input(
    assertion: ContentAssertion, bounds: Bounds | None = None
) -> Result[SigningInput]:
    return _trying(lambda: _signing_input(assertion, bounds))


def _signing_input(assertion: ContentAssertion, bounds: Bounds | None) -> SigningInput:
    b = _compact_bounds(bounds)
    kid = _kid(assertion.attestor_key_id, b)
    identifiers = {
        "jti": _identifier(assertion.jti, b),
        "iss": _identifier(assertion.iss, b),
        "aud": _identifier(assertion.aud, b),
        "sub": _identifier(assertion.sub, b),
        "profile": _identifier(assertion.profile, b),
    }
    profile_digest = _digest(assertion.profile_digest)
    asserted_content_digest = _digest(assertion.content_digest)
    prev = _digest(assertion.prev)
    gen = _integer(assertion.gen, b)
    iat = _integer(assertion.iat, b)
    nbf = _integer(assertion.nbf, b)
    exp = _integer(assertion.exp, b)
    _structure(gen, prev, iat, nbf, exp, b)
    header: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "kid": JString(str_utf8(kid)),
        "typ": JString(str_utf8(CONTENT_ASSERTION_TYP)),
    }
    payload: dict[str, Tagged] = {
        "aud": JString(str_utf8(identifiers["aud"])),
        "content_digest": JString(base64url_encode(asserted_content_digest)),
        "exp": JInt(exp),
        "gen": JInt(gen),
        "iat": JInt(iat),
        "iss": JString(str_utf8(identifiers["iss"])),
        "jti": JString(str_utf8(identifiers["jti"])),
        "nbf": JInt(nbf),
        "prev": JString(base64url_encode(prev)),
        "profile": JString(str_utf8(identifiers["profile"])),
        "profile_digest": JString(base64url_encode(profile_digest)),
        "sub": JString(str_utf8(identifiers["sub"])),
        "v": JInt(VERSION),
    }
    signing = SigningInput(
        kind="content_assertion",
        protected_segment=base64url_encode(jcs_encode(JObject(header), b)),
        payload_segment=base64url_encode(jcs_encode(JObject(payload), b)),
    )
    _projected_compact_bounds(signing, b)
    return signing


@_closed_shape
def assemble_content_assertion_compact(
    signing_input: SigningInput, signature: bytes, bounds: Bounds | None = None
) -> Result[bytes]:
    def body() -> bytes:
        b = _compact_bounds(bounds)
        if signing_input.kind != "content_assertion":
            fail("content assertion: signing kind")
        _projected_compact_bounds(signing_input, b)
        assembled = assemble_segments(signing_input, signature)
        if not isinstance(assembled, Ok):
            fail("content assertion: assembly")
        _parse(assembled.value, b)
        return assembled.value

    return _trying(body)


@_closed_shape
def decode_assertion(
    compact: bytes, bounds: Bounds | None = None
) -> Result[ContentAssertionDecoded]:
    def body() -> ContentAssertionDecoded:
        b = _compact_bounds(bounds)
        _segments, kid, payload = _parse(compact, b)
        return ContentAssertionDecoded(
            version=VERSION,
            attestor_key_id=kid,
            jti=_json_identifier(payload.v.get("jti"), b),
            iss=_json_identifier(payload.v.get("iss"), b),
            aud=_json_identifier(payload.v.get("aud"), b),
            sub=_json_identifier(payload.v.get("sub"), b),
            profile=_json_identifier(payload.v.get("profile"), b),
            profile_digest=_json_digest(payload.v.get("profile_digest")),
            content_digest=_json_digest(payload.v.get("content_digest")),
            gen=_json_integer(payload.v.get("gen"), b),
            prev=_json_digest(payload.v.get("prev")),
            iat=_json_integer(payload.v.get("iat"), b),
            nbf=_json_integer(payload.v.get("nbf"), b),
            exp=_json_integer(payload.v.get("exp"), b),
        )

    return _trying(body)


def _expected(expected: ExpectedContentAssertion, bounds: Bounds) -> None:
    attestor = expected.attestor
    _kid(attestor.key_id, bounds)
    if len(attestor.public_key) != 32:
        fail("content assertion: attestor key width")
    valid_from = _integer(attestor.valid_from, bounds)
    if attestor.valid_before is not None:
        valid_before = _integer(attestor.valid_before, bounds)
        if not valid_from < valid_before:
            fail("content assertion: attestor window")
    for value in (expected.issuer, expected.audience, expected.subject, expected.profile):
        _identifier(value, bounds)
    _digest(expected.profile_digest)
    _digest(expected.content_digest)
    _integer(expected.now, bounds)


@_closed_shape
def verify_assertion(
    compact: bytes, expected: ExpectedContentAssertion
) -> Result[ContentAssertionFacts]:
    def body() -> ContentAssertionFacts:
        b = _compact_bounds(expected.bounds)
        _expected(expected, b)
        segments, kid, payload = _parse(compact, b)
        attestor = expected.attestor
        if kid != attestor.key_id:
            fail("content assertion: attestor key id")
        actual_identifiers = (
            _json_identifier(payload.v.get("iss"), b),
            _json_identifier(payload.v.get("aud"), b),
            _json_identifier(payload.v.get("sub"), b),
            _json_identifier(payload.v.get("profile"), b),
        )
        if actual_identifiers != (
            expected.issuer,
            expected.audience,
            expected.subject,
            expected.profile,
        ):
            fail("content assertion: expected identities")
        profile_digest = _json_digest(payload.v.get("profile_digest"))
        asserted_content_digest = _json_digest(payload.v.get("content_digest"))
        if not _bytes_equal(profile_digest, expected.profile_digest):
            fail("content assertion: expected profile digest")
        if not _bytes_equal(asserted_content_digest, expected.content_digest):
            fail("content assertion: expected content digest")
        iat = _json_integer(payload.v.get("iat"), b)
        nbf = _json_integer(payload.v.get("nbf"), b)
        exp = _json_integer(payload.v.get("exp"), b)
        if iat < attestor.valid_from or nbf < attestor.valid_from:
            fail("content assertion: key window start")
        if attestor.valid_before is not None and exp > attestor.valid_before:
            fail("content assertion: key window end")
        if not nbf <= expected.now < exp:
            fail("content assertion: current window")
        fingerprint = thumbprint_raw(jwk_from_public_key(attestor.public_key))
        key = import_public_key(attestor.public_key, utf8_str(base64url_encode(fingerprint)))
        if not ed25519_verify(segments.signing_input, segments.signature, key):
            fail("content assertion: signature")
        return ContentAssertionFacts(
            version=VERSION,
            attestor_key_id=attestor.key_id,
            attestor_key_fingerprint=fingerprint,
            jti=_json_identifier(payload.v.get("jti"), b),
            iss=actual_identifiers[0],
            aud=actual_identifiers[1],
            sub=actual_identifiers[2],
            profile=actual_identifiers[3],
            profile_digest=profile_digest,
            content_digest=asserted_content_digest,
            gen=_json_integer(payload.v.get("gen"), b),
            prev=_json_digest(payload.v.get("prev")),
            iat=iat,
            nbf=nbf,
            exp=exp,
            digest=sha256(compact),
        )

    return _trying(body)


@_closed_shape
def assertion_digest(compact: bytes, bounds: Bounds | None = None) -> Result[bytes]:
    def body() -> bytes:
        b = _compact_bounds(bounds)
        _parse(compact, b)
        return sha256(compact)

    return _trying(body)


def _facts(value: ContentAssertionFacts, bounds: Bounds) -> None:
    if value.version != VERSION:
        fail("content assertion successor: version")
    if value.verification != "signature_and_window" or value.trust != "not_evaluated":
        fail("content assertion successor: markers")
    _kid(value.attestor_key_id, bounds)
    _digest(value.attestor_key_fingerprint)
    for identifier in (value.jti, value.iss, value.aud, value.sub, value.profile):
        _identifier(identifier, bounds)
    _digest(value.profile_digest)
    _digest(value.content_digest)
    _digest(value.prev)
    _digest(value.digest)
    gen = _integer(value.gen, bounds)
    iat = _integer(value.iat, bounds)
    nbf = _integer(value.nbf, bounds)
    exp = _integer(value.exp, bounds)
    _structure(gen, value.prev, iat, nbf, exp, bounds)


@_closed_shape
def verify_successor(
    predecessor: ContentAssertionFacts,
    successor: ContentAssertionFacts,
    bounds: Bounds,
) -> Result[None]:
    def body() -> None:
        b = coerce_bounds(bounds)
        _facts(predecessor, b)
        _facts(successor, b)
        if (
            predecessor.iss,
            predecessor.aud,
            predecessor.sub,
            predecessor.profile,
            predecessor.profile_digest,
        ) != (
            successor.iss,
            successor.aud,
            successor.sub,
            successor.profile,
            successor.profile_digest,
        ):
            fail("content assertion successor: context")
        magnitude = bounds_resolve(b, "integer_magnitude")
        if predecessor.gen >= magnitude or successor.gen != predecessor.gen + 1:
            fail("content assertion successor: generation")
        if not _bytes_equal(successor.prev, predecessor.digest):
            fail("content assertion successor: predecessor")
        if successor.iat < predecessor.iat:
            fail("content assertion successor: time")
        if successor.jti == predecessor.jti:
            fail("content assertion successor: identity")
        return

    return _trying(body)
