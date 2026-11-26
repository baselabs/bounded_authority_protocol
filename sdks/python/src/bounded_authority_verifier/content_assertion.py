"""Independent Python implementation of ``bap-content-assertion/1``.

The wire and verification behavior in this module is derived from
``spec/bap-content-assertion-v1.md``. The profile is explicitly selected, pure, and
non-authorizing. Private keys and signer callbacks never enter this package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hmac import compare_digest as _bytes_equal

from cryptography.exceptions import InternalError, UnsupportedAlgorithm

from . import v3
from ._inputs import _buffer, _buffer_size, _bytes, _normalize_arg, _text
from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from .compact import (
    CompactSegments,
    SigningInput,
    _parse_compact,
    assemble_segments,
    assemble_segments_es256,
)
from .ed25519 import _ed25519_verify, _import_public_key, sha256
from .error import Result, _fail, _unwrap
from .facts import (
    ContentAssertionDecoded,
    ContentAssertionFacts,
    Es256ContentAssertionDecoded,
    Es256ContentAssertionFacts,
)
from .jcs import jcs_encode
from .json_alg import JInt, JObject, JString, Tagged, json_decode, str_utf8, utf8_str
from .jwk import jwk_from_public_key, thumbprint_raw
from .role_attestation import (
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
_SIGNATURE_SEGMENT_BYTES = len(_unwrap(base64url_encode(bytes(_SIGNATURE_BYTES))))
_PAYLOAD_KEYS = frozenset({
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
})


@dataclass(frozen=True)
class ContentAssertion:
    """Unsigned content-lineage claims with domain-separated content and predecessor digests.

    Fields:
        attestor_key_id: str.
        jti: str.
        iss: str.
        aud: str.
        sub: str.
        profile: str.
        profile_digest: bytes.
        content_digest: bytes.
        gen: int.
        prev: bytes.
        iat: int.
        nbf: int.
        exp: int.
    """
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
    """Caller-trusted attestor and exact expected subject, profile, content and time.

    Fields:
        attestor: HistoricalPublicKey.
        issuer: str.
        audience: str.
        subject: str.
        profile: str.
        profile_digest: bytes.
        content_digest: bytes.
        now: int.
        bounds: Bounds.
    """
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
    return _unwrap(coerce_bounds(value if value is not None else MAXIMUM_BOUNDS))


def _compact_bounds(value: Bounds | None) -> Bounds:
    b = _bounds(value)
    if _unwrap(bounds_resolve(b, "decoded_segment_bytes")) < _SIGNATURE_BYTES:
        _fail("content assertion: decoded signature bound")
    if _unwrap(bounds_resolve(b, "encoded_segment_bytes")) < _SIGNATURE_SEGMENT_BYTES:
        _fail("content assertion: encoded signature bound")
    return b


def _kid(value: str, bounds: Bounds) -> str:
    if not _is_well_formed(value):
        _fail("content assertion: kid Unicode")
    raw = _unwrap(str_utf8(value))
    if not (1 <= len(raw) <= _unwrap(bounds_resolve(bounds, "kid_bytes"))):
        _fail("content assertion: kid bytes")
    if _KID_CHARSET.fullmatch(value) is None:
        _fail("content assertion: kid charset")
    return value


def _identifier(value: str, bounds: Bounds) -> str:
    if not _is_well_formed(value) or not _is_string_or_uri(value):
        _fail("content assertion: StringOrUri")
    raw = _unwrap(str_utf8(value))
    if not (1 <= len(raw) <= _unwrap(bounds_resolve(bounds, "identifier_bytes"))):
        _fail("content assertion: identifier bytes")
    return value


def _integer(value: object, bounds: Bounds) -> int:
    if not _is_int(value):
        _fail("content assertion: integer")
    assert isinstance(value, int)
    if abs(value) > _unwrap(bounds_resolve(bounds, "integer_magnitude")):
        _fail("content assertion: integer magnitude")
    return value


def _digest(value: bytes) -> bytes:
    if len(value) != 32:
        _fail("content assertion: digest width")
    return value


def _json_digest(value: Tagged | None) -> bytes:
    if not isinstance(value, JString):
        _fail("content assertion: digest string")
    raw = _unwrap(base64url_decode(value.v))
    return _digest(raw)


def _json_identifier(value: Tagged | None, bounds: Bounds) -> str:
    if not isinstance(value, JString):
        _fail("content assertion: identifier string")
    return _identifier(_unwrap(utf8_str(value.v)), bounds)


def _json_integer(value: Tagged | None, bounds: Bounds) -> int:
    if not isinstance(value, JInt):
        _fail("content assertion: integer claim")
    return _integer(value.v, bounds)


def _preflight(compact: bytes, bounds: Bounds) -> None:
    if len(compact) > _unwrap(bounds_resolve(bounds, "anchor_bytes")):
        _fail("content assertion: anchor_bytes")
    if len(compact) > _unwrap(bounds_resolve(bounds, "compact_bytes")):
        _fail("content assertion: compact_bytes")
    segments = compact.split(b".")
    if len(segments) != 3 or any(len(segment) == 0 for segment in segments):
        _fail("content assertion: compact shape")
    encoded_limit = _unwrap(bounds_resolve(bounds, "encoded_segment_bytes"))
    decoded_limit = _unwrap(bounds_resolve(bounds, "decoded_segment_bytes"))
    for segment in segments:
        if len(segment) > encoded_limit:
            _fail("content assertion: encoded segment")
        if _project_base64url_decoded_size(len(segment)) > decoded_limit:
            _fail("content assertion: decoded segment")


@dataclass(frozen=True)
class _Suite:
    alg: bytes
    typ: bytes
    kind: str


_EDDSA = _Suite(ALG.encode("ascii"), CONTENT_ASSERTION_TYP.encode("ascii"), "content_assertion")
_ES256 = _Suite(b"ES256", b"ba+content-assertion-es256", "content_assertion_es256")


@dataclass(frozen=True, repr=False)
class _Header:
    alg: bytes
    typ: bytes
    kid: str


def _framing(compact: bytes, bounds: Bounds) -> tuple[CompactSegments, _Header]:
    _preflight(compact, bounds)
    segments = _parse_compact(compact, bounds)
    return segments, _header(segments, bounds)


def _header(segments: CompactSegments, bounds: Bounds) -> _Header:
    value = _unwrap(json_decode(segments.protected_bytes, bounds))
    if not isinstance(value, JObject) or set(value.v) != {"alg", "kid", "typ"}:
        _fail("content assertion: header members")
    alg = value.v.get("alg")
    typ = value.v.get("typ")
    kid = value.v.get("kid")
    if not isinstance(alg, JString):
        _fail("content assertion: alg")
    if not isinstance(typ, JString):
        _fail("content assertion: typ")
    if not isinstance(kid, JString):
        _fail("content assertion: kid")
    result = _kid(_unwrap(utf8_str(kid.v)), bounds)
    if not _bytes_equal(_unwrap(jcs_encode(value, bounds)), segments.protected_bytes):
        _fail("content assertion: canonical header")
    return _Header(alg.v, typ.v, result)


def _suite_matches(header: _Header, suite: _Suite) -> bool:
    return (header.alg, header.typ) == (suite.alg, suite.typ)


def _payload(
    segments: CompactSegments, kid: str, bounds: Bounds, suite: _Suite
) -> ContentAssertionDecoded:
    value = _unwrap(json_decode(segments.payload_bytes, bounds))
    if not isinstance(value, JObject) or set(value.v) != _PAYLOAD_KEYS:
        _fail("content assertion: payload members")
    version = value.v.get("v")
    if not isinstance(version, JInt) or version.v != VERSION:
        _fail("content assertion: version")
    decoded_type = Es256ContentAssertionDecoded if suite is _ES256 else ContentAssertionDecoded
    claims = decoded_type(
        version=VERSION,
        attestor_key_id=kid,
        jti=_json_identifier(value.v.get("jti"), bounds),
        iss=_json_identifier(value.v.get("iss"), bounds),
        aud=_json_identifier(value.v.get("aud"), bounds),
        sub=_json_identifier(value.v.get("sub"), bounds),
        profile=_json_identifier(value.v.get("profile"), bounds),
        profile_digest=_json_digest(value.v.get("profile_digest")),
        content_digest=_json_digest(value.v.get("content_digest")),
        gen=_json_integer(value.v.get("gen"), bounds),
        prev=_json_digest(value.v.get("prev")),
        iat=_json_integer(value.v.get("iat"), bounds),
        nbf=_json_integer(value.v.get("nbf"), bounds),
        exp=_json_integer(value.v.get("exp"), bounds),
    )
    _structure(claims.gen, claims.prev, claims.iat, claims.nbf, claims.exp, bounds)
    if not _bytes_equal(_unwrap(jcs_encode(value, bounds)), segments.payload_bytes):
        _fail("content assertion: canonical payload")
    return claims


def _structure(gen: int, prev: bytes, iat: int, nbf: int, exp: int, bounds: Bounds) -> None:
    if not (1 <= gen <= _unwrap(bounds_resolve(bounds, "integer_magnitude"))):
        _fail("content assertion: generation")
    if (gen == 1) != _bytes_equal(prev, ZERO_DIGEST):
        _fail("content assertion: genesis")
    if not (iat <= nbf < exp):
        _fail("content assertion: time structure")


def _parse(
    compact: bytes, bounds: Bounds, suite: _Suite = _EDDSA
) -> tuple[CompactSegments, ContentAssertionDecoded]:
    segments, header = _framing(compact, bounds)
    if not _suite_matches(header, suite):
        _fail("content assertion: suite")
    return segments, _payload(segments, header.kid, bounds, suite)


def _projected_compact_bounds(protected_size: int, payload_size: int, bounds: Bounds) -> None:
    if protected_size > _unwrap(bounds_resolve(bounds, "encoded_segment_bytes")):
        _fail("content assertion: protected segment")
    if payload_size > _unwrap(bounds_resolve(bounds, "encoded_segment_bytes")):
        _fail("content assertion: payload segment")
    decoded_limit = _unwrap(bounds_resolve(bounds, "decoded_segment_bytes"))
    if _project_base64url_decoded_size(protected_size) > decoded_limit:
        _fail("content assertion: decoded protected segment")
    if _project_base64url_decoded_size(payload_size) > decoded_limit:
        _fail("content assertion: decoded payload segment")
    projected = protected_size + payload_size + 2 + _SIGNATURE_SEGMENT_BYTES
    if projected > _unwrap(bounds_resolve(bounds, "compact_bytes")):
        _fail("content assertion: projected compact")
    if projected > _unwrap(bounds_resolve(bounds, "anchor_bytes")):
        _fail("content assertion: projected anchor")


def _compact_bytes(compact: bytes, bounds: Bounds) -> bytes:
    decoded = _unwrap(bounds_resolve(bounds, "decoded_segment_bytes"))
    segment_limit = min(
        _unwrap(bounds_resolve(bounds, "encoded_segment_bytes")), (4 * decoded + 2) // 3
    )
    return _bytes(compact, min(
        _unwrap(bounds_resolve(bounds, "compact_bytes")),
        _unwrap(bounds_resolve(bounds, "anchor_bytes")),
        2 * segment_limit + 2 + _SIGNATURE_SEGMENT_BYTES,
    ))


def content_digest(content: bytes, bounds: Bounds | None = None) -> Result[bytes]:
    """Hash nonempty bounded content using the content-assertion domain separator."""
    def body() -> bytes:
        b = _bounds(bounds)
        raw = _bytes(content, _unwrap(bounds_resolve(b, "content_bytes")))
        if not raw:
            _fail("content assertion: content_bytes")
        return _unwrap(sha256(CONTENT_PREFIX, raw))

    return _trying(body)


@_closed_shape
def assertion_signing_input(
    assertion: ContentAssertion, bounds: Bounds | None = None
) -> Result[SigningInput]:
    """Validate content-lineage claims and return their exact canonical signing input."""
    return _trying(lambda: _signing_input(assertion, bounds))


def _signing_input(
    assertion: ContentAssertion, bounds: Bounds | None, suite: _Suite = _EDDSA
) -> SigningInput:
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
        "alg": JString(suite.alg),
        "kid": JString(_unwrap(str_utf8(kid))),
        "typ": JString(suite.typ),
    }
    payload: dict[str, Tagged] = {
        "aud": JString(_unwrap(str_utf8(identifiers["aud"]))),
        "content_digest": JString(_unwrap(base64url_encode(asserted_content_digest))),
        "exp": JInt(exp),
        "gen": JInt(gen),
        "iat": JInt(iat),
        "iss": JString(_unwrap(str_utf8(identifiers["iss"]))),
        "jti": JString(_unwrap(str_utf8(identifiers["jti"]))),
        "nbf": JInt(nbf),
        "prev": JString(_unwrap(base64url_encode(prev))),
        "profile": JString(_unwrap(str_utf8(identifiers["profile"]))),
        "profile_digest": JString(_unwrap(base64url_encode(profile_digest))),
        "sub": JString(_unwrap(str_utf8(identifiers["sub"]))),
        "v": JInt(VERSION),
    }
    protected_bytes = _unwrap(jcs_encode(JObject(header), b))
    payload_bytes = _unwrap(jcs_encode(JObject(payload), b))
    _unwrap(json_decode(protected_bytes, b))
    _unwrap(json_decode(payload_bytes, b))
    signing = SigningInput(
        kind=suite.kind,
        protected_segment=_unwrap(base64url_encode(protected_bytes)),
        payload_segment=_unwrap(base64url_encode(payload_bytes)),
    )
    _projected_compact_bounds(len(signing.protected_segment), len(signing.payload_segment), b)
    return signing


def _assemble_assertion(
    signing_input: SigningInput, signature: bytes, bounds: Bounds | None, suite: _Suite
) -> bytes:
    b = _compact_bounds(bounds)
    if type(signing_input) is not SigningInput:
        _fail("content assertion: signing input")
    kind = _text(getattr(signing_input, "kind", None))
    protected = _buffer(getattr(signing_input, "protected_segment", None))
    payload = _buffer(getattr(signing_input, "payload_segment", None))
    if kind != suite.kind:
        _fail("content assertion: signing kind")
    _projected_compact_bounds(_buffer_size(protected), _buffer_size(payload), b)
    signature = _bytes(signature, _SIGNATURE_BYTES)
    signing = SigningInput(kind, _bytes(protected), _bytes(payload))
    if suite is _ES256:
        v3._es256_scalars(signature)
        compact = _unwrap(assemble_segments_es256(signing, signature))
    else:
        compact = _unwrap(assemble_segments(signing, signature))
    _parse(compact, b, suite)
    return compact


def assemble_content_assertion_compact(
    signing_input: SigningInput, signature: bytes, bounds: Bounds | None = None
) -> Result[bytes]:
    """Assemble a content assertion with a canonical signature, without verifying it."""
    return _trying(lambda: _assemble_assertion(signing_input, signature, bounds, _EDDSA))


def _decode_assertion(compact: bytes, bounds: Bounds | None, suite: _Suite) -> ContentAssertionDecoded:
    b = _compact_bounds(bounds)
    return _parse(_compact_bytes(compact, b), b, suite)[1]


def decode_assertion(
    compact: bytes, bounds: Bounds | None = None
) -> Result[ContentAssertionDecoded]:
    """Decode canonical content-assertion claims without verifying their signature."""
    return _trying(lambda: _decode_assertion(compact, bounds, _EDDSA))


def _expected(expected: ExpectedContentAssertion, bounds: Bounds, suite: _Suite) -> None:
    attestor = expected.attestor
    _kid(attestor.key_id, bounds)
    if len(attestor.public_key) != (65 if suite is _ES256 else 32):
        _fail("content assertion: attestor key width")
    valid_from = _integer(attestor.valid_from, bounds)
    if attestor.valid_before is not None:
        valid_before = _integer(attestor.valid_before, bounds)
        if not valid_from < valid_before:
            _fail("content assertion: attestor window")
    for value in (expected.issuer, expected.audience, expected.subject, expected.profile):
        _identifier(value, bounds)
    _digest(expected.profile_digest)
    _digest(expected.content_digest)
    _integer(expected.now, bounds)


def verify_assertion(
    compact: bytes, expected: ExpectedContentAssertion
) -> Result[ContentAssertionFacts]:
    """Verify a content assertion against the caller-trusted attestor, content, profile and time."""
    return _trying(lambda: _verify_assertion(compact, expected, _EDDSA))


def _fingerprint(raw_key: bytes, suite: _Suite) -> bytes:
    if suite is _ES256:
        return _unwrap(v3.public_key_thumbprint_raw(raw_key))
    return _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(raw_key))))


def _signature_matches(
    segments: CompactSegments, raw_key: bytes, suite: _Suite
) -> bool:
    try:
        if suite is _ES256:
            key_es256 = v3._import_public_key(raw_key)
            return v3._es256_verify(segments.signing_input, segments.signature, key_es256)
        key = _import_public_key(raw_key)
        if not _ed25519_verify(segments.signing_input, segments.signature, key):
            return False
    except (InternalError, UnsupportedAlgorithm):
        return False
    return True


def _key_window(claims: ContentAssertionDecoded, attestor: HistoricalPublicKey) -> bool:
    return (
        claims.iat >= attestor.valid_from
        and claims.nbf >= attestor.valid_from
        and (attestor.valid_before is None or claims.exp <= attestor.valid_before)
    )


def _verified_facts(
    claims: ContentAssertionDecoded, compact: bytes, fingerprint: bytes, suite: _Suite
) -> ContentAssertionFacts:
    facts_type = Es256ContentAssertionFacts if suite is _ES256 else ContentAssertionFacts
    return facts_type(
        version=VERSION,
        attestor_key_id=claims.attestor_key_id,
        attestor_key_fingerprint=fingerprint,
        jti=claims.jti,
        iss=claims.iss,
        aud=claims.aud,
        sub=claims.sub,
        profile=claims.profile,
        profile_digest=claims.profile_digest,
        content_digest=claims.content_digest,
        gen=claims.gen,
        prev=claims.prev,
        iat=claims.iat,
        nbf=claims.nbf,
        exp=claims.exp,
        digest=_unwrap(sha256(compact)),
    )


def _verify_assertion(
    compact: bytes, expected: ExpectedContentAssertion, suite: _Suite
) -> ContentAssertionFacts:
    expected = _normalize_arg(expected, ExpectedContentAssertion)
    b = _compact_bounds(expected.bounds)
    _expected(expected, b, suite)
    compact = _compact_bytes(compact, b)
    segments, claims = _parse(compact, b, suite)
    attestor = expected.attestor
    if claims.attestor_key_id != attestor.key_id:
        _fail("content assertion: attestor key id")
    if (claims.iss, claims.aud, claims.sub, claims.profile) != (
        expected.issuer,
        expected.audience,
        expected.subject,
        expected.profile,
    ):
        _fail("content assertion: expected identities")
    if not _bytes_equal(claims.profile_digest, expected.profile_digest):
        _fail("content assertion: expected profile digest")
    asserted_content_digest = claims.content_digest
    if not _bytes_equal(asserted_content_digest, expected.content_digest):
        _fail("content assertion: expected content digest")
    if not _key_window(claims, attestor):
        _fail("content assertion: key window")
    if not claims.nbf <= expected.now < claims.exp:
        _fail("content assertion: current window")
    fingerprint = _fingerprint(attestor.public_key, suite)
    if not _signature_matches(segments, attestor.public_key, suite):
        _fail("content assertion: signature")
    return _verified_facts(claims, compact, fingerprint, suite)


def _assertion_digest(compact: bytes, bounds: Bounds | None, suite: _Suite) -> bytes:
    b = _compact_bounds(bounds)
    raw = _compact_bytes(compact, b)
    _parse(raw, b, suite)
    return _unwrap(sha256(raw))


def assertion_digest(compact: bytes, bounds: Bounds | None = None) -> Result[bytes]:
    """Validate canonical assertion bytes and hash their exact compact representation."""
    return _trying(lambda: _assertion_digest(compact, bounds, _EDDSA))


def _facts(value: ContentAssertionFacts, bounds: Bounds) -> None:
    if value.version != VERSION:
        _fail("content assertion successor: version")
    if value.verification != "signature_and_window" or value.trust != "not_evaluated":
        _fail("content assertion successor: markers")
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
    """Check verified predecessor/successor facts for consecutive generation and exact digest linkage."""
    return _trying(lambda: _verify_successor(predecessor, successor, bounds))


def _verify_successor(
    predecessor: ContentAssertionFacts, successor: ContentAssertionFacts, bounds: Bounds
) -> None:
    b = _unwrap(coerce_bounds(bounds))
    _facts(predecessor, b)
    _facts(successor, b)
    if (
        predecessor.iss,
        predecessor.aud,
        predecessor.sub,
        predecessor.profile,
    ) != (
        successor.iss,
        successor.aud,
        successor.sub,
        successor.profile,
    ):
        _fail("content assertion successor: context")
    if not _bytes_equal(predecessor.profile_digest, successor.profile_digest):
        _fail("content assertion successor: profile digest")
    magnitude = _unwrap(bounds_resolve(b, "integer_magnitude"))
    if predecessor.gen >= magnitude or successor.gen != predecessor.gen + 1:
        _fail("content assertion successor: generation")
    if not _bytes_equal(successor.prev, predecessor.digest):
        _fail("content assertion successor: predecessor")
    if successor.iat < predecessor.iat:
        _fail("content assertion successor: time")
    if successor.jti == predecessor.jti:
        _fail("content assertion successor: identity")
    return
