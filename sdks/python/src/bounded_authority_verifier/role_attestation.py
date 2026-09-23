"""The role-attestation sibling profile façade (spec/bap-role-attestation-v1.md, profile identity
``bap-role-attestation/1``).

A role attestation is a standalone, grant-unbound compact JWS in which an attestor key binds a
subject key to a role (``issuer`` or ``holder``) for a bounded window. It single-sources the
contract-major 1 primitives (EdDSA under ``BAP1-Ed25519-SHA256``, the bounded JSON/JCS/base64url/JWK
machinery) and is parsed by no contract-major profile; this profile rejects every contract-major
``typ`` and every contract-major façade rejects ``ba+role-attestation`` (REQ-RA1-CORE-*).

Four public functions, each returning ``Result[T] = Ok | Err`` (the ``{:ok, value} | {:error,
:invalid}`` mirror). No ``authorized`` / ``decision`` surface (AGENTS rule 1); no signer, no private
key, no signing callback (REQ-RA1-API-no-signer). Wire format derived from spec/bap-role-attestation-v1.md
+ the certified corpus alone (the ADR 0014 derivation bar — no code-level derivation from the Elixir
reference); the corpus is the byte-level arbiter.

The dispatch structs here are frozen dataclasses mirroring the SDK's established shapes: ``bytes``
for raw-32 key fields, ``int`` / ``str`` for scalars, ``int | None`` for the unbounded attestor
window edge.
"""

from __future__ import annotations

import functools
import inspect
import re
import types as _types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, is_dataclass
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMA, MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from .compact import CompactSegments, SigningInput, assemble_segments, parse_compact
from .ed25519 import ed25519_verify, import_public_key
from .error import InvalidError, Ok, Result, err, fail
from .facts import AttestationDecoded, AttestationFacts
from .jcs import jcs_encode
from .json_alg import (
    JArray,
    JBool,
    JFloat,
    JInt,
    JNull,
    JObject,
    JString,
    Tagged,
    json_decode,
    str_utf8,
    utf8_str,
)
from .jwk import jwk_from_public_key, thumbprint_raw
from .uri import _valid_ipv6_literal

# --- constants (the closed role-attestation profile header/claim literals) ---

ALG = "EdDSA"
ATTESTATION_TYP = "ba+role-attestation"
VERSION = 1

# REQ-RA1-CLAIM-role-closed-set: the attested role is exactly one of these two.
ROLES: tuple[str, ...] = ("issuer", "holder")

_KID_CHARSET = re.compile(r"[A-Za-z0-9._~-]+")
_URI_BYTES = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*")
_SIGNATURE_BYTES = 64
_SIGNATURE_SEGMENT_BYTES = len(base64url_encode(bytes(_SIGNATURE_BYTES)))


def _is_int(value: object) -> bool:
    """isinstance(int) that EXCLUDES bool (Python ``isinstance(True, int)`` is True; a bool-typed
    nbf/exp/now is a wrong-typed caller value, not an integer NumericDate)."""
    return isinstance(value, int) and not isinstance(value, bool)


# --- dispatch struct types (the contract for each façade) ---


@dataclass(frozen=True)
class AttestationProducer:
    """The producer-side attestation: everything but the signature (REQ-RA1-API-complete surface 1).

    ``public_key`` is the raw 32-byte Ed25519 SUBJECT public key being attested; ``attestor_key_id``
    lands in the protected ``kid``; ``key_id`` is the attested subject key id.
    """

    attestor_key_id: str
    jti: str
    key_id: str
    public_key: bytes  # raw 32
    role: str          # "issuer" | "holder"
    nbf: int
    exp: int


@dataclass(frozen=True)
class TrustedAttestor:
    """The caller-trusted attestor key and its own validity window (REQ-RA1-VERIFY-caller-supplied).

    ``valid_before is None`` is the configured-unbounded window (REQ-RA1-SECURITY-trust-scope: a
    configured unbounded attestor window admits unbounded attestation lifetimes by that choice).
    """

    key_id: str
    public_key: bytes  # raw 32
    valid_from: int
    valid_before: int | None  # None = unbounded


@dataclass(frozen=True)
class ExpectedAttestation:
    """The expected context for verification (REQ-RA1-VERIFY-caller-supplied): trusted attestor +
    window, the expected subject binding, the caller's ``now``, and bounds."""

    attestor: TrustedAttestor
    subject_key_id: str
    subject_public_key: bytes  # raw 32
    now: int
    bounds: Bounds | None = None


# --- bounded member helpers (the BAP1 kid / StringOrUri / int / b64url claim rules) ---


def _require_kid_value(v: Tagged | None, key: str, ctx: str, bounds: Bounds) -> str:
    """The BAP1 ``kid`` rules on one member: non-empty bounded ASCII ``[A-Za-z0-9._~-]``."""
    if v is None or not isinstance(v, JString):
        fail(f"{ctx}: {key} string")
    b = v.v
    if not (1 <= len(b) <= bounds_resolve(bounds, "kid_bytes")):
        fail(f"{ctx}: {key} bytes")
    s = utf8_str(b)
    if _KID_CHARSET.fullmatch(s) is None:
        fail(f"{ctx}: {key} charset")
    return s


def _require_object_exact(v: Tagged, keys: list[str], ctx: str) -> JObject:
    """Validate that ``v`` is a JObject with exactly ``keys`` members; return it narrowed."""
    if not isinstance(v, JObject):
        fail(f"{ctx}: object")
    if set(v.v) != set(keys):
        fail(f"{ctx}: closed members")
    return v


def _require_string_lit(obj: JObject, key: str, lit: str, ctx: str) -> None:
    v = obj.v.get(key)
    if v is None or not isinstance(v, JString) or utf8_str(v.v) != lit:
        fail(f"{ctx}: {key}={lit}")


# StringOrURI (RFC 7519 §2). A bare string with no ':' is always valid; an opaque scheme `a:b` (no
# `//`) is valid; a `//` authority is structurally validated.
def _is_string_or_uri(s: str) -> bool:
    if not _is_well_formed(s):
        return False
    colon = s.find(":")
    if colon == -1:
        return True  # bare string: always a StringOrURI
    scheme = s[:colon]
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9+\-.]*", scheme) is None:
        return False
    if _URI_BYTES.fullmatch(s) is None:
        return False
    if s.count("#") > 1:
        return False
    rest = s[colon + 1:]
    if not rest.startswith("//"):
        # Elixir URI.new reserves raw brackets for an IP-literal authority host. Percent-encoded
        # brackets remain ordinary URI bytes, and colon-free plain strings use the branch above.
        return "[" not in rest and "]" not in rest
    hierarchical = rest[2:]
    delimiters = [position for token in "/?#" if (position := hierarchical.find(token)) >= 0]
    authority_end = min(delimiters, default=len(hierarchical))
    authority = hierarchical[:authority_end]
    remainder = hierarchical[authority_end:]
    if "[" in remainder or "]" in remainder:
        return False
    return _valid_uri_authority(authority)


def _valid_uri_authority(authority: str) -> bool:
    at = authority.find("@")
    userinfo = "" if at == -1 else authority[:at]
    hostport = authority if at == -1 else authority[at + 1:]
    if "@" in hostport or "[" in userinfo or "]" in userinfo:
        return False  # a second @ lands in the host — invalid.
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return False  # unterminated IPv6 literal.
        if not _is_ipv6(hostport[1:close]):
            return False
        suffix = hostport[close + 1:]
        return suffix == "" or re.fullmatch(r":\d*", suffix) is not None
    if "[" in hostport or "]" in hostport:
        return False  # stray bracket in host.
    if hostport.count(":") > 1:
        return False  # host/port ambiguity.
    sep = hostport.rfind(":")
    return sep == -1 or re.fullmatch(r"\d*", hostport[sep + 1:]) is not None


def _is_ipv6(literal: str) -> bool:
    return _valid_ipv6_literal(str_utf8(literal))


def _is_well_formed(s: str) -> bool:
    # A well-formed Unicode string has no unpaired surrogates (the defense for direct, non-JSON
    # producer inputs; strings from json_decode were already rejected at the escape level).
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _require_string_or_uri(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} string")
    s = utf8_str(v.v)
    b = str_utf8(s)
    if not (1 <= len(b) <= bounds_resolve(bounds, "identifier_bytes")):
        fail(f"claim: {key} bytes")
    if not _is_string_or_uri(s):
        fail(f"claim: {key} string-or-uri")
    return s


def _require_int(v: Tagged | None, key: str) -> int:
    if v is None or not isinstance(v, JInt):
        fail(f"claim: {key} integer")
    return v.v


def _require_b64url_n(v: Tagged | None, key: str, n: int) -> bytes:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} b64url string")
    raw = base64url_decode(v.v)
    if len(raw) != n:
        fail(f"claim: {key} width")
    return raw


def _require_role(v: Tagged | None) -> str:
    if v is None or not isinstance(v, JString):
        fail("claim: role string")
    s = utf8_str(v.v)
    if s not in ROLES:
        fail("claim: role closed set")
    return s


def _bytes_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b, strict=True):
        diff |= x ^ y
    return diff == 0


# --- the protected header + payload contracts (spec §2) ---


def _parse_attestation_header(seg: CompactSegments, bounds: Bounds) -> str:
    """The closed header {alg, kid, typ} with JCS-canonical protected bytes (REQ-RA1-HEADER-*,
    REQ-RA1-CLAIM-canonical). Returns the attestor key id (a hint, never a trust selector)."""
    h = json_decode(seg.protected_bytes, bounds)
    h = _require_object_exact(h, ["alg", "kid", "typ"], "attestation header")
    _require_string_lit(h, "alg", ALG, "attestation header alg")
    _require_string_lit(h, "typ", ATTESTATION_TYP, "attestation header typ")
    kid = _require_kid_value(h.v.get("kid"), "kid", "attestation header", bounds)
    # REQ-RA1-CLAIM-canonical: both segments must equal their RFC 8785 canonical re-encoding.
    if not _bytes_equal(jcs_encode(h, bounds), seg.protected_bytes):
        fail("attestation header: canonical")
    return kid


def _validate_attestation_payload(p: Tagged, payload_bytes: bytes, bounds: Bounds) -> None:
    """The closed payload member rules (REQ-RA1-CLAIM-*): every listed member required, every
    unlisted member invalid, integral numerics, ``nbf < exp``, JCS-canonical payload bytes."""
    p = _require_object_exact(
        p, ["exp", "jti", "key_id", "nbf", "public_key", "role", "v"], "attestation payload"
    )
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("attestation: v=1")
    _require_string_or_uri(p.v.get("jti"), "jti", bounds)
    _require_kid_value(p.v.get("key_id"), "key_id", "attestation payload", bounds)
    _require_b64url_n(p.v.get("public_key"), "public_key", 32)
    _require_role(p.v.get("role"))
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if not (nbf < exp):
        fail("attestation: nbf < exp")
    # REQ-RA1-CLAIM-canonical: both segments must equal their RFC 8785 canonical re-encoding.
    if not _bytes_equal(jcs_encode(p, bounds), payload_bytes):
        fail("attestation payload: canonical")


_T = TypeVar("_T")


def _trying(fn: Callable[[], _T]) -> Result[_T]:
    """Run a thunk that may raise InvalidError; convert to Result. Any NON-InvalidError propagates."""
    try:
        return Ok(fn())
    except InvalidError:
        return err()


def _coerce_attestation_bounds(bounds: Bounds | None) -> Bounds:
    """Validate profile-entry bounds, including unknown keys that shared Bounds cannot resolve."""
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    if any(key not in MAXIMA for key in b.overrides):
        fail("role_attestation: unknown bound")
    b = coerce_bounds(b)
    if bounds_resolve(b, "decoded_segment_bytes") < _SIGNATURE_BYTES:
        fail("role_attestation: signature decoded segment bound")
    if bounds_resolve(b, "encoded_segment_bytes") < _SIGNATURE_SEGMENT_BYTES:
        fail("role_attestation: signature encoded segment bound")
    return b


def _project_base64url_decoded_size(encoded_size: int) -> int:
    """Exact decoded byte count implied by a valid unpadded base64url segment length."""
    return encoded_size * 3 // 4


def _preflight_attestation_compact(compact: bytes, bounds: Bounds) -> None:
    """Bound all compact segments before shared parsing performs any base64url decode."""
    if len(compact) > bounds_resolve(bounds, "anchor_bytes"):
        fail("role_attestation: anchor_bytes")
    if len(compact) > bounds_resolve(bounds, "compact_bytes"):
        fail("role_attestation: compact_bytes")
    segments = compact.split(b".")
    if len(segments) != 3 or any(len(segment) == 0 for segment in segments):
        fail("role_attestation: three non-empty segments")
    encoded_limit = bounds_resolve(bounds, "encoded_segment_bytes")
    decoded_limit = bounds_resolve(bounds, "decoded_segment_bytes")
    for segment in segments:
        if len(segment) > encoded_limit:
            fail("role_attestation: encoded segment bound")
        if _project_base64url_decoded_size(len(segment)) > decoded_limit:
            fail("role_attestation: decoded segment bound")


# --- the closed-Result shape gate (ADR 0017 clauses 1-2) ---
#
# A wrong-typed caller value (a non-string role, a float nbf, a bool in an int field, an entirely
# non-struct argument) must return Err, never raise AttributeError/TypeError out of the public
# façade and never be silently coerced. The gate is annotation-driven and total over the declared
# contract: the façade signatures and dataclass fields ARE the shape contract. Shape rules are
# exact on scalars — bool is not int (clause 2), bytearray is not bytes — while sequence containers
# (tuple[X, ...], Sequence[X]) accept list|tuple, the historical input surface. The tagged JSON
# algebra (JNull..JObject) and Bounds are matched opaquely: their interiors are validated by the
# bodies' own bounds/semantic gates. An annotation form the gate does not understand raises at
# import (fail fast for the developer), never silently under-validates.

_OPAQUE_ANNOTATIONS = (Bounds, JNull, JBool, JInt, JFloat, JString, JArray, JObject)
_DATACLASS_HINTS: dict[type, dict[str, object]] = {}


class _MissingField:
    """Sentinel: a struct attribute absent entirely (malformed construction)."""


_MISSING = _MissingField()


def _dataclass_hints(cls: type) -> dict[str, object]:
    hints = _DATACLASS_HINTS.get(cls)
    if hints is None:
        hints = get_type_hints(cls)
        _DATACLASS_HINTS[cls] = hints
    return hints


def _is_union(annotation: object) -> bool:
    return get_origin(annotation) is Union or isinstance(annotation, _types.UnionType)


def _walk_annotation(annotation: object) -> None:
    """Fail fast at decoration time on any annotation form the gate cannot validate exactly."""
    if annotation is Any or annotation is object or annotation is type(None):
        return
    if isinstance(annotation, type):
        if annotation in _OPAQUE_ANNOTATIONS or annotation in (str, bytes, int, float, bool):
            return
        if is_dataclass(annotation):
            for sub in _dataclass_hints(annotation).values():
                _walk_annotation(sub)
            return
        raise TypeError(f"closed_shape: unsupported annotation {annotation!r}")
    if _is_union(annotation):
        for member in get_args(annotation):
            _walk_annotation(member)
        return
    origin = get_origin(annotation)
    if origin is tuple:
        (elem, rest) = get_args(annotation)
        if rest is not Ellipsis:
            raise TypeError(f"closed_shape: fixed-arity tuple not supported: {annotation!r}")
        _walk_annotation(elem)
        return
    if origin is Sequence or origin is Mapping:
        for elem in get_args(annotation):
            _walk_annotation(elem)
        return
    raise TypeError(f"closed_shape: unsupported annotation {annotation!r}")


def _shape_ok(value: object, annotation: object) -> bool:
    """True iff value matches the declared annotation shape exactly (ADR 0017 clauses 1-2)."""
    if annotation is Any or annotation is object:
        return True
    if annotation is type(None):
        return value is None
    if isinstance(annotation, type):
        if annotation in _OPAQUE_ANNOTATIONS:
            return isinstance(value, annotation)
        if annotation is str:
            return isinstance(value, str)
        if annotation is bytes:
            return isinstance(value, bytes)
        if annotation is int:
            return isinstance(value, int) and not isinstance(value, bool)
        if annotation is float:
            return isinstance(value, float)
        if annotation is bool:
            return isinstance(value, bool)
        if is_dataclass(annotation):
            if not isinstance(value, annotation):
                return False
            # A struct can arrive malformed (constructed via __new__ or a broken subclass) with
            # attributes missing entirely — that is a shape failure, never a crash (the gate
            # itself must uphold the closed surface it enforces).
            hints = _dataclass_hints(annotation)
            for name, sub in hints.items():
                member = getattr(value, name, _MISSING)
                if member is _MISSING or not _shape_ok(member, sub):
                    return False
            return True
        return False  # unreachable — _walk_annotation rejects unsupported types at import
    if _is_union(annotation):
        return any(_shape_ok(value, member) for member in get_args(annotation))
    origin = get_origin(annotation)
    if origin is tuple:
        # Variadic tuple[X, ...] carries the ELEMENT contract; the container accepts list|tuple
        # (the historical input surface — conformant fixtures pass lists; bodies iterate).
        if not isinstance(value, (list, tuple)):
            return False
        (elem, _rest) = get_args(annotation)
        return all(_shape_ok(item, elem) for item in value)
    if origin is Sequence:
        if not isinstance(value, (list, tuple)):
            return False
        (elem,) = get_args(annotation)
        return all(_shape_ok(item, elem) for item in value)
    if origin is Mapping:
        return isinstance(value, Mapping)
    return False  # unreachable — _walk_annotation rejects unsupported origins at import


def _closed_shape(fn: Callable[..., Result[Any]]) -> Callable[..., Result[Any]]:
    """Façade decorator: validate caller arguments against their declared shapes before the
    body runs; a wrong-typed argument returns the closed Err directly (never raises, never
    coerces). Applied to all four public functions of this sibling profile. Hints resolve lazily
    on the first call — façade signatures forward-reference structs defined in this module."""
    resolved: list[tuple[dict[str, object], inspect.Signature]] = []

    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> Result[Any]:
        if not resolved:
            hints = get_type_hints(fn)
            for name, annotation in hints.items():
                if name != "return":
                    _walk_annotation(annotation)
            resolved.append((hints, inspect.signature(fn)))
        hints, signature = resolved[0]
        bound = signature.bind(*args, **kwargs)
        for name, value in bound.arguments.items():
            annotation = hints.get(name)
            if annotation is not None and not _shape_ok(value, annotation):
                return err()
        return fn(*args, **kwargs)

    return wrapper


# --- the four public surfaces (REQ-RA1-API-complete) ---


# 1. attestation signing-input production (REQ-RA1-API-complete surface 1; REQ-RA1-API-no-signer:
# the output is the ASCII signing input, never a signature).
@_closed_shape
def attestation_signing_input(
    attestation: AttestationProducer, bounds: Bounds | None = None
) -> Result[SigningInput]:
    return _trying(lambda: _attestation_signing_input_body(attestation, bounds))


def _attestation_signing_input_body(
    attestation: AttestationProducer, bounds: Bounds | None
) -> SigningInput:
    b = _coerce_attestation_bounds(bounds)
    if not _is_well_formed(attestation.attestor_key_id):
        fail("attestation_signing_input: attestor_key_id Unicode")
    kid_bytes = str_utf8(attestation.attestor_key_id)
    if not (1 <= len(kid_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("attestation_signing_input: attestor_key_id bytes")
    if _KID_CHARSET.fullmatch(attestation.attestor_key_id) is None:
        fail("attestation_signing_input: attestor_key_id charset")
    if not _is_string_or_uri(attestation.jti):
        fail("attestation_signing_input: jti")
    jti_bytes = str_utf8(attestation.jti)
    if not (1 <= len(jti_bytes) <= bounds_resolve(b, "identifier_bytes")):
        fail("attestation_signing_input: jti bytes")
    if not _is_well_formed(attestation.key_id):
        fail("attestation_signing_input: key_id Unicode")
    subject_kid_bytes = str_utf8(attestation.key_id)
    if not (1 <= len(subject_kid_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("attestation_signing_input: key_id bytes")
    if _KID_CHARSET.fullmatch(attestation.key_id) is None:
        fail("attestation_signing_input: key_id charset")
    if len(attestation.public_key) != 32:
        fail("attestation_signing_input: public key width")
    if attestation.role not in ROLES:
        fail("attestation_signing_input: role closed set")
    if not (_is_int(attestation.nbf) and _is_int(attestation.exp)):
        fail("attestation_signing_input: integer times")
    if not (attestation.nbf < attestation.exp):
        fail("attestation_signing_input: nbf < exp")
    header: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "kid": JString(kid_bytes),
        "typ": JString(str_utf8(ATTESTATION_TYP)),
    }
    payload: dict[str, Tagged] = {
        "exp": JInt(attestation.exp),
        "jti": JString(jti_bytes),
        "key_id": JString(subject_kid_bytes),
        "nbf": JInt(attestation.nbf),
        "public_key": JString(base64url_encode(attestation.public_key)),
        "role": JString(str_utf8(attestation.role)),
        "v": JInt(VERSION),
    }
    protected_bytes = jcs_encode(JObject(header), b)
    payload_bytes = jcs_encode(JObject(payload), b)
    if len(protected_bytes) > bounds_resolve(b, "decoded_segment_bytes") or len(
        payload_bytes
    ) > bounds_resolve(b, "decoded_segment_bytes"):
        fail("attestation_signing_input: decoded segment bound")
    # Re-parse the exact bytes the producer emits so json_bytes and number_lexeme_bytes constrain
    # production exactly as they constrain assembly, decode, and verification.
    json_decode(protected_bytes, b)
    json_decode(payload_bytes, b)
    protected_segment = base64url_encode(protected_bytes)
    payload_segment = base64url_encode(payload_bytes)
    if len(protected_segment) > bounds_resolve(b, "encoded_segment_bytes") or len(
        payload_segment
    ) > bounds_resolve(b, "encoded_segment_bytes"):
        fail("attestation_signing_input: encoded segment bound")
    compact_size = (
        len(protected_segment) + 1 + len(payload_segment) + 1 + _SIGNATURE_SEGMENT_BYTES
    )
    if compact_size > bounds_resolve(b, "compact_bytes"):
        fail("attestation_signing_input: compact_bytes")
    if compact_size > bounds_resolve(b, "anchor_bytes"):
        fail("attestation_signing_input: anchor_bytes")
    return SigningInput(
        kind="role_attestation",
        protected_segment=protected_segment,
        payload_segment=payload_segment,
    )


# 2. compact assembly from signing input + external signature (REQ-RA1-API-assembly-revalidate:
# the protected header, payload, member rules, segment bounds, and signature width are revalidated
# under this profile before a compact artifact is returned).
@_closed_shape
def assemble_attestation_compact(
    input_: SigningInput, signature: bytes, bounds: Bounds | None = None
) -> Result[bytes]:
    def body() -> bytes:
        b = _coerce_attestation_bounds(bounds)
        if input_.kind != "role_attestation":
            fail("assemble_attestation_compact: kind")
        if len(input_.protected_segment) > bounds_resolve(b, "encoded_segment_bytes") or len(
            input_.payload_segment
        ) > bounds_resolve(b, "encoded_segment_bytes"):
            fail("assemble_attestation_compact: segment bound")
        assembled = assemble_segments(input_, signature)
        if not isinstance(assembled, Ok):
            fail("assemble_attestation_compact: signing input")
        compact = assembled.value
        _preflight_attestation_compact(compact, b)
        # Full attestation re-parse (validate_assembled_compact → decode_attestation: closed sets,
        # member rules, canonical segments, segment + signature width) — the assembler must not
        # mint bytes its own consumer (verify) would reject (REQ-RA1-API-symmetry).
        r = decode_attestation(compact, b)
        if not r.is_ok:
            fail("assemble_attestation_compact: re-parse")
        return compact

    return _trying(body)


# 3. attestation decoding (structural; verification=not_evaluated).
@_closed_shape
def decode_attestation(compact: bytes, bounds: Bounds | None = None) -> Result[AttestationDecoded]:
    return _trying(lambda: _decode_attestation_body(compact, bounds))


def _decode_attestation_body(compact: bytes, bounds: Bounds | None) -> AttestationDecoded:
    b = _coerce_attestation_bounds(bounds)
    _preflight_attestation_compact(compact, b)
    seg = parse_compact(compact, b)
    kid = _parse_attestation_header(seg, b)
    p = json_decode(seg.payload_bytes, b)
    _validate_attestation_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        fail("decode_attestation: payload object")
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    key_id = _require_kid_value(p.v.get("key_id"), "key_id", "attestation payload", b)
    subject_key = _require_b64url_n(p.v.get("public_key"), "public_key", 32)
    role = _require_role(p.v.get("role"))
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    return AttestationDecoded(
        attestor_key_id=kid,
        jti=jti,
        subject_key_id=key_id,
        public_key=subject_key,
        role=role,
        nbf=nbf,
        exp=exp,
    )


# 4. attestation verification (the citation symbol the companion signer documents:
# verify_attestation/2 — compact + expected context).
@_closed_shape
def verify_attestation(compact: bytes, expected: ExpectedAttestation) -> Result[AttestationFacts]:
    return _trying(lambda: _verify_attestation_body(compact, expected))


def _verify_attestation_body(compact: bytes, expected: ExpectedAttestation) -> AttestationFacts:
    attestor = expected.attestor
    b = _coerce_attestation_bounds(expected.bounds)
    magnitude = bounds_resolve(b, "integer_magnitude")
    # Fail-closed shallow context checks (a malformed context struct is a closed Invalid, never an
    # AttributeError past the Result contract — mirrors the v1 verify_grant pattern).
    if not isinstance(getattr(attestor, "public_key", None), bytes) or len(attestor.public_key) != 32:
        fail("verify_attestation: attestor key width")
    if not isinstance(getattr(attestor, "key_id", None), str):
        fail("verify_attestation: attestor key id")
    if not _is_int(getattr(attestor, "valid_from", None)):
        fail("verify_attestation: attestor valid_from")
    valid_before = getattr(attestor, "valid_before", None)
    if valid_before is not None and not _is_int(valid_before):
        fail("verify_attestation: attestor valid_before")
    # Attestor-window endpoints are magnitude-bounded caller input — the HistoricalPublicKey
    # gates the Elixir reference (ContextValidation.historical_key) and the Rust leg apply.
    # Containment alone is trivially satisfied by an out-of-magnitude window, so nothing
    # downstream rejects it (cross-vendor review 2026-09-22).
    if abs(attestor.valid_from) > magnitude:
        fail("verify_attestation: attestor valid_from magnitude")
    if valid_before is not None and abs(valid_before) > magnitude:
        fail("verify_attestation: attestor valid_before magnitude")
    if not isinstance(getattr(expected, "subject_key_id", None), str):
        fail("verify_attestation: subject key id")
    if not isinstance(getattr(expected, "subject_public_key", None), bytes) or len(
        expected.subject_public_key
    ) != 32:
        fail("verify_attestation: subject key width")
    if not _is_int(getattr(expected, "now", None)):
        fail("verify_attestation: integer now")
    # 1. the closed header and payload sets and canonical bytes of §2 (REQ-RA1-VERIFY-closed-sets).
    _preflight_attestation_compact(compact, b)
    seg = parse_compact(compact, b)
    kid = _parse_attestation_header(seg, b)
    p = json_decode(seg.payload_bytes, b)
    _validate_attestation_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        fail("verify_attestation: payload object")
    # 2. header kid == attestor key id + Ed25519 signature under the attestor public key
    #    (REQ-RA1-VERIFY-attestor-signature).
    if kid != attestor.key_id:
        fail("verify_attestation: kid exact")
    attestor_fingerprint = thumbprint_raw(jwk_from_public_key(attestor.public_key))
    key = import_public_key(attestor.public_key, utf8_str(base64url_encode(attestor_fingerprint)))
    if not ed25519_verify(seg.signing_input, seg.signature, key):
        fail("verify_attestation: signature")
    # 3. the payload subject binding equals the expected subject binding (key_id equality + raw
    #    public_key byte-equality) (REQ-RA1-VERIFY-subject-binding).
    key_id = _require_kid_value(p.v.get("key_id"), "key_id", "attestation payload", b)
    subject_key = _require_b64url_n(p.v.get("public_key"), "public_key", 32)
    if key_id != expected.subject_key_id or not _bytes_equal(subject_key, expected.subject_public_key):
        fail("verify_attestation: subject binding")
    # 4. the attestor and the subject are distinct (REQ-RA1-VERIFY-no-self-attestation).
    subject_fingerprint = thumbprint_raw(jwk_from_public_key(subject_key))
    if _bytes_equal(attestor_fingerprint, subject_fingerprint) or (
        attestor.key_id == expected.subject_key_id
    ):
        fail("verify_attestation: self-attestation")
    # 5. window containment: nbf >= attestor.valid_from, and exp <= valid_before when bounded
    #    (exp == valid_before is containment and is valid) (REQ-RA1-VERIFY-window-containment).
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if nbf < attestor.valid_from:
        fail("verify_attestation: nbf before attestor window")
    if valid_before is not None and exp > valid_before:
        fail("verify_attestation: exp outlives attestor window")
    # 6. the caller-supplied now is in [nbf, exp) (REQ-RA1-VERIFY-now-window).
    if not (nbf <= expected.now < exp):
        fail("verify_attestation: now window")
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    role = _require_role(p.v.get("role"))
    return AttestationFacts(
        attestor_key_id=attestor.key_id,
        attestor_key_fingerprint=attestor_fingerprint,
        subject_key_id=key_id,
        subject_key_fingerprint=subject_fingerprint,
        role=role,
        jti=jti,
        nbf=nbf,
        exp=exp,
    )
