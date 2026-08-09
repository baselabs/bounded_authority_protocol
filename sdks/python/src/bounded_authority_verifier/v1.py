"""The v1 verification façade (protocol-v1.md § Public verification contract, L270-290).

17 public functions, each returning ``Result[T] = Ok | Err`` (the ``{:ok, value} | {:error, :invalid}``
mirror). No ``authorized`` / ``decision`` surface (AGENTS rule 1). All claims revalidated at every
public entry (REQ1-VERIFY-revalidate). Wire formats derived from ``docs/protocol-v1.md`` + ADR 0004 +
the corpus; the corpus is the byte-level arbiter.

The dispatch structs here are frozen dataclasses mirroring the TS ``interface`` shapes (the contract
for each façade). They use ``bytes`` for raw-32 fields and ``int`` / ``str`` for scalars.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TypeVar, cast

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_new, bounds_resolve  # noqa: F401
from .compact import CompactSegments, SigningInput, assemble_compact, parse_compact  # noqa: F401
from .digest import request_digest as compute_request_digest
from .ed25519 import ed25519_verify, import_public_key, sha256
from .error import InvalidError, Ok, Result, err, fail, invalid_error, require
from .facts import (
    AnchoredExportFacts,
    AnchorFacts,
    ChainFacts,
    EnvelopeFacts,
    GrantDecoded,
    GrantFacts,
    KeyLocator,
    KeyTransitionFacts,
    ProofDecoded,
)
from .jcs import jcs_encode
from .json_alg import (
    JArray,
    JFloat,
    JInt,
    JObject,
    JString,
    Tagged,
    json_decode,
    str_utf8,
    utf8_str,
)
from .jwk import (
    OkpPublic,
    jwk_encode_public,  # noqa: F401
    jwk_from_public_key,
    thumbprint_raw,
)
from .selector import parse_selector, selector_matches
from .uri import uri_normalize

# --- constants (the closed v1 profile header/claim literals) ---

ALG = "EdDSA"
GRANT_TYP = "ba+cap"
PROOF_TYP = "dpop+jwt"
ANCHOR_TYP = "ba+chain-anchor"
TRANSITION_TYP = "ba+key-transition"
VERSION = 1

# BAP1-CHAIN\0 prefix for consumption-row hashing (ADR 0004 § Consumption rows).
ROW_PREFIX = b"BAP1-CHAIN\x00"

# BAP1-ARCHIVE\0EXPORT\0 prefix (ADR 0004 § Anchored export; the 20-byte magic, NOT framed).
ARCHIVE_PREFIX = b"BAP1-ARCHIVE\x00EXPORT\x00"

# The all-zero 32-byte hash: sequence-1 predecessor + sequence-0 anchor chain hash (ADR 0004).
DEFAULT_HASH = bytes(32)

# Lowercase RFC 4122 UUID.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_KID_CHARSET = re.compile(r"^[A-Za-z0-9._~-]+$")
_METHOD_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_OPERATION_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")


# --- dispatch struct types (match corpus input field names; the contract for each façade) ---


@dataclass(frozen=True)
class TrustedIssuer:
    key_id: str
    public_key: bytes  # raw 32


@dataclass(frozen=True)
class ExpectedGrant:
    issuer: str
    audience: str
    evaluation_time: int
    clock_skew: int
    bounds: Bounds | None = None


@dataclass(frozen=True)
class HistoricalPublicKey:
    key_id: str
    public_key: bytes  # raw 32
    valid_from: int
    valid_before: int | None  # None = unbounded


@dataclass(frozen=True)
class ExpectedAnchor:
    anchor_id: str
    anchored_at: int
    chain_id: str
    sequence: int
    chain_hash: bytes  # raw 32
    key_id: str
    key_fingerprint: bytes  # raw 32
    bounds: Bounds | None = None


@dataclass(frozen=True)
class ExpectedKeyTransition:
    transition_id: str
    chain_id: str
    effective_at: int
    current_key_id: str
    current_key_fingerprint: bytes  # raw 32
    next_key_id: str
    next_key_fingerprint: bytes  # raw 32
    bounds: Bounds | None = None


@dataclass(frozen=True)
class ConsumptionEntry:
    chain_id: str
    sequence: int
    previous_hash: bytes  # raw 32
    commitment: bytes  # raw 32


@dataclass(frozen=True)
class ChainInput:
    rows: tuple[bytes, ...]  # raw canonical row bytes
    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    previous_hash: bytes  # raw 32
    last_hash: bytes  # raw 32


@dataclass(frozen=True)
class ExpectedChain:
    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    previous_hash: bytes  # raw 32
    last_hash: bytes  # raw 32
    bounds: Bounds | None = None


@dataclass(frozen=True)
class NonceRequired:
    value: str
    kind: str = field(default="required", init=False)


@dataclass(frozen=True)
class NonceNotRequired:
    kind: str = field(default="not_required", init=False)


@dataclass(frozen=True)
class ExpectedRequest:
    trusted_issuer: TrustedIssuer
    issuer: str
    audience: str
    method: str
    target_uri: str
    invocation_id: str
    operation: str
    cast_arguments: Tagged
    evaluation_time: int
    clock_skew: int
    proof_max_age: int
    nonce: NonceNotRequired | NonceRequired
    bounds: Bounds | None = None


# A selector input to the grant producer: either the bare "all" string or a tagged object.
SelectorInput = str | Mapping[str, object]


@dataclass(frozen=True)
class OperationInput:
    name: str
    selectors: Sequence[SelectorInput]


@dataclass(frozen=True)
class GrantProducer:
    key_id: str
    issuer: str
    grant_id: str
    audiences: Sequence[str]
    issued_at: int
    not_before: int
    expires_at: int
    holder_thumbprint: str  # base64url 32
    operations: Sequence[OperationInput]


@dataclass(frozen=True)
class ProofProducer:
    holder_public_key: bytes  # raw 32
    proof_id: str
    method: str
    target_uri: str
    issued_at: int
    invocation_id: str
    operation: str
    grant_compact: bytes
    cast_arguments: Tagged
    nonce: str | None = None


@dataclass(frozen=True)
class BoundaryAnchorProducer:
    anchor_id: str
    anchored_at: int
    chain_id: str
    sequence: int
    chain_hash: bytes  # raw 32
    key_id: str
    public_key: bytes  # raw 32


@dataclass(frozen=True)
class KeyTransitionProducer:
    transition_id: str
    chain_id: str
    effective_at: int
    current_key_id: str
    current_public_key: bytes  # raw 32
    next_key_id: str
    next_public_key: bytes  # raw 32


@dataclass(frozen=True)
class AnchoredExportInput:
    rows: tuple[bytes, ...]
    start_anchor: bytes
    end_anchor: bytes
    transitions: tuple[bytes, ...]
    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    previous_hash: bytes  # raw 32
    last_hash: bytes  # raw 32


@dataclass(frozen=True)
class ArchivedObject:
    chunks: tuple[bytes, ...]
    version: str


@dataclass(frozen=True)
class HistoricalKeyChain:
    keys: tuple[HistoricalPublicKey, ...]


@dataclass(frozen=True)
class EncodedConsumptionEntry:
    bytes_: bytes
    hash_: bytes


@dataclass(frozen=True)
class EncodedAnchoredExport:
    archive: bytes
    digest: bytes


# --- shared closed-header / claim validators (derived from protocol-v1.md + RFCs) ---


def _parse_grant_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = json_decode(seg.protected_bytes, bounds)
    h = _require_object_exact(h, ["alg", "typ", "kid"], "grant header")
    _require_string_lit(h, "alg", ALG, "grant header alg")
    _require_string_lit(h, "typ", GRANT_TYP, "grant header typ")
    return _require_kid(h, bounds)


def _parse_proof_header(seg: CompactSegments, bounds: Bounds) -> tuple[bytes, bytes]:
    """Returns (holderThumbprint raw32, holderKey raw32)."""
    h = json_decode(seg.protected_bytes, bounds)
    h = _require_object_exact(h, ["alg", "typ", "jwk"], "proof header")
    _require_string_lit(h, "alg", ALG, "proof header alg")
    _require_string_lit(h, "typ", PROOF_TYP, "proof header typ")
    jwk_v = h.v.get("jwk")
    if not isinstance(jwk_v, JObject):
        fail("proof header: jwk object")
    # Closed OKP members {crv, kty, x}; reject any extra member (incl. private d).
    jwk_v = _require_object_exact(jwk_v, ["crv", "kty", "x"], "proof jwk")
    _require_string_lit(jwk_v, "crv", "Ed25519", "proof jwk crv")
    _require_string_lit(jwk_v, "kty", "OKP", "proof jwk kty")
    x_v = jwk_v.v.get("x")
    if not isinstance(x_v, JString):
        fail("proof jwk: x string")
    raw_key = base64url_decode(x_v.v)
    if len(raw_key) != 32:
        fail("proof jwk: x width")
    tp = thumbprint_raw(jwk_from_public_key(raw_key))
    return tp, raw_key


def _parse_anchor_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = json_decode(seg.protected_bytes, bounds)
    h = _require_object_exact(h, ["alg", "typ", "kid"], "anchor header")
    _require_string_lit(h, "alg", ALG, "anchor header alg")
    _require_string_lit(h, "typ", ANCHOR_TYP, "anchor header typ")
    return _require_kid(h, bounds)


def _parse_transition_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = json_decode(seg.protected_bytes, bounds)
    h = _require_object_exact(h, ["alg", "typ", "kid"], "transition header")
    _require_string_lit(h, "alg", ALG, "transition header alg")
    _require_string_lit(h, "typ", TRANSITION_TYP, "transition header typ")
    return _require_kid(h, bounds)


def _require_kid(h: JObject, bounds: Bounds) -> str:
    kid_v = h.v.get("kid")
    if not isinstance(kid_v, JString):
        fail("header: kid string")
    b = kid_v.v
    if not (1 <= len(b) <= bounds_resolve(bounds, "kid_bytes")):
        fail("header: kid bytes")
    s = utf8_str(b)
    if _KID_CHARSET.match(s) is None:
        fail("header: kid charset")
    return s


def _require_object_exact(v: Tagged, keys: list[str], ctx: str) -> JObject:
    """Validate that ``v`` is a JObject with exactly ``keys`` members; return it narrowed.

    Returns the narrowed ``JObject`` so callers do not need a separate isinstance check (Python has
    no ``asserts x is T`` type-guard, so the narrowing flows through the return value).
    """
    if not isinstance(v, JObject):
        fail(f"{ctx}: object")
    got = ",".join(sorted(v.v.keys()))
    want = ",".join(sorted(keys))
    if got != want:
        fail(f"{ctx}: closed members")
    return v


def _require_string_lit(obj: JObject, key: str, lit: str, ctx: str) -> None:
    v = obj.v.get(key)
    if v is None or not isinstance(v, JString) or utf8_str(v.v) != lit:
        fail(f"{ctx}: {key}={lit}")


# StringOrURI (RFC 7519 §2; mirrors the official valid_uri? / StringOrURI). A bare string with no
# ':' is always valid; an opaque scheme `a:b` (no `//`) is valid; a `//` authority is structurally
# validated. This is REQUIRED to reject the corpus's `ht tp://x` and `http://a:b` cases.
def _is_string_or_uri(s: str) -> bool:
    if not _is_well_formed(s):
        return False
    colon = s.find(":")
    if colon == -1:
        return True  # bare string: always a StringOrURI
    scheme = s[:colon]
    if re.match(r"^[A-Za-z][A-Za-z0-9+\-.]*$", scheme) is None:
        return False
    # uri_bytes shape: unreserved + reserved punctuation, or a %HH escape.
    if re.match(r"^(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*$", s) is None:
        return False
    rest = s[colon + 1:]
    if not rest.startswith("//"):
        return True  # opaque / path-rootless: no authority to validate.
    return _valid_uri_authority(rest[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0])


def _valid_uri_authority(authority: str) -> bool:
    at = authority.find("@")
    hostport = authority if at == -1 else authority[at + 1:]
    if "@" in hostport:
        return False  # a second @ lands in the host — invalid.
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return False  # unterminated IPv6 literal.
        if not _is_ipv6(hostport[1:close]):
            return False
        suffix = hostport[close + 1:]
        return suffix == "" or re.match(r"^:\d*$", suffix) is not None
    if "[" in hostport or "]" in hostport:
        return False  # stray bracket in host.
    if hostport.count(":") > 1:
        return False  # host/port ambiguity.
    sep = hostport.rfind(":")
    return sep == -1 or re.match(r"^\d*$", hostport[sep + 1:]) is not None


def _is_ipv6(literal: str) -> bool:
    return re.match(r"^[0-9A-Fa-f:.]+$", literal) is not None


def _is_well_formed(s: str) -> bool:
    # A well-formed Unicode string has no unpaired surrogates. Python str CAN carry lone surrogates
    # (e.g. a caller-supplied chain_id with '\ud800'); re-encoding to UTF-8 rejects them. For strings
    # that came through json_decode, the unpaired-surrogate case was already rejected at the escape
    # level — this check is the defense for direct (non-JSON) inputs like producer fields.
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


# StringOrURI claim: non-empty, ≤ identifier_bytes, well-formed, valid StringOrURI.
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


def _require_uuid(v: Tagged | None, key: str) -> str:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} uuid string")
    s = utf8_str(v.v)
    if _UUID_RE.match(s) is None:
        fail(f"claim: {key} uuid")
    return s


def _require_b64url_n(v: Tagged | None, key: str, n: int) -> bytes:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} b64url string")
    raw = base64url_decode(v.v)
    if len(raw) != n:
        fail(f"claim: {key} width")
    return raw


def _require_operation(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} operation string")
    b = v.v
    if not (1 <= len(b) <= bounds_resolve(bounds, "operation_bytes")):
        fail(f"claim: {key} operation bytes")
    s = utf8_str(b)
    if _OPERATION_PRINTABLE.match(s) is None:
        fail(f"claim: {key} operation printable ASCII")
    return s


def _require_method(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} method string")
    b = v.v
    if not (1 <= len(b) <= bounds_resolve(bounds, "method_bytes")):
        fail(f"claim: {key} method bytes")
    s = utf8_str(b)
    if _METHOD_TOKEN.match(s) is None:
        fail(f"claim: {key} method token")
    return s


def _require_normalized_uri(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        fail(f"claim: {key} uri string")
    b = v.v
    if not (1 <= len(b) <= bounds_resolve(bounds, "uri_bytes")):
        fail(f"claim: {key} uri bytes")
    s = utf8_str(b)
    if not s.lower().startswith("https://"):
        fail(f"claim: {key} https scheme")
    norm = uri_normalize(b)
    if not isinstance(norm, Ok):
        fail(f"claim: {key} uri normalized")
    if utf8_str(norm.value) != s:
        fail(f"claim: {key} uri pre-normalized")
    return s


def _validate_grant_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    pobj = _require_object_exact(p, ["v", "iss", "jti", "aud", "iat", "nbf", "exp", "cnf", "operations"], "grant payload")
    v_v = pobj.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("grant: v=1")
    ops_v = pobj.v["operations"]
    if not isinstance(ops_v, JArray):
        fail("grant: operations array")
    if not (1 <= len(ops_v.v) <= bounds_resolve(bounds, "operations")):
        fail("grant: operations count")
    names: set[str] = set()
    for op in ops_v.v:
        op_obj = _require_object_exact(op, ["name", "selectors"], "grant operation")
        name = _require_operation(op_obj.v.get("name"), "operation name", bounds)
        if name in names:
            fail("grant: operation name unique")
        names.add(name)
        sels = op_obj.v["selectors"]
        if not isinstance(sels, JArray):
            fail("grant: selectors array")
        if not (1 <= len(sels.v) <= bounds_resolve(bounds, "selectors")):
            fail("grant: selectors count")
        for s in sels.v:
            parse_selector(s, bounds)


def _extract_audience(v: Tagged | None, bounds: Bounds = MAXIMUM_BOUNDS) -> list[str]:
    if v is None:
        fail("claim: aud")
    if isinstance(v, JString):
        s = utf8_str(v.v)
        b = str_utf8(s)
        if not (1 <= len(b) <= bounds_resolve(bounds, "identifier_bytes")):
            fail("claim: aud bytes")
        if not _is_string_or_uri(s):
            fail("claim: aud string-or-uri")
        return [s]
    if isinstance(v, JArray):
        if not (1 <= len(v.v) <= bounds_resolve(bounds, "audiences")):
            fail("claim: aud count")
        seen: set[str] = set()
        out: list[str] = []
        for a in v.v:
            if not isinstance(a, JString):
                fail("claim: aud string")
            s = utf8_str(a.v)
            b = str_utf8(s)
            if not (1 <= len(b) <= bounds_resolve(bounds, "identifier_bytes")):
                fail("claim: aud member bytes")
            if not _is_string_or_uri(s):
                fail("claim: aud member string-or-uri")
            if s in seen:
                fail("claim: aud unique")
            seen.add(s)
            out.append(s)
        return out
    raise invalid_error("claim: aud shape")


def _validate_proof_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    if not isinstance(p, JObject):
        fail("proof payload: object")
    has_nonce = "nonce" in p.v
    keys = (
        ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req", "nonce"]
        if has_nonce
        else ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"]
    )
    p = _require_object_exact(p, keys, "proof payload")
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("proof: v=1")
    _require_string_or_uri(p.v.get("jti"), "jti", bounds)
    _require_method(p.v.get("htm"), "htm", bounds)
    _require_normalized_uri(p.v.get("htu"), "htu", bounds)
    _require_int(p.v.get("iat"), "iat")
    _require_uuid(p.v.get("ba_inv"), "ba_inv")
    _require_operation(p.v.get("ba_op"), "ba_op", bounds)
    _require_b64url_n(p.v.get("ath"), "ath", 32)
    _require_b64url_n(p.v.get("ba_req"), "ba_req", 32)
    if has_nonce:
        n = p.v["nonce"]
        if not isinstance(n, JString):
            fail("proof: nonce string")
        ns = utf8_str(n.v)
        nb = str_utf8(ns)
        if not (1 <= len(nb) <= bounds_resolve(bounds, "nonce_bytes")):
            fail("proof: nonce bytes")


def _validate_anchor_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    p = _require_object_exact(
        p,
        ["anchor_id", "anchored_at", "chain_hash", "chain_id", "key_fingerprint", "sequence", "v"],
        "anchor payload",
    )
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("anchor: v=1")
    _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", bounds)
    _require_int(p.v.get("anchored_at"), "anchored_at")
    _require_string_or_uri(p.v.get("chain_id"), "chain_id", bounds)
    _require_int(p.v.get("sequence"), "sequence")
    _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)


def _validate_transition_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    p = _require_object_exact(
        p,
        [
            "chain_id", "effective_at", "from_key_fingerprint", "to_key_fingerprint",
            "to_key_id", "transition_id", "v",
        ],
        "transition payload",
    )
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("transition: v=1")
    _require_string_or_uri(p.v.get("transition_id"), "transition_id", bounds)
    _require_string_or_uri(p.v.get("chain_id"), "chain_id", bounds)
    _require_int(p.v.get("effective_at"), "effective_at")
    _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    to_key_id = p.v["to_key_id"]
    if not isinstance(to_key_id, JString):
        fail("transition: to_key_id string")
    s = utf8_str(to_key_id.v)
    if not (1 <= len(s) <= bounds_resolve(bounds, "kid_bytes")):
        fail("transition: to_key_id bytes")
    if _KID_CHARSET.match(s) is None:
        fail("transition: to_key_id charset")


def _in_window(time: int, key: HistoricalPublicKey) -> bool:
    return key.valid_from <= time and (key.valid_before is None or time < key.valid_before)


def _bytes_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b, strict=True):
        diff |= x ^ y
    return diff == 0


_T = TypeVar("_T")


# --- the 17 façade functions ---


def _trying(fn: Callable[[], _T]) -> Result[_T]:
    """Run a thunk that may raise InvalidError; convert to Result. Any NON-InvalidError propagates."""
    try:
        return Ok(fn())
    except InvalidError:
        return err()


# 1. untrusted_key_locator (protocol-v1.md § Untrusted key locator).
def untrusted_key_locator(compact: bytes, bounds: Bounds | None = None) -> Result[KeyLocator]:
    return _trying(lambda: _untrusted_key_locator_body(compact, bounds))


def _untrusted_key_locator_body(compact: bytes, bounds: Bounds | None) -> KeyLocator:
    # Cross-vendor #13: the reference (v1.ex:21-34) decodes ONLY the protected segment — payload and
    # signature are NOT decoded, interpreted, or independently size-checked. parse_compact decodes
    # all three, so a compact with a valid protected grant header but non-canonical payload/signature
    # bytes was wrongly rejected. Mirror the reference: split into exactly 3 segments, decode protected
    # only, validate the grant header + kid. (An invalid payload/signature does not affect the kid.)
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    from .facts import KeyLocator

    if len(compact) > bounds_resolve(b, "compact_bytes"):
        fail("key_locator: compact bound")
    # Exactly 3 segments on '.' (a 2- or 4-segment input fails the closed shape).
    parts = compact.split(b".")
    if len(parts) != 3:
        fail("key_locator: three segments")
    protected_text = parts[0]
    if len(protected_text) == 0 or len(parts[1]) == 0 or len(parts[2]) == 0:
        fail("key_locator: empty segment")
    if len(protected_text) > bounds_resolve(b, "encoded_segment_bytes"):
        fail("key_locator: protected bound")
    protected_bytes = base64url_decode(protected_text, bounds_resolve(b, "decoded_segment_bytes"))
    # Cross-vendor re-review Finding 3: thread the caller-resolved bounds into the JSON decode
    # (reference v1.ex:27 Json.decode(header_bytes, bounds) — depth/total_nodes limits honor bounds).
    h = json_decode(protected_bytes, b)
    h = _require_object_exact(h, ["alg", "typ", "kid"], "grant header")
    _require_string_lit(h, "alg", ALG, "grant header alg")
    _require_string_lit(h, "typ", GRANT_TYP, "grant header typ")
    kid_v = h.v.get("kid")
    if not isinstance(kid_v, JString):
        fail("header: kid string")
    if not (1 <= len(kid_v.v) <= bounds_resolve(b, "kid_bytes")):
        fail("header: kid bytes")
    kid = utf8_str(kid_v.v)
    if _KID_CHARSET.match(kid) is None:
        fail("header: kid charset")
    return KeyLocator(key_id=kid)


# 2. decode_grant (REQ1-VERIFY-decode-not-evaluated).
def decode_grant(compact: bytes, bounds: Bounds | None = None) -> Result[GrantDecoded]:
    return _trying(lambda: _decode_grant_body(compact, bounds))


def _decode_grant_body(compact: bytes, bounds: Bounds | None) -> GrantDecoded:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    kid = _parse_grant_header(seg, b)
    p = json_decode(seg.payload_bytes, b)
    _validate_grant_payload(p, b)
    if not isinstance(p, JObject):
        fail("decode_grant: payload object")
    iss = _require_string_or_uri(p.v.get("iss"), "iss", b)
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    aud = _extract_audience(p.v.get("aud"), b)
    iat = _require_int(p.v.get("iat"), "iat")
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if not (iat < exp) or not (nbf < exp):
        fail("grant: times coherent")
    cnf = p.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    from .facts import GrantDecoded

    return GrantDecoded(
        key_id=kid, issuer=iss, grant_id=jti, audiences=tuple(aud),
        issued_at=iat, not_before=nbf, expires_at=exp, holder_thumbprint=jkt,
    )


# 3. decode_proof.
def decode_proof(compact: bytes, bounds: Bounds | None = None) -> Result[ProofDecoded]:
    return _trying(lambda: _decode_proof_body(compact, bounds))


def _decode_proof_body(compact: bytes, bounds: Bounds | None) -> ProofDecoded:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    holder_thumbprint, _ = _parse_proof_header(seg, b)
    p = json_decode(seg.payload_bytes, b)
    _validate_proof_payload(p, b)
    if not isinstance(p, JObject):
        fail("decode_proof: payload object")
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    from .facts import ProofDecoded

    return ProofDecoded(proof_id=jti, holder_thumbprint=holder_thumbprint)


# 4. verify_grant (REQ1-VERIFY-grant-exact, grant-times, no-iat-nbf-order).
def verify_grant(compact: bytes, trusted: TrustedIssuer, expected: ExpectedGrant) -> Result[GrantFacts]:
    return _trying(lambda: _verify_grant_body(compact, trusted, expected))


def _verify_grant_body(compact: bytes, trusted: TrustedIssuer, expected: ExpectedGrant) -> GrantFacts:
    if trusted is None:
        fail("verify_grant: trusted issuer required")
    require(len(trusted.public_key) == 32, "verify_grant: issuer key width")
    # Cross-vendor #19: the reference requires is_integer(evaluation_time) and is_integer(clock_skew)
    # (>= 0) — runtime.ex:522-523. Range-only `< 0` checks accept fractional times.
    if not isinstance(expected.evaluation_time, int):
        fail("verify_grant: integer evaluation time")
    # BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:186) and
    # threads it into validate_expected_grant (clock_skew <= bounds.clock_skew) + every bound-sensitive
    # check below. A caller tightening via expected.bounds now actually takes effect.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    if not isinstance(expected.clock_skew, int) or expected.clock_skew < 0 or expected.clock_skew > bounds_resolve(b, "clock_skew"):
        fail("verify_grant: skew")
    seg = parse_compact(compact, b)
    kid = _parse_grant_header(seg, b)
    if kid != trusted.key_id:
        fail("verify_grant: kid exact")
    p = json_decode(seg.payload_bytes, b)
    _validate_grant_payload(p, b)
    if not isinstance(p, JObject):
        fail("verify_grant: payload object")
    iss = _require_string_or_uri(p.v.get("iss"), "iss", b)
    if iss != expected.issuer:
        fail("verify_grant: issuer exact")
    aud = _extract_audience(p.v.get("aud"), b)
    if expected.audience not in aud:
        fail("verify_grant: audience match")
    iat = _require_int(p.v.get("iat"), "iat")
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if not (iat < exp) or not (nbf < exp):
        fail("verify_grant: times coherent")
    if not (iat <= expected.evaluation_time + expected.clock_skew):
        fail("verify_grant: iat window")
    if not (nbf <= expected.evaluation_time + expected.clock_skew):
        fail("verify_grant: nbf window")
    if not (exp > expected.evaluation_time - expected.clock_skew):
        fail("verify_grant: exp window")
    cnf = p.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    fp = thumbprint_raw(jwk_from_public_key(trusted.public_key))
    key = import_public_key(trusted.public_key, utf8_str(base64url_encode(fp)))
    if not ed25519_verify(seg.signing_input, seg.signature, key):
        fail("verify_grant: signature")
    from .facts import GrantFacts

    return GrantFacts(
        version=VERSION, issuer=iss, grant_id=_require_string_or_uri(p.v.get("jti"), "jti", b),
        issuer_key_fingerprint=fp, holder_thumbprint=jkt, matched_audience=expected.audience,
        issued_at=iat, not_before=nbf, expires_at=exp,
    )


# 5. check_envelope (REQ1-VERIFY-envelope-binding).
def check_envelope(grant_compact: bytes, proof_compact: bytes, expected: ExpectedRequest) -> Result[EnvelopeFacts]:
    return _trying(lambda: _check_envelope_body(grant_compact, proof_compact, expected))


def _check_envelope_body(grant_compact: bytes, proof_compact: bytes, expected: ExpectedRequest) -> EnvelopeFacts:
    t = expected.trusted_issuer
    # Cross-vendor #22: a None trusted_issuer must fail closed, not raise AttributeError on the
    # .public_key deref below. The reference returns {:error,:invalid} for all malformed input.
    if t is None:
        fail("check_envelope: trusted issuer required")
    require(len(t.public_key) == 32, "check_envelope: issuer key width")
    # Cross-vendor #19: the reference requires is_integer(evaluation_time), is_integer(clock_skew)
    # (>= 0), and proof_max_age > 0 (strictly positive) — runtime.ex:522-523,550-551. Range-only
    # `< 0` checks accept fractional times and proof_max_age=0. The signed-time boundary is exact.
    if not isinstance(expected.evaluation_time, int):
        fail("check_envelope: integer evaluation time")
    # BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:204) and
    # threads it into validate_expected_request (clock_skew, proof_max_age) + parse_grant + parse_proof
    # + every bound-sensitive claim check below. A caller tightening via expected.bounds now takes
    # effect across both the grant and the proof.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    if not isinstance(expected.clock_skew, int) or expected.clock_skew < 0 or expected.clock_skew > bounds_resolve(b, "clock_skew"):
        fail("check_envelope: skew")
    if not isinstance(expected.proof_max_age, int) or expected.proof_max_age <= 0 or expected.proof_max_age > bounds_resolve(b, "proof_max_age"):
        fail("check_envelope: proof_max_age")
    # --- verify grant (issuer signature + context) ---
    gseg = parse_compact(grant_compact, b)
    gkid = _parse_grant_header(gseg, b)
    if gkid != t.key_id:
        fail("check_envelope: grant kid")
    gp = json_decode(gseg.payload_bytes, b)
    _validate_grant_payload(gp, b)
    if not isinstance(gp, JObject):
        fail("check_envelope: grant payload")
    giss = _require_string_or_uri(gp.v.get("iss"), "iss", b)
    if giss != expected.issuer:
        fail("check_envelope: issuer")
    gaud = _extract_audience(gp.v.get("aud"), b)
    if expected.audience not in gaud:
        fail("check_envelope: audience")
    giat = _require_int(gp.v.get("iat"), "iat")
    gnbf = _require_int(gp.v.get("nbf"), "nbf")
    gexp = _require_int(gp.v.get("exp"), "exp")
    # Cross-vendor #4: check_envelope must enforce grant-time coherence (iat<exp, nbf<exp), mirroring
    # the reference's coherent_times? (runtime.ex:872-875) which fires at parse time. verify_grant
    # already checks this; check_envelope had its own inline path that omitted it.
    if not (giat < gexp) or not (gnbf < gexp):
        fail("check_envelope: grant times coherent")
    if not (giat <= expected.evaluation_time + expected.clock_skew):
        fail("check_envelope: grant iat")
    if not (gnbf <= expected.evaluation_time + expected.clock_skew):
        fail("check_envelope: grant nbf")
    if not (gexp > expected.evaluation_time - expected.clock_skew):
        fail("check_envelope: grant exp")
    gfp = thumbprint_raw(jwk_from_public_key(t.public_key))
    gkey = import_public_key(t.public_key, utf8_str(base64url_encode(gfp)))
    if not ed25519_verify(gseg.signing_input, gseg.signature, gkey):
        fail("check_envelope: grant signature")
    # --- verify proof (holder signature) ---
    pseg = parse_compact(proof_compact, b)
    holder_thumbprint, holder_key = _parse_proof_header(pseg, b)
    pp = json_decode(pseg.payload_bytes, b)
    _validate_proof_payload(pp, b)
    hkey = import_public_key(holder_key, utf8_str(base64url_encode(holder_thumbprint)))
    if not ed25519_verify(pseg.signing_input, pseg.signature, hkey):
        fail("check_envelope: proof signature")
    if not isinstance(pp, JObject):
        fail("check_envelope: proof payload")
    # ath = SHA-256(ASCII grant compact).
    ath_raw = sha256(grant_compact)
    ath_b64 = utf8_str(base64url_encode(ath_raw))
    pp_ath = pp.v["ath"]
    if not isinstance(pp_ath, JString) or utf8_str(pp_ath.v) != ath_b64:
        fail("check_envelope: ath")
    # Method / URI / invocation / operation bindings.
    htm = _require_method(pp.v.get("htm"), "htm", b)
    if htm != expected.method:
        fail("check_envelope: method")
    htu = _require_normalized_uri(pp.v.get("htu"), "htu", b)
    if htu != expected.target_uri:
        fail("check_envelope: target_uri")
    ba_inv = _require_uuid(pp.v.get("ba_inv"), "ba_inv")
    if ba_inv != expected.invocation_id:
        fail("check_envelope: invocation_id")
    ba_op = _require_operation(pp.v.get("ba_op"), "ba_op", b)
    if ba_op != expected.operation:
        fail("check_envelope: operation")
    # ba_req = request_digest(operation, cast_arguments) (base64url).
    ba_req_raw = compute_request_digest(ba_op, expected.cast_arguments, b)
    ba_req_b64 = utf8_str(base64url_encode(ba_req_raw))
    pp_ba_req = pp.v["ba_req"]
    if not isinstance(pp_ba_req, JString) or utf8_str(pp_ba_req.v) != ba_req_b64:
        fail("check_envelope: ba_req")
    # Proof time window.
    piat = _require_int(pp.v.get("iat"), "iat")
    if not (piat >= expected.evaluation_time - expected.proof_max_age - expected.clock_skew):
        fail("check_envelope: proof iat min")
    if not (piat <= expected.evaluation_time + expected.clock_skew):
        fail("check_envelope: proof iat max")
    # Nonce binding.
    pp_nonce = pp.v.get("nonce")
    if isinstance(expected.nonce, NonceNotRequired):
        if pp_nonce is not None:
            fail("check_envelope: nonce must be absent")
    else:
        if (
            pp_nonce is None
            or not isinstance(pp_nonce, JString)
            or utf8_str(pp_nonce.v) != expected.nonce.value
        ):
            fail("check_envelope: nonce mismatch")
    # Holder thumbprint must match grant cnf.jkt.
    cnf = gp.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    if not _bytes_equal(jkt, holder_thumbprint):
        fail("check_envelope: holder thumbprint")
    # The requested operation must be unique + every selector conjunctively matches.
    ops_v = gp.v.get("operations")
    if ops_v is None or not isinstance(ops_v, JArray):
        fail("check_envelope: operations")
    matching = [
        op for op in ops_v.v
        if isinstance(op, JObject)
        and (name_v := op.v.get("name")) is not None
        and isinstance(name_v, JString)
        and utf8_str(name_v.v) == expected.operation
    ]
    if len(matching) != 1:
        fail("check_envelope: unique operation")
    match_op = matching[0]
    sels_v = match_op.v.get("selectors")
    if sels_v is None or not isinstance(sels_v, JArray):
        fail("check_envelope: selectors")
    for s in sels_v.v:
        sel = parse_selector(s, b)
        if not selector_matches(sel, expected.cast_arguments):
            fail("check_envelope: selector")
    from .facts import EnvelopeFacts

    return EnvelopeFacts(
        version=VERSION, issuer=giss,
        grant_id=_require_string_or_uri(gp.v.get("jti"), "jti", b),
        issuer_key_fingerprint=gfp, holder_thumbprint=holder_thumbprint,
        matched_audience=expected.audience,
        grant_issued_at=giat, grant_not_before=gnbf, grant_expires_at=gexp,
        proof_id=_require_string_or_uri(pp.v.get("jti"), "jti", b),
        invocation_id=ba_inv, operation=ba_op, uri=htu,
        grant_hash=ath_raw, request_hash=ba_req_raw, proof_issued_at=piat,
    )


# 6. request_digest (the façade; returns Ok<raw 32-byte digest> | Err — cross-vendor #21: mirror
# the Elixir {:ok, binary} | {:error, :invalid} and the other 15 façade functions).
def request_digest(operation: str, cast_arguments: Tagged, bounds: Bounds | None = None) -> Result[bytes]:
    return _trying(lambda: compute_request_digest(operation, cast_arguments, bounds if bounds is not None else MAXIMUM_BOUNDS))


# 7. encode_consumption_entry (ADR 0004 § Consumption rows). Returns canonical row bytes + hash.
def encode_consumption_entry(entry: ConsumptionEntry, bounds: Bounds | None = None) -> Result[EncodedConsumptionEntry]:
    return _trying(lambda: _encode_consumption_entry_body(entry, bounds))


def _encode_consumption_entry_body(entry: ConsumptionEntry, bounds: Bounds | None) -> EncodedConsumptionEntry:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    if not isinstance(entry.sequence, int) or isinstance(entry.sequence, bool) or entry.sequence < 1:
        fail("encode_consumption_entry: positive sequence")
    require(len(entry.previous_hash) == 32, "encode_consumption_entry: previous_hash width")
    require(len(entry.commitment) == 32, "encode_consumption_entry: commitment width")
    chain_id_bytes = str_utf8(entry.chain_id)
    if not (1 <= len(chain_id_bytes) <= bounds_resolve(b, "identifier_bytes")):
        fail("encode_consumption_entry: chain_id bytes")
    if not _is_string_or_uri(entry.chain_id):
        fail("encode_consumption_entry: chain_id string-or-uri")
    # Genesis invariant (consumption_chain.ex:123 validate_entry): sequence 1 requires the all-zero
    # predecessor. The verifier re-checks this; the producer rejects pre-signing.
    if entry.sequence == 1 and not _bytes_equal(entry.previous_hash, DEFAULT_HASH):
        fail("encode_consumption_entry: genesis predecessor")
    row_bytes = _canonical_row_bytes_from_id(chain_id_bytes, entry.sequence, entry.previous_hash, entry.commitment, b)
    if len(row_bytes) > bounds_resolve(b, "chain_row_bytes"):
        fail("encode_consumption_entry: chain_row_bytes")
    hash_ = sha256(ROW_PREFIX, row_bytes)
    return EncodedConsumptionEntry(bytes_=row_bytes, hash_=hash_)


def _canonical_row_bytes_from_id(
    chain_id_bytes: bytes, sequence: int, previous_hash: bytes, commitment: bytes, b: Bounds
) -> bytes:
    """The canonical row bytes shared by the producer and the verifier (so the verifier's re-encode
    produces EXACTLY the bytes the producer emits and the chain hash is computed over)."""
    members: dict[str, Tagged] = {
        "chain_id": JString(chain_id_bytes),
        "commitment": JString(str_utf8(utf8_str(base64url_encode(commitment)))),
        "previous": JString(str_utf8(utf8_str(base64url_encode(previous_hash)))),
        "sequence": JInt(sequence),
        "v": JInt(VERSION),
    }
    return jcs_encode(JObject(members), b)


def _canonical_row_bytes(
    chain_id: str, sequence: int, previous_hash: bytes, commitment: bytes, b: Bounds = MAXIMUM_BOUNDS,
) -> bytes:
    return _canonical_row_bytes_from_id(str_utf8(chain_id), sequence, previous_hash, commitment, b)


# 8. check_chain (ADR 0004 § Consumption rows; REQ1-CHAIN-raw-rows-bounds).
def check_chain(chain: ChainInput, expected: ExpectedChain) -> Result[ChainFacts]:
    return _trying(lambda: _check_chain_body(chain, expected))


def _check_chain_body(chain: ChainInput, expected: ExpectedChain) -> ChainFacts:
    # BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (consumption_chain.ex
    # check_chain) and threads it into the row-count bound + every parse_row (chain_row_bytes). A
    # caller tightening via expected.bounds now takes effect.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    if expected.chain_id != chain.chain_id:
        fail("check_chain: chain_id")
    if expected.first_sequence != chain.first_sequence:
        fail("check_chain: first_sequence")
    if expected.last_sequence != chain.last_sequence:
        fail("check_chain: last_sequence")
    if expected.row_count != chain.row_count:
        fail("check_chain: row_count")
    if chain.row_count != len(chain.rows) or chain.row_count < 1:
        fail("check_chain: row count")
    if chain.row_count > bounds_resolve(b, "chain_rows"):
        fail("check_chain: chain_rows bound")
    if chain.last_sequence != chain.first_sequence + chain.row_count - 1:
        fail("check_chain: range")
    # Genesis: firstSequence === 1 requires the all-zero predecessor.
    if chain.first_sequence == 1:
        if not _bytes_equal(expected.previous_hash, DEFAULT_HASH):
            fail("check_chain: genesis predecessor")
    else:
        if not _bytes_equal(expected.previous_hash, chain.previous_hash):
            fail("check_chain: previous_hash")
    previous = expected.previous_hash
    sequence = chain.first_sequence
    for i, row_bytes in enumerate(chain.rows):
        if len(row_bytes) > bounds_resolve(b, "chain_row_bytes"):
            fail(f"check_chain: row {i} bytes")
        row = json_decode(row_bytes, b)
        row = _require_object_exact(row, ["v", "chain_id", "sequence", "previous", "commitment"], f"check_chain row {i}")
        v_v = row.v["v"]
        if not isinstance(v_v, JInt) or v_v.v != VERSION:
            fail(f"check_chain row {i}: v")
        cid_v = row.v["chain_id"]
        if not isinstance(cid_v, JString) or utf8_str(cid_v.v) != chain.chain_id:
            fail(f"check_chain row {i}: chain_id")
        seq_v = row.v["sequence"]
        if not isinstance(seq_v, JInt) or seq_v.v != sequence:
            fail(f"check_chain row {i}: sequence")
        # valid_sequence?: sequence must be strictly positive (> 0). The encode_consumption_entry
        # producer already rejects sequence < 1, but the raw row stream is untrusted input here, so
        # reject sequence 0 at verify time too (mirrors consumption_chain.ex:163 valid_sequence?).
        if seq_v.v < 1:
            fail(f"check_chain row {i}: sequence positive")
        prev_raw = _require_b64url_n(row.v.get("previous"), "previous", 32)
        if not _bytes_equal(prev_raw, previous):
            fail(f"check_chain row {i}: previous link")
        commitment_raw = _require_b64url_n(row.v.get("commitment"), "commitment", 32)
        # Canonical re-encode: the input row bytes MUST byte-equal the canonical re-encoded form
        # (mirrors consumption_chain.ex:96 parse_row `encode(entry).bytes == ^bytes`). This rejects
        # whitespace drift and member-order drift that would otherwise hash to a different chain link.
        re_encoded = _canonical_row_bytes(chain.chain_id, seq_v.v, prev_raw, commitment_raw, b)
        if not _bytes_equal(re_encoded, row_bytes):
            fail(f"check_chain row {i}: canonical")
        previous = sha256(ROW_PREFIX, row_bytes)
        sequence += 1
    if not _bytes_equal(previous, expected.last_hash):
        fail("check_chain: head")
    from .facts import ChainFacts

    return ChainFacts(
        version=VERSION, chain_id=chain.chain_id, first_sequence=chain.first_sequence,
        last_sequence=chain.last_sequence, row_count=chain.row_count,
        previous_hash=chain.previous_hash, last_hash=previous,
    )


# 9. grant_signing_input (the deterministic producer; REQ1-SIGNING-deterministic-produce).
def grant_signing_input(grant: GrantProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    return _trying(lambda: _grant_signing_input_body(grant, bounds))


def _grant_signing_input_body(grant: GrantProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    key_id_bytes = str_utf8(grant.key_id)
    if not (1 <= len(key_id_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("grant_signing_input: key_id bytes")
    if _KID_CHARSET.match(grant.key_id) is None:
        fail("grant_signing_input: key_id charset")
    if not _is_string_or_uri(grant.issuer):
        fail("grant_signing_input: issuer")
    if not _is_string_or_uri(grant.grant_id):
        fail("grant_signing_input: grant_id")
    if not (1 <= len(grant.audiences) <= bounds_resolve(b, "audiences")):
        fail("grant_signing_input: audiences count")
    for a in grant.audiences:
        ab = str_utf8(a)
        if not (1 <= len(ab) <= bounds_resolve(b, "identifier_bytes")):
            fail("grant_signing_input: audience bytes")
        if not _is_string_or_uri(a):
            fail("grant_signing_input: audience string-or-uri")
    if not (isinstance(grant.issued_at, int) and isinstance(grant.not_before, int) and isinstance(grant.expires_at, int)):
        fail("grant_signing_input: integer times")
    jkt_raw = base64url_decode(str_utf8(grant.holder_thumbprint))
    if len(jkt_raw) != 32:
        fail("grant_signing_input: holder_thumbprint width")
    if not (1 <= len(grant.operations) <= bounds_resolve(b, "operations")):
        fail("grant_signing_input: operations count")
    header: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "kid": JString(key_id_bytes),
        "typ": JString(str_utf8(GRANT_TYP)),
    }
    payload = _build_grant_payload(grant, b)
    return SigningInput(
        kind="grant",
        protected_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(header), b)))),
        payload_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(payload, b)))),
    )


def _build_grant_payload(grant: GrantProducer, b: Bounds) -> Tagged:
    aud_members = tuple(JString(str_utf8(a)) for a in grant.audiences)
    ops_members: list[Tagged] = []
    for op in grant.operations:
        name_bytes = str_utf8(op.name)
        if not (1 <= len(name_bytes) <= bounds_resolve(b, "operation_bytes")):
            fail("grant_signing_input: operation name bytes")
        if _OPERATION_PRINTABLE.match(op.name) is None:
            fail("grant_signing_input: operation name charset")
        if not (1 <= len(op.selectors) <= bounds_resolve(b, "selectors")):
            fail("grant_signing_input: selectors count")
        sels = tuple(_selector_to_tagged(s, b) for s in op.selectors)
        op_members: dict[str, Tagged] = {
            "name": JString(name_bytes),
            "selectors": JArray(sels),
        }
        ops_members.append(JObject(op_members))
    cnf_members: dict[str, Tagged] = {"jkt": JString(str_utf8(grant.holder_thumbprint))}
    payload: dict[str, Tagged] = {
        "aud": JArray(tuple(aud_members)),
        "cnf": JObject(cnf_members),
        "exp": JInt(grant.expires_at),
        "iat": JInt(grant.issued_at),
        "iss": JString(str_utf8(grant.issuer)),
        "jti": JString(str_utf8(grant.grant_id)),
        "nbf": JInt(grant.not_before),
        "operations": JArray(tuple(ops_members)),
        "v": JInt(VERSION),
    }
    return JObject(payload)


def _selector_to_tagged(s: SelectorInput, b: Bounds) -> Tagged:
    if s == "all":
        return JObject({"kind": JString(str_utf8("all"))})
    if isinstance(s, Mapping):
        kind = s.get("kind")
        if kind == "all":
            return JObject({"kind": JString(str_utf8("all"))})
        if kind == "equals":
            path = _validate_path(cast("Sequence[str]", s["path"]), b)
            value = cast("Tagged", s["value"])
            _validate_selector_value(value, b)
            return JObject({
                "kind": JString(str_utf8("equals")),
                "path": path,
                "value": value,
            })
        if kind == "one_of":
            path = _validate_path(cast("Sequence[str]", s["path"]), b)
            values = cast("Sequence[Tagged]", s["values"])
            if not (1 <= len(values) <= bounds_resolve(b, "one_of_values")):
                fail("selector: values count")
            for v in values:
                _validate_selector_value(v, b)
            return JObject({
                "kind": JString(str_utf8("one_of")),
                "path": path,
                "values": JArray(tuple(values)),
            })
    raise invalid_error("selector: shape")


def _validate_path(path: Sequence[str], b: Bounds) -> Tagged:
    if not (1 <= len(path) <= bounds_resolve(b, "path_segments")):
        fail("selector: path length")
    segs: list[Tagged] = []
    for seg in path:
        sb = str_utf8(seg)
        if not (1 <= len(sb) <= bounds_resolve(b, "key_bytes")):
            fail("selector: path segment bytes")
        segs.append(JString(sb))
    return JArray(tuple(segs))


def _validate_selector_value(v: Tagged, b: Bounds) -> None:
    _check_node(v, 1, b)


def _check_node(v: Tagged, depth: int, b: Bounds) -> None:
    if depth > bounds_resolve(b, "depth"):
        fail("selector: value depth")
    if isinstance(v, JString):
        if len(v.v) > bounds_resolve(b, "string_bytes"):
            fail("selector: string bytes")
    elif isinstance(v, JInt):
        if abs(v.v) > bounds_resolve(b, "integer_magnitude"):
            fail("selector: int magnitude")
    elif isinstance(v, JFloat):
        if abs(v.v) > bounds_resolve(b, "float_magnitude"):
            fail("selector: float magnitude")
    elif isinstance(v, JArray):
        if len(v.v) > bounds_resolve(b, "array_items"):
            fail("selector: array items")
        for item in v.v:
            _check_node(item, depth + 1, b)
    elif isinstance(v, JObject):
        if len(v.v) > bounds_resolve(b, "object_members"):
            fail("selector: object members")
        for val in v.v.values():
            _check_node(val, depth + 1, b)


# 10. proof_signing_input (REQ1-SIGNING-deterministic-produce).
def proof_signing_input(proof: ProofProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    return _trying(lambda: _proof_signing_input_body(proof, bounds))


def _proof_signing_input_body(proof: ProofProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    require(len(proof.holder_public_key) == 32, "proof_signing_input: holder key width")
    if not _is_string_or_uri(proof.proof_id):
        fail("proof_signing_input: proof_id")
    method_bytes = str_utf8(proof.method)
    if not (1 <= len(method_bytes) <= bounds_resolve(b, "method_bytes")):
        fail("proof_signing_input: method bytes")
    if _METHOD_TOKEN.match(proof.method) is None:
        fail("proof_signing_input: method token")
    htu_norm = uri_normalize(str_utf8(proof.target_uri), b)
    if not isinstance(htu_norm, Ok):
        fail("proof_signing_input: htu")
    if utf8_str(htu_norm.value) != proof.target_uri:
        fail("proof_signing_input: htu pre-normalized")
    if not isinstance(proof.issued_at, int) or isinstance(proof.issued_at, bool):
        fail("proof_signing_input: integer iat")
    if _UUID_RE.match(proof.invocation_id) is None:
        fail("proof_signing_input: invocation_id")
    op_bytes = str_utf8(proof.operation)
    if not (1 <= len(op_bytes) <= bounds_resolve(b, "operation_bytes")):
        fail("proof_signing_input: operation bytes")
    if _OPERATION_PRINTABLE.match(proof.operation) is None:
        fail("proof_signing_input: operation charset")
    if proof.nonce is not None:
        if not _is_well_formed(proof.nonce):
            fail("proof_signing_input: nonce well-formed")
        nb = str_utf8(proof.nonce)
        if not (1 <= len(nb) <= bounds_resolve(b, "nonce_bytes")):
            fail("proof_signing_input: nonce bytes")
    jwk = jwk_from_public_key(proof.holder_public_key)
    header_members: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "jwk": _jwk_to_tagged(jwk),
        "typ": JString(str_utf8(PROOF_TYP)),
    }
    ath_raw = sha256(proof.grant_compact)
    ba_req_raw = compute_request_digest(proof.operation, proof.cast_arguments, b)
    payload_members: dict[str, Tagged] = {
        "ath": JString(str_utf8(utf8_str(base64url_encode(ath_raw)))),
        "ba_inv": JString(str_utf8(proof.invocation_id)),
        "ba_op": JString(op_bytes),
        "ba_req": JString(str_utf8(utf8_str(base64url_encode(ba_req_raw)))),
        "htm": JString(method_bytes),
        "htu": JString(str_utf8(proof.target_uri)),
        "iat": JInt(proof.issued_at),
        "jti": JString(str_utf8(proof.proof_id)),
        "v": JInt(VERSION),
    }
    if proof.nonce is not None:
        payload_members["nonce"] = JString(str_utf8(proof.nonce))
    return SigningInput(
        kind="proof",
        protected_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(header_members), b)))),
        payload_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(payload_members), b)))),
    )


def _jwk_to_tagged(jwk: OkpPublic) -> Tagged:
    members: dict[str, Tagged] = {
        "crv": JString(str_utf8(jwk.crv)),
        "kty": JString(str_utf8(jwk.kty)),
        "x": JString(str_utf8(jwk.x)),
    }
    return JObject(members)


# 11. assemble_compact (REQ1-VERIFY-no-signer-callback). Re-exported from compact.


# 12. boundary_anchor_signing_input (ADR 0004 § Boundary anchors).
def boundary_anchor_signing_input(anchor: BoundaryAnchorProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    return _trying(lambda: _boundary_anchor_signing_input_body(anchor, bounds))


def _boundary_anchor_signing_input_body(anchor: BoundaryAnchorProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    key_id_bytes = str_utf8(anchor.key_id)
    if not (1 <= len(key_id_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("anchor_signing_input: key_id bytes")
    if _KID_CHARSET.match(anchor.key_id) is None:
        fail("anchor_signing_input: key_id charset")
    if not _is_string_or_uri(anchor.anchor_id):
        fail("anchor_signing_input: anchor_id")
    if not _is_string_or_uri(anchor.chain_id):
        fail("anchor_signing_input: chain_id")
    if not isinstance(anchor.anchored_at, int) or isinstance(anchor.anchored_at, bool):
        fail("anchor_signing_input: integer anchored_at")
    if not isinstance(anchor.sequence, int) or isinstance(anchor.sequence, bool) or anchor.sequence < 0:
        fail("anchor_signing_input: non-negative sequence")
    require(len(anchor.chain_hash) == 32, "anchor_signing_input: chain_hash width")
    require(len(anchor.public_key) == 32, "anchor_signing_input: public_key width")
    # Genesis invariant (boundary_anchor_codec.ex:185-189 valid_anchor_binding?): sequence 0 is the
    # chain root and requires the all-zero chain_hash. The verifier re-checks this; the producer
    # rejects pre-signing so a mis-bound genesis anchor cannot be minted.
    if anchor.sequence == 0 and not _bytes_equal(anchor.chain_hash, DEFAULT_HASH):
        fail("anchor_signing_input: genesis chain_hash")
    header: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "kid": JString(key_id_bytes),
        "typ": JString(str_utf8(ANCHOR_TYP)),
    }
    fp = thumbprint_raw(jwk_from_public_key(anchor.public_key))
    payload: dict[str, Tagged] = {
        "anchor_id": JString(str_utf8(anchor.anchor_id)),
        "anchored_at": JInt(anchor.anchored_at),
        "chain_hash": JString(str_utf8(utf8_str(base64url_encode(anchor.chain_hash)))),
        "chain_id": JString(str_utf8(anchor.chain_id)),
        "key_fingerprint": JString(str_utf8(utf8_str(base64url_encode(fp)))),
        "sequence": JInt(anchor.sequence),
        "v": JInt(VERSION),
    }
    return SigningInput(
        kind="boundary_anchor",
        protected_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(header), b)))),
        payload_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(payload), b)))),
    )


# 13. key_transition_signing_input (ADR 0004 § Authenticated key transitions).
def key_transition_signing_input(t: KeyTransitionProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    return _trying(lambda: _key_transition_signing_input_body(t, bounds))


def _key_transition_signing_input_body(t: KeyTransitionProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    require(len(t.current_public_key) == 32 and len(t.next_public_key) == 32, "transition_signing_input: key width")
    if _bytes_equal(t.current_public_key, t.next_public_key):
        fail("transition_signing_input: distinct keys")
    current_key_id_bytes = str_utf8(t.current_key_id)
    if not (1 <= len(current_key_id_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("transition_signing_input: current_key_id bytes")
    if _KID_CHARSET.match(t.current_key_id) is None:
        fail("transition_signing_input: current_key_id charset")
    next_key_id_bytes = str_utf8(t.next_key_id)
    if not (1 <= len(next_key_id_bytes) <= bounds_resolve(b, "kid_bytes")):
        fail("transition_signing_input: next_key_id bytes")
    if _KID_CHARSET.match(t.next_key_id) is None:
        fail("transition_signing_input: next_key_id charset")
    if not _is_string_or_uri(t.transition_id):
        fail("transition_signing_input: transition_id")
    if not _is_string_or_uri(t.chain_id):
        fail("transition_signing_input: chain_id")
    if not isinstance(t.effective_at, int) or isinstance(t.effective_at, bool):
        fail("transition_signing_input: integer effective_at")
    header: dict[str, Tagged] = {
        "alg": JString(str_utf8(ALG)),
        "kid": JString(current_key_id_bytes),
        "typ": JString(str_utf8(TRANSITION_TYP)),
    }
    from_fp = thumbprint_raw(jwk_from_public_key(t.current_public_key))
    to_fp = thumbprint_raw(jwk_from_public_key(t.next_public_key))
    payload: dict[str, Tagged] = {
        "chain_id": JString(str_utf8(t.chain_id)),
        "effective_at": JInt(t.effective_at),
        "from_key_fingerprint": JString(str_utf8(utf8_str(base64url_encode(from_fp)))),
        "to_key_fingerprint": JString(str_utf8(utf8_str(base64url_encode(to_fp)))),
        "to_key_id": JString(next_key_id_bytes),
        "transition_id": JString(str_utf8(t.transition_id)),
        "v": JInt(VERSION),
    }
    return SigningInput(
        kind="key_transition",
        protected_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(header), b)))),
        payload_segment=str_utf8(utf8_str(base64url_encode(jcs_encode(JObject(payload), b)))),
    )


# 14. encode_anchored_export (ADR 0004 § Anchored export; REQ1-EXPORT-input-shape).
def encode_anchored_export(input_: AnchoredExportInput, expected: ExpectedExport) -> Result[EncodedAnchoredExport]:
    return _trying(lambda: _encode_anchored_export_body(input_, expected))


def _encode_anchored_export_body(input_: AnchoredExportInput, expected: ExpectedExport) -> EncodedAnchoredExport:
    # Validate inputs BEFORE framing (mirrors anchored_export_codec.ex:33-57 encode →
    # validate_expected_export + parse_expected_transitions + validate_expected_key_path). The parser
    # would reject the bytes a too-large input would produce; the producer rejects earlier.
    # BAP-09 #10/#11: resolve expected.bounds once and thread it through the encode-time bounds
    # checks so a caller tightening via expected.bounds takes effect (matches verify_anchored_export).
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    _validate_export_inputs(input_, expected, b)
    header_bytes = _build_archive_header(input_, expected.chain, b)
    parts = [ARCHIVE_PREFIX, _frame(header_bytes), _frame(input_.start_anchor)]
    parts.extend(_frame(t) for t in input_.transitions)
    parts.extend(_frame(r) for r in input_.rows)
    parts.append(_frame(input_.end_anchor))
    archive = b"".join(parts)
    if len(archive) > bounds_resolve(b, "archive_bytes"):
        fail("encode_anchored_export: archive_bytes")
    return EncodedAnchoredExport(archive=archive, digest=sha256(archive))


def _validate_export_inputs(input_: AnchoredExportInput, expected: ExpectedExport, b: Bounds) -> None:
    """Encode-time input validation (mirrors anchored_export_codec.ex validate_expected_export +
    validate_chunks): the transition count, chain range coherence, anchor bindings, and the key-path
    invariants must hold before framing. The parser enforces all of this at verify time; the producer
    must not mint bytes its own consumer would reject."""
    chain = expected.chain
    # Transition count bound (anchored_export_codec.ex:360 transition_count <= bounds.key_transitions).
    if len(input_.transitions) > bounds_resolve(b, "key_transitions"):
        fail("encode_anchored_export: transition_count bound")
    if len(expected.transitions) != len(input_.transitions):
        fail("encode_anchored_export: transition count")
    # Anchor bindings (anchored_export_codec.ex:364-371): start spans first_sequence-1 with the
    # chain's previous_hash; end spans last_sequence with the chain's last_hash.
    if expected.start_anchor.sequence != chain.first_sequence - 1:
        fail("encode_anchored_export: start sequence")
    if not _bytes_equal(expected.start_anchor.chain_hash, chain.previous_hash):
        fail("encode_anchored_export: start chain_hash")
    if expected.end_anchor.sequence != chain.last_sequence:
        fail("encode_anchored_export: end sequence")
    if not _bytes_equal(expected.end_anchor.chain_hash, chain.last_hash):
        fail("encode_anchored_export: end chain_hash")
    # All transitions + both anchors carry the chain_id (anchored_export_codec.ex:361-363).
    for i, t in enumerate(expected.transitions):
        if t.chain_id != chain.chain_id:
            fail(f"encode_anchored_export: transition {i} chain_id")
    if expected.start_anchor.chain_id != chain.chain_id:
        fail("encode_anchored_export: start chain_id")
    if expected.end_anchor.chain_id != chain.chain_id:
        fail("encode_anchored_export: end chain_id")
    # Key-path invariants (validate_expected_key_path): the no-transition path requires start==end key
    # identity with a chronologically-non-decreasing end anchored_at; the transition path requires strictly
    # increasing effective_at with no fingerprint cycle. Mirrored by _validate_key_path.
    _validate_key_path(expected.start_anchor, expected.transitions, expected.end_anchor)


def _build_archive_header(input_: AnchoredExportInput, chain: ExpectedChain, b: Bounds) -> bytes:
    if chain.chain_id != input_.chain_id:
        fail("encode_anchored_export: chain_id")
    if chain.first_sequence != input_.first_sequence:
        fail("encode_anchored_export: first_sequence")
    if chain.last_sequence != input_.last_sequence:
        fail("encode_anchored_export: last_sequence")
    if chain.row_count != input_.row_count:
        fail("encode_anchored_export: row_count")
    members: dict[str, Tagged] = {
        "chain_id": JString(str_utf8(chain.chain_id)),
        "first_sequence": JInt(chain.first_sequence),
        "last_hash": JString(str_utf8(utf8_str(base64url_encode(chain.last_hash)))),
        "last_sequence": JInt(chain.last_sequence),
        "previous_hash": JString(str_utf8(utf8_str(base64url_encode(chain.previous_hash)))),
        "row_count": JInt(chain.row_count),
        "transition_count": JInt(len(input_.transitions)),
        "v": JInt(VERSION),
    }
    header_bytes = jcs_encode(JObject(members), b)
    if len(header_bytes) > bounds_resolve(b, "archive_header_bytes"):
        fail("encode_anchored_export: header bytes")
    return header_bytes


def _frame(data: bytes) -> bytes:
    """UINT32_BE(len) || bytes — the archive framing (ADR 0004 § Anchored export)."""
    if len(data) == 0:
        fail("archive: zero-length frame")
    v = len(data)
    return bytes([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]) + data


# 15. verify_historical_anchor (ADR 0004 § Boundary anchors; protocol-v1.md § Historical anchor).
def verify_historical_anchor(compact: bytes, key: HistoricalPublicKey, expected: ExpectedAnchor) -> Result[AnchorFacts]:
    return _trying(lambda: _verify_historical_anchor_body(compact, key, expected))


def _verify_historical_anchor_body(compact: bytes, key: HistoricalPublicKey, expected: ExpectedAnchor) -> AnchorFacts:
    require(len(key.public_key) == 32, "verify_historical_anchor: key width")
    # BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check, as
    # the reference does (boundary_anchor_codec.ex parses the compact + payload under bounds).
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    kid = _parse_anchor_header(seg, b)
    if kid != key.key_id:
        fail("verify_historical_anchor: kid")
    if expected.key_id != key.key_id:
        fail("verify_historical_anchor: expected key id")
    p = json_decode(seg.payload_bytes, b)
    _validate_anchor_payload(p, b)
    if not isinstance(p, JObject):
        fail("verify_historical_anchor: payload object")
    anchor_id = _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", b)
    if anchor_id != expected.anchor_id:
        fail("verify_historical_anchor: anchor_id")
    anchored_at = _require_int(p.v.get("anchored_at"), "anchored_at")
    if anchored_at != expected.anchored_at:
        fail("verify_historical_anchor: anchored_at")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        fail("verify_historical_anchor: chain_id")
    sequence = _require_int(p.v.get("sequence"), "sequence")
    if sequence != expected.sequence:
        fail("verify_historical_anchor: sequence")
    chain_hash = _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    if not _bytes_equal(chain_hash, expected.chain_hash):
        fail("verify_historical_anchor: chain_hash")
    key_fp_raw = _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)
    if not _bytes_equal(key_fp_raw, expected.key_fingerprint):
        fail("verify_historical_anchor: key_fingerprint")
    if expected.sequence == 0 and not _bytes_equal(expected.chain_hash, DEFAULT_HASH):
        fail("verify_historical_anchor: genesis hash")
    derived_fp = thumbprint_raw(jwk_from_public_key(key.public_key))
    if not _bytes_equal(derived_fp, expected.key_fingerprint):
        fail("verify_historical_anchor: fingerprint")
    if not _in_window(anchored_at, key):
        fail("verify_historical_anchor: window")
    pk = import_public_key(key.public_key, utf8_str(base64url_encode(derived_fp)))
    if not ed25519_verify(seg.signing_input, seg.signature, pk):
        fail("verify_historical_anchor: signature")
    from .facts import AnchorFacts

    return AnchorFacts(
        version=VERSION, anchor_id=anchor_id, anchored_at=anchored_at, chain_id=chain_id,
        sequence=sequence, chain_hash=chain_hash, key_fingerprint=key_fp_raw,
    )


# 16. verify_key_transition (ADR 0004 § Authenticated key transitions).
def verify_key_transition(compact: bytes, old_key: HistoricalPublicKey, new_key: HistoricalPublicKey, expected: ExpectedKeyTransition) -> Result[KeyTransitionFacts]:
    return _trying(lambda: _verify_key_transition_body(compact, old_key, new_key, expected))


def _verify_key_transition_body(compact: bytes, old_key: HistoricalPublicKey, new_key: HistoricalPublicKey, expected: ExpectedKeyTransition) -> KeyTransitionFacts:
    require(len(old_key.public_key) == 32 and len(new_key.public_key) == 32, "verify_key_transition: key width")
    if _bytes_equal(old_key.public_key, new_key.public_key):
        fail("verify_key_transition: distinct keys")
    # BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    kid = _parse_transition_header(seg, b)
    if kid != old_key.key_id:
        fail("verify_key_transition: kid")
    if expected.current_key_id != old_key.key_id:
        fail("verify_key_transition: current key id")
    if expected.next_key_id != new_key.key_id:
        fail("verify_key_transition: next key id")
    p = json_decode(seg.payload_bytes, b)
    _validate_transition_payload(p, b)
    if not isinstance(p, JObject):
        fail("verify_key_transition: payload object")
    transition_id = _require_string_or_uri(p.v.get("transition_id"), "transition_id", b)
    if transition_id != expected.transition_id:
        fail("verify_key_transition: transition_id")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        fail("verify_key_transition: chain_id")
    effective_at = _require_int(p.v.get("effective_at"), "effective_at")
    if effective_at != expected.effective_at:
        fail("verify_key_transition: effective_at")
    from_fp_raw = _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    if not _bytes_equal(from_fp_raw, expected.current_key_fingerprint):
        fail("verify_key_transition: from fp")
    to_fp_raw = _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    if not _bytes_equal(to_fp_raw, expected.next_key_fingerprint):
        fail("verify_key_transition: to fp")
    to_key_id_v = p.v["to_key_id"]
    if not isinstance(to_key_id_v, JString) or utf8_str(to_key_id_v.v) != expected.next_key_id:
        fail("verify_key_transition: to_key_id")
    derived_from = thumbprint_raw(jwk_from_public_key(old_key.public_key))
    if not _bytes_equal(derived_from, expected.current_key_fingerprint):
        fail("verify_key_transition: current fp")
    derived_to = thumbprint_raw(jwk_from_public_key(new_key.public_key))
    if not _bytes_equal(derived_to, expected.next_key_fingerprint):
        fail("verify_key_transition: next fp")
    if not _in_window(effective_at, old_key):
        fail("verify_key_transition: current window")
    if not _in_window(effective_at, new_key):
        fail("verify_key_transition: next window")
    pk = import_public_key(old_key.public_key, utf8_str(base64url_encode(derived_from)))
    if not ed25519_verify(seg.signing_input, seg.signature, pk):
        fail("verify_key_transition: signature")
    from .facts import KeyTransitionFacts

    return KeyTransitionFacts(
        version=VERSION, transition_id=transition_id, chain_id=chain_id, effective_at=effective_at,
        current_key_fingerprint=from_fp_raw, next_key_fingerprint=to_fp_raw,
    )


# 17. verify_anchored_export (ADR 0004 § Anchored export; REQ1-EXPORT-complete-scan).
def verify_anchored_export(archived: ArchivedObject, key_chain: HistoricalKeyChain, expected: ExpectedExport) -> Result[AnchoredExportFacts]:
    return _trying(lambda: _verify_anchored_export_body(archived, key_chain, expected))


def _verify_anchored_export_body(archived: ArchivedObject, key_chain: HistoricalKeyChain, expected: ExpectedExport) -> AnchoredExportFacts:
    # BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once
    # (anchored_export_codec.ex:84-185) and threads it into validate_chunks (archive_chunks,
    # archive_bytes), parse_archive (frame reads), and every row check. The inner anchors/transitions
    # carry their own bounds (used by their own compact parsers). A caller tightening via
    # expected.bounds now takes effect.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    # Validate the chunk list BEFORE concatenation (mirrors anchored_export_codec.ex:101-102,333-342
    # validate_chunks): each chunk nonempty, count < archive_chunks, total ≤ archive_bytes. Hashing
    # happens after the shape is validated.
    _validate_chunks(archived.chunks, b)
    archive = b"".join(archived.chunks)
    if len(archive) <= len(ARCHIVE_PREFIX):
        fail("verify_anchored_export: archive too short")
    if len(archive) > bounds_resolve(b, "archive_bytes"):
        fail("verify_anchored_export: byte bound")
    digest = sha256(archive)
    if not _bytes_equal(digest, expected.digest):
        fail("verify_anchored_export: digest")
    if archived.version != expected.object_version:
        fail("verify_anchored_export: object version")
    parsed = _parse_archive(archive, b)
    # Header canonical equality.
    header_members: dict[str, Tagged] = {
        "chain_id": JString(str_utf8(expected.chain.chain_id)),
        "first_sequence": JInt(expected.chain.first_sequence),
        "last_hash": JString(str_utf8(utf8_str(base64url_encode(expected.chain.last_hash)))),
        "last_sequence": JInt(expected.chain.last_sequence),
        "previous_hash": JString(str_utf8(utf8_str(base64url_encode(expected.chain.previous_hash)))),
        "row_count": JInt(expected.chain.row_count),
        "transition_count": JInt(len(expected.transitions)),
        "v": JInt(VERSION),
    }
    expected_header_bytes = jcs_encode(JObject(header_members), b)
    if not _bytes_equal(parsed.header_bytes, expected_header_bytes):
        fail("verify_anchored_export: header")
    # Verify start + end anchors + each transition against the ordered historical key chain.
    # A key chain of N keys spans N-1 transitions (keys[0]→[1], ..., keys[N-2]→[N-1]); a 1-key,
    # 0-transition archive is the no-rollover case the reference accepts (validate_historical_key_shapes
    # requires keys == transitions+1, with no minimum). The exact-count check below is the gate.
    _verify_anchor_compact(parsed.start, key_chain.keys[0], expected.start_anchor, "verify_anchored_export start")
    _verify_anchor_compact(parsed.end, key_chain.keys[-1], expected.end_anchor, "verify_anchored_export end")
    if len(parsed.transitions) != len(expected.transitions):
        fail("verify_anchored_export: transition count")
    if len(key_chain.keys) != len(parsed.transitions) + 1:
        fail("verify_anchored_export: key chain length")
    # Key-path invariants (anchored_export_codec.ex:506-572 validate_expected_key_path): the expected
    # transition list must form a strictly-increasing effective_at sequence with no fingerprint cycle,
    # and the end anchor must close the path with a chronologically-non-decreasing anchored_at.
    _validate_key_path(expected.start_anchor, expected.transitions, expected.end_anchor)
    for i, tr in enumerate(parsed.transitions):
        _verify_transition_compact(tr, key_chain.keys[i], key_chain.keys[i + 1], expected.transitions[i], f"verify_anchored_export transition {i}")
    # Chronology over the ACTUAL anchored times (anchored_export_codec.ex:138-154 verify_transitions
    # + chronological_end?): each transition's effective_at must be strictly greater than the previous
    # anchor/transition time, and the end anchor's anchored_at must be >= the last transition's
    # effective_at (>= the start anchor's anchored_at for the no-transition case — covered by
    # _validate_key_path's chronological_end on the start anchor).
    transition_time = expected.start_anchor.anchored_at
    for i, t in enumerate(expected.transitions):
        if not (t.effective_at > transition_time):
            fail(f"verify_anchored_export transition {i}: chronology")
        transition_time = t.effective_at
    if not (expected.end_anchor.anchored_at >= transition_time):
        fail("verify_anchored_export: end chronology")
    # Re-check every row (REQ1-EXPORT-complete-scan; mirrors check_chain).
    previous = expected.chain.previous_hash
    sequence = expected.chain.first_sequence
    if expected.chain.first_sequence == 1 and not _bytes_equal(previous, DEFAULT_HASH):
        fail("verify_anchored_export: genesis predecessor")
    if len(parsed.rows) != expected.chain.row_count:
        fail("verify_anchored_export: row count")
    for i, row_bytes in enumerate(parsed.rows):
        row = json_decode(row_bytes, b)
        row = _require_object_exact(row, ["v", "chain_id", "sequence", "previous", "commitment"], f"verify_anchored_export row {i}")
        v_v = row.v["v"]
        if not isinstance(v_v, JInt) or v_v.v != VERSION:
            fail(f"verify_anchored_export row {i}: v")
        cid_v = row.v["chain_id"]
        if not isinstance(cid_v, JString) or utf8_str(cid_v.v) != expected.chain.chain_id:
            fail(f"verify_anchored_export row {i}: chain_id")
        seq_v = row.v["sequence"]
        if not isinstance(seq_v, JInt) or seq_v.v != sequence:
            fail(f"verify_anchored_export row {i}: sequence")
        if seq_v.v < 1:
            fail(f"verify_anchored_export row {i}: sequence positive")
        prev_raw = _require_b64url_n(row.v.get("previous"), "previous", 32)
        if not _bytes_equal(prev_raw, previous):
            fail(f"verify_anchored_export row {i}: previous link")
        commitment_raw = _require_b64url_n(row.v.get("commitment"), "commitment", 32)
        re_encoded = _canonical_row_bytes(expected.chain.chain_id, seq_v.v, prev_raw, commitment_raw, b)
        if not _bytes_equal(re_encoded, row_bytes):
            fail(f"verify_anchored_export row {i}: canonical")
        previous = sha256(ROW_PREFIX, row_bytes)
        sequence += 1
    if not _bytes_equal(previous, expected.chain.last_hash):
        fail("verify_anchored_export: head")
    from .facts import AnchoredExportFacts

    return AnchoredExportFacts(
        version=VERSION, object_version=archived.version, chain_id=expected.chain.chain_id,
        first_sequence=expected.chain.first_sequence, last_sequence=expected.chain.last_sequence,
        row_count=expected.chain.row_count, previous_hash=expected.chain.previous_hash,
        last_hash=previous, digest=digest,
        start_anchor_id=expected.start_anchor.anchor_id, start_anchored_at=expected.start_anchor.anchored_at,
        start_key_fingerprint=expected.start_anchor.key_fingerprint,
        end_anchor_id=expected.end_anchor.anchor_id, end_anchored_at=expected.end_anchor.anchored_at,
        end_key_fingerprint=expected.end_anchor.key_fingerprint,
        transition_count=len(expected.transitions),
    )


# ExpectedExport (the verify_anchored_export expected-context struct).
@dataclass(frozen=True)
class ExpectedExport:
    chain: ExpectedChain
    digest: bytes  # raw 32
    start_anchor: ExpectedAnchor
    end_anchor: ExpectedAnchor
    transitions: tuple[ExpectedKeyTransition, ...]
    object_version: str
    bounds: Bounds | None = None


def _verify_anchor_compact(compact: bytes, key: HistoricalPublicKey, expected: ExpectedAnchor, ctx: str) -> None:
    require(len(key.public_key) == 32, f"{ctx}: key width")
    # BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    kid = _parse_anchor_header(seg, b)
    if kid != key.key_id:
        fail(f"{ctx}: kid")
    if expected.key_id != key.key_id:
        fail(f"{ctx}: expected key id")
    p = json_decode(seg.payload_bytes, b)
    _validate_anchor_payload(p, b)
    if not isinstance(p, JObject):
        fail(f"{ctx}: payload object")
    anchor_id = _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", b)
    if anchor_id != expected.anchor_id:
        fail(f"{ctx}: anchor_id")
    anchored_at = _require_int(p.v.get("anchored_at"), "anchored_at")
    if anchored_at != expected.anchored_at:
        fail(f"{ctx}: anchored_at")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        fail(f"{ctx}: chain_id")
    sequence = _require_int(p.v.get("sequence"), "sequence")
    if sequence != expected.sequence:
        fail(f"{ctx}: sequence")
    chain_hash = _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    if not _bytes_equal(chain_hash, expected.chain_hash):
        fail(f"{ctx}: chain_hash")
    key_fp_raw = _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)
    if not _bytes_equal(key_fp_raw, expected.key_fingerprint):
        fail(f"{ctx}: key_fingerprint")
    if expected.sequence == 0 and not _bytes_equal(expected.chain_hash, DEFAULT_HASH):
        fail(f"{ctx}: genesis hash")
    derived_fp = thumbprint_raw(jwk_from_public_key(key.public_key))
    if not _bytes_equal(derived_fp, expected.key_fingerprint):
        fail(f"{ctx}: fingerprint")
    if not _in_window(anchored_at, key):
        fail(f"{ctx}: window")
    pk = import_public_key(key.public_key, utf8_str(base64url_encode(derived_fp)))
    if not ed25519_verify(seg.signing_input, seg.signature, pk):
        fail(f"{ctx}: signature")


def _verify_transition_compact(compact: bytes, current_key: HistoricalPublicKey, next_key: HistoricalPublicKey, expected: ExpectedKeyTransition, ctx: str) -> None:
    require(len(current_key.public_key) == 32 and len(next_key.public_key) == 32, f"{ctx}: key width")
    if _bytes_equal(current_key.public_key, next_key.public_key):
        fail(f"{ctx}: distinct keys")
    # BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check.
    b = expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS
    seg = parse_compact(compact, b)
    kid = _parse_transition_header(seg, b)
    if kid != current_key.key_id:
        fail(f"{ctx}: kid")
    if expected.current_key_id != current_key.key_id:
        fail(f"{ctx}: current key id")
    if expected.next_key_id != next_key.key_id:
        fail(f"{ctx}: next key id")
    p = json_decode(seg.payload_bytes, b)
    _validate_transition_payload(p, b)
    if not isinstance(p, JObject):
        fail(f"{ctx}: payload object")
    transition_id = _require_string_or_uri(p.v.get("transition_id"), "transition_id", b)
    if transition_id != expected.transition_id:
        fail(f"{ctx}: transition_id")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        fail(f"{ctx}: chain_id")
    effective_at = _require_int(p.v.get("effective_at"), "effective_at")
    if effective_at != expected.effective_at:
        fail(f"{ctx}: effective_at")
    from_fp_raw = _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    if not _bytes_equal(from_fp_raw, expected.current_key_fingerprint):
        fail(f"{ctx}: from fp")
    to_fp_raw = _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    if not _bytes_equal(to_fp_raw, expected.next_key_fingerprint):
        fail(f"{ctx}: to fp")
    to_key_id_v = p.v["to_key_id"]
    if not isinstance(to_key_id_v, JString) or utf8_str(to_key_id_v.v) != expected.next_key_id:
        fail(f"{ctx}: to_key_id")
    derived_from = thumbprint_raw(jwk_from_public_key(current_key.public_key))
    if not _bytes_equal(derived_from, expected.current_key_fingerprint):
        fail(f"{ctx}: current fp")
    derived_to = thumbprint_raw(jwk_from_public_key(next_key.public_key))
    if not _bytes_equal(derived_to, expected.next_key_fingerprint):
        fail(f"{ctx}: next fp")
    if not _in_window(effective_at, current_key):
        fail(f"{ctx}: current window")
    if not _in_window(effective_at, next_key):
        fail(f"{ctx}: next window")
    pk = import_public_key(current_key.public_key, utf8_str(base64url_encode(derived_from)))
    if not ed25519_verify(seg.signing_input, seg.signature, pk):
        fail(f"{ctx}: signature")


@dataclass(frozen=True)
class _ParsedArchive:
    header_bytes: bytes
    start: bytes
    transitions: tuple[bytes, ...]
    rows: tuple[bytes, ...]
    end: bytes


def _parse_archive(data: bytes, bounds: Bounds) -> _ParsedArchive:
    if not _bytes_equal(data[: len(ARCHIVE_PREFIX)], ARCHIVE_PREFIX):
        fail("archive: prefix")
    cursor = len(ARCHIVE_PREFIX)
    header_frame = _read_frame(data, cursor, bounds_resolve(bounds, "archive_header_bytes"), "archive header")
    cursor = header_frame[1]
    header = json_decode(header_frame[0], bounds)
    header = _require_object_exact(
        header,
        ["v", "chain_id", "first_sequence", "last_sequence", "row_count", "transition_count", "previous_hash", "last_hash"],
        "archive header",
    )
    v_v = header.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        fail("archive: header v")
    tc_v = header.v["transition_count"]
    if not isinstance(tc_v, JInt) or tc_v.v < 0 or tc_v.v > bounds_resolve(bounds, "key_transitions"):
        fail("archive: transition_count")
    rc_v = header.v["row_count"]
    if not isinstance(rc_v, JInt) or rc_v.v < 1 or rc_v.v > bounds_resolve(bounds, "chain_rows"):
        fail("archive: row_count")
    fs_v = header.v["first_sequence"]
    ls_v = header.v["last_sequence"]
    if not isinstance(fs_v, JInt) or not isinstance(ls_v, JInt):
        fail("archive: header sequences")
    if not (fs_v.v > 0 and ls_v.v >= fs_v.v and rc_v.v == ls_v.v - fs_v.v + 1):
        fail("archive: row range")
    _require_b64url_n(header.v.get("previous_hash"), "previous_hash", 32)
    _require_b64url_n(header.v.get("last_hash"), "last_hash", 32)
    start_frame = _read_frame(data, cursor, bounds_resolve(bounds, "anchor_bytes"), "start anchor")
    cursor = start_frame[1]
    transitions: list[bytes] = []
    for i in range(tc_v.v):
        f = _read_frame(data, cursor, bounds_resolve(bounds, "anchor_bytes"), f"transition {i}")
        transitions.append(f[0])
        cursor = f[1]
    rows: list[bytes] = []
    for i in range(rc_v.v):
        f = _read_frame(data, cursor, bounds_resolve(bounds, "chain_row_bytes"), f"row {i}")
        rows.append(f[0])
        cursor = f[1]
    end_frame = _read_frame(data, cursor, bounds_resolve(bounds, "anchor_bytes"), "end anchor")
    cursor = end_frame[1]
    if cursor != len(data):
        fail("archive: exact EOF")
    return _ParsedArchive(
        header_bytes=header_frame[0], start=start_frame[0],
        transitions=tuple(transitions), rows=tuple(rows), end=end_frame[0],
    )


def _read_frame(data: bytes, cursor: int, maximum: int, ctx: str) -> tuple[bytes, int]:
    if cursor + 4 > len(data):
        fail(f"{ctx}: frame length")
    length = (data[cursor] << 24 | data[cursor + 1] << 16 | data[cursor + 2] << 8 | data[cursor + 3]) & 0xFFFFFFFF
    if length == 0 or length > maximum:
        fail(f"{ctx}: frame bound")
    start = cursor + 4
    end = start + length
    if end > len(data):
        fail(f"{ctx}: complete frame")
    return data[start:end], end


def _validate_key_path(
    start: ExpectedAnchor, transitions: Sequence[ExpectedKeyTransition], end: ExpectedAnchor
) -> None:
    """Validate the expected key-transition path (anchored_export_codec.ex:506-572
    validate_expected_key_path). The no-transition path requires the start and end anchors to share
    key id + fingerprint with a chronologically-non-decreasing end anchored_at. The transition path
    requires: each transition's current key matches the running key; effective_at is strictly
    increasing; no next fingerprint has appeared before (cycle rejection); the end anchor closes on
    the last transition's next key with a chronologically-non-decreasing anchored_at."""
    if len(transitions) == 0:
        if start.key_id != end.key_id or not _bytes_equal(start.key_fingerprint, end.key_fingerprint):
            fail("key path: start==end key")
        if not (end.anchored_at >= start.anchored_at):
            fail("key path: end chronological")
        return
    current_key_id = start.key_id
    current_fp = start.key_fingerprint
    previous_time = start.anchored_at
    # seen is seeded with the start anchor's fingerprint (anchored_export_codec.ex:523).
    seen: list[bytes] = [start.key_fingerprint]
    for i, t in enumerate(transitions):
        if t.current_key_id != current_key_id or not _bytes_equal(t.current_key_fingerprint, current_fp):
            fail(f"key path: transition {i} current key")
        # strictly_after?(effective_at, previous_time) — strictly increasing.
        if not (t.effective_at > previous_time):
            fail(f"key path: transition {i} chronology")
        # No cycle: next_key_fingerprint must not be in seen.
        if any(_bytes_equal(t.next_key_fingerprint, s) for s in seen):
            fail(f"key path: transition {i} cycle")
        current_key_id = t.next_key_id
        current_fp = t.next_key_fingerprint
        previous_time = t.effective_at
        seen.append(t.next_key_fingerprint)
    # The end anchor must close on the last transition's next key.
    if end.key_id != current_key_id or not _bytes_equal(end.key_fingerprint, current_fp):
        fail("key path: end key")
    # chronological_end?(end.anchored_at, previous_time) — >= the last transition's effective_at.
    if not (end.anchored_at >= previous_time):
        fail("key path: end chronological")


def _validate_chunks(chunks: Sequence[bytes], bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    """Validate the chunk list BEFORE concatenation (anchored_export_codec.ex:333-342
    validate_chunks): at least one chunk, each chunk nonempty, count < archive_chunks, running total
    ≤ archive_bytes."""
    if len(chunks) == 0:
        fail("archive: no chunks")
    # Cross-vendor re-review Finding 2: the reference's validate_chunks guard is
    # `count < archive_chunks` on the recursive clause (start 0), accepting up to archive_chunks
    # INCLUSIVE. Use `>` not `>=`.
    if len(chunks) > bounds_resolve(bounds, "archive_chunks"):
        fail("archive: chunk count")
    total = 0
    for i, c in enumerate(chunks):
        if len(c) == 0:
            fail(f"archive: empty chunk {i}")
        total += len(c)
        if total > bounds_resolve(bounds, "archive_bytes"):
            fail("archive: chunk bytes")
