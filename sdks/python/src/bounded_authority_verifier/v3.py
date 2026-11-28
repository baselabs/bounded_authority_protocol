"""The v3 verification facade (contract-major 3, the ``BAP3-ES256-SHA256`` suite).

The v3 profile is byte-distinct from v1 and v2 (spec/bap-v3.md under the successor-major
charter): every versioned payload carries ``v: 3``, the protected ``alg`` is exactly
``ES256`` (ECDSA over NIST P-256 with SHA-256, RFC 7518 §3.4), the domain separators are
``BAP3-REQUEST\\0`` / ``BAP3-CHAIN\\0`` / ``BAP3-ARCHIVE\\0EXPORT\\0``, the proof JWK is the EC
JWK ``{crv:"P-256", kty:"EC", x, y}`` with the RFC 7638 thumbprint over that four-member set,
raw public keys are the 65-byte uncompressed SEC1 point ``0x04 || x || y``, and signatures are
the RFC 7518 §3.4 raw ``r || s`` form with the low-S rule enforced at verification. The selector
algebra admits the five kinds ``all``/``equals``/``one_of``/``lte``/``gte`` (incorporated from
v2 §4). This facade rejects v1 and v2 bytes, and those facades reject v3 bytes: each major
verifies under its own complete closed profile (REQ3-CORE-cross-major-reject).

The local-loopback application proof profile is bound to contract-major 1 (spec/bap-v3.md §2);
this facade exposes no loopback functions.

17 public functions, each returning ``Result[T] = Ok | Err`` (the ``{:ok, value} | {:error, :invalid}``
mirror). No ``authorized`` / ``decision`` surface. All claims revalidated at every
public entry (REQ1-VERIFY-revalidate, incorporated). Derived from spec/bap-v3.md + spec/bap-v1.md
(incorporated with the §2 substitutions) + spec/bap-v2.md §4 + the certified corpus; the corpus is
the byte-level arbiter. Derived from the spec and certified corpus, not from
any sibling-SDK or reference source (docs/design/conformance-contract.md, Independent implementation rule).

Frozen dataclasses carry the caller inputs defined by spec/bap-v1.md §16
(incorporated by spec/bap-v2.md §2 and spec/bap-v3.md §2). They use ``bytes`` for raw-32/raw-65 fields and ``int`` / ``str`` for scalars.
"""

from __future__ import annotations

import functools
import inspect
import re
import types as _types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, is_dataclass, replace
from typing import Any, ParamSpec, TypeVar, Union, cast, get_args, get_origin, get_type_hints

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ._inputs import _bytes, _normalize_arg, _text
from .base64url import base64url_decode, base64url_encode
from .bounds import (  # noqa: F401
    MAXIMA,
    MAXIMUM_BOUNDS,
    Bounds,
    bounds_resolve,
    coerce_bounds,
)
from .bounds import bounds_new as bounds_new
from .compact import (  # noqa: F401
    CompactSegments,
    SigningInput,
    _parse_compact,
    _scan_compact,
    assemble_segments_es256,
)
from .ed25519 import sha256
from .error import InvalidError, Ok, Result, _fail, _invalid_error, _require, _unwrap, err
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
    _Facts,
)
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
    _normalize_tagged,
    json_decode,
    str_utf8,
    utf8_str,
)
from .selector import Selector as _V1Selector
from .selector import _integral_float_free
from .selector import parse_selector as _parse_v1_selector
from .selector import selector_matches as _v1_selector_matches
from .uri import _valid_ipv6_literal, uri_normalize

# --- constants (the closed v3 profile header/claim literals; the §2 substitutions over v1) ---

ALG = "ES256"
GRANT_TYP = "ba+cap"
PROOF_TYP = "dpop+jwt"
ANCHOR_TYP = "ba+chain-anchor"
TRANSITION_TYP = "ba+key-transition"
VERSION = 3

# BAP3-CHAIN\0 prefix for consumption-row hashing (the v3 domain separator; the v1 §15 chain
# construction with the §2 substitution). Byte-distinct from BAP1/BAP2-CHAIN\0, so a v3 chain
# link never collides with a v1 or v2 chain link.
ROW_PREFIX = b"BAP3-CHAIN\x00"

# BAP3-ARCHIVE\0EXPORT\0 prefix (the v3 domain separator; the v1 §15 archive framing with the
# §2 substitution; the 20-byte magic, NOT framed). Byte-distinct from the v1/v2 prefixes, so
# no two majors' archives share a frame grammar.
ARCHIVE_PREFIX = b"BAP3-ARCHIVE\x00EXPORT\x00"

# BAP3-REQUEST\0 prefix for the request digest (REQ3-SIGNING-digest-prefix). The digest core
# over JCS([operation, typed(cast_arguments)]) is incorporated from v1 §7 verbatim; only the
# prefix bytes differ per major.
REQUEST_PREFIX = b"BAP3-REQUEST\x00"

# The all-zero 32-byte hash: sequence-1 predecessor + sequence-0 anchor chain hash (v1 §15
# incorporated).
DEFAULT_HASH = bytes(32)

# Lowercase RFC 4122 UUID.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_KID_CHARSET = re.compile(r"^[A-Za-z0-9._~-]+$")
_METHOD_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_OPERATION_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")


def _is_int(value: object) -> bool:
    """isinstance(int) that EXCLUDES bool (Python isinstance(True, int) is True, so a bool-typed
    evaluation_time/clock_skew/proof_max_age would pass an isinstance(x, int) check. The
    temporal context excludes booleans (spec/bap-v1.md §16, REQ1-VERIFY-revalidate).)"""
    return isinstance(value, int) and not isinstance(value, bool)


# --- the ES256 signature suite (spec/bap-v3.md §3) ---
#
# ECDSA over NIST P-256 with SHA-256. The P-256 domain parameters (SEC 2) are protocol constants:
#
#   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
#   y^2 = x^3 - 3x + b  (mod p)  : a = -3, the short-Weierstrass form the check below uses
#
# On-curve validation of decoded JWK points is PURE ARITHMETIC in the profile (REQ3-KEY-point-on-
# curve): it precedes the crypto backend, whose off-curve behavior is backend-specific and never
# load-bearing.

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
"""The P-256 field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1."""
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
"""The P-256 curve coefficient b."""
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
"""The P-256 group order n."""
_LOW_S_MAX = (P256_N - 1) // 2
"""The largest low-S value: n is odd, so s <= n/2 (rationally) is s <= (n-1)/2 exactly."""


def _canonical_signature(signature: bytes) -> bool:
    """The suite's canonical-signature rule (spec/bap-v3.md § 3.2): a raw 64-byte r || s has
    0 < r < n and 0 < s <= floor(n / 2). Every producer surface (compact assembly,
    anchored-export encoding, erratum 3) refuses a signature that fails it; the producer never
    normalizes: low-S is the signer's duty."""
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    return 0 < r < P256_N and 0 < s <= _LOW_S_MAX


# Suite fixed widths (REQ3-BOUNDS-fixed-widths, spec/bap-v3.md §5): coordinate 32, raw public key
# (uncompressed SEC1) 65, signature (r || s) 64, SHA-256 digest 32. Immutable cryptographic
# constants of BAP3-ES256-SHA256: the shared bounds table's 32-byte public-key width is the v1
# suite's; the v3 width is enforced here as the profile's own constant.
COORDINATE_BYTES = 32
PUBLIC_KEY_BYTES = 65
SIGNATURE_BYTES = 64

@dataclass(frozen=True)
class EcPublic:
    """The public EC JWK value: exactly ``{crv: "P-256", kty: "EC", x, y}`` (REQ3-HEADER-proof-jwk)."""

    crv: str  # always "P-256"
    kty: str  # always "EC"
    x: str  # base64url of exactly 32 raw bytes (the fixed-width big-endian coordinate)
    y: str  # base64url of exactly 32 raw bytes


def _point_on_curve(x: int, y: int) -> bool:
    """y^2 = x^3 - 3x + b (mod p): pure arithmetic over the decoded coordinates."""
    return (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0


def _validated_public_key(raw_key: bytes) -> bytes:
    """Validate a raw v3 public key: exactly 65 bytes, ``0x04 || x || y`` uncompressed SEC1
    (compressed points invalid: REQ3-KEY-uncompressed-sec1), each coordinate < p, and the point
    on the curve (REQ3-KEY-point-on-curve). Returns the same bytes narrowed."""
    _require(len(raw_key) == PUBLIC_KEY_BYTES, "es256: public key must be 65 bytes")
    if raw_key[0] != 0x04:
        _fail("es256: uncompressed SEC1 form required")
    x = int.from_bytes(raw_key[1:33], "big")
    y = int.from_bytes(raw_key[33:65], "big")
    if x >= P256_P or y >= P256_P:
        _fail("es256: coordinate >= p")
    if not _point_on_curve(x, y):
        _fail("es256: point not on curve")
    return raw_key


def _import_public_key(raw_key: bytes) -> ec.EllipticCurvePublicKey:
    """Import an uncompressed SEC1 P-256 public key after validating the point.

    The pure on-curve/coordinate checks run FIRST (REQ3-BOUNDS-ordering); the backend import is
    never load-bearing for those rejections.
    """
    _validated_public_key(raw_key)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_key)


def _es256_scalars(signature: bytes) -> tuple[int, int]:
    """Validate the exact raw signature representation, including low-S."""
    _require(len(signature) == SIGNATURE_BYTES, "es256: signature must be 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r == 0 or s == 0:
        _fail("es256: r/s zero")
    if r >= P256_N or s >= P256_N:
        _fail("es256: r/s range")
    if s > _LOW_S_MAX:
        _fail("es256: high-s")
    return r, s


def _es256_verify(message: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verify low-S ECDSA with SHA-256 over the original JWS signing input."""
    r, s = _es256_scalars(signature)
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def jwk_from_public_key(raw_key: bytes) -> Result[EcPublic]:
    """The EC JWK of a raw 65-byte public key (validating width, form, and the point)."""
    try:
        raw_key = _bytes(raw_key)
        _validated_public_key(raw_key)
        return Ok(
            EcPublic(
                crv="P-256",
                kty="EC",
                x=_unwrap(utf8_str(_unwrap(base64url_encode(raw_key[1:33])))),
                y=_unwrap(utf8_str(_unwrap(base64url_encode(raw_key[33:65])))),
            )
        )
    except InvalidError:
        return err()


def _raw_public_key_from_jwk(jwk: EcPublic) -> bytes:
    """The raw 65-byte uncompressed SEC1 point of a validated EC JWK."""
    return (
        b"\x04"
        + _unwrap(base64url_decode(_unwrap(str_utf8(jwk.x))))
        + _unwrap(base64url_decode(_unwrap(str_utf8(jwk.y))))
    )


def _ec_public_from_tagged(obj: JObject, ctx: str) -> EcPublic:
    """Validate a decoded EC JWK object: the closed member set ``{crv, kty, x, y}`` with
    ``crv: "P-256"``, ``kty: "EC"``, and canonical unpadded base64url of exactly 32 bytes for
    each coordinate (REQ3-HEADER-proof-jwk + REQ3-BOUNDS-fixed-widths); each coordinate < p and
    the point on the curve (REQ3-KEY-point-on-curve, pure arithmetic before any backend call).
    Every additional member, including private ``d``, is invalid (REQ3-HEADER-no-private-jwk)."""
    obj = _require_object_exact(obj, ["crv", "kty", "x", "y"], ctx)
    _require_string_lit(obj, "crv", "P-256", f"{ctx} crv")
    _require_string_lit(obj, "kty", "EC", f"{ctx} kty")
    x_v = obj.v.get("x")
    y_v = obj.v.get("y")
    if not isinstance(x_v, JString) or not isinstance(y_v, JString):
        _fail(f"{ctx}: x/y strings")
    raw_x = _unwrap(base64url_decode(x_v.v))
    raw_y = _unwrap(base64url_decode(y_v.v))
    if len(raw_x) != COORDINATE_BYTES or len(raw_y) != COORDINATE_BYTES:
        _fail(f"{ctx}: coordinate width")
    xi = int.from_bytes(raw_x, "big")
    yi = int.from_bytes(raw_y, "big")
    if xi >= P256_P or yi >= P256_P:
        _fail(f"{ctx}: coordinate >= p")
    if not _point_on_curve(xi, yi):
        _fail(f"{ctx}: point not on curve")
    return EcPublic(crv="P-256", kty="EC", x=_unwrap(utf8_str(x_v.v)), y=_unwrap(utf8_str(y_v.v)))


def jwk_from_json(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[EcPublic]:
    """Decode + validate a public EC JWK from JSON bytes (the jwk.* primitive surface).
    Returns the closed Err on every non-conforming input."""
    try:
        data = _bytes(data)
        value = _unwrap(json_decode(data, bounds))
        if not isinstance(value, JObject):
            _fail("jwk: object")
        return Ok(_ec_public_from_tagged(value, "jwk"))
    except InvalidError:
        return err()


def jwk_encode_public(raw_key: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    """Encode a raw 65-byte public key as the canonical EC JWK JSON bytes."""
    try:
        raw_key = _bytes(raw_key)
        jwk = _unwrap(jwk_from_public_key(raw_key))
        members: dict[str, Tagged] = {
            "crv": JString(_unwrap(str_utf8(jwk.crv))),
            "kty": JString(_unwrap(str_utf8(jwk.kty))),
            "x": JString(_unwrap(str_utf8(jwk.x))),
            "y": JString(_unwrap(str_utf8(jwk.y))),
        }
        return Ok(_unwrap(jcs_encode(JObject(members), bounds)))
    except InvalidError:
        return err()


def jwk_decode_public(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    """Decode an EC public JWK from JSON bytes. Returns ``Ok(raw65)`` or ``Err``."""
    try:
        data = _bytes(data)
        jwk = _unwrap(jwk_from_json(data, bounds))
        return Ok(_raw_public_key_from_jwk(jwk))
    except InvalidError:
        return err()


def thumbprint_preimage(jwk: EcPublic) -> Result[bytes]:
    """RFC 7638 thumbprint preimage: the JCS bytes of exactly ``{"crv","kty","x","y"}`` in
    lexicographic order (REQ3-HEADER-thumbprint)."""
    try:
        jwk = _normalize_arg(jwk, EcPublic)
        members: dict[str, Tagged] = {
            "crv": JString(_unwrap(str_utf8(jwk.crv))),
            "kty": JString(_unwrap(str_utf8(jwk.kty))),
            "x": JString(_unwrap(str_utf8(jwk.x))),
            "y": JString(_unwrap(str_utf8(jwk.y))),
        }
        return Ok(_unwrap(jcs_encode(JObject(members))))
    except InvalidError:
        return err()


def thumbprint(jwk: EcPublic) -> Result[str]:
    """Thumbprint as unpadded base64url SHA-256 of the preimage."""
    try:
        jwk = _normalize_arg(jwk, EcPublic)
        return Ok(
            _unwrap(
                utf8_str(
                    _unwrap(base64url_encode(_unwrap(sha256(_unwrap(thumbprint_preimage(jwk))))))
                )
            )
        )
    except InvalidError:
        return err()


def thumbprint_raw(jwk: EcPublic) -> Result[bytes]:
    """Raw 32-byte thumbprint (REQ3-HEADER-digest-width, incorporated)."""
    try:
        jwk = _normalize_arg(jwk, EcPublic)
        return Ok(_unwrap(sha256(_unwrap(thumbprint_preimage(jwk)))))
    except InvalidError:
        return err()


def public_key_thumbprint_raw(raw_key: bytes) -> Result[bytes]:
    """Raw 32-byte thumbprint directly from a raw 65-byte public key (REQ3-HEADER-issuer-
    fingerprint: the same construction over the caller's raw key; ``kid`` excluded)."""
    try:
        raw_key = _bytes(raw_key)
        return Ok(_unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(raw_key)))))
    except InvalidError:
        return err()


# --- the v3 selector algebra (spec/bap-v3.md §4: the v2 algebra unchanged, five kinds) ---
#
# The closed kind set is {all, equals, one_of, lte, gte}. The three v1 kinds delegate to the
# shared selector module (the identical closed validation); lte/gte use the EXISTING
# {kind, path, value} recognized member set (no fourth member set), with the bound constrained
# to the numeric tags. Same-tag semantics: the traversed value and the bound must BOTH be
# integer-tagged or BOTH be float-tagged; a cross-tag pair NEVER matches (fail closed: the v1
# no-tag-collapse invariant extended from identity to ordering). Comparison is INCLUSIVE by
# numeric value on the closed numeric domain the bounded decoder admits (lte: value <= bound;
# gte: value >= bound). Non-numeric operands never match, and a missing path fails closed
# exactly as equals/one_of (REQ3-SELECTOR-*; the REQ2-SELECTOR-* semantics incorporated).


@dataclass(frozen=True)
class SelLte:
    """An inclusive numeric upper bound; integer and float tags must match.

    Fields:
        path: tuple[str, ...].
        bound: Tagged.
    """

    path: tuple[str, ...]
    bound: Tagged  # JInt | JFloat by construction


@dataclass(frozen=True)
class SelGte:
    """An inclusive numeric lower bound; integer and float tags must match.

    Fields:
        path: tuple[str, ...].
        bound: Tagged.
    """

    path: tuple[str, ...]
    bound: Tagged  # JInt | JFloat by construction


V3Selector = _V1Selector | SelLte | SelGte


def parse_selector(obj: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[V3Selector]:
    """Parse a v3 selector: the v1 kinds delegate; lte/gte validate the numeric bound at decode.

    A non-numeric bound (string/boolean/null/array/object) rejects HERE: the producer must not
    mint, and the verifier must not accept, a range selector whose bound cannot participate in
    the same-tag domain.
    """
    try:
        obj = _normalize_tagged(obj, bounds)
        if not isinstance(obj, JObject):
            _fail("selector: object")
        kind_v = obj.v.get("kind")
        if not isinstance(kind_v, JString):
            _fail("selector: kind")
        kind = _unwrap(utf8_str(kind_v.v))
        if kind not in ("lte", "gte"):
            return Ok(_unwrap(_parse_v1_selector(obj, bounds)))
        # Exactly the {kind, path, value} recognized member set (no fourth member set).
        if frozenset(obj.v) != frozenset({"kind", "path", "value"}):
            _fail("selector: member set")
        path = _parse_selector_path(obj.v.get("path"), bounds)
        bound = obj.v.get("value")
        # isinstance narrows to the numeric tags (JInt | JFloat); every other tag rejects at decode.
        if not isinstance(bound, (JInt, JFloat)):
            _fail(f"selector: {kind} numeric bound")
        _validate_selector_value(bound, bounds)
        return Ok((SelLte if kind == "lte" else SelGte)(path, bound))
    except InvalidError:
        return err()


def _parse_selector_path(path_v: Tagged | None, bounds: Bounds) -> tuple[str, ...]:
    """The shared path discipline (REQ1-SELECTOR-path-shape, incorporated): 1..32 object-member
    names, each 1..128 UTF-8 bytes, traversing OBJECTS only."""
    if path_v is None or not isinstance(path_v, JArray):
        _fail("selector: path array")
    if not (1 <= len(path_v.v) <= _unwrap(bounds_resolve(bounds, "path_segments"))):
        _fail("selector: path length")
    names: list[str] = []
    for seg in path_v.v:
        if not isinstance(seg, JString):
            _fail("selector: path segment string")
        if not (1 <= len(seg.v) <= _unwrap(bounds_resolve(bounds, "key_bytes"))):
            _fail("selector: path segment bytes")
        names.append(_unwrap(utf8_str(seg.v)))
    return tuple(names)


def _traverse_selector_path(root: Tagged, path: tuple[str, ...]) -> Tagged | None:
    """Traverse a path over OBJECTS (paths never index arrays); None = missing."""
    cur: Tagged | None = root
    for name in path:
        if not isinstance(cur, JObject):
            return None
        cur = cur.v.get(name)
    return cur


def selector_matches(sel: V3Selector, cast_arguments: Tagged) -> Result[bool]:
    """v3 apply: lte/gte are inclusive same-tag numeric comparisons; the v1 kinds delegate."""
    try:
        sel = cast(V3Selector, _normalize_arg(sel, V3Selector))
        cast_arguments = _normalize_tagged(cast_arguments, MAXIMUM_BOUNDS)
        if isinstance(sel, (SelLte, SelGte)):
            target = _traverse_selector_path(cast_arguments, sel.path)
            if target is None:
                return Ok(False)  # missing path fails closed exactly as equals/one_of
            bound = sel.bound
            inclusive_low = isinstance(sel, SelLte)
            # Same-tag arms ONLY: JInt pairs compare as integers, JFloat pairs as floats; every other
            # pairing (cross-tag, or a non-numeric traversed operand) is False.
            if isinstance(bound, JInt) and isinstance(target, JInt):
                return Ok(target.v <= bound.v if inclusive_low else target.v >= bound.v)
            if isinstance(bound, JFloat) and isinstance(target, JFloat):
                return Ok(target.v <= bound.v if inclusive_low else target.v >= bound.v)
            return Ok(False)
        return Ok(_unwrap(_v1_selector_matches(sel, cast_arguments)))
    except InvalidError:
        return err()


# --- dispatch struct types (match corpus input field names; the contract for each facade) ---


@dataclass(frozen=True)
class TrustedIssuer:
    """An already-trusted issuer key selected by the caller; decoding never establishes trust.

    Fields:
        key_id: str.
        public_key: bytes.
    """

    key_id: str
    public_key: bytes  # raw 65 (uncompressed SEC1)


@dataclass(frozen=True)
class ExpectedGrant:
    """Caller-derived issuer, audience, evaluation time and allowed skew for grant verification.

    Fields:
        issuer: str.
        audience: str.
        evaluation_time: int.
        clock_skew: int.
        bounds: Bounds | None.
    """

    issuer: str
    audience: str
    evaluation_time: int
    clock_skew: int
    bounds: Bounds | None = None


@dataclass(frozen=True)
class HistoricalPublicKey:
    """An already-trusted historical public key with an inclusive start and exclusive end.

    Fields:
        key_id: str.
        public_key: bytes.
        valid_from: int.
        valid_before: int | None.
    """

    key_id: str
    public_key: bytes  # raw 65 (uncompressed SEC1)
    valid_from: int
    valid_before: int | None  # None = unbounded


@dataclass(frozen=True)
class ExpectedAnchor:
    """Expected chain boundary and key identity for a historical anchor.

    Fields:
        anchor_id: str.
        anchored_at: int.
        chain_id: str.
        sequence: int.
        chain_hash: bytes.
        key_id: str.
        key_fingerprint: bytes.
        bounds: Bounds | None.
    """

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
    """Expected chain and old/new key identities for a signed key transition.

    Fields:
        transition_id: str.
        chain_id: str.
        effective_at: int.
        current_key_id: str.
        current_key_fingerprint: bytes.
        next_key_id: str.
        next_key_fingerprint: bytes.
        bounds: Bounds | None.
    """

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
    """Caller-supplied chain row fields; encoding does not write or reserve a consumption.

    Fields:
        chain_id: str.
        sequence: int.
        previous_hash: bytes.
        commitment: bytes.
    """

    chain_id: str
    sequence: int
    previous_hash: bytes  # raw 32
    commitment: bytes  # raw 32


@dataclass(frozen=True)
class ChainInput:
    """Canonical row bytes and their claimed chain boundary, before verification.

    Fields:
        rows: tuple[bytes, ...].
        chain_id: str.
        first_sequence: int.
        last_sequence: int.
        row_count: int.
        previous_hash: bytes.
        last_hash: bytes.
    """

    rows: tuple[bytes, ...]  # raw canonical row bytes
    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    previous_hash: bytes  # raw 32
    last_hash: bytes  # raw 32


@dataclass(frozen=True)
class ExpectedChain:
    """Caller-owned expected chain identity, sequence interval and terminal hash.

    Fields:
        chain_id: str.
        first_sequence: int.
        last_sequence: int.
        row_count: int.
        previous_hash: bytes.
        last_hash: bytes.
        bounds: Bounds | None.
    """

    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    previous_hash: bytes  # raw 32
    last_hash: bytes  # raw 32
    bounds: Bounds | None = None


@dataclass(frozen=True)
class NonceRequired:
    """Require an exact nonce value selected by the host; presence alone is insufficient.

    Fields:
        value: str.
        kind: str.
    """

    value: str
    kind: str = field(default="required", init=False)


@dataclass(frozen=True)
class NonceNotRequired:
    """Explicitly choose the no-nonce policy; this does not disable replay checks in the host.

    Fields:
        kind: str.
    """

    kind: str = field(default="not_required", init=False)


@dataclass(frozen=True)
class ExpectedRequest:
    """Complete caller-derived request context; verified facts never authorize its execution.

    Fields:
        trusted_issuer: TrustedIssuer.
        issuer: str.
        audience: str.
        method: str.
        target_uri: str.
        invocation_id: str.
        operation: str.
        cast_arguments: Tagged.
        evaluation_time: int.
        clock_skew: int.
        proof_max_age: int.
        nonce: NonceNotRequired | NonceRequired.
        bounds: Bounds | None.
    """

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
    """An operation name and tagged selectors that constrain its arguments.

    Fields:
        name: str.
        selectors: Sequence[SelectorInput].
    """

    name: str
    selectors: Sequence[SelectorInput]


@dataclass(frozen=True)
class GrantProducer:
    """Validated unsigned grant claims; obtaining signing bytes does not issue authority.

    Fields:
        key_id: str.
        issuer: str.
        grant_id: str.
        audiences: Sequence[str].
        issued_at: int.
        not_before: int.
        expires_at: int.
        holder_thumbprint: str.
        operations: Sequence[OperationInput].
    """

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
    """Unsigned holder proof bound to one grant and canonical request.

    Fields:
        holder_public_key: bytes.
        proof_id: str.
        method: str.
        target_uri: str.
        issued_at: int.
        invocation_id: str.
        operation: str.
        grant_compact: bytes.
        cast_arguments: Tagged.
        nonce: str | None.
    """

    holder_public_key: bytes  # raw 65 (uncompressed SEC1)
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
    """Unsigned historical chain-boundary claims; signing remains caller-owned.

    Fields:
        anchor_id: str.
        anchored_at: int.
        chain_id: str.
        sequence: int.
        chain_hash: bytes.
        key_id: str.
        public_key: bytes.
    """

    anchor_id: str
    anchored_at: int
    chain_id: str
    sequence: int
    chain_hash: bytes  # raw 32
    key_id: str
    public_key: bytes  # raw 65 (uncompressed SEC1)


@dataclass(frozen=True)
class KeyTransitionProducer:
    """Unsigned chain key-transition claims; this value cannot install a trusted key.

    Fields:
        transition_id: str.
        chain_id: str.
        effective_at: int.
        current_key_id: str.
        current_public_key: bytes.
        next_key_id: str.
        next_public_key: bytes.
    """

    transition_id: str
    chain_id: str
    effective_at: int
    current_key_id: str
    current_public_key: bytes  # raw 65 (uncompressed SEC1)
    next_key_id: str
    next_public_key: bytes  # raw 65 (uncompressed SEC1)


@dataclass(frozen=True)
class AnchoredExportInput:
    """Caller-supplied canonical archive components and boundary evidence.

    Fields:
        rows: tuple[bytes, ...].
        start_anchor: bytes.
        end_anchor: bytes.
        transitions: tuple[bytes, ...].
        chain_id: str.
        first_sequence: int.
        last_sequence: int.
        row_count: int.
        previous_hash: bytes.
        last_hash: bytes.
    """

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
    """Immutable object identity and version carried by an anchored export.

    Fields:
        chunks: tuple[bytes, ...].
        version: str.
    """

    chunks: tuple[bytes, ...]
    version: str


@dataclass(frozen=True)
class HistoricalKeyChain:
    """Caller-supplied initial historical key and its signed transition sequence.

    Fields:
        keys: tuple[HistoricalPublicKey, ...].
    """

    keys: tuple[HistoricalPublicKey, ...]


@dataclass(frozen=True)
class EncodedConsumptionEntry:
    """Canonical row bytes and their hash, without any persistence side effect.

    Fields:
        bytes_: bytes.
        hash_: bytes.
    """

    bytes_: bytes
    hash_: bytes


@dataclass(frozen=True)
class EncodedAnchoredExport:
    """Canonical archive bytes and their digest, without any archive writes.

    Fields:
        archive: bytes.
        digest: bytes.
    """

    archive: bytes
    digest: bytes


# --- shared closed-header / claim validators (v1 §10-11 incorporated with §2 substitutions) ---


def _parse_grant_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = _unwrap(json_decode(seg.protected_bytes, bounds))
    h = _require_object_exact(h, ["alg", "typ", "kid"], "grant header")
    _require_string_lit(h, "alg", ALG, "grant header alg")
    _require_string_lit(h, "typ", GRANT_TYP, "grant header typ")
    return _require_kid(h, bounds)


def _parse_proof_header(seg: CompactSegments, bounds: Bounds) -> tuple[bytes, bytes]:
    """Returns (holderThumbprint raw32, holderKey raw65 uncompressed SEC1).

    The protected proof JWK is validated here in full: closed member set, coordinate widths,
    coordinate range, on-curve (REQ3-BOUNDS-ordering: the JWK checks precede the signature
    integer-range checks and the backend).
    """
    h = _unwrap(json_decode(seg.protected_bytes, bounds))
    h = _require_object_exact(h, ["alg", "typ", "jwk"], "proof header")
    _require_string_lit(h, "alg", ALG, "proof header alg")
    _require_string_lit(h, "typ", PROOF_TYP, "proof header typ")
    jwk_v = h.v.get("jwk")
    if not isinstance(jwk_v, JObject):
        _fail("proof header: jwk object")
    jwk = _ec_public_from_tagged(jwk_v, "proof jwk")
    tp = _unwrap(thumbprint_raw(jwk))
    return tp, _raw_public_key_from_jwk(jwk)


def _parse_anchor_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = _unwrap(json_decode(seg.protected_bytes, bounds))
    h = _require_object_exact(h, ["alg", "typ", "kid"], "anchor header")
    _require_string_lit(h, "alg", ALG, "anchor header alg")
    _require_string_lit(h, "typ", ANCHOR_TYP, "anchor header typ")
    kid = _require_kid(h, bounds)
    # Canonical form: the protected segment must be the exact JCS encoding (the v1 §15 anchor
    # canonical-form requirement, incorporated).
    if not _bytes_equal(_unwrap(jcs_encode(h, bounds)), seg.protected_bytes):
        _fail("anchor header: canonical")
    return kid


def _parse_transition_header(seg: CompactSegments, bounds: Bounds) -> str:
    h = _unwrap(json_decode(seg.protected_bytes, bounds))
    h = _require_object_exact(h, ["alg", "typ", "kid"], "transition header")
    _require_string_lit(h, "alg", ALG, "transition header alg")
    _require_string_lit(h, "typ", TRANSITION_TYP, "transition header typ")
    kid = _require_kid(h, bounds)
    # Canonical form: the protected segment must be the exact JCS encoding (the v1 §15
    # transition canonical-form requirement, incorporated).
    if not _bytes_equal(_unwrap(jcs_encode(h, bounds)), seg.protected_bytes):
        _fail("transition header: canonical")
    return kid


def _require_kid(h: JObject, bounds: Bounds) -> str:
    kid_v = h.v.get("kid")
    if not isinstance(kid_v, JString):
        _fail("header: kid string")
    b = kid_v.v
    if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "kid_bytes"))):
        _fail("header: kid bytes")
    s = _unwrap(utf8_str(b))
    if _KID_CHARSET.match(s) is None:
        _fail("header: kid charset")
    return s


def _require_object_exact(v: Tagged, keys: list[str], ctx: str) -> JObject:
    """Validate that ``v`` is a JObject with exactly ``keys`` members; return it narrowed.

    Returns the narrowed ``JObject`` so callers do not need a separate isinstance check (Python has
    no ``asserts x is T`` type-guard, so the narrowing flows through the return value).
    """
    if not isinstance(v, JObject):
        _fail(f"{ctx}: object")
    got = ",".join(sorted(v.v.keys()))
    want = ",".join(sorted(keys))
    if got != want:
        _fail(f"{ctx}: closed members")
    return v


def _require_string_lit(obj: JObject, key: str, lit: str, ctx: str) -> None:
    v = obj.v.get(key)
    if v is None or not isinstance(v, JString) or _unwrap(utf8_str(v.v)) != lit:
        _fail(f"{ctx}: {key}={lit}")


# StringOrURI (RFC 7519 §2; the v1 §11 claim shape, incorporated). A bare string with no
# ':' is always valid; an opaque scheme `a:b` (no `//`) is valid; a `//` authority is structurally
# validated.
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
    rest = s[colon + 1 :]
    if not rest.startswith("//"):
        return True  # opaque / path-rootless: no authority to validate.
    return _valid_uri_authority(rest[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0])


def _valid_uri_authority(authority: str) -> bool:
    at = authority.find("@")
    hostport = authority if at == -1 else authority[at + 1 :]
    if "@" in hostport:
        return False  # a second @ lands in the host: invalid.
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return False  # unterminated IPv6 literal.
        if not _is_ipv6(hostport[1:close]):
            return False
        suffix = hostport[close + 1 :]
        return suffix == "" or re.match(r"^:\d*$", suffix) is not None
    if "[" in hostport or "]" in hostport:
        return False  # stray bracket in host.
    if hostport.count(":") > 1:
        return False  # host/port ambiguity.
    sep = hostport.rfind(":")
    return sep == -1 or re.match(r"^\d*$", hostport[sep + 1 :]) is not None


def _is_ipv6(literal: str) -> bool:
    return _valid_ipv6_literal(literal.encode("ascii"))


def _is_well_formed(s: str) -> bool:
    # A well-formed Unicode string has no unpaired surrogates. Python str CAN carry lone surrogates
    # (e.g. a caller-supplied chain_id with '\ud800'); re-encoding to UTF-8 rejects them. For strings
    # that came through json_decode, the unpaired-surrogate case was already rejected at the escape
    # level: this check is the defense for direct (non-JSON) inputs like producer fields.
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


# StringOrURI claim: non-empty, ≤ identifier_bytes, well-formed, valid StringOrURI.
def _require_string_or_uri(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} string")
    s = _unwrap(utf8_str(v.v))
    b = _unwrap(str_utf8(s))
    if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "identifier_bytes"))):
        _fail(f"claim: {key} bytes")
    if not _is_string_or_uri(s):
        _fail(f"claim: {key} string-or-uri")
    return s


def _require_int(v: Tagged | None, key: str) -> int:
    if v is None or not isinstance(v, JInt):
        _fail(f"claim: {key} integer")
    return v.v


def _require_uuid(v: Tagged | None, key: str) -> str:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} uuid string")
    s = _unwrap(utf8_str(v.v))
    if _UUID_RE.match(s) is None:
        _fail(f"claim: {key} uuid")
    return s


def _require_b64url_n(v: Tagged | None, key: str, n: int) -> bytes:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} b64url string")
    raw = _unwrap(base64url_decode(v.v))
    if len(raw) != n:
        _fail(f"claim: {key} width")
    return raw


def _require_operation(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} operation string")
    b = v.v
    if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "operation_bytes"))):
        _fail(f"claim: {key} operation bytes")
    s = _unwrap(utf8_str(b))
    if _OPERATION_PRINTABLE.match(s) is None:
        _fail(f"claim: {key} operation printable ASCII")
    return s


def _require_method(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} method string")
    b = v.v
    if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "method_bytes"))):
        _fail(f"claim: {key} method bytes")
    s = _unwrap(utf8_str(b))
    if _METHOD_TOKEN.match(s) is None:
        _fail(f"claim: {key} method token")
    return s


def _require_normalized_uri(v: Tagged | None, key: str, bounds: Bounds = MAXIMUM_BOUNDS) -> str:
    if v is None or not isinstance(v, JString):
        _fail(f"claim: {key} uri string")
    b = v.v
    if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "uri_bytes"))):
        _fail(f"claim: {key} uri bytes")
    s = _unwrap(utf8_str(b))
    norm = uri_normalize(b, bounds)
    if not isinstance(norm, Ok):
        _fail(f"claim: {key} uri normalized")
    if _unwrap(utf8_str(norm.value)) != s:
        _fail(f"claim: {key} uri pre-normalized")
    return s


def _validate_grant_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    pobj = _require_object_exact(
        p, ["v", "iss", "jti", "aud", "iat", "nbf", "exp", "cnf", "operations"], "grant payload"
    )
    v_v = pobj.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        _fail("grant: v=3")
    ops_v = pobj.v["operations"]
    if not isinstance(ops_v, JArray):
        _fail("grant: operations array")
    if not (1 <= len(ops_v.v) <= _unwrap(bounds_resolve(bounds, "operations"))):
        _fail("grant: operations count")
    names: set[str] = set()
    for op in ops_v.v:
        op_obj = _require_object_exact(op, ["name", "selectors"], "grant operation")
        name = _require_operation(op_obj.v.get("name"), "operation name", bounds)
        if name in names:
            _fail("grant: operation name unique")
        names.add(name)
        sels = op_obj.v["selectors"]
        if not isinstance(sels, JArray):
            _fail("grant: selectors array")
        if not (1 <= len(sels.v) <= _unwrap(bounds_resolve(bounds, "selectors"))):
            _fail("grant: selectors count")
        for s in sels.v:
            _unwrap(parse_selector(s, bounds))


def _extract_audience(v: Tagged | None, bounds: Bounds = MAXIMUM_BOUNDS) -> list[str]:
    if v is None:
        _fail("claim: aud")
    if isinstance(v, JString):
        s = _unwrap(utf8_str(v.v))
        b = _unwrap(str_utf8(s))
        if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "identifier_bytes"))):
            _fail("claim: aud bytes")
        if not _is_string_or_uri(s):
            _fail("claim: aud string-or-uri")
        return [s]
    if isinstance(v, JArray):
        if not (1 <= len(v.v) <= _unwrap(bounds_resolve(bounds, "audiences"))):
            _fail("claim: aud count")
        seen: set[str] = set()
        out: list[str] = []
        for a in v.v:
            if not isinstance(a, JString):
                _fail("claim: aud string")
            s = _unwrap(utf8_str(a.v))
            b = _unwrap(str_utf8(s))
            if not (1 <= len(b) <= _unwrap(bounds_resolve(bounds, "identifier_bytes"))):
                _fail("claim: aud member bytes")
            if not _is_string_or_uri(s):
                _fail("claim: aud member string-or-uri")
            if s in seen:
                _fail("claim: aud unique")
            seen.add(s)
            out.append(s)
        return out
    raise _invalid_error("claim: aud shape")


def _validate_proof_payload(p: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    if not isinstance(p, JObject):
        _fail("proof payload: object")
    has_nonce = "nonce" in p.v
    keys = (
        ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req", "nonce"]
        if has_nonce
        else ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"]
    )
    p = _require_object_exact(p, keys, "proof payload")
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        _fail("proof: v=3")
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
            _fail("proof: nonce string")
        ns = _unwrap(utf8_str(n.v))
        nb = _unwrap(str_utf8(ns))
        if not (1 <= len(nb) <= _unwrap(bounds_resolve(bounds, "nonce_bytes"))):
            _fail("proof: nonce bytes")


def _validate_anchor_payload(
    p: Tagged, payload_bytes: bytes, bounds: Bounds = MAXIMUM_BOUNDS
) -> None:
    p = _require_object_exact(
        p,
        ["anchor_id", "anchored_at", "chain_hash", "chain_id", "key_fingerprint", "sequence", "v"],
        "anchor payload",
    )
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        _fail("anchor: v=3")
    _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", bounds)
    _require_int(p.v.get("anchored_at"), "anchored_at")
    _require_string_or_uri(p.v.get("chain_id"), "chain_id", bounds)
    _require_int(p.v.get("sequence"), "sequence")
    _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)
    # Genesis binding (v1 §15 incorporated): sequence 0 carries the all-zero chain hash (the
    # canonical base64url of 32 zero bytes is 43 "A" characters).
    seq_v, hash_v = p.v["sequence"], p.v["chain_hash"]
    if (
        isinstance(seq_v, JInt)
        and seq_v.v == 0
        and (not isinstance(hash_v, JString) or hash_v.v != b"A" * 43)
    ):
        _fail("anchor payload: genesis")
    # Canonical form: the payload segment must be the exact JCS encoding (v1 §15 incorporated).
    if not _bytes_equal(_unwrap(jcs_encode(p, bounds)), payload_bytes):
        _fail("anchor payload: canonical")


def _validate_transition_payload(
    p: Tagged, payload_bytes: bytes, bounds: Bounds = MAXIMUM_BOUNDS
) -> None:
    p = _require_object_exact(
        p,
        [
            "chain_id",
            "effective_at",
            "from_key_fingerprint",
            "to_key_fingerprint",
            "to_key_id",
            "transition_id",
            "v",
        ],
        "transition payload",
    )
    v_v = p.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        _fail("transition: v=3")
    _require_string_or_uri(p.v.get("transition_id"), "transition_id", bounds)
    _require_string_or_uri(p.v.get("chain_id"), "chain_id", bounds)
    _require_int(p.v.get("effective_at"), "effective_at")
    _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    to_key_id = p.v["to_key_id"]
    if not isinstance(to_key_id, JString):
        _fail("transition: to_key_id string")
    s = _unwrap(utf8_str(to_key_id.v))
    if not (1 <= len(s) <= _unwrap(bounds_resolve(bounds, "kid_bytes"))):
        _fail("transition: to_key_id bytes")
    if _KID_CHARSET.match(s) is None:
        _fail("transition: to_key_id charset")
    # Canonical form: the payload segment must be the exact JCS encoding (v1 §15 incorporated).
    if not _bytes_equal(_unwrap(jcs_encode(p, bounds)), payload_bytes):
        _fail("transition payload: canonical")


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


# --- the 17 facade functions ---


def _trying(fn: Callable[[], _T]) -> Result[_T]:
    """Run a thunk that may raise InvalidError; convert to Result. Any NON-InvalidError propagates."""
    try:
        return Ok(fn())
    except InvalidError:
        return err()


# --- closed-Result input boundary ---
# Validate declared shapes and copy bytes-like inputs and underlying string data before
# protocol code uses caller values. Tagged algebra is depth-, width-, and node-bounded.
# Unsupported annotations are SDK defects and propagate; malformed inputs return Err.

_OPAQUE_ANNOTATIONS = (Bounds, JNull, JBool, JInt, JFloat, JString, JArray, JObject)


class _MissingField:
    """Sentinel: a struct attribute absent entirely (malformed construction)."""


_MISSING = _MissingField()


def _dataclass_hints(cls: type[object]) -> dict[str, object]:
    hints = get_type_hints(cls.__init__) if issubclass(cls, _Facts) else get_type_hints(cls)
    hints.pop("return", None)
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
        if is_dataclass(annotation) or issubclass(annotation, _Facts):
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
    """True iff value matches the declared annotation shape exactly (closed results and exact structured-input types (spec/bap-v1.md §§15-17))."""
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
        if is_dataclass(annotation) or issubclass(annotation, _Facts):
            if not isinstance(value, annotation):
                return False
            # A struct can arrive malformed (constructed via __new__ or a broken subclass) with
            # attributes missing entirely: that is a shape failure, never a crash (the gate
            # itself must uphold the closed surface it enforces).
            hints = _dataclass_hints(annotation)
            for name, sub in hints.items():
                member = getattr(value, name, _MISSING)
                if member is _MISSING or not _shape_ok(member, sub):
                    return False
            return True
        return False  # unreachable: _walk_annotation rejects unsupported types at import
    if _is_union(annotation):
        return any(_shape_ok(value, member) for member in get_args(annotation))
    origin = get_origin(annotation)
    if origin is tuple:
        # Variadic tuple[X, ...] carries the ELEMENT contract; the container accepts list|tuple
        # (the historical input surface: conformant fixtures pass lists; bodies iterate).
        if not isinstance(value, (list, tuple)):
            return False
        (elem, _rest) = get_args(annotation)
        return all(_shape_ok(item, elem) for item in cast(Sequence[object], value))
    if origin is Sequence:
        if not isinstance(value, (list, tuple)):
            return False
        (elem,) = get_args(annotation)
        return all(_shape_ok(item, elem) for item in cast(Sequence[object], value))
    if origin is Mapping:
        return isinstance(value, Mapping)
    return False  # unreachable: _walk_annotation rejects unsupported origins at import


_P = ParamSpec("_P")


def _closed_shape(fn: Callable[_P, Result[_T]]) -> Callable[_P, Result[_T]]:
    """Facade decorator: validate caller arguments against their declared shapes before the
    body runs; malformed values return Err, and accepted buffers are copied. Applied to all 17 public functions. Hints resolve lazily on the first call,
    facade signatures forward-reference structs defined later in this module (ExpectedExport);
    an unsupported annotation form therefore fails on first call (the family sweep exercises
    every facade, so it fails in CI, just not at import)."""
    signature = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Result[_T]:
        hints: dict[str, object] = get_type_hints(fn)
        for name, annotation in hints.items():
            if name != "return":
                _walk_annotation(annotation)
        bound = signature.bind(*args, **kwargs)
        try:
            for name, value in bound.arguments.items():
                annotation = hints.get(name)
                if annotation is not None:
                    bound.arguments[name] = _normalize_arg(value, annotation)
                    if not _shape_ok(bound.arguments[name], annotation):
                        return err()
        except InvalidError:
            return err()
        return cast(Callable[..., Result[_T]], fn)(*bound.args, **bound.kwargs)

    return wrapper


# 1. untrusted_key_locator (v1 §18, incorporated).
@_closed_shape
def untrusted_key_locator(compact: bytes, bounds: Bounds | None = None) -> Result[KeyLocator]:
    """Extract an untrusted key identifier for lookup; the result never selects a trusted key."""

    return _trying(lambda: _untrusted_key_locator_body(compact, bounds))


def _untrusted_key_locator_body(compact: bytes, bounds: Bounds | None) -> KeyLocator:
    # The v1 §18 locator decodes ONLY the protected segment: payload and signature are NOT
    # decoded, interpreted, or independently size-checked (REQ1-LOCATOR-opaque-payload,
    # incorporated). Split into exactly 3 segments, decode protected only, validate the grant
    # header + kid. (An invalid payload/signature does not affect the kid.)
    # Re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits).
    b = _unwrap(coerce_bounds(bounds if bounds is not None else MAXIMUM_BOUNDS))
    from .facts import KeyLocator

    if len(compact) > _unwrap(bounds_resolve(b, "compact_bytes")):
        _fail("key_locator: compact bound")
    # Exactly 3 segments on '.' (a 2- or 4-segment input fails the closed shape).
    parts = compact.split(b".")
    if len(parts) != 3:
        _fail("key_locator: three segments")
    protected_text = parts[0]
    # Empty payload/signature segments are ACCEPTED (only the protected segment is decoded;
    # an empty protected segment is invalid: it must base64url-decode to a header).
    if len(protected_text) == 0:
        _fail("key_locator: empty protected segment")
    if len(protected_text) > _unwrap(bounds_resolve(b, "encoded_segment_bytes")):
        _fail("key_locator: protected bound")
    protected_bytes = _unwrap(
        base64url_decode(protected_text, _unwrap(bounds_resolve(b, "decoded_segment_bytes")))
    )
    # Thread the caller-resolved bounds into the JSON decode (depth/total_nodes limits honor
    # bounds).
    h = _unwrap(json_decode(protected_bytes, b))
    h = _require_object_exact(h, ["alg", "typ", "kid"], "grant header")
    _require_string_lit(h, "alg", ALG, "grant header alg")
    _require_string_lit(h, "typ", GRANT_TYP, "grant header typ")
    kid_v = h.v.get("kid")
    if not isinstance(kid_v, JString):
        _fail("header: kid string")
    if not (1 <= len(kid_v.v) <= _unwrap(bounds_resolve(b, "kid_bytes"))):
        _fail("header: kid bytes")
    kid = _unwrap(utf8_str(kid_v.v))
    if _KID_CHARSET.match(kid) is None:
        _fail("header: kid charset")
    return KeyLocator(key_id=kid)


# 2. decode_grant (REQ1-VERIFY-decode-not-evaluated, incorporated).
@_closed_shape
def decode_grant(compact: bytes, bounds: Bounds | None = None) -> Result[GrantDecoded]:
    """Decode canonical grant bytes without signature verification or establishing trust."""

    return _trying(lambda: _decode_grant_body(compact, bounds))


def _decode_grant_body(compact: bytes, bounds: Bounds | None) -> GrantDecoded:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    seg = _parse_compact(compact, b)
    kid = _parse_grant_header(seg, b)
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_grant_payload(p, b)
    if not isinstance(p, JObject):
        _fail("decode_grant: payload object")
    iss = _require_string_or_uri(p.v.get("iss"), "iss", b)
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    aud = _extract_audience(p.v.get("aud"), b)
    iat = _require_int(p.v.get("iat"), "iat")
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if not (iat < exp) or not (nbf < exp):
        _fail("grant: times coherent")
    cnf = p.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    from .facts import GrantDecoded

    operations = p.v["operations"]
    assert isinstance(operations, JArray)
    return GrantDecoded(
        version=VERSION,
        key_id=kid,
        issuer=iss,
        grant_id=jti,
        audiences=tuple(aud),
        operations=tuple(op for op in operations.v if isinstance(op, JObject)),
        issued_at=iat,
        not_before=nbf,
        expires_at=exp,
        holder_thumbprint=jkt,
    )


# 3. decode_proof.
@_closed_shape
def decode_proof(compact: bytes, bounds: Bounds | None = None) -> Result[ProofDecoded]:
    """Decode canonical proof bytes without signature verification; diagnostic rendering redacts its nonce."""

    return _trying(lambda: _decode_proof_body(compact, bounds))


def _decode_proof_body(compact: bytes, bounds: Bounds | None) -> ProofDecoded:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    seg = _parse_compact(compact, b)
    holder_thumbprint, holder_public_key = _parse_proof_header(seg, b)
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_proof_payload(p, b)
    if not isinstance(p, JObject):
        _fail("decode_proof: payload object")
    jti = _require_string_or_uri(p.v.get("jti"), "jti", b)
    from .facts import ProofDecoded

    def text(name: str) -> str:
        member = p.v[name]
        assert isinstance(member, JString)
        return _unwrap(utf8_str(member.v))

    nonce = p.v.get("nonce")
    return ProofDecoded(
        version=VERSION,
        proof_id=jti,
        holder_thumbprint=holder_thumbprint,
        holder_public_key=holder_public_key,
        method=text("htm"),
        target_uri=text("htu"),
        issued_at=_require_int(p.v.get("iat"), "iat"),
        nonce=text("nonce") if nonce is not None else None,
        invocation_id=text("ba_inv"),
        operation=text("ba_op"),
        grant_hash=_require_b64url_n(p.v.get("ath"), "ath", 32),
        request_hash=_require_b64url_n(p.v.get("ba_req"), "ba_req", 32),
    )


# 4. verify_grant (REQ1-VERIFY-grant-exact, grant-times, no-iat-nbf-order; all incorporated).
@_closed_shape
def verify_grant(
    compact: bytes, trusted: TrustedIssuer, expected: ExpectedGrant
) -> Result[GrantFacts]:
    """Verify canonical grant bytes against an already-trusted issuer and explicit expected context."""

    return _trying(lambda: _verify_grant_body(compact, trusted, expected))


def _verify_grant_body(
    compact: bytes, trusted: TrustedIssuer, expected: ExpectedGrant
) -> GrantFacts:
    # Fail-closed shallow: a None OR a struct missing public_key/key_id must fail closed: not
    # raise AttributeError past the Result contract (the closed-Result discipline of the v1/v2
    # facades, carried into v3).
    if trusted is None:
        _fail("verify_grant: trusted issuer required")
    if (
        not isinstance(getattr(trusted, "public_key", None), bytes)
        or len(trusted.public_key) != PUBLIC_KEY_BYTES
    ):
        _fail("verify_grant: issuer key width")
    if not isinstance(getattr(trusted, "key_id", None), str):
        _fail("verify_grant: issuer key id")
    # Temporal context requires integers, nonnegative skew, and positive proof age.
    # Range checks alone admit fractional or boolean values (spec/bap-v1.md §16,
    # REQ1-VERIFY-time-bounds, REQ1-VERIFY-revalidate).
    if not _is_int(expected.evaluation_time):
        _fail("verify_grant: integer evaluation time")
    # Resolve caller bounds once and enforce them throughout nested parsing
    # (spec/bap-v1.md §17, REQ1-BOUNDS-tighten-only, incorporated by spec/bap-v3.md §2).
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    if (
        not _is_int(expected.clock_skew)
        or expected.clock_skew < 0
        or expected.clock_skew > _unwrap(bounds_resolve(b, "clock_skew"))
    ):
        _fail("verify_grant: skew")
    seg = _parse_compact(compact, b)
    kid = _parse_grant_header(seg, b)
    if kid != trusted.key_id:
        _fail("verify_grant: kid exact")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_grant_payload(p, b)
    if not isinstance(p, JObject):
        _fail("verify_grant: payload object")
    iss = _require_string_or_uri(p.v.get("iss"), "iss", b)
    if iss != expected.issuer:
        _fail("verify_grant: issuer exact")
    aud = _extract_audience(p.v.get("aud"), b)
    if expected.audience not in aud:
        _fail("verify_grant: audience match")
    iat = _require_int(p.v.get("iat"), "iat")
    nbf = _require_int(p.v.get("nbf"), "nbf")
    exp = _require_int(p.v.get("exp"), "exp")
    if not (iat < exp) or not (nbf < exp):
        _fail("verify_grant: times coherent")
    if not (iat <= expected.evaluation_time + expected.clock_skew):
        _fail("verify_grant: iat window")
    if not (nbf <= expected.evaluation_time + expected.clock_skew):
        _fail("verify_grant: nbf window")
    if not (exp > expected.evaluation_time - expected.clock_skew):
        _fail("verify_grant: exp window")
    cnf = p.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(trusted.public_key))))
    key = _import_public_key(trusted.public_key)
    if not _es256_verify(seg.signing_input, seg.signature, key):
        _fail("verify_grant: signature")
    from .facts import GrantFacts

    return GrantFacts(
        version=VERSION,
        issuer=iss,
        grant_id=_require_string_or_uri(p.v.get("jti"), "jti", b),
        issuer_key_fingerprint=fp,
        holder_thumbprint=jkt,
        matched_audience=expected.audience,
        issued_at=iat,
        not_before=nbf,
        expires_at=exp,
    )


# 5. check_envelope (REQ1-VERIFY-envelope-binding, incorporated).
@_closed_shape
def check_envelope(
    grant_compact: bytes, proof_compact: bytes, expected: ExpectedRequest
) -> Result[EnvelopeFacts]:
    """Verify a grant and holder proof against the exact caller-derived request; return facts, never permission."""

    return _trying(lambda: _check_envelope_body(grant_compact, proof_compact, expected))


def _check_envelope_body(
    grant_compact: bytes,
    proof_compact: bytes,
    expected: ExpectedRequest,
) -> EnvelopeFacts:
    t = expected.trusted_issuer
    # Fail-closed shallow: a None or malformed trusted_issuer must fail closed, not raise
    # AttributeError on the .public_key deref below.
    if t is None:
        _fail("check_envelope: trusted issuer required")
    if (
        not isinstance(getattr(t, "public_key", None), bytes)
        or len(t.public_key) != PUBLIC_KEY_BYTES
    ):
        _fail("check_envelope: issuer key width")
    if not isinstance(getattr(t, "key_id", None), str):
        _fail("check_envelope: issuer key id")
    # Temporal context requires integers, nonnegative skew, and positive proof age.
    # Range checks alone admit fractional or boolean values (spec/bap-v1.md §16,
    # REQ1-VERIFY-time-bounds, REQ1-VERIFY-revalidate).
    if not _is_int(expected.evaluation_time):
        _fail("check_envelope: integer evaluation time")
    # Resolve caller bounds once and enforce them throughout nested parsing
    # (spec/bap-v1.md §17, REQ1-BOUNDS-tighten-only, incorporated by spec/bap-v3.md §2).
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    if (
        not _is_int(expected.clock_skew)
        or expected.clock_skew < 0
        or expected.clock_skew > _unwrap(bounds_resolve(b, "clock_skew"))
    ):
        _fail("check_envelope: skew")
    if (
        not _is_int(expected.proof_max_age)
        or expected.proof_max_age <= 0
        or expected.proof_max_age > _unwrap(bounds_resolve(b, "proof_max_age"))
    ):
        _fail("check_envelope: proof_max_age")
    # --- verify grant (issuer signature + context) ---
    gseg = _parse_compact(grant_compact, b)
    gkid = _parse_grant_header(gseg, b)
    if gkid != t.key_id:
        _fail("check_envelope: grant kid")
    gp = _unwrap(json_decode(gseg.payload_bytes, b))
    _validate_grant_payload(gp, b)
    if not isinstance(gp, JObject):
        _fail("check_envelope: grant payload")
    giss = _require_string_or_uri(gp.v.get("iss"), "iss", b)
    if giss != expected.issuer:
        _fail("check_envelope: issuer")
    gaud = _extract_audience(gp.v.get("aud"), b)
    if expected.audience not in gaud:
        _fail("check_envelope: audience")
    giat = _require_int(gp.v.get("iat"), "iat")
    gnbf = _require_int(gp.v.get("nbf"), "nbf")
    gexp = _require_int(gp.v.get("exp"), "exp")
    # check_envelope must enforce grant-time coherence (iat<exp, nbf<exp), mirroring the
    # incorporated coherent-times check that fires at parse time.
    if not (giat < gexp) or not (gnbf < gexp):
        _fail("check_envelope: grant times coherent")
    if not (giat <= expected.evaluation_time + expected.clock_skew):
        _fail("check_envelope: grant iat")
    if not (gnbf <= expected.evaluation_time + expected.clock_skew):
        _fail("check_envelope: grant nbf")
    if not (gexp > expected.evaluation_time - expected.clock_skew):
        _fail("check_envelope: grant exp")
    gfp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(t.public_key))))
    gkey = _import_public_key(t.public_key)
    if not _es256_verify(gseg.signing_input, gseg.signature, gkey):
        _fail("check_envelope: grant signature")
    # --- verify proof (holder signature) ---
    pseg = _parse_compact(proof_compact, b)
    holder_thumbprint, holder_key = _parse_proof_header(pseg, b)
    pp = _unwrap(json_decode(pseg.payload_bytes, b))
    _validate_proof_payload(pp, b)
    hkey = _import_public_key(holder_key)
    if not _es256_verify(pseg.signing_input, pseg.signature, hkey):
        _fail("check_envelope: proof signature")
    if not isinstance(pp, JObject):
        _fail("check_envelope: proof payload")
    # Hash the complete received grant compact after bounded structural scanning
    # (spec/bap-v1.md §11, REQ1-CLAIM-ath; §17, REQ1-BOUNDS-ordering).
    _scan_compact(grant_compact, b)
    ath_raw = _unwrap(sha256(grant_compact))
    ath_b64 = _unwrap(utf8_str(_unwrap(base64url_encode(ath_raw))))
    pp_ath = pp.v["ath"]
    if not isinstance(pp_ath, JString) or _unwrap(utf8_str(pp_ath.v)) != ath_b64:
        _fail("check_envelope: ath")
    # Method / URI / invocation / operation bindings.
    htm = _require_method(pp.v.get("htm"), "htm", b)
    if htm != expected.method:
        _fail("check_envelope: method")
    htu = _require_normalized_uri(pp.v.get("htu"), "htu", b)
    if htu != expected.target_uri:
        _fail("check_envelope: target_uri")
    ba_inv = _require_uuid(pp.v.get("ba_inv"), "ba_inv")
    if ba_inv != expected.invocation_id:
        _fail("check_envelope: invocation_id")
    ba_op = _require_operation(pp.v.get("ba_op"), "ba_op", b)
    if ba_op != expected.operation:
        _fail("check_envelope: operation")
    # ba_req = request_digest(operation, cast_arguments) (base64url).
    ba_req_raw = _unwrap(compute_request_digest(ba_op, expected.cast_arguments, b))
    ba_req_b64 = _unwrap(utf8_str(_unwrap(base64url_encode(ba_req_raw))))
    pp_ba_req = pp.v["ba_req"]
    if not isinstance(pp_ba_req, JString) or _unwrap(utf8_str(pp_ba_req.v)) != ba_req_b64:
        _fail("check_envelope: ba_req")
    # Proof time window.
    piat = _require_int(pp.v.get("iat"), "iat")
    if not (piat >= expected.evaluation_time - expected.proof_max_age - expected.clock_skew):
        _fail("check_envelope: proof iat min")
    if not (piat <= expected.evaluation_time + expected.clock_skew):
        _fail("check_envelope: proof iat max")
    # Nonce binding.
    pp_nonce = pp.v.get("nonce")
    if isinstance(expected.nonce, NonceNotRequired):
        if pp_nonce is not None:
            _fail("check_envelope: nonce must be absent")
    else:
        if (
            pp_nonce is None
            or not isinstance(pp_nonce, JString)
            or _unwrap(utf8_str(pp_nonce.v)) != expected.nonce.value
        ):
            _fail("check_envelope: nonce mismatch")
    # Holder thumbprint must match grant cnf.jkt (the EC thumbprint of the proof JWK).
    cnf = gp.v["cnf"]
    cnf = _require_object_exact(cnf, ["jkt"], "grant cnf")
    jkt = _require_b64url_n(cnf.v.get("jkt"), "jkt", 32)
    if not _bytes_equal(jkt, holder_thumbprint):
        _fail("check_envelope: holder thumbprint")
    # The requested operation must be unique + every selector conjunctively matches.
    ops_v = gp.v.get("operations")
    if ops_v is None or not isinstance(ops_v, JArray):
        _fail("check_envelope: operations")
    matching = [
        op
        for op in ops_v.v
        if isinstance(op, JObject)
        and (name_v := op.v.get("name")) is not None
        and isinstance(name_v, JString)
        and _unwrap(utf8_str(name_v.v)) == expected.operation
    ]
    if len(matching) != 1:
        _fail("check_envelope: unique operation")
    match_op = matching[0]
    sels_v = match_op.v.get("selectors")
    if sels_v is None or not isinstance(sels_v, JArray):
        _fail("check_envelope: selectors")
    for s in sels_v.v:
        sel = _unwrap(parse_selector(s, b))
        if not _unwrap(selector_matches(sel, expected.cast_arguments)):
            _fail("check_envelope: selector")
    from .facts import EnvelopeFacts

    return EnvelopeFacts(
        version=VERSION,
        issuer=giss,
        grant_id=_require_string_or_uri(gp.v.get("jti"), "jti", b),
        issuer_key_fingerprint=gfp,
        holder_thumbprint=holder_thumbprint,
        matched_audience=expected.audience,
        grant_issued_at=giat,
        grant_not_before=gnbf,
        grant_expires_at=gexp,
        proof_id=_require_string_or_uri(pp.v.get("jti"), "jti", b),
        invocation_id=ba_inv,
        operation=ba_op,
        uri=htu,
        grant_hash=ath_raw,
        request_hash=ba_req_raw,
        proof_issued_at=piat,
    )


# 6. request_digest (the facade; returns Ok<raw 32-byte digest> | Err). The v3 digest is
# base64url(SHA-256("BAP3-REQUEST\0" || JCS([operation, typed(cast_arguments)]))): the v1 §7
# construction with the REQ3-SIGNING-digest-prefix substitution.
@_closed_shape
def request_digest(
    operation: str, cast_arguments: Tagged, bounds: Bounds | None = None
) -> Result[bytes]:
    """Hash the canonical tagged arguments and request binding with the selected contract-major."""

    return _trying(
        lambda: _unwrap(
            compute_request_digest(
                operation, cast_arguments, bounds if bounds is not None else MAXIMUM_BOUNDS
            )
        )
    )


def compute_request_digest(operation: str, cast_arguments: Tagged, bounds: Bounds) -> Result[bytes]:
    """The v3-profile request digest core (returns the raw 32-byte digest).

    Mirrors the shared digest core (digest.py) with the profile-fixed ``BAP3-REQUEST\\0`` prefix;
    the shared module is the v1/v2-frozen surface, so v3 carries its own domain-separated core
    over the same shared ``typed`` projection and bounds gates.
    """
    # Re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits).
    try:
        operation = _text(operation)
        cast_arguments = _normalize_tagged(cast_arguments, bounds)
        b = _unwrap(coerce_bounds(bounds))
        op_bytes = _unwrap(str_utf8(operation))
        if not (1 <= len(op_bytes) <= _unwrap(bounds_resolve(b, "operation_bytes"))):
            _fail("request_digest: operation bound")
        for byte in op_bytes:
            if byte < 0x20 or byte > 0x7E:
                _fail("request_digest: operation printable ASCII")
        # The projection: [operation_string, typed(cast_arguments)].
        from .digest import typed_project

        projected = _unwrap(typed_project(cast_arguments))
        array: Tagged = JArray((JString(op_bytes), projected))
        # Per-node bounds on the TYPED projection (not the raw args): `typed` deepens the tree, so
        # the depth boundary tightens and total_nodes is reachable inline.
        if not _within_tagged_bounds(array, 0, b):
            _fail("request_digest: cast_arguments bounds")
        if _count_tagged_nodes(array) > _unwrap(bounds_resolve(b, "total_nodes")):
            _fail("request_digest: total_nodes")
        jcs = _unwrap(jcs_encode(array, b))
        if len(jcs) > _unwrap(bounds_resolve(b, "jcs_bytes")):
            _fail("request_digest: jcs_bytes")
        return Ok(_unwrap(sha256(REQUEST_PREFIX, jcs)))
    except InvalidError:
        return err()


def _within_tagged_bounds(v: Tagged, level: int, bounds: Bounds) -> bool:
    """Per-node-type bounds gate over the tagged algebra (the shared digest core's gate,
    carried locally so the v3 prefix variant enforces the identical limits)."""
    if isinstance(v, (JNull, JBool)):
        return level <= _unwrap(bounds_resolve(bounds, "depth"))
    if isinstance(v, JInt):
        return level <= _unwrap(bounds_resolve(bounds, "depth")) and abs(v.v) <= _unwrap(
            bounds_resolve(bounds, "integer_magnitude")
        )
    if isinstance(v, JFloat):
        return (
            level <= _unwrap(bounds_resolve(bounds, "depth"))
            and v.v == v.v  # not NaN
            and v.v not in (float("inf"), float("-inf"))
            and abs(v.v) <= _unwrap(bounds_resolve(bounds, "float_magnitude"))
        )
    if isinstance(v, JString):
        return level <= _unwrap(bounds_resolve(bounds, "depth")) and len(v.v) <= _unwrap(
            bounds_resolve(bounds, "string_bytes")
        )
    if isinstance(v, JArray):
        return (
            level < _unwrap(bounds_resolve(bounds, "depth"))
            and len(v.v) <= _unwrap(bounds_resolve(bounds, "array_items"))
            and all(_within_tagged_bounds(item, level + 1, bounds) for item in v.v)
        )
    if isinstance(v, JObject):
        return (
            level < _unwrap(bounds_resolve(bounds, "depth"))
            and len(v.v) <= _unwrap(bounds_resolve(bounds, "object_members"))
            and all(_within_tagged_bounds(val, level + 1, bounds) for val in v.v.values())
        )
    return False  # type: ignore[unreachable]  # unreachable: the algebra is closed


def _count_tagged_nodes(v: Tagged) -> int:
    """Node count: one node per value (scalar OR container); object keys are not nodes."""
    if isinstance(v, JArray):
        return 1 + sum(_count_tagged_nodes(item) for item in v.v)
    if isinstance(v, JObject):
        return 1 + sum(_count_tagged_nodes(val) for val in v.v.values())
    return 1


# 7. encode_consumption_entry (v1 §15 Consumption rows, incorporated). Returns canonical row
# bytes + hash.
@_closed_shape
def encode_consumption_entry(
    entry: ConsumptionEntry, bounds: Bounds | None = None
) -> Result[EncodedConsumptionEntry]:
    """Encode one canonical consumption row and compute its link hash; write nothing."""

    return _trying(lambda: _encode_consumption_entry_body(entry, bounds))


def _encode_consumption_entry_body(
    entry: ConsumptionEntry, bounds: Bounds | None
) -> EncodedConsumptionEntry:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    if (
        not isinstance(entry.sequence, int)
        or isinstance(entry.sequence, bool)
        or entry.sequence < 1
    ):
        _fail("encode_consumption_entry: positive sequence")
    _require(len(entry.previous_hash) == 32, "encode_consumption_entry: previous_hash width")
    _require(len(entry.commitment) == 32, "encode_consumption_entry: commitment width")
    chain_id_bytes = _unwrap(str_utf8(entry.chain_id))
    if not (1 <= len(chain_id_bytes) <= _unwrap(bounds_resolve(b, "identifier_bytes"))):
        _fail("encode_consumption_entry: chain_id bytes")
    if not _is_string_or_uri(entry.chain_id):
        _fail("encode_consumption_entry: chain_id string-or-uri")
    # Genesis invariant (v1 §15 incorporated): sequence 1 requires the all-zero predecessor.
    # The verifier re-checks this; the producer rejects pre-signing.
    if entry.sequence == 1 and not _bytes_equal(entry.previous_hash, DEFAULT_HASH):
        _fail("encode_consumption_entry: genesis predecessor")
    row_bytes = _canonical_row_bytes_from_id(
        chain_id_bytes, entry.sequence, entry.previous_hash, entry.commitment, b
    )
    if len(row_bytes) > _unwrap(bounds_resolve(b, "chain_row_bytes")):
        _fail("encode_consumption_entry: chain_row_bytes")
    hash_ = _unwrap(sha256(ROW_PREFIX, row_bytes))
    return EncodedConsumptionEntry(bytes_=row_bytes, hash_=hash_)


def _canonical_row_bytes_from_id(
    chain_id_bytes: bytes, sequence: int, previous_hash: bytes, commitment: bytes, b: Bounds
) -> bytes:
    """The canonical row bytes shared by the producer and the verifier (so the verifier's re-encode
    produces EXACTLY the bytes the producer emits and the chain hash is computed over)."""
    members: dict[str, Tagged] = {
        "chain_id": JString(chain_id_bytes),
        "commitment": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(commitment))))))
        ),
        "previous": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(previous_hash))))))
        ),
        "sequence": JInt(sequence),
        "v": JInt(VERSION),
    }
    return _unwrap(jcs_encode(JObject(members), b))


def _canonical_row_bytes(
    chain_id: str,
    sequence: int,
    previous_hash: bytes,
    commitment: bytes,
    b: Bounds = MAXIMUM_BOUNDS,
) -> bytes:
    return _canonical_row_bytes_from_id(
        _unwrap(str_utf8(chain_id)), sequence, previous_hash, commitment, b
    )


# 8. check_chain (v1 §15 Consumption rows; REQ1-CHAIN-raw-rows-bounds, incorporated).
@_closed_shape
def check_chain(chain: ChainInput, expected: ExpectedChain) -> Result[ChainFacts]:
    """Verify canonical rows and their expected hash-chain boundary without live state."""

    return _trying(lambda: _check_chain_body(chain, expected))


def _check_chain_body(chain: ChainInput, expected: ExpectedChain) -> ChainFacts:
    # Expected-side AND ChainInput-side chain integers type-strict (Python 1 == True would
    # otherwise wrong-accept row_count=True / first_sequence=True).
    _expected_int(expected.first_sequence, "check_chain: first_sequence type")
    _expected_int(expected.last_sequence, "check_chain: last_sequence type")
    _expected_int(expected.row_count, "check_chain: row_count type")
    _expected_int(chain.first_sequence, "check_chain: input first_sequence type")
    _expected_int(chain.last_sequence, "check_chain: input last_sequence type")
    _expected_int(chain.row_count, "check_chain: input row_count type")
    # Resolve caller bounds once and enforce them throughout nested parsing
    # (spec/bap-v1.md §17, REQ1-BOUNDS-tighten-only, incorporated by spec/bap-v3.md §2).
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    if (
        not isinstance(chain.chain_id, str)
        or not _is_string_or_uri(chain.chain_id)
        or expected.chain_id != chain.chain_id
    ):
        _fail("check_chain: chain_id")
    if expected.first_sequence != chain.first_sequence:
        _fail("check_chain: first_sequence")
    if expected.last_sequence != chain.last_sequence:
        _fail("check_chain: last_sequence")
    if expected.row_count != chain.row_count:
        _fail("check_chain: row_count")
    if chain.row_count != len(chain.rows) or chain.row_count < 1:
        _fail("check_chain: row count")
    if chain.row_count > _unwrap(bounds_resolve(b, "chain_rows")):
        _fail("check_chain: chain_rows bound")
    if chain.last_sequence != chain.first_sequence + chain.row_count - 1:
        _fail("check_chain: range")
    # Genesis: firstSequence === 1 requires the all-zero predecessor.
    if chain.first_sequence == 1 and not _bytes_equal(expected.previous_hash, DEFAULT_HASH):
        _fail("check_chain: genesis predecessor")
    # chain.previous_hash must equal the expected value in BOTH cases (genesis + non-genesis),
    # so chain.previous_hash is never an unverified echo flowing into the returned facts.
    if not _bytes_equal(expected.previous_hash, chain.previous_hash):
        _fail("check_chain: previous_hash")
    previous = expected.previous_hash
    sequence = chain.first_sequence
    for i, row_bytes in enumerate(chain.rows):
        if len(row_bytes) > _unwrap(bounds_resolve(b, "chain_row_bytes")):
            _fail(f"check_chain: row {i} bytes")
        row = _unwrap(json_decode(row_bytes, b))
        row = _require_object_exact(
            row, ["v", "chain_id", "sequence", "previous", "commitment"], f"check_chain row {i}"
        )
        v_v = row.v["v"]
        if not isinstance(v_v, JInt) or v_v.v != VERSION:
            _fail(f"check_chain row {i}: v")
        cid_v = row.v["chain_id"]
        if not isinstance(cid_v, JString) or _unwrap(utf8_str(cid_v.v)) != chain.chain_id:
            _fail(f"check_chain row {i}: chain_id")
        seq_v = row.v["sequence"]
        if not isinstance(seq_v, JInt) or seq_v.v != sequence:
            _fail(f"check_chain row {i}: sequence")
        # Sequence numbers must be strictly positive (spec/bap-v1.md §15). The encode_consumption_entry
        # producer already rejects sequence < 1, but the raw row stream is untrusted input here,
        # so reject sequence 0 at verify time too.
        if seq_v.v < 1:
            _fail(f"check_chain row {i}: sequence positive")
        prev_raw = _require_b64url_n(row.v.get("previous"), "previous", 32)
        if not _bytes_equal(prev_raw, previous):
            _fail(f"check_chain row {i}: previous link")
        commitment_raw = _require_b64url_n(row.v.get("commitment"), "commitment", 32)
        # Canonical re-encode: the input row bytes MUST byte-equal the canonical re-encoded form.
        # This rejects whitespace drift and member-order drift that would otherwise hash to a
        # different chain link.
        re_encoded = _canonical_row_bytes(chain.chain_id, seq_v.v, prev_raw, commitment_raw, b)
        if not _bytes_equal(re_encoded, row_bytes):
            _fail(f"check_chain row {i}: canonical")
        previous = _unwrap(sha256(ROW_PREFIX, row_bytes))
        sequence += 1
    if not _bytes_equal(previous, expected.last_hash):
        _fail("check_chain: head")
    from .facts import ChainFacts

    # Return the VERIFIED expected.previous_hash, not the caller's chain.previous_hash input.
    # Python bytes are immutable so no aliasing hazard, but the value must be the verified one.
    return ChainFacts(
        version=VERSION,
        chain_id=chain.chain_id,
        first_sequence=chain.first_sequence,
        last_sequence=chain.last_sequence,
        row_count=chain.row_count,
        previous_hash=expected.previous_hash,
        last_hash=previous,
    )


# 9. grant_signing_input (the deterministic producer; REQ1-SIGNING-deterministic-produce,
# incorporated).
@_closed_shape
def grant_signing_input(grant: GrantProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    """Validate grant claims and return exact JWS signing bytes; no private key enters the verifier."""

    return _trying(lambda: _grant_signing_input_body(grant, bounds))


def _grant_signing_input_body(grant: GrantProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    key_id_bytes = _unwrap(str_utf8(grant.key_id))
    if not (1 <= len(key_id_bytes) <= _unwrap(bounds_resolve(b, "kid_bytes"))):
        _fail("grant_signing_input: key_id bytes")
    if _KID_CHARSET.match(grant.key_id) is None:
        _fail("grant_signing_input: key_id charset")
    if not _is_string_or_uri(grant.issuer):
        _fail("grant_signing_input: issuer")
    if not _is_string_or_uri(grant.grant_id):
        _fail("grant_signing_input: grant_id")
    if not (1 <= len(grant.audiences) <= _unwrap(bounds_resolve(b, "audiences"))):
        _fail("grant_signing_input: audiences count")
    for a in grant.audiences:
        ab = _unwrap(str_utf8(a))
        if not (1 <= len(ab) <= _unwrap(bounds_resolve(b, "identifier_bytes"))):
            _fail("grant_signing_input: audience bytes")
        if not _is_string_or_uri(a):
            _fail("grant_signing_input: audience string-or-uri")
    if not (
        isinstance(grant.issued_at, int)
        and isinstance(grant.not_before, int)
        and isinstance(grant.expires_at, int)
    ):
        _fail("grant_signing_input: integer times")
    jkt_raw = _unwrap(base64url_decode(_unwrap(str_utf8(grant.holder_thumbprint))))
    if len(jkt_raw) != 32:
        _fail("grant_signing_input: holder_thumbprint width")
    if not (1 <= len(grant.operations) <= _unwrap(bounds_resolve(b, "operations"))):
        _fail("grant_signing_input: operations count")
    header: dict[str, Tagged] = {
        "alg": JString(_unwrap(str_utf8(ALG))),
        "kid": JString(key_id_bytes),
        "typ": JString(_unwrap(str_utf8(GRANT_TYP))),
    }
    payload = _build_grant_payload(grant, b)
    return SigningInput(
        kind="grant",
        protected_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(JObject(header), b)))))
                )
            )
        ),
        payload_segment=_unwrap(
            str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(payload, b)))))))
        ),
    )


def _build_grant_payload(grant: GrantProducer, b: Bounds) -> Tagged:
    aud_members = tuple(JString(_unwrap(str_utf8(a))) for a in grant.audiences)
    ops_members: list[Tagged] = []
    for op in grant.operations:
        name_bytes = _unwrap(str_utf8(op.name))
        if not (1 <= len(name_bytes) <= _unwrap(bounds_resolve(b, "operation_bytes"))):
            _fail("grant_signing_input: operation name bytes")
        if _OPERATION_PRINTABLE.match(op.name) is None:
            _fail("grant_signing_input: operation name charset")
        if not (1 <= len(op.selectors) <= _unwrap(bounds_resolve(b, "selectors"))):
            _fail("grant_signing_input: selectors count")
        sels = tuple(_selector_to_tagged(s, b) for s in op.selectors)
        op_members: dict[str, Tagged] = {
            "name": JString(name_bytes),
            "selectors": JArray(sels),
        }
        ops_members.append(JObject(op_members))
    cnf_members: dict[str, Tagged] = {"jkt": JString(_unwrap(str_utf8(grant.holder_thumbprint)))}
    payload: dict[str, Tagged] = {
        "aud": JArray(tuple(aud_members)),
        "cnf": JObject(cnf_members),
        "exp": JInt(grant.expires_at),
        "iat": JInt(grant.issued_at),
        "iss": JString(_unwrap(str_utf8(grant.issuer))),
        "jti": JString(_unwrap(str_utf8(grant.grant_id))),
        "nbf": JInt(grant.not_before),
        "operations": JArray(tuple(ops_members)),
        "v": JInt(VERSION),
    }
    return JObject(payload)


def _selector_to_tagged(s: SelectorInput, b: Bounds) -> Tagged:
    if s == "all":
        return JObject({"kind": JString(_unwrap(str_utf8("all")))})
    if isinstance(s, Mapping):
        kind = s.get("kind")
        if kind == "all":
            return JObject({"kind": JString(_unwrap(str_utf8("all")))})
        if kind == "equals":
            path = _validate_path(cast("Sequence[str]", s["path"]), b)
            value = cast("Tagged", s["value"])
            _validate_selector_value(value, b)
            if not _integral_float_free(value):
                _fail("selector: integral float")
            return JObject(
                {
                    "kind": JString(_unwrap(str_utf8("equals"))),
                    "path": path,
                    "value": value,
                }
            )
        if kind == "one_of":
            path = _validate_path(cast("Sequence[str]", s["path"]), b)
            values = cast("Sequence[Tagged]", s["values"])
            if not (1 <= len(values) <= _unwrap(bounds_resolve(b, "one_of_values"))):
                _fail("selector: values count")
            for v in values:
                _validate_selector_value(v, b)
                if not _integral_float_free(v):
                    _fail("selector: integral float")
            return JObject(
                {
                    "kind": JString(_unwrap(str_utf8("one_of"))),
                    "path": path,
                    "values": JArray(tuple(values)),
                }
            )
        if isinstance(kind, str) and kind in ("lte", "gte"):
            # The {kind, path, value} member set with a numeric bound (the v2 §4 algebra
            # incorporated). The bound arrives as a Tagged value (programmatic callers) or a
            # JSON-decoded raw scalar (the conformance runner); bool is not a numeric tag
            # (Python bool is int, so the bool arm must precede the int arm).
            path = _validate_path(cast("Sequence[str]", s["path"]), b)
            raw = s["value"]
            bound: Tagged
            if isinstance(raw, (JInt, JFloat)):
                bound = raw
            elif isinstance(raw, bool):
                _fail("selector: numeric bound")
            elif isinstance(raw, int):
                bound = JInt(raw)
            elif isinstance(raw, float):
                bound = JFloat(raw)
            else:
                _fail("selector: numeric bound")
            _validate_selector_value(bound, b)
            if not _integral_float_free(bound):
                _fail("selector: integral float")
            return JObject(
                {
                    "kind": JString(_unwrap(str_utf8(kind))),
                    "path": path,
                    "value": bound,
                }
            )
    raise _invalid_error("selector: shape")


def _validate_path(path: Sequence[str], b: Bounds) -> Tagged:
    if not (1 <= len(path) <= _unwrap(bounds_resolve(b, "path_segments"))):
        _fail("selector: path length")
    segs: list[Tagged] = []
    for seg in path:
        sb = _unwrap(str_utf8(seg))
        if not (1 <= len(sb) <= _unwrap(bounds_resolve(b, "key_bytes"))):
            _fail("selector: path segment bytes")
        segs.append(JString(sb))
    return JArray(tuple(segs))


def _validate_selector_value(v: Tagged, b: Bounds) -> None:
    _check_node(v, 1, b)


def _check_node(v: Tagged, depth: int, b: Bounds) -> None:
    if depth > _unwrap(bounds_resolve(b, "depth")):
        _fail("selector: value depth")
    if isinstance(v, JString):
        if len(v.v) > _unwrap(bounds_resolve(b, "string_bytes")):
            _fail("selector: string bytes")
    elif isinstance(v, JInt):
        if abs(v.v) > _unwrap(bounds_resolve(b, "integer_magnitude")):
            _fail("selector: int magnitude")
    elif isinstance(v, JFloat):
        if abs(v.v) > _unwrap(bounds_resolve(b, "float_magnitude")):
            _fail("selector: float magnitude")
    elif isinstance(v, JArray):
        if len(v.v) > _unwrap(bounds_resolve(b, "array_items")):
            _fail("selector: array items")
        for item in v.v:
            _check_node(item, depth + 1, b)
    elif isinstance(v, JObject):
        if len(v.v) > _unwrap(bounds_resolve(b, "object_members")):
            _fail("selector: object members")
        for val in v.v.values():
            _check_node(val, depth + 1, b)


# 10. proof_signing_input (REQ1-SIGNING-deterministic-produce, incorporated).
@_closed_shape
def proof_signing_input(proof: ProofProducer, bounds: Bounds | None = None) -> Result[SigningInput]:
    """Validate proof claims and return the canonical JWS signing input for the caller to sign."""

    return _trying(lambda: _proof_signing_input_body(proof, bounds))


def _proof_signing_input_body(proof: ProofProducer, bounds: Bounds | None) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    # The holder key is the raw 65-byte uncompressed SEC1 point; the producer validates it in
    # full (width, form, coordinate range, on-curve) so it never mints a proof JWK the profile's
    # own decode path would reject.
    _validated_public_key(proof.holder_public_key)
    proof_id_bytes = _unwrap(str_utf8(proof.proof_id))
    if not _is_string_or_uri(proof.proof_id) or not (
        1 <= len(proof_id_bytes) <= _unwrap(bounds_resolve(b, "identifier_bytes"))
    ):
        _fail("proof_signing_input: proof_id")
    method_bytes = _unwrap(str_utf8(proof.method))
    if not (1 <= len(method_bytes) <= _unwrap(bounds_resolve(b, "method_bytes"))):
        _fail("proof_signing_input: method bytes")
    if _METHOD_TOKEN.match(proof.method) is None:
        _fail("proof_signing_input: method token")
    htu_norm = uri_normalize(_unwrap(str_utf8(proof.target_uri)), b)
    if not isinstance(htu_norm, Ok):
        _fail("proof_signing_input: htu")
    if _unwrap(utf8_str(htu_norm.value)) != proof.target_uri:
        _fail("proof_signing_input: htu pre-normalized")
    if not isinstance(proof.issued_at, int) or isinstance(proof.issued_at, bool):
        _fail("proof_signing_input: integer iat")
    if _UUID_RE.match(proof.invocation_id) is None:
        _fail("proof_signing_input: invocation_id")
    op_bytes = _unwrap(str_utf8(proof.operation))
    if not (1 <= len(op_bytes) <= _unwrap(bounds_resolve(b, "operation_bytes"))):
        _fail("proof_signing_input: operation bytes")
    if _OPERATION_PRINTABLE.match(proof.operation) is None:
        _fail("proof_signing_input: operation charset")
    if proof.nonce is not None:
        if not _is_well_formed(proof.nonce):
            _fail("proof_signing_input: nonce well-formed")
        nb = _unwrap(str_utf8(proof.nonce))
        if not (1 <= len(nb) <= _unwrap(bounds_resolve(b, "nonce_bytes"))):
            _fail("proof_signing_input: nonce bytes")
    jwk = _unwrap(jwk_from_public_key(proof.holder_public_key))
    header_members: dict[str, Tagged] = {
        "alg": JString(_unwrap(str_utf8(ALG))),
        "jwk": _jwk_to_tagged(jwk),
        "typ": JString(_unwrap(str_utf8(PROOF_TYP))),
    }
    # Producer ath: gate the grant compact by scan (shape+size, NOT base64url canonicity) before
    # hashing it into `ath`: a caller-supplied non-compact grant must not be embedded as
    # sha256(garbage) in the proof.
    _scan_compact(proof.grant_compact, b)
    ath_raw = _unwrap(sha256(proof.grant_compact))
    ba_req_raw = _unwrap(compute_request_digest(proof.operation, proof.cast_arguments, b))
    payload_members: dict[str, Tagged] = {
        "ath": JString(_unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(ath_raw))))))),
        "ba_inv": JString(_unwrap(str_utf8(proof.invocation_id))),
        "ba_op": JString(op_bytes),
        "ba_req": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(ba_req_raw))))))
        ),
        "htm": JString(method_bytes),
        "htu": JString(_unwrap(str_utf8(proof.target_uri))),
        "iat": JInt(proof.issued_at),
        "jti": JString(proof_id_bytes),
        "v": JInt(VERSION),
    }
    if proof.nonce is not None:
        payload_members["nonce"] = JString(_unwrap(str_utf8(proof.nonce)))
    return SigningInput(
        kind="proof",
        protected_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(
                        _unwrap(base64url_encode(_unwrap(jcs_encode(JObject(header_members), b))))
                    )
                )
            )
        ),
        payload_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(
                        _unwrap(base64url_encode(_unwrap(jcs_encode(JObject(payload_members), b))))
                    )
                )
            )
        ),
    )


def _jwk_to_tagged(jwk: EcPublic) -> Tagged:
    members: dict[str, Tagged] = {
        "crv": JString(_unwrap(str_utf8(jwk.crv))),
        "kty": JString(_unwrap(str_utf8(jwk.kty))),
        "x": JString(_unwrap(str_utf8(jwk.x))),
        "y": JString(_unwrap(str_utf8(jwk.y))),
    }
    return JObject(members)


# Revalidate the declared kind, closed header and payload, and all size ceilings
# at assembly (spec/bap-v1.md §16, REQ1-VERIFY-revalidate; spec/bap-v3.md §2).
@_closed_shape
def assemble_compact(
    input_: SigningInput, signature: bytes, bounds: Bounds | None = None
) -> Result[bytes]:
    """Assemble canonical JWS segments and a canonical signature; this does not verify the signature."""

    return _trying(lambda: _assemble_compact_body(input_, signature, bounds))


def _assemble_compact_body(input_: SigningInput, signature: bytes, bounds: Bounds | None) -> bytes:
    # spec/bap-v1.md §17 divergence closed (2026-08-18): apply caller-tightened segment
    # and compact ceilings at assembly (spec/bap-v1.md §17,
    # REQ1-BOUNDS-tighten-only, REQ1-BOUNDS-ordering). Absent bounds use maxima.
    b = _unwrap(coerce_bounds(bounds if bounds is not None else MAXIMUM_BOUNDS))
    if len(input_.protected_segment) > _unwrap(bounds_resolve(b, "encoded_segment_bytes")) or len(
        input_.payload_segment
    ) > _unwrap(bounds_resolve(b, "encoded_segment_bytes")):
        _fail("assemble_compact: segment bound")
    # (signature_bytes needs no gate here: it is a FIXED-WIDTH constant rejected at the
    # assembler unless exactly 64.)
    assembled = assemble_segments_es256(input_, signature)
    if not isinstance(assembled, Ok):
        _fail("assemble_compact: signing input")
    # Erratum 3 (spec/bap-v3.md §3.2, REQ3-SIGNING-producer-canonical):
    # assembly refuses raw r || s outside 0 < r < n, 0 < s <= floor(n/2)
    # and emits accepted signature bytes unchanged.
    _require(_canonical_signature(signature), "assemble_compact: signature canonicality")
    compact = assembled.value
    if len(compact) > _unwrap(bounds_resolve(b, "compact_bytes")):
        _fail("assemble_compact: compact_bytes")
    # Re-parse the composed compact per kind. parse_compact enforces the segment bounds +
    # base64url decode + the signature width; _parse_xxx_header enforces kind↔typ;
    # _validate_xxx_payload enforces the full payload structure.
    seg = _parse_compact(compact, b)
    payload = _unwrap(json_decode(seg.payload_bytes, b))
    if input_.kind == "grant":
        # Full grant re-parse (decode_grant validates iss/jti/aud/times/cnf, which the
        # structural _validate_grant_payload does not).
        r = decode_grant(compact, b)
        if not r.is_ok:
            _fail("assemble_compact: grant re-parse")
    elif input_.kind == "proof":
        _parse_proof_header(seg, b)
        _validate_proof_payload(payload, b)
    elif input_.kind == "boundary_anchor":
        _parse_anchor_header(seg, b)
        _validate_anchor_payload(payload, seg.payload_bytes, b)
    elif input_.kind == "key_transition":
        _parse_transition_header(seg, b)
        _validate_transition_payload(payload, seg.payload_bytes, b)
    else:
        _fail("assemble_compact: kind")
    return compact


# 12. boundary_anchor_signing_input (v1 §15 Boundary anchors, incorporated).
@_closed_shape
def boundary_anchor_signing_input(
    anchor: BoundaryAnchorProducer, bounds: Bounds | None = None
) -> Result[SigningInput]:
    """Validate a historical chain anchor and produce its exact signing input."""

    return _trying(lambda: _boundary_anchor_signing_input_body(anchor, bounds))


def _boundary_anchor_signing_input_body(
    anchor: BoundaryAnchorProducer, bounds: Bounds | None
) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    key_id_bytes = _unwrap(str_utf8(anchor.key_id))
    if not (1 <= len(key_id_bytes) <= _unwrap(bounds_resolve(b, "kid_bytes"))):
        _fail("anchor_signing_input: key_id bytes")
    if _KID_CHARSET.match(anchor.key_id) is None:
        _fail("anchor_signing_input: key_id charset")
    if not _is_string_or_uri(anchor.anchor_id):
        _fail("anchor_signing_input: anchor_id")
    if not _is_string_or_uri(anchor.chain_id):
        _fail("anchor_signing_input: chain_id")
    if not isinstance(anchor.anchored_at, int) or isinstance(anchor.anchored_at, bool):
        _fail("anchor_signing_input: integer anchored_at")
    if (
        not isinstance(anchor.sequence, int)
        or isinstance(anchor.sequence, bool)
        or anchor.sequence < 0
    ):
        _fail("anchor_signing_input: non-negative sequence")
    _require(len(anchor.chain_hash) == 32, "anchor_signing_input: chain_hash width")
    # The raw public key is the 65-byte uncompressed SEC1 point; validate it in full so the
    # producer never derives a fingerprint over a point the profile rejects.
    _validated_public_key(anchor.public_key)
    # Genesis invariant (v1 §15 incorporated): sequence 0 is the chain root and requires the
    # all-zero chain_hash. The verifier re-checks this; the producer rejects pre-signing so a
    # mis-bound genesis anchor cannot be minted.
    if anchor.sequence == 0 and not _bytes_equal(anchor.chain_hash, DEFAULT_HASH):
        _fail("anchor_signing_input: genesis chain_hash")
    header: dict[str, Tagged] = {
        "alg": JString(_unwrap(str_utf8(ALG))),
        "kid": JString(key_id_bytes),
        "typ": JString(_unwrap(str_utf8(ANCHOR_TYP))),
    }
    fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(anchor.public_key))))
    payload: dict[str, Tagged] = {
        "anchor_id": JString(_unwrap(str_utf8(anchor.anchor_id))),
        "anchored_at": JInt(anchor.anchored_at),
        "chain_hash": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(anchor.chain_hash))))))
        ),
        "chain_id": JString(_unwrap(str_utf8(anchor.chain_id))),
        "key_fingerprint": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(fp))))))
        ),
        "sequence": JInt(anchor.sequence),
        "v": JInt(VERSION),
    }
    return SigningInput(
        kind="boundary_anchor",
        protected_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(JObject(header), b)))))
                )
            )
        ),
        payload_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(JObject(payload), b)))))
                )
            )
        ),
    )


# 13. key_transition_signing_input (v1 §15 Authenticated key transitions, incorporated).
@_closed_shape
def key_transition_signing_input(
    t: KeyTransitionProducer, bounds: Bounds | None = None
) -> Result[SigningInput]:
    """Validate a chain key transition and produce its exact signing input."""

    return _trying(lambda: _key_transition_signing_input_body(t, bounds))


def _key_transition_signing_input_body(
    t: KeyTransitionProducer, bounds: Bounds | None
) -> SigningInput:
    b = bounds if bounds is not None else MAXIMUM_BOUNDS
    # Both raw public keys are 65-byte uncompressed SEC1 points; validate them in full.
    _validated_public_key(t.current_public_key)
    _validated_public_key(t.next_public_key)
    if _bytes_equal(t.current_public_key, t.next_public_key):
        _fail("transition_signing_input: distinct keys")
    current_key_id_bytes = _unwrap(str_utf8(t.current_key_id))
    if not (1 <= len(current_key_id_bytes) <= _unwrap(bounds_resolve(b, "kid_bytes"))):
        _fail("transition_signing_input: current_key_id bytes")
    if _KID_CHARSET.match(t.current_key_id) is None:
        _fail("transition_signing_input: current_key_id charset")
    next_key_id_bytes = _unwrap(str_utf8(t.next_key_id))
    if not (1 <= len(next_key_id_bytes) <= _unwrap(bounds_resolve(b, "kid_bytes"))):
        _fail("transition_signing_input: next_key_id bytes")
    if _KID_CHARSET.match(t.next_key_id) is None:
        _fail("transition_signing_input: next_key_id charset")
    if not _is_string_or_uri(t.transition_id):
        _fail("transition_signing_input: transition_id")
    if not _is_string_or_uri(t.chain_id):
        _fail("transition_signing_input: chain_id")
    if not isinstance(t.effective_at, int) or isinstance(t.effective_at, bool):
        _fail("transition_signing_input: integer effective_at")
    header: dict[str, Tagged] = {
        "alg": JString(_unwrap(str_utf8(ALG))),
        "kid": JString(current_key_id_bytes),
        "typ": JString(_unwrap(str_utf8(TRANSITION_TYP))),
    }
    from_fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(t.current_public_key))))
    to_fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(t.next_public_key))))
    payload: dict[str, Tagged] = {
        "chain_id": JString(_unwrap(str_utf8(t.chain_id))),
        "effective_at": JInt(t.effective_at),
        "from_key_fingerprint": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(from_fp))))))
        ),
        "to_key_fingerprint": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(to_fp))))))
        ),
        "to_key_id": JString(next_key_id_bytes),
        "transition_id": JString(_unwrap(str_utf8(t.transition_id))),
        "v": JInt(VERSION),
    }
    return SigningInput(
        kind="key_transition",
        protected_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(JObject(header), b)))))
                )
            )
        ),
        payload_segment=_unwrap(
            str_utf8(
                _unwrap(
                    utf8_str(_unwrap(base64url_encode(_unwrap(jcs_encode(JObject(payload), b)))))
                )
            )
        ),
    )


# 14. encode_anchored_export (v1 §15 Anchored export; REQ1-EXPORT-input-shape, incorporated).
@_closed_shape
def encode_anchored_export(
    input_: AnchoredExportInput, expected: ExpectedExport
) -> Result[EncodedAnchoredExport]:
    """Encode an anchored archive from caller-supplied evidence without filesystem access."""

    return _trying(lambda: _encode_anchored_export_body(input_, expected))


def _encode_anchored_export_body(
    input_: AnchoredExportInput, expected: ExpectedExport
) -> EncodedAnchoredExport:
    # Validate inputs BEFORE framing (the incorporated encode discipline): the parser would
    # reject the bytes a too-large input would produce; the producer rejects earlier. Resolve
    # expected.bounds once and thread it through the encode-time bounds checks so a caller
    # tightening via expected.bounds takes effect (matches verify_anchored_export).
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    _validate_export_inputs(input_, expected, b)
    # Row chain re-check: the rows must verify against the expected boundaries before they are
    # archived. The row walk runs under the caller's OUTER bounds; the chain's nested bounds,
    # when present, must coerce-equal the outer.
    _require_bounds_equal(expected.chain.bounds, b, "encode_anchored_export: chain bounds")
    _require_bounds_equal(
        expected.start_anchor.bounds, b, "encode_anchored_export: start anchor bounds"
    )
    _require_bounds_equal(
        expected.end_anchor.bounds, b, "encode_anchored_export: end anchor bounds"
    )
    for _i, _t in enumerate(expected.transitions):
        _require_bounds_equal(_t.bounds, b, f"encode_anchored_export: transition {_i} bounds")
    _require_ok(
        check_chain(
            ChainInput(
                rows=tuple(input_.rows),
                chain_id=expected.chain.chain_id,
                first_sequence=expected.chain.first_sequence,
                last_sequence=expected.chain.last_sequence,
                row_count=expected.chain.row_count,
                previous_hash=expected.chain.previous_hash,
                last_hash=expected.chain.last_hash,
            ),
            replace(expected.chain, bounds=b),
        ),
        "encode_anchored_export: rows chain",
    )
    # Gated parses + full signed-field matches: the start anchor, the end anchor, and every
    # transition go through the width+canonical gated decode and match their expected values
    # field-by-field.
    framed_signatures = [
        _parse_and_match_anchor(input_.start_anchor, expected.start_anchor, "start", b),
        _parse_and_match_anchor(input_.end_anchor, expected.end_anchor, "end", b),
    ]
    # strict: the count equality is already enforced above; strict zip is defense-in-depth.
    for i, (compact, exp) in enumerate(zip(input_.transitions, expected.transitions, strict=True)):
        framed_signatures.append(_parse_and_match_transition(compact, exp, i, b))
    # Erratum 3: encoding is a producer surface: it frames these signatures and verifies
    # none: so it refuses any framed signature no conforming signer emits, never rewriting
    # its bytes.
    for _signature in framed_signatures:
        _require(_canonical_signature(_signature), "encode_anchored_export: signature canonicality")
    header_bytes = _build_archive_header(input_, expected.chain, b)
    parts = [ARCHIVE_PREFIX, _frame(header_bytes), _frame(input_.start_anchor)]
    parts.extend(_frame(t) for t in input_.transitions)
    parts.extend(_frame(r) for r in input_.rows)
    parts.append(_frame(input_.end_anchor))
    # Validate the chunk list BEFORE materializing the joined archive (an over-bound input
    # rejects before the allocation).
    if len(parts) > _unwrap(bounds_resolve(b, "archive_chunks")):
        _fail("encode_anchored_export: archive_chunks")
    if sum(len(p) for p in parts) > _unwrap(bounds_resolve(b, "archive_bytes")):
        _fail("encode_anchored_export: archive_bytes")
    archive = b"".join(parts)
    return EncodedAnchoredExport(archive=archive, digest=_unwrap(sha256(archive)))


def _utf8_bytes(v: object, ctx: str) -> int:
    """UTF-8 byte length, fail-closed on non-str AND ill-formed (lone-surrogate)
    input: .encode raises UnicodeEncodeError/AttributeError, either of which
    would escape the Result contract."""
    if not isinstance(v, str):
        _fail(ctx)
    try:
        return len(v.encode("utf-8"))
    except UnicodeEncodeError:
        _fail(ctx)


def _expected_int(v: object, ctx: str) -> int:
    """Type-strict expected-side integer (Python ``1 == True``, so an untyped boolean expected
    field would equal a decoded 0/1 at the match)."""
    if not isinstance(v, int) or isinstance(v, bool):
        _fail(ctx)
    return v


def _require_ok(result: Result[_T], ctx: str) -> _T:
    """Unwrap a Result or fail closed (encode-path helper)."""
    if not isinstance(result, Ok):
        _fail(ctx)
    return result.value


def _parse_and_match_anchor(
    compact: bytes, expected: ExpectedAnchor, which: str, b: Bounds
) -> bytes:
    # Returns the decoded signature: encode_anchored_export gates every framed signature's
    # canonicality after the matches (erratum 3).
    """Parse an anchor compact and match all seven signed fields against expected values
    (spec/bap-v3.md §2 incorporates spec/bap-v1.md §§15-16, REQ1-EXPORT-input-shape).
    Encoding checks structure and canonical form without verifying signatures."""
    # Bound every anchor compact at anchor_bytes: stricter than parse_compact's whole-input
    # compact_bytes ceiling. (The ENCODE path only: the standalone verify has its own gates.)
    if len(compact) > _unwrap(bounds_resolve(b, "anchor_bytes")):
        _fail(f"encode_anchored_export: {which} anchor anchor_bytes")
    seg = _parse_compact(compact, b)
    kid = _parse_anchor_header(seg, b)
    if kid != expected.key_id:
        _fail(f"encode_anchored_export: {which} anchor kid")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_anchor_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail(f"encode_anchored_export: {which} anchor payload")
    if _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", b) != expected.anchor_id:
        _fail(f"encode_anchored_export: {which} anchor_id")
    if _require_int(p.v.get("anchored_at"), "anchored_at") != _expected_int(
        expected.anchored_at, f"encode_anchored_export: {which} anchored_at type"
    ):
        _fail(f"encode_anchored_export: {which} anchored_at")
    if _require_string_or_uri(p.v.get("chain_id"), "chain_id", b) != expected.chain_id:
        _fail(f"encode_anchored_export: {which} chain_id")
    if _require_int(p.v.get("sequence"), "sequence") != _expected_int(
        expected.sequence, f"encode_anchored_export: {which} sequence type"
    ):
        _fail(f"encode_anchored_export: {which} sequence")
    if not _bytes_equal(
        _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32), expected.chain_hash
    ):
        _fail(f"encode_anchored_export: {which} chain_hash")
    if not _bytes_equal(
        _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32),
        expected.key_fingerprint,
    ):
        _fail(f"encode_anchored_export: {which} key_fingerprint")
    return seg.signature


def _parse_and_match_transition(
    compact: bytes, expected: ExpectedKeyTransition, i: int, b: Bounds
) -> bytes:
    # Returns the decoded signature: encode_anchored_export gates every framed signature's
    # canonicality after the matches (erratum 3).
    """Parse a transition compact and match all seven signed fields
    (spec/bap-v3.md §2 incorporates spec/bap-v1.md §§15-16, REQ1-EXPORT-input-shape)."""
    # Same anchor_bytes ceiling the encode path enforces on transitions.
    if len(compact) > _unwrap(bounds_resolve(b, "anchor_bytes")):
        _fail(f"encode_anchored_export: transition {i} anchor_bytes")
    seg = _parse_compact(compact, b)
    kid = _parse_transition_header(seg, b)
    if kid != expected.current_key_id:
        _fail(f"encode_anchored_export: transition {i} kid")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_transition_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail(f"encode_anchored_export: transition {i} payload")
    if (
        _require_string_or_uri(p.v.get("transition_id"), "transition_id", b)
        != expected.transition_id
    ):
        _fail(f"encode_anchored_export: transition {i} transition_id")
    if _require_string_or_uri(p.v.get("chain_id"), "chain_id", b) != expected.chain_id:
        _fail(f"encode_anchored_export: transition {i} chain_id")
    if _require_int(p.v.get("effective_at"), "effective_at") != _expected_int(
        expected.effective_at, f"encode_anchored_export: transition {i} effective_at type"
    ):
        _fail(f"encode_anchored_export: transition {i} effective_at")
    if not _bytes_equal(
        _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32),
        expected.current_key_fingerprint,
    ):
        _fail(f"encode_anchored_export: transition {i} from_key_fingerprint")
    if not _bytes_equal(
        _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32),
        expected.next_key_fingerprint,
    ):
        _fail(f"encode_anchored_export: transition {i} to_key_fingerprint")
    to_key_id = p.v.get("to_key_id")
    if not isinstance(to_key_id, JString) or _unwrap(utf8_str(to_key_id.v)) != expected.next_key_id:
        _fail(f"encode_anchored_export: transition {i} to_key_id")
    return seg.signature


def _validate_export_inputs(
    input_: AnchoredExportInput, expected: ExpectedExport, b: Bounds
) -> None:
    """Encode-time input validation (spec/bap-v1.md §§15-17,
    REQ1-VERIFY-revalidate, REQ1-BOUNDS-ordering; spec/bap-v3.md §2): the transition count, chain range coherence, anchor bindings, and the key-path
    invariants must hold before framing. The parser enforces all of this at verify time; the
    producer must not mint bytes its own consumer would reject."""
    chain = expected.chain
    # Transition count bound (transition_count <= bounds.key_transitions).
    if len(input_.transitions) > _unwrap(bounds_resolve(b, "key_transitions")):
        _fail("encode_anchored_export: transition_count bound")
    if len(expected.transitions) != len(input_.transitions):
        _fail("encode_anchored_export: transition count")
    # Anchor bindings: start spans first_sequence-1 with the chain's previous_hash; end spans
    # last_sequence with the chain's last_hash.
    if expected.start_anchor.sequence != chain.first_sequence - 1:
        _fail("encode_anchored_export: start sequence")
    if not _bytes_equal(expected.start_anchor.chain_hash, chain.previous_hash):
        _fail("encode_anchored_export: start chain_hash")
    if expected.end_anchor.sequence != chain.last_sequence:
        _fail("encode_anchored_export: end sequence")
    if not _bytes_equal(expected.end_anchor.chain_hash, chain.last_hash):
        _fail("encode_anchored_export: end chain_hash")
    # All transitions + both anchors carry the chain_id.
    for i, t in enumerate(expected.transitions):
        if t.chain_id != chain.chain_id:
            _fail(f"encode_anchored_export: transition {i} chain_id")
    if expected.start_anchor.chain_id != chain.chain_id:
        _fail("encode_anchored_export: start chain_id")
    if expected.end_anchor.chain_id != chain.chain_id:
        _fail("encode_anchored_export: end chain_id")
    # Key-path invariants: the no-transition path requires start==end key identity with a
    # chronologically-non-decreasing end anchored_at; the transition path requires strictly
    # increasing effective_at with no fingerprint cycle. Mirrored by _validate_key_path.
    _validate_key_path(expected.start_anchor, expected.transitions, expected.end_anchor)


def _build_archive_header(input_: AnchoredExportInput, chain: ExpectedChain, b: Bounds) -> bytes:
    if chain.chain_id != input_.chain_id:
        _fail("encode_anchored_export: chain_id")
    if chain.first_sequence != input_.first_sequence:
        _fail("encode_anchored_export: first_sequence")
    if chain.last_sequence != input_.last_sequence:
        _fail("encode_anchored_export: last_sequence")
    if chain.row_count != input_.row_count:
        _fail("encode_anchored_export: row_count")
    members: dict[str, Tagged] = {
        "chain_id": JString(_unwrap(str_utf8(chain.chain_id))),
        "first_sequence": JInt(chain.first_sequence),
        "last_hash": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(chain.last_hash))))))
        ),
        "last_sequence": JInt(chain.last_sequence),
        "previous_hash": JString(
            _unwrap(str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(chain.previous_hash))))))
        ),
        "row_count": JInt(chain.row_count),
        "transition_count": JInt(len(input_.transitions)),
        "v": JInt(VERSION),
    }
    header_bytes = _unwrap(jcs_encode(JObject(members), b))
    if len(header_bytes) > _unwrap(bounds_resolve(b, "archive_header_bytes")):
        _fail("encode_anchored_export: header bytes")
    return header_bytes


def _frame(data: bytes) -> bytes:
    """UINT32_BE(len) || bytes: the archive framing (v1 §15 incorporated)."""
    if len(data) == 0:
        _fail("archive: zero-length frame")
    v = len(data)
    return bytes([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]) + data


# 15. verify_historical_anchor (v1 §15 Boundary anchors, incorporated).
@_closed_shape
def verify_historical_anchor(
    compact: bytes, key: HistoricalPublicKey, expected: ExpectedAnchor
) -> Result[AnchorFacts]:
    """Verify an anchor against an already-trusted historical key and expected boundary."""

    return _trying(lambda: _verify_historical_anchor_body(compact, key, expected))


def _verify_historical_anchor_body(
    compact: bytes, key: HistoricalPublicKey, expected: ExpectedAnchor
) -> AnchorFacts:
    _require(len(key.public_key) == PUBLIC_KEY_BYTES, "verify_historical_anchor: key width")
    # Thread expected.bounds (resolved once) through every bound-sensitive check.
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    # Key-window endpoints magnitude-bounded under the resolved bounds (the all-SDK key-window
    # parity discipline). The anchor_bytes compact ceiling at the STANDALONE verify entry.
    if len(compact) > _unwrap(bounds_resolve(b, "anchor_bytes")):
        _fail("verify_historical_anchor: anchor_bytes")
    _vf = _expected_int(key.valid_from, "verify_historical_anchor: valid_from type")
    _vb = (
        _expected_int(key.valid_before, "verify_historical_anchor: valid_before type")
        if key.valid_before is not None
        else None
    )
    _mag = _unwrap(bounds_resolve(b, "integer_magnitude"))
    if abs(_vf) > _mag:
        _fail("verify_historical_anchor: valid_from magnitude")
    if _vb is not None and abs(_vb) > _mag:
        _fail("verify_historical_anchor: valid_before magnitude")
    if _vb is not None and _vb <= _vf:
        _fail("verify_historical_anchor: valid_before ordering")
    seg = _parse_compact(compact, b)
    kid = _parse_anchor_header(seg, b)
    if kid != key.key_id:
        _fail("verify_historical_anchor: kid")
    if expected.key_id != key.key_id:
        _fail("verify_historical_anchor: expected key id")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_anchor_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail("verify_historical_anchor: payload object")
    anchor_id = _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", b)
    if anchor_id != expected.anchor_id:
        _fail("verify_historical_anchor: anchor_id")
    anchored_at = _require_int(p.v.get("anchored_at"), "anchored_at")
    if anchored_at != _expected_int(
        expected.anchored_at, "verify_historical_anchor: anchored_at type"
    ):
        _fail("verify_historical_anchor: anchored_at")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        _fail("verify_historical_anchor: chain_id")
    sequence = _require_int(p.v.get("sequence"), "sequence")
    if sequence != _expected_int(expected.sequence, "verify_historical_anchor: sequence type"):
        _fail("verify_historical_anchor: sequence")
    chain_hash = _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    if not _bytes_equal(chain_hash, expected.chain_hash):
        _fail("verify_historical_anchor: chain_hash")
    key_fp_raw = _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)
    if not _bytes_equal(key_fp_raw, expected.key_fingerprint):
        _fail("verify_historical_anchor: key_fingerprint")
    if expected.sequence == 0 and not _bytes_equal(expected.chain_hash, DEFAULT_HASH):
        _fail("verify_historical_anchor: genesis hash")
    derived_fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(key.public_key))))
    if not _bytes_equal(derived_fp, expected.key_fingerprint):
        _fail("verify_historical_anchor: fingerprint")
    if not _in_window(anchored_at, key):
        _fail("verify_historical_anchor: window")
    pk = _import_public_key(key.public_key)
    if not _es256_verify(seg.signing_input, seg.signature, pk):
        _fail("verify_historical_anchor: signature")
    from .facts import AnchorFacts

    return AnchorFacts(
        version=VERSION,
        anchor_id=anchor_id,
        anchored_at=anchored_at,
        chain_id=chain_id,
        sequence=sequence,
        chain_hash=chain_hash,
        key_fingerprint=key_fp_raw,
    )


# 16. verify_key_transition (v1 §15 Authenticated key transitions, incorporated).
@_closed_shape
def verify_key_transition(
    compact: bytes,
    old_key: HistoricalPublicKey,
    new_key: HistoricalPublicKey,
    expected: ExpectedKeyTransition,
) -> Result[KeyTransitionFacts]:
    """Verify a signed transition against caller-trusted historical key context."""

    return _trying(lambda: _verify_key_transition_body(compact, old_key, new_key, expected))


def _verify_key_transition_body(
    compact: bytes,
    old_key: HistoricalPublicKey,
    new_key: HistoricalPublicKey,
    expected: ExpectedKeyTransition,
) -> KeyTransitionFacts:
    _require(
        len(old_key.public_key) == PUBLIC_KEY_BYTES and len(new_key.public_key) == PUBLIC_KEY_BYTES,
        "verify_key_transition: key width",
    )
    if _bytes_equal(old_key.public_key, new_key.public_key):
        _fail("verify_key_transition: distinct keys")
    # Thread expected.bounds (resolved once) through every bound-sensitive check.
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    # Key-window endpoints magnitude-bounded (both keys). The anchor_bytes compact ceiling at
    # the STANDALONE verify entry.
    if len(compact) > _unwrap(bounds_resolve(b, "anchor_bytes")):
        _fail("verify_key_transition: anchor_bytes")
    _ovf = _expected_int(old_key.valid_from, "verify_key_transition: valid_from type")
    _nvf = _expected_int(new_key.valid_from, "verify_key_transition: valid_from type")
    _ovb = (
        _expected_int(old_key.valid_before, "verify_key_transition: valid_before type")
        if old_key.valid_before is not None
        else None
    )
    _nvb = (
        _expected_int(new_key.valid_before, "verify_key_transition: valid_before type")
        if new_key.valid_before is not None
        else None
    )
    _mag = _unwrap(bounds_resolve(b, "integer_magnitude"))
    if abs(_ovf) > _mag or abs(_nvf) > _mag:
        _fail("verify_key_transition: valid_from magnitude")
    if (_ovb is not None and abs(_ovb) > _mag) or (_nvb is not None and abs(_nvb) > _mag):
        _fail("verify_key_transition: valid_before magnitude")
    if (_ovb is not None and _ovb <= _ovf) or (_nvb is not None and _nvb <= _nvf):
        _fail("verify_key_transition: valid_before ordering")
    seg = _parse_compact(compact, b)
    kid = _parse_transition_header(seg, b)
    if kid != old_key.key_id:
        _fail("verify_key_transition: kid")
    if expected.current_key_id != old_key.key_id:
        _fail("verify_key_transition: current key id")
    if expected.next_key_id != new_key.key_id:
        _fail("verify_key_transition: next key id")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_transition_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail("verify_key_transition: payload object")
    transition_id = _require_string_or_uri(p.v.get("transition_id"), "transition_id", b)
    if transition_id != expected.transition_id:
        _fail("verify_key_transition: transition_id")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        _fail("verify_key_transition: chain_id")
    effective_at = _require_int(p.v.get("effective_at"), "effective_at")
    if effective_at != _expected_int(
        expected.effective_at, "verify_key_transition: effective_at type"
    ):
        _fail("verify_key_transition: effective_at")
    from_fp_raw = _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    if not _bytes_equal(from_fp_raw, expected.current_key_fingerprint):
        _fail("verify_key_transition: from fp")
    to_fp_raw = _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    if not _bytes_equal(to_fp_raw, expected.next_key_fingerprint):
        _fail("verify_key_transition: to fp")
    to_key_id_v = p.v["to_key_id"]
    if (
        not isinstance(to_key_id_v, JString)
        or _unwrap(utf8_str(to_key_id_v.v)) != expected.next_key_id
    ):
        _fail("verify_key_transition: to_key_id")
    derived_from = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(old_key.public_key))))
    if not _bytes_equal(derived_from, expected.current_key_fingerprint):
        _fail("verify_key_transition: current fp")
    derived_to = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(new_key.public_key))))
    if not _bytes_equal(derived_to, expected.next_key_fingerprint):
        _fail("verify_key_transition: next fp")
    if not _in_window(effective_at, old_key):
        _fail("verify_key_transition: current window")
    if not _in_window(effective_at, new_key):
        _fail("verify_key_transition: next window")
    pk = _import_public_key(old_key.public_key)
    if not _es256_verify(seg.signing_input, seg.signature, pk):
        _fail("verify_key_transition: signature")
    from .facts import KeyTransitionFacts

    return KeyTransitionFacts(
        version=VERSION,
        transition_id=transition_id,
        chain_id=chain_id,
        effective_at=effective_at,
        current_key_fingerprint=from_fp_raw,
        next_key_fingerprint=to_fp_raw,
    )


# 17. verify_anchored_export (v1 §15 Anchored export; REQ1-EXPORT-complete-scan, incorporated).
@_closed_shape
def verify_anchored_export(
    archived: ArchivedObject, key_chain: HistoricalKeyChain, expected: ExpectedExport
) -> Result[AnchoredExportFacts]:
    """Verify canonical archive bytes, chain and historical evidence; return facts without authorization."""

    return _trying(lambda: _verify_anchored_export_body(archived, key_chain, expected))


def _pre_identifier(value: object, ctx: str, bounds: Bounds) -> None:
    """The pre-digest identifier gate: non-empty str, UTF-8 byte length within
    identifier_bytes, StringOrURI syntax (spec/bap-v1.md §11; RFC 7519 §2)."""
    if (
        not isinstance(value, str)
        or _utf8_bytes(value, ctx) < 1
        or _utf8_bytes(value, ctx) > _unwrap(bounds_resolve(bounds, "identifier_bytes"))
        or not _is_string_or_uri(value)
    ):
        _fail(ctx)


def _verify_anchored_export_body(
    archived: ArchivedObject, key_chain: HistoricalKeyChain, expected: ExpectedExport
) -> AnchoredExportFacts:
    # Expected chain integers type-strict BEFORE the sequence arithmetic (a non-int
    # first_sequence must fail closed, not raise TypeError at the `- 1`).
    _expected_int(expected.chain.first_sequence, "verify_anchored_export: first_sequence type")
    _expected_int(expected.chain.last_sequence, "verify_anchored_export: last_sequence type")
    _expected_int(expected.chain.row_count, "verify_anchored_export: row_count type")
    # Expected-struct well-formedness BEFORE the digest (the expected-context validation
    # before archive hashing (spec/bap-v1.md §§15-17) discipline the
    # v1/v2 facades enforce): chain + both anchors + transitions validate before key shapes,
    # chunks, and hash_chunks, so a malformed expected struct never forces processing of the
    # full archive.
    _bpre = _unwrap(
        coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS)
    )
    _mpre = _unwrap(bounds_resolve(_bpre, "integer_magnitude"))
    # The count ceiling BEFORE the hoisted per-element walk.
    if len(expected.transitions) > _unwrap(bounds_resolve(_bpre, "key_transitions")):
        _fail("verify_anchored_export: transition count bound")
    _pre_identifier(expected.chain.chain_id, "verify_anchored_export: chain chain_id", _bpre)
    if (
        expected.chain.first_sequence < 1
        or expected.chain.first_sequence > _mpre
        or expected.chain.last_sequence < 1
        or expected.chain.last_sequence > _mpre
        or expected.chain.first_sequence > expected.chain.last_sequence
    ):
        _fail("verify_anchored_export: chain range")
    if (
        expected.chain.row_count < 1
        or expected.chain.row_count > _unwrap(bounds_resolve(_bpre, "chain_rows"))
        or expected.chain.row_count
        != expected.chain.last_sequence - expected.chain.first_sequence + 1
    ):
        _fail("verify_anchored_export: chain count")
    if len(expected.chain.previous_hash) != 32 or len(expected.chain.last_hash) != 32:
        _fail("verify_anchored_export: chain hash width")
    if expected.chain.first_sequence == 1 and not _bytes_equal(
        expected.chain.previous_hash, DEFAULT_HASH
    ):
        _fail("verify_anchored_export: chain genesis")
    for _anch, _which in ((expected.start_anchor, "start"), (expected.end_anchor, "end")):
        _pre_identifier(_anch.anchor_id, f"verify_anchored_export: {_which} anchor_id", _bpre)
        _pre_identifier(_anch.chain_id, f"verify_anchored_export: {_which} chain_id", _bpre)
        _aa = _expected_int(_anch.anchored_at, f"verify_anchored_export: {_which} anchored_at type")
        if abs(_aa) > _mpre:
            _fail(f"verify_anchored_export: {_which} anchored_at magnitude")
        _sq = _expected_int(_anch.sequence, f"verify_anchored_export: {_which} sequence type")
        if _sq < 0 or _sq > _mpre:
            _fail(f"verify_anchored_export: {_which} sequence range")
        if (
            not isinstance(_anch.key_id, str)
            or not (
                1
                <= _utf8_bytes(_anch.key_id, f"verify_anchored_export: {_which} key_id")
                <= _unwrap(bounds_resolve(_bpre, "kid_bytes"))
            )
            or _KID_CHARSET.match(_anch.key_id) is None
        ):
            _fail(f"verify_anchored_export: {_which} key_id")
        if len(_anch.chain_hash) != 32 or len(_anch.key_fingerprint) != 32:
            _fail(f"verify_anchored_export: {_which} hash width")
        if _sq == 0 and not _bytes_equal(_anch.chain_hash, DEFAULT_HASH):
            _fail(f"verify_anchored_export: {_which} genesis")
    for _ti, _t in enumerate(expected.transitions):
        _pre_identifier(_t.transition_id, f"verify_anchored_export: transition {_ti} id", _bpre)
        _pre_identifier(_t.chain_id, f"verify_anchored_export: transition {_ti} chain_id", _bpre)
        _eat = _expected_int(
            _t.effective_at, f"verify_anchored_export: transition {_ti} effective_at type"
        )
        if abs(_eat) > _mpre:
            _fail(f"verify_anchored_export: transition {_ti} effective_at magnitude")
        for _kid in (_t.current_key_id, _t.next_key_id):
            if (
                not isinstance(_kid, str)
                or not (
                    1
                    <= _utf8_bytes(_kid, f"verify_anchored_export: transition {_ti} key_id")
                    <= _unwrap(bounds_resolve(_bpre, "kid_bytes"))
                )
                or _KID_CHARSET.match(_kid) is None
            ):
                _fail(f"verify_anchored_export: transition {_ti} key_id")
        if (
            len(_t.current_key_fingerprint) != 32
            or len(_t.next_key_fingerprint) != 32
            or _bytes_equal(_t.current_key_fingerprint, _t.next_key_fingerprint)
        ):
            _fail(f"verify_anchored_export: transition {_ti} fingerprints")
    _vb0 = _bpre
    # Key-window validity BEFORE chunk processing/hashing (malformed intervals should not force
    # processing of the full archive).
    if len(key_chain.keys) != len(expected.transitions) + 1:
        _fail("verify_anchored_export: key count bound")
    # Expected-side identifier strings used in header construction must be well-formed BEFORE
    # the digest (a lone-surrogate chain_id must fail closed, not raise UnicodeEncodeError out
    # of the Result API at the header encode).
    _utf8_bytes(expected.chain.chain_id, "verify_anchored_export: chain_id encoding")
    _utf8_bytes(expected.start_anchor.chain_id, "verify_anchored_export: chain_id encoding")
    _utf8_bytes(expected.end_anchor.chain_id, "verify_anchored_export: chain_id encoding")
    for _t in expected.transitions:
        _utf8_bytes(_t.chain_id, "verify_anchored_export: chain_id encoding")
    # Key ID/public-key SHAPE before the digest (an oversized key ID must not reach a live
    # SHA-256 call; the window gates alone are incomplete pre-hash validation).
    for _k in key_chain.keys:
        if (
            not isinstance(_k.key_id, str)
            or not _k.key_id
            or len(_k.key_id) > _unwrap(bounds_resolve(_vb0, "kid_bytes"))
            or _utf8_bytes(_k.key_id, "verify_anchored_export: key id encoding")
            > _unwrap(bounds_resolve(_vb0, "kid_bytes"))
        ):
            _fail("verify_anchored_export: key id shape")
        # the ASCII-unreserved key_id class, pre-hash
        if not _k.key_id.isascii() or not all(c.isalnum() or c in "-._~" for c in _k.key_id):
            _fail("verify_anchored_export: key id charset")
        # (the isinstance half is owned by the _closed_shape gate: exact bytes;
        # the WIDTH is still this gate's to check: the 65-byte uncompressed SEC1 point)
        if len(_k.public_key) != PUBLIC_KEY_BYTES:
            _fail("verify_anchored_export: key width")
    for _k in key_chain.keys:
        _vf0 = _expected_int(_k.valid_from, "verify_anchored_export: key valid_from type")
        _vbv0 = (
            _expected_int(_k.valid_before, "verify_anchored_export: key valid_before type")
            if _k.valid_before is not None
            else None
        )
        _mag0 = _unwrap(bounds_resolve(_vb0, "integer_magnitude"))
        if abs(_vf0) > _mag0:
            _fail("verify_anchored_export: key valid_from magnitude")
        if _vbv0 is not None and abs(_vbv0) > _mag0:
            _fail("verify_anchored_export: key valid_before magnitude")
        if _vbv0 is not None and _vbv0 <= _vf0:
            _fail("verify_anchored_export: key valid_before ordering")

    # Static expected-side bindings: the caller's expected anchors + transitions belong to the
    # expected chain (all six enforced at verify).
    if expected.start_anchor.chain_id != expected.chain.chain_id:
        _fail("verify_anchored_export: start chain_id")
    if expected.end_anchor.chain_id != expected.chain.chain_id:
        _fail("verify_anchored_export: end chain_id")
    if expected.start_anchor.sequence != expected.chain.first_sequence - 1:
        _fail("verify_anchored_export: start sequence")
    if not _bytes_equal(expected.start_anchor.chain_hash, expected.chain.previous_hash):
        _fail("verify_anchored_export: start chain_hash")
    if expected.end_anchor.sequence != expected.chain.last_sequence:
        _fail("verify_anchored_export: end sequence")
    if not _bytes_equal(expected.end_anchor.chain_hash, expected.chain.last_hash):
        _fail("verify_anchored_export: end chain_hash")
    for _i, _t in enumerate(expected.transitions):
        if _t.chain_id != expected.chain.chain_id:
            _fail(f"verify_anchored_export: transition {_i} chain_id")

    # Resolve caller bounds once and enforce them throughout nested parsing
    # (spec/bap-v1.md §17, REQ1-BOUNDS-tighten-only, incorporated by spec/bap-v3.md §2).
    b = _unwrap(coerce_bounds(expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS))
    # Nested bounds pinning: pin every nested bounds to the top-level resolved bounds; the SDK
    # pins them explicitly so a mismatch fails closed.
    _require_bounds_equal(expected.chain.bounds, b, "verify_anchored_export: chain bounds")
    _require_bounds_equal(
        expected.start_anchor.bounds, b, "verify_anchored_export: start anchor bounds"
    )
    _require_bounds_equal(
        expected.end_anchor.bounds, b, "verify_anchored_export: end anchor bounds"
    )
    for ti, texp in enumerate(expected.transitions):
        _require_bounds_equal(texp.bounds, b, f"verify_anchored_export: transition {ti} bounds")
    # Version shape (UTF-8 BYTES) + equality BEFORE the digest (malformed metadata must not
    # force maximum-sized hashing).
    if (
        not isinstance(archived.version, str)
        or not archived.version
        or len(archived.version) > _unwrap(bounds_resolve(b, "object_version_bytes"))
        or not isinstance(expected.object_version, str)
        or not expected.object_version
        or len(expected.object_version) > _unwrap(bounds_resolve(b, "object_version_bytes"))
        or _utf8_bytes(archived.version, "verify_anchored_export: version encoding")
        > _unwrap(bounds_resolve(b, "object_version_bytes"))
        or _utf8_bytes(expected.object_version, "verify_anchored_export: version encoding")
        > _unwrap(bounds_resolve(b, "object_version_bytes"))
    ):
        _fail("verify_anchored_export: version shape")
    if archived.version != expected.object_version:
        _fail("verify_anchored_export: object version")
    # Validate the chunk list BEFORE concatenation: each chunk nonempty, count < archive_chunks,
    # total ≤ archive_bytes. Hashing happens after the shape is validated.
    _validate_chunks(archived.chunks, b)
    # Stream the digest over the chunks WITHOUT materializing the whole archive first
    # (incremental SHA-256 per chunk, no concat). An inauthentic/oversized archive is rejected
    # at the digest compare before the parse materializes the bytes. archive_bytes is already
    # enforced by _validate_chunks (running total), so no post-materialization byte bound is
    # needed.
    digest = _unwrap(sha256(*archived.chunks))
    if not _bytes_equal(digest, expected.digest):
        _fail("verify_anchored_export: digest")
    # (the version SHAPE + equality gates ran before the digest.)
    # Materialize for parsing ONLY after the digest matches (caller-legitimate, bounded archive).
    archive = b"".join(archived.chunks)
    if len(archive) <= len(ARCHIVE_PREFIX):
        _fail("verify_anchored_export: archive too short")
    parsed = _parse_archive(archive, b)
    # Header canonical equality.
    header_members: dict[str, Tagged] = {
        "chain_id": JString(_unwrap(str_utf8(expected.chain.chain_id))),
        "first_sequence": JInt(expected.chain.first_sequence),
        "last_hash": JString(
            _unwrap(
                str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(expected.chain.last_hash)))))
            )
        ),
        "last_sequence": JInt(expected.chain.last_sequence),
        "previous_hash": JString(
            _unwrap(
                str_utf8(_unwrap(utf8_str(_unwrap(base64url_encode(expected.chain.previous_hash)))))
            )
        ),
        "row_count": JInt(expected.chain.row_count),
        "transition_count": JInt(len(expected.transitions)),
        "v": JInt(VERSION),
    }
    expected_header_bytes = _unwrap(jcs_encode(JObject(header_members), b))
    if not _bytes_equal(parsed.header_bytes, expected_header_bytes):
        _fail("verify_anchored_export: header")
    # Verify start + end anchors + each transition against the ordered historical key chain.
    # A key chain of N keys spans N-1 transitions (keys[0]->[1], ..., keys[N-2]->[N-1]); a 1-key,
    # 0-transition archive is the no-rollover case. The exact-count check below is the gate.
    # Validate the key-chain length BEFORE dereferencing keys[0]/keys[-1] so a zero-key chain
    # fails closed (Err) instead of raising IndexError.
    if len(parsed.transitions) != len(expected.transitions):
        _fail("verify_anchored_export: transition count")
    if len(key_chain.keys) != len(parsed.transitions) + 1:
        _fail("verify_anchored_export: key chain length")
    # Pass the export-level resolved bounds b so a top-level tightening takes effect in the
    # nested anchor/transition verification (not just the nested struct's bounds).
    _verify_anchor_compact(
        parsed.start, key_chain.keys[0], expected.start_anchor, "verify_anchored_export start", b
    )
    _verify_anchor_compact(
        parsed.end, key_chain.keys[-1], expected.end_anchor, "verify_anchored_export end", b
    )
    # Key-path invariants: the expected transition list must form a strictly-increasing
    # effective_at sequence with no fingerprint cycle, and the end anchor must close the path
    # with a chronologically-non-decreasing anchored_at.
    _validate_key_path(expected.start_anchor, expected.transitions, expected.end_anchor)
    for i, tr in enumerate(parsed.transitions):
        _verify_transition_compact(
            tr,
            key_chain.keys[i],
            key_chain.keys[i + 1],
            expected.transitions[i],
            f"verify_anchored_export transition {i}",
            b,
        )
    # Chronology over the ACTUAL anchored times: each transition's effective_at must be strictly
    # greater than the previous anchor/transition time, and the end anchor's anchored_at must be
    # >= the last transition's effective_at (>= the start anchor's anchored_at for the
    # no-transition case: covered by _validate_key_path's chronological end).
    transition_time = expected.start_anchor.anchored_at
    for i, t in enumerate(expected.transitions):
        if not (t.effective_at > transition_time):
            _fail(f"verify_anchored_export transition {i}: chronology")
        transition_time = t.effective_at
    if not (expected.end_anchor.anchored_at >= transition_time):
        _fail("verify_anchored_export: end chronology")
    # Re-check every row (REQ1-EXPORT-complete-scan; mirrors check_chain).
    previous = expected.chain.previous_hash
    sequence = expected.chain.first_sequence
    if expected.chain.first_sequence == 1 and not _bytes_equal(previous, DEFAULT_HASH):
        _fail("verify_anchored_export: genesis predecessor")
    if len(parsed.rows) != expected.chain.row_count:
        _fail("verify_anchored_export: row count")
    for i, row_bytes in enumerate(parsed.rows):
        row = _unwrap(json_decode(row_bytes, b))
        row = _require_object_exact(
            row,
            ["v", "chain_id", "sequence", "previous", "commitment"],
            f"verify_anchored_export row {i}",
        )
        v_v = row.v["v"]
        if not isinstance(v_v, JInt) or v_v.v != VERSION:
            _fail(f"verify_anchored_export row {i}: v")
        cid_v = row.v["chain_id"]
        if not isinstance(cid_v, JString) or _unwrap(utf8_str(cid_v.v)) != expected.chain.chain_id:
            _fail(f"verify_anchored_export row {i}: chain_id")
        seq_v = row.v["sequence"]
        if not isinstance(seq_v, JInt) or seq_v.v != sequence:
            _fail(f"verify_anchored_export row {i}: sequence")
        if seq_v.v < 1:
            _fail(f"verify_anchored_export row {i}: sequence positive")
        prev_raw = _require_b64url_n(row.v.get("previous"), "previous", 32)
        if not _bytes_equal(prev_raw, previous):
            _fail(f"verify_anchored_export row {i}: previous link")
        commitment_raw = _require_b64url_n(row.v.get("commitment"), "commitment", 32)
        re_encoded = _canonical_row_bytes(
            expected.chain.chain_id, seq_v.v, prev_raw, commitment_raw, b
        )
        if not _bytes_equal(re_encoded, row_bytes):
            _fail(f"verify_anchored_export row {i}: canonical")
        previous = _unwrap(sha256(ROW_PREFIX, row_bytes))
        sequence += 1
    if not _bytes_equal(previous, expected.chain.last_hash):
        _fail("verify_anchored_export: head")
    from .facts import AnchoredExportFacts

    return AnchoredExportFacts(
        version=VERSION,
        object_version=archived.version,
        chain_id=expected.chain.chain_id,
        first_sequence=expected.chain.first_sequence,
        last_sequence=expected.chain.last_sequence,
        row_count=expected.chain.row_count,
        previous_hash=expected.chain.previous_hash,
        last_hash=previous,
        digest=digest,
        start_anchor_id=expected.start_anchor.anchor_id,
        start_anchored_at=expected.start_anchor.anchored_at,
        start_key_fingerprint=expected.start_anchor.key_fingerprint,
        end_anchor_id=expected.end_anchor.anchor_id,
        end_anchored_at=expected.end_anchor.anchored_at,
        end_key_fingerprint=expected.end_anchor.key_fingerprint,
        transition_count=len(expected.transitions),
    )


# ExpectedExport (the verify_anchored_export expected-context struct).
@dataclass(frozen=True)
class ExpectedExport:
    """Expected archive and chain context including caller-trusted historical keys.

    Fields:
        chain: ExpectedChain.
        digest: bytes.
        start_anchor: ExpectedAnchor.
        end_anchor: ExpectedAnchor.
        transitions: tuple[ExpectedKeyTransition, ...].
        object_version: str.
        bounds: Bounds | None.
    """

    chain: ExpectedChain
    digest: bytes  # raw 32
    start_anchor: ExpectedAnchor
    end_anchor: ExpectedAnchor
    transitions: tuple[ExpectedKeyTransition, ...]
    object_version: str
    bounds: Bounds | None = None


def _verify_anchor_compact(
    compact: bytes,
    key: HistoricalPublicKey,
    expected: ExpectedAnchor,
    ctx: str,
    bounds: Bounds | None = None,
) -> None:
    _require(len(key.public_key) == PUBLIC_KEY_BYTES, f"{ctx}: key width")
    # Thread the enclosing export's resolved bounds when present so the top-level tightening
    # takes effect; otherwise the nested anchor's own bounds.
    b = (
        bounds
        if bounds is not None
        else (expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS)
    )
    # Key-window endpoints: integral + magnitude-bounded (the standalone path's gates).
    _vf = _expected_int(key.valid_from, f"{ctx}: valid_from type")
    _vb = (
        _expected_int(key.valid_before, f"{ctx}: valid_before type")
        if key.valid_before is not None
        else None
    )
    _mag = _unwrap(bounds_resolve(b, "integer_magnitude"))
    if abs(_vf) > _mag:
        _fail(f"{ctx}: valid_from magnitude")
    if _vb is not None and abs(_vb) > _mag:
        _fail(f"{ctx}: valid_before magnitude")
    if _vb is not None and _vb <= _vf:
        _fail(f"{ctx}: valid_before ordering")
    seg = _parse_compact(compact, b)
    kid = _parse_anchor_header(seg, b)
    if kid != key.key_id:
        _fail(f"{ctx}: kid")
    if expected.key_id != key.key_id:
        _fail(f"{ctx}: expected key id")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_anchor_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail(f"{ctx}: payload object")
    anchor_id = _require_string_or_uri(p.v.get("anchor_id"), "anchor_id", b)
    if anchor_id != expected.anchor_id:
        _fail(f"{ctx}: anchor_id")
    anchored_at = _require_int(p.v.get("anchored_at"), "anchored_at")
    if anchored_at != _expected_int(expected.anchored_at, f"{ctx}: anchored_at type"):
        _fail(f"{ctx}: anchored_at")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        _fail(f"{ctx}: chain_id")
    sequence = _require_int(p.v.get("sequence"), "sequence")
    if sequence != _expected_int(expected.sequence, f"{ctx}: sequence type"):
        _fail(f"{ctx}: sequence")
    chain_hash = _require_b64url_n(p.v.get("chain_hash"), "chain_hash", 32)
    if not _bytes_equal(chain_hash, expected.chain_hash):
        _fail(f"{ctx}: chain_hash")
    key_fp_raw = _require_b64url_n(p.v.get("key_fingerprint"), "key_fingerprint", 32)
    if not _bytes_equal(key_fp_raw, expected.key_fingerprint):
        _fail(f"{ctx}: key_fingerprint")
    if expected.sequence == 0 and not _bytes_equal(expected.chain_hash, DEFAULT_HASH):
        _fail(f"{ctx}: genesis hash")
    derived_fp = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(key.public_key))))
    if not _bytes_equal(derived_fp, expected.key_fingerprint):
        _fail(f"{ctx}: fingerprint")
    if not _in_window(anchored_at, key):
        _fail(f"{ctx}: window")
    pk = _import_public_key(key.public_key)
    if not _es256_verify(seg.signing_input, seg.signature, pk):
        _fail(f"{ctx}: signature")


def _verify_transition_compact(
    compact: bytes,
    current_key: HistoricalPublicKey,
    next_key: HistoricalPublicKey,
    expected: ExpectedKeyTransition,
    ctx: str,
    bounds: Bounds | None = None,
) -> None:
    _require(
        len(current_key.public_key) == PUBLIC_KEY_BYTES
        and len(next_key.public_key) == PUBLIC_KEY_BYTES,
        f"{ctx}: key width",
    )
    if _bytes_equal(current_key.public_key, next_key.public_key):
        _fail(f"{ctx}: distinct keys")
    # Thread the enclosing export's resolved bounds when present; otherwise the nested
    # transition's own bounds.
    b = (
        bounds
        if bounds is not None
        else (expected.bounds if expected.bounds is not None else MAXIMUM_BOUNDS)
    )
    # Key-window endpoints: integral + magnitude-bounded for BOTH keys (the standalone path's
    # gates).
    _ovf = _expected_int(current_key.valid_from, f"{ctx}: valid_from type")
    _nvf = _expected_int(next_key.valid_from, f"{ctx}: valid_from type")
    _ovb = (
        _expected_int(current_key.valid_before, f"{ctx}: valid_before type")
        if current_key.valid_before is not None
        else None
    )
    _nvb = (
        _expected_int(next_key.valid_before, f"{ctx}: valid_before type")
        if next_key.valid_before is not None
        else None
    )
    _mag = _unwrap(bounds_resolve(b, "integer_magnitude"))
    if abs(_ovf) > _mag or abs(_nvf) > _mag:
        _fail(f"{ctx}: valid_from magnitude")
    if (_ovb is not None and abs(_ovb) > _mag) or (_nvb is not None and abs(_nvb) > _mag):
        _fail(f"{ctx}: valid_before magnitude")
    if (_ovb is not None and _ovb <= _ovf) or (_nvb is not None and _nvb <= _nvf):
        _fail(f"{ctx}: valid_before ordering")
    seg = _parse_compact(compact, b)
    kid = _parse_transition_header(seg, b)
    if kid != current_key.key_id:
        _fail(f"{ctx}: kid")
    if expected.current_key_id != current_key.key_id:
        _fail(f"{ctx}: current key id")
    if expected.next_key_id != next_key.key_id:
        _fail(f"{ctx}: next key id")
    p = _unwrap(json_decode(seg.payload_bytes, b))
    _validate_transition_payload(p, seg.payload_bytes, b)
    if not isinstance(p, JObject):
        _fail(f"{ctx}: payload object")
    transition_id = _require_string_or_uri(p.v.get("transition_id"), "transition_id", b)
    if transition_id != expected.transition_id:
        _fail(f"{ctx}: transition_id")
    chain_id = _require_string_or_uri(p.v.get("chain_id"), "chain_id", b)
    if chain_id != expected.chain_id:
        _fail(f"{ctx}: chain_id")
    effective_at = _require_int(p.v.get("effective_at"), "effective_at")
    if effective_at != _expected_int(expected.effective_at, f"{ctx}: effective_at type"):
        _fail(f"{ctx}: effective_at")
    from_fp_raw = _require_b64url_n(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32)
    if not _bytes_equal(from_fp_raw, expected.current_key_fingerprint):
        _fail(f"{ctx}: from fp")
    to_fp_raw = _require_b64url_n(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32)
    if not _bytes_equal(to_fp_raw, expected.next_key_fingerprint):
        _fail(f"{ctx}: to fp")
    to_key_id_v = p.v["to_key_id"]
    if (
        not isinstance(to_key_id_v, JString)
        or _unwrap(utf8_str(to_key_id_v.v)) != expected.next_key_id
    ):
        _fail(f"{ctx}: to_key_id")
    derived_from = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(current_key.public_key))))
    if not _bytes_equal(derived_from, expected.current_key_fingerprint):
        _fail(f"{ctx}: current fp")
    derived_to = _unwrap(thumbprint_raw(_unwrap(jwk_from_public_key(next_key.public_key))))
    if not _bytes_equal(derived_to, expected.next_key_fingerprint):
        _fail(f"{ctx}: next fp")
    if not _in_window(effective_at, current_key):
        _fail(f"{ctx}: current window")
    if not _in_window(effective_at, next_key):
        _fail(f"{ctx}: next window")
    pk = _import_public_key(current_key.public_key)
    if not _es256_verify(seg.signing_input, seg.signature, pk):
        _fail(f"{ctx}: signature")


@dataclass(frozen=True)
class _ParsedArchive:
    header_bytes: bytes
    start: bytes
    transitions: tuple[bytes, ...]
    rows: tuple[bytes, ...]
    end: bytes


def _parse_archive(data: bytes, bounds: Bounds) -> _ParsedArchive:
    if not _bytes_equal(data[: len(ARCHIVE_PREFIX)], ARCHIVE_PREFIX):
        _fail("archive: prefix")
    cursor = len(ARCHIVE_PREFIX)
    header_frame = _read_frame(
        data, cursor, _unwrap(bounds_resolve(bounds, "archive_header_bytes")), "archive header"
    )
    cursor = header_frame[1]
    header = _unwrap(json_decode(header_frame[0], bounds))
    header = _require_object_exact(
        header,
        [
            "v",
            "chain_id",
            "first_sequence",
            "last_sequence",
            "row_count",
            "transition_count",
            "previous_hash",
            "last_hash",
        ],
        "archive header",
    )
    v_v = header.v["v"]
    if not isinstance(v_v, JInt) or v_v.v != VERSION:
        _fail("archive: header v")
    tc_v = header.v["transition_count"]
    if (
        not isinstance(tc_v, JInt)
        or tc_v.v < 0
        or tc_v.v > _unwrap(bounds_resolve(bounds, "key_transitions"))
    ):
        _fail("archive: transition_count")
    rc_v = header.v["row_count"]
    if (
        not isinstance(rc_v, JInt)
        or rc_v.v < 1
        or rc_v.v > _unwrap(bounds_resolve(bounds, "chain_rows"))
    ):
        _fail("archive: row_count")
    fs_v = header.v["first_sequence"]
    ls_v = header.v["last_sequence"]
    if not isinstance(fs_v, JInt) or not isinstance(ls_v, JInt):
        _fail("archive: header sequences")
    if not (fs_v.v > 0 and ls_v.v >= fs_v.v and rc_v.v == ls_v.v - fs_v.v + 1):
        _fail("archive: row range")
    _require_b64url_n(header.v.get("previous_hash"), "previous_hash", 32)
    _require_b64url_n(header.v.get("last_hash"), "last_hash", 32)
    start_frame = _read_frame(
        data, cursor, _unwrap(bounds_resolve(bounds, "anchor_bytes")), "start anchor"
    )
    cursor = start_frame[1]
    transitions: list[bytes] = []
    for i in range(tc_v.v):
        f = _read_frame(
            data, cursor, _unwrap(bounds_resolve(bounds, "anchor_bytes")), f"transition {i}"
        )
        transitions.append(f[0])
        cursor = f[1]
    rows: list[bytes] = []
    for i in range(rc_v.v):
        f = _read_frame(
            data, cursor, _unwrap(bounds_resolve(bounds, "chain_row_bytes")), f"row {i}"
        )
        rows.append(f[0])
        cursor = f[1]
    end_frame = _read_frame(
        data, cursor, _unwrap(bounds_resolve(bounds, "anchor_bytes")), "end anchor"
    )
    cursor = end_frame[1]
    if cursor != len(data):
        _fail("archive: exact EOF")
    return _ParsedArchive(
        header_bytes=header_frame[0],
        start=start_frame[0],
        transitions=tuple(transitions),
        rows=tuple(rows),
        end=end_frame[0],
    )


def _read_frame(data: bytes, cursor: int, maximum: int, ctx: str) -> tuple[bytes, int]:
    if cursor + 4 > len(data):
        _fail(f"{ctx}: frame length")
    length = (
        data[cursor] << 24 | data[cursor + 1] << 16 | data[cursor + 2] << 8 | data[cursor + 3]
    ) & 0xFFFFFFFF
    if length == 0 or length > maximum:
        _fail(f"{ctx}: frame bound")
    start = cursor + 4
    end = start + length
    if end > len(data):
        _fail(f"{ctx}: complete frame")
    return data[start:end], end


def _validate_key_path(
    start: ExpectedAnchor, transitions: Sequence[ExpectedKeyTransition], end: ExpectedAnchor
) -> None:
    """Validate the expected key-transition path (spec/bap-v3.md §2 incorporates
    spec/bap-v1.md §15, Authenticated key transitions). The no-transition path requires the start and end anchors to share key id +
    fingerprint with a chronologically-non-decreasing end anchored_at. The transition path
    requires: each transition's current key matches the running key; effective_at is strictly
    increasing; no next fingerprint has appeared before (cycle rejection); the end anchor closes
    on the last transition's next key with a chronologically-non-decreasing anchored_at."""
    if len(transitions) == 0:
        if start.key_id != end.key_id or not _bytes_equal(
            start.key_fingerprint, end.key_fingerprint
        ):
            _fail("key path: start==end key")
        if not (end.anchored_at >= start.anchored_at):
            _fail("key path: end chronological")
        return
    current_key_id = start.key_id
    current_fp = start.key_fingerprint
    previous_time = start.anchored_at
    # seen is seeded with the start anchor's fingerprint.
    seen: list[bytes] = [start.key_fingerprint]
    for i, t in enumerate(transitions):
        if t.current_key_id != current_key_id or not _bytes_equal(
            t.current_key_fingerprint, current_fp
        ):
            _fail(f"key path: transition {i} current key")
        # strictly increasing effective_at.
        if not (t.effective_at > previous_time):
            _fail(f"key path: transition {i} chronology")
        # No cycle: next_key_fingerprint must not be in seen.
        if any(_bytes_equal(t.next_key_fingerprint, s) for s in seen):
            _fail(f"key path: transition {i} cycle")
        current_key_id = t.next_key_id
        current_fp = t.next_key_fingerprint
        previous_time = t.effective_at
        seen.append(t.next_key_fingerprint)
    # The end anchor must close on the last transition's next key.
    if end.key_id != current_key_id or not _bytes_equal(end.key_fingerprint, current_fp):
        _fail("key path: end key")
    # chronological_end: >= the last transition's effective_at.
    if not (end.anchored_at >= previous_time):
        _fail("key path: end chronological")


def _validate_chunks(chunks: Sequence[bytes], bounds: Bounds = MAXIMUM_BOUNDS) -> None:
    """Validate chunks before concatenation (spec/bap-v3.md §2 incorporates
    spec/bap-v1.md §§16-17, REQ1-EXPORT-input-shape, REQ1-BOUNDS-tighten-only): a nonempty
    list of nonempty chunks, count ≤ archive_chunks, running total ≤ archive_bytes."""
    # The input boundary requires immutable bytes chunks.
    if len(chunks) == 0:
        _fail("archive: no chunks")
    # The archive_chunks ceiling is inclusive (spec/bap-v1.md §17).
    if len(chunks) > _unwrap(bounds_resolve(bounds, "archive_chunks")):
        _fail("archive: chunk count")
    total = 0
    for i, c in enumerate(chunks):
        if len(c) == 0:
            _fail(f"archive: empty chunk {i}")
        total += len(c)
        if total > _unwrap(bounds_resolve(bounds, "archive_bytes")):
            _fail("archive: chunk bytes")


def _require_bounds_equal(nested: Bounds | None, top: Bounds, ctx: str) -> None:
    """Pin a nested expected.bounds to the top-level resolved bounds.

    When a nested bounds is present it must coerce cleanly AND resolve to the same value as
    ``top`` for every limit. An absent nested bounds is valid only when the top is also maximum
    (no tightening); a tightened top requires every nested struct to carry the same tightening.
    """
    if nested is None:
        # Gate on EFFECTIVE tightening, not override-map size: an identity override (value ==
        # the maximum) merges to the full maximum struct, so the pin's struct equality accepts
        # an absent nested bounds.
        for _k, _v in top.overrides.items():
            if _v != MAXIMA[_k]:
                _fail(f"{ctx}: nested bounds absent under tightened top")
        return
    coerced = _unwrap(coerce_bounds(nested))
    for key in MAXIMA:
        if _unwrap(bounds_resolve(coerced, key)) != _unwrap(bounds_resolve(top, key)):
            _fail(f"{ctx}: nested bounds mismatch")
