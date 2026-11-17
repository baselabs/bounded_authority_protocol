"""The fixed BAP1 maxima plus the content-assertion byte ceiling.

Pinned by the corpus ``bounds.new`` cases so any mistyped constant fails. Fixed-width keys
(REQ1-BOUNDS-fixed-widths, L395): ``digest_bytes``, ``public_key_bytes``, ``signature_bytes`` are the
immutable cryptographic constants of suite BAP1-Ed25519-SHA256 — they MUST equal the maximum exactly
(widening is forbidden); all others may be tightened to a positive integer at most the maximum.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import cast

from ._inputs import _mapping_items, _text
from .error import InvalidError, Ok, Result, _fail, err

# The original 38-row table comes from spec/bap-v1.md. ``content_bytes`` is the ADR 0018
# amendment defined by spec/bap-content-assertion-v1.md; existing profile meanings are unchanged.
MAXIMA: Mapping[str, int] = MappingProxyType({
    "compact_bytes": 65536,
    "encoded_segment_bytes": 32768,
    "decoded_segment_bytes": 24576,
    "json_bytes": 65536,
    "depth": 32,
    "object_members": 64,
    "array_items": 256,
    "total_nodes": 4096,
    "string_bytes": 8192,
    "key_bytes": 128,
    "number_lexeme_bytes": 64,
    "integer_magnitude": 9007199254740991,
    "float_magnitude": 9007199254740991,
    "kid_bytes": 128,
    "jcs_bytes": 65536,
    "uri_bytes": 8192,
    "identifier_bytes": 512,
    "nonce_bytes": 512,
    "method_bytes": 32,
    "operation_bytes": 128,
    "audiences": 64,
    "operations": 64,
    "selectors": 64,
    "path_segments": 32,
    "one_of_values": 256,
    "public_key_bytes": 32,
    "signature_bytes": 64,
    "digest_bytes": 32,
    "clock_skew": 60,
    "proof_max_age": 300,
    "chain_row_bytes": 4096,
    "chain_rows": 65536,
    "anchor_bytes": 8192,
    "archive_header_bytes": 8192,
    "archive_chunks": 65796,
    "archive_bytes": 270820384,
    "object_version_bytes": 512,
    "key_transitions": 256,
    "content_bytes": 65536,
})

MaximaKey = str
"""A key into the MAXIMA table (a string, since Python's type system treats it lexically)."""

# The fixed-width keys (REQ1-BOUNDS-fixed-widths, L395) — cannot be tightened or widened.
FIXED_WIDTH_KEYS: frozenset[str] = frozenset({"digest_bytes", "public_key_bytes", "signature_bytes"})


class Bounds:
    """Immutable limits, validated and copied exactly once at construction.

    Invalid construction retains only an invalid marker. Public bounds functions return Err for
    that marker. Resolution never re-walks the overrides.
    """

    __slots__ = ("_overrides",)
    _overrides: Mapping[str, int] | None

    def __init__(self, overrides: object = None) -> None:
        if hasattr(self, "_overrides"):
            raise TypeError("Bounds cannot be initialized twice")
        try:
            validated: dict[str, int] = {}
            if overrides is not None:
                for key, value in _mapping_items(overrides):
                    if not issubclass(type(key), str) or not issubclass(type(value), int) or type(value) is bool:
                        _fail()
                    key = str.__str__(cast(str, key))
                    value = int.__int__(cast(int, value))
                    if key not in MAXIMA or value <= 0 or value > MAXIMA[key]:
                        _fail()
                    if key in FIXED_WIDTH_KEYS and value != MAXIMA[key]:
                        _fail()
                    validated[key] = value
            object.__setattr__(self, "_overrides", MappingProxyType(validated))
        except InvalidError:
            object.__setattr__(self, "_overrides", None)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Bounds is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Bounds is immutable")

    @property
    def overrides(self) -> Mapping[str, int]:
        return self._overrides if self._overrides is not None else MappingProxyType({})

    def resolve(self, key: str) -> Result[int]:
        return bounds_resolve(self, key)


MAXIMUM_BOUNDS = Bounds()
"""The immutable maximum returned by ``bounds_maximum`` (REQ1-BOUNDS-tighten-only)."""


def bounds_maximum() -> Result[Bounds]:
    return Ok(MAXIMUM_BOUNDS)


def bounds_resolve(b: object, key: str) -> Result[int]:
    try:
        key = _text(key)
        if type(b) is not Bounds or key not in MAXIMA or getattr(b, "_overrides", None) is None:
            _fail()
        assert b._overrides is not None
        return Ok(b._overrides.get(key, MAXIMA[key]))
    except InvalidError:
        return err()


def bounds_new(tightening: Mapping[str, int] | None = None) -> Result[Bounds]:
    """Construct validated, immutable tightenings; invalid limits return the closed Err."""
    result = Bounds(tightening)
    return coerce_bounds(result)


def coerce_bounds(b: object) -> Result[Bounds]:
    """Accept only a Bounds value whose constructor validated all limits."""
    if type(b) is not Bounds or getattr(b, "_overrides", None) is None:
        return err()
    return Ok(b)
