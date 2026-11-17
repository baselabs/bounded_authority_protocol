"""The fixed BAP1 maxima plus the content-assertion byte ceiling.

Pinned by the corpus ``bounds.new`` cases so any mistyped constant fails. Fixed-width keys
(REQ1-BOUNDS-fixed-widths, L395): ``digest_bytes``, ``public_key_bytes``, ``signature_bytes`` are the
immutable cryptographic constants of suite BAP1-Ed25519-SHA256 — they MUST equal the maximum exactly
(widening is forbidden); all others may be tightened to a positive integer at most the maximum.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .error import Err, InvalidError, Ok, Result, err

# The original 38-row table comes from spec/bap-v1.md. ``content_bytes`` is the ADR 0018
# amendment defined by spec/bap-content-assertion-v1.md; existing profile meanings are unchanged.
MAXIMA: Mapping[str, int] = {
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
}

MaximaKey = str
"""A key into the MAXIMA table (a string, since Python's type system treats it lexically)."""

# The fixed-width keys (REQ1-BOUNDS-fixed-widths, L395) — cannot be tightened or widened.
FIXED_WIDTH_KEYS: frozenset[str] = frozenset({"digest_bytes", "public_key_bytes", "signature_bytes"})


class Bounds:
    """The immutable maximum + an optional per-key tightening override.

    ``maximum`` is always the full MAXIMA table; ``overrides`` carries caller tightenings as a
    READ-ONLY view (``MappingProxyType``) so a caller cannot mutate a shared ``Bounds`` to widen the
    profile maximum globally. The profile maxima is the ceiling for every key; an override may only
    lower a non-fixed key (or set a fixed-width key to exactly its maximum, a no-op).
    """

    __slots__ = ("_overrides",)

    def __init__(self, overrides: Mapping[str, int] | None = None) -> None:
        # Wrap in a read-only MappingProxyType so the overrides cannot be mutated post-construction
        # (a caller doing ``MAXIMUM_BOUNDS.overrides["depth"] = 999`` raises TypeError, not widens).
        self._overrides: Mapping[str, int] = MappingProxyType(dict(overrides)) if overrides else MappingProxyType({})

    @property
    def overrides(self) -> Mapping[str, int]:
        """The read-only override map (a MappingProxyType — mutation raises TypeError)."""
        return self._overrides

    def resolve(self, key: str) -> Result[int]:
        """Resolve a known bound after validating the caller-supplied limits."""
        if type(key) is not str or key not in MAXIMA:
            return err()
        checked = coerce_bounds(self)
        if isinstance(checked, Err):
            return checked
        return Ok(self._overrides.get(key, MAXIMA[key]))


MAXIMUM_BOUNDS = Bounds()
"""The immutable maximum returned by ``bounds_maximum`` (REQ1-BOUNDS-tighten-only)."""


def bounds_maximum() -> Result[Bounds]:
    """Return the profile maxima (REQ1-BOUNDS-tighten-only)."""
    return Ok(MAXIMUM_BOUNDS)


def bounds_resolve(b: Bounds, key: str) -> Result[int]:
    """Module-level resolve helper: the override if present, else the maximum."""
    if type(b) is not Bounds:
        return err()
    return b.resolve(key)


def bounds_new(tightening: Mapping[str, int] | None = None) -> Result[Bounds]:
    """Construct a Bounds from a tightening map.

    REQ1-BOUNDS-reject-list (L397): unknown, non-integer, zero, negative, widening, or fixed-width-
    changing limits are invalid. Fixed-width keys (L395) cannot be tightened or widened, but setting
    to the exact maximum is an identity no-op (valid). Any other value rejects.
    """
    # Local import to avoid a cycle: bounds is imported by error-adjacent primitives, and fail lives
    # in error. (fail does not import bounds, so there is no actual cycle, but the locality keeps the
    # dependency direction explicit.)
    try:
        from .error import _fail

        if tightening is None:
            return Ok(MAXIMUM_BOUNDS)
        overrides: dict[str, int] = {}
        for key, value in tightening.items():
            if key not in MAXIMA:
                _fail("bounds.new: unknown limit")
            if not isinstance(value, int) or isinstance(value, bool):
                _fail("bounds.new: non-integer limit")
            if key in FIXED_WIDTH_KEYS:
                # REQ1-BOUNDS-fixed-widths: fixed-width keys cannot be tightened or widened, but setting
                # to the exact maximum is an identity no-op (valid). Any other value rejects.
                if value != MAXIMA[key]:
                    _fail("bounds.new: fixed-width limit must equal maximum")
            else:
                if value <= 0:
                    _fail("bounds.new: non-positive limit")
                if value > MAXIMA[key]:
                    _fail("bounds.new: widening limit")
            overrides[key] = value
        return Ok(Bounds(overrides))
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()


def coerce_bounds(b: Bounds) -> Result[Bounds]:
    """Re-validate a Bounds object (mirrors the reference's Bounds.coerce/1).

    ``Bounds`` is a class with a public ``overrides`` mapping, so a caller can hand-craft a
    ``Bounds`` that bypasses ``bounds_new`` — including a WIDENING override (compact_bytes > MAXIMA).
    Without this validation the verify/decode paths could honor
    the forged widening. Resolution also uses this gate. ``coerce_bounds`` re-runs the ``bounds_new`` validation over
    the override map so every entry point that resolves caller-supplied bounds fails closed on a
    forgery.
    """
    try:
        from .error import _fail

        for key, value in b.overrides.items():
            if key not in MAXIMA:
                _fail("bounds.coerce: unknown limit")
            if not isinstance(value, int) or isinstance(value, bool):
                _fail("bounds.coerce: non-integer limit")
            if key in FIXED_WIDTH_KEYS:
                if value != MAXIMA[key]:
                    _fail("bounds.coerce: fixed-width limit must equal maximum")
            else:
                if value <= 0:
                    _fail("bounds.coerce: non-positive limit")
                if value > MAXIMA[key]:
                    _fail("bounds.coerce: widening limit")
        return Ok(b)
    except (InvalidError, AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        return err()
