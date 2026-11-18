"""Closed selector algebra (spec/bap-v1.md § Selectors, L179-199; REQ1-SELECTOR-closed-set).

Three recognized member sets. ``all`` may use any of them and ignores the
other members; ``equals`` and ``one_of`` use their matching three-member set::

    all      → {kind} | {kind,path,value} | {kind,path,values}
    equals   → {kind:"equals", path:[names], value:<JSON>}
    one_of   → {kind:"one_of", path:[names], values:[<JSON>...]}

``path`` is an array of object-member names (1..32, each 1..128 bytes) traversing OBJECTS only.
Semantic identity (REQ1-SELECTOR-semantic-identity) = JCS of the typed-projected form, so the
int/float distinction survives (REQ1-SELECTOR-no-tag-collapse).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ._inputs import _normalize_arg
from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .digest import typed_project
from .error import InvalidError, Ok, Result, _fail, _unwrap, err
from .jcs import jcs_encode
from .json_alg import JArray, JObject, JString, Tagged, _normalize_tagged, utf8_str

_SELECTOR_KINDS = {"all", "equals", "one_of"}
_SELECTOR_MEMBER_SETS = {
    frozenset({"kind"}),
    frozenset({"kind", "path", "value"}),
    frozenset({"kind", "path", "values"}),
}


@dataclass(frozen=True)
class SelAll:
    """A selector that accepts every argument value at its path."""


@dataclass(frozen=True)
class SelEquals:
    """A selector requiring exact tagged-JSON equality at its path.

    Fields:
        path: tuple[str, ...].
        value: Tagged.
    """
    path: tuple[str, ...]
    value: Tagged


@dataclass(frozen=True)
class SelOneOf:
    """A selector accepting a value from an explicit set of tagged values.

    Fields:
        path: tuple[str, ...].
        values: tuple[Tagged, ...].
    """
    path: tuple[str, ...]
    values: tuple[Tagged, ...]


Selector = SelAll | SelEquals | SelOneOf


def parse_selector(obj: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[Selector]:
    """Validate + parse a selector from a decoded tagged object. Rejects unknown members, bad shapes."""
    try:
        obj = _normalize_tagged(obj, bounds)
        if not isinstance(obj, JObject):
            _fail("selector: object")
        members = obj.v
        kind_v = members.get("kind")
        if not isinstance(kind_v, JString):
            _fail("selector: kind")
        kind = _unwrap(utf8_str(kind_v.v))
        if kind not in _SELECTOR_KINDS:
            _fail("selector: kind closed set")
        if frozenset(members) not in _SELECTOR_MEMBER_SETS:
            _fail("selector: member set")
        # For all, path/value(s) are inert and need not satisfy active-kind shapes.
        if kind == "all":
            return Ok(SelAll())
        if kind == "equals":
            if len(members) != 3:
                _fail("selector: equals members")
            path = _parse_path(members.get("path"), bounds)
            value = members.get("value")
            if value is None:
                _fail("selector: value")
            _validate_selector_value(value, bounds)
            if not _float_zero_free(value):
                _fail("selector: float zero")
            return Ok(SelEquals(path, value))
        # one_of
        if len(members) != 3:
            _fail("selector: one_of members")
        path = _parse_path(members.get("path"), bounds)
        values_v = members.get("values")
        if values_v is None:
            _fail("selector: values")
        if not isinstance(values_v, JArray):
            _fail("selector: values array")
        if not (1 <= len(values_v.v) <= _unwrap(bounds_resolve(bounds, "one_of_values"))):
            _fail("selector: values count")
        values = tuple(values_v.v)
        for v in values:
            _validate_selector_value(v, bounds)
            if not _float_zero_free(v):
                _fail("selector: float zero")
        return Ok(SelOneOf(path, values))
    except InvalidError:
        return err()


def _parse_path(path_v: Tagged | None, bounds: Bounds) -> tuple[str, ...]:
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


def _validate_selector_value(v: Tagged, bounds: Bounds) -> None:
    _check_node(v, 1, bounds)


def _check_node(v: Tagged, depth: int, bounds: Bounds) -> None:
    if depth > _unwrap(bounds_resolve(bounds, "depth")):
        _fail("selector: value depth")
    if isinstance(v, JString):
        if len(v.v) > _unwrap(bounds_resolve(bounds, "string_bytes")):
            _fail("selector: string bytes")
    elif isinstance(v, _JInt):
        if abs(v.v) > _unwrap(bounds_resolve(bounds, "integer_magnitude")):
            _fail("selector: int magnitude")
    elif isinstance(v, _JFloat):
        if abs(v.v) > _unwrap(bounds_resolve(bounds, "float_magnitude")):
            _fail("selector: float magnitude")
    elif isinstance(v, JArray):
        if len(v.v) > _unwrap(bounds_resolve(bounds, "array_items")):
            _fail("selector: array items")
        for item in v.v:
            _check_node(item, depth + 1, bounds)
    elif isinstance(v, JObject):
        if len(v.v) > _unwrap(bounds_resolve(bounds, "object_members")):
            _fail("selector: object members")
        for val in v.v.values():
            _check_node(val, depth + 1, bounds)


def _float_zero_free(value: Tagged) -> bool:
    """Erratum 6, verification (REQ1/REQ2/REQ3-SELECTOR-float-zero): an ``equals`` value or
    ``one_of`` member is admissible only when it holds no float-tagged zero at any depth. Keyed
    on the decoded value, so every spelling of zero (``0.0``, ``-0e0``, ``1e-400``, ...) is
    covered. Range bounds and inert ``all`` members are not checked
    (spec/bap-v1.md §12, REQ1-SELECTOR-float-zero)."""
    return _no_float_where(value, lambda x: x == 0.0)


def _integral_float_free(value: Tagged) -> bool:
    """Erratum 6, producers (REQ1/REQ2/REQ3-SIGNING-integral-float-selector): RFC 8785 writes an
    integral float as integer text, which decodes integer-tagged, so a producer refuses any
    float-tagged integral selector value (``0.0``, ``-0.0``, ``10.0``) rather than sign a value
    whose tag the wire changes (spec/bap-v1.md §12,
    REQ1-SIGNING-integral-float-selector)."""
    return _no_float_where(value, float.is_integer)


def _no_float_where(value: Tagged, banned: Callable[[float], bool]) -> bool:
    if isinstance(value, _JFloat):
        return not banned(value.v)
    if isinstance(value, JArray):
        return all(_no_float_where(item, banned) for item in value.v)
    if isinstance(value, JObject):
        return all(_no_float_where(member, banned) for member in value.v.values())
    return True


def semantic_identity(value: Tagged) -> Result[bytes]:
    """Semantic identity = JCS of the typed-projected form. Returns canonical bytes for comparison."""
    try:
        value = _normalize_tagged(value, MAXIMUM_BOUNDS)
        return Ok(_unwrap(jcs_encode(_unwrap(typed_project(value)))))
    except InvalidError:
        return err()


def _traverse_path(root: Tagged, path: tuple[str, ...]) -> Tagged | None:
    """Traverse a path over an OBJECT (paths never index arrays). Returns the value or None."""
    cur: Tagged | None = root
    for name in path:
        if not isinstance(cur, JObject):
            return None
        cur = cur.v.get(name)
    return cur


def selector_matches(sel: Selector, cast_arguments: Tagged) -> Result[bool]:
    """Does this selector match? equals/one_of REQUIRE the path to exist (missing path → no match)."""
    try:
        sel = _normalize_arg(sel, Selector)
        cast_arguments = _normalize_tagged(cast_arguments, MAXIMUM_BOUNDS)
        if isinstance(sel, SelAll):
            return Ok(True)
        target = _traverse_path(cast_arguments, sel.path)
        if target is None:
            return Ok(False)
        target_id = _unwrap(semantic_identity(target))
        if isinstance(sel, SelEquals):
            return Ok(_unwrap(semantic_identity(sel.value)) == target_id)
        # one_of
        return Ok(any(_unwrap(semantic_identity(v)) == target_id for v in sel.values))
    except InvalidError:
        return err()


# Late type aliases to avoid a top-of-module circular import (digest imports json_alg; this module
# imports digest). Re-import the concrete classes for isinstance.
from .json_alg import JFloat as _JFloat  # noqa: E402
from .json_alg import JInt as _JInt  # noqa: E402
