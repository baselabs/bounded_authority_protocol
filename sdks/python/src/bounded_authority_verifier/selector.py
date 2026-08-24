"""Closed selector algebra (protocol-v1.md § Selectors, L179-199; REQ1-SELECTOR-closed-set).

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

from dataclasses import dataclass

from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .digest import typed_project
from .error import fail
from .jcs import jcs_encode
from .json_alg import JArray, JObject, JString, Tagged, utf8_str

_SELECTOR_KINDS = {"all", "equals", "one_of"}
_SELECTOR_MEMBER_SETS = {
    frozenset({"kind"}),
    frozenset({"kind", "path", "value"}),
    frozenset({"kind", "path", "values"}),
}


@dataclass(frozen=True)
class SelAll:
    pass


@dataclass(frozen=True)
class SelEquals:
    path: tuple[str, ...]
    value: Tagged


@dataclass(frozen=True)
class SelOneOf:
    path: tuple[str, ...]
    values: tuple[Tagged, ...]


Selector = SelAll | SelEquals | SelOneOf


def parse_selector(obj: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> Selector:
    """Validate + parse a selector from a decoded tagged object. Rejects unknown members, bad shapes."""
    if not isinstance(obj, JObject):
        fail("selector: object")
    members = obj.v
    kind_v = members.get("kind")
    if not isinstance(kind_v, JString):
        fail("selector: kind")
    kind = utf8_str(kind_v.v)
    if kind not in _SELECTOR_KINDS:
        fail("selector: kind closed set")
    if frozenset(members) not in _SELECTOR_MEMBER_SETS:
        fail("selector: member set")
    # For all, path/value(s) are inert and need not satisfy active-kind shapes.
    if kind == "all":
        return SelAll()
    if kind == "equals":
        if len(members) != 3:
            fail("selector: equals members")
        path = _parse_path(members.get("path"), bounds)
        value = members.get("value")
        if value is None:
            fail("selector: value")
        _validate_selector_value(value, bounds)
        return SelEquals(path, value)
    # one_of
    if len(members) != 3:
        fail("selector: one_of members")
    path = _parse_path(members.get("path"), bounds)
    values_v = members.get("values")
    if values_v is None:
        fail("selector: values")
    if not isinstance(values_v, JArray):
        fail("selector: values array")
    if not (1 <= len(values_v.v) <= bounds_resolve(bounds, "one_of_values")):
        fail("selector: values count")
    values = tuple(values_v.v)
    for v in values:
        _validate_selector_value(v, bounds)
    return SelOneOf(path, values)


def _parse_path(path_v: Tagged | None, bounds: Bounds) -> tuple[str, ...]:
    if path_v is None or not isinstance(path_v, JArray):
        fail("selector: path array")
    if not (1 <= len(path_v.v) <= bounds_resolve(bounds, "path_segments")):
        fail("selector: path length")
    names: list[str] = []
    for seg in path_v.v:
        if not isinstance(seg, JString):
            fail("selector: path segment string")
        if not (1 <= len(seg.v) <= bounds_resolve(bounds, "key_bytes")):
            fail("selector: path segment bytes")
        names.append(utf8_str(seg.v))
    return tuple(names)


def _validate_selector_value(v: Tagged, bounds: Bounds) -> None:
    _check_node(v, 1, bounds)


def _check_node(v: Tagged, depth: int, bounds: Bounds) -> None:
    if depth > bounds_resolve(bounds, "depth"):
        fail("selector: value depth")
    if isinstance(v, JString):
        if len(v.v) > bounds_resolve(bounds, "string_bytes"):
            fail("selector: string bytes")
    elif isinstance(v, _JInt):
        if abs(v.v) > bounds_resolve(bounds, "integer_magnitude"):
            fail("selector: int magnitude")
    elif isinstance(v, _JFloat):
        if abs(v.v) > bounds_resolve(bounds, "float_magnitude"):
            fail("selector: float magnitude")
    elif isinstance(v, JArray):
        if len(v.v) > bounds_resolve(bounds, "array_items"):
            fail("selector: array items")
        for item in v.v:
            _check_node(item, depth + 1, bounds)
    elif isinstance(v, JObject):
        if len(v.v) > bounds_resolve(bounds, "object_members"):
            fail("selector: object members")
        for val in v.v.values():
            _check_node(val, depth + 1, bounds)


def semantic_identity(value: Tagged) -> bytes:
    """Semantic identity = JCS of the typed-projected form. Returns canonical bytes for comparison."""
    return jcs_encode(typed_project(value))


def _traverse_path(root: Tagged, path: tuple[str, ...]) -> Tagged | None:
    """Traverse a path over an OBJECT (paths never index arrays). Returns the value or None."""
    cur: Tagged | None = root
    for name in path:
        if not isinstance(cur, JObject):
            return None
        cur = cur.v.get(name)
    return cur


def selector_matches(sel: Selector, cast_arguments: Tagged) -> bool:
    """Does this selector match? equals/one_of REQUIRE the path to exist (missing path → no match)."""
    if isinstance(sel, SelAll):
        return True
    target = _traverse_path(cast_arguments, sel.path)
    if target is None:
        return False
    target_id = semantic_identity(target)
    if isinstance(sel, SelEquals):
        return semantic_identity(sel.value) == target_id
    # one_of
    return any(semantic_identity(v) == target_id for v in sel.values)


# Late type aliases to avoid a top-of-module circular import (digest imports json_alg; this module
# imports digest). Re-import the concrete classes for isinstance.
from .json_alg import JFloat as _JFloat  # noqa: E402
from .json_alg import JInt as _JInt  # noqa: E402
