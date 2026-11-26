"""Explicit host-value gates shared by public input boundaries."""

from __future__ import annotations

import types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import fields, is_dataclass
from typing import Any, TypeVar, Union, cast, get_args, get_origin, get_type_hints, overload

from .error import _fail, _invalid_error


def _buffer(value: object) -> bytes | memoryview[int]:
    if type(value) is bytes:
        return value
    if issubclass(type(value), (bytes, bytearray)):
        return memoryview(cast(bytes | bytearray, value))
    if issubclass(type(value), memoryview):
        # A released view has no readable buffer. Its built-in representation is the
        # non-raising state query; buffer access would raise ValueError.
        if memoryview.__repr__(cast("memoryview[int]", value)).startswith("<released "):
            _fail()
        return cast("memoryview[int]", value)
    raise _invalid_error()


def _buffer_size(value: bytes | memoryview[int]) -> int:
    return len(value) if isinstance(value, bytes) else value.nbytes


def _bytes(value: object, maximum: int | None = None) -> bytes:
    buffer = _buffer(value)
    if maximum is not None and _buffer_size(buffer) > maximum:
        _fail()
    return buffer if isinstance(buffer, bytes) else buffer.tobytes()


def _text(value: object) -> str:
    if not issubclass(type(value), str):
        _fail()
    text = str.__str__(cast(str, value))
    if any(0xD800 <= ord(char) <= 0xDFFF for char in text):
        _fail()
    return text


def _decode_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        _fail()


_T = TypeVar("_T")


@overload
def _normalize_arg(value: object, annotation: type[_T], depth: int = 0) -> _T: ...


@overload
def _normalize_arg(value: object, annotation: object, depth: int = 0) -> object: ...


def _normalize_arg(value: object, annotation: object, depth: int = 0) -> object:
    """Copy accepted host values before protocol code uses them; bound recursive shapes."""
    from .bounds import Bounds, coerce_bounds
    from .error import _unwrap
    from .facts import _Facts
    from .json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString, _normalize_tagged

    if depth > 32:
        _fail()
    if annotation is Any or annotation is object:
        if value is None or type(value) is bool:
            return value
        for kind in (str, bytes, int, float):
            if issubclass(type(value), kind):
                return _normalize_arg(value, kind, depth)
        if issubclass(type(value), (bytearray, memoryview)):
            return _bytes(value)
        if type(value) in (JNull, JBool, JInt, JFloat, JString, JArray, JObject):
            return _normalize_tagged(value)
        if issubclass(type(value), (list, tuple)):
            return tuple(
                _normalize_arg(v, object, depth + 1)
                for v in _sequence(cast(list[object] | tuple[object, ...], value))
            )
        return {_text(k): _normalize_arg(v, object, depth + 1) for k, v in _mapping_items(value)}
    if annotation is type(None):
        if value is not None:
            _fail()
        return None
    if isinstance(annotation, type):
        if annotation is bytes:
            return _bytes(value)
        if annotation is str:
            return _text(value)
        if annotation is int:
            if not issubclass(type(value), int) or issubclass(type(value), bool):
                _fail()
            return int.__int__(cast(int, value))
        if annotation is float:
            if not issubclass(type(value), float):
                _fail()
            return float.__float__(cast(float, value))
        if annotation is bool:
            if type(value) is not bool:
                _fail()
            return value
        if annotation is Bounds:
            return _unwrap(coerce_bounds(value))
        if annotation in (JNull, JBool, JInt, JFloat, JString, JArray, JObject):
            if type(value) is not annotation:
                _fail()
            return _normalize_tagged(value)
        if is_dataclass(annotation) or issubclass(annotation, _Facts):
            if type(value) is not annotation:
                _fail()
            missing = object()
            members: dict[str, object] = {}
            hints: dict[str, object] = (
                get_type_hints(annotation.__init__)
                if issubclass(annotation, _Facts)
                else get_type_hints(annotation)
            )
            init_names = (
                {f.name for f in fields(annotation) if f.init}
                if is_dataclass(annotation)
                else set(hints)
            )
            for name, sub in hints.items():
                if name == "return":
                    continue
                member = getattr(value, name, missing)
                if member is missing:
                    _fail()
                normalized = _normalize_arg(member, sub, depth + 1)
                if name in init_names:
                    members[name] = normalized
            return cast(Callable[..., object], annotation)(**members)
    origin = get_origin(annotation)
    if origin is Union or isinstance(annotation, types.UnionType):
        from .error import InvalidError

        for sub in get_args(annotation):
            try:
                return _normalize_arg(value, sub, depth)
            except InvalidError:
                continue
        _fail()
    if origin in (tuple, Sequence):
        if not issubclass(type(value), (list, tuple)):
            _fail()
        sub = get_args(annotation)[0]
        return tuple(
            _normalize_arg(member, sub, depth + 1)
            for member in _sequence(cast(list[object] | tuple[object, ...], value))
        )
    if origin is Mapping:
        key_type, value_type = get_args(annotation)
        return {
            _normalize_arg(k, key_type, depth + 1): _normalize_arg(v, value_type, depth + 1)
            for k, v in _mapping_items(value)
        }
    raise TypeError(f"unsupported input annotation: {annotation!r}")


def _sequence(value: Sequence[_T]) -> tuple[_T, ...]:
    """Snapshot native containers without calling subclass iteration or length methods."""
    iterator = (
        list.__iter__(cast(list[_T], value))
        if issubclass(type(value), list)
        else tuple.__iter__(cast(tuple[_T, ...], value))
    )
    return tuple(iterator)


def _mapping_items(value: object) -> list[tuple[object, object]]:
    """The sole caller-callback boundary: snapshot an arbitrary Mapping exactly once.

    Native dictionaries use their builtin storage. Exceptions from an external Mapping's
    items method or returned iterator are caller failures; SDK code outside this invocation
    remains outside the catch.
    """
    if issubclass(type(value), dict):
        return list(dict.items(cast(dict[object, object], value)))
    try:
        if not issubclass(type(value), Mapping):
            _fail()
        snapshot: list[object] = list(cast(Mapping[object, object], value).items())
    except Exception:
        _fail()
    out: list[tuple[object, object]] = []
    for pair in snapshot:
        if not issubclass(type(pair), (list, tuple)):
            _fail()
        native = _sequence(cast(list[object] | tuple[object, ...], pair))
        if len(native) != 2:
            _fail()
        out.append((native[0], native[1]))
    return out
