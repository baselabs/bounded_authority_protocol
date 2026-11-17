"""Explicit host-value gates shared by public input boundaries."""

from __future__ import annotations

import types
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from typing import Any, Union, get_args, get_origin, get_type_hints

from .error import _fail, _invalid_error


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return memoryview(value).tobytes()
    if isinstance(value, bytearray):
        return memoryview(value).tobytes()
    if isinstance(value, memoryview):
        # A released view has no readable buffer. Its built-in representation is the
        # non-raising state query; buffer access would raise ValueError.
        if memoryview.__repr__(value).startswith("<released "):
            _fail()
        return memoryview.tobytes(value)
    raise _invalid_error()


def _text(value: object) -> str:
    if not isinstance(value, str):
        _fail()
    text = str.__str__(value)
    if any(0xD800 <= ord(char) <= 0xDFFF for char in text):
        _fail()
    return text


def _decode_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        _fail()


def _normalize_arg(value: object, annotation: object, depth: int = 0) -> Any:
    """Copy accepted host values before protocol code uses them; bound recursive shapes."""
    from .bounds import Bounds, coerce_bounds
    from .error import _unwrap
    from .facts import _Facts
    from .json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString, _normalize_tagged

    if depth > 32:
        _fail()
    if annotation is Any or annotation is object:
        return value
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
            if not isinstance(value, int) or isinstance(value, bool):
                _fail()
            return int.__int__(value)
        if annotation is float:
            if not isinstance(value, float):
                _fail()
            return float.__float__(value)
        if annotation is bool:
            if type(value) is not bool:
                _fail()
            return value
        if annotation is Bounds:
            return _unwrap(coerce_bounds(value))
        if annotation in (JNull, JBool, JInt, JFloat, JString, JArray, JObject):
            if not isinstance(value, annotation):
                _fail()
            return _normalize_tagged(value)
        if is_dataclass(annotation) or issubclass(annotation, _Facts):
            if not isinstance(value, annotation):
                _fail()
            missing = object()
            members = {}
            hints = get_type_hints(annotation.__init__) if issubclass(annotation, _Facts) else get_type_hints(annotation)
            init_names = {f.name for f in fields(annotation) if f.init} if is_dataclass(annotation) else set(hints)
            for name, sub in hints.items():
                if name == "return":
                    continue
                member = getattr(value, name, missing)
                if member is missing:
                    _fail()
                normalized = _normalize_arg(member, sub, depth + 1)
                if name in init_names:
                    members[name] = normalized
            return annotation(**members)
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
        if not isinstance(value, (list, tuple)):
            _fail()
        sub = get_args(annotation)[0]
        return tuple(_normalize_arg(member, sub, depth + 1) for member in value)
    if origin is Mapping:
        if not isinstance(value, Mapping):
            _fail()
        key_type, value_type = get_args(annotation)
        return {_normalize_arg(k, key_type, depth + 1): _normalize_arg(v, value_type, depth + 1) for k, v in value.items()}
    raise TypeError(f"unsupported input annotation: {annotation!r}")
