"""Specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering), including shared container and printable limits."""
from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from itertools import islice
from typing import TypeGuard, cast


@dataclass(frozen=True)
class Term:
    kind: str
    text: str = ""
    raw: bytes = b""
    children: Iterable[Term] = ()
    more: bool = False
    value: object = None


def atom(value: object) -> Term:
    if not issubclass(type(value), str) or re.fullmatch(r"[a-z_][a-zA-Z0-9_]*[?!]?", cast(str, value)) is None:
        return Term("unrenderable")
    return Term("atom", str.__str__(cast(str, value)))


def scalar(value: object) -> Term:
    if type(value) not in (int, float):
        return native(value)
    if isinstance(value, float) and not math.isfinite(value):
        return Term("unrenderable")
    if isinstance(value, int):
        # Convert bounded decimal chunks without the host's integer-string ceiling.
        number = abs(value)
        chunks = []
        while number:
            number, chunk = divmod(number, 1_000_000_000)
            chunks.append(chunk)
        digits = str(chunks[-1]) + "".join(f"{c:09d}" for c in reversed(chunks[:-1])) if chunks else "0"
        return Term("scalar", ("-" if value < 0 else "") + digits)
    if value == 0.0:
        return Term("scalar", repr(value))
    value = cast(float, value)
    # Scalar rendering: shortest digits, then choose the prescribed notation.
    coefficient, _, exponent_text = repr(abs(value)).partition("e")
    exponent = int(exponent_text or "0")
    whole, _, fraction = coefficient.partition(".")
    digits = whole + fraction
    point = len(whole) + exponent
    point -= len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0").rstrip("0")
    scientific = digits[0] + "." + (digits[1:] or "0") + "e" + str(point - 1)
    if point <= 0:
        fixed = "0." + "0" * -point + digits
    elif point >= len(digits):
        fixed = digits + "0" * (point - len(digits)) + ".0"
    else:
        fixed = digits[:point] + "." + digits[point:]
    notation = fixed if abs(value) < 2**53 and len(fixed) <= len(scientific) else scientific
    return Term("scalar", ("-" if value < 0 else "") + notation)


def text(value: object) -> Term:
    if not issubclass(type(value), str):
        return native(value)
    value = cast(str, value)
    # At most two source scalars per escaping unit; four bytes per scalar.
    prefix = str.__getitem__(value, slice(None, 8192)).encode("utf-8", errors="surrogatepass")
    return Term("binary", raw=prefix[:16384], more=str.__len__(value) > 8192 or len(prefix) > 16384)


def raw(value: object) -> Term:
    if not issubclass(type(value), bytes):
        return native(value)
    value = cast(bytes, value)
    return Term("binary", raw=bytes.__getitem__(value, slice(None, 16384)), more=bytes.__len__(value) > 16384)


@dataclass(frozen=True)
class _Mapped:
    values: Iterable[object]
    convert: Callable[[object], Term]

    def __iter__(self) -> Iterator[Term]:
        if _sequence(self.values):
            return map(self.convert, _sequence_items(self.values))
        return map(self.convert, self.values)


def listing(values: Iterable[Term]) -> Term:
    return Term("list", children=values)


def _sequence(value: object) -> TypeGuard[tuple[object, ...] | list[object]]:
    return issubclass(type(value), (tuple, list))


def _sequence_items(value: tuple[object, ...] | list[object]) -> Iterator[object]:
    if issubclass(type(value), tuple):
        return tuple.__iter__(cast(tuple[object, ...], value))
    return list.__iter__(cast(list[object], value))


def mapped_listing(values: object, convert: Callable[[object], Term]) -> Term:
    if not _sequence(values):
        return native(values)
    return listing(_Mapped(values, convert))


def native(value: object) -> Term:
    if value is None:
        return atom("nil")
    if type(value) is bool:
        return atom("true" if value else "false")
    if issubclass(type(value), int):
        return scalar(int.__int__(cast(int, value)))
    if issubclass(type(value), float):
        return scalar(float.__float__(cast(float, value)))
    if issubclass(type(value), str):
        return text(value)
    if issubclass(type(value), bytes):
        return raw(value)
    if issubclass(type(value), tuple):
        return Term("tuple", children=_Mapped(cast(tuple[object, ...], value), native))
    if _sequence(value):
        return mapped_listing(value, native)
    return Term("unrenderable")


def tupled(*values: Term) -> Term:
    return Term("tuple", children=values)


def structure(name: str, fields: list[tuple[str, Term]]) -> Term:
    return Term("struct", name, children=tuple(tupled(atom(k), v) for k, v in fields))


def _quoted(value: bytes, more: bool = False) -> str | None:
    # Surrogate escapes retain each invalid byte for prefix scanning and suffix escaping.
    decoded = value.decode("utf-8", errors="surrogateescape")
    if not all((32 <= ord(c) <= 127 or 160 <= ord(c) <= 55295 or 57344 <= ord(c) <= 65533 or 65536 <= ord(c) <= 1114111) or c in "\a\b\t\n\v\f\r\x1b" for c in decoded[:4096]):
        return None
    escapes = {"\a": r"\a", "\b": r"\b", "\t": r"\t", "\n": r"\n", "\v": r"\v", "\f": r"\f", "\r": r"\r", "\x1b": r"\e", "\x7f": r"\d", "\0": r"\0", '"': r'\"', "\\": r"\\"}
    invisible = {0xFEFF, 0x061C, 0x200E, 0x200F, 0x200C, 0x200D, 0x034F, 0x00A0, 0x200B, 0x2060, 0x2028, 0x2029, 0x205F, *range(0x2061, 0x2065), *range(0x202A, 0x202F), *range(0x2066, 0x206A), *range(0xFFF9, 0xFFFD), *range(0x2000, 0x200B)}
    # The specified diagnostic rendering counts interpolation as one printable-limit unit
    # (spec/diagnostic-rendering.md § Diagnostic rendering; decoded-binary-rendering.json).
    pieces: list[str] = []
    i = 0
    for _ in range(4096):
        if i == len(decoded):
            break
        c = decoded[i]
        i += 1
        if c == "#" and decoded[i:i + 1] == "{":
            pieces.append(r"\#{")
            i += 1
        else:
            codepoint = ord(c)
            if c in escapes:
                pieces.append(escapes[c])
            elif codepoint in invisible:
                pieces.append(f"\\u{codepoint:04X}")
            elif codepoint < 32 or 128 <= codepoint < 160:
                pieces.append(f"\\x{codepoint:02X}")
            elif codepoint in (0xFFFE, 0xFFFF):
                pieces.append(f"\\x{{{codepoint:04X}}}")
            elif 0xDC80 <= codepoint <= 0xDCFF:
                pieces.append(f"\\x{codepoint - 0xDC00:02X}")
            else:
                pieces.append(c)
    return '"' + "".join(pieces) + '"' + (" <> ..." if more or i < len(decoded) else "")


def render(term: Term) -> str:
    remaining = 200

    def container(values: Iterable[Term], left: str, right: str, keyword: bool = False) -> str:
        nonlocal remaining
        parts = []
        for value in values:
            if remaining <= 0:
                parts.append("...")
                break
            remaining -= 1
            if keyword:
                parts.append(pair(value)[0].text + ": " + walk(pair(value)[1]))
            else:
                parts.append(walk(value))
        return left + ", ".join(parts) + right

    def resolve(value: Term) -> Term:
        return _tagged(value.value) if value.kind == "tagged" else value

    def pair(value: Term) -> tuple[Term, ...]:
        return tuple(islice(resolve(value).children, 3))

    def keyword_entry(value: Term) -> bool:
        if value.kind == "tagged":
            from .json_alg import JArray, JBool, JFloat, JInt, JObject, JString
            item = value.value
            if type(item) in (JBool, JFloat, JInt, JString):
                return True
            if type(item) is JArray:
                return _sequence(item.v)
            return type(item) is JObject and issubclass(type(item.v), dict)
        return value.kind == "tuple" and len(pair(value)) == 2 and pair(value)[0].kind == "atom"

    def walk(value: Term) -> str:
        nonlocal remaining
        value = resolve(value)
        if value.kind == "unrenderable":
            return "#unrenderable"
        if value.kind == "atom":
            return ("" if value.text in ("true", "false", "nil") else ":") + value.text
        if value.kind == "scalar":
            return value.text
        if value.kind == "binary":
            quoted = _quoted(value.raw, value.more)
            if quoted is not None:
                return quoted
            count = min(len(value.raw), max(0, remaining))
            parts = [str(b) for b in value.raw[:count]]
            # A nonempty binary with a zero budget prints an ellipsis.
            if value.more or len(value.raw) > count:
                parts.append("...")
            remaining = max(0, remaining - len(value.raw))
            return "<<" + ", ".join(parts) + ">>"
        if value.kind == "struct":
            return container(value.children, "%" + value.text + "{", "}", True)
        if value.kind == "tuple":
            return container(value.children, "{", "}")
        keyword = all(keyword_entry(c) for c in value.children)
        return container(value.children, "[", "]", keyword)

    return walk(term)


def binary(value: bytes) -> str:
    return render(raw(value))


def string(value: str) -> str:
    return render(text(value))


def tagged(value: object) -> Term:
    return Term("tagged", value=value)


def _tagged(value: object) -> Term:
    from .json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString
    if type(value) is JNull:
        return atom("null")
    if type(value) is JBool:
        return tupled(atom("boolean"), native(value.v))
    if type(value) is JInt:
        return tupled(atom("integer"), scalar(value.v))
    if type(value) is JFloat:
        return tupled(atom("float"), scalar(value.v))
    if type(value) is JString:
        return tupled(atom("string"), raw(value.v))
    if type(value) is JArray and _sequence(value.v):
        return tupled(atom("array"), mapped_listing(value.v, tagged))
    if type(value) is JObject and issubclass(type(value.v), dict):
        return tupled(atom("object"), listing(_Mapped(dict.items(value.v), _member_pair)))
    return Term("unrenderable")


def _member_pair(value: object) -> Term:
    if type(value) is not tuple or len(value) != 2:
        return Term("unrenderable")
    return tupled(text(value[0]), tagged(value[1]))


def selector(value: object) -> Term:
    from .json_alg import JArray, JObject, JString
    if type(value) is not JObject or not issubclass(type(value.v), dict):
        return Term("unrenderable")
    if not all(type(key) is str for key in dict.keys(value.v)):
        return Term("unrenderable")
    kind_value = dict.get(value.v, "kind")
    if type(kind_value) is not JString or not issubclass(type(kind_value.v), bytes):
        return Term("unrenderable")
    kind = bytes.decode(kind_value.v, "utf-8", errors="surrogateescape")
    if kind == "all":
        return atom("all")
    path = dict.get(value.v, "path")
    if type(path) is not JArray or not _sequence(path.v) or not all(type(v) is JString and issubclass(type(v.v), bytes) for v in _sequence_items(path.v)):
        return Term("unrenderable")
    names = mapped_listing(path.v, _path_name)
    if kind == "one_of":
        members = dict.get(value.v, "values")
        if type(members) is not JArray or not _sequence(members.v):
            return Term("unrenderable")
        operand = mapped_listing(members.v, tagged)
    else:
        if not dict.__contains__(value.v, "value"):
            return Term("unrenderable")
        operand = tagged(dict.__getitem__(value.v, "value"))
    return tupled(atom(kind), names, operand)


def _path_name(value: object) -> Term:
    from .json_alg import JString
    return raw(value.v) if type(value) is JString else Term("unrenderable")


def _ordinary(value: object) -> Term:
    from .json_alg import JArray, JBool, JFloat, JInt, JNull, JString
    if type(value) is JNull:
        return atom("nil")
    if type(value) is JBool:
        return native(value.v)
    if type(value) is JFloat or type(value) is JInt:
        return scalar(value.v)
    if type(value) is JString:
        return raw(value.v)
    if type(value) is JArray and _sequence(value.v):
        return mapped_listing(value.v, _ordinary)
    return Term("unrenderable")


def operations(values: object, version: int) -> Term:
    from .json_alg import JArray, JObject

    def operation(value: object) -> Term:
        if type(value) is not JObject or not issubclass(type(value.v), dict) or not all(type(key) is str for key in dict.keys(value.v)) or not {"name", "selectors"} <= dict.keys(value.v):
            return Term("unrenderable")
        selectors = dict.__getitem__(value.v, "selectors")
        selected = mapped_listing(selectors.v, selector) if type(selectors) is JArray and _sequence(selectors.v) else _ordinary(selectors)
        return structure(f"BoundedAuthorityProtocol.V{version}.Operation", [
            ("name", _ordinary(dict.__getitem__(value.v, "name"))), ("selectors", selected),
        ])

    return mapped_listing(values, operation)
