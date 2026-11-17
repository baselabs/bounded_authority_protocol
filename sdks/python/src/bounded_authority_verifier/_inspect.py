"""Specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering), including shared container and printable limits."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Term:
    kind: str
    text: str = ""
    raw: bytes = b""
    children: tuple[Term, ...] = ()


def atom(value: str) -> Term:
    return Term("atom", value)


def scalar(value: int | float) -> Term:
    text = repr(value)
    if isinstance(value, float) and "e" in text:
        coefficient, exponent = text.split("e")
        text = (
            (coefficient if "." in coefficient else coefficient + ".0") + "e" + str(int(exponent))
        )
    return Term("scalar", text)


def text(value: str) -> Term:
    return Term("binary", raw=value.encode("utf-8"))


def raw(value: bytes) -> Term:
    return Term("binary", raw=value)


def listing(values: list[Term] | tuple[Term, ...]) -> Term:
    return Term("list", children=tuple(values))


def tupled(*values: Term) -> Term:
    return Term("tuple", children=values)


def structure(name: str, fields: list[tuple[str, Term]]) -> Term:
    return Term("struct", name, children=tuple(tupled(atom(k), v) for k, v in fields))


def _quoted(value: bytes) -> str | None:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not all(
        (
            32 <= ord(c) <= 126
            or 160 <= ord(c) <= 55295
            or 57344 <= ord(c) <= 65533
            or 65536 <= ord(c) <= 1114111
        )
        or c in "\a\b\t\n\v\f\r\x1b"
        for c in decoded[:4096]
    ):
        return None
    escapes = {
        "\a": r"\a",
        "\b": r"\b",
        "\t": r"\t",
        "\n": r"\n",
        "\v": r"\v",
        "\f": r"\f",
        "\r": r"\r",
        "\x1b": r"\e",
        '"': r"\"",
        "\\": r"\\",
    }
    invisible = {
        0xFEFF,
        0x061C,
        0x200E,
        0x200F,
        0x200C,
        0x200D,
        0x034F,
        0x00A0,
        0x200B,
        0x2060,
        0x2028,
        0x2029,
        0x205F,
        *range(0x2061, 0x2065),
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
        *range(0xFFF9, 0xFFFD),
        *range(0x2000, 0x200B),
    }
    # The specified diagnostic rendering counts interpolation as one printable-limit unit
    # (spec/diagnostic-rendering.md § Diagnostic rendering; decoded-binary-rendering.json).
    pieces: list[str] = []
    i = 0
    for _ in range(4096):
        if i == len(decoded):
            break
        c = decoded[i]
        i += 1
        if c == "#" and decoded[i : i + 1] == "{":
            pieces.append(r"\#{")
            i += 1
        else:
            pieces.append(escapes.get(c, f"\\u{ord(c):04X}" if ord(c) in invisible else c))
    return '"' + "".join(pieces) + '"' + (" <> ..." if i < len(decoded) else "")


def render(term: Term) -> str:
    remaining = 200

    def container(values: tuple[Term, ...], left: str, right: str, keyword: bool = False) -> str:
        nonlocal remaining
        parts = []
        for value in values:
            if remaining <= 0:
                parts.append("...")
                break
            remaining -= 1
            if keyword:
                parts.append(value.children[0].text + ": " + walk(value.children[1]))
            else:
                parts.append(walk(value))
        return left + ", ".join(parts) + right

    def walk(value: Term) -> str:
        nonlocal remaining
        if value.kind == "atom":
            return ("" if value.text in ("true", "false", "nil") else ":") + value.text
        if value.kind == "scalar":
            return value.text
        if value.kind == "binary":
            quoted = _quoted(value.raw)
            if quoted is not None:
                return quoted
            count = min(len(value.raw), max(0, remaining))
            parts = [str(b) for b in value.raw[:count]]
            # A nonempty binary with a zero budget prints an ellipsis.
            if len(value.raw) > count:
                parts.append("...")
            remaining = max(0, remaining - len(value.raw))
            return "<<" + ", ".join(parts) + ">>"
        if value.kind == "struct":
            return container(value.children, "%" + value.text + "{", "}", True)
        if value.kind == "tuple":
            return container(value.children, "{", "}")
        keyword = bool(value.children) and all(
            c.kind == "tuple" and len(c.children) == 2 and c.children[0].kind == "atom"
            for c in value.children
        )
        return container(value.children, "[", "]", keyword)

    return walk(term)


def binary(value: bytes) -> str:
    return render(raw(value))


def string(value: str) -> str:
    return render(text(value))


def tagged(value: object) -> Term:
    from .json_alg import JArray, JBool, JFloat, JInt, JNull, JObject, JString

    if isinstance(value, JNull):
        return atom("null")
    if isinstance(value, JBool):
        return tupled(atom("boolean"), atom("true" if value.v else "false"))
    if isinstance(value, JInt):
        return tupled(atom("integer"), scalar(value.v))
    if isinstance(value, JFloat):
        return tupled(atom("float"), scalar(value.v))
    if isinstance(value, JString):
        return tupled(atom("string"), raw(value.v))
    if isinstance(value, JArray):
        return tupled(atom("array"), listing([tagged(v) for v in value.v]))
    if isinstance(value, JObject):
        return tupled(
            atom("object"), listing([tupled(text(k), tagged(v)) for k, v in value.v.items()])
        )
    raise TypeError("unsupported decoded algebra")


def selector(value: object) -> Term:
    from .json_alg import JArray, JObject, JString

    if not isinstance(value, JObject) or not isinstance(value.v["kind"], JString):
        raise TypeError("unsupported decoded selector")
    kind = value.v["kind"].v.decode()
    if kind == "all":
        return atom("all")
    path = value.v["path"]
    assert isinstance(path, JArray)
    names = listing([raw(v.v) for v in path.v if isinstance(v, JString)])
    if kind == "one_of":
        members = value.v["values"]
        assert isinstance(members, JArray)
        operand = listing([tagged(v) for v in members.v])
    else:
        operand = tagged(value.v["value"])
    return tupled(atom(kind), names, operand)
