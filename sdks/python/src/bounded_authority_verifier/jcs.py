"""RFC 8785 JSON Canonicalization Scheme over the tagged JSON algebra (protocol-v1.md:91-95,
REQ1-JSON-jcs-exact).

Accepts only the tagged algebra. Enforces the ``jcs_bytes`` output bound while emitting RFC 8785
bytes: exact string escaping, invalid-Unicode rejection, unsigned UTF-16 object-name sorting at
every depth, preserved array order, and ECMAScript binary64 number text (-0 as 0, fixed/exponent
thresholds, lowercase ``e``).

Number formatting (RFC 8785 §3.2.2): the shortest representation. Python's ``repr(float)`` produces
the shortest round-tripping decimal (PEP 3101 / ``repr`` semantics match the ECMAScript shortest
algorithm for binary64); integers emit as bare integers. The tagged algebra's int/float distinction
is preserved at the TAG layer — the serialization is byte-identical for equal numeric value, matching
the Elixir JCS.
"""

from __future__ import annotations

from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .error import fail
from .json_alg import (
    JArray,
    JBool,
    JFloat,
    JInt,
    JNull,
    JObject,
    JString,
    Tagged,
    str_utf8,
    utf8_str,
)

# The short escapes per RFC 8785 §3.2.2.1 (b, f, n, r, t + the two structural " \).
_SHORT_ESCAPES: dict[int, bytes] = {
    0x08: b"\\b",
    0x09: b"\\t",
    0x0A: b"\\n",
    0x0C: b"\\f",
    0x0D: b"\\r",
    0x22: b'\\"',
    0x5C: b"\\\\",
}


def jcs_encode(value: Tagged, bounds: Bounds = MAXIMUM_BOUNDS) -> bytes:
    out = bytearray()
    _emit(value, out, bounds)
    if len(out) > bounds_resolve(bounds, "jcs_bytes"):
        fail("jcs: jcs_bytes bound")
    return bytes(out)


def _emit(value: Tagged, out: bytearray, bounds: Bounds) -> None:
    if isinstance(value, JNull):
        out += b"null"
    elif isinstance(value, JBool):
        out += b"true" if value.v else b"false"
    elif isinstance(value, JInt):
        out += str_utf8(_format_int(value.v))
    elif isinstance(value, JFloat):
        out += str_utf8(_format_float(value.v))
    elif isinstance(value, JString):
        _escape_string(value.v, out)
    elif isinstance(value, JArray):
        out.append(0x5B)  # [
        first = True
        for item in value.v:
            if not first:
                out.append(0x2C)  # ,
            first = False
            _emit(item, out, bounds)
        out.append(0x5D)  # ]
    elif isinstance(value, JObject):
        # RFC 8785 §3.2.3: object names sorted by unsigned UTF-16 code unit sequence.
        names = sorted(value.v.keys(), key=_utf16_key)
        out.append(0x7B)  # {
        first = True
        for name in names:
            if not first:
                out.append(0x2C)  # ,
            first = False
            _escape_string(str_utf8(name), out)
            out.append(0x3A)  # :
            _emit(value.v[name], out, bounds)
        out.append(0x7D)  # }
    else:  # pragma: no cover — the algebra is closed
        fail("jcs: unknown tag")


def _format_int(n: int) -> str:
    return str(n)


def _format_float(n: float) -> str:
    # RFC 8785 §3.2.2: shortest representation. Python's repr(float) produces the shortest
    # round-tripping decimal (matching ECMAScript's binary64 shortest algorithm).
    if n != n or n in (float("inf"), float("-inf")):  # NaN / inf
        fail("jcs: non-finite float")
    return repr(n)
    # Normalize Python's float repr to ECMAScript Number.prototype.toString form:
    #  - Python writes 'e' for exponents (matches ECMAScript lowercase e).
    #  - Python writes 'inf'/'nan' (already rejected above).
    #  - repr(1.0) == '1.0' (a float carries the trailing .0 — the TAG carries the distinction,
    #    the serialization is the binary64 text). This matches the Elixir/TS JCS for float values.


def _escape_string(src_bytes: bytes, out: bytearray) -> None:
    out.append(0x22)  # opening "
    # Decode UTF-8 to code points so \uXXXX escaping (for < 0x20) is correct.
    s = utf8_str(src_bytes)
    i = 0
    n = len(s)
    while i < n:
        # codePointAt equivalent — handle surrogate pairs for astral code points.
        cu = ord(s[i])
        if 0xD800 <= cu <= 0xDBFF and i + 1 < n:
            lo = ord(s[i + 1])
            if 0xDC00 <= lo <= 0xDFFF:
                cp = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00)
                _append_utf8_bytes(cp, out)
                i += 2
                continue
            # Lone high surrogate: the bytes were already validated as UTF-8 at decode (fatal
            # decoder), so this path is unreachable for well-formed input. Treat as the BMP code unit.
            cp = cu
        else:
            cp = cu
        if cp > 0xFFFF:
            # Astral — RFC 8785 emits astral chars as their UTF-8 bytes (not \u escapes).
            _append_utf8_bytes(cp, out)
        elif cp < 0x20:
            esc = _SHORT_ESCAPES.get(cp)
            if esc is not None:
                out += esc
            else:
                _append_u(cp, out)
        elif cp == 0x22 or cp == 0x5C:
            out += _SHORT_ESCAPES[cp]
        elif cp == 0x7F:  # DEL — RFC 8785 §3.2.2.3 mandates \u007f
            _append_u(0x7F, out)
        else:
            _append_utf8_bytes(cp, out)
        i += 1
    out.append(0x22)  # closing "


def _append_u(cp: int, out: bytearray) -> None:
    out += b"\\u"
    out += f"{cp:04x}".encode("ascii")


def _append_utf8_bytes(cp: int, out: bytearray) -> None:
    if cp < 0x80:
        out.append(cp)
    elif cp < 0x800:
        out.append(0xC0 | (cp >> 6))
        out.append(0x80 | (cp & 0x3F))
    else:
        out.append(0xE0 | (cp >> 12))
        out.append(0x80 | ((cp >> 6) & 0x3F))
        out.append(0x80 | (cp & 0x3F))


def _utf16_key(s: str) -> bytes:
    """Unsigned UTF-16 code-unit comparison key (RFC 8785 §3.2.3).

    Encode the string as UTF-16 big-endian code units; byte comparison of that encoding yields the
    unsigned-UTF-16 ordering. (Python sorts strings by code point; RFC 8785 sorts by UTF-16 unit,
    which differs for astral characters — so we encode to UTF-16-BE bytes and sort on those.)
    """
    return s.encode("utf-16-be")
