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
    # RFC 8785 §3.2.2: the ECMAScript Number.prototype.toString serialization (shortest
    # round-tripping decimal, fixed-vs-exponent thresholds, lowercase unpadded exponent). Python's
    # repr() gives the shortest digits BUT diverges on formatting (repr(1.0)=="1.0", repr(1e-7)==
    # "1e-07", repr(1e16)=="1e+16"). We port the Elixir reference's ecmascript_number/1 algorithm
    # (jcs.ex:151-204): take repr's shortest digits, then re-format to the ECMAScript fixed/scientific
    # thresholds. Without this, a Python verifier computes a different request digest (ba_req) than an
    # Elixir/TS signer for ANY float-valued cast_argument — a cross-implementation divergence the
    # corpus cannot express (its digest cases use integer-only arguments).
    if n != n or n in (float("inf"), float("-inf")):  # NaN / inf
        fail("jcs: non-finite float")
    if n == 0.0:
        # Covers +0.0 and -0.0 (RFC 8785: -0 === 0, emits "0"; the sign is dropped).
        return "0"
    sign = "-" if n < 0.0 else ""
    magnitude = -n if n < 0.0 else n
    # repr gives the shortest round-tripping decimal (matches :erlang.float_to_binary [:short]).
    raw = repr(magnitude)
    mantissa, exponent = _split_exponent(raw)
    digits, decimal_index = _decimal_digits(mantissa, exponent)
    digits = _trim_trailing_zeroes(digits)
    scientific_exponent = decimal_index - 1
    if scientific_exponent < -6 or scientific_exponent >= 21:
        body = _scientific(digits, scientific_exponent)
    else:
        body = _fixed(digits, decimal_index)
    return sign + body


def _split_exponent(raw: str) -> tuple[str, int]:
    # repr may use 'e' (1e-07) or 'E'; split off the exponent.
    if "e" in raw:
        m, e = raw.split("e", 1)
        return m, int(e)
    if "E" in raw:
        m, e = raw.split("E", 1)
        return m, int(e)
    return raw, 0


def _decimal_digits(mantissa: str, exponent: int) -> tuple[str, int]:
    # Combine integer + fraction parts; decimal_index = len(integer_part) + exponent.
    if "." in mantissa:
        integer, fraction = mantissa.split(".", 1)
    else:
        integer, fraction = mantissa, ""
    return integer + fraction, len(integer) + exponent


def _trim_trailing_zeroes(digits: str) -> str:
    if len(digits) == 0:
        return digits
    while len(digits) > 1 and digits[-1] == "0":
        digits = digits[:-1]
    return digits


def _scientific(digits: str, exponent: int) -> str:
    first = digits[0]
    rest = digits[1:]
    mantissa = first if rest == "" else f"{first}.{rest}"
    sign = "+" if exponent >= 0 else ""
    return f"{mantissa}e{sign}{exponent}"


def _fixed(digits: str, decimal_index: int) -> str:
    if decimal_index <= 0:
        return "0." + "0" * (-decimal_index) + digits
    if decimal_index >= len(digits):
        return digits + "0" * (decimal_index - len(digits))
    return digits[:decimal_index] + "." + digits[decimal_index:]


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
        elif cp == 0x7F:
            # DEL: RFC 8785 §3.2.2.3 mandates \u007f, BUT the Elixir reference (the contract per
            # AGENTS rule 7 — canonical bytes are the contract) emits RAW 0x7f here (jcs.ex:147 has
            # no DEL case, so the general codepoint branch passes it through raw). Matching the
            # reference bytes is required for identical signed inputs and request digests; the SDK
            # MUST NOT diverge to the RFC's escaped form. Verified: Jcs.encode("x<DEL>y") -> raw 0x7f.
            out.append(0x7F)
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
    elif cp < 0x10000:
        out.append(0xE0 | (cp >> 12))
        out.append(0x80 | ((cp >> 6) & 0x3F))
        out.append(0x80 | (cp & 0x3F))
    else:
        # Astral code points (cp >= 0x10000) — 4-byte UTF-8 (RFC 8785 keeps astral chars as their
        # UTF-8 bytes, not \u escapes). The prior 3-byte-cap branch here produced a malformed
        # sequence for astral chars; this is the 4-byte form.
        out.append(0xF0 | (cp >> 18))
        out.append(0x80 | ((cp >> 12) & 0x3F))
        out.append(0x80 | ((cp >> 6) & 0x3F))
        out.append(0x80 | (cp & 0x3F))


def _utf16_key(s: str) -> bytes:
    """Unsigned UTF-16 code-unit comparison key (RFC 8785 §3.2.3).

    Encode the string as UTF-16 big-endian code units; byte comparison of that encoding yields the
    unsigned-UTF-16 ordering. (Python sorts strings by code point; RFC 8785 sorts by UTF-16 unit,
    which differs for astral characters — so we encode to UTF-16-BE bytes and sort on those.)
    """
    return s.encode("utf-16-be")
