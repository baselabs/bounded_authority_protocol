"""Tagged JSON algebra (protocol-v1.md § JSON algebra and decoding, L72-95).

Each JSON value is tagged so the integer/float distinction survives — selector semantic identity
(REQ1-SELECTOR-semantic-identity) and the typed request-digest projection both depend on it::

    Null | Boolean(bool) | Integer(int) | Float(float) | String(utf8) | Array([Value]) | Object([(str, Value)])

Objects retain source member order; duplicate names at any depth reject pre-dict-conversion
(REQ1-JSON-no-duplicate). Input is one complete RFC 8259 value + only whitespace (REQ1-JSON-single-
value). UTF-8 mandatory; no Unicode normalization (REQ1-JSON-no-normalization). Number lexemes are
scanned raw before conversion (64-byte ceiling, exact decimal magnitude) — REQ1-JSON-raw-lexeme.

PERMISSIVENESS CLOSURES (the load-bearing host-runtime discipline):
 - duplicate-reject: hand-rolled recursive scan with a per-object set of seen names. NOT ``json.loads``
   (which silently last-wins duplicates). [REQ1-JSON-no-duplicate]
 - null-prototype / dunder: decoded objects are plain ``dict`` read ONLY by ``dict[key]``
   subscription (never ``getattr``), so a ``__class__`` / ``__proto__`` key is DATA, not an attribute
   collision. [REQ1-SELECTOR-semantic-identity — Python's risk is dunder/attribute collision, NOT
   prototype absorption; the mechanism differs from the TS ``Object.create(null)`` closure]
 - single-value: trailing bytes after the top-level value reject. [REQ1-JSON-single-value]
 - raw-lexeme: numbers scanned before conversion; magnitude + byte ceiling enforced on the lexeme.
   [REQ1-JSON-raw-lexeme]
 - int/float tag: integer vs float distinction preserved (1 ≠ 1.0). [tagged algebra]
"""

from __future__ import annotations

from dataclasses import dataclass

from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .error import fail, invalid_error

MAX_INT = 9007199254740991
MAX_FLOAT = 9007199254740991


@dataclass(frozen=True)
class JNull:
    pass


@dataclass(frozen=True)
class JBool:
    v: bool


@dataclass(frozen=True)
class JInt:
    v: int


@dataclass(frozen=True)
class JFloat:
    v: float


@dataclass(frozen=True)
class JString:
    v: bytes  # the raw UTF-8 bytes of the decoded string


@dataclass(frozen=True)
class JArray:
    v: tuple[Tagged, ...]


@dataclass(frozen=True)
class JObject:
    # Plain dict (NOT a subclass) keyed by the decoded string; insertion order preserved (dict
    # iteration order = insertion order in Python 3.7+). Members are accessed ONLY by dict[key]
    # subscription throughout the SDK — never getattr — so __class__/__proto__ keys are data.
    v: dict[str, Tagged]


Tagged = JNull | JBool | JInt | JFloat | JString | JArray | JObject
"""The tagged JSON value union."""


# Whitespace per RFC 8259 §2.
_WS = b" \t\n\r"


class _Ctx:
    """The mutable decode cursor."""

    __slots__ = ("src", "pos", "bounds", "nodes")

    def __init__(self, src: bytes, bounds: Bounds) -> None:
        self.src = src
        self.pos = 0
        self.bounds = bounds
        self.nodes = 0


def json_decode(src: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Tagged:
    """Decode one complete RFC 8259 value with recursive duplicate rejection + bounds."""
    if len(src) > bounds_resolve(bounds, "json_bytes"):
        fail("json: input exceeds json_bytes bound")
    ctx = _Ctx(src, bounds)
    _skip_ws(ctx)
    value = _parse_value(ctx, 0)
    # REQ1-JSON-single-value: after the value, only JSON whitespace may remain.
    _skip_ws(ctx)
    if ctx.pos != len(src):
        fail("json: trailing bytes")
    if ctx.nodes > bounds_resolve(bounds, "total_nodes"):
        fail("json: total_nodes bound exceeded")
    return value


def _node(ctx: _Ctx) -> None:
    ctx.nodes += 1


def _byte_at(src: bytes, pos: int) -> int:
    """Safe byte access: returns -1 for out-of-bounds."""
    return src[pos] if pos < len(src) else -1


# Per-node-type depth gate (mirrors the official Jcs.encode/Json.decode model): root value at level 0;
# a SCALAR is valid at level <= depth; a CONTAINER is valid at level < depth (its children sit at
# level+1). A uniform `level > depth` gate wrongly accepts a container at the deepest legal scalar
# level.
def _parse_value(ctx: _Ctx, level: int) -> Tagged:
    src = ctx.src
    if ctx.pos >= len(src):
        fail("json: unexpected end of input")
    c = src[ctx.pos]
    if c == 0x22:  # "
        if level > bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_string(ctx)
    if c == 0x7B:  # {
        if level >= bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_object(ctx, level + 1)
    if c == 0x5B:  # [
        if level >= bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_array(ctx, level + 1)
    if c == 0x74 or c == 0x66:  # t / f
        if level > bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_bool(ctx)
    if c == 0x6E:  # n
        if level > bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_null(ctx)
    if c == 0x2D or 0x30 <= c <= 0x39:  # - or digit
        if level > bounds_resolve(ctx.bounds, "depth"):
            fail("json: depth bound")
        return _parse_number(ctx)
    raise invalid_error("json: unexpected byte")


def _parse_null(ctx: _Ctx) -> JNull:
    _node(ctx)
    _expect_lit(ctx, b"null")
    return JNull()


def _parse_bool(ctx: _Ctx) -> Tagged:
    _node(ctx)
    c = ctx.src[ctx.pos]
    if c == 0x74:  # t
        _expect_lit(ctx, b"true")
        return JBool(True)
    _expect_lit(ctx, b"false")
    return JBool(False)


def _expect_lit(ctx: _Ctx, lit: bytes) -> None:
    src = ctx.src
    pos = ctx.pos
    if pos + len(lit) > len(src):
        fail(f"json: expected {lit!r}")  # truncated literal — bounds-check before indexing
    for i, b in enumerate(lit):
        if src[pos + i] != b:
            fail(f"json: expected {lit!r}")
    ctx.pos += len(lit)


def _parse_string(ctx: _Ctx) -> JString:
    _node(ctx)
    start = ctx.pos
    raw = _scan_string(ctx, start)
    # RFC 8259 §2.5 / REQ1-JSON-no-normalization: a JSON string's bytes MUST be valid UTF-8. The
    # scanner copies raw bytes (multi-byte sequences pass through); validate here so an invalid byte
    # (e.g. a lone 0xff) rejects as InvalidError rather than escaping later as a UnicodeDecodeError
    # (which would bypass the closed-error whitelist) or producing a wrong JCS digest.
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("json: string not valid UTF-8")
    if len(raw) > bounds_resolve(ctx.bounds, "string_bytes"):
        fail("json: string_bytes bound")
    return JString(raw)


# Scan a JSON string starting at the opening quote; return the decoded UTF-8 bytes. Validates escapes
# and rejects unpaired surrogates / non-UTF-8 (REQ1-JSON-no-normalization: preserve without normalizing,
# but the bytes must be valid UTF-8).
def _scan_string(ctx: _Ctx, start: int) -> bytes:
    src = ctx.src
    ctx.pos = start + 1  # skip opening quote
    out = bytearray()
    while True:
        if ctx.pos >= len(src):
            fail("json: unterminated string")
        c = src[ctx.pos]
        if c == 0x22:  # "
            ctx.pos += 1
            return bytes(out)
        if c == 0x5C:  # backslash
            if ctx.pos + 1 >= len(src):
                fail("json: bad escape")
            e = src[ctx.pos + 1]
            ctx.pos += 2
            if e == 0x22:
                out.append(0x22)
            elif e == 0x5C:
                out.append(0x5C)
            elif e == 0x2F:
                out.append(0x2F)
            elif e == 0x62:
                out.append(0x08)
            elif e == 0x66:
                out.append(0x0C)
            elif e == 0x6E:
                out.append(0x0A)
            elif e == 0x72:
                out.append(0x0D)
            elif e == 0x74:
                out.append(0x09)
            elif e == 0x75:  # \uXXXX — 4 hex digits; handle surrogate pairs.
                hi = _parse_hex4(ctx)
                if 0xD800 <= hi <= 0xDBFF:
                    # High surrogate; require \uXXXX low surrogate. Bounds-guard the continuation
                    # check — a lone high-surrogate escape at end-of-buffer (b'"\uD800') must fail
                    # closed as InvalidError, not raise IndexError on src[ctx.pos+1]. The TS sibling
                    # is safe (out-of-range Uint8Array access yields undefined); Python raises.
                    if _byte_at(src, ctx.pos) != 0x5C or _byte_at(src, ctx.pos + 1) != 0x75:
                        fail("json: unpaired high surrogate")
                    ctx.pos += 2
                    lo = _parse_hex4(ctx)
                    if not (0xDC00 <= lo <= 0xDFFF):
                        fail("json: bad low surrogate")
                    cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    _encode_utf8(cp, out)
                elif 0xDC00 <= hi <= 0xDFFF:
                    fail("json: unpaired low surrogate")
                else:
                    _encode_utf8(hi, out)
            else:
                fail("json: bad escape")
        elif c < 0x20:
            fail("json: unescaped control byte")
        else:
            # Copy raw byte (UTF-8 multi-byte sequences pass through as-is; validity checked at decode).
            out.append(c)
            ctx.pos += 1


def _parse_hex4(ctx: _Ctx) -> int:
    src = ctx.src
    v = 0
    for _ in range(4):
        if ctx.pos >= len(src):
            fail("json: bad \\u escape")
        c = src[ctx.pos]
        if 0x30 <= c <= 0x39:
            d = c - 0x30
        elif 0x41 <= c <= 0x46:
            d = c - 0x41 + 10
        elif 0x61 <= c <= 0x66:
            d = c - 0x61 + 10
        else:
            fail("json: bad \\u hex")
        v = (v << 4) | d
        ctx.pos += 1
    return v


def _encode_utf8(cp: int, out: bytearray) -> None:
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
        out.append(0xF0 | (cp >> 18))
        out.append(0x80 | ((cp >> 12) & 0x3F))
        out.append(0x80 | ((cp >> 6) & 0x3F))
        out.append(0x80 | (cp & 0x3F))


def _parse_number(ctx: _Ctx) -> Tagged:
    _node(ctx)
    src = ctx.src
    start = ctx.pos
    pos = start
    if _byte_at(src, pos) == 0x2D:  # -
        pos += 1
    # Integer part: 0 or [1-9][0-9]*
    if _byte_at(src, pos) == 0x30:
        pos += 1
    else:
        c = _byte_at(src, pos)
        if 0x31 <= c <= 0x39:
            pos += 1
            d = _byte_at(src, pos)
            while 0x30 <= d <= 0x39:
                pos += 1
                d = _byte_at(src, pos)
        else:
            fail("json: bad number")
    is_float = False
    if _byte_at(src, pos) == 0x2E:  # .
        is_float = True
        pos += 1
        f = _byte_at(src, pos)
        if not (0x30 <= f <= 0x39):
            fail("json: bad fraction")
        fd = _byte_at(src, pos)
        while 0x30 <= fd <= 0x39:
            pos += 1
            fd = _byte_at(src, pos)
    ec = _byte_at(src, pos)
    if ec == 0x65 or ec == 0x45:  # e / E
        is_float = True
        pos += 1
        sign = _byte_at(src, pos)
        if sign == 0x2B or sign == 0x2D:
            pos += 1
        e = _byte_at(src, pos)
        if not (0x30 <= e <= 0x39):
            fail("json: bad exponent")
        ed = _byte_at(src, pos)
        while 0x30 <= ed <= 0x39:
            pos += 1
            ed = _byte_at(src, pos)
    lexeme_end = pos
    lexeme = src[start:lexeme_end]
    # REQ1-JSON-raw-lexeme: 64-byte ceiling on the lexeme.
    if len(lexeme) > bounds_resolve(ctx.bounds, "number_lexeme_bytes"):
        fail("json: number lexeme exceeds bound")
    ctx.pos = lexeme_end
    text = lexeme.decode("ascii")
    if is_float:
        # REQ1-JSON-raw-lexeme: check the magnitude of the RAW lexeme by decimal arithmetic BEFORE
        # float() conversion. A lexeme like "9007199254740991.0001" rounds to the max binary64 value
        # under float(), so a post-conversion abs(n) > MAX check accepts it — defeating the exact
        # bound. The reference (json.ex magnitude_within?) compares the lexeme's significant digits
        # against the maximum's digit string. Mirror that here.
        if not _lexeme_magnitude_within(text, MAX_FLOAT):
            fail("json: float magnitude bound")
        n = float(text)
        # Python floats are always finite here (a non-finite lexeme like "1e400" overflows to inf,
        # which we reject — float_magnitude is the finite bound).
        if _is_inf(n):
            fail("json: float not finite")
        return JFloat(n)
    if not _lexeme_magnitude_within(text, MAX_INT):
        fail("json: integer magnitude bound")
    n_int = int(text)
    return JInt(n_int)


def _lexeme_magnitude_within(text: str, maximum: int) -> bool:
    """Exact decimal magnitude check of a number lexeme against `maximum`, mirroring the reference
    (json.ex:298-349 magnitude_within? / compare_boundary). Returns True if |value| <= maximum.

    Compares the lexeme's significant digits by their effective integer position — NOT the float
    value (which loses precision). Handles sign, fraction, and exponent exactly.
    """
    # Strip a leading sign.
    unsigned = text[1:] if text[:1] in ("-", "+") else text
    # Split into integer digits, fraction digits, exponent (sign already validated by the scanner).
    e_pos = -1
    for marker in ("e", "E"):
        idx = unsigned.find(marker)
        if idx != -1:
            e_pos = idx
            break
    if e_pos != -1:
        mantissa = unsigned[:e_pos]
        exponent = int(unsigned[e_pos + 1:])
    else:
        mantissa = unsigned
        exponent = 0
    if "." in mantissa:
        integer_digits, fraction_digits = mantissa.split(".", 1)
    else:
        integer_digits, fraction_digits = mantissa, ""
    digits = (integer_digits + fraction_digits).lstrip("0")
    if digits == "":
        return True  # value is zero
    maximum_digits = str(maximum)
    # Effective integer-position of the last significant digit (reference's integer_length).
    integer_length = len(digits) + exponent - len(fraction_digits)
    if integer_length < len(maximum_digits):
        return True
    if integer_length > len(maximum_digits):
        return False
    # Same digit-count boundary: compare the leading integer_part (padded/truncated to maximum's
    # length) then require the leftover fractional_part to be all-zero if equal (compare_boundary).
    maximum_length = len(maximum_digits)
    if len(digits) >= maximum_length:
        integer_part = digits[:maximum_length]
        fractional_part = digits[maximum_length:]
    else:
        integer_part = digits + "0" * (maximum_length - len(digits))
        fractional_part = ""
    return integer_part < maximum_digits or (
        integer_part == maximum_digits and (fractional_part == "" or set(fractional_part) <= {"0"})
    )


def _is_inf(x: float) -> bool:
    return x != x or x in (float("inf"), float("-inf"))


# Object parse: plain dict shape; duplicate keys reject at every depth (REQ1-JSON-no-duplicate).
def _parse_object(ctx: _Ctx, child_level: int) -> JObject:
    _node(ctx)
    src = ctx.src
    ctx.pos += 1  # skip {
    members: dict[str, Tagged] = {}
    _skip_ws(ctx)
    if ctx.pos < len(src) and src[ctx.pos] == 0x7D:  # }
        ctx.pos += 1
        return JObject(members)
    count = 0
    while True:
        _skip_ws(ctx)
        if ctx.pos >= len(src) or src[ctx.pos] != 0x22:
            fail("json: expected member name")
        name_bytes = _scan_string(ctx, ctx.pos)
        if len(name_bytes) > bounds_resolve(ctx.bounds, "key_bytes"):
            fail("json: key_bytes bound")
        # A member name's bytes MUST be valid UTF-8 (RFC 8259 §2.5 / REQ1-JSON-no-normalization).
        # Validate before decode so a lone 0xff in a name fails closed as InvalidError rather than
        # raising UnicodeDecodeError past the closed-error whitelist (matches _parse_string above).
        try:
            name_str = name_bytes.decode("utf-8")
        except UnicodeDecodeError:
            fail("json: member name not valid UTF-8")
        # REQ1-JSON-no-duplicate: reject before dict insertion.
        if name_str in members:
            fail("json: duplicate member")
        _skip_ws(ctx)
        if ctx.pos >= len(src) or src[ctx.pos] != 0x3A:
            fail("json: expected colon")
        ctx.pos += 1
        _skip_ws(ctx)
        value = _parse_value(ctx, child_level)
        members[name_str] = value
        count += 1
        if count > bounds_resolve(ctx.bounds, "object_members"):
            fail("json: object_members bound")
        _skip_ws(ctx)
        sep = src[ctx.pos] if ctx.pos < len(src) else -1
        if sep == 0x2C:  # ,
            ctx.pos += 1
            continue
        if sep == 0x7D:  # }
            ctx.pos += 1
            break
        fail("json: expected , or }")
    return JObject(members)


def _parse_array(ctx: _Ctx, child_level: int) -> JArray:
    _node(ctx)
    src = ctx.src
    ctx.pos += 1  # skip [
    items: list[Tagged] = []
    _skip_ws(ctx)
    if ctx.pos < len(src) and src[ctx.pos] == 0x5D:  # ]
        ctx.pos += 1
        return JArray(tuple(items))
    while True:
        _skip_ws(ctx)
        value = _parse_value(ctx, child_level)
        items.append(value)
        if len(items) > bounds_resolve(ctx.bounds, "array_items"):
            fail("json: array_items bound")
        _skip_ws(ctx)
        sep = src[ctx.pos] if ctx.pos < len(src) else -1
        if sep == 0x2C:  # ,
            ctx.pos += 1
            continue
        if sep == 0x5D:  # ]
            ctx.pos += 1
            break
        fail("json: expected , or ]")
    return JArray(tuple(items))


def _skip_ws(ctx: _Ctx) -> None:
    src = ctx.src
    while ctx.pos < len(src) and src[ctx.pos] in _WS:
        ctx.pos += 1


# --- UTF-8 <-> str helpers (pure transformations; no I/O) ---


def utf8_str(b: bytes) -> str:
    """Decode UTF-8 bytes to str. Raises on invalid UTF-8 (mirrors the TS fatal TextDecoder)."""
    return b.decode("utf-8")


def is_valid_utf8(b: bytes) -> bool:
    """Return True iff ``b`` is valid UTF-8 (no throw).

    Cross-vendor (JCS UTF-8): the reference's ``String.valid?`` (jcs.ex:58) rejects invalid UTF-8 at
    encode. ``utf8_str`` raises ``UnicodeDecodeError`` on invalid bytes, escaping the closed-Result
    contract; this non-throwing gate lets ``jcs_encode`` fail closed instead.
    """
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def str_utf8(s: str) -> bytes:
    """Encode a str to UTF-8 bytes."""
    return s.encode("utf-8")
