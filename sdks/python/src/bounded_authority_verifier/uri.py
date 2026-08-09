"""Bounded HTTPS URI normalization (protocol-v1.md § URI normalization, L201-219; RFC 3986 §6).

No DNS, IDNA, or network work (REQ1-URI-no-network). Both expected and proof URIs MUST already
equal the normal form (REQ1-URI-pre-normalized). Reject-list: HTTP, other scheme, authority-less
form, malformed percent escapes, ambiguous authority/port, control/non-ASCII, out-of-range ports
(REQ1-URI-reject-list).

Normalization: lowercase scheme + host; uppercase percent hex; decode only percent-encoded
unreserved octets; preserve percent-encoded reserved octets as path data; remove complete dot
segments; empty path → "/"; drop port 443; preserve a valid nondefault port + all other path bytes.
"""

from __future__ import annotations

import re

from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve
from .error import Ok, Result, err, fail
from .json_alg import str_utf8, utf8_str

_SCHEME_AUTHORITY_PATH = re.compile(rb"^([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^/?#]*)([^?#]*)$")
_REG_NAME_CHAR = re.compile(rb"[A-Za-z0-9\-._~!$&'()*+,;=]")
_UNRESERVED = re.compile(rb"[A-Za-z0-9\-._~]")
_HEX2 = re.compile(rb"^[0-9A-Fa-f]{2}$")
_IPV4_OCTET = re.compile(rb"^(?:0|[1-9]\d{0,2})$")


def uri_normalize(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    try:
        return Ok(str_utf8(_normalize(data, bounds)))
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def _normalize(data: bytes, bounds: Bounds) -> str:
    if len(data) > bounds_resolve(bounds, "uri_bytes"):
        fail("uri: byte bound")
    # ASCII-only + valid UTF-8 (REQ1-URI-reject-list: control/non-ASCII invalid). bytes in 0x21..0x7E.
    for b in data:
        if b < 0x21 or b > 0x7E:
            fail("uri: ASCII")
    utf8_str(data)
    m = _SCHEME_AUTHORITY_PATH.match(data)
    if m is None:
        fail("uri: hierarchical shape")
    scheme = utf8_str(m.group(1))
    if scheme.lower() != "https":
        fail("uri: scheme")

    authority = m.group(2)
    if len(authority) == 0 or b"@" in authority:
        fail("uri: authority")
    host = b""
    port = b""

    if authority.startswith(b"["):
        close = authority.find(b"]")
        if close <= 1:
            fail("uri: IPv6 host")
        literal = authority[1:close]
        kind = _ipv6_kind(literal)
        if kind is None:
            fail("uri: IP-literal syntax")
        host = b"[" + (literal.lower() if kind == 6 else literal) + b"]"
        suffix = authority[close + 1:]
        if suffix != b"" and not re.match(rb"^:\d+$", suffix):
            fail("uri: IPv6 port")
        port = suffix[1:]
    else:
        colon_count = authority.count(b":")
        if colon_count > 1:
            fail("uri: host/port ambiguity")
        sep = authority.rfind(b":")
        if sep >= 0:
            host = authority[:sep]
            port = authority[sep + 1:]
            if len(port) == 0:
                fail("uri: empty port")
        else:
            host = authority
        if len(host) == 0:
            fail("uri: host")
        if re.match(rb"^[0-9.]+$", host):
            if not _is_canonical_ipv4(host):
                fail("uri: IPv4 syntax")
        else:
            _assert_reg_name(host)
            host = _lowercase_outside_escapes(_normalize_percent_encoding(host))

    if port != b"":
        if not re.match(rb"^\d+$", port):
            fail("uri: port")
        port_number = int(port)
        if port_number < 1 or port_number > 65535:
            fail("uri: port range")
        port = b"" if port_number == 443 else f":{port_number}".encode("ascii")

    path = m.group(3)
    if path == b"":
        path = b"/"
    normalized_path = _remove_dot_segments(_normalize_percent_encoding(path))
    if not normalized_path.startswith(b"/"):
        fail("uri: absolute path")
    return f"https://{host.decode('ascii')}{port.decode('ascii')}{normalized_path.decode('ascii')}"


def _is_canonical_ipv4(host: bytes) -> bool:
    octets = host.split(b".")
    return (
        len(octets) == 4
        and all(_IPV4_OCTET.match(o) is not None and int(o) <= 255 for o in octets)
    )


def _assert_reg_name(host: bytes) -> None:
    i = 0
    n = len(host)
    while i < n:
        ch = host[i:i + 1]
        if _REG_NAME_CHAR.match(ch) is not None:
            i += 1
            continue
        if ch == b"%" and i + 2 < n and _HEX2.match(host[i + 1:i + 3]) is not None:
            i += 3
            continue
        fail("uri: reg-name")


def _normalize_percent_encoding(value: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(value)
    while i < n:
        if value[i] != 0x25:  # %
            out.append(value[i])
            i += 1
            continue
        if i + 2 >= n or _HEX2.match(value[i + 1:i + 3]) is None:
            fail("uri: escape")
        octet = int(value[i + 1:i + 3], 16)
        ch = bytes([octet])
        if _UNRESERVED.match(ch) is not None:
            out.append(octet)
        else:
            out += b"%" + f"{octet:02X}".encode("ascii")
        i += 3
    return bytes(out)


def _lowercase_outside_escapes(value: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(value)
    while i < n:
        if value[i] == 0x25:  # %
            out += value[i:i + 3]
            i += 3
        else:
            out.append(value[i] | 0x20 if 0x41 <= value[i] <= 0x5A else value[i])
            i += 1
    return bytes(out)


# RFC 3986 §6.2.2.3 dot-segment removal (the canonical algorithm).
def _remove_dot_segments(path: bytes) -> bytes:
    inp = path
    out = bytearray()
    while len(inp) > 0:
        if inp.startswith(b"../"):
            inp = inp[3:]
        elif inp.startswith((b"./", b"/./")):
            inp = inp[2:]
        elif inp == b"/.":
            inp = b"/"
        elif inp.startswith(b"/../"):
            inp = inp[3:]
            out = bytearray(re.sub(rb"/?[^/]*$", b"", bytes(out), count=1))
        elif inp == b"/..":
            inp = b"/"
            out = bytearray(re.sub(rb"/?[^/]*$", b"", bytes(out), count=1))
        elif inp == b"." or inp == b"..":
            inp = b""
        else:
            start_at = 1 if inp.startswith(b"/") else 0
            next_slash = inp.find(b"/", start_at)
            end = len(inp) if next_slash == -1 else next_slash
            out += inp[:end]
            inp = inp[end:]
    return bytes(out)


def _ipv6_kind(literal: bytes) -> int | str | None:
    if re.match(rb"^[0-9A-Fa-f:.]+$", literal) is not None:
        return 6
    if re.match(rb"^v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:\-]+$", literal) is not None:
        return "future"
    return None


def _is_invalid(e: BaseException) -> bool:
    from .error import InvalidError

    return isinstance(e, InvalidError)
