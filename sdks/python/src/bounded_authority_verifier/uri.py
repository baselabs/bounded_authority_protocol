"""Bounded HTTPS URI normalization (spec/bap-v1.md § URI normalization, L201-219; RFC 3986 §6).

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

from .bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from .error import Ok, Result, err, fail
from .json_alg import str_utf8, utf8_str

_SCHEME_AUTHORITY_PATH = re.compile(rb"^([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^/?#]*)([^?#]*)$")
_REG_NAME_CHAR = re.compile(rb"[A-Za-z0-9\-._~!$&'()*+,;=]")
_UNRESERVED = re.compile(rb"[A-Za-z0-9\-._~]")
_PATH_CHAR = re.compile(rb"[A-Za-z0-9\-._~!$&'()*+,;=:@/]")
_HEX2 = re.compile(rb"^[0-9A-Fa-f]{2}$")
_IPV4_OCTET = re.compile(rb"^(?:0|[1-9]\d{0,2})$")


def uri_normalize(data: bytes, bounds: Bounds = MAXIMUM_BOUNDS) -> Result[bytes]:
    try:
        return Ok(str_utf8(_normalize(data, coerce_bounds(bounds))))
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def local_loopback_http_uri_normalize(
    data: bytes, bounds: Bounds = MAXIMUM_BOUNDS
) -> Result[bytes]:
    try:
        return Ok(str_utf8(_normalize_local_loopback_http(data, coerce_bounds(bounds))))
    except Exception as e:
        if _is_invalid(e):
            return err()
        raise


def _normalize_local_loopback_http(data: bytes, bounds: Bounds) -> str:
    if len(data) > bounds_resolve(bounds, "uri_bytes"):
        fail("uri: byte bound")
    for byte in data:
        if byte < 0x21 or byte > 0x7E:
            fail("uri: ASCII")
    utf8_str(data)
    match = _SCHEME_AUTHORITY_PATH.match(data)
    if match is None or match.group(1).lower() != b"http":
        fail("uri: scheme")

    authority_match = re.match(rb"^(127\.0\.0\.1|\[::1\])(?::([0-9]+))?$", match.group(2))
    if authority_match is None:
        fail("uri: loopback authority")

    host = authority_match.group(1)
    port = b""
    raw_port = authority_match.group(2)
    if raw_port is not None:
        significant = raw_port.lstrip(b"0")
        if len(significant) == 0 or len(significant) > 5:
            fail("uri: port")
        port_number = int(significant)
        if port_number < 1 or port_number > 65535:
            fail("uri: port")
        if port_number != 80:
            port = f":{port_number}".encode("ascii")

    normalized = b"http://" + host + port + _normalize_path(match.group(3), enforce_pchar=True)
    if len(normalized) > bounds_resolve(bounds, "uri_bytes"):
        fail("uri: byte bound")
    return utf8_str(normalized)


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
        suffix = authority[close + 1 :]
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
            port = authority[sep + 1 :]
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

    normalized_path = _normalize_path(m.group(3))
    return f"https://{host.decode('ascii')}{port.decode('ascii')}{normalized_path.decode('ascii')}"


def _normalize_path(path: bytes, *, enforce_pchar: bool = False) -> bytes:
    if path == b"":
        path = b"/"
    if enforce_pchar:
        for byte in path:
            ch = bytes([byte])
            if ch != b"%" and _PATH_CHAR.match(ch) is None:
                fail("uri: path character")
    normalized_path = _remove_dot_segments(_normalize_percent_encoding(path))
    if not normalized_path.startswith(b"/"):
        fail("uri: absolute path")
    return normalized_path


def _is_canonical_ipv4(host: bytes) -> bool:
    octets = host.split(b".")
    return len(octets) == 4 and all(
        _IPV4_OCTET.match(o) is not None and int(o) <= 255 for o in octets
    )


def _assert_reg_name(host: bytes) -> None:
    i = 0
    n = len(host)
    while i < n:
        ch = host[i : i + 1]
        if _REG_NAME_CHAR.match(ch) is not None:
            i += 1
            continue
        if ch == b"%" and i + 2 < n and _HEX2.match(host[i + 1 : i + 3]) is not None:
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
        if i + 2 >= n or _HEX2.match(value[i + 1 : i + 3]) is None:
            fail("uri: escape")
        octet = int(value[i + 1 : i + 3], 16)
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
            out += value[i : i + 3]
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
    if re.match(rb"^[0-9A-Fa-f:.]+$", literal) is not None and _valid_ipv6_literal(literal):
        return 6
    if re.match(rb"^v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:\-]+$", literal) is not None:
        return "future"
    return None


# Structural IPv6 validation mirroring the reference (uri.ex:181-226 valid_ipv6_literal? /
# ipv6_side_length / ipv6_groups_length). Rejects malformed literals like ":::", "1:2:3:4:5:6:7:8:9"
# (too many groups), and a "::" that does not actually compress (< 8 groups required). The prior
# implementation only checked the character class, so structurally-invalid literals normalized.
def _valid_ipv6_literal(literal: bytes) -> bool:
    parts = literal.split(b"::")
    if len(parts) == 1:
        return _ipv6_side_length(parts[0]) == 8
    if len(parts) == 2:
        left = _ipv6_side_length(parts[0])
        right = _ipv6_side_length(parts[1])
        if left is None or right is None:
            return False
        return left + right < 8
    return False  # multiple "::" compressions


def _ipv6_side_length(side: bytes) -> int | None:
    """Count groups on one side of "::". Returns None if any group is malformed."""
    if side == b"":
        return 0
    groups = side.split(b":")
    total = 0
    for i, group in enumerate(groups):
        is_last = i == len(groups) - 1
        if b"." in group:
            # An IPv4-style group is valid ONLY in the tail position (reference ipv6_groups_length
            # checks non-last groups as hex-only via valid_hex_group?). A non-tail IPv4 group is a
            # malformed literal the reference rejects.
            if not is_last or not _is_canonical_ipv4(group):
                return None
            total += 2
        else:
            if not (1 <= len(group) <= 4) or not re.match(rb"^[0-9A-Fa-f]+$", group):
                return None
            total += 1
    return total


def _is_invalid(e: BaseException) -> bool:
    from .error import InvalidError

    return isinstance(e, InvalidError)
