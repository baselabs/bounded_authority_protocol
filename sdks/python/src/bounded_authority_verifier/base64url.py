"""Unpadded base64url decode + encode, canonical per REQ1-B64-* (protocol-v1.md:107-110):

- REQ1-B64-alphabet: only ``A-Za-z0-9-_`` (no ``+``, no ``/``, no padding ``=``, no whitespace)
- REQ1-B64-no-padding: padding/whitespace forbidden
- REQ1-B64-length: length mod 4 == 1 is invalid (cannot decode)
- REQ1-B64-canonical: decode succeeds only if unpadded re-encode reproduces the input exactly

Derived from protocol-v1.md § base64url + RFC 4648 §5. NOT using ``base64.urlsafe_b64decode`` for
decode because the stdlib accepts padding/whitespace and is permissive; the bounds-checked canonical
decoder is hand-rolled.
"""

from __future__ import annotations

from .error import fail

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_REV = {ord(ch): i for i, ch in enumerate(_ALPHABET)}


def _classify(byte: int) -> int:
    """Return the alphabet index of a byte, or -1 if not in the alphabet."""
    return _REV.get(byte, -1)


def base64url_decode(data: bytes, max_decoded_bytes: int | None = None) -> bytes:
    n = len(data)
    # REQ1-B64-length: length mod 4 == 1 is structurally invalid.
    if n % 4 == 1:
        fail("base64url: invalid length mod 4 == 1")
    out_len = (n >> 2) * 3
    if n % 4 == 2:
        out_len += 1
    elif n % 4 == 3:
        out_len += 2
    if max_decoded_bytes is not None and out_len > max_decoded_bytes:
        fail("base64url: decoded length exceeds bound")
    out = bytearray(out_len)
    op = 0
    # Full 4-char groups → 3 bytes.
    rem = n % 4
    full = n - (rem if rem != 0 else 0)
    for i in range(0, full, 4):
        a = _classify(data[i])
        b = _classify(data[i + 1])
        c = _classify(data[i + 2])
        d = _classify(data[i + 3])
        if a < 0 or b < 0 or c < 0 or d < 0:
            fail("base64url: non-alphabet byte")
        out[op] = (a << 2) | (b >> 4)
        op += 1
        out[op] = ((b & 0x0F) << 4) | (c >> 2)
        op += 1
        out[op] = ((c & 0x03) << 6) | d
        op += 1
    # Tail group.
    tail = n - full
    if tail == 2:
        a = _classify(data[full])
        b = _classify(data[full + 1])
        if a < 0 or b < 0:
            fail("base64url: non-alphabet byte")
        out[op] = (a << 2) | (b >> 4)
        op += 1
    elif tail == 3:
        a = _classify(data[full])
        b = _classify(data[full + 1])
        c = _classify(data[full + 2])
        if a < 0 or b < 0 or c < 0:
            fail("base64url: non-alphabet byte")
        out[op] = (a << 2) | (b >> 4)
        op += 1
        out[op] = ((b & 0x0F) << 4) | (c >> 2)
        op += 1
    result = bytes(out[:op])
    # REQ1-B64-canonical: re-encode the decoded bytes; the unpadded form must reproduce the input.
    re_encoded = base64url_encode(result)
    if re_encoded != data:
        fail("base64url: non-canonical input")
    return result


def base64url_encode(data: bytes) -> bytes:
    n = len(data)
    rem = n % 3
    out_len = ((n + 2) // 3) * 4
    # Trim the padding: unpadded output length.
    padded = out_len if rem == 0 else out_len - (3 - rem)
    out = bytearray(padded)
    op = 0
    full = n - rem
    for i in range(0, full, 3):
        a = data[i]
        b = data[i + 1]
        c = data[i + 2]
        out[op] = ord(_ALPHABET[a >> 2])
        op += 1
        out[op] = ord(_ALPHABET[((a & 0x03) << 4) | (b >> 4)])
        op += 1
        out[op] = ord(_ALPHABET[((b & 0x0F) << 2) | (c >> 6)])
        op += 1
        out[op] = ord(_ALPHABET[c & 0x3F])
        op += 1
    if rem == 1:
        a = data[full]
        out[op] = ord(_ALPHABET[a >> 2])
        op += 1
        out[op] = ord(_ALPHABET[(a & 0x03) << 4])
        op += 1
    elif rem == 2:
        a = data[full]
        b = data[full + 1]
        out[op] = ord(_ALPHABET[a >> 2])
        op += 1
        out[op] = ord(_ALPHABET[((a & 0x03) << 4) | (b >> 4)])
        op += 1
        out[op] = ord(_ALPHABET[(b & 0x0F) << 2])
        op += 1
    return bytes(out)
