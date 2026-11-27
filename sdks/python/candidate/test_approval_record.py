"""Pin byte-for-byte canonical validation of bounded approval record strings."""

import pytest

from bounded_authority_verifier.approval_record import RecordBounds, decode_record
from bounded_authority_verifier.error import _unwrap


def record(resources: bytes) -> bytes:
    return (
        b'{"action":"a","approver_role":"r","request_id":"i","resources":['
        + resources
        + b'],"revision_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","subject":"s","v":1}'
    )


@pytest.mark.parametrize(
    ("token", "text", "width"),
    [
        (rb'"\u000b"', "\v", 1),
        (rb'"\b\t\n\f\r\"\\"', '\b\t\n\f\r"\\', 7),
        ('"😀/"'.encode(), "😀/", 5),
        ('"😀\\n"'.encode(), "😀\n", 5),
    ],
)
def test_canonical_strings_use_decoded_utf8_width(token: bytes, text: str, width: int) -> None:
    wire = record(token)
    limits = RecordBounds(string_bytes=width, record_bytes=len(wire))
    assert _unwrap(decode_record(wire, record_bounds=limits)).resources == (text,)
    if width > 1:
        tighter = RecordBounds(string_bytes=width - 1)
        assert not decode_record(wire, record_bounds=tighter).is_ok


@pytest.mark.parametrize(
    "token",
    [
        b'""',
        b'"\x00"',
        b'"\xc0\xaf"',
        b'"\xed\xa0\x80"',
        rb'"\/"',
        rb'"\u000B"',
        rb'"\u000a"',
        rb'"\u0061"',
        rb'"\ud800"',
        rb'"\ud83d\ude00"',
    ],
)
def test_rejects_noncanonical_or_invalid_strings(token: bytes) -> None:
    assert not decode_record(record(token)).is_ok


def test_resource_order_uses_decoded_scalar_values() -> None:
    # The escape for a quote sorts after A on the wire. UTF-16 sorts U+10000 before U+E000.
    ordered = (rb'"\""', b'"A"', b'"AA"', '"\ue000"'.encode(), '"\U00010000"'.encode())
    wire = record(b",".join(ordered))
    assert _unwrap(decode_record(wire)).resources == ('"', "A", "AA", "\ue000", "\U00010000")
    assert not decode_record(wire, record_bounds=RecordBounds(resource_count=4)).is_ok
    assert not decode_record(record(b",".join(reversed(ordered)))).is_ok
    assert not decode_record(record(b",".join((*ordered, ordered[-1])))).is_ok
