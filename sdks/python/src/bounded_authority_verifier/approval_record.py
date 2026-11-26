"""Canonical record codec for the candidate bap-action-approval/1 profile."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hmac import compare_digest
from json import JSONDecodeError, loads
from json.encoder import encode_basestring

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMUM_BOUNDS, Bounds, coerce_bounds
from .content_assertion import _identifier
from .error import InvalidError, Ok, Result, _fail, _unwrap, err
from .facts import _Facts
from .json_alg import _byte_at, _Ctx, _expect_lit

PROFILE = "bap-action-approval/1"
PROFILE_DIGEST = bytes.fromhex("7e44f73217cd25037839ecc25837de84aad3673626b9b125c94c97e9967fa1eb")

_STRING_SPECIAL = re.compile(rb'["\\\x00-\x1f]')
_ESCAPED_TAIL = re.compile(rb'(?:[^"\\\x00-\x1f]++|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*+"')
_SHORT_ESCAPES = frozenset(b'"\\\b\t\n\f\r')
_RECORD_SCAFFOLD = b'{"action":,"approver_role":,"request_id":,"resources":[],"revision_digest":,"subject":,"v":1}'


@dataclass(frozen=True, slots=True)
class RecordBounds:
    """Tightenable ceilings for the approval record grammar."""

    string_bytes: int = 1024
    resource_count: int = 4096
    record_bytes: int = 65536


class ApprovalRecord(_Facts):
    """Canonicalizable data for one exact operation on a resource set."""

    __slots__ = ("_subject", "_action", "_request_id", "_approver_role", "_resources", "_revision_digest")
    _subject: str
    _action: str
    _request_id: str
    _approver_role: str
    _resources: tuple[str, ...]
    _revision_digest: bytes

    def __init__(
        self,
        subject: str,
        action: str,
        request_id: str,
        approver_role: str,
        resources: tuple[str, ...],
        revision_digest: bytes,
    ) -> None:
        if hasattr(self, "_subject"):
            raise TypeError("Facts cannot be initialized twice")
        object.__setattr__(self, "_subject", subject)
        object.__setattr__(self, "_action", action)
        object.__setattr__(self, "_request_id", request_id)
        object.__setattr__(self, "_approver_role", approver_role)
        object.__setattr__(self, "_resources", resources)
        object.__setattr__(self, "_revision_digest", revision_digest)

    @property
    def subject(self) -> str:
        """The subject of the exact operation."""
        return self._subject

    @property
    def action(self) -> str:
        """The action named by the record."""
        return self._action

    @property
    def request_id(self) -> str:
        """The host request identifier bound to the record."""
        return self._request_id

    @property
    def approver_role(self) -> str:
        """The role named by the record."""
        return self._approver_role

    @property
    def resources(self) -> tuple[str, ...]:
        """The resources named by the record."""
        return self._resources

    @property
    def revision_digest(self) -> bytes:
        """The digest of the host request revision."""
        return self._revision_digest

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ActionApproval.V1.Record<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ApprovalRecord) and type(self) is type(other) and (
            self.subject == other.subject
            and self.action == other.action
            and self.request_id == other.request_id
            and self.approver_role == other.approver_role
            and self.resources == other.resources
            and self.revision_digest == other.revision_digest
        )

    def __hash__(self) -> int:
        return hash((
            self.subject, self.action, self.request_id, self.approver_role,
            self.resources, self.revision_digest,
        ))


def _limits(ca: Bounds, record: RecordBounds) -> RecordBounds:
    if type(record) is not RecordBounds or any(
        type(value) is not int or not 1 <= value <= maximum
        for value, maximum in (
            (getattr(record, "string_bytes", None), 1024),
            (getattr(record, "resource_count", None), 4096),
            (getattr(record, "record_bytes", None), 65536),
        )
    ):
        _fail()
    return RecordBounds(
        record.string_bytes,
        record.resource_count,
        min(record.record_bytes, _unwrap(ca.resolve("content_bytes"))),
    )


def _text(value: str, maximum: int) -> bytes:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail()
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail()
    if len(raw) > maximum:
        _fail()
    return raw


def _width(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail()
    return value


def _resource_bytes(values: tuple[str, ...], limits: RecordBounds) -> tuple[bytes, ...]:
    if type(values) is not tuple or not 1 <= len(values) <= limits.resource_count:
        _fail()
    return tuple(_text(value, limits.string_bytes) for value in values)


def _wire_string_size(raw: bytes) -> int:
    return 2 + len(raw) + sum(
        1 if raw[match.start()] in _SHORT_ESCAPES else 5
        for match in _STRING_SPECIAL.finditer(raw)
    )


def _quote(raw: bytes) -> bytes:
    return encode_basestring(raw.decode("utf-8")).encode("utf-8")


def _encode(
    record: ApprovalRecord, ca: Bounds, limits: RecordBounds, canonicalize: bool = False
) -> bytes:
    if type(record) is not ApprovalRecord or type(canonicalize) is not bool:
        _fail()
    if not all(hasattr(record, name) for name in ApprovalRecord.__slots__):
        _fail()
    maximum = limits.string_bytes
    action = _text(record.action, maximum)
    role = _text(record.approver_role, maximum)
    request_id = _text(record.request_id, min(maximum, _unwrap(ca.resolve("identifier_bytes"))))
    _identifier(record.request_id, ca)
    subject = _text(record.subject, maximum)
    revision = _unwrap(base64url_encode(_width(record.revision_digest)))
    resources = _resource_bytes(record.resources, limits)
    if canonicalize:
        resources = tuple(sorted(set(resources)))
    if any(a >= b for a, b in zip(resources, resources[1:], strict=False)):
        _fail()

    projected = len(_RECORD_SCAFFOLD) + len(resources) - 1
    for chunk in (action, role, request_id, revision, subject, *resources):
        projected += _wire_string_size(chunk)
        if projected > limits.record_bytes:
            _fail()
    return b"".join((
        b'{"action":', _quote(action),
        b',"approver_role":', _quote(role),
        b',"request_id":', _quote(request_id),
        b',"resources":[', b",".join(map(_quote, resources)),
        b'],"revision_digest":', _quote(revision),
        b',"subject":', _quote(subject),
        b',"v":1}',
    ))


def _string(ctx: _Ctx, maximum: int) -> str:
    _expect_lit(ctx, b'"')
    start = ctx.pos
    match = _STRING_SPECIAL.search(ctx.src, start, start + maximum + 1)
    if match is None:
        _fail()
    stop = match.start()
    if ctx.src[stop] == 34:
        raw = ctx.src[start:stop]
        ctx.pos = stop + 1
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            _fail()
    # Each decoded UTF-8 byte needs at most six wire bytes. Find the closing
    # quote inside this bound before handing the string to the JSON decoder.
    escaped = _ESCAPED_TAIL.match(ctx.src, stop, start + 6 * maximum + 1)
    if escaped is None:
        _fail()
    ctx.pos = escaped.end()
    try:
        decoded: object = loads(ctx.src[start - 1:ctx.pos].decode("utf-8"))
    except (JSONDecodeError, UnicodeDecodeError):
        _fail()
    if not isinstance(decoded, str):
        _fail()
    _text(decoded, maximum)
    return decoded


def _decode(wire: bytes, ca: Bounds, limits: RecordBounds) -> ApprovalRecord:
    if type(wire) is not bytes or not 1 <= len(wire) <= limits.record_bytes:
        _fail()
    # Exact member literals fix the grammar, disallowing duplicates before construction.
    ctx = _Ctx(wire, ca)
    _expect_lit(ctx, b'{"action":')
    action = _string(ctx, limits.string_bytes)
    _expect_lit(ctx, b',"approver_role":')
    role = _string(ctx, limits.string_bytes)
    _expect_lit(ctx, b',"request_id":')
    request_id = _string(ctx, min(limits.string_bytes, _unwrap(ca.resolve("identifier_bytes"))))
    _expect_lit(ctx, b',"resources":[')
    resources = [_string(ctx, limits.string_bytes)]
    while _byte_at(wire, ctx.pos) == 44:
        if len(resources) >= limits.resource_count:
            _fail()
        ctx.pos += 1
        resources.append(_string(ctx, limits.string_bytes))
    _expect_lit(ctx, b'],"revision_digest":')
    digest = _unwrap(base64url_decode(_string(ctx, 43).encode("utf-8")))
    _expect_lit(ctx, b',"subject":')
    subject = _string(ctx, limits.string_bytes)
    _expect_lit(ctx, b',"v":1}')
    if ctx.pos != len(wire):
        _fail()
    record = ApprovalRecord(subject, action, request_id, role, tuple(resources), digest)
    if not compare_digest(wire, _encode(record, ca, limits)):
        _fail()
    return record


def encode_record(
    record: ApprovalRecord,
    ca_bounds: Bounds = MAXIMUM_BOUNDS,
    record_bounds: RecordBounds = RecordBounds(),
    *,
    canonicalize: bool = False,
) -> Result[bytes]:
    """Encode a record, with an explicit opt-in to sorting and deduplication."""
    try:
        ca = _unwrap(coerce_bounds(ca_bounds))
        return Ok(_encode(record, ca, _limits(ca, record_bounds), canonicalize))
    except InvalidError:
        return err()


def decode_record(
    wire: bytes,
    ca_bounds: Bounds = MAXIMUM_BOUNDS,
    record_bounds: RecordBounds = RecordBounds(),
) -> Result[ApprovalRecord]:
    """Decode a bounded canonical record."""
    try:
        ca = _unwrap(coerce_bounds(ca_bounds))
        return Ok(_decode(wire, ca, _limits(ca, record_bounds)))
    except InvalidError:
        return err()
