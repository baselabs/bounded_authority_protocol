"""Candidate bap-action-approval/1 verification and host-local diagnostics."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum, StrEnum
from hmac import compare_digest
from typing import Literal

from .approval_record import (
    PROFILE,
    PROFILE_DIGEST,
    ApprovalRecord,
    RecordBounds,
    _decode,
    _limits,
    _resource_bytes,
    _text,
    _width,
)
from .bounds import MAXIMUM_BOUNDS, Bounds
from .content_assertion import (
    _EDDSA,
    _ES256,
    _Suite,
    _bounds,
    _fingerprint,
    _framing,
    _identifier,
    _integer,
    _key_window,
    _kid,
    _payload,
    _signature_matches,
    _suite_matches,
    _verified_facts,
    content_digest,
)
from .ed25519 import torsion_free
from .error import InvalidError, _fail, _unwrap
from .facts import ContentAssertionFacts, _Facts
from .v1 import HistoricalPublicKey


class Suite(Enum):
    """Carrier selected by the host before reading an assertion."""

    EDDSA = "eddsa"
    ES256 = "es256"


class Diagnostic(StrEnum):
    """Value-free host-local failure codes from the approval contract."""

    INVALID_CONTEXT = "invalid_context"
    TRUST_UNAVAILABLE = "trust_unavailable"
    STALE_TRUST = "stale_trust"
    MALFORMED = "malformed"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    UNKNOWN_KEY = "unknown_key"
    BAD_SIGNATURE = "bad_signature"
    KEY_WINDOW = "key_window"
    RECORD_MISMATCH = "record_mismatch"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    REQUEST_MISMATCH = "request_mismatch"
    SUBJECT_MISMATCH = "subject_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    LIFETIME_TOO_LONG = "lifetime_too_long"
    ACTIVE_TOO_LONG = "active_too_long"
    ROLE_NOT_PERMITTED = "role_not_permitted"
    REVOKED_KEY = "revoked_key"
    REPLAYED = "replayed"
    PREDICATE_FAILED = "predicate_failed"

    def __repr__(self) -> str:
        return f"{{:error, :{self.value}}}"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class TrustEntry:
    """Enrolled issuer, public key, historical window and current approver roles."""

    issuer: str
    key: HistoricalPublicKey
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class TrustSnapshot:
    """Caller-supplied trust snapshot for one domain and carrier suite."""

    suite: Suite
    trust_domain: str
    provenance: str
    as_of: int
    entries: tuple[TrustEntry, ...]


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalContext:
    """Expected operation, policy ceilings, time, and trust inputs."""

    trust_domain: str
    audience: str
    request_id: str
    revision_digest: bytes
    subject: str
    action: str
    resources: tuple[str, ...]
    roles: tuple[str, ...]
    now: int
    max_staleness: int
    max_lifetime: int
    snapshot: TrustSnapshot | None
    max_active: int | None = None
    bounds: Bounds = MAXIMUM_BOUNDS
    record_bounds: RecordBounds = RecordBounds()


class VerifiedApprovalFacts(_Facts):
    """Redacted facts bound to the supplied operation and trust context."""

    __slots__ = ("_suite", "_trust_domain", "_record", "_assertion")
    _suite: Suite
    _trust_domain: str
    _record: ApprovalRecord
    _assertion: ContentAssertionFacts

    def __init__(
        self,
        suite: Suite,
        trust_domain: str,
        record: ApprovalRecord,
        assertion: ContentAssertionFacts,
    ) -> None:
        if hasattr(self, "_suite"):
            raise TypeError("Facts cannot be initialized twice")
        object.__setattr__(self, "_suite", suite)
        object.__setattr__(self, "_trust_domain", trust_domain)
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_assertion", assertion)

    @property
    def suite(self) -> Suite:
        return self._suite

    @property
    def trust_domain(self) -> str:
        return self._trust_domain

    @property
    def record(self) -> ApprovalRecord:
        return self._record

    @property
    def assertion(self) -> ContentAssertionFacts:
        return self._assertion

    @property
    def trust(self) -> str:
        """Static marker for the verifier trust boundary."""
        return "not_evaluated"

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VerifiedApprovalFacts) and type(self) is type(other) and (
            self.suite == other.suite
            and self.trust_domain == other.trust_domain
            and self.record == other.record
            and self.assertion == other.assertion
        )


@dataclass(frozen=True, slots=True, repr=False)
class Approved:
    """Results of pure verification and the caller's read-only predicates."""

    facts: VerifiedApprovalFacts

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>"

    __str__ = __repr__


ApprovalResult = Approved | Diagnostic


def _roles(values: tuple[str, ...], maximum: int, *, nonempty: bool = False) -> None:
    if type(values) is not tuple or (nonempty and not values):
        _fail()
    for name in values:
        _text(name, maximum)
    if len(set(values)) != len(values):
        _fail()


def _time(value: int, bounds: Bounds) -> int:
    if type(value) is not int:
        _fail()
    return _integer(value, bounds)


def _context(context: ApprovalContext, bounds: Bounds, limits: RecordBounds) -> tuple[bytes, ...]:
    identifier_limit = _unwrap(bounds.resolve("identifier_bytes"))
    _text(context.trust_domain, identifier_limit)
    _text(context.audience, identifier_limit)
    _identifier(context.audience, bounds)
    _text(context.request_id, min(identifier_limit, limits.string_bytes))
    _identifier(context.request_id, bounds)
    _width(context.revision_digest)
    _text(context.subject, limits.string_bytes)
    _text(context.action, limits.string_bytes)
    resources = _resource_bytes(context.resources, limits)
    if len(set(resources)) != len(resources):
        _fail()
    _roles(context.roles, limits.string_bytes, nonempty=True)
    _time(context.now, bounds)
    for cap in (context.max_staleness, context.max_lifetime):
        if _time(cap, bounds) < 0:
            _fail()
    if context.max_active is not None and _time(context.max_active, bounds) < 0:
        _fail()
    return tuple(sorted(resources))


def _snapshot(
    snapshot: TrustSnapshot | None, suite: Suite, domain: str, b: Bounds, limits: RecordBounds
) -> dict[str, tuple[TrustEntry, bytes]]:
    if type(snapshot) is not TrustSnapshot or snapshot.suite is not suite:
        _fail()
    identifier_limit = _unwrap(b.resolve("identifier_bytes"))
    _text(snapshot.trust_domain, identifier_limit)
    _text(snapshot.provenance, identifier_limit)
    if snapshot.trust_domain != domain or type(snapshot.entries) is not tuple:
        _fail()
    _time(snapshot.as_of, b)
    admitted: dict[str, tuple[TrustEntry, bytes]] = {}
    for entry in snapshot.entries:
        if type(entry) is not TrustEntry or type(entry.key) is not HistoricalPublicKey:
            _fail()
        key = entry.key
        _text(key.key_id, _unwrap(b.resolve("kid_bytes")))
        _kid(key.key_id, b)
        _text(entry.issuer, identifier_limit)
        _identifier(entry.issuer, b)
        _roles(entry.roles, limits.string_bytes)
        if key.key_id in admitted or type(key.public_key) is not bytes:
            _fail()
        start = _time(key.valid_from, b)
        if key.valid_before is not None and _time(key.valid_before, b) <= start:
            _fail()
        if suite is Suite.EDDSA and not torsion_free(key.public_key):
            _fail()
        fingerprint = _fingerprint(key.public_key, _EDDSA if suite is Suite.EDDSA else _ES256)
        admitted[key.key_id] = (entry, fingerprint)
    return admitted


def _find_entry(
    entries: dict[str, tuple[TrustEntry, bytes]], kid: str
) -> tuple[TrustEntry, bytes] | None:
    return entries.get(kid)


def _verify(
    wire: bytes, compact: bytes, context: ApprovalContext, selected: Suite, suite: _Suite
) -> tuple[VerifiedApprovalFacts, TrustEntry] | Diagnostic:
    if type(context) is not ApprovalContext:
        return Diagnostic.INVALID_CONTEXT
    try:
        if type(context.bounds) is not Bounds:
            _fail()
        b = _bounds(context.bounds)
        limits = _limits(b, context.record_bounds)
        resources = _context(context, b, limits)
    except (InvalidError, AttributeError):
        return Diagnostic.INVALID_CONTEXT

    snapshot = context.snapshot
    try:
        entries = _snapshot(snapshot, selected, context.trust_domain, b, limits)
    except (InvalidError, AttributeError):
        return Diagnostic.TRUST_UNAVAILABLE
    assert snapshot is not None
    if not 0 <= context.now - snapshot.as_of <= context.max_staleness:
        return Diagnostic.STALE_TRUST

    try:
        if type(compact) is not bytes:
            _fail()
        segments, header = _framing(compact, b)
    except InvalidError:
        return Diagnostic.MALFORMED
    if not _suite_matches(header, suite):
        return Diagnostic.UNSUPPORTED_ALGORITHM
    try:
        claims = _payload(segments, header.kid, b, suite)
        _text(claims.sub, limits.string_bytes)
        record = _decode(wire, b, limits)
    except InvalidError:
        return Diagnostic.MALFORMED

    enrolled = _find_entry(entries, header.kid)
    if enrolled is None:
        return Diagnostic.UNKNOWN_KEY
    entry, fingerprint = enrolled
    try:
        authenticated = _signature_matches(segments, entry.key.public_key, suite)
    except Exception:
        authenticated = False
    if not authenticated:
        return Diagnostic.BAD_SIGNATURE
    if not _key_window(claims, entry.key):
        return Diagnostic.KEY_WINDOW
    if (
        claims.profile != PROFILE
        or not compare_digest(claims.profile_digest, PROFILE_DIGEST)
        or not compare_digest(claims.content_digest, _unwrap(content_digest(wire, b)))
    ):
        return Diagnostic.RECORD_MISMATCH
    if claims.iss != entry.issuer:
        return Diagnostic.ISSUER_MISMATCH
    if claims.aud != context.audience:
        return Diagnostic.AUDIENCE_MISMATCH
    if (
        record.request_id != context.request_id
        or claims.sub != context.request_id
        or not compare_digest(record.revision_digest, context.revision_digest)
    ):
        return Diagnostic.REQUEST_MISMATCH
    if record.subject != context.subject:
        return Diagnostic.SUBJECT_MISMATCH
    if record.action != context.action or tuple(item.encode("utf-8") for item in record.resources) != resources:
        return Diagnostic.SCOPE_MISMATCH
    if claims.nbf > context.now:
        return Diagnostic.NOT_YET_VALID
    if claims.exp <= context.now:
        return Diagnostic.EXPIRED
    if claims.exp - claims.iat > context.max_lifetime:
        return Diagnostic.LIFETIME_TOO_LONG
    if context.max_active is not None and claims.exp - claims.nbf > context.max_active:
        return Diagnostic.ACTIVE_TOO_LONG
    if record.approver_role not in context.roles or record.approver_role not in entry.roles:
        return Diagnostic.ROLE_NOT_PERMITTED
    assertion = _verified_facts(claims, compact, fingerprint, suite)
    return VerifiedApprovalFacts(selected, context.trust_domain, record, assertion), entry


def verify_approval_eddsa(
    record_bytes: bytes, assertion_compact: bytes, context: ApprovalContext
) -> VerifiedApprovalFacts | Diagnostic:
    """Verify approval under a caller-selected EdDSA trust domain."""
    result = _verify(record_bytes, assertion_compact, context, Suite.EDDSA, _EDDSA)
    return result if isinstance(result, Diagnostic) else result[0]


def verify_approval_es256(
    record_bytes: bytes, assertion_compact: bytes, context: ApprovalContext
) -> VerifiedApprovalFacts | Diagnostic:
    """Verify approval under a caller-selected ES256 trust domain."""
    result = _verify(record_bytes, assertion_compact, context, Suite.ES256, _ES256)
    return result if isinstance(result, Diagnostic) else result[0]


def verify(
    grant: bytes,
    proof: bytes,
    trusted_keys: TrustSnapshot | None,
    now: int,
    max_validity: int,
    is_replayed: Callable[[str, str, str], bool],
    is_revoked: Callable[[TrustEntry, bytes], bool],
    *,
    suite: Suite,
    expected: ApprovalContext,
) -> ApprovalResult:
    """Evaluate the pure result and the host's read-only predicates."""
    if type(expected) is not ApprovalContext or type(suite) is not Suite:
        return Diagnostic.INVALID_CONTEXT
    try:
        context = replace(expected, now=now, max_lifetime=max_validity, snapshot=trusted_keys)
    except AttributeError:
        return Diagnostic.INVALID_CONTEXT
    result = _verify(grant, proof, context, suite, _EDDSA if suite is Suite.EDDSA else _ES256)
    if isinstance(result, Diagnostic):
        return result
    facts, entry = result
    try:
        revoked = is_revoked(entry, facts.assertion.attestor_key_fingerprint)
        if revoked is True:
            return Diagnostic.REVOKED_KEY
        if revoked is False:
            replayed = is_replayed(facts.trust_domain, facts.assertion.iss, facts.assertion.jti)
            if replayed is True:
                return Diagnostic.REPLAYED
            if replayed is False:
                return Approved(facts)
    except BaseException:
        pass
    return Diagnostic.PREDICATE_FAILED


def presenter_result(result: ApprovalResult) -> Literal["approved", "invalid"]:
    """Collapse failures at the presenter boundary."""
    return "approved" if isinstance(result, Approved) else "invalid"


def render_presenter_result(result: ApprovalResult) -> str:
    """Render the disclosure-limited result for presenters and their logs."""
    return repr(result) if isinstance(result, Approved) else "{:error, :invalid}"


def render_verification_result(result: VerifiedApprovalFacts | Diagnostic) -> str:
    """Render the pure verification result for host-local inspection."""
    if isinstance(result, Diagnostic):
        return repr(result)
    return f"{{:ok, {result!r}}}"
