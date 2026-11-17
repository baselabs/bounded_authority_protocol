"""Value-bearing, redacted, non-authorizing facts (spec/bap-v1.md § Public verification contract,
REQ1-VERIFY-facts-redacted, REQ1-VERIFY-facts-not-credentials).

No generic encoder, no ``asdict``, no authorization/decision method (AGENTS rule 1). Grant/Envelope/
Export carry ``authorization="not_evaluated"``; Chain/Anchor/Transition carry
``trust="not_evaluated"``.

Verified facts are slotted value objects with read-only properties. They refuse generic
enumeration, pickling, and copy reduction; callers read named properties explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn


class _Facts:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Facts are immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("Facts are immutable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Facts have no generic reduction")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("Facts have no generic reduction")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Facts have no generic state export")


class GrantFacts(_Facts):
    'GrantFacts (spec/bap-v1.md): version, issuer, grant_id, issuer-key fingerprint (raw 32),\nholder thumbprint (raw 32), matched audience, grant times, authorization=not_evaluated.'

    __slots__ = ('_version', '_issuer', '_grant_id', '_issuer_key_fingerprint', '_holder_thumbprint', '_matched_audience', '_issued_at', '_not_before', '_expires_at', '_authorization')
    _version: int
    _issuer: str
    _grant_id: str
    _issuer_key_fingerprint: bytes
    _holder_thumbprint: bytes
    _matched_audience: str
    _issued_at: int
    _not_before: int
    _expires_at: int
    _authorization: str

    def __init__(
        self,
        version: int,
        issuer: str,
        grant_id: str,
        issuer_key_fingerprint: bytes,
        holder_thumbprint: bytes,
        matched_audience: str,
        issued_at: int,
        not_before: int,
        expires_at: int,
        authorization: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_issuer", issuer)
        object.__setattr__(self, "_grant_id", grant_id)
        object.__setattr__(self, "_issuer_key_fingerprint", issuer_key_fingerprint)
        object.__setattr__(self, "_holder_thumbprint", holder_thumbprint)
        object.__setattr__(self, "_matched_audience", matched_audience)
        object.__setattr__(self, "_issued_at", issued_at)
        object.__setattr__(self, "_not_before", not_before)
        object.__setattr__(self, "_expires_at", expires_at)
        object.__setattr__(self, "_authorization", authorization)

    @property
    def version(self) -> int:
        return self._version

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def grant_id(self) -> str:
        return self._grant_id

    @property
    def issuer_key_fingerprint(self) -> bytes:
        return self._issuer_key_fingerprint

    @property
    def holder_thumbprint(self) -> bytes:
        return self._holder_thumbprint

    @property
    def matched_audience(self) -> str:
        return self._matched_audience

    @property
    def issued_at(self) -> int:
        return self._issued_at

    @property
    def not_before(self) -> int:
        return self._not_before

    @property
    def expires_at(self) -> int:
        return self._expires_at

    @property
    def authorization(self) -> str:
        return self._authorization

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.GrantFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.GrantFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.GrantFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GrantFacts) and (
            self._version, self._issuer, self._grant_id, self._issuer_key_fingerprint, self._holder_thumbprint, self._matched_audience, self._issued_at, self._not_before, self._expires_at, self._authorization,
        ) == (
            other._version, other._issuer, other._grant_id, other._issuer_key_fingerprint, other._holder_thumbprint, other._matched_audience, other._issued_at, other._not_before, other._expires_at, other._authorization,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._issuer, self._grant_id, self._issuer_key_fingerprint, self._holder_thumbprint, self._matched_audience, self._issued_at, self._not_before, self._expires_at, self._authorization,))


class EnvelopeFacts(_Facts):
    'EnvelopeFacts (spec/bap-v1.md): GrantFacts + proof_id, invocation_id, operation, uri,\ngrant hash (ath raw 32), request hash (ba_req raw 32), proof issued_at.'

    __slots__ = ('_version', '_issuer', '_grant_id', '_issuer_key_fingerprint', '_holder_thumbprint', '_matched_audience', '_grant_issued_at', '_grant_not_before', '_grant_expires_at', '_proof_id', '_invocation_id', '_operation', '_uri', '_grant_hash', '_request_hash', '_proof_issued_at', '_authorization')
    _version: int
    _issuer: str
    _grant_id: str
    _issuer_key_fingerprint: bytes
    _holder_thumbprint: bytes
    _matched_audience: str
    _grant_issued_at: int
    _grant_not_before: int
    _grant_expires_at: int
    _proof_id: str
    _invocation_id: str
    _operation: str
    _uri: str
    _grant_hash: bytes
    _request_hash: bytes
    _proof_issued_at: int
    _authorization: str

    def __init__(
        self,
        version: int,
        issuer: str,
        grant_id: str,
        issuer_key_fingerprint: bytes,
        holder_thumbprint: bytes,
        matched_audience: str,
        grant_issued_at: int,
        grant_not_before: int,
        grant_expires_at: int,
        proof_id: str,
        invocation_id: str,
        operation: str,
        uri: str,
        grant_hash: bytes,
        request_hash: bytes,
        proof_issued_at: int,
        authorization: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_issuer", issuer)
        object.__setattr__(self, "_grant_id", grant_id)
        object.__setattr__(self, "_issuer_key_fingerprint", issuer_key_fingerprint)
        object.__setattr__(self, "_holder_thumbprint", holder_thumbprint)
        object.__setattr__(self, "_matched_audience", matched_audience)
        object.__setattr__(self, "_grant_issued_at", grant_issued_at)
        object.__setattr__(self, "_grant_not_before", grant_not_before)
        object.__setattr__(self, "_grant_expires_at", grant_expires_at)
        object.__setattr__(self, "_proof_id", proof_id)
        object.__setattr__(self, "_invocation_id", invocation_id)
        object.__setattr__(self, "_operation", operation)
        object.__setattr__(self, "_uri", uri)
        object.__setattr__(self, "_grant_hash", grant_hash)
        object.__setattr__(self, "_request_hash", request_hash)
        object.__setattr__(self, "_proof_issued_at", proof_issued_at)
        object.__setattr__(self, "_authorization", authorization)

    @property
    def version(self) -> int:
        return self._version

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def grant_id(self) -> str:
        return self._grant_id

    @property
    def issuer_key_fingerprint(self) -> bytes:
        return self._issuer_key_fingerprint

    @property
    def holder_thumbprint(self) -> bytes:
        return self._holder_thumbprint

    @property
    def matched_audience(self) -> str:
        return self._matched_audience

    @property
    def grant_issued_at(self) -> int:
        return self._grant_issued_at

    @property
    def grant_not_before(self) -> int:
        return self._grant_not_before

    @property
    def grant_expires_at(self) -> int:
        return self._grant_expires_at

    @property
    def proof_id(self) -> str:
        return self._proof_id

    @property
    def invocation_id(self) -> str:
        return self._invocation_id

    @property
    def operation(self) -> str:
        return self._operation

    @property
    def uri(self) -> str:
        return self._uri

    @property
    def grant_hash(self) -> bytes:
        return self._grant_hash

    @property
    def request_hash(self) -> bytes:
        return self._request_hash

    @property
    def proof_issued_at(self) -> int:
        return self._proof_issued_at

    @property
    def authorization(self) -> str:
        return self._authorization

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.EnvelopeFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.EnvelopeFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, EnvelopeFacts) and (
            self._version, self._issuer, self._grant_id, self._issuer_key_fingerprint, self._holder_thumbprint, self._matched_audience, self._grant_issued_at, self._grant_not_before, self._grant_expires_at, self._proof_id, self._invocation_id, self._operation, self._uri, self._grant_hash, self._request_hash, self._proof_issued_at, self._authorization,
        ) == (
            other._version, other._issuer, other._grant_id, other._issuer_key_fingerprint, other._holder_thumbprint, other._matched_audience, other._grant_issued_at, other._grant_not_before, other._grant_expires_at, other._proof_id, other._invocation_id, other._operation, other._uri, other._grant_hash, other._request_hash, other._proof_issued_at, other._authorization,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._issuer, self._grant_id, self._issuer_key_fingerprint, self._holder_thumbprint, self._matched_audience, self._grant_issued_at, self._grant_not_before, self._grant_expires_at, self._proof_id, self._invocation_id, self._operation, self._uri, self._grant_hash, self._request_hash, self._proof_issued_at, self._authorization,))


class ChainFacts(_Facts):
    'Consumption-row facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16.'

    __slots__ = ('_version', '_chain_id', '_first_sequence', '_last_sequence', '_row_count', '_previous_hash', '_last_hash', '_verification', '_trust')
    _version: int
    _chain_id: str
    _first_sequence: int
    _last_sequence: int
    _row_count: int
    _previous_hash: bytes
    _last_hash: bytes
    _verification: str
    _trust: str

    def __init__(
        self,
        version: int,
        chain_id: str,
        first_sequence: int,
        last_sequence: int,
        row_count: int,
        previous_hash: bytes,
        last_hash: bytes,
        verification: str = 'boundary_consistent',
        trust: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_chain_id", chain_id)
        object.__setattr__(self, "_first_sequence", first_sequence)
        object.__setattr__(self, "_last_sequence", last_sequence)
        object.__setattr__(self, "_row_count", row_count)
        object.__setattr__(self, "_previous_hash", previous_hash)
        object.__setattr__(self, "_last_hash", last_hash)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)

    @property
    def version(self) -> int:
        return self._version

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def first_sequence(self) -> int:
        return self._first_sequence

    @property
    def last_sequence(self) -> int:
        return self._last_sequence

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def previous_hash(self) -> bytes:
        return self._previous_hash

    @property
    def last_hash(self) -> bytes:
        return self._last_hash

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.ChainFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.ChainFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.ChainFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ChainFacts) and (
            self._version, self._chain_id, self._first_sequence, self._last_sequence, self._row_count, self._previous_hash, self._last_hash, self._verification, self._trust,
        ) == (
            other._version, other._chain_id, other._first_sequence, other._last_sequence, other._row_count, other._previous_hash, other._last_hash, other._verification, other._trust,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._chain_id, self._first_sequence, self._last_sequence, self._row_count, self._previous_hash, self._last_hash, self._verification, self._trust,))


class AnchorFacts(_Facts):
    'Boundary-anchor facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16: the key binding\nis its fingerprint, without a key identifier.'

    __slots__ = ('_version', '_anchor_id', '_anchored_at', '_chain_id', '_sequence', '_chain_hash', '_key_fingerprint', '_verification', '_trust')
    _version: int
    _anchor_id: str
    _anchored_at: int
    _chain_id: str
    _sequence: int
    _chain_hash: bytes
    _key_fingerprint: bytes
    _verification: str
    _trust: str

    def __init__(
        self,
        version: int,
        anchor_id: str,
        anchored_at: int,
        chain_id: str,
        sequence: int,
        chain_hash: bytes,
        key_fingerprint: bytes,
        verification: str = 'signature_and_window',
        trust: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_anchor_id", anchor_id)
        object.__setattr__(self, "_anchored_at", anchored_at)
        object.__setattr__(self, "_chain_id", chain_id)
        object.__setattr__(self, "_sequence", sequence)
        object.__setattr__(self, "_chain_hash", chain_hash)
        object.__setattr__(self, "_key_fingerprint", key_fingerprint)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)

    @property
    def version(self) -> int:
        return self._version

    @property
    def anchor_id(self) -> str:
        return self._anchor_id

    @property
    def anchored_at(self) -> int:
        return self._anchored_at

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def chain_hash(self) -> bytes:
        return self._chain_hash

    @property
    def key_fingerprint(self) -> bytes:
        return self._key_fingerprint

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.AnchorFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.AnchorFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.AnchorFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AnchorFacts) and (
            self._version, self._anchor_id, self._anchored_at, self._chain_id, self._sequence, self._chain_hash, self._key_fingerprint, self._verification, self._trust,
        ) == (
            other._version, other._anchor_id, other._anchored_at, other._chain_id, other._sequence, other._chain_hash, other._key_fingerprint, other._verification, other._trust,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._anchor_id, self._anchored_at, self._chain_id, self._sequence, self._chain_hash, self._key_fingerprint, self._verification, self._trust,))


class KeyTransitionFacts(_Facts):
    'Authenticated key-transition facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16: key bindings\nare current and next fingerprints, without key identifiers.'

    __slots__ = ('_version', '_transition_id', '_chain_id', '_effective_at', '_current_key_fingerprint', '_next_key_fingerprint', '_verification', '_trust')
    _version: int
    _transition_id: str
    _chain_id: str
    _effective_at: int
    _current_key_fingerprint: bytes
    _next_key_fingerprint: bytes
    _verification: str
    _trust: str

    def __init__(
        self,
        version: int,
        transition_id: str,
        chain_id: str,
        effective_at: int,
        current_key_fingerprint: bytes,
        next_key_fingerprint: bytes,
        verification: str = 'authenticated_transition',
        trust: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_transition_id", transition_id)
        object.__setattr__(self, "_chain_id", chain_id)
        object.__setattr__(self, "_effective_at", effective_at)
        object.__setattr__(self, "_current_key_fingerprint", current_key_fingerprint)
        object.__setattr__(self, "_next_key_fingerprint", next_key_fingerprint)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)

    @property
    def version(self) -> int:
        return self._version

    @property
    def transition_id(self) -> str:
        return self._transition_id

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def effective_at(self) -> int:
        return self._effective_at

    @property
    def current_key_fingerprint(self) -> bytes:
        return self._current_key_fingerprint

    @property
    def next_key_fingerprint(self) -> bytes:
        return self._next_key_fingerprint

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.KeyTransitionFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.KeyTransitionFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.KeyTransitionFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KeyTransitionFacts) and (
            self._version, self._transition_id, self._chain_id, self._effective_at, self._current_key_fingerprint, self._next_key_fingerprint, self._verification, self._trust,
        ) == (
            other._version, other._transition_id, other._chain_id, other._effective_at, other._current_key_fingerprint, other._next_key_fingerprint, other._verification, other._trust,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._transition_id, self._chain_id, self._effective_at, self._current_key_fingerprint, self._next_key_fingerprint, self._verification, self._trust,))


class AnchoredExportFacts(_Facts):
    'Anchored-export facts carrying both trust and authorization=not_evaluated.\n\nFields follow spec/bap-v1.md §16.'

    __slots__ = ('_version', '_chain_id', '_first_sequence', '_last_sequence', '_row_count', '_previous_hash', '_last_hash', '_digest', '_start_anchor_id', '_start_anchored_at', '_start_key_fingerprint', '_end_anchor_id', '_end_anchored_at', '_end_key_fingerprint', '_transition_count', '_object_version', '_verification', '_trust', '_authorization')
    _version: int
    _chain_id: str
    _first_sequence: int
    _last_sequence: int
    _row_count: int
    _previous_hash: bytes
    _last_hash: bytes
    _digest: bytes
    _start_anchor_id: str
    _start_anchored_at: int
    _start_key_fingerprint: bytes
    _end_anchor_id: str
    _end_anchored_at: int
    _end_key_fingerprint: bytes
    _transition_count: int
    _object_version: str
    _verification: str
    _trust: str
    _authorization: str

    def __init__(
        self,
        version: int,
        chain_id: str,
        first_sequence: int,
        last_sequence: int,
        row_count: int,
        previous_hash: bytes,
        last_hash: bytes,
        digest: bytes,
        start_anchor_id: str,
        start_anchored_at: int,
        start_key_fingerprint: bytes,
        end_anchor_id: str,
        end_anchored_at: int,
        end_key_fingerprint: bytes,
        transition_count: int,
        object_version: str,
        verification: str = 'anchored_export',
        trust: str = 'not_evaluated',
        authorization: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_chain_id", chain_id)
        object.__setattr__(self, "_first_sequence", first_sequence)
        object.__setattr__(self, "_last_sequence", last_sequence)
        object.__setattr__(self, "_row_count", row_count)
        object.__setattr__(self, "_previous_hash", previous_hash)
        object.__setattr__(self, "_last_hash", last_hash)
        object.__setattr__(self, "_digest", digest)
        object.__setattr__(self, "_start_anchor_id", start_anchor_id)
        object.__setattr__(self, "_start_anchored_at", start_anchored_at)
        object.__setattr__(self, "_start_key_fingerprint", start_key_fingerprint)
        object.__setattr__(self, "_end_anchor_id", end_anchor_id)
        object.__setattr__(self, "_end_anchored_at", end_anchored_at)
        object.__setattr__(self, "_end_key_fingerprint", end_key_fingerprint)
        object.__setattr__(self, "_transition_count", transition_count)
        object.__setattr__(self, "_object_version", object_version)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)
        object.__setattr__(self, "_authorization", authorization)

    @property
    def version(self) -> int:
        return self._version

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def first_sequence(self) -> int:
        return self._first_sequence

    @property
    def last_sequence(self) -> int:
        return self._last_sequence

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def previous_hash(self) -> bytes:
        return self._previous_hash

    @property
    def last_hash(self) -> bytes:
        return self._last_hash

    @property
    def digest(self) -> bytes:
        return self._digest

    @property
    def start_anchor_id(self) -> str:
        return self._start_anchor_id

    @property
    def start_anchored_at(self) -> int:
        return self._start_anchored_at

    @property
    def start_key_fingerprint(self) -> bytes:
        return self._start_key_fingerprint

    @property
    def end_anchor_id(self) -> str:
        return self._end_anchor_id

    @property
    def end_anchored_at(self) -> int:
        return self._end_anchored_at

    @property
    def end_key_fingerprint(self) -> bytes:
        return self._end_key_fingerprint

    @property
    def transition_count(self) -> int:
        return self._transition_count

    @property
    def object_version(self) -> str:
        return self._object_version

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    @property
    def authorization(self) -> str:
        return self._authorization

    def __repr__(self) -> str:
        if type(self._version) is int and self._version == 2:
            return "#BoundedAuthorityProtocol.V2.AnchoredExportFacts<redacted>"
        if type(self._version) is int and self._version == 3:
            return "#BoundedAuthorityProtocol.V3.AnchoredExportFacts<redacted>"
        return "#BoundedAuthorityProtocol.V1.AnchoredExportFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AnchoredExportFacts) and (
            self._version, self._chain_id, self._first_sequence, self._last_sequence, self._row_count, self._previous_hash, self._last_hash, self._digest, self._start_anchor_id, self._start_anchored_at, self._start_key_fingerprint, self._end_anchor_id, self._end_anchored_at, self._end_key_fingerprint, self._transition_count, self._object_version, self._verification, self._trust, self._authorization,
        ) == (
            other._version, other._chain_id, other._first_sequence, other._last_sequence, other._row_count, other._previous_hash, other._last_hash, other._digest, other._start_anchor_id, other._start_anchored_at, other._start_key_fingerprint, other._end_anchor_id, other._end_anchored_at, other._end_key_fingerprint, other._transition_count, other._object_version, other._verification, other._trust, other._authorization,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._chain_id, self._first_sequence, self._last_sequence, self._row_count, self._previous_hash, self._last_hash, self._digest, self._start_anchor_id, self._start_anchored_at, self._start_key_fingerprint, self._end_anchor_id, self._end_anchored_at, self._end_key_fingerprint, self._transition_count, self._object_version, self._verification, self._trust, self._authorization,))


@dataclass(frozen=True)
class GrantDecoded:
    """Decode surface — structural grant facts (verification=not_evaluated)."""

    key_id: str
    issuer: str
    grant_id: str
    audiences: tuple[str, ...]
    issued_at: int
    not_before: int
    expires_at: int
    holder_thumbprint: bytes
    verification: str = "not_evaluated"


@dataclass(frozen=True)
class ProofDecoded:
    """Decode surface — structural proof facts (verification=not_evaluated)."""

    proof_id: str
    holder_thumbprint: bytes
    verification: str = "not_evaluated"


@dataclass(frozen=True)
class KeyLocator:
    """Locator surface — header-only key id (trust=not_evaluated)."""

    key_id: str
    trust: str = "not_evaluated"


@dataclass(frozen=True)
class AttestationDecoded:
    """Decode surface — structural role-attestation facts (verification=not_evaluated).

    ``public_key`` is the raw 32-byte subject public key exactly as it rides the payload claim —
    the member shape the Elixir ``DecodedAttestation``, Go ``AttestationDecoded``, and Rust
    ``AttestationDecoded`` decode surfaces all carry (cross-vendor review 2026-09-22 alignment;
    derived digests belong to the facts surface, not decode).
    """

    attestor_key_id: str
    jti: str
    subject_key_id: str
    public_key: bytes  # raw 32
    role: str
    nbf: int
    exp: int
    verification: str = "not_evaluated"


class AttestationFacts(_Facts):
    'AttestationFacts (spec/bap-role-attestation-v1.md §3): value-bearing, redacted,\nnon-authorizing. Fingerprints are RFC 7638 Ed25519 thumbprints (raw 32) — never a hash of\nraw key bytes. No raw key material, no signature, no decision (REQ-RA1-VERIFY-facts,\nREQ-RA1-VERIFY-facts-non-authorizing).'

    __slots__ = ('_attestor_key_id', '_attestor_key_fingerprint', '_subject_key_id', '_subject_key_fingerprint', '_role', '_jti', '_nbf', '_exp', '_verification', '_trust')
    _attestor_key_id: str
    _attestor_key_fingerprint: bytes
    _subject_key_id: str
    _subject_key_fingerprint: bytes
    _role: str
    _jti: str
    _nbf: int
    _exp: int
    _verification: str
    _trust: str

    def __init__(
        self,
        attestor_key_id: str,
        attestor_key_fingerprint: bytes,
        subject_key_id: str,
        subject_key_fingerprint: bytes,
        role: str,
        jti: str,
        nbf: int,
        exp: int,
        verification: str = 'signature_and_window',
        trust: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_attestor_key_id", attestor_key_id)
        object.__setattr__(self, "_attestor_key_fingerprint", attestor_key_fingerprint)
        object.__setattr__(self, "_subject_key_id", subject_key_id)
        object.__setattr__(self, "_subject_key_fingerprint", subject_key_fingerprint)
        object.__setattr__(self, "_role", role)
        object.__setattr__(self, "_jti", jti)
        object.__setattr__(self, "_nbf", nbf)
        object.__setattr__(self, "_exp", exp)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)

    @property
    def attestor_key_id(self) -> str:
        return self._attestor_key_id

    @property
    def attestor_key_fingerprint(self) -> bytes:
        return self._attestor_key_fingerprint

    @property
    def subject_key_id(self) -> str:
        return self._subject_key_id

    @property
    def subject_key_fingerprint(self) -> bytes:
        return self._subject_key_fingerprint

    @property
    def role(self) -> str:
        return self._role

    @property
    def jti(self) -> str:
        return self._jti

    @property
    def nbf(self) -> int:
        return self._nbf

    @property
    def exp(self) -> int:
        return self._exp

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AttestationFacts) and (
            self._attestor_key_id, self._attestor_key_fingerprint, self._subject_key_id, self._subject_key_fingerprint, self._role, self._jti, self._nbf, self._exp, self._verification, self._trust,
        ) == (
            other._attestor_key_id, other._attestor_key_fingerprint, other._subject_key_id, other._subject_key_fingerprint, other._role, other._jti, other._nbf, other._exp, other._verification, other._trust,
        )

    def __hash__(self) -> int:
        return hash((self._attestor_key_id, self._attestor_key_fingerprint, self._subject_key_id, self._subject_key_fingerprint, self._role, self._jti, self._nbf, self._exp, self._verification, self._trust,))


@dataclass(frozen=True)
class ContentAssertionDecoded:
    """Structurally decoded content assertion; no signature or trust evaluation."""

    version: int
    attestor_key_id: str
    jti: str
    iss: str
    aud: str
    sub: str
    profile: str
    profile_digest: bytes
    content_digest: bytes
    gen: int
    prev: bytes
    iat: int
    nbf: int
    exp: int
    verification: str = "not_evaluated"


class ContentAssertionFacts(_Facts):
    'Verified, value-bearing, redacted content-assertion facts.\n\nThis value remains non-authorizing and caller-provenanced. It contains no raw public key,\nsignature, decision, or authorization marker.'

    __slots__ = ('_version', '_attestor_key_id', '_attestor_key_fingerprint', '_jti', '_iss', '_aud', '_sub', '_profile', '_profile_digest', '_content_digest', '_gen', '_prev', '_iat', '_nbf', '_exp', '_digest', '_verification', '_trust')
    _version: int
    _attestor_key_id: str
    _attestor_key_fingerprint: bytes
    _jti: str
    _iss: str
    _aud: str
    _sub: str
    _profile: str
    _profile_digest: bytes
    _content_digest: bytes
    _gen: int
    _prev: bytes
    _iat: int
    _nbf: int
    _exp: int
    _digest: bytes
    _verification: str
    _trust: str

    def __init__(
        self,
        version: int,
        attestor_key_id: str,
        attestor_key_fingerprint: bytes,
        jti: str,
        iss: str,
        aud: str,
        sub: str,
        profile: str,
        profile_digest: bytes,
        content_digest: bytes,
        gen: int,
        prev: bytes,
        iat: int,
        nbf: int,
        exp: int,
        digest: bytes,
        verification: str = 'signature_and_window',
        trust: str = 'not_evaluated',
    ) -> None:
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_attestor_key_id", attestor_key_id)
        object.__setattr__(self, "_attestor_key_fingerprint", attestor_key_fingerprint)
        object.__setattr__(self, "_jti", jti)
        object.__setattr__(self, "_iss", iss)
        object.__setattr__(self, "_aud", aud)
        object.__setattr__(self, "_sub", sub)
        object.__setattr__(self, "_profile", profile)
        object.__setattr__(self, "_profile_digest", profile_digest)
        object.__setattr__(self, "_content_digest", content_digest)
        object.__setattr__(self, "_gen", gen)
        object.__setattr__(self, "_prev", prev)
        object.__setattr__(self, "_iat", iat)
        object.__setattr__(self, "_nbf", nbf)
        object.__setattr__(self, "_exp", exp)
        object.__setattr__(self, "_digest", digest)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_trust", trust)

    @property
    def version(self) -> int:
        return self._version

    @property
    def attestor_key_id(self) -> str:
        return self._attestor_key_id

    @property
    def attestor_key_fingerprint(self) -> bytes:
        return self._attestor_key_fingerprint

    @property
    def jti(self) -> str:
        return self._jti

    @property
    def iss(self) -> str:
        return self._iss

    @property
    def aud(self) -> str:
        return self._aud

    @property
    def sub(self) -> str:
        return self._sub

    @property
    def profile(self) -> str:
        return self._profile

    @property
    def profile_digest(self) -> bytes:
        return self._profile_digest

    @property
    def content_digest(self) -> bytes:
        return self._content_digest

    @property
    def gen(self) -> int:
        return self._gen

    @property
    def prev(self) -> bytes:
        return self._prev

    @property
    def iat(self) -> int:
        return self._iat

    @property
    def nbf(self) -> int:
        return self._nbf

    @property
    def exp(self) -> int:
        return self._exp

    @property
    def digest(self) -> bytes:
        return self._digest

    @property
    def verification(self) -> str:
        return self._verification

    @property
    def trust(self) -> str:
        return self._trust

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ContentAssertionFacts) and (
            self._version, self._attestor_key_id, self._attestor_key_fingerprint, self._jti, self._iss, self._aud, self._sub, self._profile, self._profile_digest, self._content_digest, self._gen, self._prev, self._iat, self._nbf, self._exp, self._digest, self._verification, self._trust,
        ) == (
            other._version, other._attestor_key_id, other._attestor_key_fingerprint, other._jti, other._iss, other._aud, other._sub, other._profile, other._profile_digest, other._content_digest, other._gen, other._prev, other._iat, other._nbf, other._exp, other._digest, other._verification, other._trust,
        )

    def __hash__(self) -> int:
        return hash((self._version, self._attestor_key_id, self._attestor_key_fingerprint, self._jti, self._iss, self._aud, self._sub, self._profile, self._profile_digest, self._content_digest, self._gen, self._prev, self._iat, self._nbf, self._exp, self._digest, self._verification, self._trust,))
