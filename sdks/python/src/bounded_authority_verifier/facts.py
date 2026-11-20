"""Value-bearing, redacted, non-authorizing facts (spec/bap-v1.md § Public verification contract,
REQ1-VERIFY-facts-redacted, REQ1-VERIFY-facts-not-credentials).

The eight public verification facts types are GrantFacts, EnvelopeFacts, ChainFacts,
AnchorFacts, KeyTransitionFacts, AnchoredExportFacts, AttestationFacts, and ContentAssertionFacts.
The sibling profiles follow spec/bap-role-attestation-v1.md and spec/bap-content-assertion-v1.md.

There is no generic encoder, ``asdict``, or authorization/decision method. GrantFacts,
EnvelopeFacts, and AnchoredExportFacts carry ``authorization="not_evaluated"``. ChainFacts,
AnchorFacts, KeyTransitionFacts, AnchoredExportFacts, AttestationFacts, and ContentAssertionFacts
carry ``trust="not_evaluated"``.

Verified facts are slotted value objects with read-only properties. They refuse generic
enumeration, pickling, and copy reduction; callers read named properties explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from . import _inspect
from .json_alg import JObject


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
    "GrantFacts (spec/bap-v1.md): version, issuer, grant_id, issuer-key fingerprint (raw 32),\nholder thumbprint (raw 32), matched audience, grant times, authorization=not_evaluated."

    __slots__ = (
        "_version",
        "_issuer",
        "_grant_id",
        "_issuer_key_fingerprint",
        "_holder_thumbprint",
        "_matched_audience",
        "_issued_at",
        "_not_before",
        "_expires_at",
        "_authorization",
    )
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
        authorization: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def issuer(self) -> str:
        """Signed issuer identifier."""
        return self._issuer

    @property
    def grant_id(self) -> str:
        """Signed grant identifier."""
        return self._grant_id

    @property
    def issuer_key_fingerprint(self) -> bytes:
        """Raw SHA-256 fingerprint of the verified issuer public key."""
        return self._issuer_key_fingerprint

    @property
    def holder_thumbprint(self) -> bytes:
        """Raw RFC 7638 thumbprint of the bound holder public key."""
        return self._holder_thumbprint

    @property
    def matched_audience(self) -> str:
        """Caller-supplied audience matched by verification."""
        return self._matched_audience

    @property
    def issued_at(self) -> int:
        """Signed issuance time in Unix seconds."""
        return self._issued_at

    @property
    def not_before(self) -> int:
        """Inclusive validity-window start in Unix seconds."""
        return self._not_before

    @property
    def expires_at(self) -> int:
        """Exclusive validity-window end in Unix seconds."""
        return self._expires_at

    @property
    def authorization(self) -> str:
        """Fixed not_evaluated marker; successful verification grants no authority."""
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
            self._version,
            self._issuer,
            self._grant_id,
            self._issuer_key_fingerprint,
            self._holder_thumbprint,
            self._matched_audience,
            self._issued_at,
            self._not_before,
            self._expires_at,
            self._authorization,
        ) == (
            other._version,
            other._issuer,
            other._grant_id,
            other._issuer_key_fingerprint,
            other._holder_thumbprint,
            other._matched_audience,
            other._issued_at,
            other._not_before,
            other._expires_at,
            other._authorization,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._issuer,
                self._grant_id,
                self._issuer_key_fingerprint,
                self._holder_thumbprint,
                self._matched_audience,
                self._issued_at,
                self._not_before,
                self._expires_at,
                self._authorization,
            )
        )


class EnvelopeFacts(_Facts):
    "EnvelopeFacts (spec/bap-v1.md): GrantFacts + proof_id, invocation_id, operation, uri,\ngrant hash (ath raw 32), request hash (ba_req raw 32), proof issued_at."

    __slots__ = (
        "_version",
        "_issuer",
        "_grant_id",
        "_issuer_key_fingerprint",
        "_holder_thumbprint",
        "_matched_audience",
        "_grant_issued_at",
        "_grant_not_before",
        "_grant_expires_at",
        "_proof_id",
        "_invocation_id",
        "_operation",
        "_uri",
        "_grant_hash",
        "_request_hash",
        "_proof_issued_at",
        "_authorization",
    )
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
        authorization: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def issuer(self) -> str:
        """Signed issuer identifier."""
        return self._issuer

    @property
    def grant_id(self) -> str:
        """Signed grant identifier."""
        return self._grant_id

    @property
    def issuer_key_fingerprint(self) -> bytes:
        """Raw SHA-256 fingerprint of the verified issuer public key."""
        return self._issuer_key_fingerprint

    @property
    def holder_thumbprint(self) -> bytes:
        """Raw RFC 7638 thumbprint of the bound holder public key."""
        return self._holder_thumbprint

    @property
    def matched_audience(self) -> str:
        """Caller-supplied audience matched by verification."""
        return self._matched_audience

    @property
    def grant_issued_at(self) -> int:
        """The grant issued at carried by this value."""
        return self._grant_issued_at

    @property
    def grant_not_before(self) -> int:
        """The grant not before carried by this value."""
        return self._grant_not_before

    @property
    def grant_expires_at(self) -> int:
        """The grant expires at carried by this value."""
        return self._grant_expires_at

    @property
    def proof_id(self) -> str:
        """The proof id carried by this value."""
        return self._proof_id

    @property
    def invocation_id(self) -> str:
        """The invocation id carried by this value."""
        return self._invocation_id

    @property
    def operation(self) -> str:
        """The operation carried by this value."""
        return self._operation

    @property
    def uri(self) -> str:
        """Normalized request target verified against the expected context."""
        return self._uri

    @property
    def grant_hash(self) -> bytes:
        """SHA-256 digest of the exact grant compact bytes."""
        return self._grant_hash

    @property
    def request_hash(self) -> bytes:
        """Domain-separated digest of the operation and tagged request arguments."""
        return self._request_hash

    @property
    def proof_issued_at(self) -> int:
        """The proof issued at carried by this value."""
        return self._proof_issued_at

    @property
    def authorization(self) -> str:
        """Fixed not_evaluated marker; successful verification grants no authority."""
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
            self._version,
            self._issuer,
            self._grant_id,
            self._issuer_key_fingerprint,
            self._holder_thumbprint,
            self._matched_audience,
            self._grant_issued_at,
            self._grant_not_before,
            self._grant_expires_at,
            self._proof_id,
            self._invocation_id,
            self._operation,
            self._uri,
            self._grant_hash,
            self._request_hash,
            self._proof_issued_at,
            self._authorization,
        ) == (
            other._version,
            other._issuer,
            other._grant_id,
            other._issuer_key_fingerprint,
            other._holder_thumbprint,
            other._matched_audience,
            other._grant_issued_at,
            other._grant_not_before,
            other._grant_expires_at,
            other._proof_id,
            other._invocation_id,
            other._operation,
            other._uri,
            other._grant_hash,
            other._request_hash,
            other._proof_issued_at,
            other._authorization,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._issuer,
                self._grant_id,
                self._issuer_key_fingerprint,
                self._holder_thumbprint,
                self._matched_audience,
                self._grant_issued_at,
                self._grant_not_before,
                self._grant_expires_at,
                self._proof_id,
                self._invocation_id,
                self._operation,
                self._uri,
                self._grant_hash,
                self._request_hash,
                self._proof_issued_at,
                self._authorization,
            )
        )


class ChainFacts(_Facts):
    "Consumption-row facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16."

    __slots__ = (
        "_version",
        "_chain_id",
        "_first_sequence",
        "_last_sequence",
        "_row_count",
        "_previous_hash",
        "_last_hash",
        "_verification",
        "_trust",
    )
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
        verification: str = "boundary_consistent",
        trust: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def chain_id(self) -> str:
        """The chain id carried by this value."""
        return self._chain_id

    @property
    def first_sequence(self) -> int:
        """The first sequence carried by this value."""
        return self._first_sequence

    @property
    def last_sequence(self) -> int:
        """The last sequence carried by this value."""
        return self._last_sequence

    @property
    def row_count(self) -> int:
        """The row count carried by this value."""
        return self._row_count

    @property
    def previous_hash(self) -> bytes:
        """The previous hash carried by this value."""
        return self._previous_hash

    @property
    def last_hash(self) -> bytes:
        """The last hash carried by this value."""
        return self._last_hash

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
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
            self._version,
            self._chain_id,
            self._first_sequence,
            self._last_sequence,
            self._row_count,
            self._previous_hash,
            self._last_hash,
            self._verification,
            self._trust,
        ) == (
            other._version,
            other._chain_id,
            other._first_sequence,
            other._last_sequence,
            other._row_count,
            other._previous_hash,
            other._last_hash,
            other._verification,
            other._trust,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._chain_id,
                self._first_sequence,
                self._last_sequence,
                self._row_count,
                self._previous_hash,
                self._last_hash,
                self._verification,
                self._trust,
            )
        )


class AnchorFacts(_Facts):
    "Boundary-anchor facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16: the key binding\nis its fingerprint, without a key identifier."

    __slots__ = (
        "_version",
        "_anchor_id",
        "_anchored_at",
        "_chain_id",
        "_sequence",
        "_chain_hash",
        "_key_fingerprint",
        "_verification",
        "_trust",
    )
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
        verification: str = "signature_and_window",
        trust: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def anchor_id(self) -> str:
        """The anchor id carried by this value."""
        return self._anchor_id

    @property
    def anchored_at(self) -> int:
        """The anchored at carried by this value."""
        return self._anchored_at

    @property
    def chain_id(self) -> str:
        """The chain id carried by this value."""
        return self._chain_id

    @property
    def sequence(self) -> int:
        """The sequence carried by this value."""
        return self._sequence

    @property
    def chain_hash(self) -> bytes:
        """The chain hash carried by this value."""
        return self._chain_hash

    @property
    def key_fingerprint(self) -> bytes:
        """The key fingerprint carried by this value."""
        return self._key_fingerprint

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
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
            self._version,
            self._anchor_id,
            self._anchored_at,
            self._chain_id,
            self._sequence,
            self._chain_hash,
            self._key_fingerprint,
            self._verification,
            self._trust,
        ) == (
            other._version,
            other._anchor_id,
            other._anchored_at,
            other._chain_id,
            other._sequence,
            other._chain_hash,
            other._key_fingerprint,
            other._verification,
            other._trust,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._anchor_id,
                self._anchored_at,
                self._chain_id,
                self._sequence,
                self._chain_hash,
                self._key_fingerprint,
                self._verification,
                self._trust,
            )
        )


class KeyTransitionFacts(_Facts):
    "Authenticated key-transition facts with trust=not_evaluated.\n\nFields follow spec/bap-v1.md §16: key bindings\nare current and next fingerprints, without key identifiers."

    __slots__ = (
        "_version",
        "_transition_id",
        "_chain_id",
        "_effective_at",
        "_current_key_fingerprint",
        "_next_key_fingerprint",
        "_verification",
        "_trust",
    )
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
        verification: str = "authenticated_transition",
        trust: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def transition_id(self) -> str:
        """The transition id carried by this value."""
        return self._transition_id

    @property
    def chain_id(self) -> str:
        """The chain id carried by this value."""
        return self._chain_id

    @property
    def effective_at(self) -> int:
        """The effective at carried by this value."""
        return self._effective_at

    @property
    def current_key_fingerprint(self) -> bytes:
        """The current key fingerprint carried by this value."""
        return self._current_key_fingerprint

    @property
    def next_key_fingerprint(self) -> bytes:
        """The next key fingerprint carried by this value."""
        return self._next_key_fingerprint

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
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
            self._version,
            self._transition_id,
            self._chain_id,
            self._effective_at,
            self._current_key_fingerprint,
            self._next_key_fingerprint,
            self._verification,
            self._trust,
        ) == (
            other._version,
            other._transition_id,
            other._chain_id,
            other._effective_at,
            other._current_key_fingerprint,
            other._next_key_fingerprint,
            other._verification,
            other._trust,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._transition_id,
                self._chain_id,
                self._effective_at,
                self._current_key_fingerprint,
                self._next_key_fingerprint,
                self._verification,
                self._trust,
            )
        )


class AnchoredExportFacts(_Facts):
    "Anchored-export facts carrying both trust and authorization=not_evaluated.\n\nFields follow spec/bap-v1.md §16."

    __slots__ = (
        "_version",
        "_chain_id",
        "_first_sequence",
        "_last_sequence",
        "_row_count",
        "_previous_hash",
        "_last_hash",
        "_digest",
        "_start_anchor_id",
        "_start_anchored_at",
        "_start_key_fingerprint",
        "_end_anchor_id",
        "_end_anchored_at",
        "_end_key_fingerprint",
        "_transition_count",
        "_object_version",
        "_verification",
        "_trust",
        "_authorization",
    )
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
        verification: str = "anchored_export",
        trust: str = "not_evaluated",
        authorization: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def chain_id(self) -> str:
        """The chain id carried by this value."""
        return self._chain_id

    @property
    def first_sequence(self) -> int:
        """The first sequence carried by this value."""
        return self._first_sequence

    @property
    def last_sequence(self) -> int:
        """The last sequence carried by this value."""
        return self._last_sequence

    @property
    def row_count(self) -> int:
        """The row count carried by this value."""
        return self._row_count

    @property
    def previous_hash(self) -> bytes:
        """The previous hash carried by this value."""
        return self._previous_hash

    @property
    def last_hash(self) -> bytes:
        """The last hash carried by this value."""
        return self._last_hash

    @property
    def digest(self) -> bytes:
        """Digest of the exact canonical evidence bytes."""
        return self._digest

    @property
    def start_anchor_id(self) -> str:
        """The start anchor id carried by this value."""
        return self._start_anchor_id

    @property
    def start_anchored_at(self) -> int:
        """The start anchored at carried by this value."""
        return self._start_anchored_at

    @property
    def start_key_fingerprint(self) -> bytes:
        """The start key fingerprint carried by this value."""
        return self._start_key_fingerprint

    @property
    def end_anchor_id(self) -> str:
        """The end anchor id carried by this value."""
        return self._end_anchor_id

    @property
    def end_anchored_at(self) -> int:
        """The end anchored at carried by this value."""
        return self._end_anchored_at

    @property
    def end_key_fingerprint(self) -> bytes:
        """The end key fingerprint carried by this value."""
        return self._end_key_fingerprint

    @property
    def transition_count(self) -> int:
        """The transition count carried by this value."""
        return self._transition_count

    @property
    def object_version(self) -> str:
        """Caller-supplied immutable archive object version."""
        return self._object_version

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
        return self._trust

    @property
    def authorization(self) -> str:
        """Fixed not_evaluated marker; successful verification grants no authority."""
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
            self._version,
            self._chain_id,
            self._first_sequence,
            self._last_sequence,
            self._row_count,
            self._previous_hash,
            self._last_hash,
            self._digest,
            self._start_anchor_id,
            self._start_anchored_at,
            self._start_key_fingerprint,
            self._end_anchor_id,
            self._end_anchored_at,
            self._end_key_fingerprint,
            self._transition_count,
            self._object_version,
            self._verification,
            self._trust,
            self._authorization,
        ) == (
            other._version,
            other._chain_id,
            other._first_sequence,
            other._last_sequence,
            other._row_count,
            other._previous_hash,
            other._last_hash,
            other._digest,
            other._start_anchor_id,
            other._start_anchored_at,
            other._start_key_fingerprint,
            other._end_anchor_id,
            other._end_anchored_at,
            other._end_key_fingerprint,
            other._transition_count,
            other._object_version,
            other._verification,
            other._trust,
            other._authorization,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._chain_id,
                self._first_sequence,
                self._last_sequence,
                self._row_count,
                self._previous_hash,
                self._last_hash,
                self._digest,
                self._start_anchor_id,
                self._start_anchored_at,
                self._start_key_fingerprint,
                self._end_anchor_id,
                self._end_anchored_at,
                self._end_key_fingerprint,
                self._transition_count,
                self._object_version,
                self._verification,
                self._trust,
                self._authorization,
            )
        )


@dataclass(frozen=True)
class GrantDecoded:
    """Decode surface: structural grant facts (verification=not_evaluated)."""

    version: int
    key_id: str
    issuer: str
    grant_id: str
    audiences: tuple[str, ...]
    issued_at: int
    not_before: int
    expires_at: int
    holder_thumbprint: bytes
    operations: tuple[JObject, ...]
    verification: str = "not_evaluated"

    def __repr__(self) -> str:
        if type(self.version) is not int or self.version not in (1, 2, 3):
            return "#unrenderable"
        operations = _inspect.operations(self.operations, self.version)
        return _inspect.render(
            _inspect.structure(
                f"BoundedAuthorityProtocol.V{self.version}.DecodedGrant",
                [
                    ("version", _inspect.scalar(self.version)),
                    ("key_id", _inspect.text(self.key_id)),
                    ("issuer", _inspect.text(self.issuer)),
                    ("grant_id", _inspect.text(self.grant_id)),
                    ("audiences", _inspect.mapped_listing(self.audiences, _inspect.text)),
                    ("issued_at", _inspect.scalar(self.issued_at)),
                    ("not_before", _inspect.scalar(self.not_before)),
                    ("expires_at", _inspect.scalar(self.expires_at)),
                    ("holder_thumbprint", _inspect.raw(self.holder_thumbprint)),
                    ("operations", operations),
                    ("verification", _inspect.atom(self.verification)),
                ],
            )
        )

    __str__ = __repr__


class ProofDecoded(_Facts):
    """Unverified decoded values; generic enumeration and reduction are refused."""

    __slots__ = (
        "_version",
        "_proof_id",
        "_method",
        "_target_uri",
        "_issued_at",
        "_nonce",
        "_invocation_id",
        "_operation",
        "_grant_hash",
        "_request_hash",
        "_holder_public_key",
        "_holder_thumbprint",
        "_verification",
    )
    _version: int
    _proof_id: str
    _method: str
    _target_uri: str
    _issued_at: int
    _nonce: str | None
    _invocation_id: str
    _operation: str
    _grant_hash: bytes
    _request_hash: bytes
    _holder_public_key: bytes
    _holder_thumbprint: bytes
    _verification: str

    def __init__(
        self,
        version: int,
        proof_id: str,
        method: str,
        target_uri: str,
        issued_at: int,
        nonce: str | None,
        invocation_id: str,
        operation: str,
        grant_hash: bytes,
        request_hash: bytes,
        holder_public_key: bytes,
        holder_thumbprint: bytes,
        verification: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Decoded values cannot be initialized twice")
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_proof_id", proof_id)
        object.__setattr__(self, "_method", method)
        object.__setattr__(self, "_target_uri", target_uri)
        object.__setattr__(self, "_issued_at", issued_at)
        object.__setattr__(self, "_nonce", nonce)
        object.__setattr__(self, "_invocation_id", invocation_id)
        object.__setattr__(self, "_operation", operation)
        object.__setattr__(self, "_grant_hash", grant_hash)
        object.__setattr__(self, "_request_hash", request_hash)
        object.__setattr__(self, "_holder_public_key", holder_public_key)
        object.__setattr__(self, "_holder_thumbprint", holder_thumbprint)
        object.__setattr__(self, "_verification", verification)

    @property
    def version(self) -> int:
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def proof_id(self) -> str:
        """The proof id carried by this value."""
        return self._proof_id

    @property
    def method(self) -> str:
        """The method carried by this value."""
        return self._method

    @property
    def target_uri(self) -> str:
        """The target uri carried by this value."""
        return self._target_uri

    @property
    def issued_at(self) -> int:
        """Signed issuance time in Unix seconds."""
        return self._issued_at

    @property
    def nonce(self) -> str | None:
        """Exact signed nonce when present, otherwise None."""
        return self._nonce

    @property
    def invocation_id(self) -> str:
        """The invocation id carried by this value."""
        return self._invocation_id

    @property
    def operation(self) -> str:
        """The operation carried by this value."""
        return self._operation

    @property
    def grant_hash(self) -> bytes:
        """SHA-256 digest of the exact grant compact bytes."""
        return self._grant_hash

    @property
    def request_hash(self) -> bytes:
        """Domain-separated digest of the operation and tagged request arguments."""
        return self._request_hash

    @property
    def holder_public_key(self) -> bytes:
        """Public key carried by the proof; decoding alone does not establish trust."""
        return self._holder_public_key

    @property
    def holder_thumbprint(self) -> bytes:
        """Raw RFC 7638 thumbprint of the bound holder public key."""
        return self._holder_thumbprint

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    def __repr__(self) -> str:
        if type(self.version) is not int or self.version not in (1, 2, 3):
            return "#unrenderable"
        return (
            f"#BoundedAuthorityProtocol.V{self.version}.DecodedProof<"
            + "version: "
            + str(self.version)
            + ", "
            + "proof_id: "
            + _inspect.string(self.proof_id)
            + ", "
            + "method: "
            + _inspect.string(self.method)
            + ", "
            + "target_uri: "
            + _inspect.string(self.target_uri)
            + ", "
            + "issued_at: "
            + _inspect.render(_inspect.scalar(self.issued_at))
            + ", "
            + "nonce: "
            + ("nil" if self.nonce is None else ":redacted")
            + ", "
            + "invocation_id: "
            + _inspect.string(self.invocation_id)
            + ", "
            + "operation: "
            + _inspect.string(self.operation)
            + ", "
            + "grant_hash: "
            + _inspect.binary(self.grant_hash)
            + ", "
            + "request_hash: "
            + _inspect.binary(self.request_hash)
            + ", "
            + "holder_public_key: "
            + _inspect.binary(self.holder_public_key)
            + ", "
            + "holder_thumbprint: "
            + _inspect.binary(self.holder_thumbprint)
            + ", "
            + "verification: "
            + _inspect.render(_inspect.atom(self.verification))
            + ">"
        )

    __str__ = __repr__


@dataclass(frozen=True)
class KeyLocator:
    """Locator surface: header-only key id (trust=not_evaluated)."""

    key_id: str
    trust: str = "not_evaluated"


@dataclass(frozen=True)
class AttestationDecoded:
    """Decode surface: structural role-attestation facts (verification=not_evaluated).

    ``public_key`` is the raw 32-byte subject public key as specified in
    spec/bap-role-attestation-v1.md §2 (REQ-RA1-CLAIM-public-key).
    Derived digests belong to the facts surface, not decode.
    """

    attestor_key_id: str
    jti: str
    subject_key_id: str
    public_key: bytes  # raw 32
    role: str
    nbf: int
    exp: int
    verification: str = "not_evaluated"

    def __repr__(self) -> str:
        return _inspect.render(
            _inspect.structure(
                "BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation",
                [
                    ("version", _inspect.scalar(1)),
                    ("attestor_key_id", _inspect.text(self.attestor_key_id)),
                    ("jti", _inspect.text(self.jti)),
                    ("key_id", _inspect.text(self.subject_key_id)),
                    ("public_key", _inspect.raw(self.public_key)),
                    ("role", _inspect.text(self.role)),
                    ("nbf", _inspect.scalar(self.nbf)),
                    ("exp", _inspect.scalar(self.exp)),
                    ("verification", _inspect.atom(self.verification)),
                ],
            )
        )

    __str__ = __repr__


class AttestationFacts(_Facts):
    "AttestationFacts (spec/bap-role-attestation-v1.md §3): value-bearing, redacted,\nnon-authorizing. Fingerprints are RFC 7638 Ed25519 thumbprints (raw 32): never a hash of\nraw key bytes. No raw key material, no signature, no decision (REQ-RA1-VERIFY-facts,\nREQ-RA1-VERIFY-facts-non-authorizing)."

    __slots__ = (
        "_attestor_key_id",
        "_attestor_key_fingerprint",
        "_subject_key_id",
        "_subject_key_fingerprint",
        "_role",
        "_jti",
        "_nbf",
        "_exp",
        "_verification",
        "_trust",
    )
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
        verification: str = "signature_and_window",
        trust: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_attestor_key_id"):
            raise TypeError("Facts cannot be initialized twice")
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
        """The attestor key id carried by this value."""
        return self._attestor_key_id

    @property
    def attestor_key_fingerprint(self) -> bytes:
        """The attestor key fingerprint carried by this value."""
        return self._attestor_key_fingerprint

    @property
    def subject_key_id(self) -> str:
        """The subject key id carried by this value."""
        return self._subject_key_id

    @property
    def subject_key_fingerprint(self) -> bytes:
        """The subject key fingerprint carried by this value."""
        return self._subject_key_fingerprint

    @property
    def role(self) -> str:
        """Exact attested role; it does not select a trusted key."""
        return self._role

    @property
    def jti(self) -> str:
        """Signed assertion or attestation identifier."""
        return self._jti

    @property
    def nbf(self) -> int:
        """Inclusive validity-window start in Unix seconds."""
        return self._nbf

    @property
    def exp(self) -> int:
        """Exclusive validity-window end in Unix seconds."""
        return self._exp

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
        return self._trust

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AttestationFacts) and (
            self._attestor_key_id,
            self._attestor_key_fingerprint,
            self._subject_key_id,
            self._subject_key_fingerprint,
            self._role,
            self._jti,
            self._nbf,
            self._exp,
            self._verification,
            self._trust,
        ) == (
            other._attestor_key_id,
            other._attestor_key_fingerprint,
            other._subject_key_id,
            other._subject_key_fingerprint,
            other._role,
            other._jti,
            other._nbf,
            other._exp,
            other._verification,
            other._trust,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._attestor_key_id,
                self._attestor_key_fingerprint,
                self._subject_key_id,
                self._subject_key_fingerprint,
                self._role,
                self._jti,
                self._nbf,
                self._exp,
                self._verification,
                self._trust,
            )
        )


class ContentAssertionDecoded(_Facts):
    """Unverified decoded values; generic enumeration and reduction are refused."""

    __slots__ = (
        "_version",
        "_attestor_key_id",
        "_jti",
        "_iss",
        "_aud",
        "_sub",
        "_profile",
        "_profile_digest",
        "_content_digest",
        "_gen",
        "_prev",
        "_iat",
        "_nbf",
        "_exp",
        "_verification",
    )
    _version: int
    _attestor_key_id: str
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
    _verification: str

    def __init__(
        self,
        version: int,
        attestor_key_id: str,
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
        verification: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Decoded values cannot be initialized twice")
        object.__setattr__(self, "_version", version)
        object.__setattr__(self, "_attestor_key_id", attestor_key_id)
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
        object.__setattr__(self, "_verification", verification)

    @property
    def version(self) -> int:
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def attestor_key_id(self) -> str:
        """The attestor key id carried by this value."""
        return self._attestor_key_id

    @property
    def jti(self) -> str:
        """Signed assertion or attestation identifier."""
        return self._jti

    @property
    def iss(self) -> str:
        """Signed issuer identifier."""
        return self._iss

    @property
    def aud(self) -> str:
        """Signed audience identifier."""
        return self._aud

    @property
    def sub(self) -> str:
        """Signed lineage subject identifier."""
        return self._sub

    @property
    def profile(self) -> str:
        """The profile carried by this value."""
        return self._profile

    @property
    def profile_digest(self) -> bytes:
        """Raw SHA-256 digest identifying the semantic profile."""
        return self._profile_digest

    @property
    def content_digest(self) -> bytes:
        """Domain-separated digest of the external content bytes."""
        return self._content_digest

    @property
    def gen(self) -> int:
        """Positive lineage generation; the first generation is one."""
        return self._gen

    @property
    def prev(self) -> bytes:
        """Predecessor assertion digest; zero bytes for generation one."""
        return self._prev

    @property
    def iat(self) -> int:
        """Signed issuance time in Unix seconds."""
        return self._iat

    @property
    def nbf(self) -> int:
        """Inclusive validity-window start in Unix seconds."""
        return self._nbf

    @property
    def exp(self) -> int:
        """Exclusive validity-window end in Unix seconds."""
        return self._exp

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion<redacted>"

    __str__ = __repr__


class ContentAssertionFacts(_Facts):
    "Verified, value-bearing, redacted content-assertion facts.\n\nThis value remains non-authorizing and caller-provenanced. It contains no raw public key,\nsignature, decision, or authorization marker."

    __slots__ = (
        "_version",
        "_attestor_key_id",
        "_attestor_key_fingerprint",
        "_jti",
        "_iss",
        "_aud",
        "_sub",
        "_profile",
        "_profile_digest",
        "_content_digest",
        "_gen",
        "_prev",
        "_iat",
        "_nbf",
        "_exp",
        "_digest",
        "_verification",
        "_trust",
    )
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
        verification: str = "signature_and_window",
        trust: str = "not_evaluated",
    ) -> None:
        if hasattr(self, "_version"):
            raise TypeError("Facts cannot be initialized twice")
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
        """Contract-major or sibling-profile version carried by this value."""
        return self._version

    @property
    def attestor_key_id(self) -> str:
        """The attestor key id carried by this value."""
        return self._attestor_key_id

    @property
    def attestor_key_fingerprint(self) -> bytes:
        """The attestor key fingerprint carried by this value."""
        return self._attestor_key_fingerprint

    @property
    def jti(self) -> str:
        """Signed assertion or attestation identifier."""
        return self._jti

    @property
    def iss(self) -> str:
        """Signed issuer identifier."""
        return self._iss

    @property
    def aud(self) -> str:
        """Signed audience identifier."""
        return self._aud

    @property
    def sub(self) -> str:
        """Signed lineage subject identifier."""
        return self._sub

    @property
    def profile(self) -> str:
        """The profile carried by this value."""
        return self._profile

    @property
    def profile_digest(self) -> bytes:
        """Raw SHA-256 digest identifying the semantic profile."""
        return self._profile_digest

    @property
    def content_digest(self) -> bytes:
        """Domain-separated digest of the external content bytes."""
        return self._content_digest

    @property
    def gen(self) -> int:
        """Positive lineage generation; the first generation is one."""
        return self._gen

    @property
    def prev(self) -> bytes:
        """Predecessor assertion digest; zero bytes for generation one."""
        return self._prev

    @property
    def iat(self) -> int:
        """Signed issuance time in Unix seconds."""
        return self._iat

    @property
    def nbf(self) -> int:
        """Inclusive validity-window start in Unix seconds."""
        return self._nbf

    @property
    def exp(self) -> int:
        """Exclusive validity-window end in Unix seconds."""
        return self._exp

    @property
    def digest(self) -> bytes:
        """Digest of the exact canonical evidence bytes."""
        return self._digest

    @property
    def verification(self) -> str:
        """Checks completed for this value; decoding alone establishes no signature validity."""
        return self._verification

    @property
    def trust(self) -> str:
        """Fixed not_evaluated marker; trust remains the caller's responsibility."""
        return self._trust

    def __repr__(self) -> str:
        return "#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ContentAssertionFacts) and (
            self._version,
            self._attestor_key_id,
            self._attestor_key_fingerprint,
            self._jti,
            self._iss,
            self._aud,
            self._sub,
            self._profile,
            self._profile_digest,
            self._content_digest,
            self._gen,
            self._prev,
            self._iat,
            self._nbf,
            self._exp,
            self._digest,
            self._verification,
            self._trust,
        ) == (
            other._version,
            other._attestor_key_id,
            other._attestor_key_fingerprint,
            other._jti,
            other._iss,
            other._aud,
            other._sub,
            other._profile,
            other._profile_digest,
            other._content_digest,
            other._gen,
            other._prev,
            other._iat,
            other._nbf,
            other._exp,
            other._digest,
            other._verification,
            other._trust,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._version,
                self._attestor_key_id,
                self._attestor_key_fingerprint,
                self._jti,
                self._iss,
                self._aud,
                self._sub,
                self._profile,
                self._profile_digest,
                self._content_digest,
                self._gen,
                self._prev,
                self._iat,
                self._nbf,
                self._exp,
                self._digest,
                self._verification,
                self._trust,
            )
        )
