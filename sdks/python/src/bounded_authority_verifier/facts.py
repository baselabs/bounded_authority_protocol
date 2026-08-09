"""Value-bearing, redacted, non-authorizing facts (protocol-v1.md § Public verification contract,
REQ1-VERIFY-facts-redacted, REQ1-VERIFY-facts-not-credentials).

No generic encoder, no ``asdict``, no authorization/decision method (AGENTS rule 1). Grant/Envelope/
Export carry ``authorization="not_evaluated"``; Chain/Anchor/Transition carry
``trust="not_evaluated"``.

These are frozen dataclasses — value objects. They expose their fields for inspection but carry no
behavior that converts them into a credential or a decision.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GrantFacts:
    """GrantFacts (protocol-v1.md:322-324): version, issuer, grant_id, issuer-key fingerprint (raw 32),
    holder thumbprint (raw 32), matched audience, grant times, authorization=not_evaluated."""

    version: int
    issuer: str
    grant_id: str
    issuer_key_fingerprint: bytes
    holder_thumbprint: bytes
    matched_audience: str
    issued_at: int
    not_before: int
    expires_at: int
    authorization: str = "not_evaluated"


@dataclass(frozen=True)
class EnvelopeFacts:
    """EnvelopeFacts (protocol-v1.md:342-348): GrantFacts + proof_id, invocation_id, operation, uri,
    grant hash (ath raw 32), request hash (ba_req raw 32), proof issued_at."""

    version: int
    issuer: str
    grant_id: str
    issuer_key_fingerprint: bytes
    holder_thumbprint: bytes
    matched_audience: str
    grant_issued_at: int
    grant_not_before: int
    grant_expires_at: int
    proof_id: str
    invocation_id: str
    operation: str
    uri: str
    grant_hash: bytes
    request_hash: bytes
    proof_issued_at: int
    authorization: str = "not_evaluated"


@dataclass(frozen=True)
class ChainFacts:
    """ChainFacts (ADR 0004:84-87; REQ1-CHAIN-facts-shape): value-bearing, trust=not_evaluated."""

    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    trust: str = "not_evaluated"


@dataclass(frozen=True)
class AnchorFacts:
    """AnchorFacts (protocol-v1.md § Historical anchor verify): trust=not_evaluated."""

    anchor_id: str
    anchored_at: int
    chain_id: str
    sequence: int
    chain_hash: bytes
    key_id: str
    key_fingerprint: bytes
    trust: str = "not_evaluated"


@dataclass(frozen=True)
class KeyTransitionFacts:
    """KeyTransitionFacts (ADR 0004:44-55): trust=not_evaluated."""

    transition_id: str
    chain_id: str
    effective_at: int
    from_key_id: str
    from_key_fingerprint: bytes
    to_key_id: str
    to_key_fingerprint: bytes
    trust: str = "not_evaluated"


@dataclass(frozen=True)
class AnchoredExportFacts:
    """AnchoredExportFacts (protocol-v1.md:437-440): the ONLY facts type with an authorization field."""

    object_version: str
    chain_id: str
    first_sequence: int
    last_sequence: int
    row_count: int
    transition_count: int
    digest: bytes
    trust: str = "not_evaluated"
    authorization: str = "not_evaluated"


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
