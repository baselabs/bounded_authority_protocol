"""Offline host example for the candidate action approval profile."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass
from hmac import compare_digest

from bounded_authority_verifier import JString, Ok, base64url_encode
from bounded_authority_verifier.action_approval import (
    ApprovalContext,
    TrustSnapshot,
    VerifiedApprovalFacts,
    verify_approval_eddsa,
)

HOST_SCHEMA = """
CREATE TABLE requests (
    id TEXT PRIMARY KEY, revision BLOB NOT NULL, effect BLOB NOT NULL
);
CREATE TABLE artifact_claims (
    trust_domain TEXT, issuer TEXT, artifact_id TEXT,
    PRIMARY KEY (trust_domain, issuer, artifact_id)
) WITHOUT ROWID;
CREATE TABLE request_claims (
    request_id TEXT, revision BLOB, PRIMARY KEY (request_id, revision)
) WITHOUT ROWID;
CREATE TABLE local_effects (identity TEXT PRIMARY KEY, effect BLOB NOT NULL);
CREATE TABLE intents (
    identity TEXT PRIMARY KEY, effect BLOB NOT NULL, delivered INTEGER NOT NULL DEFAULT 0
);
"""
DESTINATION_SCHEMA = "CREATE TABLE effects (identity TEXT PRIMARY KEY, effect BLOB NOT NULL);"


@dataclass(frozen=True)
class Effect:
    subject: str
    action: str
    resources: tuple[str, ...]

    def encode(self) -> bytes:
        resources = sorted(self.resources, key=str.encode)
        if len(resources) != len(set(resources)):
            raise ValueError("duplicate resource")
        return json.dumps(
            [self.subject, self.action, resources], ensure_ascii=False, separators=(",", ":")
        ).encode()


@dataclass(frozen=True)
class Request:
    request_id: str
    revision: bytes
    effect: Effect


@dataclass(frozen=True, repr=False)
class Policy:
    audience: str
    trust_domain: str
    roles: tuple[str, ...]
    snapshot: TrustSnapshot
    max_staleness: int
    max_lifetime: int


class ClaimRefused(Exception):
    pass


def context_for(request: Request, policy: Policy, now: int) -> ApprovalContext:
    """Build independent expected inputs from the operation and local configuration."""
    return ApprovalContext(
        trust_domain=policy.trust_domain,
        audience=policy.audience,
        request_id=request.request_id,
        revision_digest=request.revision,
        subject=request.effect.subject,
        action=request.effect.action,
        resources=request.effect.resources,
        roles=policy.roles,
        now=now,
        max_staleness=policy.max_staleness,
        max_lifetime=policy.max_lifetime,
        snapshot=policy.snapshot,
    )


def verify_and_submit(
    db: sqlite3.Connection,
    record: bytes,
    assertion: bytes,
    request: Request,
    policy: Policy,
    now: int,
    *,
    external: bool = False,
) -> str:
    """Verify one exact effect and claim both identities under the same transaction."""
    result = verify_approval_eddsa(record, assertion, context_for(request, policy, now))
    if not isinstance(result, VerifiedApprovalFacts):
        raise ClaimRefused("invalid")
    return claim(db, result, request.effect, external=external)


def claim(
    db: sqlite3.Connection, facts: VerifiedApprovalFacts, proposed: Effect, *, external: bool
) -> str:
    record, assertion = facts.record, facts.assertion
    effect = proposed.encode()
    approved = Effect(record.subject, record.action, record.resources).encode()
    identity = hashlib.sha256(
        json.dumps([facts.trust_domain, assertion.iss, assertion.jti], separators=(",", ":")).encode()
    ).hexdigest()

    with db:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute(
            "SELECT revision, effect FROM requests WHERE id = ?", (record.request_id,)
        ).fetchone()
        if current is None or not compare_digest(current[0], record.revision_digest):
            raise ClaimRefused("revision_changed")
        if not compare_digest(effect, approved) or not compare_digest(current[1], effect):
            raise ClaimRefused("effect_changed")

        artifact = db.execute(
            "INSERT INTO artifact_claims VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            (facts.trust_domain, assertion.iss, assertion.jti),
        )
        if artifact.rowcount != 1:
            raise ClaimRefused("artifact_already_claimed")
        requested = db.execute(
            "INSERT INTO request_claims VALUES (?, ?) ON CONFLICT DO NOTHING",
            (record.request_id, record.revision_digest),
        )
        if requested.rowcount != 1:
            raise ClaimRefused("request_already_claimed")

        if external:
            db.execute("INSERT INTO intents (identity, effect) VALUES (?, ?)", (identity, effect))
        else:
            db.execute("INSERT INTO local_effects VALUES (?, ?)", (identity, effect))
    return identity


def destination_lookup(db: sqlite3.Connection, identity: str) -> bytes | None:
    row = db.execute("SELECT effect FROM effects WHERE identity = ?", (identity,)).fetchone()
    return None if row is None else row[0]


def destination_commit(db: sqlite3.Connection, identity: str, effect: bytes) -> None:
    with db:
        db.execute("BEGIN IMMEDIATE")
        current = destination_lookup(db, identity)
        if current is None:
            db.execute("INSERT INTO effects VALUES (?, ?)", (identity, effect))
        elif not compare_digest(current, effect):
            raise ClaimRefused("destination_effect_changed")


def deliver(host: sqlite3.Connection, destination: sqlite3.Connection, identity: str) -> None:
    """Recover or retry the same durable intent by its destination identity."""
    row = host.execute("SELECT effect FROM intents WHERE identity = ?", (identity,)).fetchone()
    if row is None:
        raise ClaimRefused("unknown_intent")
    effect = row[0]

    current = destination_lookup(destination, identity)
    if current is None:
        destination_commit(destination, identity, effect)
    elif not compare_digest(current, effect):
        raise ClaimRefused("destination_effect_changed")

    with host:
        host.execute("UPDATE intents SET delivered = 1 WHERE identity = ?", (identity,))


def record_selector(record_digest: bytes) -> dict[str, object]:
    """A host-selected exact digest constraint for a separate capability grant."""
    if type(record_digest) is not bytes or len(record_digest) != 32:
        raise ValueError("invalid digest")
    text = base64url_encode(record_digest)
    if not isinstance(text, Ok):
        raise ValueError("invalid digest")
    return {"kind": "equals", "path": ["record_digest"], "value": JString(text.value)}


def main() -> None:
    host_path, destination_path, identity = sys.argv[1:]
    with closing(sqlite3.connect(host_path)) as host, closing(sqlite3.connect(destination_path)) as destination:
        deliver(host, destination, identity)


if __name__ == "__main__":
    main()
