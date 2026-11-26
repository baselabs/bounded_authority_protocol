"""Run the offline README example with durable SQLite files and fresh workers."""

import hashlib
import inspect
import pickle
import sqlite3
import subprocess
import sys
from contextlib import closing
from copy import copy, deepcopy
from dataclasses import asdict, fields, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.check_sdk_install import block
from sdks.python.examples import action_approval as example

from bounded_authority_verifier import (
    ExpectedRequest,
    GrantProducer,
    HistoricalPublicKey,
    JObject,
    NonceNotRequired,
    OperationInput,
    ProofProducer,
    TrustedIssuer,
    assemble_compact,
    check_envelope,
    content_assertion,
    grant_signing_input,
    jwk_from_public_key,
    proof_signing_input,
    thumbprint,
)
from bounded_authority_verifier.action_approval import (
    Suite,
    TrustEntry,
    TrustSnapshot,
    VerifiedApprovalFacts,
    verify_approval_eddsa,
)
from bounded_authority_verifier.approval_record import (
    PROFILE,
    PROFILE_DIGEST,
    ApprovalRecord,
    decode_record,
    encode_record,
)
from bounded_authority_verifier.error import _unwrap


@pytest.fixture
def databases(tmp_path):
    host_path, destination_path = tmp_path / "host.sqlite", tmp_path / "destination.sqlite"
    with closing(sqlite3.connect(host_path, timeout=0)) as host:
        host.executescript(example.HOST_SCHEMA)
    with closing(sqlite3.connect(destination_path, timeout=0)) as destination:
        destination.executescript(example.DESTINATION_SCHEMA)
    return host_path, destination_path


@pytest.fixture
def operation():
    return signed_operation("request-7")


def signed_operation(request_id):
    request = example.Request(
        request_id,
        hashlib.sha256(b"request revision 7").digest(),
        example.Effect("image-indexer", "index", ("caption", "thumbnail")),
    )
    signer = Ed25519PrivateKey.generate()
    key = HistoricalPublicKey("review-key", signer.public_key().public_bytes_raw(), 0, 60)
    snapshot = TrustSnapshot(
        Suite.EDDSA, "image-index", "local configuration", 10,
        (TrustEntry("reviewer", key, ("image-review",)),),
    )
    policy = example.Policy("image-host", "image-index", ("image-review",), snapshot, 10, 60)
    record = ApprovalRecord(
        request.effect.subject, request.effect.action, request.request_id,
        "image-review", request.effect.resources, request.revision,
    )
    wire = _unwrap(encode_record(record))
    claims = content_assertion.ContentAssertion(
        "review-key", "event-7", "reviewer", "image-host", request.request_id,
        PROFILE, PROFILE_DIGEST, _unwrap(content_assertion.content_digest(wire)),
        1, bytes(32), 10, 10, 60,
    )
    signing = _unwrap(content_assertion.assertion_signing_input(claims))
    signature = signer.sign(signing.protected_segment + b"." + signing.payload_segment)
    compact = _unwrap(content_assertion.assemble_content_assertion_compact(signing, signature))
    return request, policy, wire, compact


def install(db, request):
    with db:
        db.execute(
            "INSERT INTO requests VALUES (?, ?, ?)",
            (request.request_id, request.revision, request.effect.encode()),
        )


def facts(operation):
    request, policy, wire, compact = operation
    result = verify_approval_eddsa(wire, compact, example.context_for(request, policy, 10))
    assert isinstance(result, VerifiedApprovalFacts)
    return result


def submit(db, operation, *, external=False):
    request, policy, wire, compact = operation
    return example.verify_and_submit(db, wire, compact, request, policy, 10, external=external)


def count(db, table):
    # Test-owned fixed table names.
    return db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_readme_approval_example(databases, operation):
    readme = Path("sdks/python/README.md").read_text()
    source = block(readme, "sdk-example:action-approval", "python")
    request, policy, wire, compact = operation
    with closing(sqlite3.connect(databases[0])) as host:
        install(host, request)
        inputs = {
            "verify_and_submit": example.verify_and_submit,
            "host_db": host,
            "record_bytes": wire,
            "assertion_compact": compact,
            "prepared_request": request,
            "host_policy": policy,
            "now": 10,
        }
        exec(source, inputs)
        assert inputs["identity"]
        assert count(host, "artifact_claims") == count(host, "request_claims") == 1


@pytest.mark.parametrize("request_id", ["https://[v1.a]/r", "https://[VF.a:b]:42/r", "https://[::1]/r"])
def test_request_id_accepts_ip_literals(request_id):
    operation = signed_operation(request_id)
    _, _, wire, _ = operation
    record = _unwrap(decode_record(wire))
    assert record.request_id == request_id
    verified = facts(operation)
    assert verified.record == record
    assert verified.assertion.sub == request_id


@pytest.mark.parametrize("request_id", ["https://[v1.]/r", "https://[v1.a%20]/r", "https://[vg.a]/r"])
def test_request_id_rejects_invalid_ip_literals(request_id):
    _, _, wire, _ = signed_operation("https://[v1.a]/r")
    record = _unwrap(decode_record(wire))
    invalid = ApprovalRecord(
        record.subject, record.action, request_id, record.approver_role,
        record.resources, record.revision_digest,
    )
    assert not encode_record(invalid).is_ok
    assert not decode_record(wire.replace(b"https://[v1.a]/r", request_id.encode())).is_ok


def test_approval_values_refuse_reinitialization_and_export(operation):
    result = facts(operation)
    record = result.record
    with pytest.raises(TypeError, match="initialized twice"):
        record.__init__(
            "changed", record.action, record.request_id, record.approver_role,
            record.resources, record.revision_digest,
        )
    with pytest.raises(TypeError, match="initialized twice"):
        result.__init__(result.suite, "changed", record, result.assertion)
    assert record.subject == operation[0].effect.subject
    assert result.trust_domain == operation[1].trust_domain
    for value in (result, record):
        for export in (asdict, fields, vars, pickle.dumps, copy, deepcopy):
            with pytest.raises(TypeError):
                export(value)


@pytest.mark.parametrize("mismatch", ["subject", "action", "subset", "superset", "stored_effect"])
def test_exact_effect_inside_claim(databases, operation, mismatch):
    request = operation[0]
    effect = request.effect
    changed = {
        "subject": replace(effect, subject="other"),
        "action": replace(effect, action="scan"),
        "subset": replace(effect, resources=("caption",)),
        "superset": replace(effect, resources=(*effect.resources, "title")),
        "stored_effect": effect,
    }[mismatch]
    with closing(sqlite3.connect(databases[0])) as host:
        installed = request if mismatch != "stored_effect" else replace(request, effect=replace(effect, action="scan"))
        install(host, installed)
        with pytest.raises(example.ClaimRefused, match="effect_changed"):
            example.claim(host, facts(operation), changed, external=False)
        assert count(host, "artifact_claims") == count(host, "request_claims") == 0
        assert count(host, "local_effects") == 0


@pytest.mark.parametrize("failure", ["artifact_already_claimed", "request_already_claimed", "effect_write"])
def test_claim_collisions_and_rollback(databases, operation, failure):
    with closing(sqlite3.connect(databases[0])) as host:
        request = operation[0]
        install(host, request)
        with host:
            if failure == "artifact_already_claimed":
                host.execute("INSERT INTO artifact_claims VALUES ('image-index', 'reviewer', 'event-7')")
            elif failure == "request_already_claimed":
                host.execute("INSERT INTO request_claims VALUES (?, ?)", (request.request_id, request.revision))
            else:
                host.execute(
                    "CREATE TRIGGER refuse_effect BEFORE INSERT ON local_effects "
                    "BEGIN SELECT RAISE(ABORT, 'effect write failed'); END"
                )
        error = sqlite3.IntegrityError if failure == "effect_write" else example.ClaimRefused
        with pytest.raises(error, match=failure.replace("effect_write", "effect write failed")):
            submit(host, operation)
        assert count(host, "artifact_claims") == int(failure == "artifact_already_claimed")
        assert count(host, "request_claims") == int(failure == "request_already_claimed")
        assert count(host, "local_effects") == 0


def revise(connection, request, revision):
    connection.execute("UPDATE requests SET revision = ? WHERE id = ?", (revision, request.request_id))


def assert_busy(error):
    assert error.sqlite_errorcode & 255 == sqlite3.SQLITE_BUSY


@pytest.mark.parametrize("first", ["revision", "claim"])
def test_revision_serialization(databases, operation, first):
    request = operation[0]
    later = hashlib.sha256(b"request revision 8").digest()
    with closing(sqlite3.connect(databases[0], timeout=0)) as host, closing(
        sqlite3.connect(databases[0], timeout=0)
    ) as writer:
        install(host, request)
        if first == "revision":
            writer.execute("BEGIN IMMEDIATE")
            revise(writer, request, later)
            statements = []
            host.set_trace_callback(statements.append)
            with pytest.raises(sqlite3.OperationalError) as blocked:
                submit(host, operation)
            host.set_trace_callback(None)
            assert_busy(blocked.value)
            assert not any(sql.startswith("SELECT revision, effect") for sql in statements), (
                "comparison ran without a write lock"
            )
            writer.commit()
            with pytest.raises(example.ClaimRefused, match="revision_changed"):
                submit(host, operation)
            assert count(host, "artifact_claims") == count(host, "request_claims") == 0
            assert count(host, "local_effects") == 0
        else:
            observations = []

            def compare_under_lock(sql):
                if sql.startswith("SELECT revision, effect"):
                    try:
                        revise(writer, request, later)
                    except sqlite3.OperationalError as exc:
                        observations.append(exc.sqlite_errorcode)
                    finally:
                        writer.rollback()

            host.set_trace_callback(compare_under_lock)
            submit(host, operation)
            host.set_trace_callback(None)
            assert len(observations) == 1 and observations[0] & 255 == sqlite3.SQLITE_BUSY, (
                "revision update bypassed the claim lock"
            )
            with writer:
                revise(writer, request, later)
            with pytest.raises(example.ClaimRefused, match="revision_changed"):
                submit(host, operation)
            assert count(host, "artifact_claims") == count(host, "request_claims") == 1
            assert count(host, "local_effects") == 1


@pytest.mark.parametrize(
    ("first", "detector"),
    [("revision", "comparison ran without a write lock"),
     ("claim", "revision update bypassed the claim lock")],
)
def test_mutation_removing_write_lock_is_detected(databases, operation, first, detector, monkeypatch):
    original = inspect.getsource(example.claim)
    target = 'db.execute("BEGIN IMMEDIATE")'
    assert original.count(target) == 1
    namespace = vars(example).copy()
    exec(compile(original.replace(target, "pass"), "<claim mutation>", "exec"), namespace)
    monkeypatch.setattr(example, "claim", namespace["claim"])
    with pytest.raises(AssertionError, match=detector):
        test_revision_serialization(databases, operation, first)


@pytest.mark.parametrize("committed", [False, True])
def test_deliver_same_intent_after_restart(databases, operation, committed):
    host_path, destination_path = databases
    request = operation[0]
    effect = request.effect.encode()
    with closing(sqlite3.connect(host_path)) as host:
        install(host, request)
        identity = submit(host, operation, external=True)
        assert host.execute("SELECT delivered FROM intents").fetchone() == (0,)
    with closing(sqlite3.connect(destination_path)) as destination:
        if committed:
            example.destination_commit(destination, identity, effect)
        else:
            destination.execute("BEGIN IMMEDIATE")
            destination.execute("INSERT INTO effects VALUES (?, ?)", (identity, effect))
            # Closing this connection interrupts the write before commit.
    with closing(sqlite3.connect(destination_path)) as destination:
        assert example.destination_lookup(destination, identity) == (effect if committed else None)
    for _ in range(2):
        subprocess.run(
            [sys.executable, "-m", "sdks.python.examples.action_approval",
             str(host_path), str(destination_path), identity],
            check=True,
            timeout=10,
        )
    with closing(sqlite3.connect(host_path)) as host, closing(sqlite3.connect(destination_path)) as destination:
        assert host.execute("SELECT identity, effect, delivered FROM intents").fetchall() == [(identity, effect, 1)]
        assert destination.execute("SELECT identity, effect FROM effects").fetchall() == [(identity, effect)]


def sign(signing, signer):
    signature = signer.sign(signing.protected_segment + b"." + signing.payload_segment)
    return _unwrap(assemble_compact(signing, signature))


def test_capability_grant_with_record_digest_and_holder_proof(operation):
    _, _, wire, _ = operation
    record_digest = _unwrap(content_assertion.content_digest(wire))
    selector = example.record_selector(record_digest)
    issuer, holder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    holder_public = holder.public_key().public_bytes_raw()
    holder_thumbprint = _unwrap(thumbprint(_unwrap(jwk_from_public_key(holder_public))))
    grant = sign(
        _unwrap(grant_signing_input(GrantProducer(
            "capability-key", "https://issuer.example", "index-capability", ("https://host.example",),
            1000, 1000, 1200, holder_thumbprint, (OperationInput("start_index", (selector,)),),
        ))),
        issuer,
    )
    args = JObject({"record_digest": selector["value"]})
    expected = ExpectedRequest(
        TrustedIssuer("capability-key", issuer.public_key().public_bytes_raw()),
        "https://issuer.example", "https://host.example", "POST", "https://host.example/index",
        "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80", "start_index", args, 1010, 0, 30, NonceNotRequired(),
    )
    producer = ProofProducer(
        holder_public, "index-proof", expected.method, expected.target_uri, 1010,
        expected.invocation_id, expected.operation, grant, args,
    )
    proof = sign(_unwrap(proof_signing_input(producer)), holder)
    assert check_envelope(grant, proof, expected).is_ok

    other = Ed25519PrivateKey.generate()
    wrong_holder = replace(producer, holder_public_key=other.public_key().public_bytes_raw())
    assert not check_envelope(grant, sign(_unwrap(proof_signing_input(wrong_holder)), other), expected).is_ok

    changed = JObject({"record_digest": example.record_selector(bytes(32))["value"]})
    wrong_record = sign(_unwrap(proof_signing_input(replace(producer, cast_arguments=changed))), holder)
    assert not check_envelope(grant, wrong_record, replace(expected, cast_arguments=changed)).is_ok
