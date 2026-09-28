"""Red-capable guards for the content-assertion security boundary.

Each case compiles one changed implementation in memory, exercises real Ed25519 operations, and
requires the named behavior probe to detect the change. The working tree and external application
checkouts are never modified.
"""

from __future__ import annotations

import hashlib
import sys
import types
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import bounded_authority_verifier.content_assertion as content_assertion
from bounded_authority_verifier import (
    HistoricalPublicKey,
    SigningInput,
    base64url_decode,
    base64url_encode,
    bounds_maximum,
    bounds_new,
)
from bounded_authority_verifier.error import InvalidError

Probe = Callable[[types.ModuleType], bool]


def _mutant(name: str, needle: str, replacement: str) -> types.ModuleType:
    path = Path(content_assertion.__file__)
    source = path.read_text()
    assert source.count(needle) == 1, f"{name}: mutation target must occur exactly once"
    changed = source.replace(needle, replacement, 1)
    module_name = f"bounded_authority_verifier._content_assertion_mutant_{name.replace('-', '_')}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = "bounded_authority_verifier"
    sys.modules[module_name] = module
    exec(compile(changed, f"<{name}>", "exec"), module.__dict__)
    return module


def _producer(module: types.ModuleType, **changes: object) -> Any:
    values: dict[str, object] = {
        "attestor_key_id": "attestor-ca-1",
        "jti": "urn:example:assertion:1",
        "iss": "urn:example:issuer:1",
        "aud": "urn:example:audience:1",
        "sub": "urn:example:lineage:1",
        "profile": "urn:example:content-profile:1",
        "profile_digest": bytes(range(32)),
        "content_digest": bytes(reversed(range(32))),
        "gen": 1,
        "prev": bytes(32),
        "iat": 1_000,
        "nbf": 1_100,
        "exp": 2_000,
    }
    values.update(changes)
    return module.ContentAssertion(**values)


def _signed(module: types.ModuleType) -> tuple[bytes, Any, Any]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    producer = _producer(module)
    signing = module.assertion_signing_input(producer)
    assert signing.is_ok
    signature = private.sign(signing.value.protected_segment + b"." + signing.value.payload_segment)
    compact = module.assemble_content_assertion_compact(signing.value, signature)
    assert compact.is_ok
    expected = module.ExpectedContentAssertion(
        attestor=HistoricalPublicKey(
            key_id=producer.attestor_key_id,
            public_key=public,
            valid_from=900,
            valid_before=2_000,
        ),
        issuer=producer.iss,
        audience=producer.aud,
        subject=producer.sub,
        profile=producer.profile,
        profile_digest=producer.profile_digest,
        content_digest=producer.content_digest,
        now=producer.nbf,
        bounds=bounds_maximum(),
    )
    facts = module.verify_assertion(compact.value, expected)
    assert facts.is_ok
    return compact.value, expected, facts.value


def _rejects(operation: Callable[[], object]) -> bool:
    try:
        operation()
    except InvalidError:
        return True
    return False


def _probe_content_domain(module: types.ModuleType) -> bool:
    expected = hashlib.sha256(b"BAP1-CONTENT\x00urn:example:content:1").digest()
    result = module.content_digest(b"urn:example:content:1")
    return result.is_ok and result.value == expected


def _probe_content_ceiling(module: types.ModuleType) -> bool:
    return not module.content_digest(b"x" * 65_537).is_ok


def _probe_expected_content(module: types.ModuleType) -> bool:
    compact, expected, _facts = _signed(module)
    return not module.verify_assertion(compact, replace(expected, content_digest=b"x" * 32)).is_ok


def _probe_signature(module: types.ModuleType) -> bool:
    compact, expected, _facts = _signed(module)
    protected, payload, signature = compact.split(b".")
    raw = bytearray(base64url_decode(signature))
    raw[len(raw) // 2] ^= 1
    tampered = b".".join((protected, payload, base64url_encode(bytes(raw))))
    return not module.verify_assertion(tampered, expected).is_ok


def _probe_assembly_kind(module: types.ModuleType) -> bool:
    signing = module.assertion_signing_input(_producer(module))
    assert signing.is_ok
    wrong_kind = SigningInput(
        kind="role_attestation",
        protected_segment=signing.value.protected_segment,
        payload_segment=signing.value.payload_segment,
    )
    return not module.assemble_content_assertion_compact(wrong_kind, bytes(64)).is_ok


def _probe_decoded_segment(module: types.ModuleType) -> bool:
    producer = _producer(module)
    signing = module.assertion_signing_input(producer)
    assert signing.is_ok
    decoded_size = max(
        len(base64url_decode(signing.value.protected_segment)),
        len(base64url_decode(signing.value.payload_segment)),
        64,
    )
    return not module.assertion_signing_input(
        producer, bounds_new({"decoded_segment_bytes": decoded_size - 1})
    ).is_ok


def _probe_negative_magnitude(module: types.ModuleType) -> bool:
    _compact, _expected, facts = _signed(module)
    hostile = replace(
        facts,
        gen=2,
        prev=b"x" * 32,
        iat=-9_007_199_254_740_992,
        nbf=-9_007_199_254_740_991,
        exp=-9_007_199_254_740_990,
    )
    return _rejects(lambda: module._facts(hostile, bounds_maximum()))


def _probe_positive_generation(module: types.ModuleType) -> bool:
    _compact, _expected, facts = _signed(module)
    hostile = replace(facts, gen=0, prev=b"x" * 32)
    return _rejects(lambda: module._facts(hostile, bounds_maximum()))


def _valid_successor_pair(module: types.ModuleType) -> tuple[Any, Any]:
    _compact, _expected, predecessor = _signed(module)
    successor = replace(
        predecessor,
        jti="urn:example:assertion:2",
        content_digest=b"n" * 32,
        gen=2,
        prev=predecessor.digest,
    )
    assert module.verify_successor(predecessor, successor, bounds_maximum()).is_ok
    return predecessor, successor


def _probe_markers(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return (
        not module.verify_successor(
            replace(predecessor, verification="not_evaluated"), successor, bounds_maximum()
        ).is_ok
        and not module.verify_successor(
            predecessor, replace(successor, trust="evaluated"), bounds_maximum()
        ).is_ok
    )


def _probe_context(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return not module.verify_successor(
        predecessor, replace(successor, iss="urn:example:issuer:other"), bounds_maximum()
    ).is_ok


def _probe_generation(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return not module.verify_successor(
        predecessor, replace(successor, gen=3), bounds_maximum()
    ).is_ok


def _probe_predecessor(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return not module.verify_successor(
        predecessor, replace(successor, prev=b"x" * 32), bounds_maximum()
    ).is_ok


def _probe_time(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return not module.verify_successor(
        predecessor, replace(successor, iat=predecessor.iat - 1), bounds_maximum()
    ).is_ok


def _probe_identity(module: types.ModuleType) -> bool:
    predecessor, successor = _valid_successor_pair(module)
    return not module.verify_successor(
        predecessor, replace(successor, jti=predecessor.jti), bounds_maximum()
    ).is_ok


MUTATIONS: tuple[tuple[str, str, str, Probe], ...] = (
    (
        "content-domain-prefix",
        'CONTENT_PREFIX = b"BAP1-CONTENT\\x00"',
        'CONTENT_PREFIX = b"BAP1-CONTENT"',
        _probe_content_domain,
    ),
    (
        "content-size-ceiling",
        'if not (1 <= len(content) <= bounds_resolve(b, "content_bytes")):',
        "if not (1 <= len(content)):",
        _probe_content_ceiling,
    ),
    (
        "expected-content-digest-equality",
        "if not _bytes_equal(asserted_content_digest, expected.content_digest):",
        "if False:",
        _probe_expected_content,
    ),
    (
        "meaningful-signature-verification",
        "if not ed25519_verify(segments.signing_input, segments.signature, key):",
        "if False:",
        _probe_signature,
    ),
    (
        "profile-specific-assembly-kind",
        'if signing_input.kind != "content_assertion":',
        "if False:",
        _probe_assembly_kind,
    ),
    (
        "producer-decoded-segment-ceiling",
        "if _project_base64url_decoded_size(len(signing.payload_segment)) > decoded_limit:",
        "if False:",
        _probe_decoded_segment,
    ),
    (
        "typed-facts-negative-magnitude",
        'if abs(value) > bounds_resolve(bounds, "integer_magnitude"):',
        'if value > bounds_resolve(bounds, "integer_magnitude"):',
        _probe_negative_magnitude,
    ),
    (
        "typed-facts-positive-generation",
        'if not (1 <= gen <= bounds_resolve(bounds, "integer_magnitude")):',
        'if not (gen <= bounds_resolve(bounds, "integer_magnitude")):',
        _probe_positive_generation,
    ),
    (
        "successor-verification-trust-markers",
        'if value.verification != "signature_and_window" or value.trust != "not_evaluated":',
        "if False:",
        _probe_markers,
    ),
    (
        "successor-lineage-context",
        "if (\n            predecessor.iss,",
        "if False and (\n            predecessor.iss,",
        _probe_context,
    ),
    (
        "successor-generation-step",
        "if predecessor.gen >= magnitude or successor.gen != predecessor.gen + 1:",
        "if False:",
        _probe_generation,
    ),
    (
        "successor-predecessor-digest",
        "if not _bytes_equal(successor.prev, predecessor.digest):",
        "if False:",
        _probe_predecessor,
    ),
    (
        "successor-nondecreasing-iat",
        "if successor.iat < predecessor.iat:",
        "if False:",
        _probe_time,
    ),
    (
        "successor-distinct-jti",
        "if successor.jti == predecessor.jti:",
        "if False:",
        _probe_identity,
    ),
)


@pytest.mark.parametrize(
    ("name", "needle", "replacement", "probe"),
    MUTATIONS,
    ids=[mutation[0] for mutation in MUTATIONS],
)
def test_content_assertion_guard_mutation_is_killed(
    name: str, needle: str, replacement: str, probe: Probe
) -> None:
    mutant = _mutant(name, needle, replacement)
    assert not probe(mutant), f"survived mutation: {name}"
