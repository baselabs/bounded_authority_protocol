import hashlib
import json
from dataclasses import fields, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import bounded_authority_verifier.content_assertion as content_assertion_module
from bounded_authority_verifier import (
    ContentAssertion,
    ContentAssertionDecoded,
    ContentAssertionFacts,
    ExpectedContentAssertion,
    HistoricalPublicKey,
    SigningInput,
    assemble_content_assertion_compact,
    assertion_digest,
    assertion_signing_input,
    base64url_encode,
    bounds_maximum,
    bounds_new,
    content_digest,
    decode_assertion,
    decode_attestation,
    decode_grant,
    decode_local_loopback_http_proof,
    v2,
    v3,
    verify_assertion,
    verify_successor,
)
from bounded_authority_verifier.error import InvalidError

_CORPUS_ROOT = (
    Path(__file__).resolve().parents[3]
    / "priv/conformance/attestation-profiles/content-assertion/v1"
)
_CERTIFIED_INDEX_SHA256 = "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"


def _keypair() -> tuple[bytes, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return public, private


def _producer(**changes: object) -> ContentAssertion:
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
    return ContentAssertion(**values)  # type: ignore[arg-type]


def _signed(
    producer: ContentAssertion | None = None,
    *,
    key_id: str = "attestor-ca-1",
    valid_from: int = 900,
    valid_before: int | None = 2_000,
) -> tuple[bytes, ExpectedContentAssertion, ContentAssertion, bytes]:
    public, private = _keypair()
    producer = producer or _producer(attestor_key_id=key_id)
    signing = assertion_signing_input(producer)
    assert signing.is_ok
    message = signing.value.protected_segment + b"." + signing.value.payload_segment
    signature = private.sign(message)
    compact = assemble_content_assertion_compact(signing.value, signature)
    assert compact.is_ok
    expected = ExpectedContentAssertion(
        attestor=HistoricalPublicKey(
            key_id=key_id,
            public_key=public,
            valid_from=valid_from,
            valid_before=valid_before,
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
    return compact.value, expected, producer, signature


def test_content_digest_exact_bytes_domain_and_bounds() -> None:
    expected = hashlib.sha256(b"BAP1-CONTENT\x00urn:example:content:1").digest()
    result = content_digest(b"urn:example:content:1")
    assert result.is_ok and result.value == expected
    assert not content_digest(b"").is_ok
    assert content_digest(b"x" * 65_536).is_ok
    assert not content_digest(b"x" * 65_537).is_ok
    assert content_digest(b"abcd", bounds_new({"content_bytes": 4})).is_ok
    assert not content_digest(b"abcde", bounds_new({"content_bytes": 4})).is_ok
    assert content_digest(b"x", bounds_new({"encoded_segment_bytes": 1})).is_ok


def test_producer_decode_verify_and_assertion_digest() -> None:
    compact, expected, producer, _signature = _signed()
    decoded = decode_assertion(compact)
    assert decoded.is_ok and isinstance(decoded.value, ContentAssertionDecoded)
    assert decoded.value.verification == "not_evaluated"
    assert decoded.value.content_digest == producer.content_digest

    verified = verify_assertion(compact, expected)
    assert verified.is_ok and isinstance(verified.value, ContentAssertionFacts)
    assert verified.value.digest == hashlib.sha256(compact).digest()
    assert verified.value.verification == "signature_and_window"
    assert verified.value.trust == "not_evaluated"
    assert {field.name for field in fields(verified.value)} == {
        "version",
        "attestor_key_id",
        "attestor_key_fingerprint",
        "jti",
        "iss",
        "aud",
        "sub",
        "profile",
        "profile_digest",
        "content_digest",
        "gen",
        "prev",
        "iat",
        "nbf",
        "exp",
        "digest",
        "verification",
        "trust",
    }
    digest = assertion_digest(compact)
    assert digest.is_ok and digest.value == verified.value.digest


def test_expected_content_digest_is_required_and_every_context_mismatch_closes() -> None:
    compact, expected, _producer_value, _signature = _signed()
    mismatches = (
        replace(expected, issuer="urn:example:issuer:other"),
        replace(expected, audience="urn:example:audience:other"),
        replace(expected, subject="urn:example:lineage:other"),
        replace(expected, profile="urn:example:content-profile:other"),
        replace(expected, profile_digest=b"p" * 32),
        replace(expected, content_digest=b"c" * 32),
    )
    assert all(not verify_assertion(compact, mismatch).is_ok for mismatch in mismatches)

    malformed = object.__new__(ExpectedContentAssertion)
    object.__setattr__(malformed, "attestor", expected.attestor)
    assert not verify_assertion(compact, malformed).is_ok
    assert not verify_assertion(compact, None).is_ok  # type: ignore[arg-type]


def test_expected_requires_explicit_bounds() -> None:
    compact, expected, _producer_value, _signature = _signed()
    required_members = {
        "attestor": expected.attestor,
        "issuer": expected.issuer,
        "audience": expected.audience,
        "subject": expected.subject,
        "profile": expected.profile,
        "profile_digest": expected.profile_digest,
        "content_digest": expected.content_digest,
        "now": expected.now,
    }
    with pytest.raises(TypeError):
        ExpectedContentAssertion(**required_members)  # type: ignore[arg-type]
    assert not verify_assertion(compact, replace(expected, bounds=None)).is_ok  # type: ignore[arg-type]


def test_time_and_attestor_window_exact_edges() -> None:
    producer = _producer(iat=1_000, nbf=1_100, exp=2_000)
    compact, expected, _producer_value, _signature = _signed(producer)
    assert verify_assertion(compact, replace(expected, now=1_100)).is_ok
    assert not verify_assertion(compact, replace(expected, now=2_000)).is_ok
    assert verify_assertion(compact, expected).is_ok

    compact_edge, expected_edge, _producer_value, _signature = _signed(
        replace(producer, iat=900, nbf=900), valid_from=900, valid_before=2_000
    )
    assert verify_assertion(compact_edge, expected_edge).is_ok

    compact_old, expected_old, _producer_value, _signature = _signed(
        replace(producer, iat=899), valid_from=900
    )
    assert not verify_assertion(compact_old, expected_old).is_ok


def test_genesis_and_structural_time_are_symmetric_at_producer_and_parser() -> None:
    invalid = (
        _producer(gen=1, prev=b"x" * 32),
        _producer(gen=2, prev=bytes(32)),
        _producer(iat=1_101, nbf=1_100),
        _producer(nbf=2_000, exp=2_000),
        _producer(gen=0),
    )
    assert all(not assertion_signing_input(value).is_ok for value in invalid)

    compact, _expected, _producer_value, signature = _signed()
    protected, payload, _ = compact.split(b".")
    claims = json.loads(_decode_segment(payload))
    claims["prev"] = base64url_encode(b"x" * 32).decode()
    malformed = SigningInput(
        kind="content_assertion",
        protected_segment=protected,
        payload_segment=base64url_encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        ),
    )
    assert not assemble_content_assertion_compact(malformed, signature).is_ok


def test_producer_enforces_tightened_decoded_segment_bound() -> None:
    producer = _producer()
    signing = assertion_signing_input(producer)
    assert signing.is_ok
    decoded_size = max(
        len(_decode_segment(signing.value.protected_segment)),
        len(_decode_segment(signing.value.payload_segment)),
        64,
    )
    assert assertion_signing_input(
        producer, bounds_new({"decoded_segment_bytes": decoded_size})
    ).is_ok
    assert not assertion_signing_input(
        producer, bounds_new({"decoded_segment_bytes": decoded_size - 1})
    ).is_ok


def test_meaningful_signature_tamper_and_foreign_kind_fail_closed() -> None:
    compact, expected, _producer_value, _signature = _signed()
    parts = compact.split(b".")
    raw_signature = bytearray(_decode_segment(parts[2]))
    raw_signature[len(raw_signature) // 2] ^= 1
    tampered = b".".join((parts[0], parts[1], base64url_encode(bytes(raw_signature))))
    assert decode_assertion(tampered).is_ok
    assert not verify_assertion(tampered, expected).is_ok
    assert assertion_digest(tampered).is_ok

    signing = assertion_signing_input(_producer())
    assert signing.is_ok
    wrong_kind = replace(signing.value, kind="role_attestation")
    assert not assemble_content_assertion_compact(wrong_kind, bytes(64)).is_ok


def test_successor_allows_expired_predecessor_and_rotated_key() -> None:
    predecessor_compact, predecessor_expected, predecessor, _signature = _signed()
    predecessor_verified = verify_assertion(predecessor_compact, predecessor_expected)
    assert predecessor_verified.is_ok

    successor = replace(
        predecessor,
        attestor_key_id="attestor-ca-2",
        jti="urn:example:assertion:2",
        content_digest=b"n" * 32,
        gen=2,
        prev=predecessor_verified.value.digest,
        iat=2_000,
        nbf=2_100,
        exp=3_000,
    )
    successor_compact, successor_expected, _successor, _signature = _signed(
        successor, key_id="attestor-ca-2", valid_from=2_000, valid_before=3_000
    )
    successor_verified = verify_assertion(successor_compact, successor_expected)
    assert successor_verified.is_ok
    assert verify_successor(
        predecessor_verified.value, successor_verified.value, bounds_maximum()
    ).is_ok

    failures = (
        replace(successor_verified.value, iss="urn:example:issuer:other"),
        replace(successor_verified.value, gen=3),
        replace(successor_verified.value, prev=b"x" * 32),
        replace(successor_verified.value, iat=999),
        replace(successor_verified.value, jti=predecessor_verified.value.jti),
    )
    assert all(
        not verify_successor(predecessor_verified.value, value, bounds_maximum()).is_ok
        for value in failures
    )


def test_successor_requires_explicit_bounds() -> None:
    compact, expected, _producer_value, _signature = _signed()
    predecessor = verify_assertion(compact, expected)
    assert predecessor.is_ok
    successor = replace(
        predecessor.value,
        jti="urn:example:assertion:2",
        gen=2,
        prev=predecessor.value.digest,
    )
    with pytest.raises(TypeError):
        verify_successor(predecessor.value, successor)  # type: ignore[call-arg]
    assert not verify_successor(predecessor.value, successor, None).is_ok  # type: ignore[arg-type]


def test_successor_rejects_decoded_partial_and_forged_markers() -> None:
    compact, expected, _producer_value, _signature = _signed()
    facts = verify_assertion(compact, expected)
    decoded = decode_assertion(compact)
    assert facts.is_ok and decoded.is_ok
    successor = replace(
        facts.value,
        jti="urn:example:assertion:2",
        gen=2,
        prev=facts.value.digest,
    )
    assert verify_successor(facts.value, successor, bounds_maximum()).is_ok
    assert not verify_successor(decoded.value, facts.value, bounds_maximum()).is_ok  # type: ignore[arg-type]
    assert not verify_successor(object(), facts.value, bounds_maximum()).is_ok  # type: ignore[arg-type]
    for marker, forged in (("verification", "not_evaluated"), ("trust", "evaluated")):
        assert not verify_successor(
            replace(facts.value, **{marker: forged}), successor, bounds_maximum()
        ).is_ok
        assert not verify_successor(
            facts.value, replace(successor, **{marker: forged}), bounds_maximum()
        ).is_ok


def test_successor_revalidates_typed_facts_numeric_boundaries() -> None:
    compact, expected, _producer_value, _signature = _signed()
    facts = verify_assertion(compact, expected)
    assert facts.is_ok

    negative_magnitude = replace(
        facts.value,
        gen=2,
        prev=b"x" * 32,
        iat=-9_007_199_254_740_992,
        nbf=-9_007_199_254_740_991,
        exp=-9_007_199_254_740_990,
    )
    with pytest.raises(InvalidError):
        content_assertion_module._facts(negative_magnitude, bounds_maximum())
    assert not verify_successor(negative_magnitude, facts.value, bounds_maximum()).is_ok

    zero_generation_nonzero_prev = replace(facts.value, gen=0, prev=b"x" * 32)
    with pytest.raises(InvalidError):
        content_assertion_module._facts(zero_generation_nonzero_prev, bounds_maximum())
    assert not verify_successor(zero_generation_nonzero_prev, facts.value, bounds_maximum()).is_ok


def test_wrong_typed_producer_and_expected_fields_return_closed_error() -> None:
    assert not assertion_signing_input(replace(_producer(), gen=True)).is_ok  # type: ignore[arg-type]
    assert not assertion_signing_input(replace(_producer(), aud=["urn:example:audience:1"])).is_ok  # type: ignore[arg-type]
    compact, expected, _producer_value, _signature = _signed()
    assert not verify_assertion(compact, replace(expected, now=1.5)).is_ok  # type: ignore[arg-type]
    assert not verify_assertion(compact, replace(expected, content_digest=None)).is_ok  # type: ignore[arg-type]


def _decode_segment(segment: bytes) -> bytes:
    import base64

    return base64.urlsafe_b64decode(segment + b"==")


def test_content_assertion_corpus_index_and_files_are_certified() -> None:
    index_bytes = (_CORPUS_ROOT / "index.json").read_bytes()
    assert hashlib.sha256(index_bytes).hexdigest() == _CERTIFIED_INDEX_SHA256
    index = json.loads(index_bytes)
    assert index["profile"] == "bap-content-assertion/1"
    assert index["revision"] == 1
    assert index["assertion_cases"] > 0
    assert index["digest_cases"] > 0
    assert index["successor_cases"] > 0
    for entry in index["files"]:
        body = (_CORPUS_ROOT / entry["path"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]


def _corpus_b64(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "==")


def _corpus_expected(
    profile: dict[str, object],
    *,
    attestor_name: str = "primary",
    overrides: dict[str, object] | None = None,
    bounds: object = None,
) -> ExpectedContentAssertion:
    expected = dict(profile["expected"])  # type: ignore[arg-type]
    attestors = profile["attestors"]
    assert isinstance(attestors, dict)
    attestor = dict(attestors[attestor_name])
    for key, value in (overrides or {}).items():
        if key.startswith("attestor_"):
            attestor[key.removeprefix("attestor_")] = value
        else:
            expected[key] = value
    return ExpectedContentAssertion(
        attestor=HistoricalPublicKey(
            key_id=attestor["key_id"],
            public_key=_corpus_b64(attestor["public_key"]),
            valid_from=attestor["valid_from"],
            valid_before=attestor["valid_before"],
        ),
        issuer=expected["issuer"],
        audience=expected["audience"],
        subject=expected["subject"],
        profile=expected["profile"],
        profile_digest=_corpus_b64(expected["profile_digest"]),
        content_digest=_corpus_b64(expected["content_digest"]),
        now=expected["now"],
        bounds=bounds if bounds is not None else bounds_maximum(),
    )  # type: ignore[arg-type]


def _load_assertion_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for name in ("assertion-structure-cases.json", "assertion-verification-cases.json"):
        cases.extend(json.loads((_CORPUS_ROOT / name).read_text()))
    return cases


def test_content_assertion_corpus_drives_python_verdicts_and_cross_rejection() -> None:
    profile = json.loads((_CORPUS_ROOT / "profile.json").read_text())
    cases = _load_assertion_cases()
    index = json.loads((_CORPUS_ROOT / "index.json").read_text())
    assert len(cases) == index["assertion_cases"] == 131
    assert len({case["id"] for case in cases}) == len(cases)

    legacy_decoders = {
        "v1_grant": decode_grant,
        "v2_grant": v2.decode_grant,
        "v3_grant": v3.decode_grant,
        "loopback": decode_local_loopback_http_proof,
        "role_attestation": decode_attestation,
    }
    for case in cases:
        expected_verdicts = case["expected"]
        assert isinstance(expected_verdicts, dict)
        compact_value = case["compact"].encode()
        bounds_value = None
        try:
            if "bounds" in case:
                bounds_value = bounds_new(case["bounds"])  # type: ignore[arg-type]
        except InvalidError:
            assert expected_verdicts == {"decode": "invalid", "verify": "invalid"}, case["id"]
            continue
        expected = _corpus_expected(
            profile,
            attestor_name=case.get("attestor", "primary"),  # type: ignore[arg-type]
            overrides=case.get("expected_overrides"),  # type: ignore[arg-type]
            bounds=bounds_value,
        )
        decoded = decode_assertion(compact_value, bounds_value)
        verified = verify_assertion(compact_value, expected)
        assert decoded.is_ok == (expected_verdicts["decode"] == "valid"), case["id"]
        assert verified.is_ok == (expected_verdicts["verify"] == "valid"), case["id"]
        digested = assertion_digest(compact_value, bounds_value)
        assert digested.is_ok == decoded.is_ok, case["id"]

        legacy_accepts = set(case.get("legacy_accepts", []))  # type: ignore[arg-type]
        for name, decoder in legacy_decoders.items():
            assert decoder(compact_value).is_ok == (name in legacy_accepts), (case["id"], name)


def test_content_assertion_corpus_producer_and_assembly_match_exact_bytes() -> None:
    cases = [case for case in _load_assertion_cases() if case["expected"]["decode"] == "valid"]
    assert len(cases) == 38
    for case in cases:
        compact_value = case["compact"].encode()
        protected, payload, signature = compact_value.split(b".")
        header = json.loads(_decode_segment(protected))
        claims = json.loads(_decode_segment(payload))
        producer = ContentAssertion(
            attestor_key_id=header["kid"],
            jti=claims["jti"],
            iss=claims["iss"],
            aud=claims["aud"],
            sub=claims["sub"],
            profile=claims["profile"],
            profile_digest=_corpus_b64(claims["profile_digest"]),
            content_digest=_corpus_b64(claims["content_digest"]),
            gen=claims["gen"],
            prev=_corpus_b64(claims["prev"]),
            iat=claims["iat"],
            nbf=claims["nbf"],
            exp=claims["exp"],
        )
        bounds_value = bounds_new(case.get("bounds", {}))
        signing = assertion_signing_input(producer, bounds_value)
        assert signing.is_ok, case["id"]
        assert signing.value.protected_segment == protected, case["id"]
        assert signing.value.payload_segment == payload, case["id"]
        assembled = assemble_content_assertion_compact(
            signing.value, _decode_segment(signature), bounds_value
        )
        assert assembled.is_ok and assembled.value == compact_value, case["id"]


def test_content_digest_corpus_drives_exact_bytes_and_sidecar_bounds() -> None:
    cases = json.loads((_CORPUS_ROOT / "digest-cases.json").read_text())
    index = json.loads((_CORPUS_ROOT / "index.json").read_text())
    assert len(cases) == index["digest_cases"] == 9
    for case in cases:
        input_value = case["input"]
        if "content_file" in input_value:
            content = (_CORPUS_ROOT / input_value["content_file"]).read_bytes()
        else:
            content = _corpus_b64(input_value["content_base64url"])
        try:
            bounds_value = bounds_new(input_value["bounds"])
        except InvalidError:
            assert case["expected"]["verdict"] == "invalid", case["id"]
            continue
        result = content_digest(content, bounds_value)
        assert result.is_ok == (case["expected"]["verdict"] == "valid"), case["id"]
        if result.is_ok:
            assert result.value == _corpus_b64(case["expected"]["digest"]), case["id"]


def _verified_corpus_artifact(
    artifact: dict[str, object], profile: dict[str, object]
) -> ContentAssertionFacts | None:
    expected = _corpus_expected(
        profile,
        attestor_name=artifact["attestor"],  # type: ignore[arg-type]
        overrides=artifact.get("expected_overrides"),  # type: ignore[arg-type]
    )
    result = verify_assertion(artifact["compact"].encode(), expected)  # type: ignore[union-attr]
    if not result.is_ok:
        return None
    facts = result.value
    overrides = artifact.get("facts_overrides", {})
    assert isinstance(overrides, dict)
    normalized = dict(overrides)
    for key in ("digest", "profile_digest", "content_digest", "prev", "attestor_key_fingerprint"):
        if key in normalized:
            normalized[key] = _corpus_b64(normalized[key])
    return replace(facts, **normalized)


def test_content_assertion_successor_corpus_separates_artifact_and_relation_verdicts() -> None:
    profile = json.loads((_CORPUS_ROOT / "profile.json").read_text())
    cases = json.loads((_CORPUS_ROOT / "successor-cases.json").read_text())
    index = json.loads((_CORPUS_ROOT / "index.json").read_text())
    assert len(cases) == index["successor_cases"] == 14
    for case in cases:
        predecessor = _verified_corpus_artifact(case["predecessor"], profile)
        successor = _verified_corpus_artifact(case["successor"], profile)
        assert (predecessor is not None) == (case["expected"]["predecessor"] == "valid"), case["id"]
        assert (successor is not None) == (case["expected"]["successor"] == "valid"), case["id"]
        if case["expected"]["relation"] == "not_run":
            assert predecessor is None or successor is None, case["id"]
            continue
        assert predecessor is not None and successor is not None
        relation = verify_successor(predecessor, successor, bounds_maximum())
        assert relation.is_ok == (case["expected"]["relation"] == "valid"), case["id"]
