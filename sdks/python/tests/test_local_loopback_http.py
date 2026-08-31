import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bounded_authority_verifier import (
    Bounds,
    ExpectedRequest,
    GrantProducer,
    JNull,
    JObject,
    JString,
    NonceNotRequired,
    NonceRequired,
    OperationInput,
    ProofProducer,
    SigningInput,
    TrustedIssuer,
    assemble_compact,
    assemble_local_loopback_http_compact,
    check_envelope,
    check_local_loopback_http_envelope,
    decode_local_loopback_http_proof,
    decode_proof,
    grant_signing_input,
    local_loopback_http_proof_signing_input,
    proof_signing_input,
    public_key_thumbprint_raw,
)
from bounded_authority_verifier.uri import local_loopback_http_uri_normalize, uri_normalize

_CERTIFIED_INDEX_SHA256 = "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4"


def test_local_loopback_http_uri_profile_accepts_only_exact_loopback_literals() -> None:
    for source, expected in [
        (b"HTTP://127.0.0.1:80/a/../invoke", b"http://127.0.0.1/invoke"),
        (b"http://127.0.0.1:4000/invoke", b"http://127.0.0.1:4000/invoke"),
        (b"HTTP://[::1]:80/invoke", b"http://[::1]/invoke"),
        (b"http://127.0.0.1:443/invoke", b"http://127.0.0.1:443/invoke"),
    ]:
        result = local_loopback_http_uri_normalize(source)
        assert result.is_ok
        assert result.value == expected

    for invalid in [
        b"https://127.0.0.1/invoke",
        b"http://localhost/invoke",
        b"http://127.0.0.2/invoke",
        b"http://127.1/invoke",
        b"http://2130706433/invoke",
        b"http://[::ffff:127.0.0.1]/invoke",
        b"http://[::1%25lo0]/invoke",
        b"http://user@127.0.0.1/invoke",
        b"http://127.0.0.1/invoke?query=true",
        b"http://127.0.0.1/invoke#fragment",
        b"http://127.0.0.1/[]",
        b"http://127.0.0.1:" + (b"1" * 5000) + b"/invoke",
    ]:
        assert not local_loopback_http_uri_normalize(invalid).is_ok

    forged = Bounds({"uri_bytes": 9000})
    assert not local_loopback_http_uri_normalize(b"http://127.0.0.1/", forged).is_ok
    assert uri_normalize(b"https://resource.example.test/[]").is_ok


def _keypair() -> tuple[bytes, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return public, private


def _signing_message(signing_input: SigningInput) -> bytes:
    return signing_input.protected_segment + b"." + signing_input.payload_segment


def test_local_loopback_http_profile_is_byte_distinct_and_nonce_bound() -> None:
    issuer_public, issuer_private = _keypair()
    holder_public, holder_private = _keypair()
    holder_thumbprint = public_key_thumbprint_raw(holder_public)

    grant_input = GrantProducer(
        key_id="issuer-1",
        issuer="https://issuer.example.test",
        grant_id="urn:example:grant:1",
        audiences=("https://resource.example.test",),
        issued_at=1000,
        not_before=1000,
        expires_at=2000,
        holder_thumbprint=base64.urlsafe_b64encode(holder_thumbprint).rstrip(b"=").decode(),
        operations=(OperationInput(name="read", selectors=("all",)),),
    )
    grant_si = grant_signing_input(grant_input)
    assert grant_si.is_ok
    grant_compact = assemble_compact(
        grant_si.value, issuer_private.sign(_signing_message(grant_si.value))
    )
    assert grant_compact.is_ok

    proof_input = ProofProducer(
        holder_public_key=holder_public,
        proof_id="urn:example:proof:loopback:1",
        method="POST",
        target_uri="http://127.0.0.1:4000/invoke",
        issued_at=1400,
        invocation_id="550e8400-e29b-41d4-a716-446655440000",
        operation="read",
        grant_compact=grant_compact.value,
        cast_arguments=JNull(),
        nonce="nonce-1",
    )
    proof_si = local_loopback_http_proof_signing_input(proof_input)
    assert proof_si.is_ok
    proof_compact = assemble_local_loopback_http_compact(
        proof_si.value, holder_private.sign(_signing_message(proof_si.value))
    )
    assert proof_compact.is_ok

    assert decode_local_loopback_http_proof(proof_compact.value).is_ok
    assert not decode_proof(proof_compact.value).is_ok
    assert not assemble_compact(
        proof_si.value, holder_private.sign(_signing_message(proof_si.value))
    ).is_ok
    assert not assemble_local_loopback_http_compact(
        grant_si.value, issuer_private.sign(_signing_message(grant_si.value))
    ).is_ok

    expected = ExpectedRequest(
        trusted_issuer=TrustedIssuer(key_id="issuer-1", public_key=issuer_public),
        issuer="https://issuer.example.test",
        audience="https://resource.example.test",
        method="POST",
        target_uri="http://127.0.0.1:4000/invoke",
        invocation_id="550e8400-e29b-41d4-a716-446655440000",
        operation="read",
        cast_arguments=JNull(),
        evaluation_time=1400,
        clock_skew=0,
        proof_max_age=300,
        nonce=NonceRequired("nonce-1"),
    )
    assert check_local_loopback_http_envelope(
        grant_compact.value, proof_compact.value, expected
    ).is_ok
    assert not check_local_loopback_http_envelope(
        grant_compact.value,
        proof_compact.value,
        replace(expected, nonce=NonceRequired("wrong-nonce")),
    ).is_ok
    assert not check_local_loopback_http_envelope(
        grant_compact.value,
        proof_compact.value,
        replace(expected, trusted_issuer=TrustedIssuer("issuer-1", holder_public)),
    ).is_ok
    assert not check_local_loopback_http_envelope(
        grant_compact.value,
        proof_compact.value,
        replace(expected, invocation_id="550e8400-e29b-41d4-a716-446655440001"),
    ).is_ok
    assert not check_envelope(grant_compact.value, proof_compact.value, expected).is_ok

    no_nonce = replace(proof_input, nonce=None)
    assert not local_loopback_http_proof_signing_input(no_nonce).is_ok
    assert not local_loopback_http_proof_signing_input(
        replace(proof_input, proof_id="x" * 513)
    ).is_ok
    assert proof_signing_input(
        replace(
            proof_input,
            proof_id="x" * 513,
            target_uri="https://resource.example.test/invoke",
        )
    ).is_ok
    no_nonce_expected = replace(expected, nonce=NonceNotRequired())
    assert not check_local_loopback_http_envelope(
        grant_compact.value, proof_compact.value, no_nonce_expected
    ).is_ok


def test_certified_local_loopback_corpus_drives_python_verdicts() -> None:
    root = (
        Path(__file__).resolve().parents[3]
        / "priv/conformance/application-profiles/local-loopback-http/v1"
    )
    index_bytes = (root / "index.json").read_bytes()
    assert hashlib.sha256(index_bytes).hexdigest() == _CERTIFIED_INDEX_SHA256
    index = json.loads(index_bytes)
    assert index["profile"] == "bap-application-proof/local-loopback-http/1"
    assert index["revision"] == 1
    assert index["proof_cases"] == 8
    assert index["uri_cases"] == 36
    assert [entry["path"] for entry in index["files"]] == ["profile.json", "proof-cases.json"]
    for file in index["files"]:
        assert hashlib.sha256((root / file["path"]).read_bytes()).hexdigest() == file["sha256"]

    profile = json.loads((root / "profile.json").read_text())
    assert len(profile["uri_cases"]) == index["uri_cases"]
    for uri_case in profile["uri_cases"]:
        result = local_loopback_http_uri_normalize(uri_case["input"].encode())
        assert result.is_ok == uri_case["valid"], uri_case["id"]
        if result.is_ok:
            assert result.value.decode() == uri_case["normalized"], uri_case["id"]

    certified = profile["proofs"]["ipv4"]["compact"]
    protected, payload, signature = certified.split(".")
    producer = ProofProducer(
        holder_public_key=base64.urlsafe_b64decode(profile["holder_public_key"] + "=="),
        proof_id=profile["proofs"]["ipv4"]["proof_id"],
        method=profile["request"]["method"],
        target_uri=profile["proofs"]["ipv4"]["target_uri"],
        issued_at=profile["request"]["evaluation_time"],
        invocation_id=profile["request"]["invocation_id"],
        operation=profile["request"]["operation"],
        grant_compact=profile["grant_compact"].encode(),
        cast_arguments=JObject({"record_id": JString(b"record-1")}),
        nonce=profile["proofs"]["ipv4"]["nonce"],
    )
    signing_input = local_loopback_http_proof_signing_input(producer)
    assert signing_input.is_ok
    assert signing_input.value.protected_segment == protected.encode()
    assert signing_input.value.payload_segment == payload.encode()
    assembled = assemble_local_loopback_http_compact(
        signing_input.value, base64.urlsafe_b64decode(signature + "==")
    )
    assert assembled.is_ok and assembled.value.decode() == certified
    assert not assemble_compact(
        signing_input.value, base64.urlsafe_b64decode(signature + "==")
    ).is_ok

    expected = ExpectedRequest(
        trusted_issuer=TrustedIssuer(
            key_id=profile["issuer"]["key_id"],
            public_key=base64.urlsafe_b64decode(profile["issuer"]["public_key"] + "=="),
        ),
        issuer=profile["issuer"]["issuer"],
        audience=profile["issuer"]["audience"],
        method=profile["request"]["method"],
        target_uri=profile["proofs"]["ipv4"]["target_uri"],
        invocation_id=profile["request"]["invocation_id"],
        operation=profile["request"]["operation"],
        cast_arguments=JObject({"record_id": JString(b"record-1")}),
        evaluation_time=profile["request"]["evaluation_time"],
        clock_skew=profile["request"]["clock_skew"],
        proof_max_age=profile["request"]["proof_max_age"],
        nonce=NonceRequired(profile["proofs"]["ipv4"]["nonce"]),
    )
    grant = profile["grant_compact"].encode()

    ipv6 = profile["proofs"]["ipv6"]
    ipv6_producer = replace(
        producer,
        proof_id=ipv6["proof_id"],
        target_uri=ipv6["target_uri"],
        nonce=ipv6["nonce"],
    )
    ipv6_input = local_loopback_http_proof_signing_input(ipv6_producer)
    assert ipv6_input.is_ok
    ipv6_protected, ipv6_payload, ipv6_signature = ipv6["compact"].split(".")
    assert ipv6_input.value.protected_segment == ipv6_protected.encode()
    assert ipv6_input.value.payload_segment == ipv6_payload.encode()
    ipv6_assembled = assemble_local_loopback_http_compact(
        ipv6_input.value, base64.urlsafe_b64decode(ipv6_signature + "==")
    )
    assert ipv6_assembled.is_ok and ipv6_assembled.value.decode() == ipv6["compact"]
    assert decode_local_loopback_http_proof(ipv6_assembled.value).is_ok
    assert check_local_loopback_http_envelope(
        grant,
        ipv6_assembled.value,
        replace(
            expected,
            target_uri=ipv6["target_uri"],
            nonce=NonceRequired(ipv6["nonce"]),
        ),
    ).is_ok

    proof_cases = json.loads((root / "proof-cases.json").read_text())
    assert len(proof_cases) == index["proof_cases"]
    for proof_case in proof_cases:
        compact = proof_case["compact"].encode()
        overrides = proof_case.get("expected_overrides", {})
        assert set(overrides) <= {"trusted_issuer_public_key", "invocation_id"}
        assert len(overrides) <= 1
        case_expected = expected
        if "trusted_issuer_public_key" in overrides:
            case_expected = replace(
                case_expected,
                trusted_issuer=replace(
                    case_expected.trusted_issuer,
                    public_key=base64.urlsafe_b64decode(
                        overrides["trusted_issuer_public_key"] + "=="
                    ),
                ),
            )
        if "invocation_id" in overrides:
            case_expected = replace(case_expected, invocation_id=overrides["invocation_id"])
        assert decode_local_loopback_http_proof(compact).is_ok == proof_case["decode_local"], (
            proof_case["id"]
        )
        assert decode_proof(compact).is_ok == proof_case["decode_standard"], proof_case["id"]
        assert (
            check_local_loopback_http_envelope(grant, compact, case_expected).is_ok
            == proof_case["envelope_local"]
        ), proof_case["id"]
