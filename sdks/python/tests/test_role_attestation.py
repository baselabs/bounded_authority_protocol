import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bounded_authority_verifier import (
    AttestationProducer,
    ExpectedAttestation,
    SigningInput,
    TrustedAttestor,
    assemble_attestation_compact,
    assemble_compact,
    attestation_signing_input,
    base64url_encode,
    decode_attestation,
    decode_grant,
    decode_proof,
    public_key_thumbprint_raw,
    verify_attestation,
)
from bounded_authority_verifier import role_attestation as role_attestation_module
from bounded_authority_verifier.bounds import Bounds, bounds_new
from bounded_authority_verifier.error import InvalidError

_CERTIFIED_INDEX_SHA256 = "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

# The corpus override contract: at most one single-field override, or exactly the two-key
# self-attestation form. Any unknown key or other combination is a corpus change that must be
# reviewed, not silently applied.
_SINGLE_OVERRIDES = {"now", "subject_public_key", "subject_key_id", "attestor_public_key"}
_PAIR_OVERRIDE = {"subject_key_id", "subject_public_key"}


@pytest.mark.parametrize("surface", ["produce", "assemble", "decode", "verify"])
@pytest.mark.parametrize(
    "ceiling",
    [
        "anchor_bytes",
        "compact_bytes",
        "encoded_segment_bytes",
        "decoded_segment_bytes",
        "json_bytes",
        "number_lexeme_bytes",
    ],
)
def test_attestation_tightened_size_bounds(surface: str, ceiling: str) -> None:
    root = _corpus_root()
    profile = json.loads((root / "profile.json").read_text())
    case = next(
        case for case in json.loads((root / "attestation-cases.json").read_text())
        if case["id"] == "issuer-valid"
    )
    compact = case["compact"].encode()
    protected, payload, signature = compact.split(b".")
    claims = json.loads(_b64url(payload.decode()))
    producer = AttestationProducer(
        attestor_key_id=profile["attestor"]["key_id"],
        jti=claims["jti"],
        key_id=claims["key_id"],
        public_key=_b64url(claims["public_key"]),
        role=claims["role"],
        nbf=claims["nbf"],
        exp=claims["exp"],
    )
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id=profile["attestor"]["key_id"],
            public_key=_b64url(profile["attestor"]["public_key"]),
            valid_from=profile["attestor"]["valid_from"],
            valid_before=profile["attestor"]["valid_before"],
        ),
        subject_key_id=claims["key_id"],
        subject_public_key=producer.public_key,
        now=profile["now"],
    )
    signing_input = attestation_signing_input(producer).value
    assert _signing_message(signing_input) == protected + b"." + payload
    if ceiling in ("anchor_bytes", "compact_bytes"):
        size = len(compact)
    elif ceiling == "encoded_segment_bytes":
        size = max(map(len, (protected, payload, signature)))
    elif ceiling == "decoded_segment_bytes":
        size = max(
            map(
                len,
                (
                    _b64url(protected.decode()),
                    _b64url(payload.decode()),
                    _b64url(signature.decode()),
                ),
            )
        )
    elif ceiling == "json_bytes":
        size = max(map(len, (_b64url(protected.decode()), _b64url(payload.decode()))))
    else:
        size = max(len(str(claims[key])) for key in ("v", "nbf", "exp"))
    for limit, accepted in ((size, True), (size - 1, False), (1, False)):
        bounds = bounds_new({ceiling: limit})
        if surface == "produce":
            result = attestation_signing_input(producer, bounds)
        elif surface == "assemble":
            result = assemble_attestation_compact(signing_input, _b64url(signature.decode()), bounds)
        elif surface == "decode":
            result = decode_attestation(compact, bounds)
        else:
            result = verify_attestation(compact, replace(expected, bounds=bounds))
        assert result.is_ok == accepted, (surface, ceiling, limit)


def _corpus_root() -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "priv/conformance/attestation-profiles/role-attestation/v1"
    )


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "==")


def _keypair() -> tuple[bytes, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return public, private


def _signing_message(signing_input: SigningInput) -> bytes:
    return signing_input.protected_segment + b"." + signing_input.payload_segment


def _signed_attestation(
    *,
    attestor_key_id: str = "attestor-1",
    jti: str = "urn:example:attestation:ra-1",
    subject_key_id: str = "subject-1",
    payload_overrides: dict[str, object] | None = None,
    payload_remove: tuple[str, ...] = (),
) -> tuple[AttestationProducer, SigningInput, bytes, bytes, ExpectedAttestation]:
    subject_public, _ = _keypair()
    attestor_public, attestor_private = _keypair()
    producer = AttestationProducer(
        attestor_key_id=attestor_key_id,
        jti=jti,
        key_id=subject_key_id,
        public_key=subject_public,
        role="issuer",
        nbf=1000,
        exp=2000,
    )
    header = {"alg": "EdDSA", "kid": attestor_key_id, "typ": "ba+role-attestation"}
    payload: dict[str, object] = {
        "exp": 2000,
        "jti": jti,
        "key_id": subject_key_id,
        "nbf": 1000,
        "public_key": base64url_encode(subject_public).decode(),
        "role": "issuer",
        "v": 1,
    }
    for key in payload_remove:
        del payload[key]
    if payload_overrides is not None:
        payload.update(payload_overrides)
    signing_input = SigningInput(
        kind="role_attestation",
        protected_segment=base64url_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
        ),
        payload_segment=base64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ),
    )
    signature = attestor_private.sign(_signing_message(signing_input))
    compact = _signing_message(signing_input) + b"." + base64url_encode(signature)
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id=attestor_key_id,
            public_key=attestor_public,
            valid_from=1000,
            valid_before=2000,
        ),
        subject_key_id=subject_key_id,
        subject_public_key=subject_public,
        now=1500,
    )
    return producer, signing_input, signature, compact, expected


def _apply_overrides(
    expected: ExpectedAttestation, overrides: dict[str, object]
) -> ExpectedAttestation:
    keys = set(overrides)
    assert keys <= _SINGLE_OVERRIDES, overrides
    assert keys == _PAIR_OVERRIDE or len(keys) <= 1, overrides
    if "now" in overrides:
        expected = replace(expected, now=overrides["now"])
    if "subject_public_key" in overrides:
        expected = replace(
            expected, subject_public_key=_b64url(overrides["subject_public_key"])
        )
    if "subject_key_id" in overrides:
        expected = replace(expected, subject_key_id=overrides["subject_key_id"])
    if "attestor_public_key" in overrides:
        expected = replace(
            expected,
            attestor=replace(
                expected.attestor,
                public_key=_b64url(overrides["attestor_public_key"]),
            ),
        )
    return expected


def test_certified_role_attestation_corpus_drives_python_verdicts() -> None:
    root = _corpus_root()
    index_bytes = (root / "index.json").read_bytes()
    assert hashlib.sha256(index_bytes).hexdigest() == _CERTIFIED_INDEX_SHA256
    index = json.loads(index_bytes)
    assert index["profile"] == "bap-role-attestation/1"
    assert index["revision"] == 1
    assert index["attestation_cases"] == 40
    assert [entry["path"] for entry in index["files"]] == ["profile.json", "attestation-cases.json"]
    for file in index["files"]:
        assert hashlib.sha256((root / file["path"]).read_bytes()).hexdigest() == file["sha256"]

    profile = json.loads((root / "profile.json").read_text())
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id=profile["attestor"]["key_id"],
            public_key=_b64url(profile["attestor"]["public_key"]),
            valid_from=profile["attestor"]["valid_from"],
            valid_before=profile["attestor"]["valid_before"],
        ),
        subject_key_id=profile["subject"]["key_id"],
        subject_public_key=_b64url(profile["subject"]["public_key"]),
        now=profile["now"],
    )

    cases = json.loads((root / "attestation-cases.json").read_text())
    assert len(cases) == index["attestation_cases"]
    for case in cases:
        compact = case["compact"].encode()
        case_expected = _apply_overrides(expected, case.get("expected_overrides", {}))
        assert decode_attestation(compact).is_ok == case["decode"], case["id"]
        assert verify_attestation(compact, case_expected).is_ok == case["verify"], case["id"]
        # Cross-profile rejection, this direction: the v1 grant decoder accepts ONLY the case the
        # corpus marks v1_grant (the grant-with-ba+cap confusion probe) and rejects every
        # ba+role-attestation compact.
        assert decode_grant(compact).is_ok == case.get("v1_grant", False), case["id"]


def test_role_attestation_producer_assembles_and_stays_profile_distinct() -> None:
    profile = json.loads((_corpus_root() / "profile.json").read_text())
    subject_public = _b64url(profile["subject"]["public_key"])
    # The corpus carries public key material only (no secret material in conformance fixtures), so
    # the TEST generates the attestor signing key; the library still accepts only external
    # signatures (REQ-RA1-API-no-signer).
    attestor_public, attestor_private = _keypair()
    jti = "urn:example:attestation:ra-1"
    producer = AttestationProducer(
        attestor_key_id=profile["attestor"]["key_id"],
        jti=jti,
        key_id=profile["subject"]["key_id"],
        public_key=subject_public,
        role="issuer",
        nbf=profile["attestor"]["valid_from"],
        exp=profile["attestor"]["valid_before"],
    )
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id=profile["attestor"]["key_id"],
            public_key=attestor_public,
            valid_from=profile["attestor"]["valid_from"],
            valid_before=profile["attestor"]["valid_before"],
        ),
        subject_key_id=profile["subject"]["key_id"],
        subject_public_key=subject_public,
        now=profile["now"],
    )

    signing_input = attestation_signing_input(producer)
    assert signing_input.is_ok
    compact = assemble_attestation_compact(
        signing_input.value, attestor_private.sign(_signing_message(signing_input.value))
    )
    assert compact.is_ok

    protected_json = json.loads(_b64url(compact.value.split(b".")[0].decode()))
    assert protected_json == {
        "alg": "EdDSA",
        "kid": profile["attestor"]["key_id"],
        "typ": "ba+role-attestation",
    }
    payload_json = json.loads(_b64url(compact.value.split(b".")[1].decode()))
    assert payload_json == {
        "v": 1,
        "jti": jti,
        "key_id": profile["subject"]["key_id"],
        "public_key": profile["subject"]["public_key"],
        "role": "issuer",
        "nbf": profile["attestor"]["valid_from"],
        "exp": profile["attestor"]["valid_before"],
    }

    decoded = decode_attestation(compact.value)
    assert decoded.is_ok
    assert decoded.value.attestor_key_id == profile["attestor"]["key_id"]
    assert decoded.value.jti == jti
    assert decoded.value.subject_key_id == profile["subject"]["key_id"]
    assert decoded.value.public_key == subject_public
    assert decoded.value.verification == "not_evaluated"

    result = verify_attestation(compact.value, expected)
    assert result.is_ok
    facts = result.value
    assert facts.attestor_key_id == profile["attestor"]["key_id"]
    assert facts.subject_key_id == profile["subject"]["key_id"]
    assert facts.role == "issuer"
    assert facts.jti == jti
    assert facts.nbf == profile["attestor"]["valid_from"]
    assert facts.exp == profile["attestor"]["valid_before"]
    assert facts.attestor_key_fingerprint == public_key_thumbprint_raw(attestor_public)
    assert facts.subject_key_fingerprint == public_key_thumbprint_raw(subject_public)
    assert facts.verification == "signature_and_window"
    assert facts.trust == "not_evaluated"

    # A configured-unbounded attestor window contains the same attestation (REQ-RA1-SECURITY-
    # trust-scope: unboundedness is the deployment's choice, never a decode-level defect).
    unbounded = replace(expected, attestor=replace(expected.attestor, valid_before=None))
    assert verify_attestation(compact.value, unbounded).is_ok

    # Both valid roles assemble and verify.
    holder_input = attestation_signing_input(replace(producer, role="holder"))
    assert holder_input.is_ok
    holder_compact = assemble_attestation_compact(
        holder_input.value, attestor_private.sign(_signing_message(holder_input.value))
    )
    assert holder_compact.is_ok
    holder_result = verify_attestation(holder_compact.value, expected)
    assert holder_result.is_ok
    assert holder_result.value.role == "holder"

    # Cross-profile rejection, this direction: the v1 grant/proof decoders reject the compact, and
    # the v1 assembler rejects the role-attestation signing input.
    assert not decode_grant(compact.value).is_ok
    assert not decode_proof(compact.value).is_ok
    assert not assemble_compact(
        signing_input.value, attestor_private.sign(_signing_message(signing_input.value))
    ).is_ok


def test_attestation_producer_fails_closed() -> None:
    subject_public, _ = _keypair()
    base = AttestationProducer(
        attestor_key_id="attestor-1",
        jti="urn:example:attestation:ra-1",
        key_id="subject-1",
        public_key=subject_public,
        role="issuer",
        nbf=1000,
        exp=2000,
    )
    for mutant in [
        replace(base, role="admin"),
        replace(base, role=7),
        replace(base, public_key=b"a" * 31),
        replace(base, public_key=b"a" * 33),
        replace(base, nbf=2000, exp=2000),
        replace(base, nbf=2001, exp=2000),
        replace(base, nbf=1000.0),
        replace(base, exp=2000.0),
        replace(base, jti=""),
        replace(base, key_id="subject key!"),
        replace(base, attestor_key_id=""),
    ]:
        assert not attestation_signing_input(mutant).is_ok, mutant


def test_attestation_assembly_revalidates() -> None:
    subject_public, _ = _keypair()
    attestor_public, attestor_private = _keypair()
    producer = AttestationProducer(
        attestor_key_id="attestor-1",
        jti="urn:example:attestation:ra-1",
        key_id="subject-1",
        public_key=subject_public,
        role="issuer",
        nbf=1000,
        exp=2000,
    )
    signing_input = attestation_signing_input(producer)
    assert signing_input.is_ok
    signature = attestor_private.sign(_signing_message(signing_input.value))
    assert assemble_attestation_compact(signing_input.value, signature).is_ok

    # Wrong kind: the attestation assembler accepts only role_attestation signing inputs.
    assert not assemble_attestation_compact(
        SigningInput(
            kind="grant",
            protected_segment=signing_input.value.protected_segment,
            payload_segment=signing_input.value.payload_segment,
        ),
        signature,
    ).is_ok

    # Wrong signature width (Ed25519 signatures are exactly 64 bytes).
    assert not assemble_attestation_compact(signing_input.value, signature[:63]).is_ok

    # Non-canonical payload: same members, non-JCS member order — assembly re-parses under the
    # profile and rejects bytes its own consumer would reject (REQ-RA1-API-assembly-revalidate).
    non_canonical_payload = json.dumps(
        {
            "v": 1,
            "jti": producer.jti,
            "key_id": producer.key_id,
            "public_key": base64url_encode(subject_public).decode(),
            "role": "issuer",
            "nbf": 1000,
            "exp": 2000,
        },
        separators=(",", ":"),
    ).encode()
    assert not assemble_attestation_compact(
        SigningInput(
            kind="role_attestation",
            protected_segment=signing_input.value.protected_segment,
            payload_segment=base64url_encode(non_canonical_payload),
        ),
        signature,
    ).is_ok


def test_attestation_payload_member_set_rejects_comma_join_collision() -> None:
    _, signing_input, signature, compact, expected = _signed_attestation(
        payload_overrides={"role,v": "issuer"},
        payload_remove=("role", "v"),
    )

    assert not assemble_attestation_compact(signing_input, signature).is_ok
    assert not decode_attestation(compact).is_ok
    assert not verify_attestation(compact, expected).is_ok


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attestor_key_id", "attestor-1\n"),
        ("key_id", "subject-1\n"),
        ("jti", "urn:example:attestation:ra-1\n"),
    ],
)
def test_attestation_identifiers_reject_trailing_newline(field: str, value: str) -> None:
    kwargs = {
        "attestor_key_id": "attestor-1",
        "jti": "urn:example:attestation:ra-1",
        "subject_key_id": "subject-1",
    }
    kwargs["subject_key_id" if field == "key_id" else field] = value
    producer, _, _, compact, expected = _signed_attestation(**kwargs)

    assert not attestation_signing_input(producer).is_ok
    assert not decode_attestation(compact).is_ok
    assert not verify_attestation(compact, expected).is_ok


@pytest.mark.parametrize(
    "jti",
    [
        "https://[bad]",
        "https://[::1]:abc",
        "https://[::1",
        "https://[1::2::3]",
        "urn:example:%",
        "urn:example://[bad]",
        "https://example.com/[bad]",
        "https://example.com/?q=[bad]",
        "https://example.com/#[bad]",
        "https://[user]@example.com",
        "https://host/#a#b",
        "urn:a#b#c",
    ],
)
def test_attestation_jti_rejects_malformed_uri(jti: str) -> None:
    producer, _, _, compact, expected = _signed_attestation(jti=jti)

    assert not attestation_signing_input(producer).is_ok
    assert not decode_attestation(compact).is_ok
    assert not verify_attestation(compact, expected).is_ok


@pytest.mark.parametrize(
    "jti",
    [
        "https://user:pass@example.com",
        "file:///tmp",
        "https://:80",
        "https://user@",
        "urn:example://host",
        "https://host/?a?b",
        "https://host/a:b",
        "https://example.com/%5Bbad%5D",
        "plain[bad]",
    ],
)
def test_attestation_jti_accepts_reference_uri(jti: str) -> None:
    producer, signing_input, signature, compact, expected = _signed_attestation(jti=jti)

    produced = attestation_signing_input(producer)
    assert produced.is_ok
    assert produced.value == signing_input
    assembled = assemble_attestation_compact(produced.value, signature)
    assert assembled.is_ok
    assert assembled.value == compact
    assert decode_attestation(compact).is_ok
    assert verify_attestation(compact, expected).is_ok


@pytest.mark.parametrize("field", ["attestor_key_id", "jti", "key_id"])
def test_attestation_producer_rejects_unicode_surrogate(field: str) -> None:
    producer, _, _, _, _ = _signed_attestation()
    assert not attestation_signing_input(replace(producer, **{field: "\ud800"})).is_ok


def test_attestation_unknown_bound_fails_closed_across_all_surfaces() -> None:
    producer, signing_input, signature, compact, expected = _signed_attestation()
    malformed_bounds = Bounds({"unknown": 1})

    assert not attestation_signing_input(producer, malformed_bounds).is_ok
    assert not assemble_attestation_compact(signing_input, signature, malformed_bounds).is_ok
    assert not decode_attestation(compact, malformed_bounds).is_ok
    assert not verify_attestation(
        compact, replace(expected, bounds=malformed_bounds)
    ).is_ok


def test_attestation_base64url_decoded_size_projection() -> None:
    projection = role_attestation_module._project_base64url_decoded_size
    assert [(size, projection(size)) for size in (0, 2, 3, 4, 86, 268)] == [
        (0, 0),
        (2, 1),
        (3, 2),
        (4, 3),
        (86, 64),
        (268, 201),
    ]


def test_attestation_preflights_overlong_signature_before_decode() -> None:
    _, _, _, compact, expected = _signed_attestation()
    protected, payload, _signature = compact.split(b".")
    hostile = protected + b"." + payload + b"." + base64url_encode(bytes(201))
    bounds = bounds_new({"decoded_segment_bytes": 200})

    with pytest.raises(InvalidError):
        role_attestation_module._preflight_attestation_compact(hostile, bounds)
    assert not decode_attestation(hostile, bounds).is_ok
    assert not verify_attestation(hostile, replace(expected, bounds=bounds)).is_ok


def test_attestation_verify_bounds_attestor_window_magnitudes() -> None:
    # Cross-vendor review leg (2026-09-22, claude peer over 639d74e..e5cd033): the attestor
    # context's window endpoints are magnitude-bounded caller input — the same
    # HistoricalPublicKey gates the Elixir reference (ContextValidation.historical_key) and the
    # Rust leg (role_attestation.rs) apply. A context with valid_from below or valid_before
    # above the integer magnitude ceiling must fail closed here too: containment alone is
    # trivially satisfied by those windows, so nothing downstream rejects them.
    subject_public, _ = _keypair()
    attestor_public, attestor_private = _keypair()
    producer = AttestationProducer(
        attestor_key_id="attestor-magnitude-1",
        jti="urn:example:attestation:magnitude-1",
        key_id="subject-magnitude-1",
        public_key=subject_public,
        role="issuer",
        nbf=1000,
        exp=2000,
    )
    signing_input = attestation_signing_input(producer)
    assert signing_input.is_ok
    compact = assemble_attestation_compact(
        signing_input.value, attestor_private.sign(_signing_message(signing_input.value))
    )
    assert compact.is_ok
    expected = ExpectedAttestation(
        attestor=TrustedAttestor(
            key_id="attestor-magnitude-1",
            public_key=attestor_public,
            valid_from=1000,
            valid_before=2000,
        ),
        subject_key_id="subject-magnitude-1",
        subject_public_key=subject_public,
        now=1500,
    )
    assert verify_attestation(compact.value, expected).is_ok

    # 2**60 sits far beyond the 2**53-1 integer magnitude ceiling shared by the bounds.
    beyond = 2**60
    # The two directions nothing downstream closes (containment is trivially true):
    assert not verify_attestation(
        compact.value,
        replace(expected, attestor=replace(expected.attestor, valid_from=-beyond)),
    ).is_ok
    assert not verify_attestation(
        compact.value,
        replace(expected, attestor=replace(expected.attestor, valid_before=beyond)),
    ).is_ok
    # The mirrored directions are containment-closed everywhere (nbf >= valid_from and
    # exp <= valid_before cannot hold); pinned so the asymmetry stays deliberate.
    assert not verify_attestation(
        compact.value,
        replace(expected, attestor=replace(expected.attestor, valid_from=beyond)),
    ).is_ok
    assert not verify_attestation(
        compact.value,
        replace(expected, attestor=replace(expected.attestor, valid_before=-beyond)),
    ).is_ok
