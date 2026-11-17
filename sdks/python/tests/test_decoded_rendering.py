"""Decoded diagnostics retain the specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering) without exporting redacted members."""

import copy
import pickle
from dataclasses import asdict, fields

import pytest

from bounded_authority_verifier.facts import ContentAssertionDecoded, ProofDecoded


def content():
    return ContentAssertionDecoded(
        1,
        "hidden-attestor",
        "hidden-jti",
        "hidden-iss",
        "hidden-aud",
        "hidden-sub",
        "hidden-profile",
        b"x" * 32,
        b"y" * 32,
        1,
        bytes(32),
        1,
        1,
        2,
    )


def proof():
    return ProofDecoded(
        version=1,
        proof_id="proof",
        method="POST",
        target_uri="https://example.test/",
        issued_at=1,
        nonce="hidden-nonce",
        invocation_id="invocation",
        operation="read",
        grant_hash=bytes(32),
        request_hash=bytes(32),
        holder_public_key=bytes(32),
        holder_thumbprint=bytes(32),
    )


def test_content_rendering_is_exact():
    expected = "#BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion<redacted>"
    assert repr(content()) == str(content()) == expected


def test_proof_rendering_is_exact_and_hides_nonce():
    raw = "<<" + ", ".join(["0"] * 32) + ">>"
    expected = (
        '#BoundedAuthorityProtocol.V1.DecodedProof<version: 1, proof_id: "proof", method: "POST", '
        'target_uri: "https://example.test/", issued_at: 1, nonce: :redacted, invocation_id: "invocation", '
        'operation: "read", grant_hash: '
        + raw
        + ", request_hash: "
        + raw
        + ", holder_public_key: "
        + raw
        + ", holder_thumbprint: "
        + raw
        + ", verification: :not_evaluated>"
    )
    assert repr(proof()) == str(proof()) == expected


@pytest.mark.parametrize("factory", [content, proof])
@pytest.mark.parametrize(
    "operation",
    [
        asdict,
        fields,
        vars,
        copy.copy,
        copy.deepcopy,
        pickle.dumps,
        lambda v: v.__reduce__(),
        lambda v: v.__getstate__(),
    ],
)
def test_redacted_decoded_types_refuse_bulk_export(factory, operation):
    with pytest.raises(TypeError):
        operation(factory())


@pytest.mark.parametrize("factory", [content, proof])
def test_redacted_decoded_types_are_immutable(factory):
    value = factory()
    with pytest.raises(AttributeError):
        value.verification = "changed"
    with pytest.raises(TypeError):
        # Supplying every argument still cannot overwrite a live value.
        if factory is proof:
            value.__init__(
                1,
                "changed",
                "POST",
                "https://example.test/",
                1,
                "changed",
                "id",
                "read",
                bytes(32),
                bytes(32),
                bytes(32),
                bytes(32),
            )
        else:
            value.__init__(
                1,
                "changed",
                "id",
                "iss",
                "aud",
                "sub",
                "profile",
                bytes(32),
                bytes(32),
                1,
                bytes(32),
                1,
                1,
                2,
            )


@pytest.mark.parametrize("major", [1, 2, 3])
def test_each_decoded_surface_matches_reference_golden(major):
    import json
    from pathlib import Path

    from bounded_authority_verifier import JArray, JObject, JString
    from bounded_authority_verifier.facts import AttestationDecoded, GrantDecoded

    gold = json.loads((Path(__file__).parent / "fixtures" / "decoded-rendering.json").read_text())
    grant = GrantDecoded(
        major,
        "kid",
        "issuer",
        "grant",
        ("aud",),
        1,
        2,
        3,
        bytes(32),
        (
            JObject(
                {
                    "name": JString(b"read"),
                    "selectors": JArray((JObject({"kind": JString(b"all")}),)),
                }
            ),
        ),
    )
    decoded = ProofDecoded(
        major,
        "proof",
        "POST",
        "https://example.test/",
        1,
        "hidden-nonce",
        "invocation",
        "read",
        bytes(32),
        bytes(32),
        bytes(32),
        bytes(32),
    )
    attestation = AttestationDecoded("attestor", "jti", "subject", bytes(32), "issuer", 1, 2)
    for value, key in [
        (grant, f"grant{major}"),
        (decoded, f"proof{major}"),
        (attestation, "attestation"),
        (content(), "content"),
    ]:
        assert repr(value) == str(value) == gold[key]


def test_real_decoded_compacts_match_independent_reference():
    import json
    from pathlib import Path

    from bounded_authority_verifier import Ok, v1, v2, v3

    rows = json.loads(
        (Path(__file__).parent / "fixtures" / "decoded-wire-rendering.json").read_text()
    )
    for row in rows:
        major = {1: v1, 2: v2, 3: v3}[row["major"]]
        result = getattr(major, f"decode_{row['kind']}")(row["compact"].encode())
        assert isinstance(result, Ok)
        assert str(result.value) == repr(result.value) == row["expected"]


def test_decoded_binary_notation_matches_independent_reference():
    import json
    from pathlib import Path

    from bounded_authority_verifier import _inspect

    rows = json.loads(
        (Path(__file__).parent / "fixtures" / "decoded-binary-rendering.json").read_text()
    )
    for row in rows:
        assert _inspect.binary(bytes.fromhex(row["hex"])) == row["expected"]
