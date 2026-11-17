"""Decoded diagnostics retain the specified diagnostic rendering (spec/diagnostic-rendering.md § Diagnostic rendering) without exporting redacted members."""

import copy
import json
import pickle
from dataclasses import asdict, fields
from pathlib import Path

import pytest

from bounded_authority_verifier.facts import ContentAssertionDecoded, ProofDecoded

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


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

    from bounded_authority_verifier import JArray, JObject, JString
    from bounded_authority_verifier.facts import AttestationDecoded, GrantDecoded

    gold = fixture("decoded-rendering.json")
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

    from bounded_authority_verifier import Ok, v1, v2, v3

    rows = fixture("decoded-wire-rendering.json")
    for row in rows:
        major = {1: v1, 2: v2, 3: v3}[row["major"]]
        result = getattr(major, f"decode_{row['kind']}")(row["compact"].encode())
        assert isinstance(result, Ok)
        assert str(result.value) == repr(result.value) == row["expected"], row.get(
            "id", row["kind"]
        )


def test_decoded_binary_notation_matches_independent_reference():

    from bounded_authority_verifier import _inspect

    rows = fixture("decoded-binary-rendering.json")
    for row in rows:
        assert _inspect.binary(bytes.fromhex(row["hex"])) == row["expected"], row.get(
            "id", row["hex"][:32]
        )


def test_float_notation_matches_specified_fixture_bytes():

    from bounded_authority_verifier import _inspect

    gold = fixture("decoded-rendering.json")
    for key, expected in gold.items():
        if key.startswith("float:"):
            assert _inspect.render(_inspect.scalar(float(key[6:]))) == expected, key


def test_hand_built_selectors_and_nested_values_are_total():
    from bounded_authority_verifier import _inspect as display
    from bounded_authority_verifier.json_alg import JArray, JFloat, JInt, JObject, JString

    for kind in [b"x\ny", b"\xff", b"", b"Upper", b"a-b", b"a?b", "é".encode()]:
        value = JObject({"kind": JString(kind), "path": JArray(()), "value": JInt(1)})
        assert display.render(display.selector(value)) == "{#unrenderable, [], {:integer, 1}}"
    malformed = [
        JInt(1),
        JObject({}),
        JObject({"kind": JInt(1)}),
        JObject({"kind": JString(b"eq")}),
        JObject({"kind": JString(b"eq"), "path": JInt(1), "value": JInt(1)}),
        JObject({"kind": JString(b"eq"), "path": JArray((JInt(1),)), "value": JInt(1)}),
        JObject({"kind": JString(b"eq"), "path": JArray(())}),
        JObject({"kind": JString(b"one_of"), "path": JArray(()), "values": JInt(1)}),
    ]
    for value in malformed:
        assert display.render(display.selector(value)) == "#unrenderable"
    for kind in ["_", "ready?", "run!", "aB_9"]:
        assert display.render(display.atom(kind)) == ":" + kind
    for value in [float("nan"), float("inf"), -float("inf")]:
        assert (
            display.render(display.tagged(JArray((JFloat(value),))))
            == "{:array, [float: #unrenderable]}"
        )
    assert display.render(display.tagged(JString(b"\xff"))) == "{:string, <<255>>}"
    assert display.render(display.operations((JObject({}),), 1)) == "[#unrenderable]"
    operation = JObject({"name": JObject({}), "selectors": JInt(1)})

    gold = fixture("decoded-rendering.json")
    assert display.render(display.operations((operation,), 1)) == gold["handbuilt:operation"]
    cycle = []
    cycle.append(cycle)
    assert "..." in display.render(display.native(cycle))
    nested = JInt(1)
    for _ in range(1000):
        nested = JArray((nested,))
    assert "..." in display.render(display.tagged(nested))


def test_hand_built_public_fields_never_raise_or_emit_controls():
    from dataclasses import replace

    from bounded_authority_verifier.facts import AttestationDecoded, GrantDecoded

    grant = GrantDecoded(1, "kid", "issuer", "grant", ("aud",), 1, 2, 3, bytes(32), ())
    attestation = AttestationDecoded("attestor", "jti", "subject", bytes(32), "issuer", 1, 2)
    for original in [grant, attestation]:
        for field in fields(original):
            changed = replace(original, **{field.name: {"hidden": 1}})
            assert "#unrenderable" in repr(changed)
        for field in fields(original):
            if isinstance(getattr(original, field.name), str):
                changed = replace(original, **{field.name: "x\ny\udcff"})
                output = repr(changed)
                assert "\n" not in output
                output.encode("utf-8", errors="strict")
    original = proof()
    kwargs = {slot.removeprefix("_"): getattr(original, slot) for slot in original.__slots__}
    for name in kwargs:
        changed = ProofDecoded(**(kwargs | {name: {"hidden": 1}}))
        output = repr(changed)
        assert ("nonce: :redacted" if name == "nonce" else "#unrenderable") in output
        assert "hidden" not in output
    assert repr(GrantDecoded(0, "", "", "", (), 0, 0, 0, b"", ())) == "#unrenderable"


def test_large_binary_and_string_expansion_is_bounded():
    from bounded_authority_verifier import _inspect as display

    value = b"\xff" + bytes(4 * 1024 * 1024)
    expected = "<<255, " + ", ".join(["0"] * 199) + ", ...>>"
    assert display.binary(value) == display.binary(value[:201]) == expected
    assert len(display.raw(value).raw) <= 16384
    assert len(display.text("😀" * (1024 * 1024)).raw) <= 16384
    assert display.string("😀" * 4096) == '"' + "😀" * 4096 + '"'


def test_diagnostics_do_not_call_off_domain_display_hooks_or_integer_limits():
    from dataclasses import replace

    from bounded_authority_verifier import _inspect as display
    from bounded_authority_verifier.facts import GrantDecoded

    class OffDomain:
        @property
        def __class__(self):
            raise AssertionError("class hook")

        def __repr__(self):
            raise AssertionError("display hook")

    class Text(str):
        def __getitem__(self, index):
            raise AssertionError("slice hook")

        def encode(self, *args, **kwargs):
            raise AssertionError("encoding hook")

    grant = GrantDecoded(1, "kid", "issuer", "grant", (), 0, 0, 0, b"", ())
    assert "key_id: #unrenderable" in repr(replace(grant, key_id=OffDomain()))
    assert display.string(Text("x\ny")) == '"x\\ny"'
    assert display.render(display.scalar(10**5000)) == "1" + "0" * 5000


def test_native_tuple_fields_keep_tuple_shape_without_expanding_before_the_cap():
    from bounded_authority_verifier import _inspect as display

    assert display.render(display.native((1, 2))) == "{1, 2}"
    value = [tuple(range(1024 * 1024))]
    expected = "[{" + ", ".join(str(i) for i in range(199)) + ", ...}]"
    assert display.render(display.native(value)) == expected
