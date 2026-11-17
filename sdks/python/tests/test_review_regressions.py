"""Caller inputs close explicitly; programming errors and implicit truth tests stay visible."""

import ast
import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

import bounded_authority_verifier as bap
from bounded_authority_verifier import v1, v2, v3
from bounded_authority_verifier.compact import SigningInput, assemble_segments
from bounded_authority_verifier.json_alg import is_valid_utf8

_ROOT = Path(__file__).resolve().parents[3]


def _b64(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _unb64(value: str | bytes) -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def _envelope(major):
    cases = json.loads((_ROOT / f"priv/conformance/v{major.VERSION}/corpus/cases/envelope/check.json").read_text())
    if isinstance(cases, dict):
        cases = cases["cases"]
    inp = next(case["input"] for case in cases if case["class"] == "valid")
    expected = dict(inp["expected"])
    issuer = expected.pop("trusted_issuer")
    expected["cast_arguments"] = bap.json_decode(json.dumps(expected["cast_arguments"]).encode()).value
    expected["trusted_issuer"] = major.TrustedIssuer(issuer["key_id"], _unb64(issuer["public_key"]))
    expected["nonce"] = major.NonceNotRequired()
    return inp["grant"].encode(), inp["proof"].encode(), major.ExpectedRequest(**expected)


@pytest.mark.parametrize("major", [v1, v2, v3])
@pytest.mark.parametrize("surface", ["decode_proof", "check_envelope", "expected_uri"])
def test_oversize_port_fails_closed_through_each_facade(major, surface):
    grant, proof, expected = _envelope(major)
    assert isinstance(major.check_envelope(grant, proof, expected), bap.Ok)
    uri = "https://resource.example.test:" + "9" * 4301 + "/invoke"
    if surface == "expected_uri":
        result = major.check_envelope(grant, proof, replace(expected, target_uri=uri))
    else:
        header, payload, signature = proof.split(b".")
        claims = json.loads(_unb64(payload))
        claims["htu"] = uri
        proof = b".".join((header, _b64(json.dumps(claims, separators=(",", ":")).encode()), signature))
        result = major.decode_proof(proof) if surface == "decode_proof" else major.check_envelope(grant, proof, expected)
    assert isinstance(result, bap.Err)


@pytest.mark.parametrize("primitive,args", [
    (bap.acceptable_public_key, (None,)),
    (bap.torsion_free, (b"",)),
    (bap.verify_strict, (b"message", b"", b"")),
])
def test_crypto_predicates_are_plain_false(primitive, args):
    assert primitive(*args) is False


@pytest.mark.parametrize("result", [bap.Ok(False), bap.Ok(True), bap.err()])
def test_result_truthiness_is_refused(result):
    with pytest.raises(TypeError):
        bool(result)


class Text(str):
    def __str__(self):
        raise AssertionError("must use underlying characters")

    def encode(self, *args, **kwargs):
        raise AssertionError("must use base str encoding")


@pytest.mark.parametrize("factory", [bytes, bytearray, memoryview])
def test_bytes_like_primitives_and_facades(factory):
    assert bap.base64url_encode(factory(b"abc")) == bap.Ok(b"YWJj")
    assert bap.base64url_decode(factory(b"YWJj")) == bap.Ok(b"abc")
    assert bap.json_decode(factory(b"null")) == bap.Ok(bap.JNull())
    assert bap.utf8_str(factory(b"abc")) == bap.Ok("abc")
    for major in (v1, v2, v3):
        grant, proof, expected = _envelope(major)
        expected = replace(expected, trusted_issuer=replace(expected.trusted_issuer, public_key=factory(expected.trusted_issuer.public_key)))
        assert isinstance(major.decode_proof(factory(proof)), bap.Ok)
        assert isinstance(major.check_envelope(factory(grant), factory(proof), expected), bap.Ok)


def test_string_subclass_uses_underlying_data():
    assert bap.str_utf8(Text("abc")) == bap.Ok(b"abc")
    assert bap.jcs_encode(bap.JObject({Text("abc"): bap.JNull()})) == bap.Ok(b'{"abc":null}')
    grant, proof, expected = _envelope(v1)
    assert isinstance(v1.check_envelope(grant, proof, replace(expected, target_uri=Text(expected.target_uri))), bap.Ok)


@pytest.mark.parametrize("bad", [None, "signature", 64, [], object()])
def test_assembler_wrong_types_return_err(bad):
    assert isinstance(assemble_segments(SigningInput("proof", b"e30", b"e30"), bad), bap.Err)
    assert isinstance(assemble_segments(bad, b"x" * 64), bap.Err)


@pytest.mark.parametrize("value", [bap.JFloat("bad"), bap.JBool("false"), bap.JString(None), bap.JArray(None), bap.JObject({1: bap.JNull()}), bap.JObject({"x": object()})])
def test_malformed_tagged_values_fail_closed(value):
    assert isinstance(bap.jcs_encode(value), bap.Err)
    assert isinstance(bap.typed_project(value), bap.Err)
    for major in (v1, v2, v3):
        assert isinstance(major.request_digest("read", value), bap.Err)


def test_cyclic_tagged_input_is_bounded():
    members = {}
    value = bap.JObject(members)
    members["cycle"] = value
    assert isinstance(bap.typed_project(value), bap.Err)
    assert isinstance(bap.jcs_encode(value), bap.Err)
    for major in (v1, v2, v3):
        assert isinstance(major.request_digest("read", value), bap.Err)


def test_released_memoryview_is_closed():
    value = memoryview(b"abc")
    value.release()
    assert isinstance(bap.base64url_encode(value), bap.Err)
    assert bap.acceptable_public_key(value) is False


@pytest.mark.parametrize("value", [b"\xff", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xc0\x80", b"\xe2\x82"])
def test_invalid_utf8_fails_closed(value):
    assert isinstance(bap.utf8_str(value), bap.Err)
    assert is_valid_utf8(value) == bap.Ok(False)


def test_only_protocol_errors_are_caught():
    forbidden = {"Exception", "BaseException", "TypeError", "ValueError", "AttributeError", "KeyError", "IndexError", "OverflowError", "RecursionError"}
    source = Path(bap.__file__).parent
    catches = []
    for path in source.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                names = {part.id for part in ast.walk(node.type) if isinstance(part, ast.Name)}
                if names & forbidden:
                    catches.append(f"{path.name}:{node.lineno}")
    assert catches == []


def test_bounds_resolution_uses_validated_construction():
    limits = {"depth": 12}
    result = bap.bounds_new(limits)
    assert isinstance(result, bap.Ok)
    limits["depth"] = 999
    assert result.value.resolve("depth") == bap.Ok(12)
    tree = ast.parse((Path(bap.__file__).parent / "bounds.py").read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Bounds")
    resolve = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "resolve")
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"coerce_bounds", "bounds_new"} for node in ast.walk(resolve))
