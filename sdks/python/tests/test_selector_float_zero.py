"""Erratum 6 (selector float-zero soundness repair), through the public v1/v2/v3 surfaces.

Verification: grant decode rejects an ``equals`` value or ``one_of`` member holding a float-tagged
number equal to zero at any depth, whatever its sign or spelling; range bounds and inert ``all``
members are unchanged, and range comparison treats -0.0 and 0.0 as equal. Producers: the grant
signing-input producer refuses any float-tagged INTEGRAL selector value (its RFC 8785 bytes
would decode integer-tagged), range bounds included.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from bounded_authority_verifier import v1, v2, v3
from bounded_authority_verifier.base64url import base64url_encode
from bounded_authority_verifier.error import InvalidError
from bounded_authority_verifier.json_alg import JArray, JFloat, JInt, JObject, JString, Tagged

_MAJORS: dict[int, Any] = {1: v1, 2: v2, 3: v3}
_ALG = {1: "EdDSA", 2: "EdDSA", 3: "ES256"}
_JKT = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"

# Every spelling that decodes to a float-tagged zero (an underflowing exponent included).
_ZERO_SPELLINGS = ["0.0", "-0.0", "0e0", "-0e0", "-0E0", "-0e-5", "0.000", "1e-400", "-1e-400"]


def _b64(raw: bytes) -> str:
    return base64url_encode(raw).decode()


def _compact(major: int, selector_text: str) -> bytes:
    """A grant compact whose single selector is spliced in as raw JSON text, so the number
    LEXEME is exactly the one under test. decode_grant does not verify the signature."""
    header = json.dumps({"alg": _ALG[major], "kid": "issuer", "typ": "ba+cap"},
                        separators=(",", ":")).encode()
    payload = (
        '{"aud":["https://resource.example.test"],"cnf":{"jkt":"' + _JKT + '"},'
        '"exp":2000,"iat":1000,"iss":"https://issuer.example.test",'
        '"jti":"urn:example:grant:float-zero","nbf":1000,'
        '"operations":[{"name":"transfer","selectors":[' + selector_text + "]}],"
        f'"v":{major}}}'
    ).encode()
    return f"{_b64(header)}.{_b64(payload)}.{_b64(bytes([0x11]) * 64)}".encode()


def _decodes(major: int, selector_text: str) -> bool:
    try:
        return bool(_MAJORS[major].decode_grant(_compact(major, selector_text)).is_ok)
    except InvalidError:
        return False


def _equals(value_text: str) -> str:
    return '{"kind":"equals","path":["x"],"value":' + value_text + "}"


def _one_of(values_text: str) -> str:
    return '{"kind":"one_of","path":["x"],"values":' + values_text + "}"


ALL_MAJORS = [1, 2, 3]


# --- verification: grant decode ------------------------------------------------------------


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize("spelling", _ZERO_SPELLINGS)
def test_decode_rejects_float_zero_equals_value(major: int, spelling: str) -> None:
    assert not _decodes(major, _equals(spelling))


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize("spelling", _ZERO_SPELLINGS)
def test_decode_rejects_float_zero_one_of_member(major: int, spelling: str) -> None:
    assert not _decodes(major, _one_of(f"[1,{spelling}]"))


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize(
    "selector_text",
    [
        _equals("[1,-0.0]"),
        _equals('{"a":{"b":0.0}}'),
        _equals('[{"a":[2,"s",{"b":[-0e0]}]}]'),
        _one_of("[[0e0]]"),
        _one_of('[{"a":-0e-5}]'),
    ],
)
def test_decode_rejects_float_zero_at_any_depth(major: int, selector_text: str) -> None:
    assert not _decodes(major, selector_text)


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize(
    "selector_text",
    [
        _equals("0"),
        _equals("-0"),
        _equals("0.5"),
        _equals("10.0"),
        _equals("1e1"),
        _equals("[0,1.5]"),
        _equals('{"a":{"b":0}}'),
        _one_of("[0,10.0,-2.25]"),
        # Inert members of an `all` selector are not checked.
        '{"kind":"all","path":["x"],"value":-0.0}',
        '{"kind":"all","path":["x"],"values":[0.0]}',
    ],
)
def test_decode_accepts_integer_zero_and_nonzero_floats(major: int, selector_text: str) -> None:
    assert _decodes(major, selector_text)


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.parametrize("kind", ["lte", "gte"])
@pytest.mark.parametrize("spelling", ["0.0", "-0.0", "-0e0", "1e-400"])
def test_decode_accepts_float_zero_range_bound(major: int, kind: str, spelling: str) -> None:
    assert _decodes(major, '{"kind":"' + kind + '","path":["x"],"value":' + spelling + "}")


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.parametrize(("bound", "target"), [(0.0, -0.0), (-0.0, 0.0)])
def test_range_comparison_treats_signed_zeros_as_equal(major: int, bound: float, target: float) -> None:
    mod = _MAJORS[major]
    args = JObject({"x": JFloat(target)})
    assert mod.selector_matches(mod.SelLte(("x",), JFloat(bound)), args)
    assert mod.selector_matches(mod.SelGte(("x",), JFloat(bound)), args)


# --- producers: grant_signing_input --------------------------------------------------------


def _signs(major: int, selector: object) -> bool:
    mod = _MAJORS[major]
    producer = mod.GrantProducer(
        key_id="issuer", issuer="https://issuer.example.test",
        grant_id="urn:example:grant:float-zero", audiences=("https://resource.example.test",),
        issued_at=1000, not_before=1000, expires_at=2000, holder_thumbprint=_JKT,
        operations=(mod.OperationInput(name="transfer", selectors=(selector,)),),
    )
    try:
        return bool(mod.grant_signing_input(producer).is_ok)
    except InvalidError:
        return False


_INTEGRAL_FLOATS = [0.0, -0.0, 10.0, -3.0, 4503599627370496.0]


def _eq(value: Tagged) -> dict[str, object]:
    return {"kind": "equals", "path": ("x",), "value": value}


def _oneof(*values: Tagged) -> dict[str, object]:
    return {"kind": "one_of", "path": ("x",), "values": values}


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize("number", _INTEGRAL_FLOATS)
def test_producer_refuses_integral_float_equals_and_one_of(major: int, number: float) -> None:
    assert not _signs(major, _eq(JFloat(number)))
    assert not _signs(major, _oneof(JInt(1), JFloat(number)))


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize(
    "value",
    [
        JArray((JInt(1), JFloat(0.0))),
        JObject({"a": JFloat(10.0)}),
        JObject({"a": JArray((JString(b"s"), JObject({"b": JFloat(-3.0)})))}),
    ],
)
def test_producer_refuses_integral_float_at_any_depth(major: int, value: Tagged) -> None:
    assert not _signs(major, _eq(value))
    assert not _signs(major, _oneof(value))


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.parametrize("kind", ["lte", "gte"])
@pytest.mark.parametrize("number", _INTEGRAL_FLOATS)
def test_producer_refuses_integral_float_range_bound(major: int, kind: str, number: float) -> None:
    assert not _signs(major, {"kind": kind, "path": ("x",), "value": JFloat(number)})


@pytest.mark.parametrize("major", ALL_MAJORS)
@pytest.mark.parametrize(
    "selector",
    [
        _eq(JFloat(0.5)),
        _eq(JFloat(-2.25)),
        _eq(JInt(0)),
        _eq(JInt(10)),
        _eq(JArray((JInt(0), JFloat(1.5)))),
        _oneof(JInt(10), JFloat(0.5)),
        "all",
    ],
)
def test_producer_signs_integers_and_nonintegral_floats(major: int, selector: object) -> None:
    assert _signs(major, selector)


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.parametrize("kind", ["lte", "gte"])
@pytest.mark.parametrize("bound", [JFloat(0.5), JFloat(-2.25), JInt(0), JInt(10)])
def test_producer_signs_integer_and_nonintegral_range_bounds(major: int, kind: str, bound: Tagged) -> None:
    assert _signs(major, {"kind": kind, "path": ("x",), "value": bound})
