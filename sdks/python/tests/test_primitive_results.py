"""Public primitives have one Result shape on success and malformed caller input."""

from collections.abc import Callable

import pytest

import bounded_authority_verifier as bap
from bounded_authority_verifier import v2, v3


@pytest.mark.parametrize(
    "primitive, args",
    [
        (bap.base64url_decode, (b"=",)),
        (bap.base64url_encode, (None,)),
        (bap.json_decode, (b'{"a":1,"a":2}',)),
        (bap.jcs_encode, (bap.JFloat("bad"),)),
        (bap.bounds_new, ({"depth": True},)),
        (bap.coerce_bounds, (None,)),
        (bap.jwk_encode_public, (b"",)),
        (bap.jwk_from_public_key, (b"",)),
        (bap.public_key_thumbprint_raw, (b"",)),
        (bap.thumbprint, (None,)),
        (bap.thumbprint_raw, (None,)),
        (bap.thumbprint_preimage, (None,)),
        (bap.str_utf8, ("\ud800",)),
        (bap.utf8_str, (b"\xff",)),
        (bap.sha256, (None,)),
        (bap.parse_selector, (bap.JNull(),)),
        (bap.semantic_identity, (bap.JString(b"\xff"),)),
        (bap.typed_project, (None,)),
        (bap.request_digest_v2, (None, bap.JNull())),
        (v2.parse_selector, (bap.JNull(),)),
        (v3.jwk_from_public_key, (b"",)),
        (v3.jwk_from_json, (b"{}",)),
        (v3.jwk_encode_public, (b"",)),
        (v3.thumbprint, (None,)),
        (v3.thumbprint_raw, (None,)),
        (v3.thumbprint_preimage, (None,)),
        (v3.public_key_thumbprint_raw, (b"",)),
        (v3.parse_selector, (bap.JNull(),)),
    ],
)
def test_public_primitive_invalid_input_is_closed(
    primitive: Callable[..., object], args: tuple[object, ...]
) -> None:
    result = primitive(*args)
    assert isinstance(result, bap.Err)
    assert vars(result.error) == {}
    assert str(result.error) == "invalid"


@pytest.mark.parametrize(
    "primitive, args, expected",
    [
        (bap.base64url_decode, (b"YQ",), b"a"),
        (bap.base64url_encode, (b"a",), b"YQ"),
        (bap.json_decode, (b"1",), bap.JInt(1)),
        (bap.jcs_encode, (bap.JInt(1),), b"1"),
        (bap.str_utf8, ("ok",), b"ok"),
        (bap.utf8_str, (b"ok",), "ok"),
        (bap.bounds_maximum, (), bap.MAXIMUM_BOUNDS),
    ],
)
def test_public_primitive_success_is_result(
    primitive: Callable[..., object], args: tuple[object, ...], expected: object
) -> None:
    result = primitive(*args)
    assert isinstance(result, bap.Ok)
    assert result.value == expected


@pytest.mark.parametrize("primitive", [bap.json_decode, bap.jcs_encode, bap.uri_normalize])
def test_primitive_revalidates_forged_bounds(primitive: Callable[..., object]) -> None:
    value = bap.JNull() if primitive is bap.jcs_encode else b"null"
    assert isinstance(primitive(value, bap.Bounds({"depth": 999})), bap.Err)


def test_selector_matches_returns_result() -> None:
    selector = bap.parse_selector(bap.JObject({"kind": bap.JString(b"all")}))
    assert isinstance(selector, bap.Ok)
    assert bap.selector_matches(selector.value, bap.JNull()) == bap.Ok(True)


@pytest.mark.parametrize("limit", [True, -1, "small"])
def test_base64url_rejects_invalid_limit(limit: object) -> None:
    assert isinstance(bap.base64url_decode(b"YQ", limit), bap.Err)  # type: ignore[arg-type]


def test_bounds_resolution_is_result() -> None:
    from bounded_authority_verifier.bounds import bounds_resolve

    assert bap.MAXIMUM_BOUNDS.resolve("depth") == bap.Ok(32)
    assert isinstance(bap.MAXIMUM_BOUNDS.resolve("unknown"), bap.Err)
    assert isinstance(bounds_resolve(bap.Bounds({"depth": 999}), "depth"), bap.Err)
