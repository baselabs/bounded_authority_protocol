"""Host subclasses and callbacks cannot change protocol limits or immutable values."""
import ast
from collections.abc import Mapping
from pathlib import Path

import pytest

import bounded_authority_verifier as bap
from bounded_authority_verifier import v1, v2, v3
from bounded_authority_verifier._inputs import _normalize_arg
from bounded_authority_verifier.bounds import MAXIMUM_BOUNDS, Bounds, bounds_resolve, coerce_bounds
from bounded_authority_verifier.facts import GrantFacts


class Wide(Bounds):
    def resolve(self, key):
        return bap.Ok(10**12)


@pytest.mark.parametrize("entry", [coerce_bounds, lambda b: bounds_resolve(b, "depth"),
                                  lambda b: bap.json_decode(b"[" * 1100 + b"0" + b"]" * 1100, b)])
def test_bounds_subclasses_are_rejected(entry):
    assert isinstance(entry(Wide()), bap.Err)


class LyingKey(str):
    def __hash__(self):
        return hash("depth")

    def __eq__(self, other):
        return True


class LyingInt(int):
    def __le__(self, other):
        return False

    def __gt__(self, other):
        return False

    def __abs__(self):
        return 0


@pytest.mark.parametrize("limits", [{LyingKey("unknown"): 1}, {"depth": LyingInt(10000)}])
def test_bounds_checks_underlying_key_and_integer(limits):
    assert isinstance(bap.bounds_new(limits), bap.Err)


class LyingFloat(float):
    def __gt__(self, other):
        return False

    def __ge__(self, other):
        return True

    def __le__(self, other):
        return True


class LyingList(list):
    def __len__(self):
        return 0

    def __iter__(self):
        raise RuntimeError("caller iterator")


class LyingDict(dict):
    def __len__(self):
        return 0

    def items(self):
        raise RuntimeError("caller items")


@pytest.mark.parametrize("value", [bap.JInt(LyingInt(10**30)), bap.JFloat(LyingFloat("inf")),
                                    bap.JFloat(LyingFloat("nan")), bap.JArray(LyingList([bap.JNull()] * 257)),
                                    bap.JObject(LyingDict({str(i): bap.JNull() for i in range(65)}))])
def test_tagged_checks_underlying_values(value):
    assert isinstance(bap.jcs_encode(value), bap.Err)
    assert isinstance(bap.typed_project(value), bap.Err)


@pytest.mark.parametrize("selector", [v3.SelLte, v3.SelGte])
def test_numeric_selectors_reject_infinite_subclasses(selector):
    value = bap.JFloat(LyingFloat("inf"))
    assert isinstance(v3.selector_matches(selector(("n",), value), bap.JObject({"n": bap.JFloat(1.0)})), bap.Err)
    assert isinstance(v3.selector_matches(selector(("n",), bap.JFloat(1.0)), bap.JObject({"n": value})), bap.Err)


class RaisingMapping(Mapping):
    def __getitem__(self, key):
        raise RuntimeError("caller lookup")

    def __iter__(self):
        raise RuntimeError("caller iterator")

    def __len__(self):
        raise RuntimeError("caller length")

    def items(self):
        raise RuntimeError("caller items")


def test_mapping_callback_exceptions_close_at_the_boundary():
    assert isinstance(bap.bounds_new(RaisingMapping()), bap.Err)
    for major in (v1, v2, v3):
        assert isinstance(major.grant_signing_input(RaisingMapping()), bap.Err)


def test_mapping_snapshot_is_taken_once():
    class Once(dict):
        calls = 0

        def items(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("second snapshot")
            return super().items()

    value = Once(depth=12)
    assert bap.bounds_new(value).value.resolve("depth") == bap.Ok(12)
    assert value.calls <= 1


@pytest.mark.parametrize("major", [v1, v2, v3])
def test_facade_struct_subclasses_do_not_dispatch_properties(major):
    class HostIssuer(major.TrustedIssuer):
        def __getattribute__(self, name):
            raise RuntimeError("caller getter")

    from bounded_authority_verifier.error import InvalidError
    with pytest.raises(InvalidError):
        _normalize_arg(HostIssuer("kid", b"x" * 32), major.TrustedIssuer)


def test_tag_subclasses_cannot_dispatch_properties():
    class HostInt(bap.JInt):
        def __getattribute__(self, name):
            raise RuntimeError("caller getter")

    assert isinstance(bap.jcs_encode(HostInt(1)), bap.Err)


def test_bounds_cannot_be_reinitialized():
    limits = Bounds({"depth": 12})
    with pytest.raises(TypeError):
        limits.__init__({"depth": 25})
    assert limits.resolve("depth") == bap.Ok(12)
    with pytest.raises(TypeError):
        MAXIMUM_BOUNDS.__init__(5)
    assert MAXIMUM_BOUNDS.resolve("depth") == bap.Ok(32)


def test_facts_cannot_be_reinitialized():
    values = {"version": 1, "issuer": "original", "grant_id": "id", "issuer_key_fingerprint": b"x" * 32,
              "holder_thumbprint": b"y" * 32, "matched_audience": "aud", "issued_at": 1, "not_before": 1, "expires_at": 2}
    facts = GrantFacts(**values)
    with pytest.raises(TypeError):
        facts.__init__(**dict(values, issuer="changed"))
    assert facts.issuer == "original"


def test_json_decode_copies_input_once():
    source = Path(bap.__file__).parent / "json_alg.py"
    tree = ast.parse(source.read_text())
    decode = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "json_decode")
    copies = [n for n in ast.walk(decode) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_bytes"]
    assert len(copies) == 1


def test_es256_doc_distinguishes_backend_failures():
    assert "or backend exception" not in v3._es256_verify.__doc__


def test_uninitialized_bounds_fail_closed():
    value = object.__new__(Bounds)
    assert isinstance(coerce_bounds(value), bap.Err)
    assert isinstance(bounds_resolve(value, "depth"), bap.Err)
    assert isinstance(bap.json_decode(b"null", value), bap.Err)


def test_mapping_snapshot_calls_external_items_once():
    class CountingMapping(Mapping):
        calls = 0

        def __getitem__(self, key):
            return 12

        def __iter__(self):
            return iter(("depth",))

        def __len__(self):
            return 1

        def items(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("repeated callback")
            return [("depth", 12)]

    value = CountingMapping()
    limits = bap.bounds_new(value).value
    for _ in range(3):
        assert bounds_resolve(limits, "depth") == bap.Ok(12)
    assert value.calls == 1


@pytest.mark.parametrize("major", [v1, v2, v3])
def test_all_public_struct_types_reject_subclass_dispatch(major):
    from dataclasses import is_dataclass

    from bounded_authority_verifier.error import InvalidError
    from bounded_authority_verifier.facts import _Facts
    for kind in vars(major).values():
        if not isinstance(kind, type) or not (is_dataclass(kind) or issubclass(kind, _Facts)):
            continue

        class Host(kind):
            def __getattribute__(self, name):
                raise RuntimeError("caller getter")

        with pytest.raises(InvalidError):
            _normalize_arg(object.__new__(Host), kind)


@pytest.mark.parametrize("selector", [v3.SelLte, v3.SelGte])
def test_float_with_only_overridden_gt_cannot_reach_numeric_comparison(selector):
    class F(float):
        def __gt__(self, other):
            return False

    value = bap.JFloat(F("inf"))
    assert isinstance(v3.selector_matches(selector(("n",), value), bap.JObject({"n": bap.JFloat(1.0)})), bap.Err)
    assert isinstance(v3.selector_matches(selector(("n",), bap.JFloat(1.0)), bap.JObject({"n": value})), bap.Err)


def test_changelog_documents_bounds_contract_changes():
    text = (Path(__file__).parents[3] / "CHANGELOG.md").read_text()
    assert "`MAXIMA` is a read-only `MappingProxyType`" in text
    assert "Invalid `Bounds(...)` builds an unusable value rather" in text


@pytest.mark.parametrize("failure", ["items", "iterator"])
def test_external_mapping_callbacks_close_in_bounds_and_all_producers(failure):
    class External(RaisingMapping):
        def items(self):
            if failure == "items":
                raise RuntimeError("caller items")
            def members():
                raise RuntimeError("caller iterator")
                yield
            return members()

    value = External()
    assert isinstance(bap.bounds_new(value), bap.Err)
    for major in (v1, v2, v3):
        grant = major.GrantProducer("kid", "issuer", "id", ("aud",), 1, 1, 2, "A" * 43,
                                    (major.OperationInput("read", (value,)),))
        assert isinstance(major.grant_signing_input(grant), bap.Err)


def test_native_container_callbacks_are_never_dispatched():
    class NativeList(list):
        def __len__(self):
            raise RuntimeError("caller length")
        def __iter__(self):
            raise RuntimeError("caller iterator")
    class NativeDict(dict):
        def items(self):
            raise RuntimeError("caller items")
        def __len__(self):
            raise RuntimeError("caller length")
        def __iter__(self):
            raise RuntimeError("caller iterator")
    assert bap.jcs_encode(bap.JArray(NativeList([bap.JNull()]))) == bap.Ok(b"[null]")
    assert bap.jcs_encode(bap.JObject(NativeDict(a=bap.JNull()))) == bap.Ok(b'{"a":null}')


def test_bounds_invalid_constructor_keeps_only_an_invalid_marker():
    from bounded_authority_verifier.bounds import MAXIMA
    value = Bounds({"depth": 0})
    assert value.overrides == {}
    assert isinstance(value.resolve("depth"), bap.Err)
    with pytest.raises(TypeError):
        MAXIMA["depth"] = 10000


@pytest.mark.parametrize("module", ["compact", "jwk", "role_attestation", "content_assertion"])
def test_other_public_sdk_structs_reject_subclass_dispatch(module):
    import importlib
    from dataclasses import is_dataclass

    from bounded_authority_verifier.error import InvalidError
    from bounded_authority_verifier.facts import _Facts
    source = importlib.import_module("bounded_authority_verifier." + module)
    for kind in vars(source).values():
        if not isinstance(kind, type) or not (is_dataclass(kind) or issubclass(kind, _Facts)):
            continue
        class Host(kind):
            def __getattribute__(self, name):
                raise RuntimeError("caller getter")
        with pytest.raises(InvalidError):
            _normalize_arg(object.__new__(Host), kind)
