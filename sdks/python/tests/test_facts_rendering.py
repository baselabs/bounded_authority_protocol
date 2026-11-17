"""Specified diagnostic rendering (ADR 0014 D3) and refusal of generic facts enumeration."""

import copy
import inspect
import json
import pickle
from dataclasses import asdict, fields, is_dataclass

import pytest

from bounded_authority_verifier import Ok
from bounded_authority_verifier import facts as facts_module

FACTS_TYPES = (
    facts_module.GrantFacts, facts_module.EnvelopeFacts, facts_module.ChainFacts,
    facts_module.AnchorFacts, facts_module.KeyTransitionFacts, facts_module.AnchoredExportFacts,
    facts_module.AttestationFacts, facts_module.ContentAssertionFacts,
)
CASES = [(kind, major) for kind in FACTS_TYPES for major in
         ((1,) if kind in (facts_module.AttestationFacts, facts_module.ContentAssertionFacts) else (1, 2, 3))]


def _facts(kind, major):
    values = {
        name: major if name == "version" else b"caller-bytes-7f3a"
        if inspect.signature(kind).parameters[name].annotation == "bytes" else 987654321
        if inspect.signature(kind).parameters[name].annotation == "int" else "caller-text-7f3a"
        for name in inspect.signature(kind).parameters
    }
    return kind(**values), values


@pytest.mark.parametrize("kind,major", CASES)
def test_facts_rendering_is_fixed_and_value_free(kind, major):
    facts, values = _facts(kind, major)
    profile = "RoleAttestation.V1" if kind is facts_module.AttestationFacts else "ContentAssertion.V1" if kind is facts_module.ContentAssertionFacts else f"V{major}"
    expected = f"#BoundedAuthorityProtocol.{profile}.{kind.__name__}<redacted>"
    for rendered in (repr(facts), str(facts), f"{facts}", f"{facts!r}"):
        assert rendered == expected
        for sentinel in ("caller-bytes-7f3a", "caller-text-7f3a", "987654321"):
            assert sentinel not in rendered
    assert repr(Ok(facts)) == f"Ok(value={expected})"
    assert repr([facts]) == f"[{expected}]"
    for name, value in values.items():
        assert getattr(facts, name) == value
        with pytest.raises(AttributeError):
            setattr(facts, name, value)


def _reduce(value):
    return value.__reduce__()


def _reduce_ex(value):
    return value.__reduce_ex__(4)


def _getstate(value):
    return value.__getstate__()


OPERATIONS = [asdict, fields, vars, json.dumps, copy.copy, copy.deepcopy,
              _reduce, _reduce_ex, _getstate]
OPERATIONS += [pytest.param(lambda value, protocol=protocol: pickle.dumps(value, protocol=protocol),
                            id=f"pickle-{protocol}")
               for protocol in range(pickle.HIGHEST_PROTOCOL + 1)]


@pytest.mark.parametrize("kind,major", CASES)
@pytest.mark.parametrize("operation", OPERATIONS)
def test_facts_refuse_generic_enumeration_and_reduction(kind, major, operation):
    facts, _ = _facts(kind, major)
    with pytest.raises(TypeError):
        operation(facts)


@pytest.mark.parametrize("kind,major", CASES)
def test_facts_are_not_dataclasses(kind, major):
    facts, _ = _facts(kind, major)
    assert not is_dataclass(facts)


@pytest.mark.parametrize("kind,major", CASES)
def test_facts_refuse_reinitialization(kind, major):
    facts, values = _facts(kind, major)
    with pytest.raises(TypeError):
        facts.__init__(**values)
    for name, value in values.items():
        assert getattr(facts, name) == value
