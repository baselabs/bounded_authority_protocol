"""Fixed rendering hides every value, including when facts are nested in a Result."""

from dataclasses import fields

import pytest

from bounded_authority_verifier import Ok
from bounded_authority_verifier import facts as facts_module

FACTS_TYPES = (
    facts_module.GrantFacts,
    facts_module.EnvelopeFacts,
    facts_module.ChainFacts,
    facts_module.AnchorFacts,
    facts_module.KeyTransitionFacts,
    facts_module.AnchoredExportFacts,
    facts_module.AttestationFacts,
    facts_module.ContentAssertionFacts,
)


@pytest.mark.parametrize("facts_type", FACTS_TYPES)
def test_facts_rendering_is_fixed_and_value_free(facts_type: type) -> None:
    # Populate every field, including default markers, with distinctive caller values.
    values = {
        field.name: b"caller-bytes-7f3a"
        if field.type == "bytes"
        else 987654321
        if field.type == "int"
        else "caller-text-7f3a"
        for field in fields(facts_type)
    }
    facts = facts_type(**values)
    expected = f"#{facts_type.__name__}<redacted>"
    for rendered in (repr(facts), str(facts), f"{facts}", f"{facts!r}"):
        assert rendered == expected
        for value in values.values():
            assert str(value) not in rendered
    assert repr(Ok(facts)) == f"Ok(value={expected})"
    assert repr([facts]) == f"[{expected}]"
