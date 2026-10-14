"""Bounds rejections are value-free: an InvalidError never carries a caller-supplied limit name or
value (AGENTS rule 3, closed value-free errors)."""

from __future__ import annotations

import pytest

from bounded_authority_verifier import Bounds, InvalidError, bounds_new, coerce_bounds

CALLER_TEXT = "caller-supplied-name-7f3a"


@pytest.mark.parametrize(
    "overrides",
    [{CALLER_TEXT: 1}, {CALLER_TEXT: "x"}, {CALLER_TEXT: -1}],
)
def test_bounds_new_rejection_does_not_echo_caller_input(overrides: dict[str, object]) -> None:
    with pytest.raises(InvalidError) as raised:
        bounds_new(overrides)  # type: ignore[arg-type]
    assert CALLER_TEXT not in str(raised.value)
    assert CALLER_TEXT not in repr(raised.value)


@pytest.mark.parametrize(
    "overrides",
    [{CALLER_TEXT: 1}, {CALLER_TEXT: "x"}, {CALLER_TEXT: 0}],
)
def test_coerce_bounds_rejection_does_not_echo_caller_input(overrides: dict[str, object]) -> None:
    with pytest.raises(InvalidError) as raised:
        coerce_bounds(Bounds(overrides))  # type: ignore[arg-type]
    assert CALLER_TEXT not in str(raised.value)
    assert CALLER_TEXT not in repr(raised.value)
