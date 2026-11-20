"""The single closed error value + the Result shape.

Public protocol functions return ``Result[T] = Ok | Err``; the three Ed25519 predicates
return plain booleans. Input gates explicitly turn malformed caller values into ``InvalidError``.
Public boundaries catch only ``InvalidError``. A runner or SDK programming error must propagate,
never masquerade as a protocol rejection. Results refuse implicit truth testing; inspect ``is_ok``
or match ``Ok`` / ``Err`` explicitly.

``Result`` is a frozen dataclass: ``Ok(value) | Err(InvalidError)``: never both. The ``Err``
branch carries an ``InvalidError`` (closed, value-free) so callers can match on the type, but it
exposes no reason and no partial value, exactly mirroring ``{:error, :invalid}``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, NoReturn, TypeVar

T = TypeVar("T")


class InvalidError(Exception):
    """The single closed error value. No reason, no partial (mirrors ``{:error, :invalid}``)."""

    def __init__(self, message: str = "invalid") -> None:
        super().__init__(message)


@dataclass(frozen=True)
class Ok(Generic[T]):
    """The success variant of Result: carries a value."""

    value: T

    def __bool__(self) -> bool:
        raise TypeError("Result has no implicit truth value; match Ok or Err")

    @property
    def is_ok(self) -> bool:
        """Whether this is the Ok variant; Result refuses implicit truth testing."""
        return True


@dataclass(frozen=True)
class Err:
    """The failure variant of Result: closed, value-free (carries an InvalidError sentinel)."""

    error: InvalidError

    def __bool__(self) -> bool:
        raise TypeError("Result has no implicit truth value; match Ok or Err")

    @property
    def is_ok(self) -> bool:
        """Whether this is the Ok variant; Result refuses implicit truth testing."""
        return False


Result = Ok[T] | Err
"""Result[T] = Ok(value) | Err(InvalidError). Mirrors ``{:ok, value} | {:error, :invalid}``."""


def ok(value: T) -> Ok[T]:
    """Wrap a successful value in Ok; inspect the result explicitly instead of truth-testing it."""
    return Ok(value)


def err() -> Err:
    """Return the closed, value-free invalid result."""
    return Err(InvalidError())


def _unwrap(result: Result[T]) -> T:
    """Propagate an internal rejection to the enclosing public Result boundary."""
    if isinstance(result, Err):
        raise result.error
    return result.value


def _fail(message: str = "invalid") -> NoReturn:
    """Raise the closed InvalidError. Every protocol rejection funnels through this."""
    raise InvalidError(message)


def _invalid_error(message: str = "invalid") -> InvalidError:
    """Construct an InvalidError for use in ``raise`` expressions where NoReturn-awareness matters.

    Equivalent to ``fail`` semantically; provided so exhaustiveness fallthroughs can write
    ``raise _invalid_error(...)`` (both mypy and ruff recognize a trailing ``raise`` as a return
    path, which they do not for a bare ``_fail()`` call at function end).
    """
    return InvalidError(message)


def _require(condition: object, message: str = "requirement failed") -> None:
    """Raise the closed InvalidError when a precondition fails (spec/bap-v1.md §16).

    Named ``require`` rather than ``assert`` so it does not shadow the Python keyword.
    """
    if not condition:
        _fail(message)
