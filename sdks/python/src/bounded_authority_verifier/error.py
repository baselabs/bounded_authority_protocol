"""The single closed error value + the Result shape.

Mirrors the Elixir ``{:error, :invalid}`` (AGENTS rule 1: verification is not authority; rule 3:
fail closed). Every public façade function returns ``Result[T] = Ok | Err``. A GENUINE protocol
rejection raises/returns ``InvalidError``; a runner/SDK bug (``TypeError``, ``ValueError``, an
uncaught library exception) is a distinct class that must NOT map to Invalid (the whitelist
discipline — only a genuine protocol rejection maps to ``INVALID``; everything else is a bug).

``Result`` is a frozen dataclass: ``Ok(value) | Err(InvalidError)`` — never both. The ``Err``
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
    """The success variant of Result — carries a value."""

    value: T

    @property
    def is_ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Err:
    """The failure variant of Result — closed, value-free (carries an InvalidError sentinel)."""

    error: InvalidError

    @property
    def is_ok(self) -> bool:
        return False


Result = Ok[T] | Err
"""Result[T] = Ok(value) | Err(InvalidError). Mirrors ``{:ok, value} | {:error, :invalid}``."""


def ok(value: T) -> Ok[T]:
    return Ok(value)


def err() -> Err:
    return Err(InvalidError())


def fail(message: str = "invalid") -> NoReturn:
    """Raise the closed InvalidError. Every protocol rejection funnels through this."""
    raise InvalidError(message)


def invalid_error(message: str = "invalid") -> InvalidError:
    """Construct an InvalidError for use in ``raise`` expressions where NoReturn-awareness matters.

    Equivalent to ``fail`` semantically; provided so exhaustiveness fallthroughs can write
    ``raise invalid_error(...)`` (both mypy and ruff recognize a trailing ``raise`` as a return
    path, which they do not for a bare ``fail()`` call at function end).
    """
    return InvalidError(message)


def require(condition: object, message: str = "requirement failed") -> None:
    """The precondition helper (mirrors the TS ``assert``). Raise InvalidError when false.

    Named ``require`` rather than ``assert`` so it does not shadow the Python keyword.
    """
    if not condition:
        fail(message)
