"""The package ships the PEP 561 ``py.typed`` marker, so a consumer's type checker reads its
annotations instead of reporting the import as untyped."""

from __future__ import annotations

from pathlib import Path

import bounded_authority_verifier


def test_package_ships_the_typed_marker() -> None:
    assert (Path(bounded_authority_verifier.__file__).parent / "py.typed").is_file()
