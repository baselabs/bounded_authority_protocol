"""The README quickstart runs: its Python block is byte-identical to examples/quickstart.py, and
that script verifies a fresh envelope and rejects the same proof for other arguments."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "quickstart.py"


def test_quickstart_prints_the_verified_and_rejected_outcomes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runpy.run_path(str(EXAMPLE), run_name="__main__")
    output = capsys.readouterr().out
    assert output == "publish_article grant-001 not_evaluated\nTrue\n"

    # The README's sentence about the output states exactly what the script printed.
    first, second = output.splitlines()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"It prints `{first}`, then `{second}`." in readme


def test_readme_quickstart_is_the_example_file() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    _, found, section = readme.partition("## Quickstart\n")
    assert found, "README.md has no Quickstart section"
    _, found, block = section.partition("```python\n")
    assert found, "the README Quickstart section has no python block"
    block, found, _ = block.partition("```\n")
    assert found, "the README Quickstart python block is not closed"
    assert block == EXAMPLE.read_text(encoding="utf-8"), (
        "the README Quickstart block differs from examples/quickstart.py; copy the file into the README"
    )
