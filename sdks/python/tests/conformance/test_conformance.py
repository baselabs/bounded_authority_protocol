"""Pytest wrapper for the conformance runner (BAP-09 T9). Runs the full 259-case corpus + census."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_RUN_PY = _HERE / "run.py"


def _load_run_module():
    spec = importlib.util.spec_from_file_location("bap09_conformance_run", _RUN_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bap09_conformance_run"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_conformance_259_cases_agree():
    """All 259 published vectors agree + the two-boundary census is equal."""
    run = _load_run_module()
    result = run.run_all()
    assert result["fail"] == 0, (
        f"{result['fail']}/{result['total']} cases disagreed: {result['failures'][:10]}"
    )
    assert result["pass"] == result["total"] == 259
