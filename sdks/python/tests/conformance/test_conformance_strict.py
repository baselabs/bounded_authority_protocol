"""Pytest wrapper for the strict-Ed25519 conformance runner: every case in the additive corpus agrees."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_RUN_STRICT_PY = Path(__file__).resolve().parent / "run_strict.py"


def _load_run_module():
    spec = importlib.util.spec_from_file_location("bap_strict_conformance_run", _RUN_STRICT_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bap_strict_conformance_run"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_strict_ed25519_corpus_all_cases_agree():
    run = _load_run_module()
    result = run.run_all()
    assert result["fail"] == 0, (
        f"{result['fail']}/{result['total']} strict cases disagreed: {result['failures'][:10]}"
    )
    assert result["pass"] == result["total"] == run.TOTAL_CASES == 2410
