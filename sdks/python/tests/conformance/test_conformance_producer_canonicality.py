"""Pytest wrapper for the producer-canonicality conformance runner (erratum 3): every case in the
additive bap-producer-canonicality/1 corpus agrees — a refused signature is the closed error, an
accepted signature's bytes are emitted unchanged."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_RUN_PY = Path(__file__).resolve().parent / "run_producer_canonicality.py"


def _load_run_module():
    spec = importlib.util.spec_from_file_location("bap_producer_canonicality_run", _RUN_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bap_producer_canonicality_run"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_producer_canonicality_corpus_all_cases_agree():
    run = _load_run_module()
    result = run.run_all()
    assert result["fail"] == 0, (
        f"{result['fail']}/{result['total']} producer-canonicality cases disagreed: {result['failures'][:10]}"
    )
    assert result["pass"] == result["total"] == run.TOTAL_CASES == 75
    assert result["refused"] == 60 and result["accepted"] == 15
