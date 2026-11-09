"""Pytest wrapper for the selector float-zero conformance runner (erratum 6): every case in the
additive bap-selector-float-zero/1 corpus agrees — grant decode rejects a float-tagged zero in an
equals value or one_of member, the grant producer refuses a float-tagged integral selector value,
and range bounds keep comparing numerically."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_RUN_PY = Path(__file__).resolve().parent / "run_selector_float_zero.py"


def _load_run_module():
    spec = importlib.util.spec_from_file_location("bap_selector_float_zero_run", _RUN_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bap_selector_float_zero_run"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_selector_float_zero_corpus_all_cases_agree():
    run = _load_run_module()
    result = run.run_all()
    assert result["fail"] == 0, (
        f"{result['fail']}/{result['total']} selector-float-zero cases disagreed: {result['failures'][:10]}"
    )
    assert result["pass"] == result["total"] == run.TOTAL_CASES == 161
    assert result["rejected"] == 98 and result["accepted"] == 63
