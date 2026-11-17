"""The certified pin binds every input byte and the exact file set."""

import importlib.util
import shutil
from pathlib import Path

import pytest


def runner():
    spec = importlib.util.spec_from_file_location(
        "integrity_runner", Path(__file__).with_name("run.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("mutation", ["case-byte", "raw-byte", "extra-file", "missing-file"])
def test_input_integrity_fails_closed(tmp_path, mutation):
    run = runner()
    root = tmp_path / "corpus"
    shutil.copytree(run.CORPUS_DIR, root)
    run.CORPUS_DIR = root
    try:
        if mutation == "case-byte":
            path = root / "cases/uri/normalize.json"
            path.write_bytes(path.read_bytes() + b" ")
        elif mutation == "raw-byte":
            path = next(root.rglob("*.raw"))
            path.write_bytes(path.read_bytes() + b" ")
        elif mutation == "extra-file":
            (root / "extra.json").write_text("{}")
        else:
            (root / "cases/uri/normalize.json").unlink()
        with pytest.raises((AssertionError, SystemExit, FileNotFoundError)):
            run.load_corpus()
    finally:
        shutil.rmtree(root)
