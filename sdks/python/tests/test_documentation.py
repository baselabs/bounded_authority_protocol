"""Native API documentation and the migration examples are part of the SDK contract."""

from __future__ import annotations

import ast
import dataclasses
import inspect
import runpy
from pathlib import Path

import pytest

import bounded_authority_verifier as api
from bounded_authority_verifier import Err, JInt, Ok, bounds_new, json_decode

ROOT = Path(__file__).resolve().parents[1]


def test_every_public_declaration_has_an_explicit_docstring() -> None:
    missing = []
    for source in sorted((ROOT / "src" / "bounded_authority_verifier").glob("*.py")):
        if source.name.startswith("_"):
            continue
        declarations = ast.parse(source.read_text()).body
        for node in declarations:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef)) or node.name.startswith("_"):
                continue
            if not ast.get_docstring(node):
                missing.append(f"{source.name}:{node.lineno}:{node.name}")
            if isinstance(node, ast.ClassDef):
                missing.extend(
                    f"{source.name}:{member.lineno}:{node.name}.{member.name}"
                    for member in node.body
                    if isinstance(member, ast.FunctionDef)
                    and not member.name.startswith("_")
                    and not ast.get_docstring(member)
                )
    assert not missing, "\n".join(missing)
    for name in api.__all__:
        value = getattr(api, name)
        if inspect.isfunction(value) or inspect.isclass(value):
            assert inspect.getdoc(value), name


def test_migration_result_bounds_and_readonly_facts(capsys: pytest.CaptureFixture[str]) -> None:
    result = json_decode(b"1")
    assert isinstance(result, Ok) and result.value == JInt(1)
    with pytest.raises(TypeError):
        bool(result)
    assert isinstance(json_decode(b"{"), Err)
    assert api.verify_strict(b"", b"", b"") is False
    assert isinstance(bounds_new({"depth": 8}), Ok)
    assert isinstance(bounds_new({"depth": 0}), Err)
    with pytest.raises(TypeError):
        api.MAXIMA["depth"] = 8  # type: ignore[index]

    namespace = runpy.run_path(str(ROOT / "examples" / "quickstart.py"))
    facts = namespace["facts"]
    assert facts.grant_id == "grant-001"
    assert repr(facts) == "#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>"
    with pytest.raises((AttributeError, TypeError)):
        facts.grant_id = "other"
    with pytest.raises(TypeError):
        dataclasses.asdict(facts)
    assert capsys.readouterr().out == "publish_article grant-001 not_evaluated\nTrue\n"
