#!/usr/bin/env python3
"""Library-path purity linter for ``bounded_authority_verifier`` (ADR 0014 D8).

Forbids I/O + clock + RNG + network + filesystem imports/calls in ``src/`` — the analog of the
Elixir ``architecture_gate.exs`` purity rules for the library path. A stray ``datetime.now()`` /
``time.time()`` / ``random.random()`` / ``open(...)`` / ``socket.*`` / ``subprocess.*`` /
``os.environ`` / ``urllib.request`` / ``http.client`` in the verify path fails it.

Walks the AST of every ``.py`` file under ``src/bounded_authority_verifier/`` and reports any
forbidden import or call. Exits 1 on any violation.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# The forbidden module paths (an import of any of these in src/ fails).
FORBIDDEN_IMPORTS: dict[str, str] = {
    "datetime": "datetime (clock)",
    "time": "time (clock)",
    "random": "random (RNG)",
    "socket": "socket (network)",
    "subprocess": "subprocess (process spawn)",
    "urllib.request": "urllib.request (network)",
    "http.client": "http.client (network)",
    "asyncio": "asyncio (event loop / I/O)",
    "threading": "threading (concurrency / not pure)",
    "multiprocessing": "multiprocessing (process / not pure)",
    "select": "select (I/O multiplexing)",
    "signal": "signal (OS signal handling)",
    "ctypes": "ctypes (FFI / not pure)",
    "ssl": "ssl (network)",
}

# Forbidden attribute calls: ``os.environ`` access, ``os.system``, ``open(...)``, etc.
FORBIDDEN_ATTR: dict[str, str] = {
    "os.environ": "os.environ (environment access)",
    "os.system": "os.system (process spawn)",
    "os.popen": "os.popen (process spawn)",
    "os.execv": "os.execv (process spawn)",
    "os.fork": "os.fork (process spawn)",
    "os.getcwd": "os.getcwd (filesystem)",
    "os.chdir": "os.chdir (filesystem)",
    "sys.exit": "sys.exit (control flow, not a verdict)",
}

# Forbidden bare calls: ``open(...)``, ``input(...)``.
FORBIDDEN_CALLS: dict[str, str] = {
    "open": "open (filesystem I/O)",
    "input": "input (console I/O)",
    "breakpoint": "breakpoint (debugger)",
}

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "bounded_authority_verifier"


class PurityChecker(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[str] = []

    def _violation(self, lineno: int, msg: str) -> None:
        self.violations.append(f"{self.path}:{lineno}: {msg}")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            full = alias.name
            # Match the longest forbidden prefix (e.g. urllib.request over urllib).
            if full in FORBIDDEN_IMPORTS:
                self._violation(node.lineno, f"forbidden import: {full} ({FORBIDDEN_IMPORTS[full]})")
            elif root in FORBIDDEN_IMPORTS:
                self._violation(node.lineno, f"forbidden import: {root} ({FORBIDDEN_IMPORTS[root]})")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is not None:
            root = node.module.split(".")[0]
            full = node.module
            if full in FORBIDDEN_IMPORTS:
                self._violation(node.lineno, f"forbidden import: {full} ({FORBIDDEN_IMPORTS[full]})")
            elif root in FORBIDDEN_IMPORTS:
                self._violation(node.lineno, f"forbidden import: {root} ({FORBIDDEN_IMPORTS[root]})")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Bare name calls: open(...), input(...).
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            self._violation(node.lineno, f"forbidden call: {node.func.id} ({FORBIDDEN_CALLS[node.func.id]})")
        # Attribute calls: os.environ (a Subscript/Attribute access, handled below), os.system(...).
        if isinstance(node.func, ast.Attribute):
            qual = _qualified_name(node.func)
            if qual in FORBIDDEN_ATTR:
                self._violation(node.lineno, f"forbidden call: {qual} ({FORBIDDEN_ATTR[qual]})")
            # datetime.now(), time.time(), random.* — the clock/RNG family via attribute call.
            if _is_clock_rng_call(node.func):
                self._violation(node.lineno, f"forbidden call: {_qualified_name(node.func)} (clock/RNG)")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # os.environ access (not a call — a read).
        qual = _qualified_name(node)
        if qual in FORBIDDEN_ATTR:
            self._violation(node.lineno, f"forbidden access: {qual} ({FORBIDDEN_ATTR[qual]})")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["X"] — the subscript on os.environ.
        if isinstance(node.value, ast.Attribute):
            qual = _qualified_name(node.value)
            if qual in FORBIDDEN_ATTR:
                self._violation(node.lineno, f"forbidden access: {qual} ({FORBIDDEN_ATTR[qual]})")
        self.generic_visit(node)


# Modules whose attribute access is clock/RNG (datetime.now, time.time, random.random, etc.).
_CLOCK_RNG_MODULES = {"datetime", "time", "random"}


def _is_clock_rng_call(func: ast.Attribute) -> bool:
    """True for ``<clock_rng_module>.<anything>`` calls (datetime.now, time.time, random.randint)."""
    return isinstance(func.value, ast.Name) and func.value.id in _CLOCK_RNG_MODULES


def _qualified_name(node: ast.expr) -> str:
    """Best-effort qualified name for an attribute/name chain (os.environ, urllib.request.urlopen)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_qualified_name(node.value)}.{node.attr}"
    return ""


def main() -> int:
    if not SRC_DIR.is_dir():
        print(f"purity: source dir not found: {SRC_DIR}", file=sys.stderr)
        return 1
    total_violations: list[str] = []
    for py in sorted(SRC_DIR.rglob("*.py")):
        try:
            tree = ast.parse(py.read_text("utf8"), filename=str(py))
        except SyntaxError as e:
            print(f"{py}: syntax error: {e}", file=sys.stderr)
            return 1
        checker = PurityChecker(py)
        checker.visit(tree)
        total_violations.extend(checker.violations)
    if total_violations:
        for v in total_violations:
            print(f"purity: {v}", file=sys.stderr)
        print(f"\npurity: {len(total_violations)} violation(s) in src/ — the verify path must be pure", file=sys.stderr)
        return 1
    print("purity: PASS (no I/O/clock/RNG/network in src/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
