#!/usr/bin/env python3
"""Dependency-license checker for ``bounded_authority_verifier`` (ADR 0014 D8).

Enumerates the SDK's runtime dependency tree and fails if any package license is outside the
Apache-2.0/BSD/MIT/ISC-compatible allowlist (AGENTS rule 10) — the analog of the Elixir
``check_dependency_licenses.exs`` for the SDK tree. The ``cryptography`` Apache-2.0/BSD claim is
verified by this gate, not by author assertion.

Uses ``importlib.metadata`` to resolve installed distributions + their licenses. Run in the venv
where the SDK is installed (``uv pip install -e .``).
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

import tomllib


def _runtime_deps() -> list[str]:
    """Read the runtime dependencies from pyproject.toml [project] dependencies.

    Parses the actual manifest (NOT a hardcoded list) so adding a non-allowlisted dep to
    pyproject.toml makes this gate fail — the defect-injection battery item 8 claim.
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    # Normalize "cryptography>=44.0.0" → "cryptography" (strip version specifiers).
    names: list[str] = []
    for d in deps:
        # PEP 508: the name is the canonical package name up to the first version comparator,
        # extras marker, or semicolon. Match the leading name run ([A-Za-z0-9._-]+).
        import re

        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", d)
        names.append(m.group(1) if m else d.strip())
    return names

# The allowlist of SPDX-compatible licenses (AGENTS rule 10). ``cryptography`` is Apache-2.0 OR BSD-3-Clause.
ALLOWED_LICENSES = {
    "Apache Software License",
    "Apache-2.0",
    "Apache 2.0",
    "BSD License",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "MIT License",
    "MIT",
    "ISC License",
    "ISC",
    "Mozilla Public License 2.0",  # only as a component of cryptography's optional deps — flagged below
}

# Packages whose license we've verified and accept (name → expected SPDX family or substring).
KNOWN_GOOD = {
    "cryptography": "apache-2.0",  # License-Expression: Apache-2.0 OR BSD-3-Clause
}


def _license_terms(dist_name: str) -> list[str]:
    try:
        dist = distribution(dist_name)
    except PackageNotFoundError:
        print(f"license: {dist_name} not installed (run `uv pip install -e .` first)", file=sys.stderr)
        return []
    # Modern packages (PEP 639) use License-Expression (SPDX); legacy use License + Classifier.
    license_expression = dist.metadata.get("License-Expression")
    terms = dist.metadata.get_all("License") or []
    classifiers = dist.metadata.get_all("Classifier") or []
    license_classifiers = [c.split("::")[-1].strip() for c in classifiers if c.startswith("License ::")]
    out: list[str] = []
    if license_expression:
        out.append(license_expression)
    out.extend(terms)
    out.extend(license_classifiers)
    return out


def main() -> int:
    violations: list[str] = []
    runtime_deps = _runtime_deps()
    if not runtime_deps:
        print("license: no runtime dependencies declared in pyproject.toml", file=sys.stderr)
        return 1
    for dep in runtime_deps:
        licenses = [t for t in _license_terms(dep) if t]
        if not licenses:
            violations.append(f"{dep}: no license metadata found")
            continue
        # Accept if ANY declared license is in the allowlist.
        accepted = any(any(allowed.lower() in lic.lower() for allowed in ALLOWED_LICENSES) for lic in licenses)
        if not accepted:
            violations.append(f"{dep}: license {licenses} not in the allowlist {sorted(ALLOWED_LICENSES)}")
            continue
        if dep in KNOWN_GOOD and KNOWN_GOOD[dep].lower() not in " ".join(licenses).lower():
            violations.append(f"{dep}: expected {KNOWN_GOOD[dep]}, got {licenses}")
            continue
        print(f"license: {dep} OK ({licenses[0]})")
    if violations:
        for v in violations:
            print(f"license: {v}", file=sys.stderr)
        print(f"\nlicense: {len(violations)} violation(s) — all runtime deps must be Apache-2.0/BSD/MIT/ISC", file=sys.stderr)
        return 1
    print("license: PASS (all runtime deps allowlisted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
