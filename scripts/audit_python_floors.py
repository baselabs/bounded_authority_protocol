#!/usr/bin/env python3
"""Resolve and audit every declared Python dependency floor, including build tooling.

The committed SDK lock is audited separately. Lowest-direct resolution deliberately
keeps transitive dependencies current while testing the SDK's direct lower bounds.
The real resolver and advisory database run against a disposable project.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    manifest = tomllib.loads((ROOT / "sdks/python/pyproject.toml").read_text())
    project = manifest["project"]
    dependencies = (
        project.get("dependencies", []) + manifest["build-system"]["requires"]
    )
    groups = dict(manifest.get("dependency-groups", {}))
    for name, requirements in project.get("optional-dependencies", {}).items():
        groups["optional-" + name] = requirements
    with tempfile.TemporaryDirectory(prefix="bap-python-floors-") as directory:
        scratch = Path(directory)
        text = (
            '[project]\nname = "bap-dependency-floors"\nversion = "0.0.0"\n'
            + "requires-python = "
            + json.dumps(project["requires-python"])
            + "\n"
            + "dependencies = "
            + json.dumps(dependencies)
            + "\n[dependency-groups]\n"
            + "\n".join(
                json.dumps(name) + " = " + json.dumps(reqs)
                for name, reqs in groups.items()
            )
            + "\n"
        )
        (scratch / "pyproject.toml").write_text(text)
        env = dict(
            os.environ,
            UV_PYTHON_DOWNLOADS="never",
            UV_PYTHON=sys.executable,
            UV_RESOLUTION="lowest-direct",
        )
        for command in [
            ["uv", "lock", "--resolution", "lowest-direct"],
            [
                "uv",
                "export",
                "--locked",
                "--all-groups",
                "--no-emit-project",
                "--format",
                "pylock.toml",
                "--output-file",
                "pylock.toml",
            ],
            [
                "uvx",
                "--from",
                "pip-audit==2.9.0",
                "pip-audit",
                "--locked",
                str(scratch),
            ],
        ]:
            subprocess.run(
                command,
                cwd=scratch,
                env=env,
                check=True,
                stdout=subprocess.DEVNULL if command[1] == "export" else None,
            )
        print(
            "Python dependency floors: all runtime, build, development, and optional groups audited"
        )


if __name__ == "__main__":
    run()
