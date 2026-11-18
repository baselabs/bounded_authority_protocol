"""Execute the documented empty-project installs and quickstarts in GitHub CI only."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "c8b3bab8e4caf0b7f93e6f240570673534c331e2"


def block(source: str, marker: str, language: str) -> str:
    """Extract a uniquely marked executable install or complete manifest."""
    pattern = rf"<!-- {re.escape(marker)} -->\s*`{{3}}{language}\n(.*?)\n`{{3}}"
    found = re.findall(pattern, source, re.S)
    if len(found) != 1:
        raise AssertionError(f"expected one {marker}, found {len(found)}")
    return found[0] + "\n"


def quickstart(sdk: str) -> str:
    """Read the same native example exercised by each SDK's own suite."""
    source = (ROOT / "sdks" / sdk / "README.md").read_text()
    language = {"python": "python", "go": "go", "rust": "rust"}[sdk]
    found = re.findall(rf"^`{{3}}{language}\n(.*?)^`{{3}}$", source, re.M | re.S)
    if len(found) != 1:
        raise AssertionError(f"{sdk}: expected one complete quickstart")
    return found[0] + "\n"


def run(args: list[str], directory: Path) -> None:
    subprocess.run(args, cwd=directory, check=True, env={**os.environ, "GOTOOLCHAIN": "local"})


def main(sdk: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("SDK consumer execution belongs in GitHub CI")
    readme = (ROOT / "sdks" / sdk / "README.md").read_text()
    deployment = (ROOT / "docs" / "deployment" / f"{sdk}-sdk.md").read_text()
    for mode in (["path", "git"] if sdk == "rust" else ["source"]):
        with TemporaryDirectory(prefix=f"bap-{sdk}-{mode}-") as temporary:
            work = Path(temporary)
            if sdk == "rust":
                manifest = block(deployment, f"sdk-manifest:{mode}", "toml")
                parsed = tomllib.loads(manifest)
                dependency = parsed["dependencies"]["bounded-authority-protocol"]
                if mode == "path":
                    run(["bash", "-eu", "-c", block(deployment, "sdk-install:rust", "bash")], work)
                else:
                    assert dependency["rev"] == COMMIT
                    (work / "src").mkdir()
                (work / "Cargo.toml").write_text(manifest)
                (work / "src" / "main.rs").write_text(quickstart(sdk))
                run(["cargo", "generate-lockfile"], work)
                run(["cargo", "run", "--locked"], work)
            else:
                install = block(readme, f"sdk-install:{sdk}", "bash")
                assert COMMIT in install
                run(["bash", "-eu", "-c", install], work)
                if sdk == "python":
                    (work / "quickstart.py").write_text(quickstart(sdk))
                    # PEP 610 records the installed Git identity, independently of the URL text.
                    identity = (
                        "import importlib.metadata as m, json; "
                        "d=json.loads(m.distribution('bounded-authority-verifier').read_text('direct_url.json')); "
                        f"assert d['vcs_info']['commit_id'] == '{COMMIT}'; "
                        "assert d['url'] == 'https://github.com/baselabs/bounded_authority_protocol.git'; "
                        "assert d['subdirectory'] == 'sdks/python'"
                    )
                    run(["venv/bin/python", "-c", identity], work)
                    run(["venv/bin/python", "quickstart.py"], work)
                else:
                    (work / "quickstart_test.go").write_text(quickstart(sdk))
                    run(["go", "test", "-v", "."], work)
        if work.exists():
            raise AssertionError("consumer cleanup left residue")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"python", "go", "rust"}:
        raise SystemExit("usage: python scripts/check_sdk_install.py python|go|rust")
    main(sys.argv[1])
