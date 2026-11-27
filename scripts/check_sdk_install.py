"""Execute the documented empty-project installs and quickstarts in GitHub CI only.

A document cannot name the commit that contains it, so the documented Git installs pin an
earlier commit of the default branch. Each Git install runs twice: as documented, proving the
pinned commit still installs, and with the pin replaced by the commit under test, proving the
same steps against the source being qualified.
"""

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
    return block(source, f"sdk-quickstart:{sdk}", language)


def run(args: list[str], directory: Path) -> None:
    subprocess.run(args, cwd=directory, check=True, env={**os.environ, "GOTOOLCHAIN": "local"})


def main(sdk: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("SDK consumer execution belongs in GitHub CI")
    under_test = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", under_test):
        raise AssertionError("GITHUB_SHA is not a full commit")
    readme = (ROOT / "sdks" / sdk / "README.md").read_text()
    deployment = (ROOT / "docs" / "deployment" / f"{sdk}-sdk.md").read_text()
    commits = list(dict.fromkeys([COMMIT, under_test]))
    modes = [("path", None)] if sdk == "rust" else []
    modes += [("git" if sdk == "rust" else "source", commit) for commit in commits]
    for mode, commit in modes:
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
                    manifest = manifest.replace(COMMIT, commit)
                    (work / "src").mkdir()
                (work / "Cargo.toml").write_text(manifest)
                (work / "src" / "main.rs").write_text(quickstart(sdk))
                run(["cargo", "generate-lockfile"], work)
                run(["cargo", "run", "--locked"], work)
            else:
                install = block(readme, f"sdk-install:{sdk}", "bash")
                assert COMMIT in install
                install = install.replace(COMMIT, commit)
                run(["bash", "-eu", "-c", install], work)
                if sdk == "python":
                    (work / "quickstart.py").write_text(quickstart(sdk))
                    # PEP 610 records the installed Git identity, independently of the URL text.
                    expected_name = (
                        "assert names == ['bounded-authority-protocol-verifier']; "
                        if commit == under_test else ""
                    )
                    identity = (
                        "import importlib.metadata as m, json; "
                        "names=m.packages_distributions()['bounded_authority_verifier']; assert len(names)==1; "
                        f"{expected_name}"
                        "d=json.loads(m.distribution(names[0]).read_text('direct_url.json')); "
                        f"assert d['vcs_info']['commit_id'] == '{commit}'; "
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
