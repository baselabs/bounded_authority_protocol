#!/usr/bin/env bash
set -euo pipefail

# BAP-16: enforce the library-path purity invariant for the Go SDK.
#
# The library path (every non-test .go file at the module root, the `verifier`
# package) must contain no I/O, filesystem,
# network, process-spawn, environment, wall/monotonic clock, RNG, or unsafe
# code. `go vet` catches none of these classes, so a grep is the enforcement.
#
# Test files (_test.go), the conformance/ runner package, and the tests/
# battery legitimately read corpus files and use encoding/json: only the
# library path is purity-bound.
#
# Exits 0 if the library path is pure, 1 on any forbidden API or import
# outside the pure allowlist. Red-capable: planting `os.ReadFile` in a
# library file makes this script exit 1; removing it restores exit 0 (proven
# at authoring, recorded in the README).

script_dir=$(dirname "$0")
lib_dir=$(cd "$script_dir/.." && pwd)

# Safe-but-impure APIs (dots escaped; `os\.` also catches os.ReadFile etc.).
patterns='os\.|io\.|net\.|time\.|math/rand|crypto/rand|os/exec|unsafe\.|syscall\.|runtime\.GC|flag\.|log\.|context\.|sync\.'

# Import allowlist: the pure stdlib packages the library consumes.
allowed_imports='^"(crypto/ecdsa|crypto/ed25519|crypto/elliptic|crypto/sha256|crypto/subtle|encoding/binary|errors|fmt|math|math/big|slices|sort|strconv|strings|unicode/utf16|unicode/utf8)"$'

status=0
if [ "${1:-}" != "--derivation-top-level" ]; then
for f in "$lib_dir"/*.go; do
  case "$f" in
    *_test.go) continue ;; # test files are not the library path
  esac
  # strip // comment tails first so doc prose (e.g. "I/O", "context.") cannot
  # false-positive: only code is scanned
  code=$(sed 's://.*$::' "$f")
  if matches=$(grep -En "$patterns" <<< "$code"); then
    echo "purity_check: FAIL: forbidden API in library path of ${f##*/}:" >&2
    printf '%s\n' "$matches" >&2
    status=1
  else
    [ "$?" -eq 1 ]
  fi
  # any import line (block, aliased, dotted, or single) whose quoted path
  # is outside the allowlist fails (aliases and dot-imports cannot hide it):
  # extract the import block plus single imports, then filter quoted paths
  imp_block=$(awk '/^import \(/ {flag=1} flag {print} /^\)/ {if (flag) flag=0}' "$f")
  imp_single=$(grep -E '^import ' "$f") || [ "$?" -eq 1 ]
  import_lines=$(printf '%s\n%s\n' "$imp_block" "$imp_single")
  imports=$(grep -oE '"[^"]+"' <<< "$import_lines") || [ "$?" -eq 1 ]
  bad_imports=$(grep -vE "$allowed_imports" <<< "$imports") || [ "$?" -eq 1 ]
  if [ -n "$bad_imports" ]; then
    echo "purity_check: FAIL: non-allowlisted import in ${f##*/}:" >&2
    printf '%s\n' "$bad_imports" >&2
    status=1
  fi
done
fi

sdk_dir="$lib_dir"

# Authored-text derivation rules also support the monorepo's top-level SDK documents.
scan_root="$sdk_dir"
scan_mode=tree
if [ "${1:-}" = "--derivation-top-level" ]; then
  scan_root="$2"
  scan_mode=top
fi
if ! python3 - "$scan_root" "$scan_mode" <<'PYSCAN'
import os
import re
import sys
from pathlib import Path

# BEGIN DERIVATION RULES
# independent spec-and-corpus derivation (docs/design/conformance-contract.md): identical rules
# travel with each independently publishable SDK.
# Split and escaped literals keep this checker inside its own scan boundary.
DERIVATION_PATTERNS = [
    ("reference source citation", re.compile(
        rb"lib[/\\]" rb"bounded_authority_protocol|\b[A-Za-z0-9_][A-Za-z0-9_./\\-]*[.]exs?\b",
        re.IGNORECASE,
    )),
    ("reference function citation", re.compile(
        rb"(?<![A-Za-z0-9_./\\:-])(?:[A-Z][A-Za-z0-9_]*(?:[.][A-Z][A-Za-z0-9_]*)*"
        rb"[.][a-z_][A-Za-z0-9_]*[?!]?|[a-z_][A-Za-z0-9_]*[?!])/[0-9]+"
        rb"(?![A-Za-z0-9_/\\-]|[.][A-Za-z0-9_])",
    )),
    ("reference struct citation", re.compile(rb"%[A-Z][A-Za-z0-9_.]*[{]")),
    ("reference authority phrase", re.compile(
        rb"\bel" rb"ixir\s+" rb"reference\b|\breference\s+" rb"implementation\b",
        re.IGNORECASE,
    )),
]
GENERATED_DIRS = {
    ".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target", "dist", "build", "node_modules",
}
RENDERING_NAMES = (
    "decoded-rendering.json", "decoded-wire-rendering.json", "decoded-binary-rendering.json",
)


def derivation_violations(root: Path, top_level_only: bool = False, fixture_directory: str = "tests/fixtures") -> list[str]:
    rendering_fixtures = {f"{fixture_directory}/{name}" for name in RENDERING_NAMES}
    violations = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [] if top_level_only else sorted(
            name for name in dirs if name not in GENERATED_DIRS and not name.endswith(".egg-info")
        )
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            # Scan whole files so whitespace cannot hide a phrase across lines.
            for message, pattern in DERIVATION_PATTERNS:
                if message == "reference struct citation" and relative in rendering_fixtures:
                    continue
                for match in pattern.finditer(data):
                    lineno = data.count(b"\n", 0, match.start()) + 1
                    violations.append(f"{relative}:{lineno}: {message}")
    return violations
# END DERIVATION RULES

violations = derivation_violations(
    Path(sys.argv[1]), top_level_only=sys.argv[2] == "top", fixture_directory="testdata",
)
for violation in violations:
    print(f"purity_check: {violation}", file=sys.stderr)
if violations:
    sys.exit(1)
print("purity_check: OK - no reference source citations in SDK.")
PYSCAN
then
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "purity_check: OK: no I/O / clock / RNG / network / env / unsafe API in the library path."
