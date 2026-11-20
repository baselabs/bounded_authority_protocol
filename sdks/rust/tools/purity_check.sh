#!/usr/bin/env bash
set -euo pipefail

# BAP-15 Task 16: enforce the lib-path purity invariant.
#
# The library path under src/ must contain no I/O, filesystem, network,
# process-spawn, environment, wall/monotonic clock, or RNG.
# These are SAFE Rust APIs that #![forbid(unsafe_code)] does NOT catch, so a
# grep is the enforcement. Test modules (#[cfg(test)]) are stripped before the
# scan: the corpus loaders under tests legitimately read corpus files; only the
# non-test lib path is purity-bound.
#
# `unsafe` is enforced separately by the crate-level #![forbid(unsafe_code)]
# (a planted `unsafe {}` block fails `cargo build`: that is the red-capable
# proof for the unsafe half). It is intentionally NOT grep-checked here: several
# src/ doc comments legitimately name the forbid policy, so a bare-`unsafe` grep
# would false-positive on the very prose that documents the invariant.
#
# Exits 0 if the lib path is pure, 1 on any forbidden API. Adversarially probed
# red-capable: planting `use std::fs;` in a src/ lib path makes this script
# exit 1; removing it restores exit 0.

script_dir=$(dirname "$0")
sdk_dir=$(cd "$script_dir/.." && pwd)
src_dir="$sdk_dir/src"

# Safe-but-impure APIs that #![forbid(unsafe_code)] does not catch.
# `rand::` / `rand_core::` are path-qualified to avoid the doc-comment mention
# of `rand_core` (features) in src/ed25519.rs. The bare tokens `HashSet` /
# `HashMap` match the default `RandomState::new()` collections (whose constructor
# reads OS entropy via hashmap_random_keys: a randomness boundary this pure
# library forbids; use `BTreeSet`/`BTreeMap`) in ANY spelling: fully-qualified,
# brace-import (`use std::collections::{HashSet, …}`), or bare. The src/ comments
# that document this choice are worded to avoid the bare tokens, so the grep does
# not false-positive on its own prose.
patterns='std::fs|std::net|std::process|std::env|std::io|std::time::SystemTime|std::time::Instant|getrandom|rand::|rand_core::|HashSet|HashMap'

status=0
# find -print0 / read -d '' is not POSIX; src/ is flat, so a plain glob suffices
# and stays portable. The glob always matches (src/ has .rs files).
if [ "${1:-}" != "--derivation-top-level" ]; then
for f in "$src_dir"/*.rs; do
  # Strip the trailing #[cfg(test)] module (test code reads corpus files).
  lib_path=$(awk '/^#\[.*cfg\(test\)/{exit} {print}' "$f")
  if matches=$(grep -En "$patterns" <<< "$lib_path"); then
    echo "purity_check: FAIL: forbidden API in lib path of ${f##*/}:" >&2
    printf '%s\n' "$matches" >&2
    status=1
  else
    [ "$?" -eq 1 ]
  fi
done
fi

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
    Path(sys.argv[1]), top_level_only=sys.argv[2] == "top", fixture_directory="tests/fixtures",
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

echo "purity_check: OK: no I/O / clock / RNG / network / env API in src/ lib path."
