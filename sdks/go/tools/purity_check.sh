#!/bin/sh
# BAP-16 — enforce the library-path purity invariant for the Go SDK.
#
# AGENTS rule 2 + ADR 0014 D8: the library path (every non-test .go file at
# the module root — the `verifier` package) must contain no I/O, filesystem,
# network, process-spawn, environment, wall/monotonic clock, RNG, or unsafe
# code. `go vet` catches none of these classes, so a grep is the enforcement.
#
# Test files (_test.go), the conformance/ runner package, and the tests/
# battery legitimately read corpus files and use encoding/json — only the
# library path is purity-bound.
#
# Exits 0 if the library path is pure, 1 on any forbidden API or import
# outside the pure allowlist. Red-capable: planting `os.ReadFile` in a
# library file makes this script exit 1; removing it restores exit 0 (proven
# at authoring, recorded in the README).

set -eu

lib_dir=$(cd "$(dirname "$0")/.." && pwd)

# Safe-but-impure APIs (dots escaped; `os\.` also catches os.ReadFile etc.).
patterns='os\.|io\.|net\.|time\.|math/rand|crypto/rand|os/exec|unsafe\.|syscall\.|runtime\.GC|flag\.|log\.|context\.|sync\.'

# Import allowlist: the pure stdlib packages the library consumes.
allowed_imports='^\t"crypto/ed25519"$|^\t"crypto/sha256"$|^\t"encoding/binary"$|^\t"errors"$|^\t"math"$|^\t"math/big"$|^\t"sort"$|^\t"strconv"$|^\t"strings"$|^\t"unicode/utf16"$|^\t"unicode/utf8"$|^import \($|^\)$'

status=0
for f in "$lib_dir"/*.go; do
  case "$f" in
    *_test.go) continue ;; # test files are not the library path
  esac
  # strip // comment tails first so doc prose (e.g. "I/O", "context.") cannot
  # false-positive — only code is scanned
  if sed 's://.*$::' "$f" | grep -En "$patterns" >/dev/null 2>&1; then
    echo "purity_check: FAIL — forbidden API in library path of ${f##*/}:" >&2
    sed 's://.*$::' "$f" | grep -En "$patterns" >&2 || true
    status=1
  fi
  # any import line — block, aliased, dotted, or single — whose quoted path
  # is outside the allowlist fails (aliases and dot-imports cannot hide it):
  # extract the import block plus single imports, then filter quoted paths
  imp_block=$(awk '/^import \(/ {flag=1} flag {print} /^\)/ {if (flag) flag=0}' "$f" 2>/dev/null || true)
  imp_single=$(grep -E '^import ' "$f" 2>/dev/null || true)
  bad_imports=$(printf '%s\n%s\n' "$imp_block" "$imp_single" | grep -oE '"[^"]+"' | grep -vE '^"(crypto/ed25519|crypto/sha256|crypto/subtle|encoding/binary|errors|fmt|math|math/big|sort|strconv|strings|unicode/utf16|unicode/utf8)"$' || true)
  if [ -n "$bad_imports" ]; then
    echo "purity_check: FAIL — non-allowlisted import in ${f##*/}:" >&2
    printf '%s\n' "$bad_imports" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "purity_check: OK — no I/O / clock / RNG / network / env / unsafe API in the library path."
