#!/bin/sh
# BAP-16 — enforce the runtime dependency-license allowlist for the Go SDK.
#
# AGENTS rule 10 + ADR 0014 D8: every dependency a CONSUMER inherits must
# carry a permissive license. This module pins ZERO runtime dependencies by
# design (stdlib crypto/ed25519 + crypto/sha256 only, BAP-16 acceptance row),
# so the gate asserts the dependency closure is exactly empty — with a
# fail-closed floor: a degraded or unparseable `go list` output can never
# satisfy the gate, and any require line (module dependency) fails it.
#
# The Go standard library is BSD-3-Clause toolchain surface, not a module
# dependency, and is therefore not enumerated here.
#
# Exits 0 iff the module graph holds no runtime dependencies. Red-capable:
# adding any require line to go.mod (e.g. a GPL-licensed helper) makes this
# script exit 1 (proven at authoring with a fabricated require, recorded in
# the README).

set -eu

cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
  echo "license_check: FAIL — go toolchain not found." >&2
  exit 1
fi

deps=$(go list -m all 2>/dev/null || true)

if [ -z "$deps" ]; then
  echo "license_check: FAIL — 'go list -m all' returned nothing (degraded output refused)." >&2
  exit 1
fi

# every line beyond the main module is a dependency
count=$(printf '%s\n' "$deps" | grep -v '^github.com/baselabs/bounded_authority_protocol_go$' | grep -c . || true)

if [ "$count" -ne 0 ]; then
  echo "license_check: FAIL — $count runtime module dependency(ies) present; the SDK pins zero:" >&2
  printf '%s\n' "$deps" | grep -v '^github.com/baselabs/bounded_authority_protocol_go$' | grep . >&2 || true
  exit 1
fi

echo "license_check: OK — zero runtime dependencies (stdlib-only module)."
