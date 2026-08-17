#!/bin/sh
# BAP-15 Task 16 — enforce the runtime dependency-license allowlist.
#
# AGENTS rule 10 + ADR 0014 D8: every dependency a CONSUMER inherits must carry
# a permissive license. This mirrors the Elixir prod-only gate
# (scripts/check_dependency_licenses.exs audits `--only prod`): only the
# `[dependencies]` closure (cargo `kind=normal`) is audited, because
# `[dev-dependencies]` (serde/serde_json — the conformance runner's test-time
# tools) are NOT inherited by a downstream consumer and do not ship in its
# binary. The runtime closure is taken from `cargo tree --edges normal`, the
# authoritative source for the consumer-facing tree.
#
# SPDX expression handling: `OR` is a distributor choice (the expression passes
# when ANY disjunct is allowlisted — e.g. `Apache-2.0 OR BSL-1.0` passes via
# Apache-2.0); `AND` is cumulative (ALL conjuncts must be allowlisted); `/` is
# treated as `OR` (Rust crate convention, e.g. `MIT/Apache-2.0`); parenthesized
# sub-expressions are evaluated RECURSIVELY (e.g. `(MIT OR Apache-2.0) AND
# Unicode-3.0`, the unicode-ident license since 1.0.15+, needs the inner OR
# evaluated, not leaf-matched). Any leaf not in the allowlist, or any unparseable
# expression, fails the gate (fail-closed).
#
# CLOSURE VARIANCE (observed 2026-08-17): `cargo tree --edges normal` is not a
# pure function of the manifest+lock — the audited set differs by toolchain and
# target platform (cargo 1.95/macOS closes at 15 deps, MSRV 1.81/linux at 19,
# including the curve25519-dalek-derive -> syn -> unicode-ident proc-macro
# chain). The allowlist must cover the UNION; the enforcing run is the CI job,
# which sees the larger closure.
#
# Exits 0 if every runtime dep is permissively licensed, 1 otherwise. Proven
# red-capable: a fabricated `GPL-3.0` license string is rejected.

set -eu

cd "$(dirname "$0")/.."

# Allowlist (D-RISK-2 verified permissive set). Unicode-DFS-2016 is the
# pre-2023 Unicode data license; Unicode-3.0 is its OSI-approved (2023-11-17)
# successor, carried by unicode-ident >= 1.0.15 — a transitive of syn inside
# the linux/MSRV-1.81 runtime closure (see CLOSURE VARIANCE above).
ALLOW='Apache-2.0 MIT BSD-3-Clause ISC BSD-2-Clause BSD-1-Clause Zlib Unicode-DFS-2016 Unicode-3.0'

# `cargo tree --edges normal --prefix none` lists the runtime closure; pipe both
# through python3 which also pulls license expressions from `cargo metadata`.
# python3 is available on the CI runner and locally (the repo already uses it
# for SBOM pruning scripts).
python3 - "$ALLOW" <<'PY'
import json, subprocess, sys

allow = set(sys.argv[1].split())


def license_ok(expr, allow):
    """SPDX evaluate: OR = any, AND = all, '/' = OR, parens = grouping
    (recursive). Conservative (fail-closed) on unparseable or non-allowlisted
    leaves."""
    if not expr:
        return False
    expr = _strip_parens(expr.replace("/", " OR "))
    or_parts = _split_top(expr, " OR ")
    if len(or_parts) > 1:
        return any(license_ok(p, allow) for p in or_parts)
    and_parts = _split_top(expr, " AND ")
    if len(and_parts) > 1:
        return all(license_ok(p, allow) for p in and_parts)
    leaf = expr.strip()
    if " " in leaf or "(" in leaf or ")" in leaf:
        # A compound the splitter could not decompose — never silently pass it.
        return False
    return leaf in allow


def _strip_parens(t):
    """Strip parentheses that wrap the WHOLE expression (balanced-aware —
    `(A) OR (B)` keeps its outer parens because they do not enclose it all)."""
    t = t.strip()
    while t.startswith("(") and t.endswith(")"):
        depth = 0
        wraps = True
        for i, ch in enumerate(t):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(t) - 1:
                    wraps = False
                    break
        if not wraps:
            break
        t = t[1:-1].strip()
    return t


def _split_top(expr, sep):
    """Split on `sep` at paren-depth 0. Returns the trimmed parts."""
    parts = []
    depth = 0
    cur = []
    i = 0
    while i < len(expr):
        tok = expr[i:i + len(sep)]
        ch = expr[i]
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif depth == 0 and tok == sep:
            parts.append("".join(cur).strip())
            cur = []
            i += len(sep)
            continue
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def main():
    meta = json.loads(
        subprocess.check_output(["cargo", "metadata", "--format-version", "1"], text=True)
    )
    # (name, version) -> license expression, from the full package set.
    lic_by_nv = {}
    for p in meta["packages"]:
        lic_by_nv[(p["name"], p["version"])] = p.get("license") or ""

    # Runtime closure from cargo tree --edges normal (authoritative, schema-free).
    tree = subprocess.check_output(
        ["cargo", "tree", "--edges", "normal", "--prefix", "none"], text=True
    )
    seen = set()
    rows = []
    for line in tree.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        name = parts[0]
        version = parts[1][1:]  # strip leading 'v'
        if name == "bounded-authority-protocol":
            continue
        nv = (name, version)
        if nv in seen:
            continue
        seen.add(nv)
        expr = lic_by_nv.get(nv, "")
        ok = license_ok(expr, allow)
        rows.append((name, version, expr, ok))

    print(f"license_check: {len(rows)} runtime dependencies audited")
    # Fail-closed floor (gate-integrity): if cargo tree's output drifted to
    # fewer than the 3 direct runtime deps (ed25519-dalek, sha2, ryu-js), the
    # parser audited nothing meaningful — refuse the "OK" path on empty or
    # degraded input rather than reporting success over zero dependencies.
    if len(rows) < 3:
        print(
            f"license_check: FAIL — only {len(rows)} runtime dep(s) parsed "
            f"(expected >= 3: ed25519-dalek, sha2, ryu-js). cargo tree output "
            f"drift or an empty success suspected.",
            file=sys.stderr,
        )
        sys.exit(1)
    bad = [r for r in rows if not r[3]]
    for name, version, expr, ok in sorted(rows):
        flag = "OK " if ok else "FAIL"
        print(f"  [{flag}] {name} {version} :: {expr or '<no license>'}")
    if bad:
        print(f"license_check: FAIL — {len(bad)} runtime dep(s) outside the allowlist.", file=sys.stderr)
        sys.exit(1)
    print("license_check: OK — every runtime dependency is permissively licensed.")


if __name__ == "__main__":
    main()
PY
