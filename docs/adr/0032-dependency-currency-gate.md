# ADR 0032: Dependency currency gate (latest-first)

- Status: accepted
- Date: 2026-09-16
- Governs: dependency currency policy for the dev/test tool set and the gate that
  enforces it

## Context

Nothing in the repository checked dependency currency: resolver-updatable packages
sat un-updated (dialyxir 1.4.7 → 1.4.8, ex_doc 0.40.3 → 0.40.4, and the transitive
ex_json_pointer 0.7.0 → 0.8.0 were all resolvable drift at audit time), and nothing
would surface drift after a future disclosure.

Two traps shape the gate's contract. First, `mix hex.outdated` exits nonzero both on
drift and on lookup failure, so the exit code cannot carry the verdict. Second, the
rendered table pads rows with trailing whitespace, so a status match anchored on a
hard end-of-line fails open on the padded rows.

The family precedent (the sibling `bounded_authority_report_adapter`) landed its
gate as a shell script inside its battery. The tri-platform build bar
([ADR 0031](0031-self-enforcing-toolchain-and-tri-platform-build-bar.md)) rejects a
POSIX shell inside a declared gate — `mix cmd scripts/*.sh` cannot execute on
Windows — so this gate is Elixir.

## Decision

1. Latest-first policy: everything resolvable is updated in the change that
   discovers it. Anything deliberately not at latest carries an inline reason next
   to its requirement in mix.exs. The current pin: `jsonschex ~> 0.9.2` (0.10 is a
   major-version jump pending a review of its validator changes against the
   certified corpus schema gates).
2. The gate is `scripts/check_deps_currency.exs` — Elixir, spawning `mix
   hex.outdated` as a subprocess (through `cmd /c` on Windows, where `mix` is a
   `.bat` shim `System.cmd` cannot execute). It runs inside `mix quality` via the
   `deps.currency` alias, so the CI quality job and every local battery run gate
   currency.
3. Classification is on the rendered table, never the exit code:
   - `Update possible` → resolvable drift → exit 1, packages named.
   - `Update not possible` → resolver-rejected → reported with each package's
     requirement chain (`mix hex.outdated <pkg>`); a parent's requirement is a pin
     upstream of this repository and does not fail the gate.
   - no table rendered → currency state unverified → exit 1. An unverified
     currency state never passes.
   Status matching is anchored with `\s*$` (trailing-whitespace tolerant) because
   the table pads its rows.
4. Both the direct-dependency table and `--all` (transitives) are classified: a
   resolvable transitive drift is drift.
5. After any dependency move, the full battery re-runs; a move without the
   corpus/conformance/differential gates the battery already carries is not done.

## Consequences

- The gate is three-way proven: green on the current lock (exit 0, pins reported
  with chains); red on a fabricated drift (a scratch copy with dialyxir reverted to
  1.4.7 in the lock exits 1 naming dialyxir); and the no-table path exits 1 when no
  dependency table renders.
- Dependency audits (`mix hex.audit`) ride the existing `audit` alias inside the
  same battery, so currency and CVE discipline gate together.
