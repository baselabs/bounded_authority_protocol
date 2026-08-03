# ADR 0005: Portable conformance corpus and verifier CLI

- Status: accepted
- Date: 2026-08-02

## Context

BAP-05 must deliver a language-neutral conformance corpus and a deterministic offline verifier
CLI so that any implementation of the v1 protocol — the reference Elixir package, the future
BAP-09 TypeScript/Python SDKs, or a third-party implementation — can prove byte-exact agreement
with the normative v1 parsing/verification profile (ADR 0002) on the same fixed inputs. The
corpus IS the normative evidence: a wrong expected byte or a misclassified cell certifies future
nonconforming implementations, and the failure is maximally quiet (nothing fails today).

Two prior conformance surfaces existed but were each scoped to one fixture family: the
grant-holder-proof vectors (BAP-03) and the chain/archive vectors (BAP-04), each with its own
independent Node verifier. Neither covered the full surface set, neither was total (every
surface × class applicability cell), and neither had a single canonical corpus identity a
consumer could pin.

## Decision

### Corpus format

A corpus is a directory carrying an `index.json` plus case files under `cases/<area>/*.json`
and `.raw` sidecars for oversize wire inputs. The index format is
`bounded-authority-protocol-v1-conformance-corpus-index` with: `public_key_fingerprints`
(sorted; the full set of keys the corpus declares, equal to what an independent runner imports),
`files` (path / SHA-256 / case-count triples; ≤256 entries), `total_cases`, and `applicability`
(an object keyed by the 28 surface names, each with 16 class leaves — an integer count for
populated cells or `"n_a"` for not-applicable). Case file format is
`bounded-authority-protocol-v1-conformance-cases`; case members: `id`, `surface` (closed
28-value enum), `class` (closed 16-value enum), `input` (byte forms: `text` / `base64url` /
`raw_file`+`sha256_base64url` sidecar), `expected` (`verdict:"valid"` + exact outputs, or bare
`verdict:"invalid"`), and optional `tamper` (verbatim artifact + derivation descriptor).

### Sidecar rule

Inputs that exceed the corpus loader's own JSON byte bound (a wire input at the maximum-plus-one
boundary) ride as a `.raw` sidecar: the case references it by `raw_file` + `sha256_base64url`,
and the loader binds the sidecar's hash before feeding its bytes (bypassing the loader's own
decoder) to the facade. This lets the corpus pin the maximum-plus-one magnitude ceiling
(`9007199254740992` raw JSON bytes) even though that literal cannot appear in a corpus JSON file
(it exceeds the decoder's own magnitude bound by construction).

### Published-artifacts definition

The published artifact set is exactly the Hex `files:` list: `lib`, `priv/conformance/v1/corpus`
(the corpus itself), `priv/conformance/v1/schemas`, the docs, and the package metadata files.
The corpus is self-contained — an independent runner verifies against a tree containing ONLY the
corpus directory (no vectors, no schemas, no source) and agrees on every case.

### Applicability matrix + n_a criterion

Every surface × class cell is either populated (≥1 executed case) or explicitly `n_a`. The `n_a`
criterion is falsifiable and mechanical: a cell is `n/a` only when the input algebra cannot
express that class for that surface (e.g. a pure decoder has no `invalid_nonce` class). Required
cells (valid, boundary_near, exact_bound, maximum_plus_one where expressible) must be ≥1; `n_a`
cells must be 0. Enforced in both directions by both the official loader and the independent
runner, and pinned byte-exact in ExUnit.

### Census evolution + index self-census

The corpus index declares `public_key_fingerprints` — the full set of public keys carried by the
corpus case data (4 valid verify-surface keys + 2 invalid_key-case keys = 6). An independent
runner's published-mode census is HARD two-way: the keys observed at its crypto import boundary
must equal the index's declared set exactly, both directions, always — no softness (a vacuous
green is the V4 hole this design exists to kill). The vector manifest grows to three partitions
(bap03 + chain_archive + corpus); the three-partition union equals the canonical set (17 keys),
and the corpus partition equals the index list.

### CLI contract

The verifier is shipped as an escript `bounded_authority_conformance`. `--corpus DIR` is REQUIRED
(no default — a wrong-corpus run that exits 0 is a quiet misverification path in the tool built
to eliminate quiet misverification; the escript's `:code.priv_dir` default resolves to an
archive-internal path and a CWD-relative default silently points into a consumer's own `priv/`).
Exit 0 only on complete agreement; 1 on any integrity/verdict/coverage failure; 2 on usage error.
The report is deterministic JCS bytes binding the index SHA-256 it ran against. No clock, network,
randomness, or trust selection.

### Carve-out shape

The package remains pure (AGENTS rule 2): no runtime side-effects in the verification path. The
CLI is a single I/O carve-out — `cli.ex` does argv parsing + `File.read`/`File.ls`/`File.write`/
`File.dir?`/`IO.binwrite`/`Path.join` only, delegating every judgment to the pure
`Corpus`/`Runner`/`Report` core; `cli/main.ex` is the two-line escript entry (`System.halt`). The
architecture gate keys the allowance per-file-per-function (a `System.halt` in `cli.ex` is denied;
a `File.write` in `cli/main.ex` is denied), and no module outside `conformance/` may reference the
`Conformance.Cli` module. A new ignore-modules pin asserts `test_coverage[:ignore_modules]` equals
exactly `[Cli.Main]`.

### Gate set + battery placement

The conformance surface is gated by: corpus integrity (per-file SHA-256, file-set equality both
directions, counts, case-id uniqueness, applicability totality both directions, tamper
verbatim-vs-derived, `.raw` hash binding); the official CLI; the independent Node runner (proves
normativity — a value that only round-trips the official implementation is not normative until an
independent runner agrees); property + fuzz gates (facade closure totality — every input returns
`{:ok,_}|{:error,:invalid}`, never raises); and a source-isolated mutation battery proving every
named integrity check and the carve-out keying actually catch the failures they claim. Both
mutation batteries (chain_archive + conformance) run in `mix quality` (measured basis ~155s +
the existing battery, under the 8-minute threshold).

### Package-files decision

The corpus ships in the published package (`files:` += `priv/conformance/v1/corpus`), and the
fresh-consumer package check runs the packaged escript against the packaged corpus, proving the
published set is sufficient for verification.

## Consequences

- A second implementation that disagrees with the corpus is a conformance failure by definition;
  the corpus is now the arbiter, not the reference implementation.
- Adding a new surface requires populating its applicability row and landing cases for every
  populated class, or the corpus fails to load.
- The index's `public_key_fingerprints` must track the corpus case data exactly; adding a
  verify-surface case with a new key requires updating the index + manifest partition + canonical
  set in the same commit.
- The CLI carve-out is the package's only I/O surface; widening it (a second File/IO call outside
  the exact allowance) turns the architecture gate red and the mutation battery red.
