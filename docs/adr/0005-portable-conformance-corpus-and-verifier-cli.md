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

**n_a reason obligation (Q29).** Each `n_a` leaf carries a one-line falsifiable reason naming
what the surface's input algebra cannot express: a leaf is either a positive integer count OR the
object `{"n_a": "<reason>"}` (the bare string `"n_a"` is also accepted for backward shape
compatibility, but the shipped corpus uses the object form everywhere so every not-applicable
cell is reviewable). The reason is for human review, not machine logic — the loader and the
independent runner treat `{"n_a": reason}` identically to the bare `"n_a"` string (zero executed
cases). Flipping a required cell to `n_a` therefore requires writing a mechanical impossibility
claim that review can falsify; the "author fixes the matrix too" variant of V2 is met with a
falsifiable-reason obligation, not trust. The shape, the reasons, and the loader's acceptance of
the object form are all pinned in ExUnit.

### bounds.new constant-pinning (Q31) + two-key exception

The `bounds.new` surface pins every immutable profile maximum as portable data. For every key of
the maxima table (`lib/bounded_authority_protocol/v1/bounds.ex:91-130`), the corpus carries a
tighten-to-exact-maximum case (`class: exact_bound`, verdict `valid`) and, except for the
two-key exception below, a tighten-to-maximum-plus-one case (`class: maximum_plus_one`, verdict
`invalid` — widening violates the tightening-only contract). The fixed-width keys
(`public_key_bytes`, `signature_bytes`, `digest_bytes`) additionally carry change-rejection
cases (`class: invalid_limit`) exercising both below- and above-max values. A second
implementation with any mistyped maximum constant fails these cases; no oversized artifact is
needed to pin any constant.

**Two-key exception (mechanically forced).** `integer_magnitude` and `float_magnitude` ship the
tighten-to-exact-maximum `valid` pin only — they cannot carry the tighten-to-maximum-plus-one
member because the +1 literal (`9,007,199,254,740,992`) exceeds the decoder's own magnitude
ceiling (`lib/bounded_authority_protocol/v1/json.ex:147`, `9,007,199,254,740,991`), so any
corpus JSON file containing it is rejected by the corpus loader by construction. The `bounds.new`
input is structured JSON, so the `.raw` sidecar escape (which applies only to byte-bearing
fields) does not help. The magnitude ceiling itself is still portably pinned through `json.decode`
`maximum_plus_one` cases whose input is a `.raw` sidecar carrying the raw JSON bytes
`9007199254740992` → expected `verdict: "invalid"`. The exception and its mechanical reason are
pinned in ExUnit (the two keys' `maximum_plus_one` absence is asserted).

### Legacy-depth subsumption (V5) + the [:::] divergence

The corpus subsumes the legacy code-embedded case sets as data: all 18 legacy URI byte-values
from `conformance/bap03_independent.mjs:22-41` and the legacy duplicate-member case appear as
corpus data. The 6 idempotent-valid legacy URIs port as `uri.normalize` `valid` cases (normalized
output equals input); the 5 normalizable-but-non-idempotent legacy URIs (e.g. default-port,
uppercase-host, percent-encoded-tilde, dot-segments) port as `valid` cases whose pinned normalized
output differs from the input — faithfully subsuming the byte value AND pinning the normalization
behavior; the 6 URIs rejected by both implementations port as `invalid_uri` cases.

**`https://[:::]/` is omitted (implementation-divergent).** This one legacy URI diverges between
the two implementations: `V1.Uri.normalize/2` rejects it (`:invalid`, treating `:::` as an
invalid IPv6 literal), while the independent Node runner accepts it and normalizes it to
`https://[:::]/`. Any declared verdict makes exactly one side disagree, breaking the hard
"both sides agree (exit 0)" normativity constraint. It is therefore omitted from the corpus; the
other 17 of 18 legacy byte-values are subsumed. The divergence is recorded here (rather than
hidden) so it is visible and tracked; resolving it (harmonizing the IPv6-literal acceptance rule
across both implementations) is a frozen-profile change owned by a separate task, not a
conformance-corpus concern. The 17 port-able cases and the omission are pinned in ExUnit.


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
- Every `n_a` applicability cell carries a falsifiable reason (`{"n_a": "<reason>"}`); removing a
  reason or weakening it to a bare `"n_a"` is a visible diff against the pinned reason set, and
  the loader rejects any leaf that is neither an integer, the bare `"n_a"`, nor the exact
  `{"n_a": <string>}` shape.
- Adding a new maxima key requires landing both the `exact_bound` and (except for magnitude keys)
  the `maximum_plus_one` `bounds.new` pins, or the Q31 pin goes red.
