# ADR 0014: Cross-language verifier SDKs

- Status: accepted
- Date: 2026-08-08
- Track: T2
- Refines: [ADR 0001](0001-public-protocol-verifier-boundary.md) (the public verifier boundary — the
  SDKs are additional language surfaces of it), [ADR 0005](0005-portable-conformance-corpus-and-verifier-cli.md)
  (the conformance corpus the SDKs consume), [ADR 0008](0008-release-candidate-contract.md) (the
  release posture the SDKs inherit in spirit)

## Context

ROADMAP row BAP-09 ratifies "Thin TypeScript and Python verifier SDKs consuming only the published
spec, vectors, and conformance corpus (client libraries of the extension; independent second
implementations by design)." The acceptance bar is: "Each SDK passes every valid and invalid
published vector; spec + vectors are the only inputs (no code-level derivation from the Elixir
implementation); its own ADR at authoring covers packaging and support surface." This ADR is that
acceptance gate.

[ADR 0005](0005-portable-conformance-corpus-and-verifier-cli.md) already closed the corpus's
normativity question: `conformance/corpus_independent.mjs` (Node, BAP-05 Task 4) is the independent
second implementation that makes the corpus normative. The SDKs are therefore NOT additional
normativity — that role is occupied. The SDKs' *authority* justification is the ROADMAP ratification
itself, not consumer demand: "whether to ship" is the roadmap's call, already made. The engineering
question this ADR records is *how* to ship two verifier libraries whose independence and
permissiveness-discipline are honest.

The ROADMAP row calls the SDKs "client libraries of the extension" (the BAP-08 capability-authorization
extension). [ADR 0013](0013-capability-authorization-extension.md) resolves the ambiguity this raises:
"this project's BAP-09 verifier SDKs verify *this* protocol, they are not implementations *in* an MCP
SDK," and "an 'official SDK' is an MCP-org SDK; a BaseLabs repo would not satisfy the term." The SDKs
therefore stand as verifier libraries for the v1 **protocol** (the frozen, BAP-05-normative profile),
not as gating artifacts for BAP-08's official-track submission — their value is not contingent on
BAP-08 clearing its external preconditions, because they verify the protocol that exists independent of
the extension. Their ROADMAP mention as "client libraries of the extension" is the historical reason
they were ratified, not a delivery dependency.

The load-bearing permissiveness lesson is [ADR 0005:240-246](0005-portable-conformance-corpus-and-verifier-cli.md):
*"for a differential checker, 'both implementations agree on the corpus' only constrains the runner
where the corpus has cases. Permissiveness is invisible to agreement by construction, so it must be
closed by reading the reference implementation's validators and mirroring them, then PROVING each
mirror with a case that goes red when the mirror is removed."* The BAP-09 acceptance bar forbids
reading `lib/`. This ADR records how the two statements are reconciled without violating either.

## Decision

1. **Framing — ratified cross-language verifier libraries, not normativity.** The SDKs are published,
   typed façades that reimplement the frozen v1 profile from the spec + corpus, with conformance
   independently verifiable against the same published corpus, and with permissiveness-discipline
   enforced by a per-language mutation-gate (Decision 7). The design does not claim marginal
   normativity as a justification — an unquantified four-way-agreement gain is not architecture
   authority. The "distribution / third-party-consumer" framing is descriptive of the artifact's
   shape, not the justification for shipping; the justification is the roadmap.

2. **Packaging — monorepo `sdks/` subtree, not separate repos, not in the Hex `files:`.** The SDKs
   live under `sdks/typescript/` and `sdks/python/` in THIS repository, tracked in git, physically
   co-located with the spec + corpus they conform to (the simplest architecture; separate repos would
   add release/publish infrastructure not authorized in-slice). They are NOT included in the Hex
   package `files:` list — they are not Elixir. The TypeScript SDK publishes as
   `@bounded-authority/verifier` (npm); the Python SDK publishes as `bounded-authority-verifier`
   (PyPI). License is Apache-2.0 for both ([ADR 0001](0001-public-protocol-verifier-boundary.md)
   license decision; AGENTS rule 10) — the patent grant fits a cryptographic protocol. Each SDK
   subtree carries its own `LICENSE` + `NOTICE`. Package manifests are authored ready-to-publish, but
   no `npm publish` / `twine upload` runs in-slice — publication is a separate, user-authorized step
   (a new-authority action per the forge whitelist).

3. **Support surface — the frozen v1 façade.** Each SDK exposes the 17 public verification functions
   ([protocol-v1.md § Public verification contract](../protocol-v1.md), lines 270-290) translated to
   its language's idioms, plus the versioned primitives (`Jcs.encode`, `Uri.normalize`,
   `Jwk.thumbprint*`, `base64urlDecode`, `Bounds.maximum`/`Bounds.new`). Every function returns
   `Ok<Facts>` / `Err(Invalid)` (TS: a tagged result; Python: a `Result` dataclass) — exactly mirroring
   the Elixir `{:ok, value}` / `{:error, :invalid}` shape. **No `allowed`/`authorized`/`decision`/
   verify-then-act surface** (AGENTS rule 1). Facts are value-bearing and redacted exactly as the
   Elixir facts are (`authorization: "not_evaluated"` for Grant/Envelope/Export;
   `trust: "not_evaluated"` for Chain/Anchor/Transition). Version floors: **Node >= 20** (matches the
   existing Node runner's baseline + the repo's CI Node pin; `node:crypto` Ed25519 + WebCrypto stable
   on 20), **Python >= 3.10** (the floor where `match` statements + modern typing land; `cryptography`
   supports 3.10+). The TS SDK defaults to `node:crypto` (stdlib-only, matching the Node runner);
   `@noble/curves` is a documented optional browser-build path, not a default dependency. The Python
   SDK uses the `cryptography` package (the one unavoidable crypto dep — stdlib has no Ed25519) +
   stdlib `hashlib`/`urllib`/`base64`. Maintenance posture: the SDKs track the published corpus; a
   corpus amendment is a SDK MINOR bump.

4. **Corpus binding — vendor a snapshot + assert the SHA at startup.** A published SDK consumer either
   vendors the SDK's corpus snapshot (versioned with the SDK) or points the runner at a corpus dir. The
   binding is a MECHANISM, not documentation: the SDK records the `index.json` SHA-256 it was certified
   against, and the runner hashes the loaded `index.json` at startup and fails closed on mismatch — so
   a consumer who vendors a mismatched corpus gets a hard failure rather than a silent drift. SemVer:
   the SDK is 0.x; a corpus-snapshot bump is a MINOR bump (recorded in CHANGELOG). In dev mode, both
   runners load `priv/conformance/v1/corpus/` via a repo-relative path with the same startup SHA
   assertion. This is strictly stronger binding than the Node runner has.

5. **Derivation hygiene — honestly scoped.** The "no code-level derivation from Elixir" acceptance bar
   is enforced by **(a) process** (the author reads `docs/protocol-v1.md` + the RFCs it cites + the
   corpus JSON only; does not open `lib/*.ex`), backed by **(b) a review grep** that no Elixir module
   path (`BoundedAuthorityProtocol`, `lib/bounded_authority_protocol`, `.ex`) appears in SDK source
   (catches *literal* derivation but **not** semantic transcription), **(c) the corpus backstop** for
   constants/Enums/verdicts the corpus pins (a mistyped maximum or wrong closed-set verdict fails its
   case), and **(d) the permissiveness mutation-gate** (Decision 7) for the permissiveness class
   specifically — a closure transcribed wrong is caught by the red-capable test that fails when the
   closure is removed. The bar is **honor-system + grep + corpus + permissiveness-gate**, not
   cryptographically enforced. The residual blind spot (algorithm transcription from memory of a
   non-permissiveness routine) is the irreducible honor-system limit of a bar that forbids the
   reference — disclosed here plainly, not hidden behind a grep or a corpus backstop.

6. **Permissiveness closures — derived from spec REQs, proven by a per-language mutation-gate.** The
   closures are mandated by spec REQs (`REQ1-JSON-no-duplicate`, `REQ1-SELECTOR-semantic-identity`,
   `REQ1-JSON-raw-lexeme`, `REQ1-JSON-single-value`, the tagged JSON algebra's int/float distinction),
   and the SDKs implement them from the spec — this keeps the bar intact (deriving a spec-mandated
   closure from the spec is not derivation-from-Elixir even when the Node runner happened to find them
   by reading `lib/`). The closures, and their per-language defects:
   - **Duplicate-rejecting JSON decoder** (both SDKs) — neither uses host `JSON.parse`/`json.loads` for
     protocol-JSON; a hand-rolled recursive scan rejects duplicate members at every depth.
   - **Null-prototype containers** — TS uses `Object.create(null)` (a `__proto__` member cannot be
     absorbed by `Object`'s prototype setter); Python uses plain `dict` with `dict[key]` subscription
     only (never `getattr`), so `__class__`/`__proto__` keys are ordinary data. **The mechanism differs
     per language** — Python's risk is dunder/attribute collision, not prototype absorption, so the
     Python closure is NOT analogous to the TS one.
   - **Raw number-lexeme scan** (both) — magnitude + 64-byte ceiling checked before host conversion.
   - **Single-value + trailing-bytes rejection** (both) — host parsers that accept trailing data are
     not used.
   - **int/float tag distinction** (both) — the tagged algebra preserves integer-vs-float through
     decoding (selector semantic identity + the typed request-digest projection depend on it).
   Each closure is **proven red-capable** by a per-language mutation-gate test in the SDK's own suite
   (Decision 7): construct the host-specific defect, assert the SDK REJECTs it, and prove the test goes
   RED when the closure is mechanically removed. This is the second half of the ADR 0005:240-246
   discipline applied per-language — the frozen corpus has no parser-layer permissiveness cases, so the
   mutation-gate is the falsifier the corpus cannot be. The **residual permissiveness gap** (a
   host-runtime edge-case beyond what the spec REQs name, the mutation-gates prove, AND the corpus pins
   — e.g. an exotic Unicode-handling divergence in `node:crypto` vs `:crypto` vs `cryptography` on a
   signature edge-case none of them construct) is disclosed as the irreducible residual: anything the
   REQs name OR a red-capable test can construct is covered; anything outside that set is a
   corpus-extension candidate (a new case), never a silently-claimed-conformant surface.

7. **Permissiveness mutation-gate — the per-language falsifier.** Each SDK ships a
   permissiveness test module (`test/permissiveness.ts` / `tests/test_permissiveness.py`) that, for
   each closure in Decision 6, (a) constructs the host-specific permissive defect the closure defeats,
   (b) asserts the SDK REJECTs it, and (c) is run in CI twice — once green-as-is, once with the closure
   mechanically removed (the test goes RED). This is the ADR 0005:240-246 proof method applied
   per-language; it makes each closure falsifiable in the language whose host runtime it targets. The
   defect-injection battery (run at authoring + documented in the SDK README) records that every
   closure + the census + the purity lint + the license check is red-capable.

8. **Enforcement posture — in-slice gates, not honor-system.** The repo's Elixir
   `tools/architecture_gate.exs` governs `lib/` only and does not extend to `sdks/`, and
   `scripts/check_dependency_licenses.exs` operates on the Elixir tooling SBOM only. Without new
   in-slice gates the SDKs would ship with weaker purity + license enforcement than the Elixir
   reference. This ADR closes both gaps:
   - **Critical-surface declaration:** `sdks/**` is added to `.forge/critical-surfaces` (tracked via
     `git add -f`) — the "user declares critical" trigger that makes any touch of `sdks/**` a T2-gauge
     slice. The repo's critical-surface commit hook is not installed, so the declaration governs via
     honor-system `track: T2` + the closeout lenses (the gauge is auditable via the `track:` field).
     This is the same regime the existing `lib/**` entry runs under.
   - **Purity lint:** each SDK ships a library-path purity linter that forbids I/O + clock + RNG +
     network + filesystem imports/calls in `src/` (TS: an ESLint rule; Python: an AST check). It runs
     in CI as part of the `sdks-conformance` job — the analog of `architecture_gate.exs`'s purity
     rules for the library path. A stray `Date.now()` / `datetime.now()` in the verify path fails it.
   - **License check:** the `sdks-conformance` CI job runs a dependency-license check that enumerates
     the SDK dependency trees and fails if any package license is outside the Apache-2.0/BSD/MIT/ISC-
     compatible allowlist (AGENTS rule 10) — the analog of `check_dependency_licenses.exs` for the SDK
     trees. The `cryptography` Apache-2.0/BSD claim is verified by the gate, not by author assertion.
   Extending the Elixir architecture gate's full AST sophistication to TS/Python is a separate tooling
   decision, not this slice; the purity lint covers the purity invariant (no I/O/clock/RNG/network in
     the verify path) that AGENTS rule 2 binds.

9. **Two-boundary key census — per-runner, not a new manifest partition.** Each SDK's conformance
   runner asserts (a) every key the corpus fixtures carry is imported at the SDK's crypto boundary AND
   (b) the set of keys fed to Ed25519 verify equals the index `public_key_fingerprints` — both
   directions ([ADR 0005 § Census evolution](0005-portable-conformance-corpus-and-verifier-cli.md)).
   The SDKs are NOT added to the BAP-05 three-partition vector manifest (that governs the *internal*
   independent verifiers the corpus pins for normativity); the SDKs are *external* consumers whose
   census is asserted per-runner against the index, not woven into the normativity-manifest partition
   count. A future "add a verify-surface case with a new key" change updates the index (single source)
   and every runner re-derives, not four manifest partitions.

## Alternatives considered

- **Separate repos per SDK.** Rejected: would add release/publish infrastructure (a new-authority
  action) not authorized in-slice, and loses the physical co-location with the spec + corpus the SDKs
  conform to. The existing `conformance/corpus_independent.mjs` proves Node code can live in the same
  repo as `lib/`, import nothing from it, and be the BAP-05 normativity runner — the same derivation-
  hygiene pattern works for the SDKs.

- **One SDK at a time (TS first, Python later).** Rejected: the acceptance bar is "each SDK passes
  every vector" — shipping one language and deferring the other is effort-shaped narrowing below the
  ratified target. Both ship in one slice, sequenced TS→Python within the slice so the Python
  implementer diffs against the TS permissiveness closures rather than a blank slate.

- **Read `lib/` to close permissiveness (the ADR 0005:240-246 method).** Rejected: the acceptance bar
  forbids it. The closures are spec-mandated, so deriving them from the spec REQs + proving each with a
  per-language mutation-gate keeps the bar intact for the hardest class without violating it.

- **Use host `JSON.parse` / `json.loads` for protocol-JSON.** Rejected: both are last-wins on
  duplicate members and accept trailing data, violating `REQ1-JSON-no-duplicate` +
  `REQ1-JSON-single-value`. Both SDKs ship a hand-rolled duplicate-rejecting decoder.

- **Extend the Elixir architecture gate to TS/Python in-slice.** Rejected as a separate tooling
  decision: `architecture_gate.exs` is an Elixir AST/purity gate; a TS/Python equivalent is a distinct
  tooling effort. The in-slice purity lint covers the rule-2 invariant; the full AST gate is a
  follow-up.

## Consequences

- The repository gains two new language toolchains (TypeScript under `sdks/typescript/`, Python under
  `sdks/python/`) with their own package manifests, test suites, and CI job. The Elixir package is
  untouched (`lib/`, `priv/conformance/`, `test/`, `mix.exs`, `mix.lock` unchanged — verified at
  closeout by an empty `git diff`).
- A new `sdks-conformance` CI job runs on every push/PR touching `sdks/**` or `priv/conformance/**`,
  exercising conformance (259 cases + census), the permissiveness mutation-gates, the purity lint, and
  the license check for both SDKs.
- SDK conformance is durable: a future touch of an SDK file that drifts a canonicalization rule or
  breaks a permissiveness closure fails CI (the corpus for constants/canonicalization/closed-sets; the
  mutation-gate for the permissiveness class).
- The derivation-hygiene bar's irreducible blind spot (algorithm transcription from memory of a
  non-permissiveness routine) is disclosed here as the honor-system limit, not hidden — a future
  contributor who reads `lib/` and transcribes a non-permissiveness routine is outside what any
  in-repo mechanism can detect, and must self-attest.
- The four-way agreement (Elixir reference + Node runner + TS SDK + Python SDK) is marginally stronger
  evidence of corpus correctness, but is NOT the bar BAP-09 was ratified against and is not claimed as
  a justification.
