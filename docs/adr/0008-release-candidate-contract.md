# ADR 0008: Release-candidate contract

- Status: accepted
- Date: 2026-08-05

## Context

BAP-06 must freeze the release-candidate contract for the unpublished 0.1.0 package before BAP-07
publishes it. Two questions need a recorded product decision rather than an execution detail:

1. **What is the locked public API surface, and what enforces the lock?** A consumer (the private
   `bounded_authority` runtime, a future BAP-09 TypeScript/Python SDK, a third-party implementation)
   depends on a specific set of public functions. An unlocked or misspecified surface ships to first
   publication and is post-publication-irreversible: a removal, rename, or arity change after third
   parties depend on it is a breaking change.
2. **Is the candidate archive reproducible, and how is that claim scoped?** A release-candidate
   contract must prove (not assert) that the archive is reproducibly built, so a reviewer comparing
   a local candidate against a CI-attested candidate compares like for like.

ADR 0001 §8 committed to "SemVer + contract-major discipline" as a concept; BAP-06 is its first
concrete instantiation for the 0.1.0 candidate. ADR 0001 did not specify the API-lock mechanism or
the reproducibility gate — both are ADR-grade choices with post-publication consequences.

## Decision

### 1. The locked 0.1.0 public API surface

The locked public API is the set of modules and functions a consumer depends on, enforced by the
existing mechanical lock and enumerated for human readers + SemVer review:

**Mechanical lock (already exists, uncited until BAP-06):** `tools/architecture_gate.exs:184-287`
`@compiled_export_allowances` pins the exact compiled exports per `.beam` for the dominant contract
modules — `Elixir.BoundedAuthorityProtocol.V1.beam` (the facade, lines 188-207), `V1.Runtime.beam`,
the codecs, and the public structs. For those modules, any export addition, removal, or arity change
turns `mix architecture` red (full-export-set enforcement at `:1581-1596`). The named decoder/bounds
submodules (`V1.Json`, `V1.Base64Url`, `V1.Bounds`) are enforced under `@compiled_dynamic_allowances`
(dynamic-call-count enforcement at `:1894-1910`): removal/rename/arity change of their existing
locked functions surfaces via the dynamic-call check plus the unpacked-consumer gate, though a
brand-new additive export on those specific submodules is not caught by the full-set check. **The
`V1.beam` facade pin IS the lock for the dominant contract surface; the doc enumeration below is for
readers, and the submodule gap is noted honestly rather than overclaimed.**

**Doc enumeration (for human readers + SemVer review), the locked surface:**

`BoundedAuthorityProtocol.V1` facade (`lib/bounded_authority_protocol/v1.ex`):

- Producer functions: `grant_signing_input/2`, `proof_signing_input/2`,
  `boundary_anchor_signing_input/2`, `key_transition_signing_input/2`, `assemble_compact/2`.
- Decode/verify functions: `untrusted_key_locator/2` (the default-arg `untrusted_key_locator/1` is
  also pinned by the gate), `decode_grant/2`, `decode_proof/2`, `verify_grant/3`,
  `check_envelope/2`, `request_digest/3`, `encode_consumption_entry/2`, `check_chain/2`,
  `encode_anchored_export/2`, `verify_historical_anchor/3`, `verify_key_transition/4`,
  `verify_anchored_export/3`.

Named submodules: `BoundedAuthorityProtocol.V1.Json.decode/2`,
`BoundedAuthorityProtocol.V1.Base64Url.decode/2` (the only decoder façade, per ADR 0002).

Public structs: `GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`,
`AnchoredExportFacts`, plus the `Expected*` / `Historical*` / input structs a consumer must build.

`BoundedAuthorityProtocol.V1.Bounds` (the tightening-only bounds constructor).

Anything else in `lib/` is internal (implementation modules under `v1/`), not part of the locked
contract even if public-ish.

The doc lists PRIMARY arities where a function has a default-arg variant (e.g.
`untrusted_key_locator/2`); the gate pins ALL compiled arities (including the default-arg `/1`).
The gate is the authoritative full-arity lock; a divergence between the doc and the gate is a
docs-currency finding, not a contract change.

### 2. SemVer convention for 0.1.0

0.1.0 is the first release-candidate version. Under pre-1.0 SemVer (SemVer §4: "Major version zero
(0.x.y) is for initial development ... MAY make incompatible changes"), the 0.x.y line reserves the
right to break compatibility until 1.0.0. The API lock above is the COMMITMENT that the enumerated
surface is the intended 1.0.0 surface; breaking changes before 1.0.0 land as 0.x.0 version bumps
with a CHANGELOG entry, never silently. 1.0.0 (first stable) is a future decision, not BAP-06's.

Removal, rename, signature change, or a new REQUIRED argument to a locked function is a
contract-major (1.x→2.x after 1.0.0; 0.x→0.(x+1) before) change and requires extending the gate's
`@compiled_export_allowances` allowlist in the same commit (a missing entry fails `mix architecture`).
Additive changes (new optional argument, new function) require extending the allowlist and are minor.

### 3. Reproducibility gate

The candidate archive is built by `scripts/check_release_candidate.exs`, gated into `mix quality`
via the `release.candidate` alias. The gate builds the archive TWICE with `_build` and `deps` purged
between builds, then asserts byte-identical SHA-256. The gate's claim is "two independent builds
agree," scoped honestly: `mix hex.build` packages source files (the `files:` list), not compiled
BEAMs, so the gate's value is regression detection — it catches the moment a future change
introduces a non-deterministic packaged input (a generated file embedding a build path or timestamp,
a dep writing into a packaged dir). Hex normalizes tar mtimes to epoch; the cache purge + second
build catches non-determinism in the assembly path. The gate does NOT assert "the build is
reproducible" from a shared-cache self-comparison.

The SHA-256 printed on a green run is the candidate-evidence yardstick — the same yardstick the
supply-chain workflow's `SHA256SUMS` uses. It is recorded locally in the BAP-06 closeout-evidence
block for comparison; it carries no decision semantics and is not an authority shape (AGENTS rule 1:
no `receipt`/`decision`).

## Alternatives considered

- **Doc-only API lock, no mechanical enforcement.** Rejected (design-adversarial Challenge 2): a doc
  claim with no enforcement drifts silently, and the existing `@compiled_export_allowances` pin is a
  stronger lock that was uncited. The doc enumerates; the gate enforces.
- **Shared-cache reproducibility probe ("two builds of the same tree, 1s apart").** Rejected
  (design-adversarial Challenge 3): it cannot distinguish "deterministic" from "second build reused
  cached artifacts" — claimed-limit-unverified. The cache-purged two-build gate is the honest scope.
- **A new authority-bearing "candidate receipt" artifact.** Rejected (design-adversarial Challenge 4):
  AGENTS rule 1 forbids `receipt` as an authority shape. The candidate-evidence record is the existing
  attestation path (`SHA256SUMS` + `gh attestation verify`), renamed to avoid the authority collision.

## Consequences

- A breaking change to a locked function requires a version bump + a CHANGELOG entry + an
  `@compiled_export_allowances` allowlist edit in the same commit, or `mix architecture` fails.
- `mix quality` now proves the candidate archive reproduces on every local + CI + supply-chain run;
  a future non-reproducible input turns the gate red at the next quality run.
- The 0.1.0 candidate is locked but not stable; stability is the 1.0.0 commitment (BAP-07 or later).
- BAP-07 publishes the exact candidate BAP-06 froze; the candidate-evidence record (CI-attested
  SHA-256 + `gh attestation verify` constraints) is the publication receipt, recorded in ROADMAP.
