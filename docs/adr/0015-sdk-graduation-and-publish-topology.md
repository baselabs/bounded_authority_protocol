# ADR 0015: SDK graduation and publish topology

- Status: accepted
- Date: 2026-08-09
- Track: T1
- Refines: [ADR 0014](0014-cross-language-verifier-sdks.md) (the monorepo-authoring decision this narrows for the
  publish phase), [ADR 0008](0008-release-candidate-contract.md) (the SemVer + provenance discipline a graduated SDK
  inherits), [ADR 0001](0001-public-protocol-verifier-boundary.md) (the public/private dependency direction a
  per-SDK publish surface preserves)

## Context

[ADR 0014](0014-cross-language-verifier-sdks.md) placed the TypeScript and Python verifier SDKs under `sdks/` in this
repository, co-located with the spec and conformance corpus they are certified against. That decision is correct for
the **authoring phase** — unpublished co-development benefits from one clone, atomic cross-SDK corpus updates, and the
absence of release/publish infrastructure. The load-bearing property ADR 0014 relied on was *reversibility*: a mistake
in monorepo placement is cheap to correct, and `git filter-repo` lifts a subtree cleanly.

The question ADR 0014 did not settle — and could not, before any SDK published — is the **publish topology**: where a
SDK lives once it is published to a language registry. Two facts make this a distinct decision, not an execution
detail of ADR 0014:

1. **Registry publication is irreversible.** A published version cannot be moved to a different provenance. npm/PyPI/
   crates.io do not let a published `0.1.0` change the repository it was published from. New versions may publish from
   a new repository; old versions stay orphaned under the old publish path forever. Consumers on a registry pin are
   unaffected; consumers on a **git pin are not** — a pin like `git: "...monorepo...", tag: "ts-v0.1.0"` keeps
   resolving against the old repository and goes silently stale. On a cryptographic verification library, staleness is
   a security property, not a convenience one.
2. **Published provenance is part of the contract.** [ADR 0008](0008-release-candidate-contract.md) and
   [`release-candidate-contract.md`](../release-candidate-contract.md) bind verifiability to a specific repository +
   workflow via `gh attestation verify --repo ... --signer-workflow ...`. Move the repository and the attestation
   source changes: old versions attest under repository A, new under repository B. For a library whose pitch is
   "you can independently verify this," a broken provenance chain is not cosmetic.

Together these invert the reversibility assumption ADR 0014's monorepo relies on. Before publication, monorepo
placement is cheap to change; **after publication, it is not.** The decision boundary is therefore the moment of
first publication, not a count of SDKs. (An earlier analysis of this question framed the boundary as "decide at ~4
active SDKs." That framing was wrong: it used a count where the load-bearing variable is irreversibility. This ADR
records the corrected boundary.)

## Decision

1. **Two-phase model — monorepo for authoring, per-SDK repo for publishing.** A SDK is authored under `sdks/<lang>/`
   in this repository (ADR 0014) while unpublished. On first publication it **graduates** to its own repository,
   `bounded_authority_protocol_<lang>` (for example `bounded_authority_protocol_rust`,
   `bounded_authority_protocol_go`). The monorepo is the authoring surface; the per-SDK repository is the publish
   surface. The graduation is a deliberate, recorded step — never an accident of someone running a publish command
   from the monorepo.

2. **Graduation is per-SDK, not all-at-once.** The trigger is *that SDK's first publication*, not a global threshold.
   TypeScript's and Python's graduation windows are open today (neither is published); each closes the moment that
   SDK publishes. A SDK may remain in the monorepo indefinitely if it is never published; graduation is gated on
   publication, not on time or on the existence of other graduated SDKs.

3. **Graduation carries the corpus-binding discipline unchanged.** A graduated SDK keeps its vendored corpus snapshot
   and its startup `index.json` SHA-256 assertion (ADR 0014 Decision 4). This is the property that makes the move
   mechanical rather than a re-architecture: no SDK depends on a sibling, on a monorepo-relative path, or on the
   Elixir reference. The graduation step is `git filter-repo` (or an equivalent subtree lift) plus the new repository's
   publish/release/provenance infrastructure; the SDK source and its corpus binding are identical before and after.

4. **Why per-SDK repositories for the publish surface, not a single SDK-org repo or the monorepo:**
   - **Independent release cadence.** A TypeScript bugfix bumps the TypeScript package and nothing else. No
     cross-language tag gymnastics, no "bump Python to keep its version monotonic with a release it did not participate
     in." Per-language version tags are the natural unit.
   - **Per-language CI done right.** Each repository runs its own optimal toolchain — pnpm+Vitest, cargo+tarpaulin,
     `go test`+golangci-lint — instead of a path-filtered job matrix in one workflow. The `sdks-conformance` job
   pattern (ADR 0014) generalizes to one self-contained CI per language.
   - **Isolated publish secrets.** The npm token lives in the TypeScript repository; the crates.io token in the Rust
     repository; the PyPI token in the Python repository. Blast radius is per language, not one monorepo holding every
     language's publish credentials.
   - **Clean issue and release history.** A language consumer's bug does not clutter the Elixir protocol tracker;
     release notes are per language.
   - **The monorepo's only real advantage — atomic cross-SDK corpus updates — is already neutralized** by ADR 0014's
     per-SDK vendored-snapshot + SHA-assertion design. Each SDK already carries its own corpus snapshot and asserts the
     SHA at startup; a corpus amendment is already a per-SDK snapshot bump, not a monorepo-relative import. Co-location
     is a convenience for the authoring phase, not a dependency the publish phase needs.

5. **No SDK publishes from the monorepo.** The graduation model is meaningless if a SDK can publish directly from
   `sdks/<lang>/`. ADR 0014's package manifests are authored ready-to-publish (so graduation is not blocked on
   manifest edits), but no publish action — `npm publish`, `twine upload`, `hatch publish`, `flit publish`,
   `uv publish`, registry-publish CI steps, `prepublishOnly`/`prepack` scripts, or `publishConfig` — is committed to
   this repository. This is enforced at two layers:
   - A **tracked local hook** (install via `scripts/install-hooks.sh`) gives fast contributor feedback: it rejects a
     commit that stages SDK publish infrastructure in a manifest or workflow.
   - A **CI job** on `main` is the non-bypassable backstop: it fails a push or pull request that introduces the same
     publish infrastructure.
   Both layers guard against *publish infrastructure being committed* — the enabling change. **Honesty limit, stated
   plainly:** neither layer can catch a literal ad-hoc publish command typed at a terminal against a working tree; that
   is a runtime act no commit gate sees. CI on `main` is the hard gate for committed infrastructure; the local hook is
   honor-system for contributors. The deliberate-admin bypass is `git commit --no-verify`, documented in
   `CONTRIBUTING.md`. This matches the forge skill's honesty boundary for hooks: a gate the
   agent's own process runs is a claim; a non-bypassable check on a machine it does not control is the proof.

6. **Standalone versioned corpus artifact — deferred, not decided here.** At two SDKs, per-SDK
   vendoring (ADR 0014 Decision 4) suffices and the bump amplitude is small. As the number of SDKs grows, a standalone versioned corpus
   release — SDKs fetch a versioned corpus artifact rather than each vendoring a copy — reduces the per-SDK bump
   amplitude and becomes the cleaner distribution model. This is recorded as a known follow-up; it is not decided or
   built in this ADR. A future ADR will settle it when a third SDK is in flight, on the evidence of the bump amplitude
   at that point.

## Alternatives considered

- **Stay monorepo forever; publish each SDK from `sdks/<lang>/`.** Rejected. The publish-topology friction is real
  (cross-language version tags, one workflow holding every language's publish credentials, a cluttered issue tracker),
  and registry-publication irreversibility makes the topology sticky once any SDK publishes. The monorepo is the right
  call for the authoring phase and the wrong call for the publish phase; this ADR separates the two rather than forcing
  one answer across both.

- **A single `bounded_authority_sdks` organization repository holding all SDKs.** Rejected in favor of per-SDK
  repositories. An org repo holding every language gains little over the monorepo (it still has cross-language tag
  friction and shared publish-credential surface) while losing the per-SDK benefits of independent cadence, isolated
  secrets, and clean release history. The per-SDK vendored-snapshot + SHA-assertion design (ADR 0014 Decision 4) means
  the SDKs do not need to be co-located to stay in sync with the corpus, so the one thing an org repo would buy —
  co-location — is not needed at the publish phase.

- **Decide the split at ~4 active SDKs (a count threshold).** Rejected. This was the framing an earlier analysis of
  this question reached, and it is wrong for the reason stated in Context: the load-bearing variable is
  irreversibility, not count. A single published SDK has already crossed the irreversibility line; the count of
  unpublished SDKs in the monorepo is irrelevant to it. Per-SDK graduation (Decision 2) replaces the count threshold.

- **Graduate all SDKs together on the first one's publication.** Rejected. Graduation is per-SDK because publication
  is per-SDK. Forcing a SDK that has no reason to publish yet to graduate because a sibling published adds
  release infrastructure and a repository move for no benefit. Each SDK graduates on its own publication trigger.

## Consequences

- [ADR 0014](0014-cross-language-verifier-sdks.md)'s monorepo decision stands **unchanged for the authoring phase**;
  this ADR governs the publish phase. Nothing in ADR 0014 is superseded or overturned. The two ADRs are complementary:
  ADR 0014 says *where SDKs are built*; this ADR says *where they are published*.
- TypeScript and Python (BAP-09) may remain under `sdks/` until they publish; Rust (BAP-15) and Go (BAP-16), when
  authored, follow the same authoring-under-`sdks/`-then-graduate path.
- The enforcement layer in Decision 5 is part of this decision and lands with it: the local hook, the CI job, and the
  contributor documentation that names the deliberate-admin bypass.
- A graduated SDK inherits the SemVer and provenance discipline of [ADR 0008](0008-release-candidate-contract.md):
  registry versions follow SemVer, attestation binds to the graduated repository's publish workflow, and the
  candidate-evidence recipe applies per language.
- The standalone-corpus-artifact question (Decision 6) is a known follow-up for a future ADR, not a defect in this one.
- This ADR records a corrected boundary (publication irreversibility, not SDK count). The earlier "decide at ~4 SDKs"
  framing is withdrawn here explicitly so it does not survive as latent advice.
