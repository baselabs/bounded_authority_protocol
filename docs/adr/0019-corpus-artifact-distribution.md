# ADR 0019: Corpus artifact distribution — per-SDK binding until first graduation

- Status: accepted
- Date: 2026-08-17
- Track: T2
- Refines: [ADR 0015](0015-sdk-graduation-and-publish-topology.md) Decision 6 (the deferred
  corpus-artifact question this ADR settles), [ADR 0014](0014-cross-language-verifier-sdks.md)
  Decision 4 (the per-SDK corpus binding this ADR keeps), [ADR 0005](0005-portable-conformance-corpus-and-verifier-cli.md)
  (the corpus itself)

## Context

[ADR 0015](0015-sdk-graduation-and-publish-topology.md) Decision 6 deferred the standalone
versioned corpus artifact — SDKs fetching a versioned corpus release instead of each carrying a
binding — with a promised re-evaluation "when a third SDK is in flight, on the evidence of the bump
amplitude at that point." The trigger's first half has fired: the third SDK (Rust, BAP-15) is
complete. This ADR reads the bump-amplitude evidence and decides.

**The evidence, traced at commit level (2026-08-17).** The corpus grew 259 → 283 across four
landings (`0719387` → 280, `52a927a` rework → 279, `584f539` → 280 — all 2026-08-11 — and
`696384c` → 283, 2026-08-12). Each landing coordinated, in one atomic commit: the corpus itself,
the certified index-SHA constants in the TypeScript and Python runners, the SDK READMEs' case
counts, and the CI matrix — a **two-SDK amplitude, observed four times**. The Rust SDK did not
exist for those bumps;
it vendored the post-bump 283-case snapshot once, at its own authoring (`66d5ebb`), as a
self-contained `sdks/rust/conformance/corpus/` copy. So: **no corpus amendment has yet been paid at
three SDKs.** The current per-SDK cost is also asymmetric — Rust vendors a snapshot (~a full corpus
copy), while TypeScript and Python consume the monorepo corpus in place with a startup SHA
assertion (the in-place pattern ADR 0014 D4 names as the dev-mode binding).

The projection at three monorepo SDKs is linear: one more SHA constant in one more runner plus (for
Rust) one snapshot re-copy, all still inside a single atomic landing in a single repository.

## Decision

**Keep per-SDK corpus binding; the standalone versioned corpus artifact stays deferred — and the
re-evaluation trigger moves from "a third SDK in flight" to "the first SDK graduation."**

1. **The amplitude evidence does not justify the artifact while the monorepo makes coordination
   atomic.** A corpus amendment today is one commit that carries corpus + every SDK's certified SHA
   + docs together; there is no drift window and no cross-repository release lockstep. Adding the
   third SDK's constant to that commit is the projected — and only remaining — cost.
2. **A standalone versioned corpus artifact is distribution infrastructure.** It needs a versioned
   home, a release process, and consumers who cannot simply read the monorepo. Building it before
   any SDK has graduated would put publish-shaped infrastructure into the monorepo that
   [ADR 0015](0015-sdk-graduation-and-publish-topology.md) Decision 5 and the `sdk-publish-guard`
   hook + CI job exist to keep out, or would create a new repository before any published consumer
   exists.
3. **First graduation is the honest trigger.** When the first SDK graduates to its own repository, a
   corpus amendment stops being one atomic landing: the graduated repository must re-vendor or
   re-pin in release lockstep with the monorepo, across two provenance chains. That — not SDK
   count — is when the amplitude evidence must be re-read, per graduation, and when a versioned
   artifact has its first consumer who genuinely cannot consume the monorepo in place.

When that trigger fires, the open question is the artifact's home and versioning (a tagged release
in this repository consumed cross-repo, versus a dedicated corpus repository), to be decided on the
graduation-time evidence of at least one paid cross-repo bump.

## Alternatives considered

- **Build the standalone artifact now (the literal reading of ADR 0015 D6's trigger).** Rejected:
   the trigger fired on its "third SDK in flight" clause, but the evidence it was framed to read —
   bump amplitude at three SDKs — does not exist yet (no three-SDK bump has been paid), and the
   artifact would be publish-shaped infrastructure with zero published consumers.
- **Decide the artifact is never needed.** Rejected: the graduation-time coordination cost is real
   and projected above; "never" is a prediction this ADR has no evidence to make.
- **All three SDKs vendor snapshots (symmetrize the binding).** Rejected for now: the in-place
   monorepo binding is ADR 0014 D4's documented dev-mode pattern, and Rust's snapshot exists for
   its self-contained-SDK posture, not as a distribution requirement. Symmetrizing would triple the
   copy cost inside the very repository that already holds the corpus.

## Consequences

- ADR 0015 Decision 6's deferred question is settled for the authoring phase: per-SDK binding, with
  the re-evaluation trigger re-anchored to first graduation (this ADR supersedes that Decision's
  trigger framing; nothing else in ADR 0015 changes).
- The next corpus amendment inside the monorepo updates all three SDKs' certified SHAs (and the
  Rust snapshot) in the same landing — the four-bump 259→283 arc is the template.
- The Go SDK (BAP-16), when authored, binds the same way: certified index SHA asserted at startup,
  snapshot or in-place per its own posture.
