# ADR 0018: SDK bounds contract — caller-tightenable limits through the expected structs

- Status: accepted
- Date: 2026-08-17
- Track: T2
- Refines: [ADR 0014](0014-cross-language-verifier-sdks.md) (the SDK support surface whose bounds
  entry this ADR specifies — 0014 mentions `Bounds.maximum`/`Bounds.new` only in passing),
  [ADR 0002](0002-normative-v1-parsing-profile.md) (the bounded-decoder origin of the profile
  bounds), [ADR 0017](0017-inter-sdk-behavioral-contract.md) (the behavioral contract these gates
  feed)

## Context

The Elixir reference threads caller-tightenable limits everywhere a ceiling applies: caller context
arrives as `expected` structs whose optional bounds are resolved once (`Bounds.coerce`) and applied
to every bound-sensitive check on the path. Until BAP-15, the SDKs' archive façades ran at profile
maximum only — a caller could not tighten below the maxima, silently diverging from the reference
contract for every consumer that verifies under constrained memory or untrusted-input budgets.

The parity landing (`b4ca616`, Rust) plus the sibling encode-path landings gave all three SDKs the
full contract, proven by 27 (Rust) + 15 + 15 (TS/Python) mutation-proven battery legs against the
Elixir oracle. The contract itself was recorded only in ROADMAP amendment #2; [ADR
0014](0014-cross-language-verifier-sdks.md) names `Bounds.maximum`/`Bounds.new` as versioned
primitives without specifying the threading semantics. This ADR is the contract of record.

## Decision

1. **Additive optional bounds on the expected structs.** Each archive/chain expected struct carries
   an optional bounds field — Rust: `Option<Bounds>` on `ExpectedChain`, `ExpectedAnchor`,
   `ExpectedKeyTransition`, `ExpectedExport`, `ExpectedAnchoredExport`
   (`sdks/rust/src/types.rs`); TypeScript: `bounds?: Bounds` on the corresponding expected types;
   Python: `bounds: Bounds | None = None`. **Absent means the profile maximum** — the additive
   default preserves every existing call; a present value may only tighten below the profile
   maxima ([ADR 0002](0002-normative-v1-parsing-profile.md)'s tightening-only discipline — a caller
   can never loosen above them).

2. **Nested-pins identity semantics.** Where an expected struct nests another expected struct
   (an anchored export carrying an expected chain, anchors, and transitions), a present nested
   bounds must coerce-equal the outer bounds; an absent nested bounds is valid only under an
   effectively-untightened outer. **An identity override is NOT tightening** — supplying the same
   value twice does not create a second, independently-checkable limit. The reference's resolution
   order is mirrored exactly; the identity rule exists so that a tightened outer cannot be silently
   satisfied by a nested structure that re-asserts the maximum.

3. **One resolved bounds, threaded through every ceiling.** The resolved bounds apply at every
   bound-sensitive check on BOTH the encode and verify paths, and on the standalone chain / anchor /
   transition entries — including the chunk-count pin (the archive chunk count is bounded by the
   resolved bounds, not just the wire size). A bounds field that is accepted but not threaded into
   some ceiling is a contract breach even when the unthreaded ceiling coincides with the maximum:
   the contract is the threading, not the value.

4. **Named open divergence — `assemble_compact` stays at maximum in all three SDKs.** The Elixir
   reference threads caller limits through `assemble_compact` (`runtime.ex:147-151`: `Bounds.coerce`
   → `CompactJws.assemble` → `validate_assembled_compact`); the SDKs' `assemble_compact` equivalents
   run at profile maximum only. This is a disclosed divergence awaiting maintainer direction —
   closing it is a public-API change per SDK (a new parameter on an existing function), its own
   slice, not a silent widening. The Go SDK (BAP-16) picks the full contract — including the
   question this divergence leaves open — up at authoring.

## Alternatives considered

- **Maximum-only SDKs (the pre-BAP-15 state).** Rejected: every consumer verifying untrusted input
  under a memory budget gets no lever, and the SDK silently diverges from the reference contract.
- **Required bounds fields.** Rejected: breaks the additive default for every existing caller and
  forces ceremony (`bounds: Bounds.maximum()`) on the common path; optionality-with-maximum-default
  matches the reference's optional expected-side limits.
- **Verifier-side-only threading (encode stays at maximum).** Rejected: the encode paths build the
  very archives the verify paths check; a producer that can exceed a consumer's tightened bounds
  defeats the point of tightening. The parity landing threaded both sides deliberately.

## Consequences

- A caller tightening via the expected structs now gets enforcement at every ceiling in all three
  SDKs — parity with the reference on the archive façades, proven mutation-red per SDK.
- The `assemble_compact` divergence is the single named exception; it is tracked as the ROADMAP
  BAP-15 amendment #2 residual and in [ADR 0017](0017-inter-sdk-behavioral-contract.md)'s successor
  scope, and closes only on maintainer direction.
- The Go SDK (BAP-16) implements this contract at authoring; its acceptance bar cites this ADR
  alongside ADR 0014/0017.
