# ADR 0030: v2 contract-major activation (`lte`/`gte` range selector kinds)

- Status: accepted (activation — the successor contract-major exists)
- Date: 2026-09-13
- Track: T2
- Activates: [ADR 0028](0028-range-selector-kinds.md) per the
  [successor-major charter](../design/successor-major-charter.md) activation checklist
- Implements: roadmap row BAP-21

## Context

ADR 0028 reserved `lte`/`gte` and specified their mechanism at ADR quality; the closed v1
profile rejects both names at every choke point (proven by the BAP-20 tripwires and the
executed surgical/crude mutations). The charter's activation checklist names five conditions;
this ADR records their satisfaction and the decisions the activating major owns.

## Decision

### 1. The successor contract-major is contract-major 2 (`v: 2`, `BAP2-Ed25519-SHA256`)

The v2 wire profile is the v1 profile with exactly the substitutions enumerated in
[`spec/bap-v2.md`](../../spec/bap-v2.md) §2: payload `v` = 2 everywhere `v` appears, the three
version-bound domain separators (`BAP2-REQUEST\0`, `BAP2-CHAIN\0`, `BAP2-ARCHIVE\0EXPORT\0`),
the suite name under the major-bound `BAP<contract-major>-<signature>-<digest>` scheme, facts
and decoded structs carrying `version: 2`, and the selector kind set extended by `lte`/`gte`.
Everything else — headers, typs, claims, bounds, algorithms, JCS, JWK, URI rules — is unchanged
and incorporated from the v1 normative text by reference.

Suite naming reconciliation: the registries' anticipated `BAP2-*` ML-DSA family row described
the first successor major generically, written before any successor existed; with major 2 now
taken by this activation at unchanged algorithms, the ML-DSA family's activation major index
shifts to the next successor (its row is relabeled accordingly). The suite SCHEME is
unchanged; only the anticipated index moves.

Cross-major: each major verifies under its own complete closed profile. The v2 verifier
rejects `v: 1` bytes at every payload decode; v1 rejects `v: 2` (its closed
`{:integer, 1}` checks — pinned by the v1 corpus's unchanged verdicts and the v1 closed-set
tests). No fallback, no downgrade, no mixed-major envelope. The local-loopback application
proof profile stays contract-major-1-bound; a v2 loopback variant is future work if wanted.

### 2. The Elixir surface

The `BoundedAuthorityProtocol.V2` namespace mirrors the v1 module set with the version-bound
modules re-authored (Runtime, Selector, RequestDigest, ConsumptionChain, BoundaryAnchorCodec,
KeyTransitionCodec, AnchoredExportCodec, the version-bearing structs and facts) while
single-sourcing the version-neutral algebra (Json, Jcs, Base64Url, Jwk, Uri, StringOrUri,
Bounds, FixedBytes, CompactJws, SigningInput, KeyLocator, and the carrier structs) from `V1`:
the no-verdict-flip rule means the shared implementations can never legitimately diverge, so a
duplicate would be an unreviewable drift hazard, not isolation. The v1 lib tree is
byte-unchanged (git diff over `lib/bounded_authority_protocol/v1*` and
`priv/conformance/v1` is empty; the v1 corpus index SHA remains the shipped pin).

### 3. The bounds review (ADR 0028 §4 obligation)

Inherited unchanged: every v1 bound carries over (`REQ2-BOUNDS-inherited`). The concrete review
found no new bound is required — a comparison consumes two decoder-bounded numbers and produces
a boolean; it derives no new magnitude (the structural argument ADR 0028 §4 records, in
contrast with ADR 0016 §2's multiplied-exposure ceiling).

### 4. The conformance corpus (checklist items 2–3)

`priv/conformance/v2/corpus` — 268 cases, 28 surfaces, 16 classes, revision 1, certified index
SHA-256 `6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0`
(base64url `beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A`), pinned in the verifier CLI
(major-keyed certification map), the CLI test, and all four SDK v2 runners
(`scripts/regen_corpus_digests.exs` rotates the twelve pins — six per major — as one change). Provenance mirrors
v1: fixtures minted with ephemeral in-memory Ed25519 keys, throwaway mint scripts, no private
material tracked; the committed generator (`conformance/generators/build_corpus.mjs --major 2`
over `curated-inputs-v2.json`) re-derives index, counts, applicability, and tamper audits
byte-identically.

Composition: the version-neutral primitive-surface cases are carried from the certified v1
corpus byte-for-byte (they execute the identical shared implementations); the profile-bound
surfaces carry v2-minted fixtures covering, per surface, a valid baseline plus the v1
rejection-class coverage (every applicability cell v1 populates is populated in v2), the full
range-selector class matrix — same-tag accept and reject, boundary-equal on both kinds and both
endpoints, cross-tag in both directions, non-numeric operand and non-numeric bound, missing
path, over-maxima, integer and float extremes at the closed numeric-domain edges, interval
conjunction, crossed endpoints, equals-still-enforced — and the cross-major rejections (v1
grant/proof/rows/anchor/transition/archive bytes under v2 verification). Signed-zero is NOT a
wire corpus case and cannot be one: RFC 8785 serializes −0.0 as `0`, so a zero-valued float
operand re-derives integer-tagged from the case bytes — the ADR 0028 §2 rationale ("signed zero
distinguishes no authority in either dimension") is demonstrated by the corpus's inability to
express the distinction; the matcher-level equality is unit-tested in both Elixir and every SDK.

Cross-implementation evidence (checklist item 3's analogue for this activation): the reference
implementation and all four independent SDKs (TypeScript, Python, Rust, Go) pass all 268 cases
against their own v2 reimplementations with the certified digest asserted at load, and the
byte-distinct report families (v1/v2 report format strings) keep the two corpora's evidence
separable. Corpus growth within major 2 (deeper per-surface matrices beyond the v1-populated
cells) is a named follow-up, legal under the revision-sidecar discipline without verdict
change.

### 5. Registries (checklist item 4)

`lte` and `gte` flip reserved → **active in the v2 closed profile** (the v1 profile continues
to reject both names — reservation discipline means "inactive until a major lists it", not
"retired"). The suite table gains `BAP2-Ed25519-SHA256` (active); the ML-DSA anticipated row's
index moves to the next successor major.

### 6. Requirement identities

The v2 profile carries `REQ2-*` ids (ADR 0007's successor range) with its own
MUST-to-cell rows in the [requirement map](../design/requirement-map.md) § v2, each mapped to
populated v2 corpus cells or a falsifiable reason, and each new gate's red proof recorded
there. `REQ1-*` ids stay bound to v1.

### 7. Deprecation posture (checklist item 5)

v1 is NOT deprecated by this activation. Per the governance deprecation policy, v1 enters
deprecation only after its successor has a published normative profile, a published corpus, and
at least two independent implementations passing that corpus — this landing provides the
profile and corpus in-tree; the published-package and external-implementation conditions are
release and adoption events, not code events, and remain owner decisions. Until then, v1
remains the published package profile and v2 is available in-tree and in the SDKs.

## Alternatives considered

- **Activating `lte`/`gte` inside v1.** Rejected: verdict flip
  (`REQ1-EVO-no-verdict-flip`); the entire reserve-and-activate program exists because of this.
- **A v2 corpus that mirrors all 283 v1 cases under v2 constants.** Rejected as the
  activation deliverable: the v1-minted fixtures' signing keys are destroyed, so every fixture
  would need re-minting from transcribed semantics with no gain where the executed code is the
  identical shared module. The chosen composition (byte-carried primitive cases + v2-minted
  profile-bound cases covering every v1-populated applicability cell + the range/cross-major
  matrices) gives every surface executed coverage in the v2 corpus's own certification. Depth
  growth is the follow-up above.
- **Duplicating the version-neutral modules into V2.** Rejected: the frozen-v1 discipline
  means duplicates could never legitimately diverge; duplication would double the
  security-critical parser surface under review without adding isolation (§2).
- **A v2 facts-extraction baseline (`spec.facts` extension).** Deferred with disclosure: the
  spec-facts drift gate remains v1-scoped this landing; the v2 spec's `facts:selector-kinds`
  region is carried as documentation, and v2 drift detection is carried by the corpus
  integrity + certified-pin + SDK census machinery. Extending the extractor with a v2 baseline
  is a named follow-up.

## Consequences

- The successor contract-major exists in-tree: Elixir reference, normative spec, certified
  corpus, CLI (verifies both corpora, major-keyed certification), four SDKs, requirement map,
  registries, changelog, and this ADR land together.
- v1 is byte-frozen and proven unchanged: `git diff` over the v1 lib/corpus/spec/SDK-v1 trees
  is empty for this landing, and the v1 certified pin (`TLUHKrQP…`) still verifies its corpus.
- Issuers can express per-request ranges on the wire for v2 audiences: "the argument at this
  path is ≤/≥ this value", intervals as two conjuncts, verified statelessly by every conforming
  v2 verifier. Cumulative budgets remain out of scope (ADR 0029 `ba+budget-window`, reserved).
- The durable-contract-identity scanner enumerates the accepted v2 families (namespace, paths,
  wire fields, domains, suite, `REQ2-*`); the next unaccepted major (V3/`BAP3-*`/`REQ3-*`)
  remains rejected exactly as V2 was before this ADR.
- Named follow-ups: v2 corpus depth growth; the `spec.facts` v2 baseline; ADR 0029
  `ba+budget-window`; the remaining charter successor-major scope (delegation, offline claims,
  suite succession) as separately activated majors; SDK publication and any v2 Hex release are
  owner decisions outside this landing.

## See also

- [ADR 0028](0028-range-selector-kinds.md) — the mechanism this ADR activates.
- [ADR 0007](0007-normative-requirement-identifiers.md) — the `REQ2-*` range.
- [ADR 0022](0022-durable-contract-identities.md) — the identity scanner this activation
  enumerates v2 into.
- [successor-major charter](../design/successor-major-charter.md) — the activation checklist.
- [governance](../governance.md) — change classes and the deprecation policy §7 cites.
- [`spec/bap-v2.md`](../../spec/bap-v2.md) — the normative v2 profile.
