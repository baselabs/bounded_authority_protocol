# ADR 0011: Published governance

- Status: accepted
- Date: 2026-08-06
- Track: T2

## Context

[ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §7 decided that the
protocol's governance is published:

> Change classes (editorial/clarifying/contract-major), public ADRs for every product-shaping
> decision, a thirty-day comment window plus implementer change-control group once two external
> implementations exist, the numbered errata registry, and the verdict-flip prohibition as a
> governance invariant.

The policy substance lives in the [standards track charter](../design/standards-track.md) §
Governance. ROADMAP row BAP-13 carries that decision to a standalone normative project document so
adopters read the policy directly, with the charter remaining its authoritative source. This is the
same split as [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md)
(ADR 0006 §2 → mechanism) and [ADR 0010](0010-delegation-with-attenuation.md) (ADR 0006 §5 →
mechanism): ADR 0006 §7 stays the decision; this ADR records the publication execution.

## Decision

1. **`docs/governance.md` is a companion republication; the charter § Governance stays
   authoritative.** The charter preamble names itself "the standing authority for standards-track
   decisions" and enumerates governance among the postures it "defines"
   ([standards-track.md](../design/standards-track.md):7,13-14). That authority is not relocated.
   `docs/governance.md` carries the policy verbatim (with four labeled departures — deictic
   resolution, intro rationale, the § Errata channel cross-source composite, and the § Deprecation
   policy facts-vs-identifiers split) and names the charter as its source; in any conflict, the
   charter governs. The charter § Governance gains an in-place forward-ref to governance.md, exactly
   as § Evidence longevity forward-refs [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md)
   and § Delegation forward-refs [ADR 0010](0010-delegation-with-attenuation.md). (An earlier draft
   stubbed the charter § Governance and made governance.md the single source of truth; that was
   rejected by the design-adversarial pass — relocating ratified charter authority without a
   ratifying ADR contradicts the charter's own standing-authority claim and has no precedent in
   BAP-11/BAP-14, which edited charter sections in place.)

2. **Controlled dual-copy of the general policy sections (Change classes, Change control), with a
   post-publication sync mechanism.** These sections are reproduced in governance.md AND stay in the
   charter § Governance. This is a CONTROLLED dual copy, distinguished from the forbidden dual
   copies (§ Deprecation policy, § Security policy) by a principle: the deprecation and
   security-release rules are SPECIAL-CASE — deprecation is conformance-traced under `REQ1-EVO-*`
   (a second copy would fork traced requirements), and the security-release rule is a single-place
   rule (a second copy in SECURITY.md is forbidden; SECURITY.md carries a one-line link). The
   general policy sections (change classes, change control) are GENERAL policy whose authority is
   the charter and whose governance.md copy is an explicitly-subordinate republication. The drift
   risk is real and is mitigated by a **post-publication sync mechanism**: the closeout fidelity
   check (diff governance.md's general sections against the charter § Governance) is re-run on
   every charter § Governance edit. This obligation rides with the charter section, recorded here.

3. **`SECURITY.md`, `docs/governance.md`, and `docs/design/standards-track.md` are added to
   `.forge/critical-surfaces`.** The manifest is not the strict-T2 code/wire set — AGENTS.md defines
   T2 as wire, cryptography, verification, canonicalization, and conformance, yet the manifest
   already carries `usage-rules.md`, `docs/design/threat-model.md`, and `docs/adr/**`, none of which
   is a wire/crypto surface. Its operative criterion is *shipped public-contract or normative docs
   whose silent drift is dangerous*; the `track: T2` trailer is the honor-system flag on any change
   touching a member, wire surface or not (every BAP-13 doc commit carries it). Under that criterion:
   SECURITY.md (vulnerability-reporting flow + verdict-change cross-ref; authored across BAP-04 and
   BAP-06 but never added — a retroactive gap close, latent since BAP-06); `docs/governance.md`
   (a published normative document carrying a controlled dual-copy of the charter § Governance whose
   *only* failure mode is silent drift — exactly what the manifest guards, and what decision 2's
   post-publication sync mechanism has no installed gate to catch); and `docs/design/standards-track.md`
   (the standing authority and the source of the published policy — editing it is what must trigger
   the sync mechanism, so leaving it unflagged is the load-bearing gap). An earlier draft excluded
   governance.md on strict-T2 grounds and did not add standards-track.md; that reasoning was
   inconsistent with the manifest's own membership and is corrected here. A residual
   manifest-completeness gap remains — `docs/design/registries.md`, `docs/design/requirement-map.md`,
   and `docs/release-candidate-contract.md` are shipped normative docs still absent — and is flagged
   for a dedicated manifest audit rather than resolved in this publish-verbatim slice.

4. **The SECURITY.md verdict-change cross-reference is a one-line LINK, not a restated rule.** The
   verdict-change rule lives in ONE place (governance.md § Security policy, as the verbatim
   republication of the charter § Governance security-policy bullet). SECURITY.md points to it,
   symmetric with how governance.md § Deprecation policy cross-references (not duplicates) the
   evolution contract.

## Alternatives considered

- **Stub the charter § Governance and make governance.md the single source of truth.** Rejected
  (design-adversarial, blocking): the charter preamble ([standards-track.md](../design/standards-track.md):7,13-14)
  names itself the standing authority and enumerates governance; relocating that authority without a
  ratifying ADR contradicts it. No prior slice relocated charter authority — BAP-11/BAP-14 edited
  charter sections in place and added ADRs alongside.
- **Restate the verdict-change rule in SECURITY.md.** Rejected (design-adversarial): a second copy
  of a single-place rule is the drift hazard the design's no-dual-copy discipline exists to prevent;
  asymmetric with the deprecation cross-ref. SECURITY.md carries a one-line link.
- **Exclude `docs/governance.md` from `.forge/critical-surfaces` on strict-T2 grounds.** Rejected:
  the manifest is not the strict-T2 set — it already carries `usage-rules.md` and
  `docs/design/threat-model.md`, neither a wire/crypto surface — so "not a wire surface" does not
  exclude. A published normative doc with a controlled dual-copy whose only failure mode is silent
  drift is exactly what the manifest exists to flag; excluding it while including SECURITY.md applies
  two different criteria to reach opposite results. The same criterion adds the standing-authority
  charter `docs/design/standards-track.md`, whose absence is the load-bearing gap in the drift story.
- **Record the publication decision as a charter amendment rather than a new ADR.** Rejected: the
  charter's own change-control rule ("every product-shaping decision lands as a numbered public ADR",
  [standards-track.md](../design/standards-track.md):204-206) applies, and ADR 0006 spans many
  surfaces; amending it for one execution decision loses traceability.

## Consequences

- `docs/governance.md` is a published public contract; changes to it follow the very change-control
  policy it states (editorial errata vs. clarifying minor vs. contract-major). A changelog entry
  accompanies its publication.
- The charter § Governance remains the authoritative source; governance.md is its faithful
  companion republication. The post-publication sync mechanism (fidelity check re-run on charter §
  Governance edits) governs drift, recorded here.
- `SECURITY.md`, `docs/governance.md`, and `docs/design/standards-track.md` join
  `.forge/critical-surfaces` (SECURITY.md a retroactive gap close since BAP-06; standards-track.md a
  pre-existing gap for the standing authority); future edits to any of them carry `track: T2` under
  the manifest's honor-system regime (the commit hook is not installed in this repo). A
  manifest-completeness audit for the remaining shipped normative docs (`registries.md`,
  `requirement-map.md`, `release-candidate-contract.md`) is flagged as follow-up.
- No wire byte, bound, or verdict change. `git diff -- lib/ test/ priv/conformance/ mix.lock` is
  empty at closeout; the conformance corpus is unchanged at `agreed=259`.

## Amendment — 2026-09-03 (manifest relocation)

At commit `1448102` the tracked critical-surface declaration moved from
`.forge/critical-surfaces` to `.kimosabe/critical-surfaces` — the path the current kimosabe
guards read; nothing reads `.forge/`. This decision stands unchanged: the manifest content is
byte-identical, the honor-system `track: T2` regime is unchanged, and the follow-up audit named
above (manifest completeness for the remaining shipped normative docs) still rides with the
manifest wherever it lives. References to `.forge/critical-surfaces` elsewhere in this ADR are
historical (the path as it stood at decision time).
