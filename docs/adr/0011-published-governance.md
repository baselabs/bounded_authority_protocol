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

3. **`SECURITY.md` is added to `.forge/critical-surfaces`; `docs/governance.md` is NOT.** SECURITY.md
   carries the vulnerability-reporting flow and the verdict-change-handling cross-ref — a
   security-policy gap fails quietly, which is the manifest's purpose. SECURITY.md was authored
   across BAP-04 (supply-chain verification) and BAP-06 (the release-candidate contract it
   describes) but was never added to the manifest; this is a retroactive gap close, latent since
   BAP-06. `docs/governance.md` is NOT added: `.forge/critical-surfaces` is uniformly
   code/wire/charter/conformance surfaces, and a governance doc is not a T2 surface (the project
   defines T2 as wire formats, cryptography, verification, canonicalization, and conformance — none
   of which governance prose is). Adding governance.md would mislabel a non-T2 surface.

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
- **Add `docs/governance.md` to `.forge/critical-surfaces`.** Rejected (design-adversarial): a
  governance doc is not a T2 surface (T2 = wire/crypto/verification/canonicalization/conformance);
  the manifest has no standalone-policy-doc precedent. SECURITY.md qualifies on its own
  (public-contract security policy, retroactive gap).
- **Record the publication decision as a charter amendment rather than a new ADR.** Rejected: the
  charter's own change-control rule ("every product-shaping decision lands as a numbered public ADR",
  [standards-track.md](../design/standards-track.md):202-204) applies, and ADR 0006 spans many
  surfaces; amending it for one execution decision loses traceability.

## Consequences

- `docs/governance.md` is a published public contract; changes to it follow the very change-control
  policy it states (editorial errata vs. clarifying minor vs. contract-major). A changelog entry
  accompanies its publication.
- The charter § Governance remains the authoritative source; governance.md is its faithful
  companion republication. The post-publication sync mechanism (fidelity check re-run on charter §
  Governance edits) governs drift, recorded here.
- `SECURITY.md` joins `.forge/critical-surfaces` (retroactive gap close since BAP-06); future
  SECURITY.md edits carry `track: T2` under the manifest's honor-system regime (the commit hook is
  not installed in this repo).
- No wire byte, bound, or verdict change. `git diff -- lib/ test/ priv/conformance/ mix.lock` is
  empty at closeout; the conformance corpus is unchanged at `agreed=259`.
