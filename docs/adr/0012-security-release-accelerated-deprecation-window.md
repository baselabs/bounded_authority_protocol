# ADR 0012: Security-release accelerated deprecation window

- Status: accepted
- Date: 2026-08-06
- Track: T2
- Refines: [ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §1
  (deprecation overlap window) and the [standards track charter](../design/standards-track.md)
  § The evolution contract

## Context

The review of BAP-13 (published governance) surfaced a normative contradiction inside the charter's
own deprecation and security policy — republished verbatim into
[governance.md](../governance.md) and therefore now stated to adopters as normative policy:

- The evolution contract sets the deprecation window "never shorter than twelve months"
  (`REQ1-EVO-deprecation-window-minimum`) and requires that "during the window, conforming verifier
  deployments support both majors in parallel" (`REQ1-EVO-parallel-support-during-window`),
  [standards-track.md](../design/standards-track.md) § The evolution contract.
- The § Governance security-policy bullet says a verdict-changing vulnerability is "handled as a
  contract-major security release with an **accelerated overlap window**"
  ([standards-track.md](../design/standards-track.md) § Governance).

These collide. Under the closed-per-major posture — each accepted major "is verified under its own
complete closed profile," with "no cross-major fallback, no downgrade path"
(`REQ1-EVO-no-downgrade`) — the vulnerable major keeps producing its (now-known-insecure) verdict
for the whole time deployments must support it. An absolute twelve-month floor therefore forces
deployments to keep accepting a vulnerable major for up to a year, while the security bullet's word
"accelerated" plainly signals the charter *intended* a shorter window for security. The floor and
the security bullet were never reconciled; BAP-13 faithfully republished both, which is correct for
a publish-verbatim slice but leaves the published policy self-contradictory.

The deprecation window is deployment-lifecycle policy, not verifier behavior: the four
`REQ1-EVO-*` deprecation requirements are all traced `gap` in the requirement map with an
input-algebra-impossibility reason ("the v1 corpus input algebra has no temporal/policy axis,"
[requirement-map.md](../design/requirement-map.md)). The pure, stateless v1 verifier has no
wall-clock input, so no corpus case turns on a window duration. Resolving the contradiction thus
changes no byte, bound, or verdict, and leaves the conformance corpus untouched.

## Decision

1. **The twelve-month deprecation-window minimum is scoped to planned deprecations; a security
   contract-major is exempt.** A security contract-major — one that remediates a verdict-changing
   vulnerability — may publish an overlap window shorter than twelve months. That window is still
   **published at announcement**, set **proportional to the vulnerability's severity**, and its
   sunset remains a **deployment decision, never a silent library change**
   (`REQ1-EVO-sunset-is-deployment-decision`). The exemption narrows the minimum *duration* only;
   the closed-per-major (`REQ1-EVO-no-downgrade`), no-mixed-major (`REQ1-EVO-mixed-major-invalid`),
   published, and no-silent-change guarantees are unchanged. This makes the security bullet's
   "accelerated overlap window" coherent with the deprecation-window rule.

2. **The authoritative home of the accelerated-window rule stays the charter § Governance
   security-policy bullet; the § evolution contract window-minimum bullet cross-references it.** That
   bullet already carried the "accelerated overlap window" language, so the fix strengthens it in
   place rather than relocating it. `governance.md` re-syncs both sections; the requirement map's
   one-line restatement of `REQ1-EVO-deprecation-window-minimum` is clarified to note the exemption.

3. **No new `REQ1-EVO-*` identifier is minted (deliberate, and reversible additively).** The
   security-handling rule already lives in § Governance *without* a traced `REQ1-EVO-*` id — it is a
   governance-section rule, not an item in the evolution contract's requirement list. Keeping it
   there is consistent with the existing structure and avoids churning the closed BAP-10
   acceptance-artifact counts (`requirement-map.md`: 86 requirement ids, 10 `REQ1-EVO-*`). If the
   maintainer later wants the accelerated-window rule in the traced requirement list, it slots in
   additively as `REQ1-EVO-<tag>` per [ADR 0007](0007-normative-requirement-identifiers.md)
   ("an erratum adding a requirement within major 1 slots in … without renumbering") with a `gap`
   requirement-map row — no renumbering, no verdict change.

4. **This is a governance-policy refinement, not a wire contract-major.** The deprecation window is
   `gap`-traced deployment policy; nothing here alters a byte, bound, or verdict, and the conformance
   corpus is unaffected (`git diff -- lib/ test/ priv/conformance/ mix.lock` stays empty).

## Alternatives considered

- **Keep the twelve-month floor absolute; document continued vulnerable-major acceptance as a
  deployment-owned residual risk.** Rejected: it forces up to a year of accepting a major known to
  produce an insecure verdict — the security hole itself — and contradicts the charter's own
  "accelerated overlap window" commitment rather than reconciling it.
- **Mint a `REQ1-EVO-security-release-accelerated-window` identifier and requirement-map row now.**
  Considered, not taken here (see Decision 3): the security-handling rule already lives untraced in
  § Governance, so adding an id in this change would be inconsistent until a broader traceability
  pass and would disturb the closed BAP-10 acceptance-artifact counts. It remains available as a
  purely additive follow-up per ADR 0007.
- **Treat the security release as a contract-major with no overlap window (instant flag-day).**
  Rejected: it violates `REQ1-EVO-sunset-is-deployment-decision` and the no-silent-change posture.
  Even a security sunset is published and deployment-decided; the exemption removes only the duration
  floor, not the publication and deployment-decision guarantees.
- **Amend ADR 0006 §1 in place rather than record a new ADR.** Rejected: the charter's own
  change-control rule routes every product-shaping decision to a numbered public ADR
  ([standards-track.md](../design/standards-track.md) § Governance), and the repo's convention is to
  refine an earlier ADR with a later one, not rewrite its body (as [ADR 0007](0007-normative-requirement-identifiers.md)
  refined ADR 0006 §3). ADR 0006 §1 and ADR 0007's "at least twelve months" context lines stay as
  historical records; this ADR and the charter (the standing authority) carry the current rule.

## Consequences

- The charter § The evolution contract (window-minimum bullet) and § Governance (security-policy
  bullet) are amended; [governance.md](../governance.md) § Deprecation policy and § Security policy
  re-sync; [requirement-map.md](../design/requirement-map.md) restates
  `REQ1-EVO-deprecation-window-minimum` with the exemption. The published governance policy is no
  longer self-contradictory.
- No wire byte, bound, or verdict change; the deprecation window is `gap`-traced deployment policy
  and the conformance corpus is unchanged at `agreed=259`. The design-only invariant
  (`git diff -- lib/ test/ priv/conformance/ mix.lock` empty) holds.
- The accelerated-window rule remains untraced in the `REQ1-EVO-*` list by design (Decision 3); a
  future additive id is the flagged option if traceability is later wanted.
