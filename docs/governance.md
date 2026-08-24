# Governance policy

This document publishes the governance policy whose authoritative source is the
[standards track charter](design/standards-track.md) § Governance; in any conflict, the charter
governs. It is a companion republication: the policy is settled (decided in
[ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) §7 and stated in
the charter § Governance), published here as a standalone normative project document so adopters
read it directly.

The bulk of each section below is verbatim from the charter § Governance
([standards-track.md](design/standards-track.md) § Governance). Four kinds of departure are
unavoidable when the text is lifted out of its charter context, and are LABELED as such — never
disguised as verbatim:

1. **Deictic resolution** — the charter's "see below" is resolved to an explicit link (the referent
   only follows physically inside the charter).
2. **Intro rationale carried** — the charter § Governance opening rationale is carried here as this
   document's own opening.
3. **Cross-source composite** (§ Errata channel) — the charter splits one policy fact across
   § Governance and the evolution contract; this section stitches them and cites both.
4. **Facts vs. identifiers** (§ Deprecation policy) — the deprecation window NUMBERS are carried
   here as policy facts, while the authoritative prose and conformance-traced `REQ1-EVO-*`
   requirement identifiers stay cross-referenced to the evolution contract (single-sourced).

## Why governance is published now

Published now, while the project is single-maintainer, because publishing the policy is the
credibility step and the policy is what makes single-maintainer tolerable to adopters
([standards-track.md](design/standards-track.md) § Governance, opening rationale — carried verbatim;
departure 2).

## Change classes

Editorial (errata; never verdict-changing) · clarifying (minor version; additive docs/cases only) ·
wire or verification behavior (contract-major only, with a public ADR).
([standards-track.md](design/standards-track.md):201-203, verbatim.)

## Change control

Every product-shaping decision lands as a numbered public ADR. Once at least two independent
external implementations pass the conformance corpus, contract-major ADRs gain a published comment
window of no fewer than thirty days and a change-control group with implementer representation. The
hand-off criterion to a formal standards body is adoption, not ceremony: when a venue (see the
charter § [Venue strategy](design/standards-track.md#venue-strategy)) accepts the work, that venue's
process supersedes this one.
([standards-track.md](design/standards-track.md):204-208, verbatim except for departure 1 — the
charter's "see below" is resolved to an explicit link to the charter § Venue strategy.)

## Errata channel

[docs/errata.md](errata.md) is the numbered errata registry; each entry names affected versions and
its corpus impact, and the no-verdict-flip invariant is checked at review
([standards-track.md](design/standards-track.md):209-211, the charter § Governance errata bullet,
verbatim). **No erratum may flip a corpus verdict** — any change that would alter an accept/reject
outcome is by definition a contract-major change and follows the evolution contract, never this
registry (the no-verdict-flip invariant, stated in the evolution contract as
`REQ1-EVO-no-verdict-flip`, [standards-track.md](design/standards-track.md):66-69).
*(This section is a composite — departure 3: the charter splits the errata fact across § Governance
:207-209, the registry + "checked at review," and the evolution contract :64-67, the "any change…
contract-major" gloss. Both sources are cited.)*

## Deprecation policy

A contract-major enters deprecation only after its successor has a published normative profile, a
published conformance corpus, and **at least two independent implementations passing that corpus**.
The deprecation window is published at announcement and is **never shorter than twelve months**,
except for a security contract-major (§ Security policy below); during the window, conforming
verifier deployments support both majors in parallel. Sunset of a major is a deployment decision
after the published window, never a silent library change.
([standards-track.md](design/standards-track.md):56-65 — the window numbers are policy FACTS, carried
here per departure 4.) The authoritative deprecation prose and the conformance-traced requirement
identifiers (`REQ1-EVO-deprecation-prerequisites`, `-window-minimum`,
`-parallel-support-during-window`, `-sunset-is-deployment-decision`) live in the charter § evolution
contract ([standards-track.md](design/standards-track.md) § Parallel-version support and
deprecation, :52-69) and are not duplicated here; the charter explicitly names that text "the
authoritative one" for deprecation ([standards-track.md](design/standards-track.md):213).

## Security policy

[SECURITY.md](../SECURITY.md) governs vulnerability intake; a vulnerability whose fix would change a
verdict is handled as a contract-major security release with an accelerated overlap window —
published at announcement and set proportional to the vulnerability's severity, exempt from the
twelve-month deprecation minimum (charter § [The evolution contract](design/standards-track.md#the-evolution-contract)),
yet still a published, deployment-decided sunset, not a flag-day — never as a silent verdict change.
([standards-track.md](design/standards-track.md):214-218, the charter § Governance security-policy
bullet, verbatim except the deictic "above (§ The evolution contract)" resolved to a cross-doc link
— departure 1.)
[SECURITY.md](../SECURITY.md) cross-references this section (rather than restating the rule) so the
verdict-change rule lives in one place.

## Errata registry posture

The errata registry at [docs/errata.md](errata.md) is **live** — it is the operational
no-verdict-flip governance instrument, with a numbered entry and per-entry corpus impact. It
currently carries Erratum 1, the correction for the v1 `all` selector's three recognized member
sets (ADR 0021). New errata follow the § Errata channel no-verdict-flip process above. *(This
statement is this document's own framing of the registry's operational posture, not a charter
extract — labeled as such.)*
