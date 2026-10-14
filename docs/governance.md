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

Editorial (errata; never verdict-changing) · soundness repair (an erratum that changes verdicts
only from accept to reject on producer-impossible inputs, under every condition of
[ADR 0040](adr/0040-strict-ed25519-soundness-erratum.md) Decision 4) · clarifying (minor version;
additive docs/cases only) ·
byte-distinct sibling proof profile (breaking pre-1.0 package release, public ADR, independent
normative/corpus/API identity) · byte-distinct sibling attestation profile (same release/ADR/identity
shape, under its own class conditions) · existing-profile wire or verification behavior
(contract-major only, with a public ADR).
([standards-track.md](design/standards-track.md) § Governance; amended by
[ADR 0027](adr/0027-byte-distinct-application-proof-profiles.md),
[ADR 0036](adr/0036-role-attestation-profile.md), and
[ADR 0040](adr/0040-strict-ed25519-soundness-erratum.md).)

## Soundness repairs

A soundness repair corrects an existing profile's verdicts on inputs that no conforming producer
emits, where keeping the old verdict would leave a forgery or an equivalent soundness failure
conforming. It is allowed only when all of the following hold:

1. every changed verdict goes from accept to reject;
2. the newly rejected inputs are proven producer-impossible;
3. no verdict of any existing certified corpus changes, proven by running the reference and the
   independent runners over every existing corpus;
4. the new cases land in a new additive corpus with its own certified identity;
5. every maintained SDK and the independent runners ship the repair in the same release window;
6. disclosure follows the order: private advisory, then publication of the fixed releases, then
   the public advisory.

A soundness repair is not a sunset: the major continues, and it keeps no overlap window during
which the vulnerable verdict remains conforming. Releases before the repair are retired on the
package registry. A change that fails any condition remains contract-major work. The decision,
its split justification, and the first instance are in
[ADR 0040](adr/0040-strict-ed25519-soundness-erratum.md).

## Byte-distinct sibling proof profiles

A sibling proof profile is permitted only when a new signed protected `typ` gives its artifacts a
machine-visible identity, every existing profile rejects those bytes, and no byte accepted by an
existing profile changes meaning or verdict. It has its own public namespace, normative
specification, stable requirement namespace, conformance corpus identity, registry entry, and
independent implementations. Every shipped SDK implements its relevant verification surface before
release. Its first publication is a breaking pre-1.0 package release (`0.x.0`) with immutable source,
package, corpus, and real-substrate evidence.

This class does not create an open extension mechanism: there is no runtime profile registry,
negotiation, inference, fallback, or best-effort parsing. Every future sibling is another numbered
public ADR and closed corpus. Any change to an existing profile's accepted bytes, claims, algorithms,
bounds, suite, or verdicts remains contract-major work. The complete decision and rejection tests
are in [ADR 0027](adr/0027-byte-distinct-application-proof-profiles.md).

## Byte-distinct sibling attestation profiles

A sibling attestation profile is the second sibling class
([ADR 0036](adr/0036-role-attestation-profile.md)), permitted only when its artifact carries a new
signed protected `typ`, is standalone and grant-unbound (parsed by no existing profile's verification
path, verified only through its own named API), cross-rejects every existing profile by corpus leg in
both directions, and changes no byte, bound, or verdict anywhere. It has its own public namespace,
normative specification, profile-scoped requirement range, conformance corpus identity, and registry
entry; it single-sources the shared primitives of the contract-major it binds; every shipped SDK
implements its verification surface before any release bearing it; its first publication is a
breaking pre-1.0 package release (`0.x.0`) with immutable source, package, corpus, and the
ADR-0036 release-evidence conditions. No runtime registry, negotiation, inference, fallback, or
plugin mechanism exists. The charter's reserve-and-activate-in-a-major discipline for attestation
shapes governs verifier-integration-bound artifacts; a consumer-gated artifact no major verifier
ingests takes this class. The complete decision, the class conditions, and the rejection tests are
in [ADR 0036](adr/0036-role-attestation-profile.md).

## Change control

Every product-shaping decision lands as a numbered public ADR. Once at least two independent
external implementations pass the conformance corpus, contract-major ADRs and sibling-profile ADRs
gain a published comment window of no fewer than thirty days and a change-control group with
implementer representation. The
hand-off criterion to a formal standards body is adoption, not ceremony: when a venue (see the
charter § [Venue strategy](design/standards-track.md#venue-strategy)) accepts the work, that venue's
process supersedes this one.
([standards-track.md](design/standards-track.md):204-208, verbatim except for departure 1 — the
charter's "see below" is resolved to an explicit link to the charter § Venue strategy; the
sibling-profile extension is [ADR 0036](adr/0036-role-attestation-profile.md) Decision 1.)

## Errata channel

[docs/errata.md](errata.md) is the numbered errata registry; each entry names affected versions and
its corpus impact, and the no-verdict-flip invariant is checked at review
([standards-track.md](design/standards-track.md):209-211, the charter § Governance errata bullet,
verbatim). **No erratum may flip a verdict of an existing certified corpus** — any change that
would alter such an accept/reject outcome is by definition a contract-major change and follows the
evolution contract, never this registry. The one exception is a soundness repair
(§ Soundness repairs), which adds its cases in a new corpus, flips no existing corpus verdict, and
is recorded in this registry with its corpus impact. A sibling proof profile is not an erratum and cannot
reclassify an existing case (the no-verdict-flip invariant, stated in the evolution contract as
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
verdict and that does not meet every soundness-repair condition (§ Soundness repairs) is handled
as a contract-major security release with an accelerated overlap window —
published at announcement and set proportional to the vulnerability's severity, exempt from the
twelve-month deprecation minimum (charter § [The evolution contract](design/standards-track.md#the-evolution-contract)),
yet still a published, deployment-decided sunset, not a flag-day — never as a silent verdict change.
([standards-track.md](design/standards-track.md):214-218, the charter § Governance security-policy
bullet, verbatim except the deictic "above (§ The evolution contract)" resolved to a cross-doc link
— departure 1.)
A fix that meets every soundness-repair condition lands as an erratum with a security advisory,
in the same release across every implementation; [ADR 0040](adr/0040-strict-ed25519-soundness-erratum.md) amends the charter
bullet accordingly.
[SECURITY.md](../SECURITY.md) cross-references this section instead of restating the rule, so the
verdict-change rule lives in one place.

## Errata registry posture

The errata registry at [docs/errata.md](errata.md) is **live** — it is the operational
no-verdict-flip governance instrument, with a numbered entry and per-entry corpus impact. It
currently carries Erratum 1, the correction for the v1 `all` selector's three recognized member
sets (ADR 0021); Erratum 2, the strict Ed25519 verification soundness repair (ADR 0040); Erratum 3,
producer-surface signature canonicality; Erratum 4, an editorial correction of the torsion
encoding count in `spec/bap-v1.md` § 14.1; and Erratum 5, editorial heading anchors and
cross-reference links in the contract-major specifications. New errata follow the § Errata channel no-verdict-flip process above. *(This
statement is this document's own framing of the registry's operational posture, not a charter
extract — labeled as such.)*
