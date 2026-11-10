# Governance policy

This document is the single normative home of the project's governance policy. The
[standards track charter](design/standards-track.md) § Governance points here and carries no
independent policy statement. Decisions publish through this policy, the normative
specifications, and the [errata registry](errata.md); there are no separately published decision
records.

## Why governance is published now

Published now, while the project is single-maintainer, because publishing the policy is the
credibility step and the policy is what makes single-maintainer tolerable to adopters.

## Change classes

Editorial (errata; never verdict-changing) · soundness repair (an erratum that changes verdicts
only from accept to reject on producer-impossible inputs, under every condition of
§ [Soundness repairs](#soundness-repairs)) · clarifying (additive docs/cases only) ·
byte-distinct sibling proof profile (independent normative/corpus/API identity,
§ [Byte-distinct sibling proof profiles](#byte-distinct-sibling-proof-profiles)) · byte-distinct
sibling attestation profile (same identity shape, under its own class conditions,
§ [Byte-distinct sibling attestation profiles](#byte-distinct-sibling-attestation-profiles)) ·
existing-profile wire or verification behavior (contract-major only). Each class maps to a
package version as § [Package versions](#package-versions) states.

## Package versions

The Hex package follows Semantic Versioning. Package versions and contract-majors are separate
numbers: "package 1.x" names a release line of this package, and "contract-major N" (suite
`BAPN-…`) names a wire profile. One package release carries several contract-majors, and a new
package major changes no wire profile.

From package 1.0.0:

- **Minor:** a new contract-major, a new sibling profile, a new public function, a new optional
  argument, or a new struct field with a default; a soundness repair that meets every condition of
  § [Soundness repairs](#soundness-repairs); a clarifying change; a raised toolchain floor
  (Elixir or Erlang/OTP), announced in the CHANGELOG.
- **Patch:** an editorial erratum, or a fix that changes no documented behavior or verdict.
- **Major (2.0.0):** removing a namespace, or changing a struct field, a function arity, a return
  shape, an enforced key, or a documented error.

Before 1.0.0, a breaking change shipped as a `0.x.0` release; that rule ends at 1.0.0.

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
6. disclosure follows the order private advisory, then publication of the fixed releases, then
   public advisory, when a party without the signing key can make a release before the repair
   accept a newly rejected input; otherwise the errata entry, published with the fixed releases,
   is the disclosure and names every affected release of every implementation.

Verifiers that each conform to the published profile yet return different verdicts for the same
issuer-signed bytes are an equivalent soundness failure: a constraint the issuer signed is enforced
by some conforming hosts and not by others, which defeats the certified corpus. Erratum 6 (selector
float zero) is a soundness repair on that ground.

A soundness repair is not a sunset: the major continues, and it keeps no overlap window during
which the vulnerable verdict remains conforming. Releases before a repair that needs an advisory
under condition 6 are retired on the package registry; other earlier releases stay installable and
return the pre-repair verdict, which the errata entry records. A change that fails any condition
remains contract-major work. The first soundness repair was erratum 2 (strict Ed25519
verification).

*Note (2026-11-09):* condition 6 distinguishes keyless repairs from signer-bound ones. Erratum 2
(strict Ed25519) is keyless: anyone can produce a malleable `S + L` signature, so it shipped with
advisories and the earlier releases were retired. Erratum 6 (selector float zero) is signer-bound:
every affected selector value sits inside issuer-signed bytes, so its errata entry is the
disclosure and the earlier releases stay installable. The distinction was introduced with
erratum 6.

## Byte-distinct sibling proof profiles

A sibling proof profile is permitted only when a new signed protected `typ` gives its artifacts a
machine-visible identity, every existing profile rejects those bytes, and no byte accepted by an
existing profile changes meaning or verdict. It has its own public namespace, normative
specification, stable requirement namespace, conformance corpus identity, registry entry, and
independent implementations. Every shipped SDK implements its relevant verification surface before
release. Its first publication is a package minor release (§ [Package versions](#package-versions))
with immutable source, package, corpus, and real-substrate evidence.

This class does not create an open extension mechanism: there is no runtime profile registry,
negotiation, inference, fallback, or best-effort parsing. Every future sibling is another published
specification and closed corpus. Any change to an existing profile's accepted bytes, claims,
algorithms, bounds, suite, or verdicts remains contract-major work.

## Byte-distinct sibling attestation profiles

A sibling attestation profile is the second sibling class, permitted only when its artifact carries
a new signed protected `typ`, is standalone and grant-unbound (parsed by no existing profile's
verification path, verified only through its own named API), cross-rejects every existing profile
by corpus leg in both directions, and changes no byte, bound, or verdict anywhere. It has its own
public namespace, normative specification, profile-scoped requirement range, conformance corpus
identity, and registry entry; it single-sources the shared primitives of the contract-major it
binds; every shipped SDK implements its verification surface before any release bearing it; its
first publication is a package minor release (§ [Package versions](#package-versions)) with
immutable source, package, corpus, and real-substrate release evidence. No runtime registry,
negotiation, inference, fallback, or plugin mechanism exists. The charter's
reserve-and-activate-in-a-major discipline for attestation shapes governs
verifier-integration-bound artifacts; a consumer-gated artifact no major verifier ingests takes
this class.

## Change control

Every product-shaping decision is published through this policy, a normative specification, or
the errata registry. Once at least two independent external implementations pass the conformance
corpus, contract-major and sibling-profile proposals gain a published comment window of no fewer
than thirty days and a change-control group with implementer representation. The hand-off
criterion to a formal standards body is adoption, not ceremony: when a venue (see the charter
§ [Venue strategy](design/standards-track.md#venue-strategy)) accepts the work, that venue's
process supersedes this one.

## Errata channel

[docs/errata.md](errata.md) is the numbered errata registry; each entry names affected versions and
its corpus impact, and the no-verdict-flip invariant is checked at review. **No erratum may flip a
verdict of an existing certified corpus** — any change that would alter such an accept/reject
outcome is by definition a contract-major change and follows the evolution contract, never this
registry. The one exception is a soundness repair (§ [Soundness repairs](#soundness-repairs)),
which adds its cases in a new corpus, flips no existing corpus verdict, and is recorded in this
registry with its corpus impact. A sibling proof profile is not an erratum and cannot reclassify an
existing case (the no-verdict-flip invariant, stated in the
[evolution contract](design/standards-track.md#the-evolution-contract) as
`REQ1-EVO-no-verdict-flip`).

## Deprecation policy

A contract-major enters deprecation only after its successor has a published normative profile, a
published conformance corpus, and **at least two independent implementations passing that corpus**.
The deprecation window is published at announcement and is **never shorter than twelve months**,
except for a security contract-major (§ [Security policy](#security-policy) below); during the
window, conforming verifier deployments support both majors in parallel. Sunset of a major is a
deployment decision after the published window, never a silent library change. The authoritative
deprecation prose and the conformance-traced requirement identifiers
(`REQ1-EVO-deprecation-prerequisites`, `-window-minimum`, `-parallel-support-during-window`,
`-sunset-is-deployment-decision`) live in the charter § [Parallel-version support and
deprecation](design/standards-track.md#parallel-version-support-and-deprecation) and are not
duplicated here.

## Security policy

[SECURITY.md](../SECURITY.md) governs vulnerability intake; a vulnerability whose fix would change a
verdict and that does not meet every soundness-repair condition (§ [Soundness
repairs](#soundness-repairs)) is handled as a contract-major security release with an accelerated
overlap window — published at announcement and set proportional to the vulnerability's severity,
exempt from the twelve-month deprecation minimum (charter § [The evolution
contract](design/standards-track.md#the-evolution-contract)), yet still a published,
deployment-decided sunset, not a flag-day — never as a silent verdict change. A fix that meets
every soundness-repair condition lands as an erratum, disclosed as condition 6 of § Soundness
repairs requires, in the same release across every implementation. [SECURITY.md](../SECURITY.md)
cross-references this section instead of restating the rule, so the verdict-change rule lives in
one place.

## Errata registry posture

The errata registry at [docs/errata.md](errata.md) is **live** — it is the operational
no-verdict-flip governance instrument, with a numbered entry and per-entry corpus impact. It
currently carries Erratum 1, the correction for the contract-major 1 `all` selector's three
recognized member sets; Erratum 2, the strict Ed25519 verification soundness repair; Erratum 3,
producer-surface signature canonicality; Erratum 4, an editorial correction of the torsion
encoding count in `spec/bap-v1.md` § 14.1; Erratum 5, editorial heading anchors and
cross-reference links in the contract-major specifications; and Erratum 6, the signer-bound
selector float-zero soundness repair. New errata follow the § [Errata channel](#errata-channel)
no-verdict-flip process above.
