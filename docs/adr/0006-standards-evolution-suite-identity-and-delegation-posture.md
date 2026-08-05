# ADR 0006: Standards evolution, suite identity, and delegation posture

- Status: accepted
- Date: 2026-08-03

## Context

The protocol's goal is to become the industry standard for bounded agent capability verification.
A standards-readiness assessment against ISO best practices and the anticipated future of agentic
verification found the security core strong — profiled RFCs rather than invented crypto, a
machine-checkable conformance corpus, honest scope boundaries — and identified the gaps that decide
whether this becomes a standard or stays a very good library: no written evolution mechanism above
the closed wire format, a frozen cryptographic suite with long-retention evidence that would
outlive its algorithm's trustworthiness, prose requirements without RFC 2119 keywords, unregistered
claim/media names, single-maintainer governance with no published change control, and no decided
shape for multi-agent delegation. Every one of these is cheap to fix before third parties implement
the profile and nearly impossible to retrofit after.

The user directed (2026-08-03) that all of it be captured as tracked product authority now, with
deferral framing kept to the bare minimum: what can be designed, named, reserved, or policied in
the current contract-major lands now; only activations that would change frozen wire bytes wait for
a successor contract-major, and those arrive with their design already specified.

## Decision

1. **Evolution above the wire format.** The closed profile (reject every unlisted member) is
   permanent. Evolution is parallel contract-majors: artifacts self-declare their major (`v`,
   `typ`, domain separators); a proof's major must equal its grant's; each accepted major verifies
   under its own complete closed profile; no downgrade or mixed-major path exists. Deprecation
   requires a published successor corpus plus two independent passing implementations, and a
   published overlap window of at least twelve months. Errata never flip a corpus verdict — any
   verdict change is by definition a contract-major. Authority:
   [standards-track.md](../design/standards-track.md) § The evolution contract.

2. **Named cryptographic suites.** The current profile is the suite `BAP1-Ed25519-SHA256`
   (registered in [registries.md](../design/registries.md)); successors follow
   `BAP<contract-major>-<signature>-<digest>` with ML-DSA (FIPS 204) the anticipated signature
   family. Evidence longevity is solved by cross-suite countersignature: boundary anchors of a
   current suite countersign archives of an earlier suite, generalizing the existing
   historical-key rollover to historical-suite rollover; trust freshness comes from the newest
   countersignature. Specified now (the mechanism — a content-covering countersignature binding the
   archive's content digest, not a key/suite-identity chain — is carried to ADR quality in
   [ADR 0009](0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md));
   activation is a successor-suite concern.

3. **Requirement-to-corpus traceability.** Before BAP-06, the normative profile is rewritten with
   RFC 2119/8174 keywords and stable requirement identifiers, with the acceptance bar that every
   MUST maps to at least one conformance applicability cell or a named falsifiable gap.

4. **Registries and registrations.** [registries.md](../design/registries.md) is the authoritative
   namespace for claims, `typ` values, selector kinds, suites, and operation-name conventions.
   `ba_dlg`, `ba_obo`, and `ba+cap-delegated` are reserved now. IANA templates are prepared as
   roadmap row BAP-12 and filed at first external submission.

5. **Delegation with attenuation, decided.** The successor contract-major's delegation shape is
   chained attenuated grants: each link a signed grant issued by the parent's holder, bound by
   parent-grant hash (`ba_dlg`), attenuation-only and mechanically checkable (operations subset,
   conjunctive selector narrowing, window/audience containment), no caveat DSL — the closed
   selector algebra is the attenuation language. The current major remains single-holder. The
   mechanism is carried to ADR quality in [ADR 0010](0010-delegation-with-attenuation.md).

6. **Revocation and principal binding get designed homes.** Deployment-level revocation guidance
   (validity windows + nonce challenges as baseline, a reserved status-check profile for long-lived
   grants) ships with normative force at submission; `ba_obo` reserves the issuer-asserted
   on-behalf-of principal claim.

7. **Published governance.** Change classes (editorial/clarifying/contract-major), public ADRs for
   every product-shaping decision, a thirty-day comment window plus implementer change-control
   group once two external implementations exist, the numbered errata registry
   ([errata.md](../errata.md)), and the verdict-flip prohibition as a governance invariant.

8. **Venue.** MCP `ext-auth` first (BAP-08); IETF (OAuth/GNAP orbit) as the durable home if
   traction warrants; ISO treated as a design checklist, not a destination.

9. **Sequencing is enforced by the roadmap.** New rows BAP-10 (evolution contract + registries +
   RFC 2119 pass), BAP-11 (suite identity + evidence longevity design), BAP-12 (IANA templates),
   BAP-13 (published governance), BAP-14 (delegation contract design). BAP-07 (first public
   release) additionally depends on BAP-10 and BAP-11; BAP-12 and BAP-13 gate the external
   submission path with BAP-08.

## Consequences

The wire profile of the current contract-major does not change — nothing here alters a byte, a
bound, or a verdict, and the conformance corpus is unaffected. What changes is authority: the
evolution mechanism, suite identity, delegation shape, and governance are now written product
decisions with reserved names, so future work implements specifications instead of opening
debates, and external implementers can adopt the current major knowing exactly how it will be
succeeded, deprecated, and kept verifiable over evidence-retention horizons.
