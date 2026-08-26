# ADR 0026: The post-quantum successor-suite statement

- Status: accepted
- Date: 2026-08-26

## Context

The v1 suite (`BAP1-Ed25519-SHA256`) is classical. ADR 0009 established the succession
design (named-suite successors under their own contract-majors, cross-suite evidence
longevity via content-covering countersignature); this ADR makes the post-quantum successor
CONCRETE: what it will be named, what its parameters may be, and what triggers its
activation. The external landscape is now settled enough to cite: RFC 9964 (ML-DSA for
JOSE/COSE, published May 2026) defines the JOSE mapping for ML-DSA;
draft-ietf-jose-pq-composite-sigs (WG document) defines the hybrid-composite signature
posture; NIST IR 8547 IPD names the 2030/2035 quantum-risk horizon for harvest-now-
decrypt-later sensitive deployments.

## Decision

1. **The successor candidate family is `BAP2-*`.** A successor contract-major carries its own
   complete closed suite named per the existing scheme `BAP<contract-major>-<signature>-<digest>`;
   the concrete candidates are ML-DSA-65 (NIST category 3) as the baseline and ML-DSA-87
   (category 5) for the higher-security tier, with SHA-256/SHAKE-256 digest parameters fixed
   at suite definition. RFC 9964's JOSE mapping is the wire vehicle for the ML-DSA signature
   and JWK forms.
2. **Hybrid-composite posture room is reserved.** `draft-ietf-jose-pq-composite-sigs`
   (Ed25519+ML-DSA composite) is the anticipated migration shape for evidence continuity:
   composite signatures let a verifier accept either classical or post-quantum verification
   during the transition. The reserved names `ba+suite-attestation` / `ba_sut` (ADR 0009)
   carry the cross-suite countersignature that keeps v1 evidence verifiable after a
   classical break; the composite posture is the successor-major's option, decided at its
   own definition time on the state of the then-published RFC.
3. **The quantum-readiness statement.** The v1 profile is a fit for deployments whose
   evidence sensitivity window is shorter than the harvest-now-decrypt-later horizon (NIST
   IR 8547 IPD: 2030/2035 risk horizons). Deployments with longer evidence lifetimes —
   consumption chains and anchored exports are the long-lived artifacts — should plan for
   suite succession (re-anchoring archives under a successor suite with `ba+suite-attestation`
   cross-signatures before the classical break). The public verifier stays stateless through
   all of this: succession is a new closed profile, never a v1 mutation.
4. **Activation remains successor-major only** (ADR 0009): the closed v1 profile rejects
   every `BAP2-*` artifact, `ba_sut`, and the composite names today — the conformance corpus
   (283 green) proves the rejection mechanically — and activation requires the full
   successor-major process: complete closed profile, corpus, and cross-suite evidence rules.
5. **Registries reconciliation:** the registries document's anticipated-suite row names the
   `BAP2-*` family with this ADR; the standards-track charter's succession section cites it.
   Both stay reserved-status until the successor major exists.

## Bets and revisit triggers

- Bet: ML-DSA-65 is the right baseline (category 3 matches the profile's current 128-bit
  posture; RFC 9964 makes it JOSE-ready). Revisit: the pq-composite RFC's final parameter
  set, or FIPS 204 updates.
- Bet: hybrid composite is the transition shape (evidence continuity beats flag-day
  migration). Revisit: draft-ietf-jose-pq-composite-sigs progressing to RFC — re-read the
  composite security discussion at that point.
- Bet: 2030/2035 is the planning horizon (NIST IR 8547 IPD). Revisit: IR 8547 final, or any
  cryptanalytic advance against Ed25519.

## Consequences

- Zero wire change: every name here stays reserved-and-rejected in v1; the corpus and the
  closed-rejection invariant enforce it.
- The successor-major's work items are now named and citable: the `BAP2-*` profile, its
  corpus, the composite decision, and the re-anchoring procedure for long-lived evidence.
- Long-evidence deployments have a published posture to plan against instead of an open
  question.
