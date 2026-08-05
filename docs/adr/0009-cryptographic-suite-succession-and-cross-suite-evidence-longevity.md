# ADR 0009: Cryptographic suite succession and cross-suite evidence longevity

- Status: accepted
- Date: 2026-08-05

## Context

The current contract-major's cryptographic suite is `BAP1-Ed25519-SHA256` (EdDSA over Ed25519, SHA-256
digests, RFC 8785 JCS canonical bytes, the `BAP1-*` domain separators). It is a named suite, not
"the" algorithm set — successor suites follow `BAP<contract-major>-<signature>-<digest>` ([registries.md](../design/registries.md)).
[ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §2 committed to two
design directions in charter prose:

1. The anticipated successor signature family is ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)),
   with a hybrid Ed25519 + ML-DSA composite posture to be evaluated when the successor suite is defined.
2. Long-retention evidence under a frozen signature algorithm outlives the algorithm's trustworthiness;
   the committed solution is **cross-suite countersignature**, where "boundary anchors of a current
   suite countersign archives of an earlier suite ... attesting 'verified complete under suite A at
   time T'" and "trust freshness comes from the newest countersignature, not from the original
   signature surviving cryptanalysis" ([standards-track.md](../design/standards-track.md) § Evidence longevity).

ADR 0006 §2 committed to the DIRECTION; this ADR carries the MECHANISM to ADR-quality design. The
design-adversarial pass on BAP-11 (Challenge 1, blocking) defeated the first mechanism draft — a
`ba+suite-transition` chaining key/suite identity — because it solves KEY succession, not ALGORITHM
break: if the original suite's signature algorithm is broken, the original boundary anchors (which
bind the chain hash) and transitions are forgeable, and a key/suite-identity chain attests a forgery.
The charter's "trust freshness ... not from the original signature surviving cryptanalysis" requires
a **content-covering re-attestation**: a current-suite key signing the archive's CONTENT, independent
of the original signatures. This ADR specifies that primitive.

Activation of any of this is a successor-contract-major concern; the current major stays single-suite
and the closed profile rejects every reserved name this ADR introduces.

## Decision

### 1. Suite-naming scheme (ADR-grade; refines ADR 0006 §2)

The suite-naming scheme is `BAP<contract-major>-<signature>-<digest>`. The current suite is
`BAP1-Ed25519-SHA256`; a successor suite binds its own domain separators, `alg` values, and fixed
widths under its own contract-major. The `kid`/thumbprint indirection at the key-locator boundary is
already key-type independent, so trusted-key resolution survives suite succession unchanged. This is
the scheme [registries.md](../design/registries.md) § Cryptographic suites carries; this ADR records
it as an ADR-grade decision (ADR 0006 §2 named it in charter prose).

### 2. ML-DSA successor path (named, not constant-bearing)

The anticipated successor signature family is ML-DSA (FIPS 204). The three parameter sets are
ML-DSA-44 (NIST security category 2), ML-DSA-65 (category 3), and ML-DSA-87 (category 5). This ADR
names the family and the parameter-set/security-category mapping; it does NOT cite byte sizes or
select a parameter set — those belong to the successor suite's own ADR at its definition, gated by
the deprecation-prerequisites rule (published profile + corpus + two independent passing
implementations, [standards-track.md](../design/standards-track.md) § Parallel-version support).

A hybrid Ed25519 + ML-DSA composite posture is FLAGGED for evaluation when the successor suite is
defined. It is NOT specified here: a composite changes frozen wire bytes, which is a contract-major
change, and the composite's value is a migration-window optimization (a single archive remains
directly verifiable during the overlap without re-attestation), not the only path to evidence
longevity (the content-countersignature below solves algorithm break on its own). The deferral is on
the wire-freeze barrier, not "speculative design."

### 3. The content-covering countersignature mechanism (the core)

**The mechanism binds the archive's CONTENT DIGEST under a current-suite key, independent of the
original suite's signatures.** [ADR 0004](0004-consumption-chain-rollover-and-anchored-export-verification.md)
already computes the archive's SHA-256 content digest over every raw byte ("hashes every raw byte, and
compares the raw SHA-256 digest in constant time"). That digest IS the archive's content identity.
A cross-suite content countersignature is a current-suite key signing a closed statement binding that
digest, attesting "verified complete."

A successor major defines a **`ba+suite-attestation`** typ (reserved now in
[registries.md](../design/registries.md)) with:

- a closed payload binding: the archive's chain identity, the sequence range covered, the archive's
  SHA-256 content digest, the original suite identity under which the archive was verified, the
  attestation time, and the attesting key's identity;
- a **typed, suite-parameterized key binding** (NOT "one extra field" — the design-adversarial
  Challenge 3): the current major's fingerprint is RFC 7638 OKP over `{"crv":"Ed25519","kty":"OKP","x":...}`
  (`lib/bounded_authority_protocol/v1/jwk.ex`); an ML-DSA key has no OKP JWK form, so a successor
  suite defines its own canonical key preimage + thumbprint. The payload carries the suite identity so
  the verifier knows which fingerprint construction applies to which key;
- signed by the attesting current-suite key.

The reserved claim name `ba_sut` (suite-attestation) carries the payload binding
([registries.md](../design/registries.md)).

### Verification of aged evidence (the charter's two-part rule, corrected)

1. **Content integrity re-attested (load-bearing):** the caller supplies a currently-trusted suite's
   public key + the `ba+suite-attestation` countersignature over the archive. The verifier re-derives
   the archive's content digest (ADR 0004's exact byte-walk), compares it to the countersigned digest
   in constant time, and verifies the countersignature under the current key. **This step does NOT
   depend on the original suite's signatures** — it covers the content.
2. **Original-suite verification as historical record (the algorithm-break class):** the archive MAY
   still verify under its original suite's rules (anchors, transitions, row hashes) when those
   signatures are still trusted, preserving the issuance provenance. Under cryptanalytic break of the
   original suite, step 1 alone suffices for trust: the content countersignature covers what the
   original signatures covered (the content digest), signed by a current key. The original signatures
   become historical record, not the trust root.

### Failure classes the mechanism closes (including algorithm break — Challenge 2)

- **Algorithm break of the original suite (the load-bearing class):** an attacker forges every
  original-suite signature (anchors that bind the chain hash, transitions, row commitments). CLOSED
  by the content-covering countersignature — trust rests on the current key's signature over the
  content digest, re-derived and compared in constant time, NOT on the original signatures.
- **Content-digest mismatch:** a countersignature over digest D presented with an archive whose
  re-derived digest is D'. CLOSED by the constant-time digest comparison (ADR 0004's mechanism).
- **Suite-downgrade / suite-mismatch / window gaps:** the caller supplies the trusted current suite +
  key; the attestation's original-suite field must match the archive's declared suite; ADR 0004's
  window rules apply to the attesting key's validity.

## Alternatives considered

- **A `ba+suite-transition` chaining key/suite identity (the original BAP-11 draft).** Rejected
  (design-adversarial Challenge 1): it solves key succession, not algorithm break. If the original
  suite breaks, the original anchors/transitions are forgeable, and the chain attests a forgery. The
  content-covering countersignature is required.
- **Re-sign archives under the new suite.** Rejected: it destroys the original evidence's byte-identity
  (the archive's value IS that it is the original bytes), and requires the new-suite key to see every
  old archive. The content countersignature preserves the original bytes and adds a layered attestation
  over their digest.
- **No mechanism ("re-verify under the old suite if you still trust it").** Rejected: that is the
  status quo's failure mode — long-retention evidence's trustworthiness expires before its retention
  period.

## Consequences

- A successor major implementing evidence longevity implements the `ba+suite-attestation` typ as a
  content-covering countersignature, NOT a key/suite-identity chain. The reserved `ba+suite-attestation`
  typ and `ba_sut` claim are REJECTED by the current major's closed profile (the unchanged conformance
  corpus proves this; the rejection evidence is the code's closed typ set `{ba+cap, dpop+jwt,
  ba+chain-anchor, ba+key-transition}` and closed claim set, neither of which admits the reserved names).
- Activation is a successor-contract-major decision. The current major's wire profile, bounds, and
  verdicts are unchanged.
- The hybrid Ed25519 + ML-DSA composite is a successor-suite-ADR concern (wire-freeze barrier), not
  this ADR's.
- The ML-DSA family + parameter-set/security-category mapping is named; the successor suite's ADR
  selects a parameter set and cites byte sizes.
