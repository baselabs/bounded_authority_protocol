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
longevity (the content-countersignature below solves signature-family break on its own; digest-
primitive break requires the successor suite to bind a fresh digest, named in § 3). The deferral is on
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
   signatures are still trusted, preserving the issuance provenance. Under **signature-family break**
   of the original suite (e.g. Ed25519 broken, SHA-256 still trusted), step 1 alone suffices for
   trust: the archive's content digest D (SHA-256 over the FULL archive bytes, including the signed
   anchors/transitions/rows per ADR 0004's `hash_chunks`) COVERS the original signatures — they are
   bytes within the hashed content — so a current key's signature over D re-attests the complete
   archive byte-for-byte, and an Ed25519-break attacker cannot alter any archive byte without
   changing D nor forge the current-key countersignature. The original signatures become historical
   record, not the trust root. (Under **digest-primitive break** — SHA-256 itself compromised — step 1
   does NOT suffice, because D is the broken digest; see the failure-class enumeration below for the
   hash-agility gap and the successor-major fresh-digest requirement.) (Note: no original-suite
   signature signs D itself — the anchors sign the chain hash, the transitions sign key succession —
   so the relationship is "D covers the signatures," not "the signatures cover D.")

### Failure classes the mechanism closes (including algorithm break — Challenge 2)

"Algorithm break" splits into two sub-classes with different closures, because the content digest
D the countersignature binds IS the original suite's SHA-256 (`anchored_export_codec.ex:706`) — a
named member of `BAP1-Ed25519-SHA256`. The mechanism as specified (countersigning the existing
digest D) closes signature-family break fully; digest-primitive break requires the successor suite
to bind a FRESH successor-suite digest, named honestly below rather than overclaimed.

- **Signature-family break of the original suite (the load-bearing class — e.g. Ed25519 broken):**
  an attacker forges every original-suite signature (anchors that bind the chain hash, transitions,
  row commitments). CLOSED by the content-covering countersignature — trust rests on the current
  key's signature over the content digest, re-derived and compared in constant time, NOT on the
  original signatures. (SHA-256 is presumed unbroken in this sub-class; the break is the signature
  primitive.)
- **Digest-primitive break (NOT closed by re-signing the existing digest — hash-agility gap):** if
  the reason for suite succession is SHA-256's compromise (second-preimage/collision resistance
  lost), an attacker presents a colliding archive with the same digest D and inherits the legitimate
  current-key countersignature — the constant-time digest comparison passes on forged content. The
  mechanism as specified does NOT close this sub-class, because it binds D (the original suite's
  digest). A successor major that anticipates digest break MUST bind a FRESH successor-suite digest
  of the raw archive bytes (hash-agile: the countersignature signs `H_succ(raw_archive_bytes)`, not
  the inherited D, and binds the digest algorithm in the payload). This is a successor-major
  mechanism detail; this ADR names the gap honestly rather than claiming the whole "algorithm break"
  class is closed. (NIST's collision-resistance guidance for signature applications applies: the
  digest bound by a countersignature must be one the verifier still trusts.)
- **Content-digest mismatch (signature-family-break regime, SHA-256 trusted):** a countersignature
  over digest D presented with an archive whose re-derived digest is D'. CLOSED by the constant-time
  digest comparison (ADR 0004's mechanism) — under the signature-family-break regime where SHA-256
  remains collision-resistant.
- **Compromise of the attesting current-suite key:** a rogue `K_cur` can countersign arbitrary
  archives (including ones carrying forged original-suite signatures). This is the trust-root risk
  the caller manages by supplying the trusted current key — it is a key-custody/trust-decision, not
  a verifier bypass (the verifier only accepts keys the caller declared trusted). The mitigation is
  operational (the caller's trusted-key set), exactly as ADR 0004's caller supplies the trusted
  current key for the historical-key chain.
- **Suite-downgrade:** the caller supplies the trusted current suite, so a downgrade (a weaker suite
  claimed as "current" to bypass a stronger suite's deprecation) is a caller trust-decision, not a
  verifier bypass.
- **Suite-mismatch:** the attestation's `original_suite` field must match the archive's original
  suite. ADR 0004's archive carries no explicit suite field (the suite is implicit in the `BAP1-*`
  prefix/alg/fixed widths); a successor major derives the archive's original suite from those
  markers (the prefix byte `BAP1-ARCHIVE\0`, the anchor `alg`/`typ`, the fixed widths) and the
  verifier requires the attestation's `original_suite` to equal the derived value. The successor
  major's ADR specifies the exact derivation.
- **Attesting-key validity window:** only the generic `valid_from <= attestation_time < valid_before`
  check transfers from ADR 0004 (a single key's interval), NOT ADR 0004's positional anti-cycling /
  no-fingerprint-cycle rules — those govern an ordered transition CHAIN, and the attestation is
  deliberately NOT a chain link. The attesting key's interval is checked against the attestation
  time; ordering across multiple attestations is the successor major's concern.

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
  typ and `ba_sut` claim are REJECTED by the current major's closed profile — the rejection evidence
  is the CODE's closed typ set `{ba+cap, dpop+jwt, ba+chain-anchor, ba+key-transition}`
  (`compact_jws.ex:117,149-150`, `runtime.ex:280`, `boundary_anchor_codec.ex:92`,
  `key_transition_codec.ex:124`) and closed claim set, neither of which admits the reserved names.
  (The unchanged conformance corpus at `agreed=259` is CONSISTENT with this — it exercises the closed
  code sets — but is not itself the rejection proof for names that live in docs only, since the corpus
  verifies code behavior, not docs reservations.)
- Activation is a successor-contract-major decision. The current major's wire profile, bounds, and
  verdicts are unchanged.
- The hybrid Ed25519 + ML-DSA composite is a successor-suite-ADR concern (wire-freeze barrier), not
  this ADR's.
- The ML-DSA family + parameter-set/security-category mapping is named; the successor suite's ADR
  selects a parameter set and cites byte sizes.
