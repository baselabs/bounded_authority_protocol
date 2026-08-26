# BAP v1 formal attacker model

Pinned to: `spec/bap-v1.md` rev 1 (Doc-Revision). This file is a companion of the specification
at exactly that revision; the spec-facts gate (rule 8) reds if either side drifts alone.

## Scope

The model covers the stateless verification core: grant/proof construction and verification,
request binding, and facts disclosure. The consumption chain, boundary anchors, key
transitions, and archive framing are ORDERED-EVIDENCE constructions whose core invariants
(hash-chain integrity, positional authentication, exact-EOF framing) are proven by the
conformance corpus's tamper classes and the mutation gates; a process-calculus treatment of
their ordering is the named follow-on (ADR 0025).

## Attacker

A Dolev-Yao network attacker: reads, drops, reorders, forges, and injects every message on
every channel; cannot break cryptography (signatures, hashes, and key secrecy hold in the
symbolic model). Additionally a MALICIOUS HOLDER: possesses their own valid long-term key and
any credentials legitimately issued to them, signs arbitrary proofs, and attempts cross-grant,
cross-operation, cross-endpoint, cross-invocation, and cross-time confusion. The issuer is
honest; verifiers are honest; the network is hostile.

Symbolic assumptions, recorded: perfect cryptography; Ed25519/SHA-256 as symbolic sign/hash;
time abstracted to an order with a bounded skew window (no dense-time reasoning); JSON
canonicalization taken as an injective encoding (the typed projection makes this sound — the
tagged algebra is a free term algebra, which is exactly what the typed-projection table buys
the model).

## Properties

- **P1 (grant binding).** A proof accepted against a grant g carries `ath` = the exact grant
  digest of g, and the acceptance is impossible against any other grant: cross-grant replay is
  impossible even for the malicious holder who holds valid keys and multiple valid grants.
- **P2 (request binding).** The request digest accepted by a verifier equals the digest of the
  VERIFIER-DERIVED pair (operation, typed(cast_arguments)) — a proof signed for one request
  cannot be accepted for a different operation or any different typed-arguments value
  (injectivity of the typed projection is the load-bearing lemma).
- **P3 (context-binding completeness).** Acceptance requires equality of every context
  element — method, target URI, invocation identifier, operation, request digest, grant digest,
  holder thumbprint, and the nonce in required mode — with the verifier's expected context.
  Time is abstracted (assumption above): temporal windows are modeled as ordered predicates
  the verifier checks, not as clock physics.
- **P4 (facts disclosure).** The facts returned on acceptance disclose exactly the declared
  fields: identifiers, digests, times, and the not-evaluated markers — never arguments,
  selector values, raw credentials, signatures, JWK containers, or nonces.

## Out of model

Operational controls (replay reservation, revocation, trust selection), denial of service,
side channels, storage-layer integrity, and the archive ordering constructions (above).
