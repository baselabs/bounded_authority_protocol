# ADR 0040: Strict Ed25519 verification soundness erratum

- Status: accepted
- Date: October 12, 2026
- Erratum: 2
- Track: T2
- Amends:
  - [ADR 0012](0012-security-release-accelerated-deprecation-window.md) Decision 1: a soundness
    repair keeps no overlap window for the vulnerable verdict (Decision 5);
  - `REQ1-EVO-sunset-is-deployment-decision` and `REQ1-EVO-no-verdict-flip`, restated in
    Decision 5;
  - `REQ1-SIGNING-backend-reject`, which now applies after the strict gate (Decision 1);
  - the [standards track charter](../design/standards-track.md) § Parallel-version support and
    deprecation (the errata bullet) and § Governance (the errata-channel and security-policy
    bullets);
  - [governance.md](../governance.md) § Change classes, § Errata channel,
    § Security policy, and § Errata registry posture;
  - the [errata registry](../errata.md) header, and [SECURITY.md](../../SECURITY.md);
  - [ADR 0007](0007-normative-requirement-identifiers.md): the v1 surface vocabulary gains `KEY`
    (already used by contract-major 3) and `HOST` (a requirement a host must meet, mapped to
    corpus cells like any other).
- Related, not precedent: [ADR 0021](0021-v1-all-selector-recognized-shapes-erratum.md)
- Normative text: [spec/bap-v1.md](../../spec/bap-v1.md) § 14.1 and § 21,
  [spec/bap-v2.md](../../spec/bap-v2.md) § 7, and the signature clauses of the local-loopback,
  role-attestation, and content-assertion profile specifications
- Traceability: [requirement map](../design/requirement-map.md) § SIGNING, § KEY, § HOST, and § v2

## Context

Every Ed25519 surface of the protocol validated fixed widths, completed its bounded parsing and
context checks, and then delegated the verdict to the cryptographic backend
([spec/bap-v1.md](../../spec/bap-v1.md) § 7 before this erratum: "delegates Ed25519
verification to the underlying cryptographic backend"). RFC 8032 permits public keys of small
order and allows either the cofactored or the cofactorless verification equation, and widely
deployed backends also accept some non-canonical point encodings. The backends used by the
reference implementation, every verifier SDK, and the independent conformance runners differ
from one another on those inputs.

The defect class is the acceptance of Ed25519 signatures under small-order and non-canonical
point encodings. Under a public key of small order, a signature that verifies can be produced
without any private key. Wherever such a key can reach a verification input, a successful
verification proves nothing about possession: a holder JWK in a proof header, a role-attestation
subject key, a key-transition successor key, or a misconfigured trusted key. The security
advisory carries the details; this record names only the class.

The verdict delegation also made conformance depend on the backend. Two conforming
implementations could disagree on the same bytes, which defeats the purpose of a certified
corpus.

The governance rules in force when this was found were written for planned evolution:

- the charter's errata bullet says errata never change verification behavior, and any change to
  an accept or reject outcome is by definition a contract-major change;
- the security policy routes a verdict-changing fix through a contract-major security release
  with an accelerated overlap window;
- ADR 0012 accepted that a vulnerable major keeps its verdict during that overlap, and kept
  `REQ1-EVO-sunset-is-deployment-decision`.

Applied literally, these keep a forgeable verdict conforming for the whole overlap.
ADR 0021 is a related erratum but not a precedent: it corrected prose and schemas to the released
verdicts and changed no verdict of the reference or the independent runner. This ADR is the
first change to the reference's released verdicts, so it amends those rules explicitly; it does
not read an exception into them.

## Decision

### 1. Rule S1, strict Ed25519 verification

Rule S1 applies to the suites `BAP1-Ed25519-SHA256` and `BAP2-Ed25519-SHA256`, and therefore to
every profile built on them: contract-majors 1 and 2, the local-loopback proof profile, the
role-attestation profile, and the content-assertion profile. A signature `R || S` over a message
`M` under a public key `A` verifies only if all of the following hold. Checks (a) to (d) run
before any backend call:

- (a) `A` is exactly 32 bytes and the signature exactly 64 bytes (the existing fixed widths);
- (b) `A` and `R` are canonical encodings: the encoded `y` is below `p = 2^255 - 19`, and the
  sign bit is clear whenever `x = 0` (`REQ1-SIGNING-ed25519-canonical-point`);
- (c) neither `A` nor `R` is of small order, that is, neither is one of the eight points `P` with
  `[8]P = O` (`REQ1-SIGNING-ed25519-small-order-reject`);
- (d) the scalar `S` is below the group order `L` (`REQ1-SIGNING-ed25519-scalar-range`);
- (e) the cofactorless equation holds byte for byte: `encode([S]B - [k]A) == R`, with
  `k = SHA-512(R || A || M) mod L` (`REQ1-SIGNING-ed25519-cofactorless`).

Any failure returns the profile's single closed error. A backend rejection or exception after
the gate also returns exactly that error (`REQ1-SIGNING-backend-reject`, restated as applying
after the strict gate). Rule S1 performs no subgroup check at verification. Contract-major 2
carries the same rule under its own `REQ2` identifiers (spec/bap-v2.md § 7).

### 2. Key acceptance

A public key entering any verification input or producer is accepted only if it is 32 bytes,
canonical, not of small order, and on the curve, meaning the RFC 8032 §5.1.3 decoding succeeds
(`REQ1-KEY-ed25519-acceptable`, `REQ2-KEY-ed25519-acceptable`). Producers refuse keys that fail:
signing-input construction, JWK encode and decode, and thumbprint computation. At verification,
curve membership of `A` is left to the backend; every observed backend rejects off-curve keys,
and off-curve corpus cases pin that verdict.

### 3. Split justification

The four rules have two different grounds.

- **Conformance repair: rules (b) and (d).** The suite names EdDSA over Ed25519 with RFC 8032 as
  a normative reference ([spec/bap-v1.md](../../spec/bap-v1.md) § 5). RFC 8032 §5.1.3 decoding
  fails for `y >= p` and for `x = 0` with the sign bit set, and §5.1.7 treats a failed decoding or
  `S >= L` as an invalid signature. An implementation that accepted those inputs did not conform
  to the standard the suite already cites. Rejecting them repairs conformance; it creates no new
  verdict.
- **New behavior: rules (c) and (e).** RFC 8032 permits small-order keys and either equation.
  Rejecting small-order points and mandating the cofactorless equation are new verdicts, adopted
  under the change class of Decision 4.

### 4. A new change class: soundness repair

A verdict change to an existing profile may land as a soundness repair, without a new
contract-major, only if all of the following hold:

1. every changed verdict goes from accept to reject;
2. the newly rejected inputs are proven producer-impossible (Decision 6);
3. no verdict of any existing certified corpus changes, proven by running the reference and the
   independent runners over every existing corpus;
4. the new cases land in a new additive corpus with its own certified identity;
5. every maintained SDK and the independent runners ship the repair in the same release window;
6. disclosure follows the order: private advisory, then publication of the fixed releases, then
   the public advisory.

A change that fails any condition remains contract-major work.

### 5. Restated requirements and the ADR 0012 amendment

- `REQ1-EVO-no-verdict-flip` is scoped to certified corpus verdicts: no erratum flips a verdict of
  an existing certified corpus. A soundness repair adds its cases in a new corpus and flips none.
- `REQ1-EVO-sunset-is-deployment-decision` is unchanged for every sunset. A soundness repair is not
  a sunset: the major continues, and only its verdicts on producer-impossible inputs are corrected.
- ADR 0012 Decision 1 is amended. Its accelerated overlap window still governs a security
  contract-major. A soundness repair carries no overlap during which the forgeable verdict remains
  conforming; releases before the repair are retired on the package registry instead.

### 6. Honest producers are untouched

These facts make rules (b) to (e) reject only what a conforming producer never emits.

- RFC 8032 §5.1.5 clamps the secret scalar to a multiple of 8 between `2^254` and `2^255`, so the
  public key `A = [a]B` has prime order `L`: it is never of small order and has no torsion
  component.
- No non-canonical encoding decodes to a point of order `L`. Of the 40 non-canonical encodings,
  6 decode to small-order points, 20 to mixed-order points, and 14 to no point on the curve. An
  honest key therefore stays canonical however it is re-encoded.
- `R = [r]B` with `r` derived by hashing, so `R` is the identity only when `r = 0 mod L`, with
  probability about `2^-252`, and is never of order 2, 4, or 8.
- `S` is reduced modulo `L`, so `S < L`.

### 7. The exact mixed-order property and the host requirement

Let `A = A0 + T`, where `A0 = [a]B` has order `L`, `T` is a point of order dividing 8, and `A` is
canonical and not of small order.

- (i) At verification, S1 accepts `(R, S)` on `M` under `A` exactly when the cofactorless
  equation holds, with `k` computed over `A`'s bytes.
- (ii) Whoever knows `a` can sign under each of the up to eight encodings `A0 + T_i`. One secret
  can therefore present up to eight distinct keys and thumbprints.
- (iii) Without `a`, no party can produce a signature S1 accepts under any `A0 + T_i`; this reduces
  to the unforgeability of Ed25519 under `A0`. It holds only while `a` stays secret: for a key
  whose secret is public, such as an RFC 8032 test key, every torsion variant is forgeable by
  anyone.
- (iv) An honest signature under `A0` never verifies under `A0 + T_i` with `T_i != O`, so there is
  no key substitution.

Mixed-order keys are therefore not a verification-time failure, but they let one secret evade a
thumbprint-keyed deny list, a revocation list, or a rotation check that compares fingerprints.
The normative host requirement (`REQ1-HOST-ed25519-torsion-free`): a host MUST reject any key that
fails the torsion-free check (`[L]A = O`, in addition to key acceptance) at key enrollment, at
trust install (issuer, attestor, archive, and every other trusted key), and before any deny-list
or revocation comparison. A canonical, torsion-free key has exactly one encoding per secret, so
key equality is identity equality. A FIPS-style validator that applies full public-key
validation is conforming at those host points and non-conforming at verification, where the
cofactorless S1 verdict governs.

### 8. Public API

The new public module `BoundedAuthorityProtocol.Ed25519` is the single owner of the rule:

- `verify_strict/3` (rule S1; never raises);
- `acceptable_public_key?/1` (Decision 2);
- `torsion_free?/1` (Decision 7; for hosts, never on the verification path).

Every internal Ed25519 verification calls `verify_strict/3`, and an architecture test forbids any
other Ed25519 verification call in the library. Each verifier SDK mirrors the three functions at
its single Ed25519 choke point. In every SDK, JWK encode and decode, the raw-key thumbprint, and
the public thumbprint functions now fail closed on a key that fails key acceptance; censuses and
generators use a separate hash-only path that never feeds verification.

### 9. Corpus

The new cases live in a new additive corpus, profile `bap-strict-ed25519/1`, revision 1, at
`priv/conformance/strict-ed25519`: 2,410 cases in 14 families (primitive, key acceptance, grant
verification, envelope, loopback, boundary anchor, key transition, anchored export, JWK,
role attestation, content assertion, a 1,024-case cross-language differential set, the 12
published vectors of the "Taming the many EdDSAs" test suite, and a JCS UTF-8 boundary family).
Its certified index SHA-256 is
`732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`, pinned in the verifier CLI,
the reference test, and every SDK runner.

- Expected verdicts come from pure arithmetic in an independent generator (strict decoding, an
  order test, and the cofactorless equation; no blocklist and no backend), cross-checked at
  generation against a backend behind the gate. Every case names the requirement it isolates.
- The 12 published vectors are imported byte for byte under the Apache License 2.0 and attributed
  in [NOTICE](../../NOTICE).
- The JCS UTF-8 family pins `REQ1-JSON-jcs-exact` at every UTF-8 sequence-length boundary. It
  pins a related interoperability defect in which an SDK rejected valid text; it changes no
  reference verdict.
- Every existing corpus index stays byte-identical, so no existing certified pin rotates: v1
  (283 cases), v2 (268), v3 (292), local loopback, role attestation (40), and content assertion.
- An anchored export whose historical key chain contains a key that fails key acceptance is
  unverifiable by design.

### 10. Successors

Successor contract-majors and future sibling profiles on an Ed25519 suite inherit rule S1. A
prime-order requirement on `A` or `R` at verification is reserved to a successor major's own
closed profile.

## Pre-upgrade scan and re-anchoring

Before upgrading, a host runs `acceptable_public_key?/1` and `torsion_free?/1` over every stored
trusted key, enrolled holder key, role-attestation subject and attestor key, and every key in the
historical key chain of each retained anchored export. A key that fails either check is treated as
a compromise: revoke it, re-issue what it signed, and re-anchor any affected archive under a
torsion-free key. After the upgrade, an archive whose key chain contains a key that fails key
acceptance no longer verifies. That is the intended outcome, and the scan turns it into a
planned event.

## Alternatives considered

- **A literal security contract-major.** Rejected. During the overlap the old majors keep
  accepting forgeries, and the wire bytes are identical, so a new major would need new `typ` and
  suite identities, five new profiles, and five new corpora for no behavioral gain.
- **Host-side mitigation only.** Rejected as the fix: the library stays forgeable through the
  holder JWK, role attestation, and content assertion. It remains the interim mitigation before
  the fixed release is available.
- **A specification clarification only.** Rejected: the backends observably differ, so text alone
  cannot make implementations agree.
- **Prime-order `A` at verification (S2).** Rejected for the verification path: it costs a full
  scalar multiplication per key and needs curve arithmetic in every SDK. Its protection is kept
  where it pays, once per key, through the host requirement of Decision 7.
- **Prime-order `A` and `R` at verification (S3).** Rejected for the same reason, at roughly
  twice the cost.
- **The cofactored equation (ZIP 215 style).** Rejected: it accepts small-order keys, so it does
  not close the defect, and it disagrees with every cofactorless backend on mixed-order inputs.

## Consequences

- The strict gate is a few byte comparisons, negligible beside the signature verification it
  precedes. Honest producers are unaffected (Decision 6).
- The public API gains `BoundedAuthorityProtocol.Ed25519`; producers and JWK functions now refuse
  weak keys. The release is 0.8.0, a pre-1.0 minor, because it adds a public module and changes
  producer behavior.
- Existing certified corpora, pins, and digests are unchanged; the new corpus carries the new
  verdicts.
- The charter, governance, errata registry, and security policy name the soundness-repair class,
  so a future repair of the same kind has a defined route.
- Hosts gain one normative obligation: the torsion-free check at enrollment, trust install, and
  deny-list comparison.

## Enforcement

The release that carries this erratum is complete only when all of the following hold:

- the reference, every in-repository SDK, and the independent runners execute the strict corpus
  and assert its index digest at load, with the existing corpora running unchanged beside it;
- the independent runners implement rule S1 from the specification text alone;
- an architecture test forbids any Ed25519 verification call outside the public module;
- per-rule unit tests derive the small-order set by arithmetic instead of copying the table, and
  mutation tests that delete each gate clause make a named test fail.
