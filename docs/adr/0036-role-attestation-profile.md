# ADR 0036: The role-attestation sibling profile (`bap-role-attestation/1`)

- Status: accepted
- Date: 2026-09-22
- Track: T2
- Amends: [ADR 0007](0007-normative-requirement-identifiers.md) (profile-scoped requirement
  ranges), [ADR 0006](0006-standards-evolution-suite-identity-and-delegation-posture.md) §
  Evolution contract (a second sibling class alongside the proof class of
  [ADR 0027](0027-byte-distinct-application-proof-profiles.md)),
  [governance](../governance.md) (change classes and the comment-window scope),
  [standards-track](../design/standards-track.md) and
  [registries](../design/registries.md) (labeled class references)
- Implements: roadmap row BAP-23
- Consumer contract: BARA (the companion-signer repo) ADR-0008 and its ROADMAP row RA11 — the
  caller-supplied `verify_attestation/2` that strengthens BARA's `sign_grant` C1 gate from a
  handle self-declaration to a cryptographically-signed role binding

## Context

BARA's grant-signing gate currently proves **declaration-rejection, not key-role separation**:
a handle that consistently mis-declares its role signs internally-consistent grants that fail
only downstream, at every correctly-configured verifier's `TrustedIssuer` key check. The
strengthening path, recorded across BARA's ADR-0008 and ROADMAP RA11, is a
runtime-authority-signed role attestation: the authority signs `{key_id, public_key, role,
valid_window}` at key provisioning, and the signer consumes it as data — the dependency wall
holds because verification lives in this package. The consumer contract names
`BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2` as the exact citation
symbol.

Two prior questions decide the shape. First, the [successor-major
charter](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/successor-major-charter.md): its five families (delegation, offline floor
limits, suite succession, freshness/revocation artifact shapes, selector expressiveness) do
not include a standalone role-binding attestation, and the artifact changes no existing
profile's bytes or verdicts — but the charter's attestation-shape language and
[ADR 0029](0029-budget-window-posture.md) route *some* attestation shapes to successor
contract-majors, so the boundary must be stated, not assumed. Second, ADR 0027's
byte-distinct sibling **proof** profile class: its conditions govern an application proof
profile that reuses "an existing grant-major and shared claim mechanics" — a grant-bound,
wholesale-claim-reuse artifact this attestation is not.

A three-lens adversarial design review (security/fail-closed, standards/governance,
consumer-fit/purity) and an independent judge ruling (2026-09-22) are recorded in the landing
evidence; this ADR carries their substance. The review's two convergent blockers — a
retired-attestor-key backdating window attack against the one-sided window check, and a facts
posture that breached critical rule 1's closed facts enumeration — are closed by Decision 4
and Decision 5 below. The judge's reconciliation criterion, class structure, and forced fixes
are adopted as ruled.

## Decision

### 1. A second sibling class: byte-distinct sibling attestation profiles

A **sibling attestation profile** MAY exist only when all of the following hold:

1. its artifact is mechanically distinguishable by a new signed protected `typ`;
2. it has a separate public namespace, normative specification, profile-scoped requirement
   range (Decision 11), conformance corpus identity, and registry entry;
3. every existing profile rejects its bytes and it rejects every existing profile's bytes —
   proven by corpus legs in both directions, with every existing corpus verdict retained;
4. it adds no claim to and reinterprets no byte accepted by any existing profile;
5. it is **standalone and grant-unbound**: parsed by no existing profile's verification path
   and verified only through its own separately named public API at a deployment's explicit
   choice — profile selection is never inferred, negotiated, or retried;
6. it single-sources the shared primitives of the contract-major it binds rather than
   duplicating them;
7. it has independent conformance implementations, and every shipped SDK implements its
   verification surface before any package release bearing it;
8. its first publication is a breaking pre-1.0 package release (`0.x.0`) with immutable
   source, package, corpus, and the release evidence of Decision 10;
9. it introduces no runtime registry, negotiation, inference, fallback, or plugin mechanism.

**Reconciliation with the charter's attestation-shape posture.** The charter family
(`ba+budget-window` per ADR 0029, `ba+suite-attestation` per ADR 0009, status documents, replay
witnesses) is **verifier-integration-bound**: those artifacts are ingested by a conforming
verifier of a contract-major as part of grant or evidence verification, which is exactly why
they are reserved and activate only inside a successor major's closed profile. A sibling
attestation profile is **consumer-gated**: no major's verifier ever ingests it; acceptance
lives behind its own named API at a deployment's explicit choice — the same posture the
evolution contract already grants sibling proof profiles. This criterion, not silence, is why
this profile does not implicate ADR 0029's posture, and ADR 0029's deferral of
`ba+budget-window` stands unchanged.

**Governance.** The governance change-class list gains this class beside the sibling proof
profile class, and the change-control comment window, once its two-external-implementation
trigger fires, applies to sibling attestation profile ADRs as it does to contract-major ADRs.
ADR 0027 is amended by pointer (its class remains the proof-profile class; nothing in its text
changes meaning). ADR 0036 does not create an open extension mechanism: every future sibling
of either class is another numbered public ADR and closed corpus.

### 2. Profile identity

The profile identity is `bap-role-attestation/1` (profile schema version `1`; the registries
gain an **attestation profiles** family). Its protected `typ` is `ba+role-attestation`; its
media type is `application/ba-role-attestation+jwt`. The public module is
`BoundedAuthorityProtocol.RoleAttestation.V1`; the citation symbol BARA's rows name is
`BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2`.

The `/1` segment is the profile schema version — further schemas are new sibling ADRs, never
in-place edits. The payload `v` claim binds the profile to contract-major 1 mechanics
(Ed25519/EdDSA under the `BAP1-Ed25519-SHA256` suite identity, and the version-neutral V1
primitives). At any future contract-major this profile stays contract-major-1-bound — the
posture ADR 0030 §1 records for the loopback profile, restated for a grant-unbound artifact;
major re-binding is a new profile schema.

### 3. Wire contract

The compact JWS protected header has exactly these members:

| Member | Required value |
|---|---|
| `alg` | `EdDSA` |
| `kid` | attestor key id — kid rules (bounded ASCII `[A-Za-z0-9.-_~]`), a hint, never a trust selector |
| `typ` | `ba+role-attestation` |

The payload has exactly these members:

| Member | Type | Rule |
|---|---|---|
| `v` | integer `1` | contract-major-1 mechanics binding |
| `jti` | string | non-empty bounded StringOrUri identifier (grant `jti` rules) — audit and revocation-reference handle |
| `key_id` | string | the attested subject key id, kid rules |
| `public_key` | string | base64url of exactly 32 raw Ed25519 subject public-key bytes |
| `role` | string | `"issuer"` or `"holder"` — closed set |
| `nbf` | integer NumericDate | integral; `nbf < exp` |
| `exp` | integer NumericDate | integral; the attestation's acceptance window is `[nbf, exp)` |

Registered claim names (`jti`, `nbf`, `exp`) are used where registered semantics apply; the
private members carry the subject binding. Bytes are JCS-canonical: both segments must equal
their canonical re-encoding, duplicate members are rejected, and every unlisted member, value,
encoding, or extension is invalid with exactly `{:error, :invalid}`.

The subject key rides the wire as the raw public key — not a fingerprint — because the
consumer contract carries `public_key`, and a wire fingerprint would make every consumer a
thumbprint implementor. Fingerprints (RFC 7638 thumbprints under
`Jwk.public_key_thumbprint_raw`, the suite-wide discipline) are derived internally.

### 4. Verification contract

`verify_attestation(compact, expected)` where `expected` is `%ExpectedAttestation{}` carrying
the caller-supplied attestor (`%HistoricalPublicKey{}`: key id, raw 32-byte public key,
`valid_from`, `valid_before | :unbounded`), the expected subject binding (`subject_key_id` and
`subject_public_key` raw 32 bytes), `now` (integer), and bounds. Verification proves, in the
package's pure fail-closed style (single `{:error, :invalid}`):

- the parsed header/payload closed sets and canonical bytes (Decision 3);
- the header `kid` equals the attestor key id, and the signature verifies under the attestor
  public key;
- the payload subject binding equals the expected binding (`key_id` and raw `public_key`
  byte-equality);
- **self-attestation rejection**: invalid when the attestor thumbprint equals the subject
  thumbprint, or the attestor key id equals the subject key id (the key-transition
  distinct-fingerprints precedent; a self-signed role attestation is the declaration gate with
  extra steps);
- **window containment**: `nbf >= attestor.valid_from` and `exp <= attestor.valid_before`
  (`:unbounded` excepted) — the attestation window is contained in the attestor key window, so
  a retired or rotated-out attestor key cannot backdate an outliving attestation (`exp ==
  valid_before` is containment and accepts: the half-open `now ∈ [nbf, exp)` check already
  prevents acceptance at any instant the key no longer covers);
- the caller-supplied `now` is in `[nbf, exp)`.

The arity-2 form is a named departure from the trust-argument-separation convention of
`verify_grant/3` / `verify_historical_anchor/3`: under the purity contract every parameter is
caller-supplied trusted input, so bundling the attestor into the expected struct is ergonomics
without a trust boundary, the consumer contract is written `/2`, and the confusion attack the
separation would guard is structurally killed by the self-attestation rejection.

The maximum attestation lifetime is caller-owned policy, not a new bound: no `Bounds` field is
added, and the containment check makes the attestor key's `valid_before` the ceiling. The
authority should issue bounded attestor windows; deployments that configure `:unbounded`
attestor windows accept unbounded attestation lifetimes by that choice.

### 5. Facts

`verify_attestation` returns `%AttestationFacts{version: 1, attestor_key_id,
attestor_key_fingerprint, subject_key_id, subject_key_fingerprint, role, jti, nbf, exp,
verification: :signature_and_window, trust: :not_evaluated}` — the anchor-facts posture: a
diagnostic binding carries `trust: :not_evaluated` and no `authorization` marker (critical
rule 1 reserves that marker to grant/envelope/export facts). The enumerated field set is the
facts contract; `version` and other mechanical members ride the language's facts idiom
(Elixir's facts structs all carry one; bindings without such an idiom may omit it). Both fingerprints are RFC 7638
thumbprints derived internally; facts carry no raw key material. `role` is a binary — no
data-bearing atoms in facts results. Facts are value-bearing, redacted (`Inspect`), and never
execution credentials: which attestor to trust, which role a consumer requires, what scope a
deployment accepts, and replay reservation are caller-side. Critical rule 1's facts enumeration
and the repository guide's current-state text are amended in this landing to add
`AttestationFacts`.

The attestation binds a role to a key and to nothing else — no issuer identity, audience, or
scope claim. An attestation is valid wherever its attestor key is trusted; scoping is the
caller's trust configuration. This is a named limitation, not an oversight: neither consumer
document carries or needs a scope member, and a scope claim without a consumer contract is
speculative surface. Future scope claims are new profile schemas with a consumer contract.

### 6. Role vocabulary

The closed role set is exactly `{"issuer", "holder"}` — the protocol's grant-party roles;
product role vocabulary never enters. A `holder` attestation is admission control and
defense-in-depth only; per-grant holder standing remains each grant's `cnf.jkt` binding, and a
`holder` attestation never confers per-grant authority. Role-expectation policy (checking
`role == "issuer"`) belongs to the consumer, which is why `verify_attestation` takes no
expected role and facts carry the attested role for the consumer to gate on.

### 7. Mechanism

The profile is self-contained: a private codec module under the profile namespace
(`RoleAttestation.V1.Codec`, `@moduledoc false`) single-sources the
version-neutral V1 primitives (Json, Jcs, Base64Url, Jwk, StringOrUri, Bounds, FixedBytes,
CompactJws, SigningInput) by alias; the public facade delegates to it. This satisfies ADR
0027 §3's one-implementation-mechanism clause for an artifact with no existing pipeline to
dispatch through. Exactly two V1-tree touches are made, both in the same closed kind
machinery and labeled here: `V1.SigningInput`'s `kind` union gains `| :role_attestation`, and
`V1.CompactJws`'s assembly kind list gains the same atom with an `exact_signing_header?`
clause for the profile header (the loopback-kind precedent; assembly for every existing kind
is byte-unchanged). No existing V1 file's verdicts change; the v1 corpus bytes and certified
pins are unchanged. The architecture boundary gate gains the `RoleAttestation` namespace
allowance in this landing.

The public surface is four functions on the facade: `attestation_signing_input/2` (external
signature only — the package owns no signer and accepts no private key),
`assemble_compact/{2,3}`, `decode_attestation/2` (bounded decode, no trust evaluation), and
`verify_attestation/2`.

### 8. Conformance corpus and mutation gates

The corpus lives at `priv/conformance/attestation-profiles/role-attestation/v1/`
(`profile.json`, `attestation-cases.json`, `index.json`), minted with ephemeral in-memory
Ed25519 keys, no tracked private material. Case families: valid baselines (both roles); the
missing-member matrix (one per payload member); unknown header/payload member; wrong
`typ`/`alg`; `v` deviations (including `1.0` float); role outside the closed set; inverted and
equal windows; wrong `public_key` width; non-canonical JCS bytes; duplicate members; tampered
signatures; wrong attestor `kid`; subject-binding mismatches; the window boundary equalities
(`now == nbf` accept, `now == exp` reject, `nbf == attestor.valid_from` accept,
`exp == attestor.valid_before` accept); self-attestation; window outliving the attestor key;
an ES256-signed confusion case; truncation and base64url defects; and the cross-profile legs
in both directions (attestation bytes rejected by v1/v2/v3 verification surfaces; a live
v1 grant compact rejected by attestation decode).

Certification is the BAP-19 pattern: the corpus index SHA-256 is pinned in the ExUnit suite,
the spec text, and every SDK test; `mix quality` runs the per-profile check script
(`role_attestation.verify`) and the profile's red-capable entries in the shared conformance
mutation battery. The mutation entries are red-capable per named
check (self-attestation rejection ×2, containment ×2, `now` window, kid binding, subject
binding, role closed set, canonical bytes, signature): each injected source defect must turn
at least one corpus case's verdict, reddening the targeted test.

### 9. SDK obligations

The Python, Rust, and Go SDKs (in this repository) implement the four surfaces in this
landing, asserting the certified index SHA-256 against the in-repo corpus at test load
(vendoring the corpus snapshot is the graduation-time posture of ADR 0015), with the applicable
per-language permissiveness legs (duplicate rejection, integer/float tag distinction, lexeme
ceilings). The graduated TypeScript verifier (its own repository per ADR 0015) implements the
surface as a **hard precondition of any `0.x.0` release bearing this profile**, coordinated at
corpus freeze per the ADR 0035 pattern.

### 10. Release evidence

The public evidence for this profile is the certified corpus dual-verified across the Elixir
reference and every SDK plus the red-capable mutation gates. The artifact has no public
transport to drill: its real substrate is issuance-and-consumption across the dependency wall.
Accordingly, the first release bearing this profile additionally requires, as named
preconditions recorded in the roadmap row, the authority-runtime issuance receipt and the
companion-signer consumption receipt from their own private closeouts. Release itself remains
the owner's decision; nothing in this ADR publishes anything.

### 11. Requirement identifiers (ADR 0007 amendment)

ADR 0007's format governs contract-major profiles. This ADR amends it with a second, disjoint
form for sibling profiles: `REQ-<PROFILE>-<SURFACE>-<short-tag>`, where `<PROFILE>` is the
profile's requirement prefix, unique across sibling profiles and disjoint from every major's
`REQ<major>-` range. This profile's range is `REQ-RA1-*` with its own requirement map
([role-attestation requirement map](../design/role-attestation-requirement-map.md)); the
loopback profile's existing `REQ-LLH1-*` range is regularized under this amendment
retroactively. ADR 0007's rationale applies unchanged: these ids are public, third-party
cited, and post-publication irreversible.

## Alternatives considered

- **Activation as contract-major 4.** Rejected: couples an unrelated standalone artifact to
  the charter's five-family successor-major program — the same coupling ADR 0027 rejected a
  transport-only v2 for — and pays the complete-major process (full profile, corpus, REQ
  range, cross-major rules) for an object no major verifier ingests.
- **An extension draft under `docs/extensions/`.** Rejected: extensions are submission drafts
  documenting already-normative profiles; the consumer needs callable code and a certified
  corpus.
- **Generalizing ADR 0027's class by rename ("sibling profiles", same conditions verbatim).**
  Rejected: textually false (the class governs grant-bound proof profiles reusing claim
  mechanics wholesale), launders class conditions instead of re-deriving them, and converts a
  one-member transport-variance precedent into an open signed-artifact pipeline. The
  separately-stated class of Decision 1 is the honest form.
- **A wire fingerprint instead of the raw subject public key.** Rejected: both consumer
  documents carry `public_key`; a fingerprint makes every consumer a thumbprint implementor
  and invites per-language hash-the-wrong-encoding defects.
- **`attestation_id` / `valid_from` / `valid_until` private spellings.** Rejected: a third
  window spelling in a `+jwt` artifact; registered `jti`/`nbf`/`exp` semantics match exactly.
- **SHA-256 over raw key bytes as the fingerprint.** Rejected: not the suite discipline — the
  anchor's fingerprints are RFC 7638 thumbprints (algorithm-bound preimage); raw-byte hashing
  is cross-algorithm confusion material.
- **`authorization: :not_evaluated` in facts.** Rejected: critical rule 1 reserves that marker
  to grant/envelope/export facts; a diagnostic binding carries `trust: :not_evaluated`.
- **A one-sided attestor-window check (the anchor's `inside_window?` at `nbf` only).**
  Rejected: a retired attestor key could backdate `nbf` into its old window with an outliving
  `exp`; containment closes it.
- **Arity 3 with the attestor as a separate argument.** Overruled on review: no security delta
  under the purity contract, against the consumer's written `/2`; recorded as a named
  departure instead.
- **A closed scope/audience claim now.** Rejected: no consumer contract carries one; named
  limitation instead (Decision 5).

## Consequences

- The protocol package gains its first sibling attestation profile: normative spec
  ([`spec/bap-role-attestation-v1.md`](../../spec/bap-role-attestation-v1.md)), the
  `BoundedAuthorityProtocol.RoleAttestation.V1` facade, the certified corpus, the REQ-RA1
  requirement map, registry rows (typ, media type, attestation-profiles family), and the three
  in-repo SDK legs land together; v1/v2/v3 lib, corpora, and certified pins are unchanged
  (the labeled `SigningInput`/`CompactJws` kind touches are the only V1-tree changes).
- Governance, standards-track, registries, and ADR 0027 carry the labeled class amendments;
  the ADR-0007 amendment regularizes profile-scoped requirement ranges.
- The companion signer may now consume BA-issued role attestations as data; the
  authority-runtime issuance direction and the signer's RA11 gate are cross-repo work owned in
  their repositories; the TS verifier surface and the two private receipts are named release
  preconditions.
- Every future signed-artifact family faces an explicit choice — verifier-integration-bound
  (charter family, successor major) or consumer-gated (a sibling class ADR) — stated in text
  rather than implied.
