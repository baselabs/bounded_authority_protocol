# Protocol registries

Authoritative name coordination for the Bounded Authority Protocol, per the
[standards track charter](standards-track.md). Reservation is immediate and cheap. Shared claims,
selector kinds, and suite semantics activate only with a contract-major; a byte-distinct sibling
proof `typ` may activate under the sibling proof-profile class, and a byte-distinct sibling
attestation `typ` under the sibling attestation-profile class (both defined in
[governance](../governance.md)).
The closed-profile posture is unchanged: a conforming verifier rejects every unlisted or
reserved-but-inactive name exactly as it rejects any other unlisted member.

Registry policy: entries are added by a published specification or governance change. `active` means normative in a named closed profile;
`reserved` means the name is held for a specified future purpose and MUST NOT be used for anything
else by any implementation or deployment.

## Cryptographic suites

Naming scheme: `BAP<contract-major>-<signature>-<digest>`.

| Suite | Status | Definition |
|---|---|---|
| `BAP1-Ed25519-SHA256` | active | EdDSA/Ed25519, SHA-256, RFC 8785 JCS, `BAP1-*` domain separators, fixed 32-byte keys / 64-byte signatures, strict Ed25519 verification (rule S1, erratum 2) — the complete contract-major 1 profile ([`spec/bap-v1.md`](../../spec/bap-v1.md)) |
| `BAP2-Ed25519-SHA256` | active | Contract-major 2 ([`spec/bap-v2.md`](../../spec/bap-v2.md)): the same EdDSA/Ed25519, SHA-256, RFC 8785 JCS algorithms under the major-bound naming scheme, `BAP2-*` domain separators, payload `v: 2`, and the `lte`/`gte` selector kinds; strict Ed25519 verification as for major 1 |
| `BAP3-ES256-SHA256` | active | Contract-major 3 ([`spec/bap-v3.md`](../../spec/bap-v3.md)): ECDSA over NIST P-256 with SHA-256 (`alg: "ES256"`, RFC 7518 §3.4 raw `r \|\| s` signatures with the low-S canonicality rule), RFC 8785 JCS, EC JWK holder keys with RFC 7638 thumbprints, uncompressed-SEC1 raw keys, `BAP3-*` domain separators, payload `v: 3`, and the five-kind selector algebra inherited from v2 |
| ML-DSA family (FIPS 204 / RFC 9964) | anticipated | The post-quantum successor candidate family (charter § Cryptographic suite identity): ML-DSA-65 (category 3) baseline, ML-DSA-87 (category 5) higher tier, JOSE mapping per RFC 9964, hybrid Ed25519+ML-DSA composite posture reserved per draft-ietf-jose-pq-composite-sigs (decided at successor definition time); activation successor-major only. The family binds to whichever contract-major activates it — with majors 2 and 3 taken, its anticipated index is the next successor major |

## Claim names

| Claim | Status | Purpose |
|---|---|---|
| `ba_inv` | active | Invocation UUID bound into the holder proof |
| `ba_op` | active | Operation name bound into the holder proof |
| `ba_req` | active | Request digest (`BAP1-REQUEST\0` domain) over `[operation, typed(cast_arguments)]` |
| `ba_dlg` | reserved | Parent-grant hash binding a delegated (attenuated) grant to its parent — charter § Delegation with attenuation; full mechanism charted in the successor-major charter |
| `ba_obo` | reserved | Issuer-asserted on-behalf-of principal identifier (StringOrURI) — charter § Principal binding |
| `ba_offline` | reserved | Issuer-set offline floor limits (maximum value with explicit currency, maximum offline use count, and offline-window expiry) as a closed nested grant-payload object — charter § Revocation and freshness; absence means online-only. Full mechanism (the closed `{cnt, cur, max, win}` object, the facts contract, the `max × cnt` ceiling, the `ba_dlg` attenuation interaction) charted in the successor-major charter; activation is a successor contract-major (the closed v1 profile rejects the name today) |
| `ba_sut` | reserved | Suite-attestation payload binding (chain identity, sequence range, archive content digest, original suite, attestation time, typed suite-parameterized key) — charter § Evidence longevity and cross-suite attestation |

Standard JWT claims used by the profile (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `cnf`, `ath`,
`htm`, `htu`, `nonce`) carry their RFC 7519 / RFC 7638 / RFC 9449 registered meanings.

## `typ` values

<!-- facts:typ-values -->
| Value | Status | Media type | Purpose |
|---|---|---|---|
| `ba+cap` | active | `application/ba-cap+jwt` | Capability grant (compact JWS) |
| `dpop+jwt` | active | registered by RFC 9449 | Holder proof (RFC 9449) |
| `ba+loopback-proof` | active | `application/ba-loopback-proof+jwt` | Literal-loopback HTTP holder proof under `bap-application-proof/local-loopback-http/1` (a sibling application proof profile) |
| `ba+chain-anchor` | active | `application/ba-chain-anchor+jwt` | Signed consumption-chain boundary anchor |
| `ba+role-attestation` | active | `application/ba-role-attestation+jwt` | Signed role attestation binding a subject key to a role under `bap-role-attestation/1` (a sibling attestation profile) |
| `ba+content-assertion` | active | `application/ba-content-assertion+jwt` | Standalone exact-content assertion under `bap-content-assertion/1` (a sibling attestation profile) |
| `ba+key-transition` | active | `application/ba-key-transition+jwt` | Authenticated historical-key transition |
| `ba+cap-delegated` | reserved | `application/ba-cap-delegated+jwt` | Delegated attenuated grant — charter § Delegation with attenuation; full mechanism charted in the successor-major charter |
| `ba+suite-attestation` | reserved | `application/ba-suite-attestation+jwt` | Cross-suite content-covering countersignature — a current-suite key signs the archive's content digest so evidence trust survives the original suite's cryptanalytic break; charter § Evidence longevity and cross-suite attestation |

## Application proof profiles

| Identity | Status | Protected `typ` | Definition |
|---|---|---|---|
| `bap-application-proof/local-loopback-http/1` | active | `ba+loopback-proof` | Exact literal-loopback HTTP proof profile in [`spec/bap-local-loopback-http-v1.md`](../../spec/bap-local-loopback-http-v1.md); the current `dpop+jwt` profile rejects these bytes |

## Attestation profiles

The sibling attestation class ([governance](../governance.md#byte-distinct-sibling-attestation-profiles)): standalone,
grant-unbound signed artifacts verified only through their own named API.

| Identity | Status | Protected `typ` | Definition |
|---|---|---|---|
| `bap-role-attestation/1` | active | `ba+role-attestation` | Role attestation binding a subject key to `issuer` or `holder` for a bounded window, in [`spec/bap-role-attestation-v1.md`](../../spec/bap-role-attestation-v1.md); every contract-major profile rejects these bytes |
| `bap-content-assertion/1` | active | `ba+content-assertion` | Digest-bound context, validity and successor assertions in [`spec/bap-content-assertion-v1.md`](../../spec/bap-content-assertion-v1.md) |

## Selector kinds

| Kind | Status | Semantics |
|---|---|---|
| `all` | active | Matches any argument root |
| `equals` | active | Non-empty object path must exist; tagged semantic identity with the given value |
| `one_of` | active | Non-empty object path must exist; tagged semantic identity with any listed value |
| `lte` | active | Inclusive upper bound — the value at the path must be same-tag numeric and numerically ≤ the bound (comparison on the closed decoder-bounded numeric domain; cross-tag does not match); full mechanism specified in [`spec/bap-v2.md` § 4](../../spec/bap-v2.md#selectors), active in the contract-major 2 closed profile and inherited unchanged by the contract-major 3 closed profile (the contract-major 1 profile rejects the kind) |
| `gte` | active | Inclusive lower bound — the value at the path must be same-tag numeric and numerically ≥ the bound (comparison on the closed decoder-bounded numeric domain; cross-tag does not match); full mechanism specified in [`spec/bap-v2.md` § 4](../../spec/bap-v2.md#selectors), active in the contract-major 2 closed profile and inherited unchanged by the contract-major 3 closed profile (the contract-major 1 profile rejects the kind) |

New selector kinds activate only with a contract-major; candidate kinds are reserved here first so
independent implementations never collide. `lte`/`gte` flipped reserved→active with contract-major 2.
Attenuation (charter § Delegation) adds no kind: it is
the conjunctive composition of existing selectors.

## Operation names

Operation names are issuer-defined, not centrally enumerated. The registry governs the namespace,
not the names: bare names (`read`, `write_record`) are deployment-scoped with no cross-deployment
meaning; cross-vendor interoperable operation vocabularies use reverse-DNS prefixes
(`com.example.billing/refund`). The `ba.` prefix is reserved for protocol-defined operations and
MUST NOT be used by deployments.

## Reserved discovery and status names

| Name | Status | Purpose |
|---|---|---|
| verifier discovery document | reserved | Deployment-published set of accepted contract-majors and suites — charter § The evolution contract; exact name and shape fixed at first external submission |
| grant status-check profile | reserved | Issuer-published revocation/status shape for long-lived grants — charter § Revocation and freshness |

## IANA

`ba_inv`, `ba_op`, `ba_req` (JWT Claims registry) and the `ba+*` media-type suffix values are
filed at first external submission. Until then this document is the
authoritative namespace and the `ba_`/`ba+` prefixes are the collision-avoidance convention.

The media-type column names the RFC 6838 registration (or reservation) associated with each
value — a related but distinct namespace from the wire `typ` itself; the wire values are
unchanged. The ready-to-file human-readable registrations are the [JWT claims](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/iana/jwt-claims.md) and
[media types](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/iana/media-types.md); machine-readable JSON sources live beside each document in the
source archive.
