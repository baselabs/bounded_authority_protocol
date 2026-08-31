# Protocol registries

Authoritative name coordination for the Bounded Authority Protocol, per the
[standards track charter](standards-track.md). Reservation is immediate and cheap. Shared claims,
selector kinds, and suite semantics activate only with a contract-major; a byte-distinct sibling
proof `typ` may activate under [ADR 0027](../adr/0027-byte-distinct-application-proof-profiles.md).
The closed-profile posture is unchanged: a conforming verifier rejects every unlisted or
reserved-but-inactive name exactly as it rejects any other unlisted member.

Registry policy: entries are added by ADR. `active` means normative in a named closed profile;
`reserved` means the name is held for a specified future purpose and MUST NOT be used for anything
else by any implementation or deployment.

## Cryptographic suites

Naming scheme: `BAP<contract-major>-<signature>-<digest>`.

| Suite | Status | Definition |
|---|---|---|
| `BAP1-Ed25519-SHA256` | active | EdDSA/Ed25519, SHA-256, RFC 8785 JCS, `BAP1-*` domain separators, fixed 32-byte keys / 64-byte signatures — the complete current `normative profile` |
| `BAP2-*` ML-DSA family (FIPS 204 / RFC 9964) | anticipated | The post-quantum successor candidate family per `docs/adr/0026-pq-successor-suite.md`: ML-DSA-65 (category 3) baseline, ML-DSA-87 (category 5) higher tier, JOSE mapping per RFC 9964, hybrid Ed25519+ML-DSA composite posture reserved per draft-ietf-jose-pq-composite-sigs (decided at successor definition time); quantum-readiness statement and revisit triggers recorded there; activation successor-major only (ADR 0009) |

## Claim names

| Claim | Status | Purpose |
|---|---|---|
| `ba_inv` | active | Invocation UUID bound into the holder proof |
| `ba_op` | active | Operation name bound into the holder proof |
| `ba_req` | active | Request digest (`BAP1-REQUEST\0` domain) over `[operation, typed(cast_arguments)]` |
| `ba_dlg` | reserved | Parent-grant hash binding a delegated (attenuated) grant to its parent — charter § Delegation with attenuation; full mechanism specified in [ADR 0010](../adr/0010-delegation-with-attenuation.md) |
| `ba_obo` | reserved | Issuer-asserted on-behalf-of principal identifier (StringOrURI) — charter § Principal binding |
| `ba_offline` | reserved | Issuer-set offline floor limits (maximum value with explicit currency, maximum offline use count, and offline-window expiry) as a closed nested grant-payload object — charter § Revocation and freshness; [offline requirements](offline-authorization-requirements.md) R-BAP-1; absence means online-only. Full mechanism (the closed `{cnt, cur, max, win}` object, the facts contract, the `max × cnt` ceiling, the `ba_dlg` attenuation interaction) specified in [ADR 0016](../adr/0016-offline-eligible-grant-claims.md); activation is a successor contract-major (the closed v1 profile rejects the name today) |
| `ba_sut` | reserved | Suite-attestation payload binding (chain identity, sequence range, archive content digest, original suite, attestation time, typed suite-parameterized key) — [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) § 3 |

Standard JWT claims used by the profile (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `cnf`, `ath`,
`htm`, `htu`, `nonce`) carry their RFC 7519 / RFC 7638 / RFC 9449 registered meanings.

## `typ` values

<!-- facts:typ-values -->
| Value | Status | Media type | Purpose |
|---|---|---|---|
| `ba+cap` | active | `application/ba-cap+jwt` | Capability grant (compact JWS) |
| `dpop+jwt` | active | registered by RFC 9449 | Holder proof (RFC 9449) |
| `ba+loopback-proof` | active | `application/ba-loopback-proof+jwt` | Literal-loopback HTTP holder proof under `bap-application-proof/local-loopback-http/1` ([ADR 0027](../adr/0027-byte-distinct-application-proof-profiles.md)) |
| `ba+chain-anchor` | active | `application/ba-chain-anchor+jwt` | Signed consumption-chain boundary anchor |
| `ba+key-transition` | active | `application/ba-key-transition+jwt` | Authenticated historical-key transition |
| `ba+cap-delegated` | reserved | `application/ba-cap-delegated+jwt` | Delegated attenuated grant — charter § Delegation with attenuation; full mechanism specified in [ADR 0010](../adr/0010-delegation-with-attenuation.md) |
| `ba+suite-attestation` | reserved | `application/ba-suite-attestation+jwt` | Cross-suite content-covering countersignature — a current-suite key signs the archive's content digest so evidence trust survives the original suite's cryptanalytic break; [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) § 3 |

## Application proof profiles

| Identity | Status | Protected `typ` | Definition |
|---|---|---|---|
| `bap-application-proof/local-loopback-http/1` | active | `ba+loopback-proof` | Exact literal-loopback HTTP proof profile in [`spec/bap-local-loopback-http-v1.md`](../../spec/bap-local-loopback-http-v1.md); the current `dpop+jwt` profile rejects these bytes |

## Selector kinds

| Kind | Status | Semantics |
|---|---|---|
| `all` | active | Matches any argument root |
| `equals` | active | Non-empty object path must exist; tagged semantic identity with the given value |
| `one_of` | active | Non-empty object path must exist; tagged semantic identity with any listed value |

New selector kinds activate only with a contract-major; candidate kinds are reserved here first so
independent implementations never collide. Attenuation (charter § Delegation) adds no kind: it is
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
filed at first external submission (roadmap row BAP-12). Until then this document is the
authoritative namespace and the `ba_`/`ba+` prefixes are the collision-avoidance convention.

The media-type column names the RFC 6838 registration (or reservation) associated with each
value — a related but distinct namespace from the wire `typ` itself; the wire values are
unchanged. The ready-to-file human-readable registrations are the [JWT claims](iana/jwt-claims.md) and
[media types](iana/media-types.md); machine-readable JSON sources live beside each document in the
source archive.
