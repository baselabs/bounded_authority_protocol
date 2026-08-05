# Protocol registries

Authoritative name coordination for the Bounded Authority Protocol, per the
[standards track charter](standards-track.md). Reservation is immediate and cheap; activation of
reserved semantics arrives only with a contract-major. The closed wire posture is unchanged: a
conforming verifier of the current contract-major rejects every reserved-but-inactive name exactly
as it rejects any other unlisted member.

Registry policy: entries are added by ADR. `active` means normative in the current contract-major;
`reserved` means the name is held for a specified future purpose and MUST NOT be used for anything
else by any implementation or deployment.

## Cryptographic suites

Naming scheme: `BAP<contract-major>-<signature>-<digest>`.

| Suite | Status | Definition |
|---|---|---|
| `BAP1-Ed25519-SHA256` | active | EdDSA/Ed25519, SHA-256, RFC 8785 JCS, `BAP1-*` domain separators, fixed 32-byte keys / 64-byte signatures — the complete current [normative profile](../protocol-v1.md) |
| ML-DSA (FIPS 204) successor | anticipated | Named on definition per the scheme (`BAP<contract-major>-ML-DSA-<digest>`); the anticipated parameter sets are ML-DSA-44 (NIST category 2), ML-DSA-65 (category 3), ML-DSA-87 (category 5); hybrid Ed25519+ML-DSA composite evaluated at that time; see [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) and charter § Cryptographic suite identity |

## Claim names

| Claim | Status | Purpose |
|---|---|---|
| `ba_inv` | active | Invocation UUID bound into the holder proof |
| `ba_op` | active | Operation name bound into the holder proof |
| `ba_req` | active | Request digest (`BAP1-REQUEST\0` domain) over `[operation, typed(cast_arguments)]` |
| `ba_dlg` | reserved | Parent-grant hash binding a delegated (attenuated) grant to its parent — charter § Delegation with attenuation |
| `ba_obo` | reserved | Issuer-asserted on-behalf-of principal identifier (StringOrURI) — charter § Principal binding |
| `ba_sut` | reserved | Suite-attestation payload binding (chain identity, sequence range, archive content digest, original suite, attestation time, typed suite-parameterized key) — [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) § 3 |

Standard JWT claims used by the profile (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `cnf`, `ath`,
`htm`, `htu`, `nonce`) carry their RFC 7519 / RFC 7638 / RFC 9449 registered meanings.

## `typ` values

| Value | Status | Purpose |
|---|---|---|
| `ba+cap` | active | Capability grant (compact JWS) |
| `dpop+jwt` | active | Holder proof (RFC 9449) |
| `ba+chain-anchor` | active | Signed consumption-chain boundary anchor |
| `ba+key-transition` | active | Authenticated historical-key transition |
| `ba+cap-delegated` | reserved | Delegated attenuated grant — charter § Delegation with attenuation |
| `ba+suite-attestation` | reserved | Cross-suite content-covering countersignature — a current-suite key signs the archive's content digest so evidence trust survives the original suite's cryptanalytic break; [ADR 0009](../adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) § 3 |

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
