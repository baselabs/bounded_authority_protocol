# Agent guide history

Text moved byte-for-byte out of [`AGENTS.md`](../../AGENTS.md) on October 28, 2026, when the
workflow was resized to the risk of each change. It is a historical record only; `AGENTS.md`
governs. Links inside the moved text are written relative to the repository root.

## Moved October 28, 2026: former "Read first" section

## Read first

Before work, read this file, [`README.md`](README.md), [`docs/ROADMAP.md`](docs/ROADMAP.md), the accepted decision records, and the stable contracts under [`docs/design/`](docs/design/).

When local process artifacts exist, they are implementation aids, not the remote cold-start
authority. The tracked roadmap, ADR, protocol charter, threat model, and conformance contract
must always be sufficient to regenerate a reviewed implementation plan.

## Moved October 28, 2026: former "Current state" section

Closed: `BAP-00` through `BAP-11`, `BAP-13` through `BAP-19`, and `BAP-21` through `BAP-24`
(`BAP-17` is design-only; `BAP-24`, the strict Ed25519 soundness erratum, closed with the 0.8.0
release). Open: `BAP-12` (IANA filing, gated on the BAP-08 external submission preconditions) and
`BAP-25` (producer-surface signature canonicality, erratum 3, landing for 0.9.0).
Consult [`docs/ROADMAP.md`](docs/ROADMAP.md); its closeout-evidence
blocks are the status authority.

Unreleased source (version 0.9.0, a clarifying minor, erratum 3): compact assembly and
anchored-export encoding refuse a signature no conforming signer emits and never rewrite accepted
bytes (`REQ1/REQ2-SIGNING-ed25519-producer-canonical`, `REQ3-SIGNING-producer-canonical`), with the
additive certified `bap-producer-canonicality/1` corpus (`priv/conformance/producer-canonicality`,
75 cases) and the new public `BoundedAuthorityProtocol.Es256` owner of the ES256 rules
(`canonical_signature?/1`, `acceptable_public_key?/1`, `verify_strict/3`, `normalize_low_s/1`,
`der_to_raw/1`). The Python, Go, Rust, and TypeScript units of erratum 3 are open.

Release 0.8.0 is the strict Ed25519 verification soundness repair
(ADR 0040, erratum 2): rule S1 (canonical
point encodings, no small-order key or `R`, `S < L`, the cofactorless equation) on every Ed25519
surface, owned by the public `BoundedAuthorityProtocol.Ed25519` (`verify_strict/3`,
`acceptable_public_key?/1`, `torsion_free?/1`), with the additive certified strict-Ed25519 corpus
(`priv/conformance/strict-ed25519`, `bap-strict-ed25519/1`, 2,410 cases) and the
soundness-repair governance class. The latest Hex release is 0.8.0, tagged `v0.8.0` (published
October 13, 2026 with its security advisory and read back from the registry; releases 0.1.0
through 0.7.0 are retired), over the 0.7.0 content-assertion release, the 0.6.2 cross-Elixir
repair patch, the 0.6.0 role-attestation release, and the 0.5.0 ES256 contract-major 3
activation. The graduated TypeScript packages are at npm verifier 0.7.0 (browser-safe) and
signer 0.5.0. The
package retains zero production
dependencies, no application callback, and no supervision tree. Contract-major 1 remains frozen;
contract-major 2 is active under `BoundedAuthorityProtocol.V2` with the `lte` and `gte` selector
kinds, its own normative profile, certified 268-case corpus, `REQ2-*` traceability, and
cross-major rejection; contract-major 3 is active under `BoundedAuthorityProtocol.V3` — the
`BAP3-ES256-SHA256` suite (ECDSA P-256/SHA-256, RFC 7518 §3.4 raw `r || s` signatures with
low-S canonicality, EC JWK holder keys, `BAP3-*` separators) with its own normative profile,
certified 292-case corpus, `REQ3-*` traceability, and cross-major rejection of v1 and v2 bytes.
The v1 corpus remains 283 cases across 28 surfaces. The protocol also carries three byte-distinct
sibling profiles parsed by no contract-major: the loopback proof profile
(`bap-application-proof/local-loopback-http/1`, ADR 0027) and the role-attestation profile
(`bap-role-attestation/1`, ADR 0036 — a standalone, grant-unbound BA-signed role binding with
`BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2`, its certified 40-case corpus,
`REQ-RA1-*` ids, and the sibling-attestation governance class; the BARA RA11 prerequisite,
released in 0.6.0 with both consumption receipts recorded), and the content-assertion profile
(`bap-content-assertion/1`, ADR 0037, released in 0.7.0: a standalone, grant-unbound signed
binding of an exact content digest to issuer, audience, lineage subject, semantic profile,
window, and predecessor, with `BoundedAuthorityProtocol.ContentAssertion.V1`, its certified
131/9/14-case corpus, and `REQ-CA1-*` ids). See
ADR 0030,
ADR 0035,
ADR 0036,
ADR 0037, [`spec/bap-v1.md`](spec/bap-v1.md),
[`spec/bap-v2.md`](spec/bap-v2.md), [`spec/bap-v3.md`](spec/bap-v3.md),
[`spec/bap-role-attestation-v1.md`](spec/bap-role-attestation-v1.md), and
[`spec/bap-content-assertion-v1.md`](spec/bap-content-assertion-v1.md).

Unpublished cross-language verifier SDKs are authored under [`sdks/`](sdks/)
(ADR 0014): Python
(`bounded-authority-verifier`), Rust
(`bounded-authority-protocol`, BAP-15), and Go (`bounded_authority_protocol_go`, BAP-16) — each
reimplements the frozen profiles from the specs and corpora alone, passes the certified v1, v2,
and v3 vectors plus the loopback, role-attestation, and content-assertion profile corpora with
every corpus index
SHA-256 asserted at load, and ships a red-capable per-language
permissiveness mutation gate. None of these three is published to a registry. Per
ADR 0015, each graduates to its own per-SDK
repository on first publication, and the `sdk-publish-guard` pre-commit hook and CI job reject
registry-publish infrastructure in this monorepo. The TypeScript SDK was the first to graduate
(2026-09-14): it is published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
from its own repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript)
(vendored corpora, self-contained CI, and two-stage npm publishing). Its source no longer lives in
this monorepo; a corpus rotation is a snapshot-bump commit in that repository.

Design-carrying slices (all zero wire-behavior change on the closed v1 profile): BAP-11
(cryptographic-suite succession and cross-suite evidence longevity,
ADR 0009),
BAP-14 (delegation with attenuation,
ADR 0010), BAP-08 (the MCP capability-authorization
extension drafts under `docs/extensions/`,
ADR 0013), BAP-13 (published governance,
[docs/governance.md](docs/governance.md)), and BAP-17 (the reserved `ba_offline` floor-limit claim
and its activating-major mechanism,
ADR 0016). The BAP-15 hardening-arc contracts are
recorded in ADR 0017 (the inter-SDK behavioral contract), ADR 0018 (the SDK bounds contract), and
ADR 0019 (corpus-artifact distribution), ADR 0020 (bounds-aware assembly and issuer-mediated
reauthorization posture), ADR 0021 (the v1 `all` selector recognized-shapes erratum), ADR 0022
(durable contract identities), and ADR 0027 (byte-distinct application-proof profiles). Accepted
ADRs are 0001–0037 and 0040 (ADR 0040 is the strict Ed25519 soundness erratum; 0038 and 0039
are reserved for designs not yet accepted; ADR 0035 activates the ES256 contract-major 3 suite; ADR 0036 adds the
role-attestation sibling profile; ADR 0037 adds the content-assertion sibling profile; ADR 0029 records the cumulative-budget posture and explicitly defers the
`ba+budget-window` attestation-shape design; ADR 0034 decides the UCP riding point as
transport-composed). BAP-19's source identity is fixed by
`v0.3.0`; the registry publication and checksum read-back closed 2026-08-31, and downstream
immutable-package adoption is tracked in the private runtime.

The companion signer `bounded_authority_report_adapter` 0.10.0 signs this profile over BAP 0.8.0
(`sign_content_assertion/3`). Each consumer's acceptance is tracked by that consumer.

## Moved October 28, 2026: former "Workflow" section

- Stay on `main`; do not create ad-hoc branches or worktrees.
- Never use stash, history rewrites, blanket staging, or destructive cleanup.
- Use Kimosabe for every change. Wire formats, cryptography, verification, canonicalization,
  conformance, and verifier SDK surfaces are T2.
- Write the failing test first. Every security gate requires allow, deny, malformed-input, and
  mutation-red evidence as applicable.
- Run `mix quality` before landing. It is the complete local package, purity, documentation,
  advisory, license, SBOM, and unpacked-consumer gate.
- Update the changelog, roadmap, ADR/design contracts, vectors, and consumer documentation in the
  same landing as a changed public contract.
- Do not claim interoperability from self-round-trips. Normative vectors require an independent
  implementation and exact-byte comparison.
