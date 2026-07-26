# bounded_authority_protocol roadmap

**Status authority:** this file
**Architecture authority:** `docs/adr/0001-public-protocol-verifier-boundary.md` and
`docs/design/`
**Implementation authority when present locally:**
`.forge/plans/2026-07-26-bounded-authority-protocol.md`

The public package is deterministic and stateless. No row authorizes a database, key custody,
trusted-key discovery, issuance, live revocation state, replay reservation, execution claims,
evidence writes, archive removal, network client, OTP server, Beamline vocabulary, or QorPay
compatibility.

| Row | Deliverable | Depends on | State | Completion gate |
|---|---|---|---|---|
| BAP-00 | Public repository, Apache-2.0 license, Forge boundary, tracked architecture and cold-start authority | — | In progress | Public/private boundary reconciled across all owning repositories; public `baselabs/bounded_authority_protocol` remote verified; clean review and documentation gates |
| BAP-01 | Mix package scaffold, pure-library architecture test, quality aliases, public CI, package inspection | BAP-00 | Planned | Zero-config compile; workflow syntax; dependency license/advisory checks; archive rejects private/product/runtime dependencies |
| BAP-02 | Closed canonical types, bounds, domain separators, RFC 8785 JCS, request digest | BAP-01 | Planned | Exact-byte independent vectors; duplicate/encoding/limit tests; malformed-input properties; mutation-red proof |
| BAP-03 | Compact EdDSA grant and RFC 9449 DPoP encode/decode/verify | BAP-02 | Planned | Official and independent vectors; meaningful-byte tamper matrix; timing/allocation bounds; no trust-selection path |
| BAP-04 | Consumption-chain, anchor, archive, and historical public-key verification | BAP-03 | Planned | Rollover, truncation, reorder, omission, archive-coverage, and tamper vectors pass independently |
| BAP-05 | Language-neutral conformance corpus, verifier CLI, property/fuzz/mutation gates | BAP-04 | Planned | A second implementation consumes only published artifacts and agrees on every valid/invalid vector |
| BAP-06 | Stable public API, guides, security policy, docs, immutable release-candidate archive and automation | BAP-05 | Planned | SemVer/API review; docs; reproducible candidate archive; unpacked consumer; checksum/SBOM/provenance gates; not yet published |
| BAP-07 | Connected verification and first public release | BAP-06, private BA-14 | Planned | Exact candidate passes private-runtime PG16/17/18 and RetiredPrivateConsumer connected gates; full public quality/conformance; fresh correctness, security, gate-integrity, and cross-vendor reviews; publish that exact archive with zero open findings |

## Next action

Execute `BAP-01` from a freshly reviewed Forge plan. The private runtime may scaffold its
dependency seam after BAP-01; it must not duplicate canonicalization or cryptographic verification.
