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
| BAP-00 | Public repository, Apache-2.0 license, Forge boundary, tracked architecture and cold-start authority | — | Complete | Evidence recorded below |
| BAP-01 | Mix package scaffold, pure-library architecture test, quality aliases, public CI, package inspection | BAP-00 | Complete | Evidence recorded below |
| BAP-02 | Normative v1 tables, bounded ordered decoder, strict base64url, untrusted key locator | BAP-01 | Complete | Evidence recorded below |
| BAP-03 | Compact EdDSA grant and RFC 9449 DPoP encode/decode/verify | BAP-02 | Planned | Official and independent vectors; meaningful-byte tamper matrix; timing/allocation bounds; no trust-selection path |
| BAP-04 | Consumption-chain, anchor, archive, and historical public-key verification | BAP-03 | Planned | Rollover, truncation, reorder, omission, archive-coverage, and tamper vectors pass independently |
| BAP-05 | Language-neutral conformance corpus, verifier CLI, property/fuzz/mutation gates | BAP-04 | Planned | A second implementation consumes only published artifacts and agrees on every valid/invalid vector |
| BAP-06 | Stable public API, guides, security policy, docs, immutable release-candidate archive and automation | BAP-05 | Planned | SemVer/API review; docs; reproducible candidate archive; unpacked consumer; checksum/SBOM/provenance gates; not yet published |
| BAP-07 | Connected verification and first public release | BAP-06, private BA-14 | Planned | Exact candidate passes private-runtime PG16/17/18 and RetiredPrivateConsumer connected gates; full public quality/conformance; fresh correctness, security, gate-integrity, and cross-vendor reviews; publish that exact archive with zero open findings |

## BAP-00 closeout evidence

- Public repository is `PUBLIC`; reviewed authority head is `6474c0d` and initial authority commit
  is `9d83914`. This closeout receipt follows those reviewed changes.
- Owning boundaries are pushed and remote-equal at private runtime `dc4f36a`, Beamline `b8767e4`,
  and historical redirect `0e400e7`.
- Beamline documentation tests pass 54/0; formatter and ExDoc gates pass; the changed commercial
  infographic renders over HTTP with both public and private authority tiers.
- Public and private Forge plans verify with 0 errors, 0 warnings; changed local links and
  high-confidence secret scans are clean.
- Independent correctness, security, and documentation lenses are clean after all admitted
  findings were fixed. Public/private cross-vendor findings were fixed and reread; Beamline's GLM
  peer returned no findings. The Beamline Claude peer was unavailable twice because the installed
  CLI reported retired model aliases, so that peer is a named degraded review, not a zero.

## BAP-01 closeout evidence

- Package-bearing closeout head `6d8f807be6f4cc76abc2763754542f1ebe91b5be` is pushed to public
  `main`. [CI run 30227584102](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30227584102)
  passed the complete quality/package boundary, workflow syntax, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30227584100](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30227584100)
  built artifact `8639043791`. Its exact unpublished archive has SHA-256
  `b018ffd134ce7c52a43d655437c6246bb725f3ac2d4b34adf502f4d69a7efcb5`; the downloaded
  `SHA256SUMS` check passed.
- `gh attestation verify` accepted separate SLSA provenance and CycloneDX 1.6 SBOM attestations
  for that exact digest, constrained to this repository, the trusted supply-chain workflow,
  `refs/heads/main`, source digest `6d8f807be6f4cc76abc2763754542f1ebe91b5be`, and
  GitHub-hosted runners.
- Local `mix quality` passed 15 tests with 0 failures and 100.00% coverage, plus format,
  warnings-as-errors compilation, Credo, Dialyzer, documentation, advisory, retired-package,
  license, SBOM, exact archive, and fresh external-consumer gates. The package has zero
  production dependencies, no application callback, and no supervision tree.
- All admitted correctness, security, gate-integrity, and cross-vendor findings were fixed. Final
  Claude and GLM code-delta reviews returned no findings. Workflow actions are pinned to exact
  signed release commits; the Node 20 artifact-action warning was removed and the replacement
  trusted-main run is clean of Node-runtime deprecation warnings.

## BAP-02 closeout evidence

- Package-bearing implementation head `458c5e6914b0ba2ac6afa6170d30fe576cd7c8e5` is pushed to
  public `main`. [CI run 30235354342](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30235354342)
  passed the complete quality/package boundary, workflow syntax, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30235354489](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30235354489)
  built artifact `8641490849`. Its exact unpublished archive has SHA-256
  `591bb037844060e0662a92a6cf93354ccb72d2ca92b6a2fe926e0a8de8bce1ef`; the downloaded
  `SHA256SUMS` check passed.
- `gh attestation verify` accepted separate SLSA provenance and CycloneDX 1.6 SBOM attestations
  for that exact digest, constrained to this repository, the trusted supply-chain workflow,
  `refs/heads/main`, source digest `458c5e6914b0ba2ac6afa6170d30fe576cd7c8e5`, and
  GitHub-hosted runners.
- Local `mix quality` passed 38 tests with 0 failures and 100.00% coverage, plus format,
  warnings-as-errors compilation, Credo, Dialyzer, documentation, advisory, retired-package,
  license, release/tooling SBOM, exact archive, and fresh external-consumer gates. The package
  retains zero production dependencies, no application callback, and no supervision tree.
- The duplicate-member, non-canonical base64url, forbidden-runtime-import, and numeric-schema
  mutation probes each made its owning gate fail before the original was restored. The
  independent review's three findings were fixed and its delta rereview returned no findings.
  Fable, Opus, and GLM cross-vendor reviews all timed out without a verdict; their partial logs
  were mined and contained no actionable finding. They remain named degraded reviews, not
  zero-finding reviews.

## Next action

BAP-02 is complete. BAP-03 remains unstarted and requires its own reviewed Forge slice.
