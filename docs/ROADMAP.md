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

<!-- forge-roadmap-schema: 1 -->
| ID | What | Acceptance | Depends | Why |
|---|---|---|---|---|
| BAP-00 | **Public authority boundary** — Public repository, Apache-2.0 license, Forge boundary, tracked architecture, and cold-start authority, slug:bap-00 | Evidence recorded below | — | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) |
| BAP-01 | **Pure Mix package** — Mix package scaffold, pure-library architecture test, quality aliases, public CI, and package inspection, slug:bap-01 | Evidence recorded below | BAP-00 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) |
| BAP-02 | **Normative bounded parsing** — Normative v1 tables, bounded ordered decoder, strict base64url, and untrusted key locator, slug:bap-02 | Evidence recorded below | BAP-01 | [ADR 0002](adr/0002-normative-v1-parsing-profile.md) |
| BAP-03 | **Grant and holder-proof verification** — Standard compact EdDSA grant and RFC 9449 DPoP production, bounded decode, standalone raw-grant verification, and combined raw-envelope verification, slug:bap-03 | Official and independently verified public-only vectors; exact key census; meaningful-byte tamper matrix; timing/allocation bounds; value-bearing redacted non-authorizing facts; no trust-selection or forgeable-intermediate path | BAP-02 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md), [ADR 0003](adr/0003-standard-jws-and-verified-grant-results.md), and the [normative v1 profile](protocol-v1.md) |
| BAP-04 | **Chain and historical-key verification** — Consumption-chain, anchor, archive, and historical public-key verification, slug:bap-04 | Rollover, truncation, reorder, omission, archive-coverage, and tamper vectors pass independently | BAP-03 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [normative v1 profile](protocol-v1.md) |
| BAP-05 | **Portable conformance** — Language-neutral conformance corpus, verifier CLI, and property, fuzz, and mutation gates, slug:bap-05 | A second implementation consumes only published artifacts and agrees on every valid and invalid vector | BAP-04 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-06 | **Release-candidate contract** — Stable public API, guides, security policy, documentation, immutable release-candidate archive, and automation, slug:bap-06 | SemVer/API review; docs; reproducible candidate archive; unpacked consumer; checksum/SBOM/provenance gates; not yet published | BAP-05 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-07 | **Connected verification and release** — Connected verification and first public release, slug:bap-07 | Exact candidate passes private-runtime PG16/17/18 and RetiredPrivateConsumer connected gates; full public quality/conformance; fresh correctness, security, gate-integrity, and cross-vendor reviews; publish that exact archive with zero open findings | BAP-06, private BA-14 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |

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

- Final verification receipt head `893680f501d39371c7f1f1f630d8e8e92cd35cf8` is pushed to
  public `main`. [CI run 30242449363](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30242449363)
  and [supply-chain run 30242449390](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30242449390)
  passed at that exact source revision.
- Package-bearing implementation head `ad80fcf9201c12010f1fed494224987e7be4b283` is pushed to
  public `main`. [CI run 30240151612](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30240151612)
  passed the complete quality/package boundary, workflow syntax, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30240151614](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30240151614)
  built artifact `8643000730`. Its exact unpublished archive has SHA-256
  `a5fac847517c093f6da0cd27da0a095a6377362219eb8287eb6affe1cedccb36`; the downloaded
  `SHA256SUMS` check passed.
- `gh attestation verify` accepted separate SLSA provenance and CycloneDX 1.6 SBOM attestations
  for that exact digest, constrained to this repository, the trusted supply-chain workflow,
  `refs/heads/main`, source digest `ad80fcf9201c12010f1fed494224987e7be4b283`, and
  GitHub-hosted runners.
- Local `mix quality` passed 45 tests with 0 failures and 100.00% coverage, plus format,
  warnings-as-errors compilation, Credo, Dialyzer, documentation, advisory, retired-package,
  license, release/tooling SBOM, exact archive, and fresh external-consumer gates. The package
  retains zero production dependencies, no application callback, and no supervision tree.
- Raw-number, duplicate-member, exact-bound, non-canonical base64url, forbidden-runtime-import,
  release-SBOM, and numeric-schema mutation probes each made its owning gate fail before the
  original was restored. Independent design, gate-integrity, and security/correctness reviews
  returned no findings after every admitted same-slice finding was fixed.
- The earlier closeout account reported a no-finding GLM result and two timed-out Claude peers.
  A 2026-07-27 exact-range reconciliation supersedes that peer account: Claude fable completed a
  review and identified two admitted gaps—focused escape-tracking mutation proof and
  positive-integer bound wording—while GLM timed out without a verdict. Both gaps are fixed in
  the authority-alignment landing. The aggregate remains a named degraded review, not a
  zero-finding cross-vendor review.

## BAP-03 closeout evidence

- Package-bearing closeout head `f322e08bba665374599b9f53c362966b6b59710a` is pushed to public
  `main`. [CI run 30331438234](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30331438234)
  passed workflow syntax, the complete quality/package boundary, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30331438252](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30331438252)
  built artifact `8677580246`. Its exact unpublished archive has SHA-256
  `2f09d66c68e3538aa1e0020710d7f2aaca07528ef60fcf571c5006212e3bf056`; the downloaded
  `SHA256SUMS` check passed. Separate SLSA provenance and CycloneDX SBOM attestations verified for
  that digest, constrained to this repository, the trusted supply-chain workflow, and source
  digest `f322e08bba665374599b9f53c362966b6b59710a`.
- Implementation head `49a9781a8e408c29b12dcd6870d24f61a59f5ed2`, followed by supported
  Elixir compiler-compatibility fixes through the closeout head, adds deterministic standard
  compact-JWS grant and RFC 9449 proof production, bounded raw decode, standalone grant
  verification, and combined raw-envelope verification without trust selection, state, signing,
  or operational authority.
- Post-review `mix quality` passed 116 tests with 0 failures and 100.00% coverage, plus format,
  warnings-as-errors compilation, exact source/BEAM architecture accounting, Credo, Dialyzer,
  documentation, advisory, retired-package, license, CycloneDX, exact archive, and fresh
  unpacked-consumer gates. The package has zero production dependencies, no application callback,
  and no supervision tree; `:crypto` is its only runtime OTP application.
- The independent Node verifier passed one vector, four exact public-key fingerprints, seven
  meaningful-byte tamper cases, one duplicate-member case, and eighteen URI cases. The portable
  worst-of-20 resource gate passed decode, verification, envelope, and maximum-invalid-input
  timing, reduction, and heap-growth bounds.
- The single bounded final review admitted five findings: signing-input revalidation, callback-gate
  accounting, scalar JWT audience support, StringOrURI enforcement, and proof-check ordering. All
  five were fixed in one pass; affected tests, architecture, independent verification, and the
  complete quality gate then passed. No further review recursion was run.

## Next action

BAP-03 is complete. BAP-04 chain and historical-key verification is next.
