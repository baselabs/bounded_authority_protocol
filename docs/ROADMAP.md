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
| BAP-04 | **Chain and historical-key verification** — Consumption-chain, anchor, archive, and historical public-key verification, slug:bap-04 | Rollover, truncation, reorder, omission, archive-coverage, and tamper vectors pass independently | BAP-03 | [ADR 0004](adr/0004-consumption-chain-rollover-and-anchored-export-verification.md) and the [normative v1 profile](protocol-v1.md) |
| BAP-05 | **Portable conformance** — Language-neutral conformance corpus, verifier CLI, and property, fuzz, and mutation gates, slug:bap-05 | A second implementation consumes only published artifacts and agrees on every valid and invalid vector | BAP-04 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-06 | **Release-candidate contract** — Stable public API, guides, security policy, documentation, immutable release-candidate archive, and automation, slug:bap-06 | SemVer/API review; docs; reproducible candidate archive; unpacked consumer; checksum/SBOM/provenance gates; not yet published | BAP-05 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-07 | **Connected verification and release** — Connected verification and first public release, slug:bap-07 | Exact candidate passes private-runtime PG16/17/18 and RetiredPrivateConsumer connected gates; full public quality/conformance; fresh correctness, security, gate-integrity, and cross-vendor reviews; publish that exact archive with zero open findings | BAP-06, BAP-10, BAP-11, private BA-14 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md), [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md), and the [conformance contract](design/conformance-contract.md) |
| BAP-08 | **Capability-authorization extension proposal** — Draft capability-authorization extension for the MCP `modelcontextprotocol/ext-auth` extensions repository plus an AP2 mandate-mapping note, documenting the already-normative v1 protocol (no wire-format, limit, or verification-rule change), slug:bap-08 | Extension document conforms to the ext-auth repository's submission requirements; every referenced mechanism cites the [normative v1 profile](protocol-v1.md) (nothing normative is introduced outside it); the AP2 note maps mandate↔grant correspondences without claiming compatibility not yet verified; its own ADR lands before any external submission | BAP-04 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) |
| BAP-09 | **Cross-language verifier SDKs** — Thin TypeScript and Python verifier SDKs consuming only the published spec, vectors, and conformance corpus (client libraries of the extension; independent second implementations by design), slug:bap-09 | Each SDK passes every valid and invalid published vector; spec + vectors are the only inputs (no code-level derivation from the Elixir implementation); its own ADR at authoring covers packaging and support surface | BAP-05 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-10 | **Evolution contract and normative conformance language** — RFC 2119/8174 rewrite of the normative profile with stable requirement identifiers, plus the evolution-contract sections (self-declaration, parallel-major support, deprecation windows) and registry reconciliation, slug:bap-10 | Every MUST maps to at least one conformance applicability cell (surface × class) or a named falsifiable gap, with the mapping published; no wire byte, bound, or verdict changes; [standards-track.md](design/standards-track.md) and [registries.md](design/registries.md) reconciled against the rewritten profile | BAP-05 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-11 | **Cryptographic suite identity and evidence longevity** — Suite naming made explicit throughout the docs, the ML-DSA successor-suite path outlined, and the cross-suite countersignature design for aged evidence carried to ADR quality, slug:bap-11 | Suite identity stated in the normative profile and registries with zero wire change; the countersignature design specifies verification of archives whose original suite is no longer trusted, reusing the authenticated key-transition mechanism; reviewed as a design, not implemented | BAP-04 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-12 | **IANA registration templates** — Registration templates for the `ba_*` JWT claims and `ba+*` media-type values, ready to file at first external submission, slug:bap-12 | Templates conform to the target registries' submission formats; claims/values match [registries.md](design/registries.md) exactly, including reserved entries marked as such; filing itself is coordinated with the BAP-08 submission | BAP-08 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) |
| BAP-13 | **Published governance** — Change-control, errata, deprecation, and security-release policy published as normative project documents, slug:bap-13 | Change classes, comment-window and change-control-group triggers, the errata verdict-flip prohibition, and the deprecation windows are published verbatim from the charter; SECURITY.md cross-references them; the errata registry is live | BAP-05 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-14 | **Delegation-with-attenuation contract design** — The chained attenuated-grant design (parent-hash binding via reserved `ba_dlg`, attenuation-only subset rules over the existing conjunctive selector algebra, no caveat DSL) carried to a full successor-contract specification, slug:bap-14 | Complete claim schema, chain-verification algorithm with depth bounds, and subset-decision rules specified; attenuation proven decidable against the existing selector algebra; explicitly no change to the current contract-major's bytes or verdicts; its ADR supersedes nothing and activates nothing | BAP-10 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |

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

## BAP-04 closeout evidence

- Package-bearing closeout head `c4d7716de6499f29524e60638207b1c36e9484b3` is pushed to public
  `main`. [CI run 30414161666](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30414161666)
  passed workflow syntax, the complete quality/package boundary, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30414161690](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30414161690)
  built artifact `8709707133`. Its exact unpublished archive has SHA-256
  `b947777a512e0e917eb42aa85fc9525087f1e555c0eba1944832431a8978a169`; the downloaded
  `SHA256SUMS` check passed. Separate SLSA provenance and CycloneDX SBOM attestations verified for
  that digest, constrained to this repository, the trusted supply-chain workflow,
  `refs/heads/main`, source digest `c4d7716de6499f29524e60638207b1c36e9484b3`, and
  GitHub-hosted runners.
- Implementation head `b48656c6942c0fe359032781c6a5d5161d9d3d82`, followed only by
  supported-compiler compatibility corrections through the package-bearing head, delivers
  canonical consumption rows and range verification, signed boundary anchors, authenticated
  historical-key rollover, deterministic anchored-export framing, and atomic raw-archive
  verification against mandatory caller boundaries, complete digest, exact EOF, every row, and
  the out-of-band object version.
- Post-review `mix quality` passed twice with 159 tests, 0 failures, and 100.00% coverage, plus
  format, warnings-as-errors compilation, exact source/BEAM architecture accounting, Credo,
  Dialyzer, documentation, advisory, retired-package, license, CycloneDX, exact archive, and
  fresh unpacked-consumer gates. The isolated mutation battery passed 47/47. The independent Node
  verifiers proved three archive cases, two direct chain cases, two boundary adversaries, eleven
  exact imported public-key fingerprints, 49 tamper cases, and seven semantic-edge cases.
- The maximum-shape resource gate exercised 65,536 rows, 256 key transitions, 65,796 chunks, and a
  45,188,751-byte archive across isolated worst-of-20 samples. The admitted review findings were
  fixed in bounded deltas; the final permitted delta review was clean, and the plan-integrity
  reconciliation confirmed all 39 implementation claims. Its eight then-open closeout receipts
  are the gates recorded above. The final cross-vendor pass was degraded, not reported as a zero:
  GLM returned no findings after running compile, 159 tests, Credo, and Dialyzer; Claude fable and
  pinned Opus were unavailable because their usage limits were exhausted. No further product
  review recursion was run.

## BAP-05 closeout evidence

- Package-bearing closeout head `ce20a8b12e7b715f5373a72763e46adff7b3e30f` is pushed to public
  `main`. [CI run 30918991087](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30918991087)
  passed workflow syntax, the complete quality/package boundary, and all supported pairs:
  Elixir 1.18.4/OTP 27.3.4.14, Elixir 1.19.5/OTP 28.5.0.3, and Elixir
  1.20.2/OTP 29.0.3.
- [Supply-chain run 30918990587](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30918990587)
  built artifact `8896780979`. Its exact unpublished archive has SHA-256
  `dd0a17eada43f1f60c8f2f23f92575dd4f995a02d93043b1ac097bb954f936df`; the downloaded
  `SHA256SUMS` check passed. `gh attestation verify` accepted separate SLSA provenance and
  CycloneDX 1.6 SBOM attestations for that digest, constrained to this repository, the trusted
  supply-chain workflow (`refs/heads/main`), source digest `ce20a8b12e7b715f5373a72763e46adff7b3e30f`,
  and GitHub-hosted runners.
- Implementation head `53c4590` (followed by supported-compiler compatibility corrections and an
  extended runner-hardening arc through the package-bearing head) delivers the portable v1
  conformance corpus (259 cases across 28 surfaces with a total applicability matrix), the
  deterministic verifier CLI (escript, `--corpus` required, exits 0/1/2, exact-path purity
  carve-out), the independent Node second-implementation runner (node:* only — the corpus is
  normative), a three-partition public-key census (hard two-way), stream_data property and
  deterministic-PRNG fuzz gates, and a source-isolated mutation battery wired into `mix quality`
  ([ADR 0005](adr/0005-portable-conformance-corpus-and-verifier-cli.md)). The corpus ships in the
  published package and the fresh-consumer check runs the packaged escript against the packaged
  corpus.
- The corpus and runner were hardened across multiple bounded deltas after their first closeout
  pass: the `check_envelope` selector-binding vacuity and its `ba_op`/CNF/operation-name
  companions were closed, and every independent-runner permissiveness residual against the official
  decoder was mirrored (StringOrURI structure, optional proof nonce, payload-field decode,
  selector-value magnitude, JSON bounds, request-digest typed projection). The committed corpus
  count (259) is reconciled in `README.md`, this roadmap, and
  [`docs/design/conformance-contract.md`](design/conformance-contract.md).
- Local `mix quality` passes with 295 tests and 13 properties (0 failures), plus format,
  warnings-as-errors compilation, exact architecture accounting, Credo, Dialyzer, documentation,
  advisory, retired-package, license, CycloneDX, exact archive, fresh unpacked-consumer,
  chain-archive mutation (47/47), conformance mutation (55/55), and conformance-verify gates. The
  conformance runner reports `agreed=259, agreement=true, disagreed=0`. The package retains zero
  production dependencies, no application callback, and no supervision tree.

## BAP-10 closeout evidence

- The slice spans `a495808` (ADR 0007) through `1ad8e44` (closeout fix); the full deliverable set is
  collectively present from `57fb3a2` (Task 5, the requirement map), with the closeout-evidence block
  itself landing at `ee873a7` and a structural closeout fix at `1ad8e44`. The slice delivers the
  RFC 2119/8174 normative rewrite of the profile and evolution contract, the stable requirement-
  identifier scheme, and the MUST-to-conformance-cell traceability map:
  - `docs/protocol-v1.md` carries the BCP 14 boilerplate (verbatim RFC 8174 §2 NEW sentence, all 11
    keywords incl. NOT RECOMMENDED, the "when, and only when, they appear in all capitals" clause)
    and **76 stable requirement identifiers** (`REQ1-<SURFACE>-<tag>`, per
    [ADR 0007](adr/0007-normative-requirement-identifiers.md)) across 13 surfaces.
  - `docs/design/standards-track.md` evolution-contract sections carry **10 `REQ1-EVO-*` ids** and a
    BCP 14 reference note.
  - `docs/design/requirement-map.md` (the [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md)
    §3 acceptance artifact) maps all 86 requirement ids to conformance cells: 45 distinct populated
    `(surface, class)` cells (all mechanically verified to resolve to integer≥1 values in
    `index.json`), and 9 `gap` rows each carrying a falsifiable input-algebra reason (the
    [ADR 0005](adr/0005-portable-conformance-corpus-and-verifier-cli.md) n_a criterion applied as the
    gap gate). The closed-rejection profile invariant (`REQ1-CORE-reject-unlisted`) is the one
    profile-level gap — proven by the union of the per-surface closed-set cells it rationalizes.
  - [ADR 0007](adr/0007-normative-requirement-identifiers.md) records the requirement-ID format
    decision: `REQ<contract-major>-<SURFACE>-<tag>`, major-namespaced to mirror the existing suite
    scheme (`BAP<contract-major>-<sig>-<digest>`) and resolve the parallel-majors ambiguity. Refines
    ADR 0006 §3 (does not supersede the RFC 2119/8174 + stable-id + MUST-to-cell bar).
- The slice was driven under forge T2: a fresh-context design-adversarial pass raised 9 challenges,
  all admitted and folded in (the ADR-0007 escalation is the resolution of the "no ADR owed"
  rubber-stamp the pass defeated; the major-namespacing resolves the parallel-majors ambiguity; the
  three-state mapping schema and gap gate resolve the n/a-cell conflation and unfalsifiable-gap
  escape; the mapping covers standards-track.md's evolution-contract MUSTs). A fresh-context
  plan-review raised 3 findings, 2 fixed in-plan (boilerplate content-fidelity verification,
  surface-name translation); 1 (AGENTS.md BAP-05 staleness) routed to a separate T0 commit.
- **No wire byte, bound, or verdict change.** `git diff 4080b9f..HEAD -- lib/ test/ priv/ mix.lock`
  is empty. Local `mix quality` passes with 295 tests and 13 properties (0 failures) and the
  conformance runner reports `agreed=259, agreement=true, disagreed=0` — unchanged from the BAP-05
  baseline. `mix.exs` is touched only for the ExDoc `extras` registration of ADR 0007 and the
  requirement map (docs-build registration, not a wire/code change). Registries reconciliation found
  no drift (`docs/design/registries.md` unchanged).

## Next action

BAP-04, BAP-05, and BAP-10 are complete. BAP-05 shipped the portable v1 conformance corpus (259
cases across 28 surfaces, total applicability matrix), the deterministic verifier CLI (escript,
`--corpus` required, exits 0/1/2) with an exact-path purity carve-out, the independent Node
second-implementation runner (node:* only — the corpus is normative), a three-partition
public-key census (hard two-way), stream_data property + deterministic-PRNG fuzz gates, and a
source-isolated mutation battery wired into `mix quality` (ADR 0005). The corpus ships
in the published package and the fresh-consumer check runs the packaged escript against the
packaged corpus. BAP-10 shipped the RFC 2119/8174 normative rewrite of the profile and evolution
contract, the major-namespaced requirement-identifier scheme (ADR 0007), and the MUST-to-cell
traceability map.

The standards track charter (ADR 0006, [standards-track.md](design/standards-track.md)) now
governs what ships before first publication: BAP-11 (suite identity + evidence longevity design)
gates BAP-07 alongside BAP-06, because neither can be retrofitted after third parties implement the
profile. BAP-12 (IANA templates) and BAP-13 (published governance) ride the BAP-08 external
submission path; BAP-14 carries the already-decided delegation design to a full successor-contract
specification. BAP-06 (release-candidate contract) and BAP-11 are next.
