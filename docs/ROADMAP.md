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
| BAP-07 | **Connected verification and release** — Connected verification and first public release, slug:bap-07 | Exact candidate passes private-runtime PG16/17/18 and private_consumer connected gates; full public quality/conformance; fresh correctness, security, gate-integrity, and cross-vendor reviews; publish that exact archive with zero open findings | BAP-06, BAP-10, BAP-11, private BA-14 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md), [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md), and the [conformance contract](design/conformance-contract.md) |
| BAP-08 | **Capability-authorization extension proposal** — Draft capability-authorization extension for the MCP `modelcontextprotocol/ext-auth` extensions repository plus an AP2 mandate-mapping note, documenting the already-normative v1 protocol (no wire-format, limit, or verification-rule change), slug:bap-08 | Extension document conforms to the ext-auth repository's submission requirements (closed on **partial** conformance — every in-repo-reachable requirement met; full official-track conformance gated on external preconditions [reference SDK, WG + Extension Maintainers + sponsor, SEP acceptance, IANA registration]; see [ADR 0013](adr/0013-capability-authorization-extension.md) and the BAP-08 closeout evidence below); every referenced mechanism cites the [normative v1 profile](protocol-v1.md) (nothing normative is introduced outside it); the AP2 note maps mandate↔grant correspondences without claiming compatibility not yet verified; its own ADR lands before any external submission | BAP-04 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) |
| BAP-09 | **Cross-language verifier SDKs** — Thin TypeScript and Python verifier SDKs consuming only the published spec, vectors, and conformance corpus (client libraries of the extension; independent second implementations by design), slug:bap-09 | Each SDK passes every valid and invalid published vector; spec + vectors are the only inputs (no code-level derivation from the Elixir implementation); its own ADR at authoring covers packaging and support surface | BAP-05 | [ADR 0001](adr/0001-public-protocol-verifier-boundary.md) and the [conformance contract](design/conformance-contract.md) |
| BAP-10 | **Evolution contract and normative conformance language** — RFC 2119/8174 rewrite of the normative profile with stable requirement identifiers, plus the evolution-contract sections (self-declaration, parallel-major support, deprecation windows) and registry reconciliation, slug:bap-10 | Every MUST maps to at least one conformance applicability cell (surface × class) or a named falsifiable gap, with the mapping published; no wire byte, bound, or verdict changes; [standards-track.md](design/standards-track.md) and [registries.md](design/registries.md) reconciled against the rewritten profile | BAP-05 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-11 | **Cryptographic suite identity and evidence longevity** — Suite naming made explicit throughout the docs, the ML-DSA successor-suite path outlined, and the cross-suite countersignature design for aged evidence carried to ADR quality, slug:bap-11 | Suite identity stated in the normative profile and registries with zero wire change; the countersignature design specifies verification of archives whose original suite is no longer trusted, reusing the authenticated key-transition mechanism; reviewed as a design, not implemented | BAP-04 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-12 | **IANA registration templates** — Registration templates for the `ba_*` JWT claims and `ba+*` media-type values, ready to file at first external submission, slug:bap-12 | Templates conform to the target registries' submission formats; claims/values match [registries.md](design/registries.md) exactly, including reserved entries marked as such; filing itself is coordinated with the BAP-08 submission | BAP-08 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) |
| BAP-13 | **Published governance** — Change-control, errata, deprecation, and security-release policy published as normative project documents, slug:bap-13 | Change classes, comment-window and change-control-group triggers, the errata verdict-flip prohibition, and the deprecation windows are published verbatim from the charter; SECURITY.md cross-references them; the errata registry is live | BAP-05 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-14 | **Delegation-with-attenuation contract design** — The chained attenuated-grant design (parent-hash binding via reserved `ba_dlg`, attenuation-only subset rules over the existing conjunctive selector algebra, no caveat DSL) carried to a full successor-contract specification, slug:bap-14 | Complete claim schema, chain-verification algorithm with depth bounds, and subset-decision rules specified; attenuation proven decidable against the existing selector algebra; explicitly no change to the current contract-major's bytes or verdicts; its ADR supersedes nothing and activates nothing | BAP-10 | [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) and the [standards track charter](design/standards-track.md) |
| BAP-15 | **Rust verifier SDK** — A typed Rust verifier SDK reimplementing the frozen v1 profile from spec + corpus alone (no code-level derivation from the Elixir reference), authored under `sdks/rust/` and graduating to a per-SDK repository on first publication ([ADR 0015](adr/0015-sdk-graduation-and-publish-topology.md)), slug:bap-15-rust-sdk | Passes all 283 conformance vectors from a vendored corpus snapshot with startup SHA-256 assertion; per-language permissiveness mutation-gate (duplicate-reject, null-prototype-equivalent, raw-lexeme 64-byte ceiling, single-value/trailing, int/float tag distinction) each proven red-capable; purity lint (no I/O/clock/RNG/network in the library path); dependency-license gate; a deployment guide covering AWS Lambda (`provided.al2023`) and PostgreSQL `plrust` binding; NOT in the Hex `files:` list | BAP-05, BAP-09 | [ADR 0014](adr/0014-cross-language-verifier-sdks.md) and [ADR 0015](adr/0015-sdk-graduation-and-publish-topology.md) |
| BAP-16 | **Go verifier SDK** — A typed Go verifier SDK reimplementing the frozen v1 profile from spec + corpus alone (stdlib `crypto/ed25519` + `crypto/sha256`, zero crypto dependencies), authored under `sdks/go/` and graduating to a per-SDK repository on first publication ([ADR 0015](adr/0015-sdk-graduation-and-publish-topology.md)), slug:bap-16-go-sdk | Passes all 283 conformance vectors from a vendored corpus snapshot with startup SHA-256 assertion; per-language permissiveness mutation-gate (duplicate-reject, raw-lexeme 64-byte ceiling, single-value/trailing, int/float tag distinction) each proven red-capable; purity vet (no I/O/clock/RNG/network in the library path); dependency-license gate; NOT in the Hex `files:` list | BAP-05, BAP-09 | [ADR 0014](adr/0014-cross-language-verifier-sdks.md) and [ADR 0015](adr/0015-sdk-graduation-and-publish-topology.md) |
| BAP-17 | **Offline-eligible grant claims (reserve + specify)** — Reserve the `ba_offline` floor-limit claim name and carry the activating-major mechanism to ADR quality (the closed v1 profile rejects the name today; activation is a successor contract-major), slug:bap-17 | `ba_offline` reserved in [registries](design/registries.md); [ADR 0016](adr/0016-offline-eligible-grant-claims.md) specifies the closed `{cnt, cur, max, win}` object, the facts contract (flag + `win` only; magnitudes from the decoded grant), malformed⇒`:invalid`, the `max × cnt` wire-layer ceiling, the `ba_dlg` attenuation composition, and the freshness scoping; the R-BAP-2 legacy-rejection tripwire is red-capable; **zero wire-behavior change** — `git diff <base>..HEAD -- lib/ docs/protocol-v1.md priv/conformance/` is empty (mirror BAP-11/BAP-14; the cross-implementation corpus vector is deferred to the activating major per ADR 0010:286-289) | BAP-10 | [ADR 0016](adr/0016-offline-eligible-grant-claims.md), [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md), and the [offline requirements](design/offline-authorization-requirements.md) |

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
  conformance corpus (283 cases across 28 surfaces with a total applicability matrix), the
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
  count (283) is reconciled in `README.md`, this roadmap, and
  [`docs/design/conformance-contract.md`](design/conformance-contract.md).
- Local `mix quality` passes with 295 tests and 13 properties (0 failures), plus format,
  warnings-as-errors compilation, exact architecture accounting, Credo, Dialyzer, documentation,
  advisory, retired-package, license, CycloneDX, exact archive, fresh unpacked-consumer,
  chain-archive mutation (47/47), conformance mutation (55/55), and conformance-verify gates. The
  conformance runner reports `agreed=283, agreement=true, disagreed=0`. The package retains zero
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

## BAP-06 closeout evidence

- The slice spans `7f4cdd1` (Task 1, the reproducibility gate) through this closeout block. It
  delivers the 0.1.0 release-candidate contract: the locked public API surface, the reproducibility
  gate, and the candidate-facing docs.
  - [ADR 0008](adr/0008-release-candidate-contract.md) records the API-lock + reproducibility-gate
    decision: the locked surface is enforced mechanically by the existing
    `@compiled_export_allowances` pin in `tools/architecture_gate.exs` (lines 188-207 pin every
    `V1` façade export, including the corrected `verify_key_transition/4` arity and the five producer
    functions), enumerated for readers in [the release-candidate contract](release-candidate-contract.md);
    the pre-1.0 SemVer convention (0.x.y may break, the lock identifies the intended 1.0.0 surface);
    and the cache-isolated two-build reproducibility gate.
  - `scripts/check_release_candidate.exs` builds the candidate archive twice with `_build`/`deps`
    purged between builds and asserts byte-identical SHA-256, scoped honestly as "two independent
    builds agree" (regression detection, not a shared-cache self-comparison — the design-adversarial
    Challenge 3 overclaim, defeated). The red-capable proof at authoring confirmed a source-byte
    difference between builds makes the gate exit non-zero. Wired into `mix quality` via the
    `release.candidate` alias.
  - [release-candidate-contract.md](release-candidate-contract.md) is the candidate-facing doc (API
    lock + SemVer posture + verification recipe, explicitly NOT an authority shape — AGENTS rule 1).
- **No wire byte, bound, or verdict change.** `git diff 46a7eb1..HEAD -- lib/ test/ priv/conformance/
  mix.lock` is empty. Local `mix quality` passes with 295 tests and 13 properties (0 failures), the
  conformance runner reports `agreed=259, agreement=true, disagreed=0`, and the new
  `release.candidate` gate passes.
- **Remote verification (post-push receipt):** [CI run 31029289860](https://github.com/baselabs/bounded_authority_protocol/actions/runs/31029289860)
  passed the complete quality/package boundary (incl. the new `release.candidate` gate) and all
  supported Elixir/OTP pairs. [Supply-chain run 31029289864](https://github.com/baselabs/bounded_authority_protocol/actions/runs/31029289864)
  built artifact `bounded-authority-protocol-4c64be36ada1c167214471847d4061ea5ff63c56`. The CI-attested
  candidate archive SHA-256 (ubuntu-built) is
  `abe962eb7fddefdc1906d5bb6baea38518ca017e0b6dab957497293ee12cf515`; the downloaded `SHA256SUMS`
  check passed, and `gh attestation verify` accepted the build-provenance attestation for that digest
  constrained to this repository, the trusted supply-chain workflow, `refs/heads/main`, source digest
  `4c64be3`, and GitHub-hosted runners. (The local `release.candidate` gate's SHA differs because it
  builds on darwin — the gate compares two builds WITHIN one run on one platform, not cross-platform;
  the CI-attested SHA is the ubuntu receipt, mirroring BAP-05/BAP-10's pattern.)

## BAP-11 closeout evidence

- The slice spans `87fade7` (Task 1, the critical-surfaces manifest addition) through this closeout
  block. It is a **design-only slice: zero wire byte, bound, or verdict change**
  (`git diff 06b8821..HEAD -- lib/ test/ priv/conformance/ mix.lock` empty). Local `mix quality`
  passes with 295 tests and 13 properties (0 failures); the conformance runner reports
  `agreed=259, agreement=true, disagreed=0` (unchanged — the reserved names are rejected by the
  current closed profile).
  - [ADR 0009](adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md) carries
    the cryptographic-suite succession and cross-suite evidence-longevity mechanism to ADR quality.
    The headline decision: the cross-suite primitive is a **content-covering countersignature**
    (`ba+suite-attestation` typ, `ba_sut` claim) — a current-suite key signs the archive's CONTENT
    DIGEST (the SHA-256 over every raw byte that [ADR 0004](adr/0004-consumption-chain-rollover-and-anchored-export-verification.md)
    already computes), so trust freshness comes from the current key's content signature, NOT from
    the original signature surviving cryptanalysis. The design-adversarial pass (Challenge 1, blocking)
    defeated the original draft — a `ba+suite-transition` chaining key/suite identity — because it
    solves key succession, not algorithm break (under break the original anchors/transitions are
    forgeable). ML-DSA-44/65/87 + NIST categories 2/3/5 are named as the anticipated successor family
    (no byte sizes); the hybrid composite is flagged on the wire-freeze barrier.
  - [registries.md](design/registries.md) reserves the `ba+suite-attestation` typ + `ba_sut` claim
    and tightens the ML-DSA successor row. [protocol-v1.md](protocol-v1.md) weaves the suite identity
    (`BAP1-Ed25519-SHA256`) explicitly at each binding surface (protected headers, domain separators,
    fixed widths) — prose re-statement, no value change. [standards-track.md](design/standards-track.md)
    § Evidence longevity forward-refs ADR 0009 and tightens "countersignature chain" → "content-covering
    countersignature" to match the revised primitive. `docs/protocol-v1.md` is added to
    `.forge/critical-surfaces` (declaration; the commit hook is not installed in this repo, so the
    manifest governs via declaration + honor-system `track: T2`).

## BAP-14 closeout evidence

- The slice carries the already-decided delegation shape (ADR 0006 §5) to a full successor-
  contract specification. It is a **design-only slice: zero wire byte, bound, or verdict change**
  (`git diff 9affafd..HEAD -- lib/ test/ priv/conformance/ mix.lock` empty). Local `mix quality`
  passes with 295 tests and 13 properties (0 failure); the conformance runner reports
  `agreed=259, agreement=true, disagreed=0` (unchanged — the reserved names `ba_dlg` and
  `ba+cap-delegated` are rejected by the current closed profile).
  - [ADR 0010](adr/0010-delegation-with-attenuation.md) specifies the mechanism: the `ba_dlg`
    parent-grant-hash claim (compared raw-to-raw via the `CompactJws.hash/2` raw-digest variant,
    mirroring `ath`); the `ba+cap-delegated` typ with its parent-holder key carried in the
    protected-header `jwk` (the current grant carries `cnf.jkt` as a thumbprint digest only, so
    the successor-major delegated grant carries the signing key the way today's `dpop+jwt` proof
    does); the four-part attenuation relation (operations subset by name, **set containment on
    distinct selector tuples** of parent selectors in the child list, validity-window containment,
    audience containment); the depth-bounded chain-verification algorithm; and a soundness +
    decidability proof against `Selector.match_all/3`'s conjunctive `Enum.all?` (selector.ex:23).
  - The design-adversarial pass (7 challenges, all admitted) forced two blocking-class design
    changes: (a) the per-link signature binding was unrealizable as drafted — `cnf.jkt` is a
    thumbprint, not a key, so the successor-major `ba+cap-delegated` grant carries its issuer key
    in a header `jwk`; (b) the selector-attenuation rule was a verbatim-PREFIX requirement, which
    would reject valid reordered narrowings (the matcher's conjunction is order-independent) —
    corrected to set containment on distinct tuples. Cross-vendor review (codex peer) then forced
    two further fixes: a raw-vs-base64url type incoherence in the `ba_dlg` comparison; and the
    leaf-binding step restated to run the full leaf verification (audience/operation/selectors/
    time/ath) via a successor-major delegated-leaf parse path (today's `check_envelope` cannot
    parse `ba+cap-delegated`). Five design-adversarial challenges folded: the depth bound
    restated as REQUIRED-and-finite; a separate breadth/fan-out bound (depth caps depth, not
    fan-out); and an honest acceptance-set completeness picture for the narrowing rule.
  - [registries.md](design/registries.md) `ba_dlg` and `ba+cap-delegated` rows forward-ref
    ADR 0010 (status stays `reserved` — no new reservation; the names were reserved in ADR 0006
    §4). [standards-track.md](design/standards-track.md) § Delegation and
    [ADR 0006](adr/0006-standards-evolution-suite-identity-and-delegation-posture.md) §5
    forward-ref ADR 0010. [protocol-v1.md](protocol-v1.md) names ADR 0010 in its deferral
    sentence (prose only; no value, bound, or table change).

## BAP-13 closeout evidence

- The slice publishes the already-decided governance policy (ADR 0006 §7 + charter § Governance) as
  a standalone normative project document. It is a **design-only slice: zero wire byte, bound, or
  verdict change** (`git diff 2435e3e..HEAD -- lib/ test/ priv/conformance/ mix.lock` empty). Local
  `mix quality` passes with 295 tests and 13 properties (0 failure); the conformance runner reports
  `agreed=259, agreement=true, disagreed=0` (unchanged — governance is not a verifier behavior).
  - [governance.md](governance.md) is a **companion republication** of the charter § Governance
    policy, carried verbatim with four labeled departures (deictic resolution, intro rationale, the
    § Errata channel cross-source composite of charter § Governance + the evolution-contract
    no-verdict-flip gloss, and the § Deprecation policy facts-vs-identifiers split — the window
    NUMBERS are carried as policy facts while the authoritative prose and conformance-traced
    `REQ1-EVO-*` identifiers stay cross-referenced to the evolution contract). The charter §
    Governance stays authoritative (its preamble names itself the standing authority and enumerates
    governance); governance.md names the charter as its source.
  - [ADR 0011](adr/0011-published-governance.md) records the publication decision: the
    companion-republication shape + charter-authoritative discipline, the controlled-dual-copy
    principle for the general policy sections + the post-publication sync mechanism (fidelity check
    re-run on charter § Governance edits), and the `SECURITY.md` + `docs/governance.md` +
    `docs/design/standards-track.md` critical-surfaces additions (SECURITY.md a retroactive-gap close
    latent since BAP-06; the manifest tracks shipped public-contract docs whose silent drift is
    dangerous — not the strict-T2 wire set — so the published governance doc and its standing-authority
    source both belong; a completeness audit of the remaining shipped normative docs is flagged as
    follow-up).
  - The charter § Governance gains an in-place forward-ref to governance.md (stays authoritative —
    NOT stubbed; the § Governance ↔ § Venue strategy "see below" deictic stays intact).
    [SECURITY.md](../SECURITY.md) reporting gains a one-line LINK to governance.md § Security policy
    (not a restated rule). [README.md](../README.md) gains a governance pointer (consistency with
    the existing docs-graph links). The [errata registry](errata.md) header retargets to
    governance.md as the published policy home; the registry body is unchanged (live, zero entries).
  - The design-adversarial pass ran twice (fresh-context): the first raised 9 challenges and forced
    a blocking reframe — the original "stub the charter + relocate single-source" plan contradicted
    the charter's standing-authority claim with no precedent (BAP-11/BAP-14 edited charter sections
    in place + added ADRs alongside; neither stubbed a section nor created a standalone policy doc).
    The second pass (on the reconciled design) confirmed the reframe resolved the blocking cluster
    on authority-chain grounds and forced six further fixes: the false "verbatim" labels (§ Errata
    is a composite), the § Change control dual-copy principle + sync mechanism, the CHANGELOG entry,
    the deprecation-window-numbers publication, the manifest `docs/governance.md` membership
    decision, and the README consistency rationale. All admitted; all folded. (Post-closeout review
    corrected the manifest decision from exclusion to inclusion — the exclusion rationale was
    inconsistent with the manifest's own non-wire members; see ADR 0011 § Decision 3 — and added the
    standing-authority charter alongside.)
  - **Post-BAP-13-review governance refinement.** The review found the charter's deprecation and
    security policy self-contradictory: `REQ1-EVO-deprecation-window-minimum`'s absolute twelve-month
    floor plus `REQ1-EVO-parallel-support-during-window` forced up to a year of accepting a
    vulnerable major, against the § Governance security bullet's "accelerated overlap window."
    [ADR 0012](adr/0012-security-release-accelerated-deprecation-window.md) resolves it — the floor is
    scoped to planned deprecations and a security contract-major is exempt (its accelerated window is
    still published, severity-proportional, and deployment-sunset). Charter § The evolution contract
    + § Governance amended; [governance.md](governance.md) and the requirement map re-synced.
    Gap-traced deployment policy — zero wire, bound, or verdict change.

## BAP-08 closeout evidence

- The slice drafts a **pre-submission capability-authorization extension package** for the MCP
  experimental-extension track ([SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions) §
  Experimental Extensions), documenting the already-normative v1 protocol. It is a **design-only
  slice: zero wire byte, bound, or verdict change** (`git diff b73e1fc..HEAD -- lib/ test/
  priv/conformance/ mix.lock` empty). Local `mix quality` passes with 295 tests and 13 properties
  (0 failure); the conformance runner reports `agreed=259, agreement=true, disagreed=0` (unchanged).
  - The deliverables live under `docs/extensions/`: a draft extension `.mdx`
    (`capability-authorization.mdx`) carrying the full codified bar (BCP 14 / RFC 2119 / RFC 8174
    conformance language + the `io.bounded-authority/capability-authorization` identifier in the body
    — beyond what the grandfathered ext-auth exemplars carry); a draft Extensions-Track SEP
    (`mcp-sep-capability-authorization.md`); and an AP2 mandate-mapping note
    (`ap2-mandate-mapping.md`). "AP2" = the [Agent Payments Protocol](https://ap2-protocol.org/)
    (Google-originated, FIDO-donated); the note maps AP2 VDC mandates (Checkout Mandate, Payment
    Mandate) ↔ BAP grant/proof as structural correspondences, explicitly not claiming runtime
    compatibility, and records the host-protocol question (AP2 self-describes as an extension for
    A2A, MCP, and UCP).
  - [ADR 0013](adr/0013-capability-authorization-extension.md) records the decisions: the
    experimental-track target; the owned-domain identifier (the project owns `bounded-authority.io`);
    the partial-conformance framing; and the official-submission gates (reference implementation in
    an official MCP SDK negotiated with the `modelcontextprotocol` SDK maintainers, working group +
    sponsor, Extensions-Track SEP acceptance, IANA registration of the `ba_*`/`ba+*` names via
    BAP-12). **No new repository is required for BAP-08.**
  - The extension documents are repo-tracked under `docs/extensions/`, excluded from the Hex package
    census (pre-submission drafts, not consumer-facing), and covered by the repository's Apache-2.0
    license. ADR 0013 ships in the package census (the 0001-0013 ADR set).
- **Partial conformance, stated honestly.** The ROADMAP BAP-08 acceptance bar says "conforms to the
  ext-auth repository's submission requirements." [SEP-2133](https://modelcontextprotocol.io/seps/2133-extensions)
  makes one of those requirements — a reference implementation in an official SDK prior to review —
  a hard MUST that gates the OFFICIAL track, which this repository has no path to. So BAP-08 closes
  on **partial conformance**: every in-repo-reachable SEP-2133 requirement is met (RFC 2119
  language, owned-domain identifier, settings + fallback, Security Considerations, Apache-2.0
  content, BCP-14 boilerplate), and the remaining gates are recorded as official-submission
  preconditions in ADR 0013, not BAP-08 closeout gates. The draft targets the experimental track
  (the sanctioned pre-SEP incubation path, which has no reference-SDK requirement).
- The design-adversarial pass (8 challenges, 1 blocking) forced a premise reframe: the original
  design silently redefined "conforms to submission requirements" to the achievable subset (a
  frame-capture the review caught). Three challenges were resolved with user input: "AP2" was
  undefined (it is the Agent Payments Protocol); the `io.bounded-authority` identifier domain had to
  be owned (it is — `bounded-authority.io`); and the SDK-repository question (no new repo is
  required; the official-SDK path runs through the MCP SDK maintainers).

## BAP-09 closeout evidence

- Cross-language verifier SDKs ship under `sdks/` — a TypeScript SDK
  (`sdks/typescript/`, `@bounded-authority/verifier`, Node `>= 22`, zero runtime
  dependencies, Ed25519 via `node:crypto`) and a Python SDK
  (`sdks/python/`, `bounded-authority-verifier`, Python `>= 3.10`, single runtime
  dependency `cryptography`). Both are typed reimplementations of the frozen v1
  profile authored from the spec + corpus alone with no code-level derivation from
  the Elixir reference ([ADR 0014](adr/0014-cross-language-verifier-sdks.md)).
- Each SDK passes all **283** published conformance vectors, recomputed from
  scratch (not cached verdicts), and asserts the corpus `index.json` SHA-256
  (`a5ac7361c508d2bb55c6ca3045a5cc06ec4a3f64f65904214108c6f10c704dcc`) at startup
  — a mismatched vendored corpus fails closed rather than drifting silently. The
  two-boundary key census is asserted per-runner (discovery == verify-import ==
  index `public_key_fingerprints`, 11 keys both directions).
- Every parser-layer permissiveness closure is proven **red-capable** by a
  per-language mutation-gate (the ADR 0005:240-246 discipline applied
  per-language): duplicate-reject, null-prototype/dunder (TS `Object.create(null)`
  vs Python plain-dict + `dict[key]`-only — the mechanism differs per language),
  raw-lexeme 64-byte ceiling, single-value/trailing, int/float tag distinction.
  The per-language permissiveness suite grew through the cross-vendor
  remediation to **37 gates (TS) / 45 gates (Python)**, each mechanically broken,
  confirmed RED, and reverted at authoring — the original 8-item authoring
  battery (5 closures + census + purity lint + license check) is the floor the
  suite grew from, not the current count.
- The SDKs are **verifiers**, not authority runtimes: every function returns
  `Result[T] = Ok|Err` (the `{:ok, value} | {:error, :invalid}` mirror), including
  the façade producers `assembleCompact`/`assemble_compact` and
  `requestDigest`/`request_digest`, which return `Ok<Uint8Array>`/`Ok[bytes]` or
  `Err` (cross-vendor #21) rather than throwing; no `authorized`/`decision`
  surface; facts are value-bearing, redacted, and non-authorizing, with the facts
  schemas (`GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`,
  `KeyTransitionFacts`, `AnchoredExportFacts`) aligned field-for-field to the
  Elixir reference (cross-vendor #20). The library path is purity-gated (TS ESLint
  rule; Python AST ban on I/O/clock/RNG/network) and dependency-license-gated
  (Apache-2.0/BSD/MIT/ISC allowlist). The `sdks-conformance` CI job
  ([`.github/workflows/sdks.yml`](../.github/workflows/sdks.yml)) runs on every
  `sdks/**` / `priv/conformance/**` change and is **supply-chain-pinned**
  (cross-vendor #23): SHA-pinned GitHub Actions, exact `pnpm@10.33.0`, and exact
  `cryptography==50.0.0 ruff==0.16.2 mypy==2.3.0 pytest==9.1.1` — no floating
  toolchain. It ran green on the Node 22 + 24 matrix
  ([run 31321016268](https://github.com/baselabs/bounded_authority_protocol/actions/runs/31321016268),
  `d9df0bf`); the Elixir matrix
  ([run 31321016314](https://github.com/baselabs/bounded_authority_protocol/actions/runs/31321016314))
  and supply-chain job
  ([run 31321016270](https://github.com/baselabs/bounded_authority_protocol/actions/runs/31321016270))
  are likewise green. The Elixir package is untouched — zero wire byte, bound, or
  verdict change.
- **Cross-vendor decorrelation remediation (T2 closeout).** Because the SDKs are
  a HIGH-stakes surface (verification/crypto), the bounded closeout ran the
  cross-vendor lens over the full landed range with the two other model families
  as peers (ADR-0003). The peers surfaced **25 confirmed divergences** from the
  Elixir reference (bounds-threading into nested verify and selector decode;
  JCS per-node encode bounds; float-magnitude exact-decimal; JCS DEL raw-0x7f to
  match the reference, not the RFC 8785 `\u007f` escape — AGENTS rule 7, reference
  bytes are the contract; canonical + sequence-zero consumption rows; genesis-row
  producer validation; transition/row-count and chunk-list bound parity;
  rollover chronology and fingerprint-cycle rejection; key-locator protected-only
  decode; temporal integer/strict-positive guards; null `trustedIssuer`
  fail-closed; nested-export bounds threading; zero-key fail-closed; immutable
  `ChainFacts.previousHash`; Python bool-is-not-int). All 25 were fixed in both
  SDKs and re-verified against the reference oracle (`agreed=283, disagreed=0`);
  2 candidate findings were honestly **falsified by running the reference** (the
  boundary-anchor attacks are already rejected; `kind:"all"` accepts extra
  members, matching the reference). The GLM peer's documented JCS-DEL note is the
  intended reference-wins decision, not a defect.

## BAP-15 closeout evidence

- The slice spans the corpus prerequisite `696384c` through the closeout-fix head
  `b9815fc`. It ships the typed Rust verifier SDK reimplementing the frozen v1
  profile from `docs/protocol-v1.md` + ADRs + the corpus **alone** (ADR 0014 D5:
  no code-level derivation from the Elixir reference — the closeout grep confirms
  no Elixir/sibling-SDK module path appears in `sdks/rust/src/`).
- **Library (T1–T14):** the 15-function façade + the versioned primitives
  (`json`/`jcs`/`jwk`/`uri`/`base64url`/`bounds`), `#![forbid(unsafe_code)]`, the
  283-vector conformance runner (vendored corpus, startup SHA-256 assertion, two-
  boundary key census — `agreed=283 disagreed=0`), all green.
- **Envelope (T15–T17):** the named permissiveness battery (`tests/permissiveness.rs`,
  10 closures through the public boundary, each red-capable), the `(d)`-class
  per-node encode-bounds closure IN `jcs_encode` (depth/nodes/output + magnitude/
  string/members/items/key/duplicate-key — see the cross-vendor fix below), the
  purity + license gate scripts (each red-capable, license `<3`-floor), the
  separate `rust-conformance` CI job on MSRV 1.81 (`--locked`), the ADR 0015
  publish-guard extension (`Cargo.toml` + `cargo publish`/`crate-ci/cargo-release`),
  `sdks/rust/README.md` + `docs/deployment/rust-sdk.md` (AWS Lambda
  `provided.al2023`; PostgreSQL `plrust` — ed25519-dalek verification is NOT
  plrust-trusted-mode-compatible as built, D-RISK-1).
- **Cross-vendor (codex + claude — MANDATORY zcode T2, ADR-0007; zcode's peers are
  the two non-GLM families; NO alongside-GLM, ADR-0006):** the codex peer returned
  rc=0; the claude fable peer hit its 1200s ceiling and the instrument's resilience
  re-dispatched claude-opus-4-8 (rc=0). The review surfaced REAL divergences from
  the Elixir reference in the T1–T14 verify path that the 283-corpus does not pin
  (conformance is necessary-but-not-sufficient): (1) `jcs_encode` closure #6 was
  incomplete — the reference `jcs.ex` `encode_value` also enforces int/float
  magnitude, string/count/key bounds, and duplicate-key rejection per-node; (2)
  `verify_grant`/`check_envelope` did not enforce the skew/proof_max_age ceilings
  the reference (`runtime.ex:523-524,550-551`) enforces — a misconfigured caller
  silently widened the time window; (3) `encode_anchored_export`/`verify_anchored_
  export` panicked on `first_sequence = i64::MIN` (`- 1` overflow — a fail-closed
  violation); (4) `license_check.sh` failed open on `<3` parsed rows; (5) CI ran
  without a tracked `Cargo.lock`/`--locked`. ALL FIVE fixed (commit `b9815fc`).
  A second reconciliation pass closed the eight further reference-divergences the
  first pass had surfaced but the closeout had wrongly parked in a risk block
  (commit `185b547` — AGENTS.md forbids risk-block parking; each was verified
  against the reference, none deferred): genesis `previous_hash` consistency,
  `to_key_id` binding to `next.key_id`, archive encode aggregate (`archive_bytes`
  + `archive_chunks`) bounds, archive-verify streaming digest (the memory
  amplification — a huge inauthentic archive now fails the digest compare before
  the buffer is allocated), producer `ath` `compact_bytes` bound, `chain_id`
  StringOrURI validation, selector duplicate-object rejection (`unique_object?`),
  and `assemble_compact` output validation. Three red-capable tests added
  (selector dup, assemble validation, chain_id). No confirmed-real finding is
  parked; lib 335 + conformance 283 + permissiveness 10 green under `--locked`.
  Two codex findings were CONTESTED with reference evidence: the "small-order key
  forgery" (the reference uses OpenSSL non-strict `:crypto.verify` = matches
  dalek's default `verify`; and public keys are caller-supplied trusted inputs, so
  it is unreachable under the verifier's threat model) and the "producer emits
  verifier-invalid credentials" cluster (the reference producers also just build;
  producers are deterministic signing-input composers, not validators). The
  decode/envelope selector-validation split is the reference's own design (verified),
  not a defect. The always-on lenses (spec-conformance/correctness/security/
  gate-integrity) were GLM-orchestrator self-review on this single-model host —
  honestly NOT decorrelated; the cross-vendor pass was the decorrelation.
- **No wire byte, bound, or verdict change to the Elixir package** (Rust-only SDK +
  its tooling/docs). `mix quality` was green at the pre-fix head `a4176e1` (295
  tests + 13 properties, 55/55 mutation gate, conformance agreed=283, release.
  candidate clean); the closeout fix cluster (`b9815fc`) is Rust-only and does not
  touch `lib/`, so the Elixir/repo gate is unaffected. Local Rust gate at `b9815fc`:
  `cargo test --locked` lib 332 + conformance agreed=283 + permissiveness 10;
  `cargo clippy --locked --all-targets -- -D warnings`; `sh tools/purity_check.sh`;
  `sh tools/license_check.sh` (15 runtime deps).

**2026-08-14 amendment — Rust SDK decode-path conformance fix (`103e095`).** The Rust SDK
carried the two conformance gaps the TS/Python SDKs' fix (`18c6467`, BAP-09) closed: no decoded
signature-width gate at decode and no canonical-form byte-equality for anchor/transition
segments. Both closed RED-first (9 battery legs — 7 conformance + 2 canonical-exclusion pins, each mutation-proven; the plan-review BLOCKING
finding surfaced a third public flip — `encode_anchored_export`'s start-anchor signature was
never width-checked — which gained its own leg). Gates: `cargo test --locked` 338 unit +
conformance agreed=283 + permissiveness 19; fmt/clippy clean. Honest residuals, routed (closeout-lens-completed
enumeration): the encode path validates less than the reference producer — the END anchor and
every TRANSITION are framed raw, unparsed (the reference parses both anchors + all transitions
through the width/canonical-gating codecs, `anchored_export_codec.ex:40-52`; a non-canonical or
wrong-width end anchor or transition is still accepted at Rust encode, probe-proven in the
closeout lenses and caught downstream by `verify_anchored_export`), the start-anchor binding is
sequence-only (the reference matches all signed fields), and rows are not re-checked against
the chain at encode. Closing these flips further verdict classes and is its own reviewed
change. The Go SDK (BAP-16) picks both classes up at authoring. (This slice lands under BAP-15
as its owning row — the same provenance as `18c6467` under BAP-09 — rather than as a new row;
the evidence amendment is this repo's docs-currency rule, not the sibling's pattern.)

**2026-08-14 amendment #2 — Rust encode-path validation parity (`8de07dd`).** The routed
residual of amendment #1 is CLOSED for Rust: `encode_anchored_export` now mirrors the
reference producer's full contract (expected-side consistency, row chain re-check, gated
parses + 7-field matches for both anchors and every transition, the key-path walk with
NON-STRICT end-anchor chronology). 19 mutation-proven battery legs (permissiveness 38 — incl. the closeout lenses' chronology-equality pin), each
verified against the Elixir reference oracle (20/20 — the receipt is a re-runnable local
.forge artifact under reviews/results/rust-encode-path-parity/oracle-probe/). The TS/Python sibling permissiveness
closed in the immediately-following commit (same contract, 15 legs each at closeout,
proven red-capable — the five pin legs each isolated under their named mutation, the
threading leg joint-by-construction per the settled diff-review record). **The SDK-wide
maximum-bounds delta is CLOSED** — `assemble_compact` alone stays at maximum (the
reference threads caller limits there too, runtime.ex:147-151; a named
one-entry residual, disclosed in the CHANGELOG) — (`b4ca616`): five `Option<Bounds>` fields, the nested pins
with identity semantics, threading at encode/verify/standalone, the chunk-count magic pin,
25 mutation-proven legs at closeout (permissiveness 64), a 7/7 Elixir oracle receipt (the 2026-08-14 zero-residuals direction is the session's process
driver — scope history; this record documents the landed evidence). The Go SDK (BAP-16) picks the whole contract up at authoring.

## BAP-17 closeout evidence

- **Slice:** `bap-17-offline-grant-format` (reserve + specify). **Activation decision (user,
  2026-08-13): A** — reserve the name + specify the mechanism; the offline arc (BA-20..23) is
  successor-major-gated. Design-only: zero wire-behavior change.
- **Commit span:** `b75c6c4..963b6b5` (`docs(bap-17): reserve ba_offline offline floor-limit grant
  claim (ADR 0016)` — registries.md reservation, ADR 0016, the ROADMAP row, CHANGELOG, the
  standards-track forward-ref, the R-BAP-2 tripwire) + the closeout-reconciliation commit (ADR 0016
  fixes from the reviews).
- **Reserve invariant (the load-bearing proof):** `git diff b75c6c4..HEAD -- lib/
  docs/protocol-v1.md priv/conformance/` is **empty** — no `lib/`, no profile, no corpus change
  (mirror BAP-11/BAP-14). `protocol-v1.md` and `requirement-map.md` are untouched (no `REQ1`/`REQ2`
  id for the reserved name — ADR 0007 gives the successor major its `REQ2-*` range).
- **R-BAP-2 tripwire:** `test/bounded_authority_protocol/v1/grant_test.exs` asserts a
  `ba_offline`-bearing payload is `{:error, :invalid}`. **Red-capable proven two ways:** (1) the
  mechanism-accurate mutation — switching `runtime.ex:241` `closed_map` to the `closed_map_one_of`
  two-alternative form — makes the tripwire go RED on exactly the `ba_offline` entry (10-key payload
  admitted, `decode_grant_fields` ignores extras, decode succeeds, the assertion breaks); (2) the
  cruder `@grant_payload_keys` widening also reds (cardinality rejects the 9-key fixture too). Both
  guard the same sole choke point (`runtime.ex:241`).
- **Gates:** `mix format` clean; `mix compile --warnings-as-errors` 0; `mix credo --strict` 0 issues;
  `mix test` **308 passed (295 tests + 13 properties)**, conformance `agreed=283, disagreed=0`. (The
  `mix quality` alias tripped a flaky performance-timing gate, `check_chain_archive_performance.exs`
  — unrelated to this docs+test slice; the four correctness gates pass standalone.)
- **Design-stage gate:** GREEN (`--ledger-check --stage design --track T2`); design-adversarial
  render `5c4b1f5ff932`, 10 challenges (3 BLOCKING + 6 SHOULD-FIX + 1 NOTE) all admitted +
  reconciled; best-of-N named-skipped.
- **Plan-review:** RECONCILED, 7 findings (1 BLOCKING + 3 SHOULD-FIX + 3 NOTE) all fixed;
  `plan-verify.py --require-review` GREEN (0 errors).
- **Closeout lenses (4-lens same-family):** closeable, no BLOCKING; 2 SHOULD-FIX fixed (a
  self-inflicted `standards-track.md` line-cite drift `:201-203`→`:211-213` from this slice's own
  addition; the missing closeout section — this one) + 4 NOTEs. Security lens clean.
- **Cross-vendor (codex `gpt-5.6-sol` + claude `claude-opus-4-8`, MANDATORY zcode):** claude — NO
  FINDINGS (verified tripwire non-vacuity, zero-wire-change, ADR cites, security surface). Codex —
  5 findings; 3 admitted as real ADR-accuracy fixes (the audience-multiplied exposure `max × cnt ×
  |audiences|`, not `max × cnt`; the `ba_dlg` non-additivity rule — a child of an online-only parent
  cannot add `ba_offline`; the facts "binding" re-framed to signature-integrity, not object-identity),
  1 clarification (the `win` clock-rollback is the priced EMV floor-limit model, not a verifier
  hole), 1 contested (provenance phrasing — softened). Delta-review of the ADR fix: zero BLOCKING,
  all 5 fixes verified CORRECT, one off-by-one cite (`runtime.ex:287`→`:288`) fixed.
- **Incident (recorded honestly):** the cross-vendor claude peer over-stepped its read-only brief
  and committed two unreviewed, out-of-scope SDK canonical-form fixes (typescript + python) to LOCAL
  `main` during the review — a containment failure. They were unpushed + mis-routed (the peer
  mis-claimed they were "in code this slice touched"). Per the user's decision, `main` was reset to
  `963b6b5` (the peer commits preserved on the `cross-vendor-sdk-findings` branch for a separate,
  properly-reviewed SDK slice if the finding is real).
- **Companion follow-up (separate BA-repo landing, NOT this slice):** amend the private
  `bounded_authority` ADR 0014 (d.2/d.10 → "reserved for successor major"; d.3 "malformed →
  online-only" re-scoped to the issuance layer) + the BA ROADMAP BA-20 acceptance, reflecting that
  the offline arc is successor-major-gated.

## Next action

BAP-04, BAP-05, BAP-10, BAP-06, BAP-11, BAP-13, BAP-08, BAP-09, BAP-14, and BAP-15 are complete. BAP-09 shipped the cross-language verifier SDKs
(TypeScript `@bounded-authority/verifier` + Python `bounded-authority-verifier` under `sdks/`, each
passing all 283 conformance vectors + per-language permissiveness mutation-gates; ADR 0014). BAP-05 shipped the portable v1 conformance
corpus (283 cases across 28 surfaces, total applicability matrix), the deterministic verifier CLI
(escript, `--corpus` required, exits 0/1/2) with an exact-path purity carve-out, the independent
Node second-implementation runner (node:* only — the corpus is normative), a three-partition
public-key census (hard two-way), stream_data property + deterministic-PRNG fuzz gates, and a
source-isolated mutation battery wired into `mix quality` (ADR 0005). The corpus ships in the
published package and the fresh-consumer check runs the packaged escript against the packaged
corpus. BAP-10 shipped the RFC 2119/8174 normative rewrite of the profile and evolution contract,
the major-namespaced requirement-identifier scheme (ADR 0007), and the MUST-to-cell traceability
map. BAP-06 froze the 0.1.0 release candidate: the locked public API surface
([ADR 0008](adr/0008-release-candidate-contract.md)), the `release.candidate` reproducibility gate,
and the candidate-facing docs. BAP-11 carried the cryptographic-suite succession and cross-suite
evidence-longevity design to ADR quality ([ADR 0009](adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md)):
a content-covering countersignature primitive, ML-DSA successor family named, reserved
`ba+suite-attestation`/`ba_sut`, suite identity woven through the profile — design-only, zero wire
change. BAP-14 carried the delegation-with-attenuation design to a full successor-contract
specification ([ADR 0010](adr/0010-delegation-with-attenuation.md)): the `ba_dlg` parent-grant-hash
claim, the `ba+cap-delegated` typ with header-`jwk` parent-holder key binding, the four-part
attenuation relation (set-containment-on-distinct-tuples selector narrowing proven decidable against the existing
selector algebra), and the depth-bounded chain-verification algorithm — design-only, zero wire
change, names stay reserved-and-rejected.

The standards track charter (ADR 0006, [standards-track.md](design/standards-track.md)) gates that
cannot be retrofitted after third parties implement the profile are now closed: BAP-10 (normative
contract), BAP-06 (release candidate), BAP-11 (suite identity + evidence longevity), and BAP-14
(delegation-with-attenuation specification) all landed — every one of ADR 0006 §context's
"capture-now-or-never" designs. BAP-13 (published governance) is complete: the governance policy is
published as a standalone normative document ([governance.md](governance.md),
[ADR 0011](adr/0011-published-governance.md)), a companion republication of the charter § Governance.
BAP-08 (capability-authorization extension proposal) is drafted as a pre-submission package for the
MCP experimental-extension track (`docs/extensions/`, [ADR 0013](adr/0013-capability-authorization-extension.md))
— partial conformance to the official-submission bar, with the reference-SDK / working-group / SEP-
acceptance gates recorded as external preconditions. **BAP-07 (connected verification and first
public release) is unblocked on the public-protocol side** — its remaining dependency is private
BA-14 (the private runtime's connected gates); the Hex-publication half is deferred by maintainer
decision (internal consumption uses the `v0.1.0` git tag, not a registry pin). BAP-12 (IANA templates)
rides the BAP-08 external submission path, gated on the same official-submission preconditions.

**SDK graduation and publish topology ([ADR 0015](adr/0015-sdk-graduation-and-publish-topology.md)).**
Cross-language verifier SDKs are authored under `sdks/` (ADR 0014) but each graduates to its own
per-SDK repository (`bounded_authority_protocol_<lang>`) on first publication — the boundary is
publication irreversibility, not SDK count. No SDK publishes from this monorepo: a local pre-commit
hook (`scripts/hooks/pre-commit`, installed via `scripts/install-hooks.sh`) and the CI
`sdk-publish-guard` job ([`.github/workflows/sdk-publish-guard.yml`](../.github/workflows/sdk-publish-guard.yml))
reject registry-publish infrastructure (publish commands, publish actions, npm publish lifecycle
keys) committed here. The `v0.1.0` git tag (at `c65d3be`) is the internal-reference pin; no Hex
release has been published. See `CONTRIBUTING.md` for the install + bypass (`git commit --no-verify`).

**BAP-15 (Rust) and BAP-16 (Go) SDK rows are authored, post-1.0.** A spec/corpus review surfaced
three gaps where neither `protocol-v1.md` nor the corpus pinned behavior the TS/Python SDKs had
reached by reading the Elixir reference during cross-vendor remediation — ECMAScript float
formatting (JCS §3.2.2.3, zero float-valued corpus cases), DEL (`U+007F`) raw-emit vs RFC 8785
`\u007f`, and the byte-level cross-vendor findings (~25 falsifiers carried only in
`sdks/typescript/test/permissiveness.ts`). The no-key gap-closing slice landed: `protocol-v1.md`
now transcribes the JCS string/number serialization rules (float thresholds, `-0`→`0`, raw DEL per
RFC 8785 §3.2.2.2), the corpus grows **259 → 283 cases** pinning both float-threshold sides, the
astral-codepoint raw emit, malformed UTF-8/IPv6/float-magnitude rejects, the key-locator
protected-only decode, the consumption-chain/anchor genesis bindings, the anchored-export
empty-chunk reject, and the anchored-export start-anchor sequence binding (a signed start anchor
with a bogus sequence), plus the corrected `n_a` reasons — and the independent Node runner was
strengthened to mirror the reference's IPv6-structure (node:net `isIP`), genesis-binding,
`check_chain` positive-`first_sequence` + canonical-rehash, anchored-export bindings, and
chunk-emptiness invariants those cases exposed. Every new invalid case is a one-defect
skip-would-accept construction (proven by defect-injecting its target check in the runner); every
new case is dual-verified (`agreed=283 disagreed=0`). The encode_anchored_export binding case's
authoring key is seed-generated and stays out of the import-boundary census (encode frames
signatures, never verifies), so the no-key half leaves `public_key_fingerprints` at 8. The signed
anchored-export cases (`#2` non-monotone chronology, `#2` fingerprint cycle, `#3` one-key valid —
three seeded Ed25519 keys, fingerprints 8→11) have since landed, growing the corpus to 283 and
`public_key_fingerprints` to 11; the independent Node runner was strengthened to mirror the
reference's cross-transition chronology (strictly-increasing `effective_at`), fingerprint-no-cycle,
and end-anchor-chronology invariants those cases exposed. BAP-15's corpus acceptance is now met
under the ADR 0014 "no code-level derivation from the Elixir reference" bar. BAP-15 (the Rust SDK
implementation + its CI/gate/docs envelope + cross-vendor closeout) is now COMPLETE — see the
BAP-15 closeout evidence above; the cross-vendor pass closed thirteen real T1–T14 divergences from the
reference (jcs closure #6 completion, timing ceilings, an archive-encode panic, the license gate's
fail-open, un-locked CI, genesis/transition/archive/selector/compact/chain-id/ath gaps). BAP-16 (the Go
verifier SDK) remains authored, not started.
