# Changelog

All notable changes to `bounded_authority_protocol` are documented here.

## [Unreleased]

### Added

- Initialize the public Apache-2.0 repository and cold-start architecture authority.
- Define the deterministic verifier boundary, public/private dependency direction, protocol
  charter, threat model, conformance contract, ADR, and implementation roadmap.
- Close BAP-00 after public-remote verification, cross-repository documentation reconciliation,
  security-contract hardening, local-link/browser checks, independent reviews, and tamper-gate
  verification.
- Add the unpublished `:bounded_authority_protocol` 0.1.0 Mix package with zero production
  dependencies, no application callback, and no supervision tree.
- Enforce the pure-library boundary across source AST, compiled imports, application metadata,
  dependency declarations, and the exact packed/unpacked Hex archive.
- Add full local quality, coverage, documentation, advisory, closed license, CycloneDX,
  fresh-consumer, public CI, checksum, provenance-attestation, and SBOM-attestation gates.
- Freeze the normative v1 header, claim, selector, JSON, encoding, URI, domain-separator, bound,
  and fixed-error tables with primary RFC and OTP provenance.
- Add bounded ordered JSON decoding with recursive duplicate rejection, strict canonical
  base64url decoding, and a protected-header-only untrusted key locator.
- Add allow, deny, malformed, exact-boundary, deterministic malformed-input sweep, symmetric
  numeric-magnitude, package-consumer, and purity-boundary proof.
- Enforce raw numeric-lexeme bytes and exact decimal magnitude before OTP conversion; validate the
  companion Draft 2020-12 schemas with an independent validator and distinguish their structural
  code-point limits from the normative UTF-8 byte contract.
- Align the tracked roadmap with Forge's authored-row contract while preserving BAP-00 through
  BAP-07 identities and exact dependency labels.
- Document the exact public `BoundedAuthorityProtocol.V1.Json.decode/2` and
  `BoundedAuthorityProtocol.V1.Base64Url.decode/2` surfaces, tightening-only positive-integer
  limits, structural-schema boundary, and fixed value-free errors.
- Extend the packed external consumer to exercise both decoder success and rejection paths, and
  add mutation-red proof that escaped string content cannot hide a following over-limit number.
- Reconcile the BAP-02 final trusted-main receipts and degraded peer-review record.
- Add deterministic standard compact-JWS grant and RFC 9449 holder-proof producers, exact external
  signature assembly, and bounded grant/proof decoders.
- Add RFC 8785 canonical JSON, RFC 7638 public Ed25519 JWK thumbprints, bounded HTTPS URI
  normalization, type-preserving request digests, and conjunctive selector evaluation.
- Add standalone raw-grant verification and combined raw-envelope verification with exact
  issuer/audience/time/holder/request/nonce/operation bindings and redacted, non-authorizing
  verified facts.
- Add public-only grant/holder-proof vectors, independent Node verification, exact public-key
  census, meaningful byte-tamper and duplicate-member cases, portable timing/allocation bounds,
  architecture census updates, and unpacked external-consumer API proof.
- Close BAP-03 at package-bearing head `f322e08bba665374599b9f53c362966b6b59710a`
  after the supported CI matrix, complete quality/package boundary, independent Node verification,
  exact archive checksum, SLSA provenance, and CycloneDX SBOM attestation passed. The single final
  review admitted five findings; all five were fixed in one pass without review recursion.
- Add closed canonical consumption rows with domain-separated hashes and mandatory-boundary raw
  chain verification for genesis and continued ranges.
- Add deterministic standard-JWS boundary anchors and authenticated historical-key transitions,
  including derived RFC 7638 fingerprints and lower-inclusive/upper-exclusive validity windows.
- Add deterministic binary anchored-export framing and atomic raw-chunk verification of complete
  digest, exact out-of-band object version, exact EOF, ordered key rollover, both signed
  boundaries, and every canonical row.
- Add closed fixed-redacted non-authorizing chain, anchor, transition, and anchored-export facts;
  exact tightening-only archive bounds; constant-time fixed-width comparisons; and expanded
  source/BEAM architecture accounting.
- Add five Draft 2020-12 structural schemas and public-only same-key, rollover, shortened,
  relinked, same-ID/equal-time, signed cross-chain, signed reverse-time, and signed invalid-genesis
  evidence. The project-independent Node verifiers prove an exact two-way eleven-key census split
  into exact per-verifier sets observed at their public-key import boundaries,
  49 named decoded-byte, structural, boundary, coverage, chronology, and limit cases, two direct
  valid chain cases, and seven signed semantic-edge cases; the isolated mutation gate proves 47
  source-level invariants go red. Published fixture verdicts and complete redacted
  chain/anchor/transition/export facts are exact-checked rather than treated as commentary.
- Add the maximum-count, maximum-width worst-of-20 chain/archive resource gate, with every sample
  isolated in a fresh monitored process, plus ADR 0004, normative documentation, and packed
  external-consumer coverage.
- Validate every nested expected field and historical-key shape before archive hashing or parsing;
  reject duplicate outer conformance JSON members; and detect self-identifying Ed25519 PKCS#8 DER
  regardless of its surrounding field name.
- Make Ed25519 public-key/signature and SHA-256 digest widths immutable bounds so tightening cannot
  produce or admit a structurally nonconforming cryptographic value.
- Centralize strict StringOrURI validation across grant/proof and BAP-04 identifiers so malformed
  percent escapes and non-URI bytes cannot enter any producer or verifier path.
- Preserve exact package-boundary accounting across supported Elixir compiler versions and pin
  bitstring match sizes required by Elixir 1.20.
- Close BAP-04 at package-bearing head `c4d7716de6499f29524e60638207b1c36e9484b3`
  after the supported CI matrix, complete quality/package boundary, independent Node verification,
  47/47 mutation battery, maximum-shape resource gate, exact archive checksum, SLSA provenance,
  and CycloneDX SBOM attestation passed.
- Author roadmap rows BAP-08 (capability-authorization extension proposal for the MCP
  `modelcontextprotocol/ext-auth` extensions repository plus an AP2 mandate-mapping note;
  depends on BAP-04 only) and BAP-09 (thin TypeScript and Python verifier SDKs consuming only
  the published spec and vectors; depends on BAP-05). Each row's own ADR lands when its work
  starts; neither changes any wire format, limit, or verification rule.
- Close the check_envelope selector-binding gap: add a non-trivial (`equals`) selector valid case
  plus an `invalid_selector` case, teach the independent Node verifier to evaluate grant selectors,
  and add a `selector-reject` mutation — so a verifier that ignores grant selectors now fails the
  corpus. Uses two new deterministic conformance keypairs (census 6→8); a companion
  `proof_signing_input` valid case carries the new holder key as a labeled field so the
  cross-verifier census discovery scan finds it (corpus 212→215).
- Close the check_envelope authority-binding gap the same re-signing capability exposed: the
  holder (`cnf.jkt`), grant (`ath`), request-argument (`ba_req`), and operation (`ba_op`) bindings
  had no corpus case isolating them, so a verifier omitting any one of them still scored a perfect
  corpus run — omitting the holder binding accepts any holder's proof against any grant. Add four
  `invalid_claim` cases (each a one-defect variant of a shared valid base, with the named binding
  as the sole rejecter) and four matching mutation-battery entries. The `ba_op` case needs a
  hand-built proof payload: the request digest is computed over the server-derived operation, never
  over the proof's own `ba_op` claim, so only a dishonest producer — which the façade cannot be —
  emits a proof whose two operation fields disagree (corpus 215→219).
- Add an empty-path `invalid_selector` case so the independent runner's selector shape and width
  validation is falsifiable: the official rejects an empty selector path at grant decode, and a
  matcher treating `[]` as "the root" would accept what the official refuses (corpus 219→220).
- Close the independent runner's remaining permissiveness against the official decoder, so it can
  no longer certify a grant the reference implementation refuses. Six divergences, each now carried
  by a corpus case and a mutation entry: an extra member inside the closed `cnf` map; a
  non-printable byte in an operation name (the official requires printable ASCII); a structurally
  invalid selector on a NON-matching operation, and duplicate operation names (the official
  validates every operation and enforces global name uniqueness, not just the requested one); a
  lone surrogate in a selector path (the official requires valid UTF-8); and a `__proto__` member
  in a selector value, which the tagged projection silently dropped to the prototype setter so that
  two structurally different values compared equal — a collapse that reached the request digest as
  well as selector matching. Selector values are now also held to the protocol JSON bounds. The
  same operation validation is applied on `verify_grant`, which reaches the same official decode
  path (corpus 220→231; `check_envelope/invalid_encoding` 6, `verify_grant/invalid_encoding` 5).
- Add `.gitleaks.toml`: the `jwt` and `generic-api-key` rules are allowlisted for the conformance
  corpus and vector paths only, where all 283 findings are JWT-shaped high-entropy public test
  material (109 `jwt`, 174 `generic-api-key`, the latter almost entirely key fingerprints). Every other default rule still applies in those trees — a `ghp_…` token committed there
  is still caught — and every rule applies everywhere else. Stated residual: a credential matching
  ONLY those two rules, under those two machine-generated fixture directories, is not flagged.
- Add the portable v1 conformance corpus (231 cases across 28 surfaces with a total
  surface × class applicability matrix, `.raw` sidecars for oversize wire inputs) and the pure
  `Conformance.Corpus`/`Runner`/`Report` core that loads, executes, and reports agreement.
- Harden the corpus against vacuous green: author the invalid vectors the crypto verifying
  surfaces were missing — algorithm-confusion (`alg:"none"`), meaningful-byte signature/commitment/
  anchor tampers (via a target-addressed tamper loader that binds a single-byte flip to the
  compact / grant / proof / row / chunk bytes), and archive/chain/envelope binding failures — plus
  exact-bound and maximum-plus-one pairs for every `json.decode` structural limit. Each new invalid
  vector is a one-defect construction confirmed rejected by BOTH the official facade and the
  independent Node runner; every remaining not-applicable applicability cell carries a falsifiable
  inexpressibility reason. The independent Node runner gained the request-binding (method / URI /
  invocation / operation / nonce) and object-name-byte checks the new vectors surfaced.
- Add the deterministic offline verifier CLI (escript `bounded_authority_conformance`,
  `--corpus DIR` required, exits 0/1/2) with an exact-path purity carve-out (File/IO in `cli.ex`,
  `System.halt` in `cli/main.ex` only) enforced by the architecture gate.
- Add the independent Node second-implementation runner
  (`conformance/corpus_independent.mjs`, node:* only) that recomputes every corpus verdict from
  scratch — making the corpus normative. Evolve the public-key census to three partitions
  (bap03 + chain_archive + corpus = the canonical set); the corpus self-census is hard two-way.
- Add stream_data property gates (JCS determinism/idempotence, base64url round-trip/pad rejection,
  URI normalization idempotence, facade closure totality) and a deterministic-PRNG fuzz gate.
- Add the source-isolated conformance mutation battery (proving the corpus integrity, CLI
  carve-out, and runner-verdict gates actually catch their named failures); wire both mutation
  batteries into `mix quality`. CI pins Node 20 for the quality job.
- Close BAP-05 with ADR 0005 (corpus formats, sidecar rule, published-artifacts definition,
  applicability matrix + n_a criterion, census evolution, CLI contract, carve-out shape,
  gate set). The corpus ships in the published package; the fresh-consumer check runs the packaged
  escript against the packaged corpus, proving published-set sufficiency.


### Not yet available

- The portable verifier CLI and a public Hex release remain planned. The current package is
  unpublished.
