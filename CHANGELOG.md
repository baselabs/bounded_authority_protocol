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

### Not yet available

- The portable verifier CLI and a public Hex release remain planned. The current package is
  unpublished.
