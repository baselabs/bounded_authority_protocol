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

### Not yet available

- Chain/archive verification, the portable verifier CLI, and a public Hex release remain planned.
  The current package is unpublished.
