# Security policy

## Supported versions

The unpublished `0.1.0` package is a **release candidate** — no version is published to Hex. The
public API surface is locked ([release-candidate contract](docs/release-candidate-contract.md));
BAP-07 (connected verification and first public release) publishes the exact candidate after the
private-runtime connected gates pass. This file becomes version-specific with that first release.

The current unpublished 0.1.0 source implements bounded parsing, deterministic standard compact
JWS grant and RFC 9449 holder-proof production, standalone raw-grant verification, and combined
raw-envelope verification. It also implements canonical consumption-chain, historical-anchor,
authenticated rollover, and exact anchored-export verification against caller-supplied
boundaries, digest, and out-of-band object version. Results are redacted facts with trust and
authorization, where the result carries it, explicitly not evaluated; the package does not select
trust, reserve replay, inspect live revocation state, certify deletion/retention, remove archives,
or authorize an effect.

Final BAP-04 package-bearing verification source
`c4d7716de6499f29524e60638207b1c36e9484b3` passed
[CI run 30414161666](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30414161666)
and
[supply-chain run 30414161690](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30414161690)
at that exact revision. The unpublished archive SHA-256 is
`b947777a512e0e917eb42aa85fc9525087f1e555c0eba1944832431a8978a169`; its checksum,
SLSA provenance, and CycloneDX SBOM attestation were independently verified.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or security-advisory flow for
`baselabs/bounded_authority_protocol`. Do not open a public issue containing an exploit,
credential, private key, production data, or unreleased vulnerability detail.

A report should identify the affected version or commit, the violated protocol property, a
minimal value-free reproduction, and the expected security outcome. BaseLabs will acknowledge,
triage, remediate, and coordinate disclosure through the private advisory.

## Supply-chain verification

Every trusted-main CI build creates an unpublished Hex archive, SHA-256 checksum, release and
tooling CycloneDX documents, a build-provenance attestation, and an SBOM attestation. Downloaded CI
archives can be checked with:

```bash
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-0.1.0.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

These artifacts prove the CI build source and package boundary. They are not published releases,
do not grant authority, and do not replace the connected release gates in `BAP-07`.
