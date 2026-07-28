# Security policy

## Supported versions

No released version exists yet. This file becomes version-specific with the first public release.

The current unpublished 0.1.0 source implements bounded parsing, deterministic standard compact
JWS grant and RFC 9449 holder-proof production, standalone raw-grant verification, and combined
raw-envelope verification. It also implements canonical consumption-chain, historical-anchor,
authenticated rollover, and exact anchored-export verification against caller-supplied
boundaries, digest, and out-of-band object version. Results are redacted facts with trust and
authorization, where the result carries it, explicitly not evaluated; the package does not select
trust, reserve replay, inspect live revocation state, certify deletion/retention, remove archives,
or authorize an effect.

Final BAP-03 package-bearing verification source
`f322e08bba665374599b9f53c362966b6b59710a` passed
[CI run 30331438234](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30331438234)
and
[supply-chain run 30331438252](https://github.com/baselabs/bounded_authority_protocol/actions/runs/30331438252)
at that exact revision. The unpublished archive SHA-256 is
`2f09d66c68e3538aa1e0020710d7f2aaca07528ef60fcf571c5006212e3bf056`; its checksum,
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
