# Security policy

## Supported versions

No released version exists yet. This file becomes version-specific with the first public release.

The current 0.1.0 source scaffold is unpublished and contains no protocol verifier behavior.

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
