# Security policy

## Supported versions

The published `0.1.x` line is supported; `0.1.1` is the current release. The public API surface is
locked and consumption uses the Hex release.

The verifier returns redacted, non-authorizing facts: trust and authorization, where a result
carries them, are explicitly not evaluated. The package does not select trust, hold keys, reserve
replay, inspect live revocation, certify deletion or retention, remove archives, or authorize an
effect — those are the responsibility of a stateful authority runtime and the consuming host.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting / security-advisory flow for
`baselabs/bounded_authority_protocol`. Do not open a public issue containing an exploit,
credential, private key, production data, or unreleased vulnerability detail.

A report should identify the affected version or commit, the violated protocol property, a minimal
value-free reproduction, and the expected security outcome. We will acknowledge, triage, remediate,
and coordinate disclosure through the private advisory.

For a vulnerability whose fix would change a verification verdict, see the
[governance policy § Security policy](docs/governance.md#security-policy) for the verdict-change
handling rule (an accelerated, published, deployment-decided contract-major overlap — never a
silent verdict change).

## Supply-chain verification

Every trusted-main CI build produces the package archive, a SHA-256 checksum, release and tooling
CycloneDX SBOM documents, and separate build-provenance and SBOM attestations. A downloaded archive
can be verified with:

```bash
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-<version>.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```
