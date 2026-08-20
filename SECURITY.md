# Security policy

## Supported versions

The published `0.1.0` package is the exact reviewed release candidate — BAP-07 (connected
verification and first public release) executed 2026-08-20. The public API surface is locked
([release-candidate contract](docs/release-candidate-contract.md)); consumption uses the Hex
release, and `0.1.0` is the only supported version.

The current 0.1.0 source implements bounded parsing, deterministic standard compact
JWS grant and RFC 9449 holder-proof production, standalone raw-grant verification, and combined
raw-envelope verification. It also implements canonical consumption-chain, historical-anchor,
authenticated rollover, and exact anchored-export verification against caller-supplied
boundaries, digest, and out-of-band object version. Results are redacted facts with trust and
authorization, where the result carries it, explicitly not evaluated; the package does not select
trust, reserve replay, inspect live revocation state, certify deletion/retention, remove archives,
or authorize an effect.

As of 2026-08-18, the most recent package-bearing verified source is the SDK behavioral-closure
cluster head `c281938d6c31862e6f09a53a55c9dd71eea975aa`, which passed
[CI run 32118915019](https://github.com/baselabs/bounded_authority_protocol/actions/runs/32118915019)
and
[supply-chain run 32118915034](https://github.com/baselabs/bounded_authority_protocol/actions/runs/32118915034)
at that exact revision. The CI-attested (ubuntu-built) candidate archive SHA-256 is
`c9b5b0cff54994cd92ec1c05daa1d5eea4c490abac1737f57f7bb26a73904d58`; its checksum and
build-provenance attestation were independently verified against that source digest via the
verification recipe below. (The local `release.candidate` gate's SHA differs because it builds on
darwin — the gate compares two builds within one run on one platform, not cross-platform.)

Earlier package-bearing verified heads, each with checksum, provenance, and SBOM attestations at
that exact revision: BAP-06 `4c64be36ada1c167214471847d4061ea5ff63c56` (CI run 31029289860,
supply-chain run 31029289864; unpublished archive SHA-256
`abe962eb7fddefdc1906d5bb6baea38518ca017e0b6dab957497293ee12cf515`), BAP-05
`ce20a8b12e7b715f5373a72763e46adff7b3e30f` (CI run 30918991087, supply-chain run 30918990587;
unpublished archive SHA-256
`dd0a17eada43f1f60c8f2f23f92575dd4f995a02d93043b1ac097bb954f936df`), and BAP-04
`c4d7716de6499f29524e60638207b1c36e9484b3` (CI run 30414161666, supply-chain run 30414161690;
unpublished archive SHA-256
`b947777a512e0e917eb42aa85fc9525087f1e555c0eba1944832431a8978a169`).

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or security-advisory flow for
`baselabs/bounded_authority_protocol`. Do not open a public issue containing an exploit,
credential, private key, production data, or unreleased vulnerability detail.

A report should identify the affected version or commit, the violated protocol property, a
minimal value-free reproduction, and the expected security outcome. BaseLabs will acknowledge,
triage, remediate, and coordinate disclosure through the private advisory.

For vulnerabilities whose fix would change a verification verdict, see the
[governance policy § Security policy](docs/governance.md#security-policy) for the verdict-change
handling rule.

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
