# Security policy

## Supported versions

The `0.8.x` source release line is supported. `v0.8.0` is the current tagged source release
and contains contract-majors 1, 2, and 3, the role-attestation and content-assertion sibling
profiles, and the strict Ed25519 verification soundness repair
([ADR 0040](docs/adr/0040-strict-ed25519-soundness-erratum.md), erratum 2). The public API
surface is locked. Registry consumers use the published Hex archive. Releases `0.7.0` and
earlier accept Ed25519 signatures that the strict rule rejects and are not supported; upgrade to
`0.8.x` and run the pre-upgrade key scan in ADR 0040. See the security advisory for the affected
versions and details.

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
handling rule: a soundness repair (an erratum with an advisory, shipped by every implementation
in the same release, followed by a public ratification window) when every condition of
[§ Soundness repairs](docs/governance.md#soundness-repairs) holds, and otherwise an accelerated,
published, deployment-decided contract-major overlap. A verdict never changes silently.

## Supply-chain verification

The supply-chain workflow runs on every push to `main` that changes `mix.exs`, `mix.lock`, or a
package manifest (a version bump always does), weekly, and on manual dispatch from `main`. Each run
produces the package archive, a SHA-256 checksum, release and tooling CycloneDX SBOM documents, and
separate build-provenance and SBOM attestations. A downloaded archive can be verified with:

```bash
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-<version>.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```
