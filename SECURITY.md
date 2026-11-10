# Security policy

## Supported versions

The `1.0.x` source release line is supported. `v1.0.0` is the current tagged source release and contains
contract-majors 1, 2, and 3, the local-loopback application profile, the role-attestation and
content-assertion sibling profiles, the strict Ed25519 verification soundness repair (erratum 2),
the producer-canonicality signature refusal (erratum 3), and the selector float-zero soundness
repair (erratum 6). Its public API follows the
[1.x stability contract](docs/guides/api-stability.md). Registry consumers use the published Hex
archive: [registry release](https://hex.pm/packages/bounded_authority_protocol/1.0.0).

Releases `0.9.1` and earlier accept a float-tagged zero in an `equals` or `one_of` selector value
(erratum 6); they stay installable and are not supported. Releases `0.7.0` and earlier also
accept Ed25519 signatures that the strict rule rejects; releases `0.1.0` through `0.7.0` are
retired on Hex for security (see the security advisory
[GHSA-jwvm-w9r9-qqf8](https://github.com/baselabs/bounded_authority_protocol/security/advisories/GHSA-jwvm-w9r9-qqf8)).
Upgrade to `1.x` with the [upgrade guide](docs/guides/upgrading.md).

The verifier returns redacted, non-authorizing facts: trust and authorization, where a result
carries them, are explicitly not evaluated. The package does not select trust, hold keys, reserve
replay, inspect live revocation, certify deletion or retention, remove archives, or authorize an
effect — those are the responsibility of a stateful authority runtime and the consuming host.

## Reporting a vulnerability

Report privately through GitHub: open the repository's
[Security tab](https://github.com/baselabs/bounded_authority_protocol/security) and choose
**Report a vulnerability** (or go straight to the
[private report form](https://github.com/baselabs/bounded_authority_protocol/security/advisories/new)).
Private vulnerability reporting is enabled for this repository; only the maintainers see the
report. Do not open a public issue or pull request containing an exploit, credential, private
key, production data, or undisclosed vulnerability detail.

A report should identify the affected version or commit, the violated protocol property, a minimal
value-free reproduction, and the expected security outcome. We acknowledge, triage, fix, and
coordinate disclosure in the private advisory.

The same channel covers the verifier SDKs under `sdks/`. Report a vulnerability in the
TypeScript verifier through the Security tab of its own repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript/security).

For a vulnerability whose fix would change a verification verdict, see the
[governance policy § Security policy](docs/governance.md#security-policy) for the verdict-change
handling rule: a soundness repair (an erratum, with an advisory when governance requires one,
shipped by every implementation in the same release) when every condition of
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
