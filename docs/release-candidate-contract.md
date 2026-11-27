# Release-candidate contract

Package 1.0.0 is the first stable release. The current public API and its exclusions are
listed in [API stability and versioning](guides/api-stability.md); package version changes
follow [governance](governance.md#package-versions). Those contracts supersede the original
0.1.0 candidate's API list and pre-1.0 versioning rules. Release history is in the
[changelog](../CHANGELOG.md).

Candidate verification compares archive bytes and build provenance. It does not grant
operational authority or replace a deployment's authorization checks.

## Candidate verification

[CI](../.github/workflows/ci.yml) runs `mix quality.source`, `mix quality.corpus`,
`mix quality.tests`, `mix quality.conformance`, `mix quality.mutations` and
`mix quality.package` as separate jobs. `mix quality` runs them all locally. The package job
qualifies the exact Hex package and HTML docs archives, records the package checksum and
produces release and tooling CycloneDX documents. Attestation requires every quality stage to pass. In the same
`kci/<sha>` qualification run, the
[supply-chain workflow](../.github/workflows/supply-chain.yml) signs separate build-provenance
and SBOM attestations for that archive. Verify by source commit, because the attestation names
the qualification branch. The commit must be on `main` before release. Consumers download
the package and docs archives, `SHA256SUMS`, `release.cdx.json` and `tooling.cdx.json` from this repository's
GitHub release `baselabs_bounded_authority_protocol-v<version>`. To compare a candidate with those release files:

```bash
gh release download baselabs_bounded_authority_protocol-v<version> --repo baselabs/bounded_authority_protocol \
  --pattern '*.tar' --pattern '*-docs.tar.gz' --pattern SHA256SUMS --pattern '*.cdx.json'
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-<version>.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-digest <commit> \
  --deny-self-hosted-runners
```

The maintainers' release operator dispatches [publish.yml](../.github/workflows/publish.yml)
from `main` with `release_commit` set to the full qualified SHA. Publication verifies the
qualified package attestation before upload. In the `publish` environment, the shared
Hex action verifies the qualification artifact, package identity, source bytes and stamped
changelog. It refuses an unknown package, a tagged or retired version, or differing served
bytes. It uses a short-lived, package-scoped workload token to upload missing archives.
Public read-back compares both served archives byte for byte and checks that the docs'
`release.json` names the exact release commit.

A held upload is incomplete. After approval on Hex, dispatch the same commit again with
`qualification_run` set to the original CI run ID. Matching uploads are preserved. The
`release-assets` bundle contains the verified archives, checksums and SBOMs. The operator
tags the published commit and attaches these files to its GitHub release.
No workflow creates a GitHub release or runs on a tag.
[pages.yml](../.github/workflows/pages.yml) is also dispatch-only from `main`, limited to the
same maintainer accounts, and retains its `github-pages` environment.

An attested candidate is not a registry release. See the [security policy](../SECURITY.md)
for vulnerability reporting and the supported release line.

## Reproducibility

```bash
mix release.candidate
```

The [reproducibility gate](../scripts/check_release_candidate.exs) builds the archive twice
from fresh source-tree copies with separate dependency and build directories, then compares
their SHA-256 digests. It requires the Hex client pinned in `.hex-version`, because that
client's version enters archive metadata. The gate removes both copies when it finishes.

This is regression detection for nondeterministic packaged inputs, not proof that every
environment produces the same archive. Compare a local candidate and a CI candidate built
from the same source and pinned toolchain using their archive checksums.
