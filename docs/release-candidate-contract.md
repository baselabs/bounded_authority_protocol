# Release-candidate contract

Package 1.0.0 is the first stable release. The current public API and its exclusions are
listed in [API stability and versioning](guides/api-stability.md); package version changes
follow [governance](governance.md#package-versions). Those contracts supersede the original
0.1.0 candidate's API list and pre-1.0 versioning rules. Release history is in the
[changelog](../CHANGELOG.md).

Candidate verification compares archive bytes and build provenance. It does not grant
operational authority or replace a deployment's authorization checks.

## Candidate verification

[CI](../.github/workflows/ci.yml) builds an unpublished Hex archive in its complete quality job,
with its SHA-256 checksum and release and tooling CycloneDX documents. In the same
`kci/<sha>` qualification run, the
[supply-chain workflow](../.github/workflows/supply-chain.yml) signs separate build-provenance
and SBOM attestations for that archive. Verify by source commit, because the attestation names
the qualification branch. The commit must be on `main` before release. To compare a candidate
with those artifacts:

```bash
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-<version>.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-digest <commit> \
  --deny-self-hosted-runners
```

The maintainers' release operator dispatches [publish.yml](../.github/workflows/publish.yml)
from `main` to publish the Hex package after qualification. It rejects an already published
or tagged version, builds docs and the archive without a cache, and checks package identity,
file inventory and source bytes before publication. Contributors and agents do not publish,
tag or dispatch. The operator verifies the published release and tags its exact commit.
[pages.yml](../.github/workflows/pages.yml) is also dispatch-only from `main` and retains its
`github-pages` environment.

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
