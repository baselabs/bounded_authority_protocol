# Release-candidate contract

This document is the candidate-facing contract for the unpublished `0.1.0` package. It states the
locked public API surface, the versioning posture, and the candidate-verification recipe a reviewer
follows to compare a local candidate against a CI-attested candidate. It is **evidence a human
reviewer compares**, not an authority shape — there is no decision, receipt, or authorization here
(per `AGENTS.md` rule 1, "verification is not authority ... there is no `allowed?`, `authorized?`,
`decision`, or receipt"). The decision record is [ADR 0008](adr/0008-release-candidate-contract.md).

## Status

`0.1.0` is a **release candidate**. No version is published to Hex. BAP-06 froze this candidate;
BAP-07 (connected verification and first public release) publishes the exact candidate, after the
private-runtime connected gates pass and a fresh correctness/security/gate-integrity/cross-vendor
review closes with zero open findings.

## Locked public API surface (0.1.0)

The locked API is the set of modules and functions a consumer depends on. It is enforced
mechanically and enumerated here for human readers + SemVer review.

**Mechanical enforcement:** `tools/architecture_gate.exs` `@compiled_export_allowances` pins the
exact compiled exports per `.beam` for the dominant contract modules (the `V1` facade, `V1.Runtime`,
the codecs, the public structs) — any export addition, removal, or arity change to those turns
`mix architecture` red. The named decoder/bounds submodules (`V1.Json`, `V1.Base64Url`, `V1.Bounds`)
are enforced under `@compiled_dynamic_allowances` (dynamic-call-count): removal/rename/arity change
of their existing functions surfaces via the dynamic-call check plus the unpacked-consumer gate.
The `V1.beam` facade pin is the authoritative full-arity lock for the dominant surface; the
enumeration below lists primary arities.

**`BoundedAuthorityProtocol.V1`** facade (`lib/bounded_authority_protocol/v1.ex`):

| Category | Functions |
|---|---|
| Producer | `grant_signing_input/2`, `proof_signing_input/2`, `boundary_anchor_signing_input/2`, `key_transition_signing_input/2`, `assemble_compact/2` |
| Decode / verify | `untrusted_key_locator/2`, `decode_grant/2`, `decode_proof/2`, `verify_grant/3`, `check_envelope/2`, `request_digest/3`, `encode_consumption_entry/2`, `check_chain/2`, `encode_anchored_export/2`, `verify_historical_anchor/3`, `verify_key_transition/4`, `verify_anchored_export/3` |

**Named submodules:** `BoundedAuthorityProtocol.V1.Json.decode/2`,
`BoundedAuthorityProtocol.V1.Base64Url.decode/2` (the only decoder façade, per
[ADR 0002](adr/0002-normative-v1-parsing-profile.md)).

**Public structs:** `GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`,
`KeyTransitionFacts`, `AnchoredExportFacts`, plus the `Expected*` / `Historical*` / input structs a
consumer builds, and `BoundedAuthorityProtocol.V1.Bounds` (the tightening-only bounds constructor).

Anything else in `lib/` is internal.

## Versioning posture

0.1.0 is the first release-candidate version. Under pre-1.0 SemVer (SemVer §4), the 0.x.y line
reserves the right to break compatibility until 1.0.0. The API lock above is the commitment that the
enumerated surface is the intended 1.0.0 surface; breaking changes before 1.0.0 land as `0.x.0`
version bumps with a [CHANGELOG](CHANGELOG.md) entry, never silently.

- Removal, rename, signature change, or a new REQUIRED argument to a locked function: a major
  change (`0.x→0.(x+1)` before 1.0.0), requiring an `@compiled_export_allowances` allowlist edit in
  the same commit.
- A new optional argument or a new additive function: a minor change (`0.0.x→0.0.(x+1)`), requiring
  an allowlist extension.
- 1.0.0 (first stable) is a future decision; BAP-06 does not declare stability.

## Candidate verification

Every trusted-main CI build produces an unpublished Hex archive, a SHA-256 checksum, release and
tooling CycloneDX documents, and separate GitHub build-provenance and SBOM attestations. A reviewer
verifies a candidate against the CI-attested record with:

```bash
sha256sum --check SHA256SUMS
gh attestation verify bounded_authority_protocol-0.1.0.tar \
  --repo baselabs/bounded_authority_protocol \
  --signer-workflow baselabs/bounded_authority_protocol/.github/workflows/supply-chain.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

These are not releases, do not grant authority, and do not replace the connected release gates in
BAP-07. The full security policy, including vulnerability reporting, is in
[SECURITY.md](SECURITY.md).

### Reproducibility

The candidate archive is checked for reproducibility on every `mix quality` run (local, CI, and
supply-chain) via the `release.candidate` gate. The gate builds the archive twice with `_build` and
`deps` purged between builds and asserts byte-identical SHA-256. A green run prints the candidate
archive SHA-256 — the same yardstick `SHA256SUMS` uses — so a local candidate and a CI-attested
candidate at the same commit compare on the same basis.

```bash
mix release.candidate
```

The gate's claim is "two independent builds agree," scoped as regression detection: it catches the
moment a future change introduces a non-deterministic packaged input. It does not assert the build
is reproducible from a shared-cache self-comparison. See [ADR 0008](adr/0008-release-candidate-contract.md)
for the scope and the rejected alternatives.
