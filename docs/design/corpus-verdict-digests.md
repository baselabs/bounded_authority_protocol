# Corpus verdict digests

The Hex release carries the complete `priv/conformance/` tree. Each unpublished verifier SDK
vendors a standalone projection at `conformance/priv/conformance/` beneath its own root.
Shared case files, schemas and focused vectors match the Hex bytes. The SDK manifest contains
the ten entries those standalone suites execute. The Hex manifest also covers three profiles
first released in 1.5.0. Each corpus directory contains exactly its index plus the files it names.

The manifest was introduced in 1.1.0. Adding the three profiles preserves the previous ten
entries, their certified indexes, and their verdicts.

## Ordering

Ordering is index order as the contract, independent of how the Elixir loader accumulates;
every runner, the Elixir one included, reorders to index order before digesting.

For each corpus, visit the index's `files` array in order, then the cases in each file's
array order. An object envelope contributes its `cases` array. The loopback profile's
`profile.json` contributes its `uri_cases` array. Sidecars, revision records, and header
objects (`format`, `families`, `class_mapping`, `case_envelope`) contribute no cases.
Only cases with IDs in the certified case inventory contribute pairs. In particular, the
two loopback `proofs` input fixtures have no IDs or outcome fields. Their API tests still
run, but they add no digest pairs. The loopback digest therefore has 44 cases; its CLI
report retains its existing additional fixture checks.

The loader currently sorts paths and accumulates loaded files in reverse. That storage
order does not define digest order. Match execution results by their unique case ID and
emit them in the index's declared order. Duplicate, unknown, or unexecuted IDs fail.

## Outcome projections

Use a case's `expected` member verbatim whenever present, including every nested value.
Otherwise use exactly the outcome members below. Member names identify outputs, never
inputs or modifiers. In particular, `expected_overrides`, `compact`, `construction`,
`request`, key material, `note`, and `rule` do not contribute.

| Corpus | Surface or case schema | Outcome members | Normative basis |
|---|---|---|---|
| `v1/corpus` | All 28 surfaces | `expected` verbatim | [BAP1 §16, Public verification contract](../../spec/bap-v1.md#verification) and the indexed surface case schemas |
| `v2/corpus` | All surfaces | `expected` verbatim | [BAP2 §6](../../spec/bap-v2.md#6-conformance-corpus) and the indexed surface case schemas |
| `v3/corpus` | All surfaces | `expected` verbatim | [BAP3 §7](../../spec/bap-v3.md#7-conformance-corpus) and the indexed surface case schemas |
| `producer-canonicality` | Compact assembly and anchored-export encoding | `expected` verbatim | [BAP3 §3.2 and §7](../../spec/bap-v3.md#signatures) and indexed `profile.json` |
| `selector-float-zero` | Grant decode, signing input, envelope | `expected` verbatim | [BAP2 §4 and §6](../../spec/bap-v2.md#4-selector-algebra) and indexed `profile.json` |
| `application-profiles/local-loopback-http/v1` | URI normalization (`uri_cases`) | `valid`; also `normalized` exactly when `valid` is true | [Local loopback HTTP §3](../../spec/bap-local-loopback-http-v1.md#3-target-uri) and [§6](../../spec/bap-local-loopback-http-v1.md#6-conformance-and-release) |
| `application-profiles/local-loopback-http/v1` | Proof decode and envelope (`proof-cases.json`) | `decode_local`, `decode_standard`, `envelope_local` | [Local loopback HTTP §6](../../spec/bap-local-loopback-http-v1.md#6-conformance-and-release) and the indexed proof case schema |
| `attestation-profiles/role-attestation/v1` | Attestation decode and verify | `decode`, `verify` | [Role attestation §6](../../spec/bap-role-attestation-v1.md#6-conformance-and-release) and the indexed attestation case schema |
| `attestation-profiles/content-assertion/v1` | Assertion, digest, successor | `expected` verbatim | [Content assertion §8](../../spec/bap-content-assertion-v1.md#8-conformance-and-release) and indexed case schemas |
| `strict-ed25519` | Primitive, key acceptance, shaped major 1/2 surfaces, content assertion | `expected` verbatim | [BAP1 §14.1](../../spec/bap-v1.md#strict-ed25519) and indexed `profile.json`, `case_envelope.primitive`, `.v1_shaped`, `.content_assertion` |
| `strict-ed25519` | `local_loopback_http` | `decode_local`, `decode_standard`, `envelope_local` | [BAP1 §14.1](../../spec/bap-v1.md#strict-ed25519), [local loopback HTTP §6](../../spec/bap-local-loopback-http-v1.md#6-conformance-and-release), indexed `profile.json`, `case_envelope.loopback` |
| `strict-ed25519` | `role_attestation` | `decode`, `verify` | [BAP1 §14.1](../../spec/bap-v1.md#strict-ed25519), [role attestation §6](../../spec/bap-role-attestation-v1.md#6-conformance-and-release), indexed `profile.json`, `case_envelope.role_attestation` |
| `string-or-uri` | `role_attestation`, `content_assertion` | `decode`, `verify` | [Erratum 7](../errata.md) |
| `string-or-uri` | Grant decode in majors 1, 2, and 3 | `expected` verbatim | [Erratum 7](../errata.md) |

The role corpus's optional `v1_grant` cross-profile diagnostic is separately asserted by
its tests. The role surface's digest projection is `decode` and `verify`, as in the strict
profile's role schema. A case without `expected` must match its declared projection:
URI outcomes are a boolean and, on success, a normalized string; proof and role outcomes
are booleans. Missing or mistyped outcome members fail generation.

## Encoding and verification

Form `[[id, value], ...]`, encode the array with RFC 8785 JCS, hash its bytes with SHA-256,
and encode the hash as unpadded base64url. The expected manifest uses the projections
above. Each runner instead uses the values computed by its SDK, independently of its
expected-value comparator. An always-pass comparator therefore cannot establish a
matching digest. Container encoding may stream JCS components to avoid applying a
protocol message's resource ceilings to this tooling aggregate.

`scripts/regen_verdict_digests.exs` implements this contract and fails when the checked-in
manifest is stale. The manifest is a JCS object without a trailing newline, matching the
corpus JSON convention. Its format is `bap-corpus-verdict-digests/1`; each corpus entry
binds its index SHA-256, case count, and expected verdict digest.

## SDK distribution boundary

Dependency manifests and lockfiles are parsed to reject local dependency paths that resolve
outside the SDK root. The source traversal scan is an early lint with counted, individually
reviewed exceptions; it cannot prove what arbitrary executable code will read. The binding
self-containment guarantee is the copied-alone isolated package run, including the unpacked
Python sdist, Rust crate, and Go module zip. Every SDK suite must pass with only its own tree
available. Mutation controls exercise manifest escapes and representative source-lint bypasses.


## Profiles first released in 1.5.0

The ES256 content assertion, holder custody attestation, and action approval indexes pin
`verdict_sha256` over the full declared inventory. Their projection is the JCS array of
`[file + "/" + id, expected]` pairs in index and case order. The index stores the SHA-256
in lowercase hexadecimal.

The Elixir CLI substitutes its observed outcomes and checks `elixir_verdict_sha256`.
It excludes approval's `helper-cases.json` and any case marked `owner: "sdk_helper"`
from that projection. In the Hex manifest for these profiles, `case_count` counts the
executed Elixir cases, `sdk_owned_case_count` counts the rest, and the verdict digest
encodes the Elixir projection as unpadded base64url.

Each profile has its own CLI report format identifier.

- `bounded-authority-protocol-action-approval-conformance-report`
- `bounded-authority-protocol-content-assertion-es256-conformance-report`
- `bounded-authority-protocol-holder-custody-attestation-conformance-report`

These reports include `profile`, `elixir_verdict_sha256`, and `sdk_owned` in addition to the
common fields. Approval requires all 202 applicable Elixir cases to execute and agree. Its 129
SDK-owned cases run in the Python, Rust, and Go source-checkout suites, which also run the 223
ES256 assertion cases. All 76 custody cases run in Elixir. The published TypeScript verifier
qualifies the exact profiles through its own release process.
