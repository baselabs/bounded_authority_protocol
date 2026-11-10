# Interoperability report — BAP conformance cross-validation

**Status:** current for corpus revision 1, certified index digest
`TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs` (base64url SHA-256 of `index.json`;
hex `4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b`).
Every figure in this report is machine-derived: the certified digests and corpus revisions come
from the corpus identity gates that run in `mix quality`; the case counts come from the certified
indexes; the per-implementation verdicts come from each implementation's own runner executed
against the identical corpus. A stale figure here fails the docs-currency tests.

Last regenerated November 9, 2026. Every result below was re-executed that day at these
identities:

| Implementation | Identity | Toolchain |
|---|---|---|
| Elixir reference | protocol commit `205d1b598f6fc01de4e412798ed1e81578ccc69e` (source for the next release after 0.9.1) | Elixir 1.20.2, Erlang/OTP 29 |
| TypeScript verifier | `bounded_authority_protocol_typescript` commit `88e86762e908e483ca054e14e6abbd18f3e65e8f` (package version 1.0.0 plus the unreleased erratum 6) | Node 22.23.1, pnpm 10.20.0 |
| Python SDK | `sdks/python` 0.1.0 at the protocol commit above | CPython 3.13.13, `cryptography` 50.0.2 |
| Rust SDK | `sdks/rust` 0.1.0 at the protocol commit above | Rust 1.81.0, the crate's declared minimum |
| Go SDK | `sdks/go` at the protocol commit above | Go 1.25.14, the module's declared floor |
| Independent Node runners | `conformance/*.mjs` at the protocol commit above | Node 22.23.1 |

## Framing: test vectors + independent cross-validation

This is NOT an implementer's-list document. The evidence norm used here is the
test-vectors-plus-independent-cross-validation model: the contract-major 1 conformance corpus is a
set of 283 published test vectors across 28 verification surfaces, and interoperability is
demonstrated by independent implementations agreeing on every vector's verdict — including the
two-boundary public-key census — not by listing organizations. An implementation appears here only
with its independently re-executed result against the certified corpus snapshot or in-place
binding named above.

## Summary

Agreed cases out of the certified total, per implementation and corpus:

| Corpus | Cases | Elixir | TypeScript | Python | Rust | Go |
|---|---|---|---|---|---|---|
| Contract-major 1 | 283 | 283/283 | 283/283 | 283/283 | 283/283 | 283/283 |
| Contract-major 2 | 268 | 268/268 | 268/268 | 268/268 | 268/268 | 268/268 |
| Contract-major 3 | 292 | 292/292 | 292/292 | 292/292 | 292/292 | 292/292 |
| `bap-strict-ed25519/1` | 2,410 | 2410/2410 | 2410/2410 | 2410/2410 | pass | 2410/2410 |
| `bap-producer-canonicality/1` | 75 | 75/75 | 75/75 | 75/75 | pass | 75/75 |
| `bap-selector-float-zero/1` | 161 | 161/161 | 161/161 | 161/161 | pass | 161/161 |
| Local-loopback HTTP | 36 URI + 8 proof | 36/36, 8/8 | 36/36, 8/8 | pass | pass | pass |
| Role attestation | 40 | 40/40 | 40/40 | pass | pass | pass |
| Content assertion | 131 + 9 + 14 | pass | 131 + 9 + 14 | pass | pass | pass |

"pass" means the implementation's certified-corpus test passed: it asserts the pinned index and
the exact case counts and fails on any disagreement, but prints no agreement count. No run
disagreed on any case.

## The implementations

### Reference implementation

- **Elixir** (`bounded_authority_protocol`) — the reference verifier. Its deterministic CLI
  executes the full corpus: **283/283 agreed, 0 disagreed, census two-way equal (11 keys)**,
  asserting the certified index digest at startup.

### Cross-language verifier SDKs (independent reimplementations)

Each SDK's behavior is defined by the [specifications](../../spec/bap-v1.md) and the certified
conformance corpora, not by the Elixir code; the Python, Rust, and Go sources carry comments that
cross-reference the Elixir reference implementation by file for traceability. Each carries its own
per-language permissiveness mutation gate proving its closures red-capable.

| SDK | Language surface | Corpus binding | Contract-major 1 result |
|---|---|---|---|
| `@bounded-authority-protocol/verifier` | TypeScript, Node >= 22, `node:crypto` only | graduated repository ([baselabs/bounded_authority_protocol_typescript](https://github.com/baselabs/bounded_authority_protocol_typescript)), vendored snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** |
| `bounded-authority-verifier` | Python >= 3.10, `cryptography` | in-place monorepo corpus, startup digest assertion | **283/283 agreed + census (11 keys)** |
| `bounded-authority-protocol` | Rust, MSRV 1.81, `ed25519-dalek`+`p256`+`sha2` | vendored self-contained snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** |
| `bounded_authority_protocol_go` | Go 1.25, stdlib only | vendored self-contained snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** |

The TypeScript verifier is published to npm; the Python, Rust, and Go SDKs are not yet published
to any registry.

### Local-loopback HTTP application-profile implementations

The byte-distinct `bap-application-proof/local-loopback-http/1` profile is certified by its own
revision-1 corpus at `priv/conformance/application-profiles/local-loopback-http/v1`. Its exact
index SHA-256 is `10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4`; the index
binds exactly `profile.json` and `proof-cases.json`.

| Implementation | Result |
|---|---|
| Elixir reference (profile test suite) | **36/36 URI cases** and **8/8 proof cases** against the pinned index |
| Elixir transport drill (`mix local_loopback_http.verify`) | real IPv4 and IPv6 listeners: valid and misleading-authority-header requests verified, wrong nonce rejected; the verifier-bypass, `Host`-header and forwarded-header mutations each proven red |
| TypeScript | **44/44 cases agree (36 URI, 8 proof)**, producer and assembly byte symmetry for the IPv4 and IPv6 proofs |
| Python | certified-corpus tests pass |
| Rust | certified-corpus tests pass |
| Go | certified-corpus test passes |

Every implementation pins the same index and per-file hashes, including signed IPv4 and IPv6
artifacts, exact producer and assembly bytes, trust and invocation binding, the mandatory nonce,
meaningful-byte tamper, and mutual standard/local profile rejection.

### Contract-majors 2 and 3

Contract-majors 2 and 3 are certified by their own revision-1 corpora, each bound by its index
SHA-256: contract-major 2 (`priv/conformance/v2/corpus`, 268 cases, index
`6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0`) and contract-major 3
(`priv/conformance/v3/corpus`, 292 cases, index
`a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c`).

| Implementation | Contract-major 2 | Contract-major 3 |
|---|---|---|
| Elixir reference CLI | **268/268 agreed**, 0 disagreed | **292/292 agreed**, 0 disagreed |
| TypeScript | **268/268 agreed**, census two-way (17 keys) | **292/292 agreed**, census two-way (11 keys) |
| Python | **268/268 agreed**, census two-way (17 keys) | **292/292 agreed**, census two-way (11 keys) |
| Rust | **268/268 agreed**, census 17/17 | **292/292 agreed**, census 11/11 |
| Go | **268/268 agreed**, every discovered key among the 17 declared | **292/292 agreed**, every discovered key among the 11 declared |

The census for these majors compares the curated key inputs with the index fingerprints in both
directions and requires every discovered key to be declared; the Go runner checks the discovered
subset against the declared set. Each runner asserts its corpus index digest before executing any
case.

### Role-attestation sibling profile

The byte-distinct `bap-role-attestation/1` profile ([specification](../../spec/bap-role-attestation-v1.md))
is certified by its revision-1 corpus at `priv/conformance/attestation-profiles/role-attestation/v1`,
index SHA-256 `be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a`, binding exactly
`profile.json` and `attestation-cases.json`.

| Implementation | Result |
|---|---|
| Elixir reference (`mix role_attestation.verify`) | **40/40 decode and 40/40 verify agreed**, cross-profile rejection against contract-majors 1, 2, and 3 |
| TypeScript | **40/40 decode and 40/40 verify agreed**, producer and assembly bytes equal the certified compact, cross-profile rejection in both directions |
| Python | certified-corpus test passes; asserts 40 cases against the pinned index |
| Rust | certified-corpus test passes; asserts 40 cases against the pinned index |
| Go | certified-corpus test passes; asserts 40 cases against the pinned index |

### Content-assertion sibling profile

The byte-distinct `bap-content-assertion/1` profile ([specification](../../spec/bap-content-assertion-v1.md))
is certified by its revision-1 corpus at `priv/conformance/attestation-profiles/content-assertion/v1`,
index SHA-256 `14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`, binding eight
files: 131 assertion cases, 9 content-digest cases, and 14 successor cases.

| Implementation | Result |
|---|---|
| Elixir reference (`mix content_assertion.verify`) | corpus consumer passes on the pinned index, 0 failures |
| TypeScript | **131 assertions, 9 digests, 14 successors agreed**; 38 producer and assembly byte checks |
| Python | certified-corpus tests pass; assert 131, 9, and 14 cases and the 38 producer vectors |
| Rust | certified-corpus and successor tests pass; case counts equal the pinned index |
| Go | certified-corpus and successor tests pass; asserts 131, 9, and 14 cases |

### Strict-Ed25519 corpus

The additive `bap-strict-ed25519/1` corpus ([erratum 2](../errata.md)) is certified by its
revision-1 index at `priv/conformance/strict-ed25519`, SHA-256
`732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`: 2,410 cases in 14 families,
with expected verdicts from an independent arithmetic generator and the 12 published
"Taming the many EdDSAs" vectors. It changes no figure above.

| Implementation | Result |
|---|---|
| Elixir reference (`bounded_authority_conformance --corpus priv/conformance/strict-ed25519`) | **agreed=2410 disagreed=0** |
| TypeScript (`conformance:strict-ed25519`) | **every case agrees** across 2,410 cases in 14 families |
| Python (`tests/conformance/run_strict.py`, reads the corpus in place) | **2410/2410 cases agree** |
| Go (`go test ./conformance/`, vendored `conformance/corpus-strict`) | **agreed=2410/2410** |
| Rust (`cargo test --locked`, vendored `conformance/corpus-strict`) | **pass** |
| Independent Node runner (`node conformance/corpus_independent.mjs --strict priv/conformance/strict-ed25519`) | **agreed=2017 disagreed=0**; it implements contract-major 1, so the 393 contract-major 2 and sibling-profile cases are reported as not covered |

### Producer-canonicality corpus

The additive `bap-producer-canonicality/1` corpus ([erratum 3](../errata.md)) is certified by its
revision-1 index at `priv/conformance/producer-canonicality`, SHA-256
`99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601`: 75 cases in 4 families (60
refused, 15 accepted at the rule's bound), generated keylessly from certified signatures. It
changes no figure above.

| Implementation | Result |
|---|---|
| Elixir reference (`bounded_authority_conformance --corpus priv/conformance/producer-canonicality`) | **agreed=75 disagreed=0** |
| TypeScript (`conformance:producer-canonicality`) | **75/75 agreed** (60 refused, 15 accepted with bytes unchanged) |
| Python (`tests/conformance/run_producer_canonicality.py`) | **75/75 agreed** (60 refused, 15 accepted) |
| Go (`go test ./conformance/`) | **75/75 agreed** (60 refused, 15 accepted with bytes unchanged) |
| Rust (`cargo test --locked`, `conformance_producer_canonicality`) | **pass** |

### Selector float-zero corpus

The additive `bap-selector-float-zero/1` corpus ([erratum 6](../errata.md)) is certified by its
revision-1 index at `priv/conformance/selector-float-zero`, SHA-256
`97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003`: 161 cases (98 rejected, 63
accepted) covering grant decode, envelope verification, and grant signing input on every
contract-major. It changes no figure above.

| Implementation | Result |
|---|---|
| Elixir reference (`bounded_authority_conformance --corpus priv/conformance/selector-float-zero`) | **agreed=161 disagreed=0** |
| TypeScript (`conformance:selector-float-zero`) | **161/161 agreed** (98 rejected, 63 accepted with certified outputs) |
| Python (`tests/conformance/run_selector_float_zero.py`) | **161/161 agreed** (98 rejected, 63 accepted) |
| Go (`go test ./conformance/`) | **agreed=161/161 disagreed=0** (98 rejected, 63 accepted) |
| Rust (`cargo test --locked`, `conformance_selector_float_zero`) | **pass** |
| Independent Node runner (`node conformance/corpus_independent.mjs --selector-float-zero priv/conformance/selector-float-zero`) | **agreed=43 disagreed=0**; the 118 cases outside its contract-major 1 surfaces are reported as not covered |

### Independent Node second-implementation runners

Three runners written from the corpus, using `node:*` modules only (the corpus is the normative
oracle for their verdicts):

| Runner | Scope | Result |
|---|---|---|
| `conformance/corpus_independent.mjs` | full 283-case corpus + tamper verbatim audit | **agreed=283 disagreed=0; census two-way equal (11 keys)** |
| `conformance/grant_proof_independent.mjs` | grant/proof vectors | **ok**: 3 vectors, 7 tamper cases, 18 URI cases |
| `conformance/chain_archive_independent.mjs` | chain/archive tamper + semantic vectors | **ok**: 3 archives, 2 chain cases, 49 tamper cases, 7 semantic cases |

## Methodology

1. The contract-major 1 corpus is the normative test-vector set: 283 cases, 28 surfaces, 16
   conformance classes (valid/boundary/exact/maximum-plus-one plus twelve rejection classes),
   with a tamper-verbatim audit re-deriving every tamper case from its base.
2. An implementation binds to a corpus either in place (startup digest assertion against the
   certified value) or through a vendored byte-identical snapshot (sync-gated).
3. A run reports per-case agreement plus the two-boundary key census
   (discovered == verify-imported == index fingerprint set); any disagreement, crash, or
   census asymmetry fails the run.
4. Every implementation additionally ships a permissiveness mutation battery: the guard
   families that keep it from being MORE permissive than the reference are each proven
   red-capable (construct the defect, watch the test go green, fix).
5. Each application-profile and attestation-profile corpus is separate from the standard corpora.
   Each implementation verifies the exact declared file set and counts, then executes every case
   through the profile's separately named surfaces; no implementation infers or retries a profile.

## Reproducing

Any implementation can reproduce this report: obtain the corpus (it ships in the package and
the repository), verify the certified digest above, run all 283 cases, and check the census.
The repository's `mix quality` runs the reference CLI on every contract-major and additive corpus,
the three independent Node runners, the corpus-identity gates, and the real IPv4/IPv6
local-profile transport drill on every change. The Elixir suite and the three in-repository SDKs
execute the sibling-profile corpora through their native APIs; the TypeScript runs live in its own
repository.

## Current limitations (stated, not hidden)

- Three of the four SDKs — Python, Rust, and Go — are not published to registries; each moves
  to its own repository on first publication. Their cross-validation above is
  repository-executed, not registry-distributed. The TypeScript verifier is published from its
  own repository.
- The TypeScript row was run at that repository's `main`, which carries the erratum 6 repair
  ahead of its next release; the published npm 1.0.0 predates erratum 6 and returns the
  pre-repair verdicts recorded in the [errata registry](../errata.md).
- Rows marked "pass" report the implementation's certified-corpus test (which asserts the pinned
  index and the exact case counts and fails on any disagreement), not a printed agreement count.
- The independent Node runner implements contract-major 1 only, so it reports the strict-Ed25519
  and selector float-zero cases of other majors and sibling profiles as not covered; the
  reference and the four SDKs run all of them.
- The local-profile real-socket drill is implemented in the Elixir release gate. The other SDK
  results certify bytes and verdicts against the shared corpus, not live transport composition.
