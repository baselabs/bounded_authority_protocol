# Interoperability report — BAP conformance cross-validation

**Status:** current for corpus revision 1, certified index digest
`TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs` (base64url SHA-256 of `index.json`;
hex `4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b`).
Every figure in this report is machine-derived: the certified digest and corpus revision come
from the corpus identity gates that run in `mix quality`; the case counts come from the
certified index; the per-implementation verdicts come from each implementation's own runner
executed against the identical corpus. This document is regenerated-against-gates, not
hand-maintained — a stale figure here fails the docs-currency surface.

Last regenerated September 28, 2026 against protocol commit
`cd3cec91c04ee4c3fae6746c511db9f04ebfef45` (Hex release 0.7.0) and the TypeScript verifier at
`0813a4c5f9710d324a2f2807e2307c23a4a555e4` (npm release 0.5.0). Every result below was
re-executed at those identities; the Go results used Go 1.25.14, the module's declared floor.

## Framing: test vectors + independent cross-validation

This is NOT an implementer's-list document. The evidence norm used here is the
test-vectors-plus-independent-cross-validation model: the conformance corpus is a set of
283 published test vectors across 28 verification surfaces, and interoperability is
demonstrated by independent implementations agreeing on every vector's verdict — including
the two-boundary public-key census — not by listing organizations. An implementation appears
here only with its independently re-executed result against the certified corpus snapshot or
in-place binding named above.

## The implementations

### Reference implementation

- **Elixir** (`bounded_authority_protocol`) — the reference verifier. Its deterministic CLI
  executes the full corpus: **283/283 agreed, 0 disagreed, census two-way equal (11 keys)**,
  asserting the certified index digest at startup.

### Cross-language verifier SDKs (independent reimplementations)

Each SDK was authored from the specification, the ADRs, and the conformance corpus ALONE
(ADR 0014's derivation-hygiene rule: no code-level derivation from the reference), and each
carries its own per-language permissiveness mutation-gate proving its closures red-capable.

| SDK | Language surface | Corpus binding | Result |
|---|---|---|---|
| `@bounded-authority-protocol/verifier` | TypeScript, Node >= 22, `node:crypto` only | graduated repository ([baselabs/bounded_authority_protocol_typescript](https://github.com/baselabs/bounded_authority_protocol_typescript)), vendored snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** (registry-distributed since 2026-09-14) |
| `bounded-authority-verifier` | Python >= 3.10, `cryptography` | in-place monorepo corpus, startup digest assertion | **283/283 agreed + census (11 keys)** |
| `bounded-authority-protocol` | Rust, MSRV 1.81, `ed25519-dalek`+`sha2` | vendored self-contained snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** |
| `bounded_authority_protocol_go` | Go 1.25, stdlib only | vendored self-contained snapshot, startup digest assertion | **283/283 agreed + census (11 keys)** |

### Local-loopback HTTP application-profile implementations

The byte-distinct `bap-application-proof/local-loopback-http/1` profile is certified by its own
revision-1 corpus at `priv/conformance/application-profiles/local-loopback-http/v1`. Its exact
index SHA-256 is `10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4`; the index binds exactly
`profile.json` and `proof-cases.json`.

The Elixir reference plus the TypeScript, Python, Rust, and Go implementations each report
**36/36 URI cases** and **8/8 proof cases**, including signed IPv4 and IPv6 artifacts, exact
producer/assembly bytes, trust and invocation binding, mandatory nonce, meaningful-byte tamper,
and mutual standard/local profile rejection. Each implementation pins the same index and per-file
hashes. This is repository-executed cross-validation: the TypeScript result was certified in this
repository at its graduation (2026-09-14) and its suite now lives in the graduated repository;
the Python, Rust, and Go SDKs remain unpublished.

### Contract-majors 2 and 3

The activated contract-majors are certified by their own revision-1 corpora, each bound by its
index SHA-256: v2 (`priv/conformance/v2/corpus`, 268 cases, index
`6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0`) and v3
(`priv/conformance/v3/corpus`, 292 cases, index
`a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c`).

| Implementation | v2 result | v3 result |
|---|---|---|
| Elixir reference CLI | **268/268 agreed**, 0 disagreed | **292/292 agreed**, 0 disagreed |
| TypeScript (`@bounded-authority-protocol/verifier` 0.5.0) | **268/268 agreed**, census two-way (17 keys) | **292/292 agreed**, census two-way (11 keys) |
| Python (`bounded-authority-verifier`) | **268/268 agreed**, census two-way (17 keys) | **292/292 agreed**, census two-way (11 keys) |
| Rust (`bounded-authority-protocol`) | **268/268 agreed**, census 17/17 | **292/292 agreed**, census 11/11 |
| Go (`bounded_authority_protocol_go`) | **268/268 agreed**, discovered keys within the 17 declared | **292/292 agreed**, discovered keys within the 11 declared |

The v2 and v3 census contract compares the curated key inputs with the index fingerprints in both
directions and requires every discovered key to be declared; the Go runner reports the discovered
subset and the declared total separately. Each runner asserts its corpus index digest before
executing any case.

### Role-attestation sibling profile

The byte-distinct `bap-role-attestation/1` profile (ADR 0036) is certified by its revision-1
corpus at `priv/conformance/attestation-profiles/role-attestation/v1`, index SHA-256
`be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a`, binding exactly
`profile.json` and `attestation-cases.json`.

| Implementation | Result |
|---|---|
| Elixir reference (`mix role_attestation.verify`) | **40/40 decode and 40/40 verify agreed**, cross-profile rejection against v1, v2, and v3 |
| TypeScript 0.5.0 | **40/40 decode and 40/40 verify agreed**, producer and assembly bytes equal the certified compact, cross-profile rejection in both directions |
| Python | certified-corpus test passes; asserts 40 cases against the pinned index |
| Rust | certified-corpus test passes; asserts 40 cases against the pinned index |
| Go | certified-corpus test passes; asserts 40 cases against the pinned index |

### Content-assertion sibling profile

The byte-distinct `bap-content-assertion/1` profile (ADR 0037, first released in 0.7.0) is
certified by its revision-1 corpus at `priv/conformance/attestation-profiles/content-assertion/v1`,
index SHA-256 `14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`, binding eight
files: 131 assertion cases, 9 content-digest cases, and 14 successor cases.

| Implementation | Result |
|---|---|
| Elixir reference (`mix content_assertion.verify`) | corpus consumer passes on the pinned index, 0 failures |
| TypeScript 0.5.0 | **131 assertions, 9 digests, 14 successors agreed**; 38 producer and assembly byte checks |
| Python | certified-corpus tests pass; assert 131, 9, and 14 cases and the 38 producer vectors |
| Rust | certified-corpus and successor tests pass; case counts equal the pinned index |
| Go | certified-corpus and successor tests pass; asserts 131, 9, and 14 cases |

Before the 0.7.0 publication, the holder-side companion signer produced a content assertion
against the built package, and the independent Python verifier accepted it with exact
content-digest equality; changed content, a wrong key, and `now == exp` were refused. The
published registry checksum equals that build.

### Independent Node second-implementation runners

Three runner-authored-from-the-corpus Node implementations (node:* only; the corpus is the
normative oracle for their verdicts):

| Runner | Scope | Result |
|---|---|---|
| `conformance/corpus_independent.mjs` | full 283-case corpus + tamper verbatim audit | **agreed=283 disagreed=0; census two-way equal** |
| `conformance/grant_proof_independent.mjs` | grant/proof vectors | **full agreement on its vector set** |
| `conformance/chain_archive_independent.mjs` | chain/archive tamper + semantic vectors | **full agreement on its vector set** |

## Methodology

1. The corpus is the normative test-vector set: 283 cases, 28 surfaces, 16 conformance
   classes (valid/boundary/exact/maximum-plus-one plus twelve rejection classes), with a
   tamper-verbatim audit re-deriving every tamper case from its base.
2. An implementation binds to the corpus either in-place (startup digest assertion against
   the certified value above) or through a vendored byte-identical snapshot (sync-gated).
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
The repository's `mix quality` runs the reference CLI, all three independent Node runners,
the corpus-identity gates, and the real IPv4/IPv6 local-profile transport drill on every change.
The Elixir suite and the three in-repo SDKs execute the same application-profile corpus through
their native APIs; the TypeScript suite's equivalent runs live in its graduated repository.

## Current limitations (stated, not hidden)

- Three of the four SDKs — Python, Rust, and Go — are not published to registries (ADR 0015:
  graduation on first publication); their cross-validation above is repository-executed, not
  registry-distributed. The TypeScript SDK graduated on first publication (2026-09-14) and is
  published from its own repository.
- For the Python, Rust, and Go SDKs the attestation-profile rows report their certified-corpus
  tests (which assert the pinned index and the exact case counts), not a separate agreement
  printout. The Elixir and TypeScript rows report their runners' printed agreement figures.
- The local-profile real-socket drill is implemented in the Elixir release gate. The other SDK
  results certify bytes and verdicts against the shared corpus, not live transport composition.
