# Interoperability report — BAP v1 conformance cross-validation

**Status:** current for corpus revision 1, certified index digest
`TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs` (base64url SHA-256 of `index.json`;
hex `4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b`).
Every figure in this report is machine-derived: the certified digest and corpus revision come
from the corpus identity gates that run in `mix quality`; the case counts come from the
certified index; the per-implementation verdicts come from each implementation's own runner
executed against the identical corpus. This document is regenerated-against-gates, not
hand-maintained — a stale figure here fails the docs-currency surface.

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
| `@bounded-authority/verifier` | TypeScript, Node >= 22, `node:crypto` only | in-place monorepo corpus, startup digest assertion | **283/283 agreed + census (11 keys)** |
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
hashes. This is repository-executed cross-validation; the four SDK packages are still unpublished.

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
5. The application-profile corpus is separate from the standard corpus. Each implementation
   verifies the exact two-file set and counts, then executes all URI and proof cases through its
   separately named local-profile surfaces; no implementation infers or retries a profile.

## Reproducing

Any implementation can reproduce this report: obtain the corpus (it ships in the package and
the repository), verify the certified digest above, run all 283 cases, and check the census.
The repository's `mix quality` runs the reference CLI, all three independent Node runners,
the corpus-identity gates, and the real IPv4/IPv6 local-profile transport drill on every change.
The four SDK suites execute the same application-profile corpus through their native APIs.

## Current limitations (stated, not hidden)

- The SDKs are not published to registries (ADR 0015: graduation on first publication); the
  cross-validation above is repository-executed, not registry-distributed.
- The report covers the frozen standard v1 profile and the local-loopback HTTP application
  profile only; successor-majors carry their own corpus and report sections when they activate.
- The local-profile real-socket drill is implemented in the Elixir release gate. The other SDK
  results certify bytes and verdicts against the shared corpus, not live transport composition.
