# Bounded Authority Protocol — Cross-language verifier SDKs

Typed, provider-neutral verifier libraries that reimplement the frozen BAP verification
profiles — contract-majors 1, 2, and 3 plus the local-loopback and role-attestation sibling
profiles — from the published specs ([v1](../spec/bap-v1.md), [v2](../spec/bap-v2.md),
[v3](../spec/bap-v3.md)) and the published conformance corpora
([`priv/conformance/`](../priv/conformance/)). They are **distribution
surfaces** — typed client libraries for third-party verifiers, not additional normativity — and
**none of the three authored here is published to a registry yet**: per
[ADR 0015](../docs/adr/0015-sdk-graduation-and-publish-topology.md), each graduates to its own
per-SDK repository on first publication, never from this monorepo (the `sdk-publish-guard`
pre-commit hook and CI job reject registry-publish infrastructure here). BAP-05 already closed the
corpus's normativity question via the independent Node runner
([`conformance/corpus_independent.mjs`](../conformance/corpus_independent.mjs)); these SDKs let third-party
verifiers consume the frozen v1 profile in their own language, with conformance independently verifiable
against the same published corpus.

## What is here

- **[`python/`](python/)** — `bounded-authority-verifier` (PyPI). Python >= 3.10, `cryptography` for
  Ed25519 and ECDSA P-256.
- **[`rust/`](rust/)** — `bounded-authority-protocol` (crates.io). Rust MSRV 1.81, `ed25519-dalek`
  (serial backend) + `sha2` + `ryu-js`. See its [README](rust/README.md) and the
  [deployment guide](../docs/deployment/rust-sdk.md) (AWS Lambda `provided.al2023` + PostgreSQL `plrust`
  posture).
- **[`go/`](go/)** — `bounded_authority_protocol_go`. Go 1.25 floor, zero runtime dependencies
  (stdlib `crypto/ed25519` + `crypto/elliptic` + `crypto/sha256` only). See its
  [README](go/README.md) and the [deployment guide](../docs/deployment/go-sdk.md).

The TypeScript SDK was the first to graduate (2026-09-14): it is published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
from its own repository,
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript)
— its source and conformance runners no longer live in this monorepo.

All four are **pure verification libraries** (no I/O, clock, RNG, or network in the verify path). They return
value-bearing redacted facts or `Invalid` — never an authorization decision. See
[ADR 0014](../docs/adr/0014-cross-language-verifier-sdks.md) for the packaging, support-surface, and
derivation-hygiene decisions.

Each SDK also implements the separately named local-loopback HTTP application profile: five public
surfaces, protected `typ: "ba+loopback-proof"`, mandatory nonce, literal `127.0.0.1`/`[::1]`
targets only, and mutual rejection with standard `dpop+jwt`. The shared profile corpus lives under
`priv/conformance/application-profiles/local-loopback-http/v1`; the three SDKs authored here pin
its exact index SHA-256 and execute the same 36 URI plus 8 proof cases. Each also implements the
role-attestation sibling profile
([ADR 0036](../docs/adr/0036-role-attestation-profile.md)): the four attestation surfaces, with
the certified 40-case profile corpus pinned the same way.

## Conformance

Each SDK passes every certified vector (valid + invalid) — the 283 v1, 268 v2, and 292 v3
contract-major corpora plus the loopback and role-attestation profile corpora — recomputing each
verdict from scratch using only its language's primitives. The conformance is independently
verifiable:

```bash
# Python (from sdks/python) — one runner per certified corpus
python tests/conformance/run.py
python tests/conformance/run_v2.py
python tests/conformance/run_v3.py

# Rust (from sdks/rust) — the conformance runners run inside the test suite
cargo test --locked

# Go (from sdks/go) — the conformance runners run inside the test suite
go test ./...
```

The graduated TypeScript SDK runs its vendored corpora in its own repository (`pnpm conformance`,
`conformance:v2`, `conformance:v3`, `conformance:role-attestation`).

Beyond the frozen corpus, each SDK ships a **per-language permissiveness mutation-gate** — for every
host-runtime closure (duplicate-rejecting decoder, null-prototype containers, raw-lexeme scan,
single-value, int/float tag distinction), a red-capable test that constructs the host-specific defect the
closure defeats and proves it goes RED when the closure is removed. This is the
[ADR 0005 § Independent-runner permissiveness](../docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md)
"prove each mirror with a case that goes red when the mirror is removed" discipline applied per-language,
closing the permissiveness class the frozen corpus has no cases for.

A SDK pins the corpus it was certified against by the SHA-256 of `index.json`; the runner asserts the
loaded corpus matches at startup (fails closed on mismatch).
