# Bounded Authority Protocol — Cross-language verifier SDKs

Typed, provider-neutral verifier libraries that reimplement the BAP v1 verification profile from the
published spec ([`spec/bap-v1.md`](../spec/bap-v1.md)) and consume the published conformance
corpus ([`priv/conformance/v1/corpus/`](../priv/conformance/v1/corpus/)). They are **distribution
surfaces** — typed client libraries for third-party verifiers, not additional normativity — and
**none is published to a registry yet**: per
[ADR 0015](../docs/adr/0015-sdk-graduation-and-publish-topology.md), each graduates to its own
per-SDK repository on first publication, never from this monorepo (the `sdk-publish-guard`
pre-commit hook and CI job reject registry-publish infrastructure here). BAP-05 already closed the
corpus's normativity question via the independent Node runner
([`conformance/corpus_independent.mjs`](../conformance/corpus_independent.mjs)); these SDKs let third-party
verifiers consume the frozen v1 profile in their own language, with conformance independently verifiable
against the same published corpus.

## What is here

- **[`typescript/`](typescript/)** — `@bounded-authority/verifier` (npm). Node >= 22, `node:crypto` (zero
  non-stdlib deps by default).
- **[`python/`](python/)** — `bounded-authority-verifier` (PyPI). Python >= 3.10, `cryptography` for
  Ed25519.
- **[`rust/`](rust/)** — `bounded-authority-protocol` (crates.io). Rust MSRV 1.81, `ed25519-dalek`
  (serial backend) + `sha2` + `ryu-js`. See its [README](rust/README.md) and the
  [deployment guide](../docs/deployment/rust-sdk.md) (AWS Lambda `provided.al2023` + PostgreSQL `plrust`
  posture).
- **[`go/`](go/)** — `bounded_authority_protocol_go`. Go 1.25 floor, zero runtime dependencies
  (stdlib `crypto/ed25519` + `crypto/sha256` only). See its [README](go/README.md) and the
  [deployment guide](../docs/deployment/go-sdk.md).

All four are **pure verification libraries** (no I/O, clock, RNG, or network in the verify path). They return
value-bearing redacted facts or `Invalid` — never an authorization decision. See
[ADR 0014](../docs/adr/0014-cross-language-verifier-sdks.md) for the packaging, support-surface, and
derivation-hygiene decisions.

## Conformance

Each SDK passes every one of the 283 published conformance vectors (valid + invalid), recomputing each
verdict from scratch using only its language's primitives. The conformance is independently verifiable:

```bash
# TypeScript
pnpm --filter @bounded-authority/verifier conformance

# Python
uv run --project sdks/python conformance

# Rust
cargo test --test conformance --manifest-path sdks/rust/Cargo.toml
```

Beyond the frozen corpus, each SDK ships a **per-language permissiveness mutation-gate** — for every
host-runtime closure (duplicate-rejecting decoder, null-prototype containers, raw-lexeme scan,
single-value, int/float tag distinction), a red-capable test that constructs the host-specific defect the
closure defeats and proves it goes RED when the closure is removed. This is the
[ADR 0005 § Independent-runner permissiveness](../docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md)
"prove each mirror with a case that goes red when the mirror is removed" discipline applied per-language,
closing the permissiveness class the frozen corpus has no cases for.

A SDK pins the corpus it was certified against by the SHA-256 of `index.json`; the runner asserts the
loaded corpus matches at startup (fails closed on mismatch).
