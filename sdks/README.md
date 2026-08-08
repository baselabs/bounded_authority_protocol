# Bounded Authority Protocol — Cross-language verifier SDKs

Typed, provider-neutral verifier libraries that reimplement the BAP v1 verification profile from the
published spec ([`docs/protocol-v1.md`](../docs/protocol-v1.md)) and consume the published conformance
corpus ([`priv/conformance/v1/corpus/`](../priv/conformance/v1/corpus/)). They are **distribution
surfaces** — published, typed client libraries — not additional normativity. BAP-05 already closed the
corpus's normativity question via the independent Node runner
([`conformance/corpus_independent.mjs`](../conformance/corpus_independent.mjs)); these SDKs let third-party
verifiers consume the frozen v1 profile in their own language, with conformance independently verifiable
against the same published corpus.

## What is here

- **[`typescript/`](typescript/)** — `@bounded-authority/verifier` (npm). Node >= 20, `node:crypto` (zero
  non-stdlib deps by default).
- **[`python/`](python/)** — `bounded-authority-verifier` (PyPI). Python >= 3.10, `cryptography` for
  Ed25519.

Both are **pure verification libraries** (no I/O, clock, RNG, or network in the verify path). They return
value-bearing redacted facts or `Invalid` — never an authorization decision. See
[ADR 0014](../docs/adr/0014-cross-language-verifier-sdks.md) for the packaging, support-surface, and
derivation-hygiene decisions.

## Conformance

Each SDK passes every one of the 259 published conformance vectors (valid + invalid), recomputing each
verdict from scratch using only its language's primitives. The conformance is independently verifiable:

```bash
# TypeScript
pnpm --filter @bounded-authority/verifier conformance

# Python
uv run --project sdks/python conformance
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
