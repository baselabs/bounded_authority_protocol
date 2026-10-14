# Bounded Authority Protocol verifier SDKs

Typed, provider-neutral verifier libraries for the Bounded Authority Protocol in Python, Rust,
and Go. Each implements contract-majors 1, 2, and 3 and the local-loopback, role-attestation,
and content-assertion sibling profiles, from the specifications ([v1](../spec/bap-v1.md),
[v2](../spec/bap-v2.md), [v3](../spec/bap-v3.md), and the profile specifications under
[`spec/`](../spec/)) and the certified conformance corpora under
[`priv/conformance/`](../priv/conformance/). They are distribution surfaces for third-party
verifiers, not additional normative text.

**None of the three is published to a registry yet.** Install them from this repository by
local path or Git commit; each README shows how. Each SDK moves to its own repository when it is
first published, never publishing from this one
([ADR 0015](../docs/adr/0015-sdk-graduation-and-publish-topology.md)); a pre-commit hook and a
CI job reject registry-publish setup here.

## What is here

- **[`python/`](python/)**: `bounded-authority-verifier` (planned PyPI name; import
  `bounded_authority_verifier`). Python 3.10 or later; one dependency, `cryptography`, for
  Ed25519 and ECDSA P-256.
- **[`rust/`](rust/)**: `bounded-authority-protocol` (planned crates.io name). Rust 1.81 or
  later; `ed25519-dalek`, `p256`, `sha2`, `ryu-js`, and an exact `zeroize` pin. See the
  [deployment notes](../docs/deployment/rust-sdk.md) for AWS Lambda and PostgreSQL.
- **[`go/`](go/)**: module path `github.com/baselabs/bounded_authority_protocol_go`. Go 1.25 or
  later; standard library only (`crypto/ed25519`, `crypto/ecdsa`, `crypto/elliptic`,
  `crypto/sha256`, `crypto/subtle`, `math/big`). See the
  [deployment notes](../docs/deployment/go-sdk.md).

The TypeScript verifier was the first to move (September 14, 2026). It is published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
from [`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript);
its source and conformance runners no longer live here.

All four are pure verification libraries (no I/O, clock, randomness, or network in the library).
They return redacted facts or a single value-free rejection, never an authorization decision.
Their behavior is defined by the specifications and the corpora; the in-repository SDKs' source
comments cross-reference the Elixir reference implementation for traceability.
[ADR 0014](../docs/adr/0014-cross-language-verifier-sdks.md) records the packaging and support
decisions.

## Known gaps

- **Erratum 3 (producer canonicality) is not implemented in any of the three.** Their compact
  assembly and anchored-export encoding check the signature width but not its value, so they can
  assemble an Ed25519 signature with `S >= L` or a non-canonical or small-order `R`, or an ES256
  signature that is out of range or high-S. Every verifier rejects such a credential. None of
  them runs the `bap-producer-canonicality/1` corpus yet. The published TypeScript verifier
  (0.7.0) does not implement erratum 3 either.
- **Facts rendering.** The specification requires facts to have a fixed redacted rendering.
  The Python `repr`, the Rust derived `Debug`, and Go's `fmt` formatting print every field.
  Facts never hold secrets, but log the fields you need by name.
- **Python `v3` export.** `bounded_authority_verifier.v3` is not listed in the package's
  `__all__`; import it explicitly.

## Profiles each SDK implements

- **Local-loopback HTTP proofs**: five surfaces, protected `typ: "ba+loopback-proof"`, a
  mandatory nonce, literal `127.0.0.1`/`[::1]` targets only, and mutual rejection with standard
  `dpop+jwt`. Each SDK pins the profile corpus index SHA-256 and runs its 36 URI and 8 proof
  cases.
- **Role attestations** ([ADR 0036](../docs/adr/0036-role-attestation-profile.md)): the four
  attestation surfaces and the 40-case corpus.
- **Content assertions** ([ADR 0037](../docs/adr/0037-content-assertion-profile.md)):
  verification, both digest functions, pairwise successor checks, the producer, and assembly,
  with the 131 assertion, 9 digest, and 14 successor cases.
- **Strict Ed25519** ([ADR 0040](../docs/adr/0040-strict-ed25519-soundness-erratum.md)): rule S1
  at each SDK's single Ed25519 verification point, the `verify_strict`, `acceptable_public_key`,
  and `torsion_free` helpers in the language's naming, and the strict-Ed25519 corpus
  (`bap-strict-ed25519/1`, [`priv/conformance/strict-ed25519`](../priv/conformance/strict-ed25519/),
  2,410 cases in 14 families, index SHA-256
  `732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`). Python reads it in place;
  Go and Rust carry byte-identical snapshots under `conformance/corpus-strict/`. Its 12 "Taming
  the many EdDSAs" vectors come from
  [ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck) (Apache-2.0),
  attributed in the root and per-SDK `NOTICE` files.

## Conformance

Each SDK passes every case of the 283-case v1, 268-case v2, and 292-case v3 corpora and the
profile corpora above, recomputing each verdict with its own language's primitives. Each pins
the SHA-256 of every corpus `index.json` it was certified against and fails at load on a
mismatch. To check:

```bash
# Python (from sdks/python): one runner each for v1, v2, v3, and strict Ed25519; pytest runs the
# profile corpora and the quickstart
python tests/conformance/run.py
python tests/conformance/run_v2.py
python tests/conformance/run_v3.py
python tests/conformance/run_strict.py
python -m pytest tests/

# Rust (from sdks/rust): every corpus and the README quickstart run inside the test suite
cargo test --locked

# Go (from sdks/go): every corpus and the quickstart example run inside the test suite
go test ./...
```

The TypeScript verifier runs its vendored corpora in its own repository.

Beyond the corpora, each SDK has a permissiveness battery: for every parser closure that guards
against a host-language trap (duplicate-rejecting decoding, raw numeric-lexeme limits, a single
value with no trailing content, the integer and float distinction), a test builds the defect
the closure exists to reject and proves the closure catches it. This applies the
[ADR 0005](../docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md) independent-runner
discipline per language, covering a class the corpus has no cases for.
