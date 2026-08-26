# `bounded-authority-verifier`

A provider-neutral, deterministic **verifier** SDK for bounded proof-of-possession authority — a
typed Python reimplementation of the BAP v1 verification profile.

This is one of four cross-language verifier SDKs ([ADR 0014][adr14] — TypeScript, Python, Rust, Go)
that reimplement the frozen v1
profile from the published [spec][spec] and [conformance corpus][corpus] alone, with no code-level
derivation from the Elixir reference. It is a **verification** library: a successful result proves
only that caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
selects trusted keys, reserves replay, grants execution, or overrides a host policy.

[adr14]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0014-cross-language-verifier-sdks.md
[adr15]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0015-sdk-graduation-and-publish-topology.md
[spec]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/protocol-v1.md
[corpus]: https://github.com/baselabs/bounded_authority_protocol/blob/main/priv/conformance/v1/corpus/

## Status

`0.1.0` — SemVer 0.x (pre-1.0). The public v1 façade is frozen; breaking changes bump the major
version once 1.0 lands. The SDK targets Python `>= 3.10` and has a single runtime dependency:
[`cryptography`][cryptography] (the one unavoidable crypto dep — the stdlib has no Ed25519).
SHA-256, base64url, and JSON canonicalization are hand-rolled from the RFCs.

[cryptography]: https://pypi.org/project/cryptography/

## Conformance

This SDK is certified against the published corpus (`priv/conformance/v1/corpus/`) and passes every
one of its **283** valid + invalid vectors, recomputed from scratch — not cached verdicts. The
conformance runner asserts the corpus `index.json` SHA-256 at startup
(`4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b`), so a consumer who vendors a
mismatched corpus snapshot gets a hard failure rather than a silent drift ([ADR 0014 D4][adr14]).

```bash
uv pip install -e .
python tests/conformance/run.py   # 283/283 + two-boundary key census
```

Permissiveness is invisible to corpus agreement by construction, so each parser-layer closure is
additionally proven **red-capable** by a per-language mutation-gate
(`python -m pytest tests/test_permissiveness.py`) — the ADR 0005 discipline applied per-language:
construct the host-specific defect the closure defeats, assert the SDK rejects it, and prove the test
goes red when the closure is mechanically removed ([ADR 0014 D6/D7][adr14]).

## Install

Not yet published to PyPI. Per the [SDK graduation model][adr15], this SDK graduates to its own
per-SDK repository (`bounded_authority_protocol_python`) on first publication — never from
this monorepo. The package name `bounded-authority-verifier` is a reserved identifier recorded
for the graduated publish.

## Quickstart — verify a grant

`verify_grant` checks a compact-JWS grant against a caller-trusted issuer key and expected context
(issuer, audience, evaluation time, clock skew, bounds). It returns `Ok(GrantFacts)` on success or
`Err` on any failure — never a decision.

```python
from bounded_authority_verifier import (
    verify_grant, ExpectedGrant, TrustedIssuer, Ok,
)

# The raw compact-JWS grant bytes (ASCII), produced out-of-band by an issuer.
grant_compact = (
    b"eyJhbGciOiJFZERTQSIsInR5cCI6ImJhK2NhcCIsImtpZCI6Imlzc3Vlci1rZXkifQ."
    b"<payload>.<signature>"
)

result = verify_grant(
    grant_compact,
    TrustedIssuer(
        key_id="issuer-key",            # must match the grant header `kid` exactly
        public_key=issuer_public_key,   # raw 32-byte Ed25519 public key
    ),
    ExpectedGrant(
        issuer="https://issuer.example",
        audience="https://resource.example",
        evaluation_time=1731728000,     # caller-supplied, seconds since epoch
        clock_skew=60,
    ),
)

if isinstance(result, Ok):
    facts = result.value                # GrantFacts — value-bearing, redacted (frozen dataclass)
    facts.issuer_key_fingerprint        # bytes(32) — raw SHA-256 thumbprint
    facts.holder_thumbprint             # bytes(32) — the bound holder key
    facts.authorization                 # "not_evaluated" — NOT a decision
else:
    # result is Err — a closed, value-free rejection. Any structural, signature,
    # header, claim, or time-window failure lands here. The SDK fails closed and
    # carries no detail (mirrors {:error, :invalid}).
    pass
```

The `Result[T]` shape mirrors the Elixir `{:ok, value} | {:error, :invalid}`: `Ok(value)` or
`Err` — the failure branch carries no value and no reason. There is no `allowed`, `authorized`,
`decision`, or receipt — facts are value-bearing frozen dataclasses and redacted, never execution
credentials.

## The public façade

The 17 frozen v1 functions ([protocol-v1.md § Public verification contract][spec]):

| Function | Returns | Purpose |
|---|---|---|
| `verify_grant` | `Result[GrantFacts]` | Verify a compact grant against a trusted issuer + expected context |
| `check_envelope` | `Result[EnvelopeFacts]` | Re-verify the grant and bind the holder proof, request, nonce, and selectors |
| `decode_grant` / `decode_proof` | `Result[GrantDecoded\|ProofDecoded]` | Structural decode (verification: not_evaluated) |
| `untrusted_key_locator` | `Result[KeyLocator]` | Header-only key id (trust: not_evaluated) |
| `request_digest` | `bytes(32)` | Typed, type-preserving request hash (`BAP1-REQUEST` prefix) |
| `encode_consumption_entry` / `check_chain` | `Result[EncodedConsumptionEntry\|ChainFacts]` | Canonical consumption rows + range verification |
| `grant_signing_input` / `proof_signing_input` | `Result[SigningInput]` | Deterministic producer signing inputs |
| `assemble_compact` | `bytes` | External signature assembly (no private keys in the SDK) |
| `boundary_anchor_signing_input` / `key_transition_signing_input` | `Result[SigningInput]` | Anchor + historical-key-transition producers |
| `encode_anchored_export` / `verify_anchored_export` | `Result[EncodedAnchoredExport\|AnchoredExportFacts]` | Deterministic archive framing + atomic verification |
| `verify_historical_anchor` / `verify_key_transition` | `Result[AnchorFacts\|KeyTransitionFacts]` | Historical boundary + authenticated rollover verification |

Plus the versioned primitives: `jwk_encode_public`, `jwk_decode_public`, `thumbprint`,
`uri_normalize`, `bounds_new`, `bounds_maximum`, `jcs_encode`, `base64url_decode`/`base64url_encode`,
and the tagged JSON algebra. See [`src/bounded_authority_verifier/__init__.py`](src/bounded_authority_verifier/__init__.py)
for the full export list.

## What this SDK does NOT do

It is a **verifier**, not an authority runtime. It holds no private keys, makes no network or
filesystem calls, reads no clock (`evaluation_time` is an explicit input), and performs no replay
reservation, revocation check, or policy decision. Selecting trusted keys, reserving replay, and
granting execution belong to the host — a `GrantFacts`/`EnvelopeFacts` value is evidence, not a
credential. See [AGENTS.md § Critical rules][agents] and [ADR 0014 D3][adr14].

[agents]: https://github.com/baselabs/bounded_authority_protocol/blob/main/AGENTS.md

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e . ruff mypy pytest
ruff check src/ tests/ tools/     # lint (the library-path purity rule is in the tools/ gate)
mypy src/                         # --strict, warnings-as-errors
python tools/purity_check.py      # AST purity gate (no I/O/clock/RNG/network in src/)
python tools/license_check.py     # dependency-license gate
python -m pytest tests/           # permissiveness mutation-gate + conformance wrapper
python tests/conformance/run.py   # 283/283 + two-boundary key census
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
