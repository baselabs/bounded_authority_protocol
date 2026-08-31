# Python verifier SDK — deployment guide

The Python verifier SDK (`sdks/python/`, package `bounded-authority-verifier`) is a pure,
deterministic, fail-closed reimplementation of the BAP v1 profile. It is a **verifier**: it
returns redacted, value-bearing facts or a single rejection, never an authorization decision.

See `spec/bap-v1.md` (the normative authority; `docs/protocol-v1.md` is its generated view)
and [ADR 0014](../adr/0014-cross-language-verifier-sdks.md) for the packaging and
derivation-hygiene decisions.

## Runtime posture

- Python >= 3.10; `cryptography` for Ed25519 (the single runtime dependency).
- Pure functions only: no clock, network, filesystem, or randomness in the verify path. Time,
  trusted keys, and expected context are explicit inputs.
- Type-annotated throughout (`mypy`-clean under the repo's SDK config); facts results are
  frozen dataclasses with redacted rendering.

## Deployment targets

| Target | Notes |
|---|---|
| Any WSGI/ASGI service | Verify at the boundary; pass RAW credential bytes, never pre-decoded dicts |
| AWS Lambda (python3.12+) | Layer or bundle the package with the pinned `cryptography` wheel; the verifier is synchronous and bounded |
| Container services | Standard wheel install; no native build step for the SDK itself (`cryptography` ships wheels) |

## Local-loopback application profile

Local development listeners select `local_loopback_http_uri_normalize`,
`local_loopback_http_proof_signing_input`, `assemble_local_loopback_http_compact`,
`decode_local_loopback_http_proof`, and `check_local_loopback_http_envelope` explicitly. Admit only
direct literal `127.0.0.1`/`[::1]` HTTP targets and require the server nonce. Never derive the target
from `Forwarded`/`X-Forwarded-*`, accept `localhost`, or retry standard `dpop+jwt` after rejection.

## Supply-chain posture

One runtime dependency (`cryptography`, BSD-3-Clause/Apache-2.0 dual). Consumers SHOULD pin
the exact versions and verify install-time integrity; the SDK's own conformance runner is
dev-tooling only and is not installed with the package.

## Verification is not authority

A green verification proves byte-level properties against the inputs the CALLER supplied.
Trust selection, replay reservation, and revocation belong to a stateful authority runtime;
see the specification's verification-contract section for the boundary in normative terms.
