# Python verifier SDK: deployment notes

The Python verifier SDK (`sdks/python/`, distribution `bounded-authority-verifier`, import
package `bounded_authority_verifier`) is a pure, deterministic implementation of the BAP
verification profiles: contract-majors 1, 2, and 3 plus the local-loopback, role-attestation,
and content-assertion sibling profiles. It is a **verifier**: it returns redacted facts or a
value-free rejection, never an authorization decision. The
[SDK README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/python/README.md)
has the quickstart and the full API list.

## Not published yet

The package is not on PyPI. It moves to its own repository when it is first published
(ADR 0015). Until then, install it from
this repository at a pinned commit:

```bash
pip install "bounded-authority-verifier @ git+https://github.com/baselabs/bounded_authority_protocol@<commit>#subdirectory=sdks/python"
```

or from a local checkout with `pip install ./bounded_authority_protocol/sdks/python`. Without a
published version, the commit is the identity of what you deployed.

Erratum 3 (producer canonicality) is not implemented in this package yet: `assemble_compact`,
`encode_anchored_export` (and their `v2` and `v3` forms), `assemble_local_loopback_http_compact`,
`assemble_attestation_compact`, and `assemble_content_assertion_compact` do not refuse a
non-canonical signature. Verification is unaffected. See the SDK README.

## Runtime posture

- Python 3.10 or later is declared; CI tests Python 3.13.
- One runtime dependency, `cryptography` `>= 44.0.0` (Ed25519 and ECDSA P-256). Nothing in the
  repository pins its exact version for consumers: the development lock file is not committed,
  and CI installs `cryptography` 50.0.0. Pin the version you deploy.
- Pure functions only: no clock, network, filesystem, or randomness in the library. Time,
  trusted keys, and expected context are explicit inputs.
- Type-annotated throughout (`mypy --strict` clean). Facts are frozen dataclasses; their `repr`
  prints every field (no redacted rendering yet), so log the fields you need by name.

## Deployment targets

| Target | Notes |
|---|---|
| Any WSGI or ASGI service | Verify at the request boundary; pass the raw compact bytes, never pre-decoded values |
| AWS Lambda (Python 3.12 or later) | Bundle the package with a `cryptography` wheel built for the Lambda architecture; verification is synchronous and bounded |
| Container services | A standard install; the package itself has no native build step, and `cryptography` ships wheels |

## Local-loopback application profile

Local development listeners select `local_loopback_http_uri_normalize`,
`local_loopback_http_proof_signing_input`, `assemble_local_loopback_http_compact`,
`decode_local_loopback_http_proof`, and `check_local_loopback_http_envelope` explicitly. Admit only
direct literal `127.0.0.1`/`[::1]` HTTP targets and require the server nonce. Never derive the target
from `Forwarded`/`X-Forwarded-*`, accept `localhost`, or retry standard `dpop+jwt` after rejection.

## Strict Ed25519 verification

Every Ed25519 verification in the SDK applies rule S1 of
ADR 0040 at its single Ed25519 verification
point: canonical point encodings, no small-order key or `R`, a scalar below the group order, and
the cofactorless equation. Key import, JWK encode and decode, and thumbprint functions refuse a
key that fails key acceptance. Call `torsion_free` at key enrollment, at trust install, and
before any deny-list or revocation comparison. The strict-Ed25519 corpus
(`priv/conformance/strict-ed25519`) runs through `tests/conformance/run_strict.py` with its index
SHA-256 pinned.

## Supply chain

One runtime dependency (`cryptography`, Apache-2.0 or BSD-3-Clause). Pin the exact versions you
deploy and verify install-time integrity (for example with `pip install --require-hashes`). The
conformance runners and tests are development tooling and are not installed with the package.

## Verification is not authority

A successful verification proves byte-level properties against the inputs the caller supplied.
Trust selection, replay reservation, and revocation belong to your service or a stateful
authority runtime; the specification's verification-contract section states the boundary in
normative terms.
