# Python verifier SDK: deployment notes

The Python verifier SDK (`sdks/python/`, distribution `bounded-authority-protocol-verifier`, import
package `bounded_authority_verifier`) is a pure, deterministic implementation of the BAP
verification profiles: contract-majors 1, 2, and 3 plus the local-loopback, role-attestation,
and content-assertion sibling profiles. It is a **verifier**: it returns redacted facts or a
value-free rejection, never an authorization decision. The
[SDK README](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/python/README.md)
has the quickstart and the full API list.

## Not published yet

The package is not on PyPI, and any package of this name there is not ours until this page
says otherwise. It moves to its own repository when it is first published.
Start in an empty directory and use the [complete pinned install and executed
quickstart](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/python/README.md#install-from-a-pinned-source). It creates a virtual
environment, installs the selected full Git commit and verifies a grant and proof before
showing an argument-mismatch refusal. The source commit is the unpublished deployment identity.

Erratum 3 (producer canonicality) is implemented: `assemble_compact`,
`encode_anchored_export` (and their `v2` and `v3` forms), `assemble_local_loopback_http_compact`,
`assemble_attestation_compact`, and `assemble_content_assertion_compact` refuse a non-canonical
signature. No verification verdict changes. See the SDK README.

## Runtime posture

- Python 3.11 is the minimum. CI runs Python 3.11, 3.12, and 3.13.
- One runtime dependency, `cryptography` `>= 50.0.0` (Ed25519 and ECDSA P-256). Nothing in the
  runtime declaration forces that exact version on consumers. CI installs the committed
  `uv.lock` (`cryptography` 50.0.2), then audits the 50.0.0 floor separately. Pin the version
  you deploy.
- Pure functions only: no clock, network, filesystem, or randomness in the library. Time,
  trusted keys, and expected context are explicit inputs.
- Type-annotated throughout (`mypy --strict` clean). Facts are slotted value
  objects with read-only properties and redacted `repr` / `str`, as the SDK README specifies.
  Read named properties for explicit application projections; generic dataclass export is refused.

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
the contract-major 1 specification (`spec/bap-v1.md` § 14.1) at its single Ed25519 verification
point: canonical point encodings, no small-order key or `R`, a scalar below the group order, and
the cofactorless equation. Key import, JWK encode and decode, and thumbprint functions refuse a
key that fails key acceptance. Call `torsion_free` at key enrollment, at trust install, and
before any deny-list or revocation comparison. The strict-Ed25519 corpus
(`priv/conformance/strict-ed25519`) runs through `tests/conformance/run_strict.py` with its index
SHA-256 pinned.

## Supply chain

One direct runtime dependency (`cryptography`, Apache-2.0 or BSD-3-Clause). It brings `cffi`
(MIT-0) and `pycparser` (BSD-3-Clause) on CPython, and `typing-extensions` (PSF-2.0) before
Python 3.11. Pin the exact versions you deploy and verify install-time integrity (for example
with `pip install --require-hashes`). The
conformance runners and tests are development tooling and are not installed with the package.

## Verification is not authority

A successful verification proves byte-level properties against the inputs the caller supplied.
Trust selection, replay reservation, and revocation belong to your service or a stateful
authority runtime; the specification's verification-contract section states the boundary in
normative terms.

Tests and corpus inputs are self-contained under the SDK root. The complete Hex corpus tree
is vendored at `conformance/priv/conformance/`; copied-alone and unpacked-package checks
protect that boundary. See the [verdict digest contract](../design/corpus-verdict-digests.md).

## Migration

Follow the [before/after source-snapshot migration](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/python/README.md#migration-from-earlier-source-snapshots)
before adopting a newer commit. There is no published earlier SDK major to migrate from.
