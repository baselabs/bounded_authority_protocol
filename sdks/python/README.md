# Bounded Authority Protocol verifier for Python

A pure, deterministic Python implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface. The distribution is `bounded-authority-verifier`; the
import package is `bounded_authority_verifier`.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns redacted facts or a value-free rejection. It
is a **verifier, not an authority**: it never selects trusted keys, reserves replay, checks
revocation, or decides whether a request may run. Those stay in your service.

Its behavior is defined by the [specifications][specs] and the certified conformance corpora;
source comments cross-reference the Elixir reference implementation for traceability.

[specs]: https://github.com/baselabs/bounded_authority_protocol/tree/main/spec
[adr15]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0015-sdk-graduation-and-publish-topology.md
[adr40]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0040-strict-ed25519-soundness-erratum.md

## Status

**Not published.** The package is not on PyPI; `bounded-authority-verifier` is the name it will
use. It moves to its own repository when it is first published ([ADR 0015][adr15]). Until then,
install it from this repository.

- Version `0.1.0`, pre-1.0: the API may change between minor versions.
- Python **3.10** or later is declared; CI tests Python 3.13.
- One runtime dependency, [`cryptography`](https://pypi.org/project/cryptography/) `>= 44.0.0`,
  for Ed25519 and ECDSA P-256 (CI pins 50.0.0). SHA-256 comes from `hashlib`; base64url, JSON
  decoding, and JCS canonicalization are implemented in the package.
- **Erratum 3 (producer canonicality) is not yet implemented.** `assemble_compact` and
  `encode_anchored_export` (and their `v2` and `v3` forms) check the signature width but not its
  value, so they can assemble an Ed25519 signature with `S >= L` or a non-canonical or
  small-order `R`, or an ES256 signature that is out of range or high-S. Every verifier, this
  one included, rejects such a credential. Until this package implements erratum 3, check a
  signature from an external signer before assembly (for ES256, normalize to low S).

## Install from this repository

```bash
pip install "bounded-authority-verifier @ git+https://github.com/baselabs/bounded_authority_protocol@<commit>#subdirectory=sdks/python"
```

or, from a local checkout:

```bash
pip install ./bounded_authority_protocol/sdks/python
```

Pin a commit: without a published version, the commit is the identity of what you deployed.

## Quickstart

This is [`examples/quickstart.py`](examples/quickstart.py). The test suite runs it, checks its
output, and keeps this copy identical to the file.

```python
"""Issue a grant, sign a holder proof for one request, verify both, then show that the same
proof fails for other arguments. The keys come from fixed seeds so the output is stable; in
production the private keys stay with the issuer and the holder, and the verifier receives only
public keys."""

from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from bounded_authority_verifier import (
    Err,
    ExpectedRequest,
    GrantProducer,
    JString,
    NonceNotRequired,
    Ok,
    OperationInput,
    ProofProducer,
    SigningInput,
    TrustedIssuer,
    assemble_compact,
    check_envelope,
    grant_signing_input,
    json_decode,
    jwk_from_public_key,
    proof_signing_input,
    thumbprint,
)

issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(32))
holder_key = Ed25519PrivateKey.from_private_bytes(bytes([1]) + bytes(31))
issuer_public = issuer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
holder_public = holder_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def signed(signing_input: SigningInput, key: Ed25519PrivateKey) -> bytes:
    """Sign ASCII(base64url(protected) || "." || base64url(payload)) and assemble the compact."""
    message = signing_input.protected_segment + b"." + signing_input.payload_segment
    result = assemble_compact(signing_input, key.sign(message))
    assert isinstance(result, Ok)
    return result.value


# The issuer grants one operation, restricted to one argument value.
grant_input = grant_signing_input(
    GrantProducer(
        key_id="issuer-1",
        issuer="https://issuer.example",
        grant_id="grant-001",
        audiences=["https://docs.example"],
        issued_at=1_800_000_000,
        not_before=1_800_000_000,
        expires_at=1_800_003_600,
        holder_thumbprint=thumbprint(jwk_from_public_key(holder_public)),
        operations=[
            OperationInput(
                name="publish_article",
                selectors=[{"kind": "equals", "path": ["section"], "value": JString(b"science")}],
            )
        ],
    )
)
assert isinstance(grant_input, Ok)
grant = signed(grant_input.value, issuer_key)

# The holder binds one request to the grant.
arguments = json_decode(b'{"section":"science","title":"Tides"}')
proof_input = proof_signing_input(
    ProofProducer(
        holder_public_key=holder_public,
        proof_id="proof-001",
        method="POST",
        target_uri="https://docs.example/articles",
        issued_at=1_800_000_100,
        invocation_id="9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
        operation="publish_article",
        grant_compact=grant,
        cast_arguments=arguments,
    )
)
assert isinstance(proof_input, Ok)
proof = signed(proof_input.value, holder_key)

# The service verifies the raw bytes against what it derived from the request.
expected = ExpectedRequest(
    trusted_issuer=TrustedIssuer(key_id="issuer-1", public_key=issuer_public),
    issuer="https://issuer.example",
    audience="https://docs.example",
    method="POST",
    target_uri="https://docs.example/articles",
    invocation_id="9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
    operation="publish_article",
    cast_arguments=arguments,
    evaluation_time=1_800_000_100,
    clock_skew=60,
    proof_max_age=300,
    nonce=NonceNotRequired(),
)

result = check_envelope(grant, proof, expected)
assert isinstance(result, Ok)
facts = result.value
print(facts.operation, facts.grant_id, facts.authorization)

# The same proof against other arguments fails closed, with no detail.
other = replace(expected, cast_arguments=json_decode(b'{"section":"sports","title":"Tides"}'))
print(isinstance(check_envelope(grant, proof, other), Err))
```

It prints `publish_article grant-001 not_evaluated`, then `True`.

## API

Contract-major 1 is the package root. Contract-major 2 is `bounded_authority_verifier.v2` (adds
the `lte` and `gte` range selectors) and contract-major 3 is `bounded_authority_verifier.v3`
(ES256 with 65-byte uncompressed SEC1 keys, 64-byte raw `r || s` signatures, and its own EC JWK
and thumbprint functions). Both modules use the root's function names. Import `v3` explicitly
(`from bounded_authority_verifier import v3`); unlike `v2`, it is not listed in the package's
`__all__`. Each major rejects the others' bytes.

| Group | Functions |
|---|---|
| Producers | `grant_signing_input`, `proof_signing_input`, `boundary_anchor_signing_input`, `key_transition_signing_input`, `assemble_compact`, `encode_consumption_entry`, `encode_anchored_export`, `request_digest` |
| Decoders (no signature check) | `decode_grant`, `decode_proof`, `untrusted_key_locator` |
| Verifiers | `verify_grant`, `check_envelope`, `check_chain`, `verify_historical_anchor`, `verify_key_transition`, `verify_anchored_export` |
| Local-loopback HTTP proofs | `local_loopback_http_uri_normalize`, `local_loopback_http_proof_signing_input`, `assemble_local_loopback_http_compact`, `decode_local_loopback_http_proof`, `check_local_loopback_http_envelope` |
| Role attestations | `attestation_signing_input`, `assemble_attestation_compact`, `decode_attestation`, `verify_attestation` |
| Content assertions | `assertion_signing_input`, `assemble_content_assertion_compact`, `decode_assertion`, `verify_assertion`, `content_digest`, `assertion_digest`, `verify_successor` |
| Strict Ed25519 | `verify_strict`, `acceptable_public_key`, `torsion_free` |
| Primitives | `json_decode`, `jcs_encode`, `base64url_decode`, `base64url_encode`, `uri_normalize`, `jwk_decode_public`, `jwk_encode_public`, `jwk_from_public_key`, `thumbprint_preimage`, `thumbprint`, `thumbprint_raw`, `public_key_thumbprint_raw`, `bounds_new`, `bounds_maximum` |

`check_envelope` takes the grant and proof compact bytes as two arguments, then the
`ExpectedRequest`. See [`src/bounded_authority_verifier/__init__.py`](src/bounded_authority_verifier/__init__.py)
for every exported name, including the argument dataclasses and the tagged JSON types
(`JObject`, `JString`, `JInt`, `JFloat`, and so on).

**Results and errors.** The producers, decoders, verifiers, the loopback, attestation, and
content-assertion functions, `request_digest`, `assemble_compact`, `uri_normalize`, and
`jwk_decode_public` return `Result[T]`: `Ok(value)` or `Err`, and `Err` carries no reason. The
lower-level primitives raise `InvalidError` instead: `json_decode`, `jcs_encode`,
`base64url_decode`, `bounds_new`, `jwk_encode_public`, `jwk_from_public_key`,
`thumbprint_preimage`, `thumbprint`, `thumbprint_raw`, and `public_key_thumbprint_raw` (the
key functions raise for a key that fails `acceptable_public_key`). `verify_strict`,
`acceptable_public_key`, and `torsion_free` return `bool`.

**Facts.** `GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`,
`AnchoredExportFacts`, `AttestationFacts`, and `ContentAssertionFacts` are frozen dataclasses
holding identifiers, digests, times, and counts, never raw signatures, keys, nonces, or
arguments. Their `authorization` or `trust` field is `"not_evaluated"`; there is no `allowed`,
`authorized`, or decision field. Their `repr` is the default dataclass `repr`, which prints
every field; the fixed redacted rendering the specification calls for is not implemented yet,
so log the fields you need by name.

## Strict Ed25519

Every Ed25519 signature check goes through one module (`bounded_authority_verifier.ed25519`)
that applies rule S1 of [ADR 0040][adr40] before the `cryptography` backend: exact widths,
canonical `A` and `R`, neither of small order, `S < L`, then the cofactorless equation.
`acceptable_public_key` is the key-entry check (canonical, not small order, on the curve), and
the JWK and thumbprint functions refuse a key that fails it. `torsion_free` adds `[L]A = O`; call
it at key enrollment, at trust install, and before any deny-list or revocation comparison, never
on the verification path.

## Conformance

Four runners check the contract-major and strict-Ed25519 corpora in place under
`priv/conformance/`, each asserting its `index.json` SHA-256 at load; the contract-major runners
also compare the keys they imported with the index's `public_key_fingerprints`:

```bash
python tests/conformance/run.py          # v1: 283/283, census 11 keys
python tests/conformance/run_v2.py       # v2: 268/268
python tests/conformance/run_v3.py       # v3: 292/292
python tests/conformance/run_strict.py   # strict Ed25519: 2410/2410
```

`python -m pytest tests/` runs the unit tests, this quickstart, the local-loopback,
role-attestation, and content-assertion corpora, the permissiveness battery (which builds each
defect a parser closure exists to reject and proves the closure catches it), and pytest
wrappers for the v1 and strict-Ed25519 runners. The producer-canonicality corpus (erratum 3) is
not run yet; see Status.

## What this SDK does not do

It holds no private keys and makes no network or filesystem calls; it reads no clock
(`evaluation_time` is an input) and performs no replay reservation, revocation check, or policy
decision (`tools/purity_check.py` enforces the purity of `src/`). Selecting trusted keys,
reserving replay, and deciding belong to the host: a facts value is evidence, not a credential.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . ruff mypy pytest
ruff check src/ tests/ tools/ examples/
mypy src/                          # strict
python tools/purity_check.py       # no I/O, clock, randomness, or network in src/
python tools/license_check.py      # dependency licenses
python -m pytest tests/
python tests/conformance/run.py && python tests/conformance/run_v2.py
python tests/conformance/run_v3.py && python tests/conformance/run_strict.py
```

Deployment notes: [`docs/deployment/python-sdk.md`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/python-sdk.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
