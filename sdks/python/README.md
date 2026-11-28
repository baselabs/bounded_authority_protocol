# Bounded Authority Protocol™ verifier for Python

A pure, deterministic Python implementation of the Bounded Authority Protocol (BAP) verification
profiles: contract-majors 1 and 2 (Ed25519) and 3 (ES256), the local-loopback HTTP proof
profile, and the role-attestation and content-assertion profiles, with strict Ed25519
verification on every Ed25519 surface. The distribution is `bounded-authority-protocol-verifier`; the
import package is `bounded_authority_verifier`.

It checks the exact bytes of a grant, a holder proof, or an evidence object against public keys
and expected context that you supply, and returns facts or a value-free rejection. Facts exclude
raw credentials and secrets; the logging notes below describe their display limitations. It
is a **verifier, not an authority**: it never selects trusted keys, reserves replay, checks
revocation, or decides whether a request may run. Those stay in your service.

Already-trusted public keys, expected context, and time are explicit inputs. The SDK has no
private-key access or custody and reads no clock.

Its behavior is defined by the [specifications][specs] and the certified conformance corpora;
source comments cite the tracked normative specifications and independent conformance corpora.

[specs]: https://github.com/baselabs/bounded_authority_protocol/tree/main/spec

## Status

**Not published.** The package is not on PyPI; `bounded-authority-protocol-verifier` is the name it will
use, and any package of that name there is not ours until this page says otherwise. It moves to
its own repository when it is first published. Until then,
install it from this repository.

- Version `0.1.0`, pre-1.0: the API may change between minor versions.
- Python **3.11** or later is required. CI tests Python 3.11, 3.12, and 3.13.
- One runtime dependency, [`cryptography`](https://pypi.org/project/cryptography/) `>= 50.0.0`,
  for Ed25519 and ECDSA P-256 (the committed lock selects 50.0.2). SHA-256 comes from `hashlib`; base64url, JSON
  decoding, and JCS canonicalization are implemented in the package.
- **Erratum 3 (producer canonicality) is implemented.** Compact assembly and anchored-export encoding for every profile refuse a signature no
  conforming signer emits under spec/bap-v1.md §16 and spec/bap-v3.md §3.2. The certified
  `bap-producer-canonicality/1` corpus (75 cases) runs with this SDK's conformance suite.
- **Erratum 6 (selector float zero) is implemented.** Grant decode on contract-majors 1, 2 and 3
  rejects an `equals` value or `one_of` member holding a float-tagged zero at any depth
  (`0.0`, `-0.0`, `-0e0`, `1e-400`); range bounds and inert `all` members are unchanged, and
  range comparison treats -0.0 and 0.0 as equal. `grant_signing_input` refuses any float-tagged
  integral selector value (`0.0`, `10.0`), range bounds included (spec/bap-v1.md §12,
  REQ1-SIGNING-integral-float-selector; spec/bap-v2.md §4; spec/bap-v3.md §4). The certified `bap-selector-float-zero/1` corpus (161 cases) runs with this
  SDK's conformance suite.

The runtime floor is `cryptography` 50.0.0, the first release fixing all advisories
known on November 16, 2026 (earlier fixes landed in 44.0.1, 46.0.5, 46.0.6, 48.0.1,
and 49.0.0). CI audits the committed universal lock and a separate lowest-direct
resolution of every runtime, build, development, and optional dependency declaration.

## Install from a pinned source

From an empty directory, install the selected source commit in a virtual environment.
This SDK is unpublished; the full commit is its deployment identity. The pinned
source predates the distribution rename. The import package is the same at both revisions.

<!-- sdk-install:python -->

```bash
python3 -m venv venv
venv/bin/python -m pip install "git+https://github.com/baselabs/bounded_authority_protocol.git@c8b3bab8e4caf0b7f93e6f240570673534c331e2#subdirectory=sdks/python"
```

Save the following quickstart as `quickstart.py` and run `venv/bin/python quickstart.py`.
CI executes this install and that example in a fresh directory. For SDK development in a
checkout, `uv sync --locked` installs the committed development lock.

## Quickstart

This is [`examples/quickstart.py`](examples/quickstart.py). The test suite runs it, checks its
output, and keeps this copy identical to the file. To run it yourself, install the package
(above) into a virtual environment and run `python examples/quickstart.py` from `sdks/python`
in a checkout, or save the block as `quickstart.py` anywhere and run `python quickstart.py`.

<!-- sdk-quickstart:python -->

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


holder_jwk = jwk_from_public_key(holder_public)
assert isinstance(holder_jwk, Ok)
holder_thumbprint = thumbprint(holder_jwk.value)
assert isinstance(holder_thumbprint, Ok)

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
        holder_thumbprint=holder_thumbprint.value,
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
arguments_result = json_decode(b'{"section":"science","title":"Tides"}')
assert isinstance(arguments_result, Ok)
arguments = arguments_result.value
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
other_arguments = json_decode(b'{"section":"sports","title":"Tides"}')
assert isinstance(other_arguments, Ok)
other = replace(expected, cast_arguments=other_arguments.value)
print(isinstance(check_envelope(grant, proof, other), Err))
```

It prints `publish_article grant-001 not_evaluated`, then `True`.

## API

Contract-major 1 is the package root. Contract-major 2 is `bounded_authority_verifier.v2` (adds
the `lte` and `gte` range selectors) and contract-major 3 is `bounded_authority_verifier.v3`
(ES256 with 65-byte uncompressed SEC1 keys, 64-byte raw `r || s` signatures, and its own EC JWK
and thumbprint functions). Both modules use the root's function names for the contract-major
functions; the local-loopback, role-attestation, and content-assertion functions exist only at the
root, because those profiles bind contract-major 1 or stand alone. Import `v3` explicitly
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

**Results and errors.** Public protocol functions return `Result[T]`: `Ok(value)` or
`Err(InvalidError())`. This includes JSON decoding, JCS, base64url encoding and decoding,
bounds construction and resolution, JWK encoding, thumbprints, and SHA-256. The three
Ed25519 predicates `verify_strict`, `acceptable_public_key`, and `torsion_free` return plain
`bool`; malformed input returns `False`. Caller-input rejections return `Err` without a
reason or partial value. Boundaries catch only `InvalidError`; SDK and runner programming
errors propagate. `bool(Ok(...))` and `bool(Err(...))` raise `TypeError`: match `Ok` / `Err`
or inspect `is_ok` explicitly.

**Input types.** Byte parameters accept `bytes`, `bytearray`, and `memoryview`; boundaries
copy their contents to immutable `bytes`. Released memoryviews and other types return `Err`
(or `False` for the three predicates). Text parameters accept `str` and its subclasses,
using the underlying characters without invoking an overridden `__str__`. Invalid Unicode
and wrong types return `Err`. A `Bounds` constructor validates and copies its limits once;
resolving a limit does not revalidate the mapping. `MAXIMA` is a read-only `MappingProxyType`.
Invalid `Bounds(...)` construction produces an unusable value; use `bounds_new` to obtain an
explicit `Err`. Bounds and all façade struct arguments require their exact SDK class; subclasses
return `Err`. Native scalar and container subclasses are copied through their builtin storage
before validation. An arbitrary `Mapping` is snapshotted once; exceptions from its `items()`
method or iterator become `Err` at that callback boundary. SDK exceptions still propagate.
Bounds, facts, and redacted decoded values refuse a second initialization.

Invalid `Bounds(...)` builds an unusable value rather than silently accepting invalid ceilings. Public operations reject that value with the closed invalid result.

**Facts.** `GrantFacts`, `EnvelopeFacts`, `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`,
`AnchoredExportFacts`, `AttestationFacts`, and `ContentAssertionFacts` are slotted value
objects with read-only properties holding identifiers, digests, times, and counts, never raw
signatures, keys, nonces, or arguments. Their `authorization` or `trust` field is
`"not_evaluated"`; there is no `allowed`, `authorized`, or decision field. Their `repr` and
`str` match the specified diagnostic rendering, for example
`#BoundedAuthorityProtocol.V1.GrantFacts<redacted>` and
`#BoundedAuthorityProtocol.V2.GrantFacts<redacted>`, including nested Results and containers.
Sibling profiles use `RoleAttestation.V1` and `ContentAssertion.V1`. Facts refuse
`dataclasses.asdict`, `dataclasses.fields`, `vars`, generic JSON encoding, pickling, and
copy reduction. Read named properties explicitly; construct a new facts object explicitly
when a copy is needed.

**Decoded diagnostics.** All four decoded types render the specified inspection notation, including
the contract-major. `GrantDecoded` includes `version` and ordered `operations`; `ProofDecoded`
now carries all decoded claims and the holder public key, but hides the optional nonce in
`repr` and `str`. `ProofDecoded` and `ContentAssertionDecoded` are slotted values with read-only
properties and refuse the same bulk exports and reduction as facts. The candidate
`ApprovalRecord` and `VerifiedApprovalFacts` use the same read-only representation. Grant and role-attestation
diagnostics have no redacted fields and remain dataclasses.

## Strict Ed25519

Every Ed25519 signature check goes through one module (`bounded_authority_verifier.ed25519`)
that applies rule S1 of [erratum 2](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md) before the `cryptography` backend: exact widths,
canonical `A` and `R`, neither of small order, `S < L`, then the cofactorless equation.
`acceptable_public_key` is the key-entry check (canonical, not small order, on the curve), and
the JWK and thumbprint functions refuse a key that fails it. `torsion_free` adds `[L]A = O`; call
it at key enrollment, at trust install, and before any deny-list or revocation comparison, never
on the verification path.

## Conformance

`conformance/priv/conformance/` is a complete, byte-identical snapshot of the Hex package built
from this commit's `priv/conformance/` tree. It includes the ten standalone corpora, schemas, focused vectors,
and `verdict-digests.json`. Every test input is inside this SDK root; copying this directory
alone is sufficient to run the suite.
The manifest was introduced in 1.1.0.

| Corpus | Cases |
|---|---:|
| v1 / v2 / v3 | 283 / 268 / 292 |
| Local-loopback HTTP | 44 (36 URI, 8 proof) |
| Role attestation | 40 |
| Content assertion | 154 (131 assertion, 9 digest, 14 successor) |
| Producer canonicality | 75 |
| Selector float zero | 161 |
| Strict Ed25519 | 2,410 |
| StringOrURI identifiers | 24 |

Each runner pins its index, hashes every indexed file, including `.raw` inputs, and rejects
extra or missing files, duplicate IDs, and skipped cases. It records computed outcomes,
orders them by the index's file and case order, and checks their JCS/SHA-256 verdict digest
against the vendored manifest. Expected-value comparison cannot substitute for this check.
Outcome projections and index ordering are specified in the
[verdict digest contract](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/corpus-verdict-digests.md).
The contract-major runners also retain their public-key import censuses.

Run from this SDK directory:

```bash
uv sync --locked
uv run pytest -q
uv run python tests/conformance/run.py
uv run python tests/conformance/run_v2.py
uv run python tests/conformance/run_v3.py
uv run python tests/conformance/run_strict.py
uv run python tests/conformance/run_producer_canonicality.py
uv run python tests/conformance/run_selector_float_zero.py
```

The source distribution includes the tests, tools, lockfile, and complete input tree. CI
unpacks it and runs the same suite from that directory. The wheel includes only the runtime
package and its distribution metadata. Test inputs are not installed with the wheel.

The monorepo's distribution job copies only this SDK root into a temporary directory,
runs its full suite, checks its package, and removes the temporary artifacts afterward.
A corpus update replaces the standalone projection from the verified Hex unpack in one change;
individual case edits are not a supported update path. These checks do not publish the SDK.

## Verifying a grant before issuing it

The Python source-checkout suite exercises `bap-action-approval/1` and its ES256 carrier
`bap-content-assertion-es256/1` against the pinned Hex 1.5.0 corpora in the protocol checkout.
The standalone SDK suite runs the ten vendored corpora.

In the [offline SQLite example](examples/action_approval.py), the host verifies a content
assertion over the canonical record for an image-indexing request. The host prepares the request
ID, its current revision, subject, action, and complete resource set. Its own policy supplies the
audience, approver roles, suite, time and validity caps, and an independently enrolled trusted-key
snapshot for the configured trust domain. The assertion binds the exact record bytes to the
`bap-action-approval/1` profile and those context checks. Use the pure
`verify_approval_eddsa` or `verify_approval_es256` entry point selected by host configuration.

<!-- sdk-example:action-approval -->

```python
identity = verify_and_submit(
    host_db, record_bytes, assertion_compact, prepared_request, host_policy, now,
    external=True,
)
```

The example acquires a SQLite write transaction before reading the current request. Inside the
transaction it compares the revision and the entire prepared effect, including exact resource
set equality. It conditionally inserts both the artifact identity and the scoped request and
revision. A collision on either insert rolls back the transaction. The same commit records the
local effect or a durable intent for an external effect. Revision writers and the claim compare
against the same SQLite write lock.

After an interruption, the worker reloads the durable intent from the host database and looks
up its identity at the destination. If the effect is absent, it delivers the same bytes with
the same identity. If the destination already has the effect, the worker confirms exact equality
before marking delivery. CI exercises both restart points and both orders of concurrent claim
and revision writes.

The optional `action_approval.verify` helper evaluates the host's read-only revocation and replay
predicates after pure verification. Keep its reason codes in host-local logs. Return only
`invalid` to the presenter on a verification failure. The host authenticates the executor and
applies its own approval policy. Where the invocation requires executor key possession, use a
separate capability grant with a holder-bound proof. The host can set an `equals` selector on
`record_digest` using the base64url of the exact record's content digest. The capability grant's
operation and lifetime come from the issuer's policy.

## What this SDK does not do

It holds no private keys and makes no network or filesystem calls; it reads no clock
(`evaluation_time` is an input) and performs no replay reservation, revocation check, or policy
decision (`tools/purity_check.py` enforces the purity of `src/`). Selecting trusted keys,
reserving replay, and deciding belong to the host: a facts value is evidence, not a credential.

## Development

```bash
python -m pip install uv==0.11.20
uv sync --locked
. .venv/bin/activate
ruff check src/ tests/ tools/ examples/
mypy src/                          # strict
python tools/purity_check.py       # no I/O, clock, randomness, or network in src/
python tools/license_check.py      # dependency licenses
python -m pytest tests/
python tests/conformance/run.py && python tests/conformance/run_v2.py
python tests/conformance/run_v3.py && python tests/conformance/run_strict.py
```

CI audits all dependencies in the committed `uv.lock` with pinned `pip-audit` and runs the
permissiveness suite again with each closure independently removed. The monorepo also runs its [closure mutation battery](https://github.com/baselabs/bounded_authority_protocol/blob/main/scripts/check_sdk_closures.py). Each named test must fail
an assertion after its closure is removed; build or collection errors fail the gate.

Deployment notes: [`docs/deployment/python-sdk.md`](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/deployment/python-sdk.md).

## Migration from earlier source snapshots

These SDKs are unpublished at version 0.1.0; there is no earlier supported registry major.
When moving from an older source commit, apply these changes recorded in the monorepo
[CHANGELOG](https://github.com/baselabs/bounded_authority_protocol/blob/main/CHANGELOG.md). The quickstart uses the current forms.

| Earlier usage | Current usage |
|---|---|
| `value = json_decode(raw)`; catch invalid-input exceptions | Match `Ok(value)` / `Err(InvalidError())`; read `result.value` only after matching. This applies to UTF-8, JSON, JCS, base64url, URI, JWK, digests, selectors, compact and bounds primitives. |
| Unwrap `verify_strict(...)` | Use its plain boolean, as for `acceptable_public_key` and `torsion_free`; invalid input is `False`. |
| `if result:` | `if isinstance(result, Ok):` or `result.is_ok`; implicit truth tests raise `TypeError`. |
| Import `fail`, `require`, `unwrap`, or `invalid_error` | Match the public Result; those validation helpers are private. |
| Pass arbitrary objects as byte/text input | Pass `bytes`, `bytearray` or `memoryview` (copied), or valid Unicode text. Released views and wrong types reject. |
| `asdict(facts)`, `vars(facts)`, `replace(facts, ...)`, pickle or copy reduction | Read `facts.grant_id` or another named property; explicitly construct an application projection. Facts and redacted decoded values are slotted and read-only. |
| Subclass `Bounds` or a façade input | Construct the exact SDK class. Native scalar/container subclasses keep builtin data semantics. |
| `MAXIMA["depth"] = 8`; rely on `Bounds(...)` raising | `bounds_new({"depth": 8})` and match the Result; `MAXIMA` is read-only and invalid direct construction is unusable. |
| Reinitialize facts, bounds, or redacted decoded objects | Construct a new value once; repeated initialization is refused. |
| Assert `#GrantFacts<redacted>` | Assert the full namespace, for example `#BoundedAuthorityProtocol.V1.GrantFacts<redacted>`. |
| Assume decoded grants omit operations or proofs omit claims | Read `version`, `operations` and the named proof claims; proof nonce rendering stays redacted. |

## License

Apache-2.0, maintained by BaseLabs Holdings LLC. See [LICENSE](LICENSE) and [NOTICE](NOTICE),
and [IPR.md](IPR.md) for contributions and use of the name.
