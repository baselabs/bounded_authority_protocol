# bounded_authority_protocol

Deterministic, dependency-free verification for cryptographically bounded, argument-level
proof-of-possession authority — the open wire profile, verifier, and conformance suite for the
Bounded Authority Protocol (BAP v1).

An issuer signs a **capability grant** that names exactly which operations a holder may invoke and
with exactly which arguments. On each call the holder presents a **proof-of-possession** bound to
that grant, the operation, and a digest of the typed arguments. A verifier checks the exact bytes
and returns cryptographic facts — never an authorization decision. The wire profile is closed: a
conforming verifier rejects every unlisted member, value, encoding, or extension with a single
value-free error, which structurally forecloses the `alg:"none"` and permissive-parsing failure
class.

This package is the **standard any party can implement**: the normative profile, the verifier, and
the conformance corpus. A stateful authority service (issuance, key custody, live revocation,
replay, evidence) and holder-side signer SDKs build on top of it; this package deliberately
contains neither, holds no keys, performs no I/O, and runs no service.

Built on IETF primitives: compact JWS (RFC 7515), DPoP proof-of-possession (RFC 9449), JCS
canonicalization (RFC 8785), JWK thumbprints (RFC 7638), and EdDSA over Ed25519 (RFC 8032). The
current cryptographic suite is `BAP1-Ed25519-SHA256`.

## Installation

```elixir
def deps do
  [
    {:bounded_authority_protocol, "~> 0.1"}
  ]
end
```

The package has **zero production dependencies**, no application callback, and no supervision tree.

## What it provides

Verification (all results are redacted and non-authorizing — they carry
`authorization: :not_evaluated`):

- `verify_grant/3` — verifies a raw compact grant against an exact public key, issuer, audience,
  time, and bounds; returns `GrantFacts`.
- `check_envelope/2` — re-verifies the raw grant and binds the holder signature, method,
  normalized URI, invocation id, operation, argument digest, time, nonce, and every selector;
  returns `EnvelopeFacts`, or exactly `{:error, :invalid}`.
- `untrusted_key_locator/2` — a bounded protected-header preparse returning only the `kid` as an
  explicitly untrusted lookup hint; it decodes no payload or signature and never marks a key
  trusted.
- `check_chain/2`, `verify_historical_anchor/3`, `verify_key_transition/4`,
  `verify_anchored_export/3` — evidence verification: canonical consumption chains, signed boundary
  anchors, authenticated historical-key rollover, and anchored archives checked to exact EOF,
  digest, and out-of-band object version.

Production (the package emits deterministic signing inputs and assembles compact forms from a
caller-supplied signature; it never accepts private key material or a signer):

- `grant_signing_input/2`, `proof_signing_input/2`, `boundary_anchor_signing_input/2`,
  `key_transition_signing_input/2`, `assemble_compact/2,3`, `encode_consumption_entry/2`,
  `encode_anchored_export/2`, `request_digest/3`.

Decoding:

- `BoundedAuthorityProtocol.V1.Json.decode/2` — the closed tagged-JSON algebra with recursive
  duplicate rejection and no input-name atomization.
- `BoundedAuthorityProtocol.V1.Base64Url.decode/2` — strict canonical unpadded base64url.

All verification inputs are explicit: the already-trusted public key, expected audience and
instance, server-derived method, normalized URI, invocation id, operation, cast arguments,
evaluation time, and limits. A successful result means only that the supplied bytes satisfy those
supplied inputs. Resource limits are tightening-only positive integers; the Ed25519 key/signature
and SHA-256 digest widths are immutable protocol constants. Unknown, non-integer, zero, negative,
widening, or width-changing values fail with the fixed `{:error, :invalid}`.

## What it does not do

This package does not discover trust, issue grants, hold keys, read a database, reserve replay,
check live revocation, claim an execution, authorize a business effect, append outcomes, remove
archived evidence, submit witnesses, or run a service. Those responsibilities belong to a stateful
authority runtime and the consuming host. Verification returns facts; the authorization decision is
a separate step the host owns.

## Conformance

The package ships a language-neutral v1 conformance corpus and a deterministic offline verifier
CLI. The corpus (`priv/conformance/v1/corpus`) is the normative evidence: 283 cases across 28
surfaces with a full surface × class applicability matrix, independently re-verified by a second
implementation that recomputes every verdict from scratch — a value that only round-trips the
reference implementation is not normative until the independent runner agrees. Every invalid case
is constructed one defect away from a passing case, so a verifier that skips the named check
accepts it.

```bash
mix escript.build
./bounded_authority_conformance --corpus priv/conformance/v1/corpus
```

`--corpus DIR` is required (no default — a wrong-corpus run that exits 0 would be a quiet
misverification path in the tool built to eliminate quiet misverification). It exits `0` only on
complete agreement, `1` on any integrity or verdict failure, `2` on usage error. From a consumer
dependency, point `--corpus` at the packaged path under `deps/bounded_authority_protocol/`. The
oracle vectors used by holder-side consumers to verify their own production live under
`priv/conformance/v1/vectors`.

## Cross-language verifier SDKs

Alongside the Elixir package, the repository authors typed **verifier** SDKs of the frozen v1
profile — TypeScript (Node, zero runtime dependencies), Python (single dependency), Rust
(`#![forbid(unsafe_code)]`), and Go (stdlib-only) — each written from the specification and corpus
alone, with no code-level derivation from the reference implementation. Each passes all 283 conformance vectors
recomputed from scratch, asserts the corpus digest at startup, and proves every parser-layer
closure red-capable via a per-language mutation gate. Each SDK graduates to its own repository on
first publication.

## Standards posture

The wire profile is closed permanently; evolution happens above it through parallel
contract-majors that never downgrade, with a minimum twelve-month deprecation window and published
change-control, errata, and security-release policy (see `docs/governance.md`). Cryptographic
agility is a named-suite succession, with a post-quantum path (ML-DSA) and cross-suite evidence
attestation designed in. A pre-submission MCP authorization extension draft targeting the MCP
extensions track lives under `docs/extensions/`.

## Documentation

- `docs/protocol-v1.md` — the normative v1 wire profile.
- `docs/design/protocol-charter.md` — what the verifier does and the verification chain.
- `docs/design/conformance-contract.md` — how conformance is proven.
- `docs/design/standards-track.md` — evolution, suite succession, governance, and venue strategy.
- `docs/governance.md` — change classes, errata, deprecation, and security-release policy.

## Development

Supported Elixir/OTP: 1.18/27, 1.19/28, 1.20/29.

```bash
mix deps.get
mix quality
```

`mix quality` runs formatting, warnings-as-errors compilation, the purity architecture gate, Credo,
tests with coverage, Dialyzer, documentation, dependency and license audits, CycloneDX SBOM
generation, the conformance corpus and mutation gates, and an exact packed/unpacked consumer test.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-reporting process.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
