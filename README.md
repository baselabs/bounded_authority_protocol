# bounded_authority_protocol

Deterministic, dependency-free verification for cryptographically bounded, argument-level
proof-of-possession authority — the open wire profile, verifier, and conformance suite for the
Bounded Authority Protocol (contract-majors 1, 2, and 3).

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
cryptographic suites are `BAP1-Ed25519-SHA256` for v1, `BAP2-Ed25519-SHA256` for v2, and `BAP3-ES256-SHA256` for v3 (ECDSA P-256 with RFC 7518 §3.4 raw signatures and low-S canonicality).

## Installation

The package is published on Hex (release 0.6.0, published 2026-09-23; the registry checksum is
read back against the tagged-tree build in the post-publish docs-currency commit). Registry
consumers use the minor-bounded requirement:

```elixir
def deps do
  [
    {:bounded_authority_protocol, "~> 0.6.0"}
  ]
end
```

The package has **zero production dependencies**, no application callback, and no supervision tree.
`v0.6.0` is the role-attestation release — the first release bearing the
`bap-role-attestation/1` sibling profile
([ADR 0036](docs/adr/0036-role-attestation-profile.md)): the
`BoundedAuthorityProtocol.RoleAttestation.V1` namespace (`verify_attestation/2` and its three
producer/decoder siblings) plus the certified 40-case profile corpus (registry checksum
`1187d57928fbc893cccce893c38862450735ff24f25fb6466475f3bb239a9e17`, byte-identical to the
tagged-tree two-build candidate, read back and pinned by a fresh `~> 0.6.0` consumer);
`v0.5.1` was a docs-maintenance patch (registry checksum
`60a8cd6e361938c5adfde1afcbbdc12426787a3d46b46c3437ef2d68a5808af0`, read back and pinned);
`v0.5.0` identified the reviewable source release for the ES256 contract-major 3 activation
(`BoundedAuthorityProtocol.V3`, [ADR 0035](docs/adr/0035-es256-contract-major-activation.md));
`v0.4.0` identified the v2 activation; `v0.4.1` was the toolchain-and-platforms release
(ADR 0031/0032); `v0.4.2` was a documentation-truth patch. The immutable package identity is
the published Hex release, not the Git tag. Depend on the package identity — never a tag or a
mutable checkout.

## Holder-side signer: the report adapter

Producing a signed envelope needs a holder key — and this package deliberately has none: it
computes the deterministic signing input for every protocol object and **refuses to sign**.
The holder-side companion is
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
([GitHub](https://github.com/baselabs/bounded_authority_report_adapter)): it takes a local
key handle (`{module(), term()}` — your HSM, KMS, or in-process test key; the private key never
enters the library) and a protocol signing input, and produces the signed compact form for
holder proofs, local-loopback application proofs, boundary anchors, key transitions, and role
attestations.
The dependency is one-directional: verifiers depend only on this protocol package; the adapter
depends on this package; this package never depends on the adapter.

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

Application proof profiles are explicit sibling namespaces. The local-development profile
`BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1` uses signed
`typ: "ba+loopback-proof"`, mandatory nonces, and only canonical literal-loopback HTTP targets
(`127.0.0.1` or `[::1]`). It exposes URI normalization, proof signing-input production, compact
assembly, proof decode, and envelope verification. Standard `dpop+jwt` functions reject these
bytes and the loopback functions reject `dpop+jwt`; callers must select one profile and never retry
another after failure. Loopback HTTP is not TLS and is not process isolation.

Sibling attestation profiles are the same posture for standalone signed artifacts. The role
attestation profile `BoundedAuthorityProtocol.RoleAttestation.V1` (ADR 0036) carries signed
`typ: "ba+role-attestation"`: an attestor key binds a subject key to `issuer` or `holder` for a
bounded window. `verify_attestation/2` takes the caller-supplied attestor key (with its own
validity window), the expected subject binding, and `now`; it proves the Ed25519 signature, the
subject binding, structural self-attestation rejection, that the attestation window is contained
in the attestor key window, and that `now` lies in the half-open `[nbf, exp)` — and returns
redacted, non-authorizing `AttestationFacts` (`trust: :not_evaluated`). Which attestor to trust,
which role a consumer requires, and replay reservation stay with the caller. Every contract-major
profile rejects these bytes, and the profile rejects theirs.

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

The local-loopback application profile has a separate certified corpus under
`priv/conformance/application-profiles/local-loopback-http/v1`. Its Elixir, Python,
Rust, and Go consumers assert the same file hashes and verdicts (the TypeScript consumer now
lives in that SDK's graduated repository). The non-mock transport drill opens
real IPv4 and IPv6 listeners, uses fresh in-memory keys, and prints a secret-free JSON receipt:

```bash
mix local_loopback_http.verify
```

The role-attestation profile's certified corpus (40 cases, revision 1) lives under
`priv/conformance/attestation-profiles/role-attestation/v1`, minted with ephemeral in-memory
keys and pinned by the Elixir suite, the requirement map, the spec, and every SDK consumer.
Its end-to-end check verifies index and file digests, every case's decode/verify verdict, and
cross-profile rejection in both directions, printing a secret-free receipt:

```bash
mix role_attestation.verify
```

## Cross-language verifier SDKs

Alongside the Elixir package, the repository authors typed **verifier** SDKs of the frozen profiles
— Python (single dependency), Rust
(`#![forbid(unsafe_code)]`), and Go (stdlib-only) — each written from the specification and corpus
alone, with no code-level derivation from the reference implementation. The TypeScript SDK
graduated on first publication (ADR 0015) and now lives at
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript),
published to npm as [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier). Each passes all 283 conformance vectors
recomputed from scratch, asserts the corpus digest at startup, and proves every parser-layer
closure red-capable via a per-language mutation gate. Each SDK graduates to its own repository on
first publication.

## Standards posture

Each wire profile is closed permanently. Evolution happens through parallel contract-majors or an
explicitly identified byte-distinct application profile with its own protected `typ`, public APIs,
normative specification, and certified corpus; no sibling profile changes standard `dpop+jwt` bytes
or verdicts, and implementations never infer or fall back between profiles. Contract-majors never
downgrade, with a minimum twelve-month deprecation window and published change-control, errata, and
security-release policy (see `docs/governance.md`). Cryptographic
agility is a named-suite succession, with a post-quantum path (ML-DSA) and cross-suite evidence
attestation designed in. Pre-submission extension drafts live under `docs/extensions/`: an MCP
authorization extension targeting the MCP extensions track, and an A2A capability-binding
extension restating the [A2A binding profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/design/a2a-capability-binding-profile.md)
for the A2A venue.

## Documentation

Guides, in curated reading order:

1. [Getting started](docs/guides/getting-started.md) — zero to a verified envelope, and the
   three rules that surprise newcomers.
2. [The implementer's guide](docs/guides/implementers-guide.md) — building a conforming
   verifier in any language.
3. [Upgrading](docs/guides/upgrading.md) — the published compatibility contract.
4. [Runnable Livebook walkthrough](docs/livebooks/bap-walkthrough.livemd) — standard HTTPS and
   literal-loopback HTTP proof production, verification, and fail-closed rejection with ephemeral
   keys.

Reference set:

- `spec/bap-v1.md` — the normative v1 wire profile (docs/protocol-v1.md is its generated view).
- `spec/bap-local-loopback-http-v1.md` — the normative literal-loopback HTTP application profile.
- `spec/bap-role-attestation-v1.md` — the normative role-attestation sibling profile.
- `docs/design/protocol-charter.md` — what the verifier does and the verification chain.
- `docs/design/conformance-contract.md` — how conformance is proven.
- `docs/design/interoperability-report.md` — exact standard and application-profile
  cross-validation identities and results.
- `docs/design/standards-track.md` — evolution, suite succession, governance, and venue strategy.
- `docs/governance.md` — change classes, errata, deprecation, and security-release policy.

## When NOT to use this

- **You need an authorization decision.** This package verifies bytes; it never decides. An
  operational decision requires a stateful authority runtime that owns trust selection,
  replay reservation, and revocation. Treating a verification result as execution authority
  moves all of those checks to nothing.
- **You need transport security, confidentiality, or storage.** Every wire object is plaintext
  JSON by design; the profile provides authenticity and integrity over TLS-transported,
  runtime-stored artifacts.
- **You want permissive parsing.** There is no compatibility mode, no tolerance for unknown
  members, and no alternate-encoding acceptance — the closed rejection IS the product.
- **You need online revocation or replay defense.** Those are runtime responsibilities; the
  verifier is stateless by contract.

## Named misuses

Misuse: treating `GrantFacts` or `EnvelopeFacts` as a decision or credential. Facts carry
`authorization: :not_evaluated` and are redacted; accepting them as authority is the
central anti-pattern this package exists to prevent.

Misuse: passing a caller-provided facts struct to the runtime boundary. The runtime accepts
RAW credentials at its public boundary and performs its own verification; a facts struct is an
output, never an input.

Misuse: re-deriving trusted keys from the credential (e.g., using the untrusted `kid` as a
lookup the attacker controls). `kid` is a case-sensitive hint; key selection belongs to the
caller's trusted-key set.

Misuse: loosening bounds because a "legitimate" payload exceeded them. The bounds are part of
the wire contract; an oversized payload is non-conforming, not a bug.

Misuse: accepting the proof without the server-derived request context. The request digest is
computed over the SERVER's derived operation and typed arguments — never over anything the
presenting client asserts.

## Development

Declared Elixir range: `~> 1.18` (1.18/1.19/1.20). Supported Erlang/OTP majors: **27, 28, 29** —
enforced by the repository itself at config load, before anything compiles
([ADR 0031](docs/adr/0031-self-enforcing-toolchain-and-tri-platform-build-bar.md)). The
platform contract is **developer portability** — a contributor on Windows, macOS, or Linux can
clone, `deps.get`, compile, and test this repository — enforced in-repo (portable test support,
the LF-forcing `.gitattributes`, no POSIX shell inside declared gates); CI itself runs on Linux
only, one lane per supported major plus the complete-quality lane
([ADR 0033](docs/adr/0033-developer-portability-ci-scope.md)). The full `mix quality` battery is
POSIX-only tooling (shell gates, Gitleaks, ProVerif, kramdown) — Windows developers run it
through WSL or ad-hoc lanes.

```bash
mix deps.get
mix quality
```

`mix quality` runs formatting, warnings-as-errors compilation, the purity architecture gate, Credo,
tests with coverage, Dialyzer, documentation, dependency, license, and currency audits, CycloneDX
SBOM generation, the conformance corpus and mutation gates, and an exact packed/unpacked consumer
test.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-reporting process.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
