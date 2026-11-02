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
canonicalization (RFC 8785), JWK thumbprints (RFC 7638), EdDSA over Ed25519 (RFC 8032), and
ES256 (RFC 7518). The cryptographic suites are `BAP1-Ed25519-SHA256` for v1,
`BAP2-Ed25519-SHA256` for v2, and `BAP3-ES256-SHA256` for v3 (ECDSA P-256 with RFC 7518 §3.4 raw
signatures and low-S canonicality).

## Installation

Install release 0.9.1 from public Hex. This documentation release removes architecture
decision records from the package and its published documentation; verification behavior is unchanged.
Releases 0.7.0 and earlier are retired. Registry consumers use the minor-bounded requirement:

```elixir
def deps do
  [
    {:bounded_authority_protocol, "~> 0.9.1"}
  ]
end
```

The package has **zero production dependencies**, no application callback, and no supervision
tree. It declares `elixir: "~> 1.18"`, which Mix enforces when it compiles the dependency, and
it needs Erlang/OTP 27 or later for the standard-library `:json` module; nothing checks the OTP
version for you. CI tests Elixir 1.18 on OTP 27, 1.19 on OTP 28, and 1.20 on OTP 29. Depend on the
published Hex release, never a Git tag or a checkout. Release notes are in the
[changelog](CHANGELOG.md), and migration notes in [Upgrading](docs/guides/upgrading.md).

## Quickstart

The whole loop in one script: an issuer signs a grant, a holder signs a proof for one request, and
the service verifies both against what it derived from the request. Paste it into `iex -S mix` in
a project that depends on the package. The repository's test suite runs this exact block.

```elixir
alias BoundedAuthorityProtocol.V1

alias BoundedAuthorityProtocol.V1.{
  Credentials,
  ExpectedRequest,
  Grant,
  Operation,
  Proof,
  TrustedIssuer
}

# Demo keys. In production the issuer's private key stays in its KMS or HSM, the holder's in its
# own key store, and the verifier only ever receives public keys.
{issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
{holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_public, %{})

# The issuer grants one operation, restricted to one argument value.
grant = %Grant{
  key_id: "issuer-1",
  issuer: "https://issuer.example",
  grant_id: "grant-001",
  audiences: ["https://docs.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: holder_thumbprint,
  operations: [
    %Operation{name: "publish_article", selectors: [{:equals, ["section"], {:string, "science"}}]}
  ]
}

{:ok, grant_input} = V1.grant_signing_input(grant, %{})
grant_signature = :crypto.sign(:eddsa, :none, grant_input.message, [issuer_private, :ed25519])
{:ok, grant_compact} = V1.assemble_compact(grant_input, grant_signature)

# The holder binds one request to the grant with a proof of possession.
now = 1_800_000_100
arguments = {:object, [{"section", {:string, "science"}}, {"title", {:string, "Tides"}}]}

proof = %Proof{
  holder_public_key: holder_public,
  proof_id: "proof-001",
  method: "POST",
  target_uri: "https://docs.example/articles",
  issued_at: now,
  nonce: nil,
  invocation_id: "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
  operation: "publish_article",
  grant_compact: grant_compact,
  cast_arguments: arguments
}

{:ok, proof_input} = V1.proof_signing_input(proof, %{})
proof_signature = :crypto.sign(:eddsa, :none, proof_input.message, [holder_private, :ed25519])
{:ok, proof_compact} = V1.assemble_compact(proof_input, proof_signature)

# The service verifies the raw bytes against what IT derived from the request.
expected = %ExpectedRequest{
  trusted_issuer: %TrustedIssuer{key_id: "issuer-1", public_key: issuer_public},
  issuer: "https://issuer.example",
  audience: "https://docs.example",
  method: "POST",
  target_uri: "https://docs.example/articles",
  invocation_id: "9b2f1c3e-7a51-4d0e-8f6a-2c4b5d6e7f80",
  operation: "publish_article",
  cast_arguments: arguments,
  evaluation_time: now,
  clock_skew: 60,
  proof_max_age: 300,
  nonce: :not_required,
  bounds: %{}
}

credentials = %Credentials{grant: grant_compact, proof: proof_compact}
{:ok, facts} = V1.check_envelope(credentials, expected)

# The same proof replayed against other arguments fails closed, with no detail.
other_section = {:object, [{"section", {:string, "sports"}}, {"title", {:string, "Tides"}}]}
{:error, :invalid} = V1.check_envelope(credentials, %{expected | cast_arguments: other_section})

{facts.operation, facts.authorization}
```

The final value is `{"publish_article", :not_evaluated}`: the bytes verified, and the
authorization decision is still yours to make. [Getting started](docs/guides/getting-started.md)
walks through the same flow step by step, then covers rejection handling, issuer-key rotation,
and testing your integration.

## Holder-side signer: the report adapter

Producing a signed envelope needs a holder key — and this package deliberately has none: it
computes the deterministic signing input for every protocol object and **refuses to sign**.
The holder-side companion is
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
([GitHub](https://github.com/baselabs/bounded_authority_report_adapter)): it takes a local
key handle (`{module(), term()}` — your HSM, KMS, or in-process test key; the private key never
enters the library) and a protocol signing input, and produces the signed compact form for
holder proofs, local-loopback application proofs, grants, boundary anchors, and key transitions
under contract-majors 1 and 3. Its grant signing can require an authority-signed role
attestation, which it verifies through this package before signing. From adapter 0.9.0 it
also signs content assertions (`sign_content_assertion/3`); adapter 0.10.0 signs over this
package's 0.8.0 release.
The dependency is one-directional: verifiers depend only on this protocol package; the adapter
depends on this package; this package never depends on the adapter.

## What it provides

Each contract-major has its own namespace, `BoundedAuthorityProtocol.V1`, `V2`, and `V3`, with
the same function names; the list below names the `V1` functions. Every function returns
`{:ok, value}` or exactly `{:error, :invalid}`.

Verification (results are redacted and non-authorizing: `GrantFacts`, `EnvelopeFacts`, and
`AnchoredExportFacts` carry `authorization: :not_evaluated`, and the evidence facts carry
`trust: :not_evaluated`):

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

Strict Ed25519 (`BoundedAuthorityProtocol.Ed25519`, ADR 0040):

- `verify_strict/3` — the one Ed25519 verification rule every surface uses: canonical point
  encodings, no small-order key or `R`, a scalar below the group order, and the cofactorless
  equation. A signature under a small-order or non-canonical key never verifies.
- `acceptable_public_key?/1` — key acceptance (32 bytes, canonical, not small-order, on the
  curve); producers and JWK functions refuse a key that fails it.
- `torsion_free?/1` — the host check for key enrollment, trust install, and deny-list or
  revocation comparison. It is not on the verification path; call it yourself at those points.

ES256 (`BoundedAuthorityProtocol.Es256`, since 0.9.0):

- `canonical_signature?/1` — the one ES256 signature rule (`0 < r < n`, `0 < s <= n/2`) that
  verification and the producer surfaces share.
- `acceptable_public_key?/1` and `verify_strict/3` — uncompressed SEC1 key acceptance (coordinates
  below `p`, on the curve) and strict verification.
- `der_to_raw/1` and `normalize_low_s/1` — signer-side utilities: convert a strict DER
  signature from an HSM, KMS, or secret store to the raw `r || s` form, then normalize it to
  low-S before assembly. Assembly itself never normalizes; it refuses (erratum 3).

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

The content-assertion profile `BoundedAuthorityProtocol.ContentAssertion.V1` (ADR 0037) carries
signed `typ: "ba+content-assertion"`: an attestor key binds the digest of exact external content
bytes to an issuer, audience, lineage subject, semantic profile, validity window, and
predecessor. `content_digest/2` hashes the bytes without parsing them. `verify_assertion/2`
requires the caller-supplied attestor key and window, every expected identifier, the expected
profile and content digests, and `now`; it returns redacted `ContentAssertionFacts`
(`trust: :not_evaluated`). `verify_successor/3` checks one generation step between two facts
values. Content meaning, trusted keys, durable lineage state, and replay stay with the caller.
Every other profile rejects these bytes, and this profile rejects theirs.

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

From a project that depends on the package, run the CLI through Mix against the packaged
corpus:

```bash
mix run -e 'BoundedAuthorityProtocol.Conformance.Cli.Main.main(["--corpus", "deps/bounded_authority_protocol/priv/conformance/v1/corpus"])'
```

or install it as a command once and run it from the project:

```bash
mix escript.install hex bounded_authority_protocol 0.9.1
bounded_authority_conformance --corpus deps/bounded_authority_protocol/priv/conformance/v1/corpus
```

(`mix escript.install` puts the command in `~/.mix/escripts`; add that directory to your
`PATH`.) In a checkout of this repository, build it with `mix escript.build` and run
`./bounded_authority_conformance --corpus priv/conformance/v1/corpus`.

`--corpus DIR` is required (no default — a wrong-corpus run that exits 0 would be a quiet
misverification path in the tool built to eliminate quiet misverification). It exits `0` only on
complete agreement, `1` on any integrity or verdict failure, `2` on usage error. The
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

The content-assertion profile's certified corpus (revision 1: 131 assertion, 9 content-digest,
and 14 successor cases; index SHA-256
`14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`) lives under
`priv/conformance/attestation-profiles/content-assertion/v1`. Its check verifies the index and
file digests, every verdict, independent producer and assembly bytes, and cross-profile
rejection:

```bash
mix content_assertion.verify
```

The strict-Ed25519 corpus (`bap-strict-ed25519/1`, revision 1: 2,410 cases in 14 families; index
SHA-256 `732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`) lives under
`priv/conformance/strict-ed25519`. It is additive: it carries the cases of the strict Ed25519
rule (ADR 0040) for every Ed25519 surface, a 1,024-case cross-language differential set, and the
12 published "Taming the many EdDSAs" vectors, while every existing corpus and verdict above stays
unchanged. The same CLI verifies it (shown from a checkout of this repository):

```bash
./bounded_authority_conformance --corpus priv/conformance/strict-ed25519
```

The producer-canonicality corpus (`bap-producer-canonicality/1`, revision 1, erratum 3: 75 cases
in 4 families; index SHA-256
`99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601`) lives under
`priv/conformance/producer-canonicality`. It certifies that compact assembly and anchored-export
encoding refuse a signature no conforming signer emits (ES256 out of range or high-S; Ed25519
`S >= L` or a non-canonical or small-order `R`) and emit accepted bytes unchanged. It ships in
0.9.0 and changes no existing verdict:

```bash
./bounded_authority_conformance --corpus priv/conformance/producer-canonicality
```

## Cross-language verifier SDKs

The repository also carries typed **verifier** SDKs for Python (one dependency, `cryptography`),
Rust (`#![forbid(unsafe_code)]` in the crate itself), and Go (standard library only) under
[`sdks/`](https://github.com/baselabs/bounded_authority_protocol/tree/main/sdks). They are **not published to any registry yet**: install them from a checkout
of this repository by local path, as each SDK's README shows. Each SDK moves to its own
repository when it is first published (ADR 0015). Their behavior is defined by the
specifications and the certified corpora, not by this package's code; source comments
cross-reference the Elixir implementation for traceability.

The TypeScript verifier has already moved: it lives at
[`baselabs/bounded_authority_protocol_typescript`](https://github.com/baselabs/bounded_authority_protocol_typescript)
and is published to npm as
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier).

Every SDK passes the certified v1 (283), v2 (268), and v3 (292) corpora, recomputing each
verdict, asserts each corpus index digest at load, and proves each parser-layer closure
red-capable with a per-language mutation test. The three in-repository SDKs also run the
local-loopback (36 URI + 8 proof), role-attestation (40), content-assertion (131 + 9 + 14), and
strict-Ed25519 (2,410) corpora; the TypeScript repository runs the same profile corpora.

Erratum 3 (producer canonicality, above) is not yet implemented in any SDK: their compact
assembly and anchored-export encoding check only the signature width, so they can assemble a
signature that every verifier rejects. Validate or normalize a signature before assembling it
with an SDK until that SDK's release notes say otherwise. See the [SDK index](https://github.com/baselabs/bounded_authority_protocol/blob/main/sdks/README.md).

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

Start here:

1. [Getting started](docs/guides/getting-started.md): from zero to a verified request, then
   rejection handling, issuer-key rotation, and testing your integration.
2. [Livebook walkthrough](docs/livebooks/bap-walkthrough.livemd): every profile end to end with
   ephemeral keys, including the attacks each one rejects.

Guides:

- [The implementer's guide](docs/guides/implementers-guide.md): building a conforming verifier
  in another language from the specifications and the corpora.
- [Upgrading](docs/guides/upgrading.md): what each release changes and the compatibility
  contract.
- [Usage rules](usage-rules.md): the rules a consuming host follows.
- SDK deployment notes: [TypeScript](docs/deployment/typescript-sdk.md),
  [Python](docs/deployment/python-sdk.md), [Rust](docs/deployment/rust-sdk.md), and
  [Go](docs/deployment/go-sdk.md).

Reference:

- The module documentation on HexDocs: `BoundedAuthorityProtocol.V1`, `V2`, and `V3`, the
  sibling profile namespaces, `BoundedAuthorityProtocol.Ed25519`, and
  `BoundedAuthorityProtocol.Es256`.
- [Protocol charter](docs/design/protocol-charter.md): what the verifier does and the
  verification chain.
- [Threat model](docs/design/threat-model.md), [conformance contract](docs/design/conformance-contract.md),
  [requirement map](docs/design/requirement-map.md), and
  [interoperability report](docs/design/interoperability-report.md).
- [Governance](docs/governance.md) and the [errata registry](docs/errata.md).
- [Changelog](CHANGELOG.md).

Specifications (normative):

- [`spec/bap-v1.md`](spec/bap-v1.md), [`spec/bap-v2.md`](spec/bap-v2.md), and
  [`spec/bap-v3.md`](spec/bap-v3.md): contract-majors 1, 2, and 3
  ([`docs/protocol-v1.md`](docs/protocol-v1.md) is the generated view of v1).
- [`spec/bap-local-loopback-http-v1.md`](spec/bap-local-loopback-http-v1.md),
  [`spec/bap-role-attestation-v1.md`](spec/bap-role-attestation-v1.md), and
  [`spec/bap-content-assertion-v1.md`](spec/bap-content-assertion-v1.md): the sibling profiles.

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
(ADR 0031). The
platform contract is **developer portability** — a contributor on macOS or Linux can
clone, `deps.get`, compile, and test this repository — enforced in-repo (portable test support,
the LF-forcing `.gitattributes`, no POSIX shell inside declared gates); CI itself runs on Linux
only, one lane per supported major plus the complete-quality lane
(ADR 0033). Windows developers use WSL2 (clone
inside the WSL filesystem, not under `/mnt/c`), which is the Linux path; no native-Windows developer
path is maintained. The full `mix quality` battery is
POSIX-only tooling (shell gates, Gitleaks, ProVerif, kramdown).

```bash
mix deps.get
mix quality
```

`mix quality` runs formatting, warnings-as-errors compilation, the purity architecture gate, Credo,
tests with coverage, Dialyzer, documentation, dependency, license, and currency audits, CycloneDX
SBOM generation, the conformance corpus and mutation gates, and an exact packed/unpacked consumer
test.

## Security

Report a vulnerability privately through the repository's
[Security tab](https://github.com/baselabs/bounded_authority_protocol/security) ("Report a
vulnerability"). [`SECURITY.md`](SECURITY.md) has the supported versions and the process.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
