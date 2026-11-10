# bounded_authority_protocol

[![Hex version](https://img.shields.io/hexpm/v/bounded_authority_protocol.svg)](https://hex.pm/packages/bounded_authority_protocol)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/bounded_authority_protocol)
[![CI](https://github.com/baselabs/bounded_authority_protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/hexpm/l/bounded_authority_protocol.svg)](LICENSE)
[![Run in Livebook](https://livebook.dev/badge/v1/blue.svg)](https://livebook.dev/run?url=https%3A%2F%2Fgithub.com%2Fbaselabs%2Fbounded_authority_protocol%2Fblob%2Fmain%2Fdocs%2Flivebooks%2Fbap-walkthrough.livemd)

The open wire profile, verifier, and conformance suite of the Bounded Authority Protocol: an
issuer signs a **capability grant** that names exactly which operations a holder may invoke, with
which arguments; the holder signs a **proof of possession** for each request; a verifier checks
the exact bytes and returns redacted facts. It never returns an authorization decision.

The package is pure and deterministic. It holds no keys, reads no clock, performs no I/O, and
has no runtime dependencies. Every failure is the single value-free `{:error, :invalid}`, and
the wire profile is closed: unknown members, algorithms, encodings, and over-limit structures
are rejected, with no permissive mode. It builds on compact JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)),
DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)), JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)),
JWK thumbprints ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)), Ed25519
([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)), and ES256 ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)).

## Versions

The Hex package and the wire contract are versioned separately. "Package 1.x" is a Hex release
line; "contract-major N" is a closed wire profile, and a package release carries several of them.

| What | Version | Namespace | Suite | Specification |
|---|---|---|---|---|
| Hex package | 0.9.1 | `BoundedAuthorityProtocol` | | [Changelog](CHANGELOG.md) |
| Contract-major 1 | frozen | `BoundedAuthorityProtocol.V1` | `BAP1-Ed25519-SHA256` | [spec](spec/bap-v1.md) |
| Contract-major 2 | frozen | `BoundedAuthorityProtocol.V2` | `BAP2-Ed25519-SHA256` | [spec](spec/bap-v2.md) |
| Contract-major 3 | frozen | `BoundedAuthorityProtocol.V3` | `BAP3-ES256-SHA256` | [spec](spec/bap-v3.md) |
| Local-loopback HTTP proofs | profile 1 | `...ApplicationProfile.LocalLoopbackHttp.V1` | Ed25519 | [spec](spec/bap-local-loopback-http-v1.md) |
| Role attestations | profile 1 | `...RoleAttestation.V1` | Ed25519 | [spec](spec/bap-role-attestation-v1.md) |
| Content assertions | profile 1 | `...ContentAssertion.V1` | Ed25519 | [spec](spec/bap-content-assertion-v1.md) |

[Choosing a profile](docs/guides/choosing-a-profile.md) explains which one to use, and
[API stability and versioning](docs/guides/api-stability.md) lists what each package release
line promises.

## Installation

```elixir
def deps do
  [
    {:bounded_authority_protocol, "~> 0.9.1"}
  ]
end
```

Mix enforces `elixir: "~> 1.18"`. The package also needs Erlang/OTP 27 or later for the
standard-library `:json` module; nothing checks that for you. CI tests Elixir 1.18 on OTP 27,
1.19 on OTP 28, and 1.20 on OTP 29. Depend on the Hex release, never on a Git tag or checkout.

## Quickstart

An issuer signs a grant, a holder signs a proof for one request, and the service verifies both
against what it derived from the request. Paste it into `iex -S mix` in a project that depends on
the package; the repository's test suite runs this exact block.

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
authorization decision is still yours to make.

## What it does, and what it leaves to you

The package verifies grants and proofs, consumption chains, boundary anchors, key transitions,
and anchored exports; it computes the exact signing input for every protocol object and
assembles compact forms from a signature you supply. It does not select trusted keys, issue
grants, hold or use private keys, reserve replay, check live revocation, or decide whether an
effect is authorized. Those belong to your service or a stateful authority runtime; the
[usage rules](usage-rules.md) list them. To sign with keys in an HSM, a KMS, or a local key
store, use the holder-side companion
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).

## Conformance

The package ships every certified corpus under `priv/conformance` and a verifier CLI that exits
`0` only on complete agreement (`1` on any disagreement or integrity failure, `2` on a usage
error). Contract-major 1's corpus has 283 cases across 28 surfaces, independently re-verified by
a second implementation. To run a corpus from your project:

```bash
mix escript.install hex bounded_authority_protocol 0.9.1
bounded_authority_conformance --corpus deps/bounded_authority_protocol/priv/conformance/v1/corpus
```

[Recipes](docs/guides/recipes.md#run-every-packaged-corpus) runs every packaged corpus from
Elixir. Python, Rust, Go, and TypeScript verifiers pass the same corpora; see
[Other languages](docs/guides/other-languages.md).

## Documentation

- Start: [Getting started](docs/guides/getting-started.md), the
  [cheatsheet](docs/guides/cheatsheet.cheatmd), and three Livebooks: the
  [protocol walkthrough](docs/livebooks/bap-walkthrough.livemd),
  [service integration](docs/livebooks/service-integration.livemd), and
  [chains and archives](docs/livebooks/chains-and-archives.livemd).
- Guides: [Choosing a profile](docs/guides/choosing-a-profile.md),
  [Recipes](docs/guides/recipes.md), [Evidence](docs/guides/evidence.md),
  [Troubleshooting `{:error, :invalid}`](docs/guides/troubleshooting.md),
  [Usage rules](usage-rules.md), [Upgrading](docs/guides/upgrading.md), and the
  [implementer's guide](docs/guides/implementers-guide.md).
- Reference: [API stability and versioning](docs/guides/api-stability.md),
  [Glossary](docs/guides/glossary.md), [FAQ](docs/guides/faq.md),
  [threat model](docs/design/threat-model.md), [governance](docs/governance.md), and the
  [errata registry](docs/errata.md).

## Security

Report a vulnerability privately through the repository's
[Security tab](https://github.com/baselabs/bounded_authority_protocol/security) ("Report a
vulnerability"). [`SECURITY.md`](SECURITY.md) has the supported versions and the process.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
