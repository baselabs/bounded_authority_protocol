# bounded_authority_protocol

[![Hex version](https://img.shields.io/hexpm/v/bounded_authority_protocol.svg)](https://hex.pm/packages/bounded_authority_protocol)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/bounded_authority_protocol)
[![CI](https://github.com/baselabs/bounded_authority_protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/hexpm/l/bounded_authority_protocol.svg)](LICENSE)
[![Run in Livebook](https://livebook.dev/badge/v1/blue.svg)](https://livebook.dev/run?url=https%3A%2F%2Fgithub.com%2Fbaselabs%2Fbounded_authority_protocol%2Fblob%2Fv1.0.0%2Fdocs%2Flivebooks%2Fbap-walkthrough.livemd)

The open wire profile, verifier, and conformance suite of the Bounded Authority Protocol: an
issuer signs a **capability grant** that names exactly which operations a holder may invoke, with
which arguments; the holder signs a **proof of possession** for each request; a verifier checks
the exact bytes and returns redacted facts. It never returns an authorization decision.

The package is pure and deterministic, with no private-key access or custody, clock reads, I/O,
or runtime dependencies. Already-trusted public keys and time are explicit caller inputs.
Credential validation failures use the single value-free `{:error, :invalid}`; crypto predicates
return booleans. `ContentAssertion.V1.verify_successor/3` returns `:ok` or
`{:error, :invalid}`. `Bounds.maximum/0` returns its struct directly;
`Conformance.Cli.run/1` returns the integer exit status `0`, `1`, or `2`. See the
[result matrix](docs/guides/api-stability.md#result-families). The wire profile is closed, with no
permissive mode. It builds on compact JWS, DPoP, JCS, and JWK thumbprints
([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [9449](https://www.rfc-editor.org/rfc/rfc9449),
[8785](https://www.rfc-editor.org/rfc/rfc8785), [7638](https://www.rfc-editor.org/rfc/rfc7638)).

## When to use it

Use this package to verify holder-bound grants, exact-request proofs, or signed evidence under
public keys and expectations your host already trusts. It supplies canonical producers and
closed verification profiles for hosts in any domain.

Do not use a verifier result as an authorization decision, a replay store, trusted-key discovery,
revocation service, private-key signer, or evidence-retention service. Those are host responsibilities.

## Versions

"Package 1.x" is a Hex release line; "contract-major N" is a closed wire profile. One package
release carries several profiles.

| What | Version | Namespace | Suite | Specification |
|---|---|---|---|---|
| Hex package | 1.0.0 | `BoundedAuthorityProtocol` | | [Changelog](CHANGELOG.md) |
| Contract-major 1 | frozen | `BoundedAuthorityProtocol.V1` | `BAP1-Ed25519-SHA256` | [spec](spec/bap-v1.md) |
| Contract-major 2 | frozen | `BoundedAuthorityProtocol.V2` | `BAP2-Ed25519-SHA256` | [spec](spec/bap-v2.md) |
| Contract-major 3 | frozen | `BoundedAuthorityProtocol.V3` | `BAP3-ES256-SHA256` | [spec](spec/bap-v3.md) |
| Local-loopback HTTP proofs | profile 1 | `...ApplicationProfile.LocalLoopbackHttp.V1` | Ed25519 | [spec](spec/bap-local-loopback-http-v1.md) |
| Role attestations | profile 1 | `...RoleAttestation.V1` | Ed25519 | [spec](spec/bap-role-attestation-v1.md) |
| Content assertions | profile 1 | `...ContentAssertion.V1` | Ed25519 | [spec](spec/bap-content-assertion-v1.md) |

See [Choosing a profile](docs/guides/choosing-a-profile.md) and
[API stability and versioning](docs/guides/api-stability.md).

## Installation

```elixir
def deps do
  [{:bounded_authority_protocol, "~> 1.0"}]
end
```

Elixir 1.18 or later (Mix enforces it) and Erlang/OTP 27 or later (for `:json`; nothing checks
it). CI tests Elixir 1.18, 1.19, and 1.20 on OTP 27, 28, and 29. A maintainer qualifies each
change with one push to `kci/<sha>`; `main` moves to that exact commit only when `qualified`
is green. Pull requests, including forks, get no CI run of their own. The maintainers' release
operator dispatches Hex publication and site deployment from `main`; see
[Contributing](CONTRIBUTING.md#package-publication-and-site-deployment).

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

## What it leaves to you

The package verifies grants, proofs, and the evidence formats, and computes the exact bytes to
sign for every protocol object. It does not select trusted keys, hold private keys, reserve
replay, check revocation, or decide whether an effect is authorized; the
[usage rules](usage-rules.md) list what your service owns. To sign with keys in an HSM, a KMS, or
a key store, use [`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).

## Conformance

Every certified corpus ships under `priv/conformance`, with a CLI that exits `0` only on
complete agreement. Contract-major 1's corpus alone has 283 cases across 28 surfaces:

```bash
mix escript.install hex bounded_authority_protocol 1.0.0
bounded_authority_conformance --corpus deps/bounded_authority_protocol/priv/conformance/v1/corpus
```

TypeScript, Python, Rust, and Go verifiers pass the same corpora
([Other languages](docs/guides/other-languages.md)).

The in-tree Python, Rust, and Go SDKs each carry the complete Hex corpus tree at
`conformance/priv/conformance/` inside their SDK root. Tests run from copied SDK roots and
unpacked language packages. Input hashes, exact inventories, complete execution, and computed
verdict digests bind each runner to the same frozen cases. See the
[distribution and projection contract](docs/design/corpus-verdict-digests.md).

## Documentation

1. Start: [getting started](docs/guides/getting-started.md), [choosing a profile](docs/guides/choosing-a-profile.md), [notebook index](docs/guides/notebooks.md).
2. Concepts: [grants and proofs](docs/guides/grants-and-holder-proofs.md), [trusted keys](docs/guides/trusted-keys-and-rotation.md), [tagged arguments](docs/guides/tagged-arguments-and-selectors.md), [nonce and time](docs/guides/nonce-and-time-policy.md), [facts and authorization](docs/guides/facts-and-authorization.md), [evidence](docs/guides/evidence.md).
3. Integrate and operate: [hosts and frameworks](docs/guides/framework-integration.md), [security](docs/guides/integration-security.md), [operations](docs/guides/operations.md), [observability](docs/guides/observability.md), [errors](docs/guides/errors.md), [troubleshooting](docs/guides/troubleshooting.md), [recipes](docs/guides/recipes.md), [testing](docs/guides/testing-your-integration.md).
4. Reference: [cheatsheet](docs/guides/cheatsheet.cheatmd), [API and result matrix](docs/guides/api-stability.md), [glossary](docs/guides/glossary.md), [FAQ](docs/guides/faq.md), [upgrading](docs/guides/upgrading.md), [other languages](docs/guides/other-languages.md), [usage rules](usage-rules.md).
5. Implementers: [implementer's guide](docs/guides/implementers-guide.md), [specifications](spec/bap-v1.md), [conformance](docs/design/conformance-contract.md), [interoperability](docs/design/interoperability-report.md).

### Notebook journeys

Each notebook introduces one step per code cell, matches success and refusal results, and
persists only safe semantic outputs. Download a file and import it into Livebook, then choose
**Run all**. The launch links open the earlier notebooks at the immutable 1.0.0 release tag;
import the current files for the steps below. The [notebook index](docs/guides/notebooks.md)
lists each journey and its checked output count.

- [Core envelope verification](docs/notebooks/bap-walkthrough.livemd)
- [Contract-major 2 ranges](docs/notebooks/range-selectors.livemd)
- [Contract-major 3 ES256](docs/notebooks/es256-signing.livemd)
- [Service integration](docs/notebooks/service-integration.livemd)
- [Local loopback](docs/notebooks/local-loopback.livemd)
- [Role attestations](docs/notebooks/role-attestations.livemd)
- [Content lineage](docs/notebooks/content-lineage.livemd)
- [Chains and archives](docs/notebooks/chains-and-archives.livemd)
- [Advanced strict crypto](docs/notebooks/strict-crypto.livemd)

## Security

Report a vulnerability privately through the
[Security tab](https://github.com/baselabs/bounded_authority_protocol/security); see
[`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
