# Getting started

This guide takes you from an empty project to a verified request in five steps, then covers the
jobs that come next: handling a rejection, rotating issuer keys, and testing your integration.
Every Elixir block below runs, in order, in the repository's test suite.

## What you are holding

`bounded_authority_protocol` is a pure, deterministic verification library. It proves that the
bytes a caller supplies satisfy the trusted keys and expected context the caller also supplies.
It never selects trusted keys, reserves replay, checks revocation, or grants execution: those
belong to your service or to a stateful authority runtime. The
[standard specification](../../spec/bap-v1.md) is the normative profile; this guide is
operational.

## Install

```elixir
defp deps do
  [{:bounded_authority_protocol, "~> 0.9.0"}]
end
```

Release 0.9.0 is the current Hex release (published October 29, 2026). Releases 0.7.0 and earlier are retired for a security
fix; the [changelog](../../CHANGELOG.md) and [Upgrading](upgrading.md)
describe each release. Depend on the Hex package, never on a Git tag or checkout. The package
has no runtime dependencies. Mix enforces its `elixir: "~> 1.18"` requirement; it also needs
Erlang/OTP 27 or later (the standard-library `:json` module), which nothing checks for you. CI
tests Elixir 1.18 on OTP 27, 1.19 on OTP 28, and 1.20 on OTP 29.

The verifier never signs. To produce signed grants and proofs with keys held in an HSM, a KMS,
or a local key store, use the holder-side companion
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).
The examples below sign with `:crypto` and throwaway keys so they run anywhere.

## Verify your first request

### 1. Keys

The issuer signs grants; the holder signs one proof per request. The verifier receives only
public keys. A grant names its holder by the RFC 7638 thumbprint of the holder's public key.

```elixir
alias BoundedAuthorityProtocol.V1

alias BoundedAuthorityProtocol.V1.{
  Credentials,
  ExpectedGrant,
  ExpectedRequest,
  Grant,
  Operation,
  Proof,
  TrustedIssuer
}

{issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
{holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_public, %{})

byte_size(holder_thumbprint)
```

The value is `32`: the thumbprint is a raw 32-byte SHA-256 digest.

### 2. The grant

A grant lists the operations the holder may invoke and, for each, selectors over the
arguments. Selectors apply together: here the holder may restart a service only in the `staging`
environment, and only one of two named services.

```elixir
grant = %Grant{
  key_id: "issuer-2026-10",
  issuer: "https://issuer.example",
  grant_id: "grant-restart-001",
  audiences: ["https://deploy.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: holder_thumbprint,
  operations: [
    %Operation{
      name: "restart_service",
      selectors: [
        {:equals, ["environment"], {:string, "staging"}},
        {:one_of, ["service"], [{:string, "search"}, {:string, "indexer"}]}
      ]
    }
  ]
}

{:ok, grant_input} = V1.grant_signing_input(grant, %{})
grant_signature = :crypto.sign(:eddsa, :none, grant_input.message, [issuer_private, :ed25519])
{:ok, grant_compact} = V1.assemble_compact(grant_input, grant_signature)

length(String.split(grant_compact, "."))
```

The value is `3`: a compact JWS has three dot-separated parts.

`grant_signing_input/2` returns the exact bytes to sign (`grant_input.message`);
`assemble_compact/2` checks the signature width and the encoded parts and returns the compact
JWS. Since 0.9.0, it also refuses a signature that no
conforming signer emits (for Ed25519, `S` not below the group order or a non-canonical or
small-order `R`) and never rewrites the bytes it accepts. Neither function sees a private key.

### 3. The proof

For each request the holder signs a proof that binds the grant (by its digest), the HTTP method
and URI, a fresh invocation id, the operation, and a digest of the typed arguments.

```elixir
now = 1_800_000_100

arguments =
  {:object, [{"environment", {:string, "staging"}}, {"service", {:string, "search"}}]}

proof = %Proof{
  holder_public_key: holder_public,
  proof_id: "proof-restart-001",
  method: "POST",
  target_uri: "https://deploy.example/services/restart",
  issued_at: now,
  nonce: nil,
  invocation_id: "3f0c2a9e-1b7d-4c55-9e21-6a8b0d4f7c13",
  operation: "restart_service",
  grant_compact: grant_compact,
  cast_arguments: arguments
}

{:ok, proof_input} = V1.proof_signing_input(proof, %{})
proof_signature = :crypto.sign(:eddsa, :none, proof_input.message, [holder_private, :ed25519])
{:ok, proof_compact} = V1.assemble_compact(proof_input, proof_signature)

length(String.split(proof_compact, "."))
```

The value is `3` again.

Arguments use the package's tagged JSON form (`{:object, members}`, `{:string, s}`,
`{:integer, i}`, and so on), so an integer and a float never compare equal by accident. Your
service builds this value from the request it parsed; `BoundedAuthorityProtocol.V1.Json.decode/2`
produces it from raw JSON bytes.

### 4. Verify

The service supplies everything: the trusted issuer key, the expected issuer and audience, the
values it derived from the incoming request, the evaluation time, and the limits.

```elixir
trusted = %TrustedIssuer{key_id: "issuer-2026-10", public_key: issuer_public}

expected = %ExpectedRequest{
  trusted_issuer: trusted,
  issuer: "https://issuer.example",
  audience: "https://deploy.example",
  method: "POST",
  target_uri: "https://deploy.example/services/restart",
  invocation_id: "3f0c2a9e-1b7d-4c55-9e21-6a8b0d4f7c13",
  operation: "restart_service",
  cast_arguments: arguments,
  evaluation_time: now,
  clock_skew: 60,
  proof_max_age: 300,
  nonce: :not_required,
  bounds: %{}
}

credentials = %Credentials{grant: grant_compact, proof: proof_compact}
{:ok, facts} = V1.check_envelope(credentials, expected)

{facts.operation, facts.grant_id, facts.authorization}
```

The result is `{"restart_service", "grant-restart-001", :not_evaluated}`. `EnvelopeFacts`
carries identifiers, digests, and times, never the raw signature, key, nonce, or arguments, and
its `authorization` field is always `:not_evaluated`.

To check a grant on its own (for example when the holder registers it), use
`verify_grant/3`:

```elixir
expected_grant = %ExpectedGrant{
  issuer: "https://issuer.example",
  audience: "https://deploy.example",
  evaluation_time: now,
  clock_skew: 60,
  bounds: %{}
}

{:ok, grant_facts} = V1.verify_grant(grant_compact, trusted, expected_grant)
{grant_facts.grant_id, grant_facts.authorization}
```

The value is `{"grant-restart-001", :not_evaluated}`.

### 5. Decide

Verification is one input to your decision. Before you act, your service still has to reserve
the invocation id against replay, check that the grant is not revoked, and apply its own policy.
See [usage rules](../../usage-rules.md).

## Handle a rejection

Every failure is the same value: `{:error, :invalid}`. A wrong key, another audience, an expired
grant, a changed byte, an argument outside the selectors, or a stale proof all look identical,
so the error leaks nothing an attacker could use.

```elixir
production = %{expected | cast_arguments: {:object, [{"environment", {:string, "production"}}, {"service", {:string, "search"}}]}}
late = %{expected | evaluation_time: now + 400}
other_audience = %{expected | audience: "https://billing.example"}

for request <- [production, late, other_audience] do
  V1.check_envelope(credentials, request)
end
```

Each entry is `{:error, :invalid}`. To find out why a credential you produced is rejected,
compare your expected values with what the credential carries. `decode_grant/2` and
`decode_proof/2` read the claims without checking any signature, so use them for diagnosis only,
never for a decision:

```elixir
{:ok, decoded} = V1.decode_grant(grant_compact, %{})
{decoded.issuer, decoded.audiences, decoded.expires_at}
```

The value is `{"https://issuer.example", ["https://deploy.example"], 1_800_003_600}`.

## Rotate issuer keys

An issuer rotates keys by signing new grants under a new `kid` while old grants keep the old
one. Keep every currently trusted issuer key in your own key set, read the grant's `kid` with
`untrusted_key_locator/2`, and look it up there. The `kid` is only a hint: an unknown `kid`
must fail, and a known `kid` still has to verify under the key you selected.

```elixir
{next_public, next_private} = :crypto.generate_key(:eddsa, :ed25519)

trusted_keys = %{
  "issuer-2026-10" => issuer_public,
  "issuer-2027-01" => next_public
}

next_grant = %{grant | key_id: "issuer-2027-01", grant_id: "grant-restart-002"}
{:ok, next_input} = V1.grant_signing_input(next_grant, %{})
next_signature = :crypto.sign(:eddsa, :none, next_input.message, [next_private, :ed25519])
{:ok, next_compact} = V1.assemble_compact(next_input, next_signature)

verify_with_trusted_keys = fn compact ->
  with {:ok, locator} <- V1.untrusted_key_locator(compact, %{}),
       {:ok, public_key} <- Map.fetch(trusted_keys, locator.kid) do
    V1.verify_grant(compact, %TrustedIssuer{key_id: locator.kid, public_key: public_key}, expected_grant)
  else
    _ -> {:error, :invalid}
  end
end

{:ok, old} = verify_with_trusted_keys.(grant_compact)
{:ok, new} = verify_with_trusted_keys.(next_compact)
{old.grant_id, new.grant_id}
```

The value is `{"grant-restart-001", "grant-restart-002"}`: both grants verify while both keys are
trusted.

To retire the old key, remove it from `trusted_keys`; its grants then fail. Before you trust a
new Ed25519 key, check it with `BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1` and
`BoundedAuthorityProtocol.Ed25519.torsion_free?/1` (usage rule 17):

```elixir
{BoundedAuthorityProtocol.Ed25519.acceptable_public_key?(next_public),
 BoundedAuthorityProtocol.Ed25519.torsion_free?(next_public)}
```

The value is `{true, true}`.

Signed rotation evidence for archives (boundary anchors, key transitions, and anchored exports)
has its own functions: `verify_historical_anchor/3`, `verify_key_transition/4`, and
`verify_anchored_export/3`. Their inputs and rules are in
[`spec/bap-v1.md` § 15](../../spec/bap-v1.md#chain).

## Test your integration

The package ships its certified conformance corpora and a verifier CLI that checks every case
and exits `0` only on full agreement (`1` on any disagreement or integrity failure, `2` on a
usage error). From your project, after `mix deps.get`:

```sh
mix run -e 'BoundedAuthorityProtocol.Conformance.Cli.Main.main(["--corpus", "deps/bounded_authority_protocol/priv/conformance/v1/corpus"])'
```

Repeat with `v2/corpus`, `v3/corpus`, or `strict-ed25519` in place of `v1/corpus`. To install
the CLI as a command instead, run `mix escript.install hex bounded_authority_protocol 0.9.0`
(it lands in `~/.mix/escripts`) and then
`bounded_authority_conformance --corpus deps/bounded_authority_protocol/priv/conformance/v1/corpus`.
In a checkout of this repository, `mix escript.build` builds the same CLI, and the repository's
quality gate runs it over every corpus. Exit `0` is conformance evidence, not an authorization.

For your own service, test the rejection paths, not only the happy path: a changed byte, a wrong
audience, an expired grant, an argument outside the selectors, and a replayed invocation id
(your replay store, not this package, must catch that one).

## The three rules that surprise newcomers

1. **Facts are not authority.** A successful verification proves byte-level properties against
   the inputs you supplied. A decision also needs trust selection, replay reservation, and
   revocation, which live outside this package.
2. **Everything is closed.** Unknown members, alternate encodings, duplicate names, and
   over-limit structures are rejected. There is no permissive mode.
3. **Time is an input.** The verifier reads no clock. You pass the evaluation time, the skew
   (at most 60 seconds), and the proof maximum age (at most 300 seconds).

## Other profiles

The same steps apply to the other namespaces, each with its own specification and corpus:

- `BoundedAuthorityProtocol.V2` (contract-major 2) adds the range selectors `lte` and `gte`
  ([spec](../../spec/bap-v2.md)).
- `BoundedAuthorityProtocol.V3` (contract-major 3) uses ES256 (ECDSA P-256) keys and signatures
  ([spec](../../spec/bap-v3.md)).
- `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1` is a byte-distinct proof
  for a local development listener on literal `127.0.0.1` or `[::1]` HTTP, with a mandatory
  server nonce ([spec](../../spec/bap-local-loopback-http-v1.md)). Loopback HTTP is not TLS and
  does not isolate local processes.
- `BoundedAuthorityProtocol.RoleAttestation.V1` binds a key to the `issuer` or `holder` role
  ([spec](../../spec/bap-role-attestation-v1.md)).
- `BoundedAuthorityProtocol.ContentAssertion.V1` binds the digest of exact content bytes to an
  issuer, audience, lineage subject, and window ([spec](../../spec/bap-content-assertion-v1.md)).

Each namespace rejects the others' bytes. Select one explicitly; never infer a profile from the
input or retry another after a rejection. The
[Livebook walkthrough](../livebooks/bap-walkthrough.livemd) runs every one of them.

## Where to go next

- The [Livebook walkthrough](../livebooks/bap-walkthrough.livemd): every profile, with the
  attacks each one rejects.
- [Usage rules](../../usage-rules.md): what a consuming host must do.
- [Upgrading](upgrading.md): what each release changes.
- The [implementer's guide](implementers-guide.md): building a verifier in another language.
