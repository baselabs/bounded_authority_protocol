# Recipes

Short, complete answers to the integration questions that come up after
[Getting started](getting-started.md). Every Elixir block on this page runs, in order, in the
repository's test suite, and the sentence after each block states the value it ends with.

The first block sets up the keys and a helper the later recipes share. The examples sign with
`:crypto` and throwaway keys; in production the issuer signs in its KMS or HSM and the holder
signs with its own key store, for example through the companion
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).

```elixir
alias BoundedAuthorityProtocol.{Es256, V1, V2, V3}
alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedGrant, ExpectedRequest, TrustedIssuer}

{issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
{holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_public, %{})

ed25519_sign = fn message, private_key ->
  :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
end

now = 1_800_000_100

{byte_size(issuer_public), byte_size(holder_thumbprint)}
```

The value is `{32, 32}`: a raw Ed25519 public key and a raw SHA-256 thumbprint.

## Plug and Phoenix integration

A service verifies a request in three steps: derive the expected values from its own routing and
configuration, read the two compact credentials from the request, and call `check_envelope/2`.
The protocol defines no HTTP binding, so the header names are a choice your deployment makes and
documents; the example uses `authorization: DPoP <grant>` and `dpop: <proof>`, as in
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), and an `invocation-id` header.

### Turn already-parsed params into tagged arguments

The request digest covers the operation's arguments in the package's tagged JSON form. When
Plug has already parsed the body, and after your own code has cast it to the operation's
declared types, convert the result once, at the boundary. The module below handles what
`Plug.Parsers` and Ecto produce: string or atom keys, strings, integers, floats, booleans, `nil`,
lists, and maps. It refuses anything else, such as a struct or a tuple, instead of guessing.

```elixir
defmodule MyApp.CastArguments do
  @moduledoc "Converts cast request params into the protocol's tagged JSON value."

  def tag(value) do
    {:ok, do_tag(value)}
  catch
    :invalid -> {:error, :invalid}
  end

  defp do_tag(nil), do: :null
  defp do_tag(value) when is_boolean(value), do: {:boolean, value}
  defp do_tag(value) when is_integer(value), do: {:integer, value}
  defp do_tag(value) when is_float(value), do: {:float, value}
  defp do_tag(value) when is_binary(value), do: {:string, value}
  defp do_tag(values) when is_list(values), do: {:array, Enum.map(values, &do_tag/1)}

  defp do_tag(%{__struct__: _}), do: throw(:invalid)

  defp do_tag(%{} = map) do
    members = for {key, value} <- map, do: {member_name(key), do_tag(value)}
    names = Enum.map(members, &elem(&1, 0))
    if length(Enum.uniq(names)) != length(names), do: throw(:invalid)
    {:object, Enum.sort(members)}
  end

  defp do_tag(_other), do: throw(:invalid)

  defp member_name(key) when is_binary(key), do: key
  defp member_name(key) when is_atom(key) and not is_nil(key) and not is_boolean(key),
    do: Atom.to_string(key)

  defp member_name(_key), do: throw(:invalid)
end

MyApp.CastArguments.tag(%{"dataset" => "tides", "rows" => 500, "dry_run" => false})
```

The value is
`{:ok, {:object, [{"dataset", {:string, "tides"}}, {"dry_run", {:boolean, false}}, {"rows", {:integer, 500}}]}}`.

Cast before you tag. A JSON body of `{"rows": 500.0}` parses to the float `500.0`, which tags as
`{:float, 500.0}`; that is a different argument from `{:integer, 500}`, so a proof signed over
one never verifies against the other. Your operation's schema decides which one the request
means. When you have the raw body bytes instead, `V1.Json.decode/2` produces the tagged value
directly, with duplicate-name and bounds checks.

### The verification boundary

The plug below reads the credentials, builds `ExpectedRequest` from the service's own
configuration (the public origin, the trusted issuer keys, the route's operation name), and
verifies. The request URL comes from the configured public origin and the request path, never
from the `Host` header or a forwarding header, which the client controls.

```elixir
defmodule MyAppWeb.BoundedAuthority do
  @moduledoc """
  Verifies a bounded-authority envelope. Use it as a plug with
  `plug MyAppWeb.BoundedAuthority, operation: "export_dataset"`.
  """

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}

  def init(options), do: Map.new(options)

  def call(conn, options) do
    case verify(conn, Map.merge(options, config()), System.os_time(:second)) do
      {:ok, facts} ->
        Plug.Conn.assign(conn, :bounded_authority_facts, facts)

      {:error, :invalid} ->
        conn |> Plug.Conn.send_resp(401, "") |> Plug.Conn.halt()
    end
  end

  # The pure part: everything it needs is an argument, so it is easy to test.
  def verify(conn, options, now) do
    with {:ok, grant} <- header(conn, "authorization", "DPoP "),
         {:ok, proof} <- header(conn, "dpop", ""),
         {:ok, invocation_id} <- header(conn, "invocation-id", ""),
         {:ok, arguments} <- MyApp.CastArguments.tag(conn.body_params),
         {:ok, locator} <- V1.untrusted_key_locator(grant, %{}),
         {:ok, issuer_key} <- Map.fetch(options.issuer_keys, locator.kid) do
      expected = %ExpectedRequest{
        trusted_issuer: %TrustedIssuer{key_id: locator.kid, public_key: issuer_key},
        issuer: options.issuer,
        audience: options.audience,
        method: conn.method,
        target_uri: options.origin <> conn.request_path,
        invocation_id: invocation_id,
        operation: options.operation,
        cast_arguments: arguments,
        evaluation_time: now,
        clock_skew: 60,
        proof_max_age: 300,
        nonce: :not_required,
        bounds: %{}
      }

      V1.check_envelope(%Credentials{grant: grant, proof: proof}, expected)
    else
      _rejected -> {:error, :invalid}
    end
  end

  defp header(conn, name, prefix) do
    case for({^name, value} <- conn.req_headers, do: value) do
      [value] -> strip_prefix(value, prefix)
      _missing_or_repeated -> {:error, :invalid}
    end
  end

  defp strip_prefix(value, prefix) do
    if String.starts_with?(value, prefix),
      do: {:ok, binary_part(value, byte_size(prefix), byte_size(value) - byte_size(prefix))},
      else: {:error, :invalid}
  end

  defp config, do: Map.new(Application.get_env(:my_app, __MODULE__, []))
end

:ok
```

The value is `:ok`. In Phoenix, add the plug to a pipeline or a controller, then read
`conn.assigns.bounded_authority_facts` in the action. The facts say the bytes verified; your
action still reserves `facts.invocation_id` in its replay store, checks revocation of
`facts.grant_id`, and decides.

To see the boundary work, a holder signs a grant and a proof, and a request shaped like a
`Plug.Conn` (the plug reads only `method`, `request_path`, `req_headers`, and `body_params`) goes
through `verify/3`:

```elixir
grant = %V1.Grant{
  key_id: "issuer-2027-01",
  issuer: "https://issuer.example",
  grant_id: "grant-export-001",
  audiences: ["https://data.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: holder_thumbprint,
  operations: [
    %V1.Operation{
      name: "export_dataset",
      selectors: [{:one_of, ["dataset"], [{:string, "tides"}, {:string, "currents"}]}]
    }
  ]
}

{:ok, grant_input} = V1.grant_signing_input(grant, %{})
{:ok, grant_compact} = V1.assemble_compact(grant_input, ed25519_sign.(grant_input.message, issuer_private))

params = %{"dataset" => "tides", "rows" => 500, "dry_run" => false}
{:ok, arguments} = MyApp.CastArguments.tag(params)

proof = %V1.Proof{
  holder_public_key: holder_public,
  proof_id: "proof-export-001",
  method: "POST",
  target_uri: "https://data.example/exports",
  issued_at: now,
  nonce: nil,
  invocation_id: "0c7d2f4a-5b1e-4f8a-9d3c-2e6b8a1f4c70",
  operation: "export_dataset",
  grant_compact: grant_compact,
  cast_arguments: arguments
}

{:ok, proof_input} = V1.proof_signing_input(proof, %{})
{:ok, proof_compact} = V1.assemble_compact(proof_input, ed25519_sign.(proof_input.message, holder_private))

conn = %{
  method: "POST",
  request_path: "/exports",
  body_params: params,
  req_headers: [
    {"authorization", "DPoP " <> grant_compact},
    {"dpop", proof_compact},
    {"invocation-id", "0c7d2f4a-5b1e-4f8a-9d3c-2e6b8a1f4c70"}
  ]
}

options = %{
  issuer: "https://issuer.example",
  audience: "https://data.example",
  origin: "https://data.example",
  operation: "export_dataset",
  issuer_keys: %{"issuer-2027-01" => issuer_public}
}

{:ok, facts} = MyAppWeb.BoundedAuthority.verify(conn, options, now)

{facts.operation, facts.invocation_id,
 MyAppWeb.BoundedAuthority.verify(%{conn | body_params: %{params | "dataset" => "salinity"}}, options, now)}
```

The value is
`{"export_dataset", "0c7d2f4a-5b1e-4f8a-9d3c-2e6b8a1f4c70", {:error, :invalid}}`: the request
verifies, and the same credentials with a dataset outside the grant's `one_of` selector do not.

## Selectors per contract-major

A selector restricts one argument path. Every contract-major has `equals`, `one_of`, and `all`
(which applies no restriction); contract-majors 2 and 3 add the inclusive ranges `lte` and `gte`
over numbers. The kinds and their exact rules are in [`spec/bap-v1.md`](../../spec/bap-v1.md)
and [`spec/bap-v2.md` § 4](../../spec/bap-v2.md).

| Kind | Form | Contract-majors |
|---|---|---|
| `equals` | `{:equals, path, value}` | 1, 2, 3 |
| `one_of` | `{:one_of, path, [value, ...]}` | 1, 2, 3 |
| `all` | `:all` | 1, 2, 3 |
| `lte` | `{:lte, path, {:integer, n} or {:float, x}}` | 2, 3 |
| `gte` | `{:gte, path, {:integer, n} or {:float, x}}` | 2, 3 |

A contract-major 2 grant can cap a numeric argument:

```elixir
v2_grant = %V2.Grant{
  key_id: "issuer-2027-01",
  issuer: "https://issuer.example",
  grant_id: "grant-render-001",
  audiences: ["https://render.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: holder_thumbprint,
  operations: [
    %V2.Operation{
      name: "render_frames",
      selectors: [
        {:equals, ["project"], {:string, "harbor-survey"}},
        {:gte, ["frames"], {:integer, 1}},
        {:lte, ["frames"], {:integer, 240}}
      ]
    }
  ]
}

{:ok, v2_input} = V2.grant_signing_input(v2_grant, %{})
{:ok, v2_compact} = V2.assemble_compact(v2_input, ed25519_sign.(v2_input.message, issuer_private))

v2_envelope = fn frames ->
  arguments = {:object, [{"frames", {:integer, frames}}, {"project", {:string, "harbor-survey"}}]}

  v2_proof = %V2.Proof{
    holder_public_key: holder_public,
    proof_id: "proof-render-#{frames}",
    method: "POST",
    target_uri: "https://render.example/jobs",
    issued_at: now,
    nonce: nil,
    invocation_id: "5e0a9c1d-2b7f-4e3a-8c6d-1f4b9a2e7" <> String.pad_leading("#{frames}", 3, "0"),
    operation: "render_frames",
    grant_compact: v2_compact,
    cast_arguments: arguments
  }

  {:ok, proof_input} = V2.proof_signing_input(v2_proof, %{})
  {:ok, proof_compact} = V2.assemble_compact(proof_input, ed25519_sign.(proof_input.message, holder_private))

  expected = %ExpectedRequest{
    trusted_issuer: %TrustedIssuer{key_id: "issuer-2027-01", public_key: issuer_public},
    issuer: "https://issuer.example",
    audience: "https://render.example",
    method: "POST",
    target_uri: "https://render.example/jobs",
    invocation_id: v2_proof.invocation_id,
    operation: "render_frames",
    cast_arguments: arguments,
    evaluation_time: now,
    clock_skew: 60,
    proof_max_age: 300,
    nonce: :not_required,
    bounds: %{}
  }

  case V2.check_envelope(%Credentials{grant: v2_compact, proof: proof_compact}, expected) do
    {:ok, _facts} -> :verified
    {:error, :invalid} -> :rejected
  end
end

Enum.map([1, 240, 241], v2_envelope)
```

The value is `[:verified, :verified, :rejected]`: both bounds are inclusive.

A range compares integers with integers and floats with floats; an integer argument never
satisfies a float bound, and the reverse. Pick the tag the argument will carry.

### Tag numbers by what they are

Tag a whole number as `{:integer, n}`. Every grant producer refuses a float-tagged integral
selector value, such as `{:float, 2.0}`, on every contract-major: canonical JSON writes `2.0` as
`2`, which decodes integer-tagged, so the signed grant would not mean what you built
([erratum 6](../errata.md)). A non-integral float stays a valid range bound.

```elixir
selector_grant = fn module, selector ->
  struct(Module.concat(module, Grant), %{
    Map.from_struct(v2_grant)
    | operations: [struct(Module.concat(module, Operation), name: "render_frames", selectors: [selector])]
  })
end

{
  V1.grant_signing_input(selector_grant.(V1, {:equals, ["scale"], {:float, 2.0}}), %{}),
  V3.grant_signing_input(selector_grant.(V3, {:lte, ["scale"], {:float, 2.0}}), %{}),
  elem(V2.grant_signing_input(selector_grant.(V2, {:lte, ["scale"], {:float, 2.5}}), %{}), 0)
}
```

The value is `{{:error, :invalid}, {:error, :invalid}, :ok}`.

Verification closes the same gap from the other side: a grant whose `equals` value or `one_of`
member holds a float zero (`0.0`, `-0.0`, or an underflowing literal such as `1e-400`) does not
decode on any contract-major, even when the issuer signed those bytes, because conforming
verifiers would otherwise disagree about whether `0.0` and `-0.0` are the same value. The block
signs such a payload by hand to show it:

```elixir
sign_compact = fn message -> message <> "." <> Base.url_encode64(ed25519_sign.(message, issuer_private), padding: false) end

zero_selector = [{:equals, ["offset"], {:integer, 0}}]
zero_grant = %{grant | operations: [%V1.Operation{name: "export_dataset", selectors: zero_selector}]}
{:ok, zero_input} = V1.grant_signing_input(zero_grant, %{})

[protected, payload] = String.split(zero_input.message, ".")

float_zero_payload =
  payload
  |> Base.url_decode64!(padding: false)
  |> String.replace(~s("value":0), ~s("value":0.0))
  |> Base.url_encode64(padding: false)

{:ok, _decoded} = V1.decode_grant(sign_compact.(zero_input.message), %{})
V1.decode_grant(sign_compact.(protected <> "." <> float_zero_payload), %{})
```

The value is `{:error, :invalid}`: the integer zero decodes, and the float zero, signed by the
same issuer, is refused.

## ES256 from a KMS or HSM

Contract-major 3 signs with ES256 (ECDSA P-256, SHA-256). Cloud KMS and HSM APIs return ECDSA
signatures in DER (`SEQUENCE { INTEGER r, INTEGER s }`) and may return either of the two valid
`s` values. The wire needs the raw 64-byte `r || s` with the low `s`, so the signer converts and
normalizes before assembly; assembly itself never rewrites a signature and refuses one that is
not canonical.

Ask the KMS to sign the signing input's `message` bytes with SHA-256 (for example AWS KMS
`ECDSA_SHA_256` with message type `RAW`, or Cloud KMS `EC_SIGN_P256_SHA256` given the SHA-256
digest of `message`). Below, `:crypto` stands in for the KMS: it also returns DER.

```elixir
{kms_public, kms_private} = :crypto.generate_key(:ecdh, :prime256v1)
{es_holder_public, _es_holder_private} = :crypto.generate_key(:ecdh, :prime256v1)
{:ok, es_holder_thumbprint} = V3.EcJwk.public_key_thumbprint_raw(es_holder_public, %{})

kms_sign = fn message -> :crypto.sign(:ecdsa, :sha256, message, [kms_private, :prime256v1]) end

es_grant = %V3.Grant{
  key_id: "kms-issuer-1",
  issuer: "https://issuer.example",
  grant_id: "grant-es-001",
  audiences: ["https://render.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: es_holder_thumbprint,
  operations: [%V3.Operation{name: "render_frames", selectors: [{:lte, ["frames"], {:integer, 240}}]}]
}

{:ok, es_input} = V3.grant_signing_input(es_grant, %{})
der = kms_sign.(es_input.message)

{:ok, raw} = Es256.der_to_raw(der)
{:ok, low_s} = Es256.normalize_low_s(raw)
{:ok, es_compact} = V3.assemble_compact(es_input, low_s)

es_expected = %ExpectedGrant{
  issuer: "https://issuer.example",
  audience: "https://render.example",
  evaluation_time: now,
  clock_skew: 60,
  bounds: %{}
}

{:ok, es_facts} =
  V3.verify_grant(es_compact, %TrustedIssuer{key_id: "kms-issuer-1", public_key: kms_public}, es_expected)

{es_facts.version, es_facts.grant_id, Es256.canonical_signature?(low_s)}
```

The value is `{3, "grant-es-001", true}`.

The `s` value's twin `n - s` verifies under plain ECDSA too, which is why the profile accepts only
the low one. `normalize_low_s/1` maps either twin to the low one, and assembly refuses the high
one:

```elixir
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
<<r::unsigned-big-256, s::unsigned-big-256>> = low_s
high_s = <<r::unsigned-big-256, n - s::unsigned-big-256>>

{Es256.normalize_low_s(high_s) == {:ok, low_s}, V3.assemble_compact(es_input, high_s), Es256.der_to_raw(raw)}
```

The value is `{true, {:error, :invalid}, {:error, :invalid}}`: `der_to_raw/1` also refuses input
that is not strict DER, such as an already-raw signature.

## Rotate issuer keys

Keep the issuer keys you trust in your own key ring, each with the window in which you accept it.
Read the grant's `kid` with `untrusted_key_locator/2`, which decodes only the protected header and
marks the result `trust: :not_evaluated`, and look it up in the ring. An unknown or retired `kid`
fails like any other rejection; a known one still has to verify under the key you selected.

```elixir
{next_public, next_private} = :crypto.generate_key(:eddsa, :ed25519)

key_ring = [
  %{kid: "issuer-2027-01", public_key: issuer_public, accept_from: 1_790_000_000, accept_until: 1_800_000_200},
  %{kid: "issuer-2027-07", public_key: next_public, accept_from: 1_800_000_000, accept_until: nil}
]

trusted_issuer = fn compact, at ->
  with {:ok, locator} <- V1.untrusted_key_locator(compact, %{}),
       %{public_key: key} <-
         Enum.find(key_ring, fn entry ->
           entry.kid == locator.kid and entry.accept_from <= at and
             (entry.accept_until == nil or at < entry.accept_until)
         end) do
    {:ok, %TrustedIssuer{key_id: locator.kid, public_key: key}}
  else
    _unknown_or_retired -> {:error, :invalid}
  end
end

verify_at = fn compact, at ->
  expected = %ExpectedGrant{issuer: "https://issuer.example", audience: "https://data.example", evaluation_time: at, clock_skew: 60, bounds: %{}}

  with {:ok, trusted} <- trusted_issuer.(compact, at),
       {:ok, facts} <- V1.verify_grant(compact, trusted, expected) do
    facts.grant_id
  end
end

next_grant = %{grant | key_id: "issuer-2027-07", grant_id: "grant-export-002"}
{:ok, next_input} = V1.grant_signing_input(next_grant, %{})
{:ok, next_compact} = V1.assemble_compact(next_input, ed25519_sign.(next_input.message, next_private))

{verify_at.(grant_compact, now), verify_at.(next_compact, now), verify_at.(grant_compact, now + 200)}
```

The value is `{"grant-export-001", "grant-export-002", {:error, :invalid}}`: during the overlap
both keys verify, and once the old key's window closes its grants fail.

Before a new Ed25519 key enters the ring, check it with
`BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1` and `torsion_free?/1`
([usage rule 17](../../usage-rules.md)); for a P-256 key, use `Es256.acceptable_public_key?/1`.
For archives that must stay verifiable across a rotation, sign a key transition; see
[Evidence](evidence.md).

## Nonce modes

`ExpectedRequest.nonce` takes one of two values, and the proof must agree with it exactly:

- `:not_required`: the proof carries no nonce (`nonce: nil`). A proof that carries one is
  rejected, so a holder cannot add a value the service did not ask for.
- `{:required, nonce}`: the service issued a challenge nonce, and the proof must carry exactly
  that value. Use it when you cannot bound replay with the invocation id alone, for example when
  the holder's clock is untrusted. Issue each nonce once, keep it until it is used or expires, and
  pass the one you issued, never one the client names.

The local-loopback profile always requires a nonce.

```elixir
nonce_proof = fn nonce ->
  proof = %{proof | proof_id: "proof-nonce-#{nonce || "none"}", nonce: nonce}
  {:ok, input} = V1.proof_signing_input(proof, %{})
  {:ok, compact} = V1.assemble_compact(input, ed25519_sign.(input.message, holder_private))
  %Credentials{grant: grant_compact, proof: compact}
end

nonce_expected = %ExpectedRequest{
  trusted_issuer: %TrustedIssuer{key_id: "issuer-2027-01", public_key: issuer_public},
  issuer: "https://issuer.example",
  audience: "https://data.example",
  method: "POST",
  target_uri: "https://data.example/exports",
  invocation_id: proof.invocation_id,
  operation: "export_dataset",
  cast_arguments: arguments,
  evaluation_time: now,
  clock_skew: 60,
  proof_max_age: 300,
  nonce: :not_required,
  bounds: %{}
}

verdict = fn credentials, nonce_mode ->
  case V1.check_envelope(credentials, %{nonce_expected | nonce: nonce_mode}) do
    {:ok, _facts} -> :verified
    {:error, :invalid} -> :rejected
  end
end

[
  verdict.(nonce_proof.(nil), :not_required),
  verdict.(nonce_proof.("challenge-7f3a"), {:required, "challenge-7f3a"}),
  verdict.(nonce_proof.("challenge-7f3a"), {:required, "challenge-0000"}),
  verdict.(nonce_proof.(nil), {:required, "challenge-7f3a"}),
  verdict.(nonce_proof.("challenge-7f3a"), :not_required)
]
```

The value is `[:verified, :verified, :rejected, :rejected, :rejected]`.

Time works the same way: the verifier reads no clock. `evaluation_time` is your clock in Unix
seconds, `clock_skew` (at most 60) tolerates clock differences, and `proof_max_age` (at most 300)
bounds how old a proof may be. A proof is accepted from `issued_at - clock_skew` until
`issued_at + proof_max_age + clock_skew`.

## Run every packaged corpus

The package ships every certified corpus in its `priv` directory, and
`BoundedAuthorityProtocol.Conformance.Cli.run/1` verifies one and returns the exit status: `0`
on complete agreement, `1` on any disagreement or integrity failure, `2` on a usage error. Run
all nine from your own project's test suite, or after each upgrade:

```elixir
alias BoundedAuthorityProtocol.Conformance.Cli

corpora = [
  "v1/corpus",
  "v2/corpus",
  "v3/corpus",
  "strict-ed25519",
  "producer-canonicality",
  "selector-float-zero",
  "application-profiles/local-loopback-http/v1",
  "attestation-profiles/role-attestation/v1",
  "attestation-profiles/content-assertion/v1"
]

report = Path.join(System.tmp_dir!(), "bap-conformance-report.json")

results =
  for corpus <- corpora do
    directory = Application.app_dir(:bounded_authority_protocol, Path.join("priv/conformance", corpus))
    status = Cli.run(["--corpus", directory, "--report", report])
    {corpus, status, report |> File.read!() |> JSON.decode!() |> Map.take(["agreement", "disagreed"])}
  end

File.rm(report)
Enum.map(results, fn {_corpus, status, summary} -> {status, summary} end) |> Enum.uniq()
```

The value is `[{0, %{"agreement" => true, "disagreed" => 0}}]`: every corpus agrees.

The report is canonical JSON with the fields `format`, `agreement`, `exit_status`, `total`,
`agreed`, `disagreed`, and `index_sha256_base64url`. From a shell, the same check is the
`bounded_authority_conformance` command (`mix escript.install hex bounded_authority_protocol`),
run once per corpus with `--corpus deps/bounded_authority_protocol/priv/conformance/<corpus>`.
Exit `0` is conformance evidence, not an authorization.
