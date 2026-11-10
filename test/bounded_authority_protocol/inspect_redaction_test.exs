defmodule BoundedAuthorityProtocol.InspectRedactionTest do
  @moduledoc false
  # Input and decoded structs that carry credentials never print compacts, typed arguments or
  # nonces through Inspect (logs, IEx, crash reports), on every contract-major and on the
  # sibling profiles that reuse them. The non-sensitive fields still render, so the output
  # stays useful when diagnosing a rejection.

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @grant "sentinel-grant-compact-AAAA.BBBB.CCCC"
  @proof "sentinel-proof-compact-DDDD.EEEE.FFFF"
  @nonce "sentinel-nonce-7f3a"
  @argument "sentinel-argument-9c1d"
  @arguments {:object, [{"recipient", {:string, @argument}}]}

  @secrets [@grant, @proof, @nonce, @argument]

  defp refute_secrets(rendered) do
    for secret <- @secrets do
      refute rendered =~ secret, "inspect/1 leaked #{inspect(secret)}: #{rendered}"
    end
  end

  test "credentials redact both compacts" do
    rendered = inspect(%Credentials{grant: @grant, proof: @proof})

    refute_secrets(rendered)

    assert rendered ==
             "#BoundedAuthorityProtocol.V1.Credentials<grant: :redacted, proof: :redacted>"
  end

  test "an expected request redacts typed arguments and a required nonce, and shows the rest" do
    expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer-key", public_key: <<1::256>>},
      issuer: "https://issuer.example",
      audience: "https://service.example",
      method: "POST",
      target_uri: "https://service.example/transfers",
      invocation_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
      operation: "transfer.create",
      cast_arguments: @arguments,
      evaluation_time: 1_700_000_000,
      clock_skew: 30,
      proof_max_age: 120,
      nonce: {:required, @nonce},
      bounds: %{}
    }

    rendered = inspect(expected)

    refute_secrets(rendered)
    assert rendered =~ ~s(method: "POST")
    assert rendered =~ ~s(operation: "transfer.create")
    assert rendered =~ "cast_arguments: :redacted"
    assert rendered =~ "nonce: {:required, :redacted}"

    assert inspect(%{expected | nonce: :not_required}) =~ "nonce: :not_required"
  end

  for major <- [
        BoundedAuthorityProtocol.V1,
        BoundedAuthorityProtocol.V2,
        BoundedAuthorityProtocol.V3
      ] do
    @major major

    test "#{inspect(major)} proof input redacts the grant compact, arguments and nonce" do
      proof =
        struct!(Module.concat(@major, Proof),
          holder_public_key: <<2::256>>,
          proof_id: "proof-1",
          method: "POST",
          target_uri: "https://service.example/transfers",
          issued_at: 1_700_000_000,
          nonce: @nonce,
          invocation_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
          operation: "transfer.create",
          grant_compact: @grant,
          cast_arguments: @arguments
        )

      rendered = inspect(proof)

      refute_secrets(rendered)
      assert rendered =~ ~s(proof_id: "proof-1")
      assert rendered =~ "grant_compact: :redacted"
      assert rendered =~ "nonce: :redacted"
      assert inspect(%{proof | nonce: nil}) =~ "nonce: nil"
    end

    test "#{inspect(major)} decoded proof redacts the nonce" do
      decoded =
        struct!(Module.concat(@major, DecodedProof),
          version: 1,
          proof_id: "proof-1",
          method: "POST",
          target_uri: "https://service.example/transfers",
          issued_at: 1_700_000_000,
          nonce: @nonce,
          invocation_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
          operation: "transfer.create",
          grant_hash: <<3::256>>,
          request_hash: <<4::256>>,
          holder_public_key: <<2::256>>,
          holder_thumbprint: <<5::256>>,
          verification: :not_evaluated
        )

      rendered = inspect(decoded)

      refute_secrets(rendered)
      assert rendered =~ ~s(operation: "transfer.create")
      assert rendered =~ "nonce: :redacted"
      assert inspect(%{decoded | nonce: nil}) =~ "nonce: nil"
    end
  end

  test "a signing input redacts its segments and message and shows its kind" do
    rendered =
      inspect(%SigningInput{
        kind: :grant,
        protected_segment: @grant,
        payload_segment: @proof,
        message: @grant <> "." <> @proof
      })

    refute_secrets(rendered)
    assert rendered =~ "kind: :grant"
  end

  test "the redaction holds inside nested structures and with custom inspect options" do
    rendered =
      inspect(%{credentials: %Credentials{grant: @grant, proof: @proof}},
        limit: :infinity,
        printable_limit: :infinity
      )

    refute_secrets(rendered)
  end
end
