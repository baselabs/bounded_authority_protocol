defmodule BoundedAuthorityProtocol.V2.FacadeTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.TrustedIssuer
  alias BoundedAuthorityProtocol.V2

  @issuer_key_id "issuer-a"
  @issuer "https://issuer.example.test"
  @audience "https://resource.example.test"

  test "every facade function rejects malformed input through its delegate" do
    for {result} <- [
          {V2.grant_signing_input(:not_a_grant, %{})},
          {V2.proof_signing_input(:not_a_proof, %{})},
          {V2.encode_consumption_entry(:not_an_entry, %{})},
          {V2.check_chain(:not_an_input, :not_expected)},
          {V2.boundary_anchor_signing_input(:not_an_anchor, %{})},
          {V2.key_transition_signing_input(:not_a_transition, %{})},
          {V2.encode_anchored_export(:not_an_input, :not_expected)},
          {V2.assemble_compact(:not_an_input, <<0::512>>)},
          {V2.assemble_compact(:not_an_input, <<0::512>>, %{})},
          {V2.decode_grant(:not_binary, %{})},
          {V2.decode_proof(:not_binary, %{})},
          {V2.verify_anchored_export(:not_archived, :not_keys, :not_expected)},
          {V2.request_digest(:not_binary, :null, %{})},
          {V2.untrusted_key_locator(:not_binary, %{})},
          {V2.untrusted_key_locator(:not_binary)}
        ] do
      assert {:error, :invalid} = result
    end

    assert {:error, :invalid} =
             V2.verify_grant(:not_binary, :not_trusted, :not_expected)

    assert {:error, :invalid} =
             V2.verify_historical_anchor(:not_binary, :not_a_key, :not_expected)

    assert {:error, :invalid} =
             V2.verify_key_transition(:not_binary, :not_a_key, :not_a_key, :not_expected)

    assert {:error, :invalid} = V2.check_envelope(%{}, %{})
  end

  test "the facade happy path reaches every delegate with a well-formed call" do
    {compact, public} = signed_grant()
    holder_thumbprint = grant().holder_thumbprint

    assert {:ok, %BoundedAuthorityProtocol.V2.DecodedGrant{version: 2}} =
             V2.decode_grant(compact, %{})

    assert {:ok, %BoundedAuthorityProtocol.V1.KeyLocator{kid: @issuer_key_id}} =
             V2.untrusted_key_locator(compact)

    assert {:ok, %BoundedAuthorityProtocol.V2.GrantFacts{version: 2}} =
             V2.verify_grant(compact, trusted(public), expected_grant())

    {:ok, input} = V2.grant_signing_input(grant(), %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    assert {:ok, ^compact} = V2.assemble_compact(input, signature)
    assert {:ok, ^compact} = V2.assemble_compact(input, signature, %{})

    proof = %BoundedAuthorityProtocol.V2.Proof{
      holder_public_key: holder_public(),
      proof_id: "urn:example:proof:v2-facade",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      issued_at: 1_400,
      nonce: nil,
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      grant_compact: compact,
      cast_arguments: {:object, [{"amount", {:integer, 75}}]}
    }

    {:ok, proof_input} = V2.proof_signing_input(proof, %{})

    proof_signature =
      :crypto.sign(:eddsa, :ed25519, proof_input.message, [holder_private(), :ed25519])

    {:ok, proof_compact} = V2.assemble_compact(proof_input, proof_signature)

    assert {:ok, %BoundedAuthorityProtocol.V2.DecodedProof{version: 2}} =
             V2.decode_proof(proof_compact, %{})

    {:ok, digest} = V2.request_digest("transfer", {:object, [{"amount", {:integer, 75}}]}, %{})
    assert byte_size(digest) == 43

    expected = %ExpectedRequest{
      trusted_issuer: trusted(public),
      issuer: @issuer,
      audience: @audience,
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "transfer",
      cast_arguments: {:object, [{"amount", {:integer, 75}}]},
      evaluation_time: 1_500,
      clock_skew: 30,
      proof_max_age: 300,
      nonce: :not_required,
      bounds: %{}
    }

    assert {:ok, %BoundedAuthorityProtocol.V2.EnvelopeFacts{version: 2}} =
             V2.check_envelope(
               struct!(Credentials, grant: compact, proof: proof_compact),
               expected
             )

    assert is_binary(holder_thumbprint) and byte_size(holder_thumbprint) == 32
  end

  defp grant do
    {:ok, jwk} = Jwk.encode_public(holder_public(), %{})
    {:ok, thumbprint} = Jwk.thumbprint_raw(jwk, %{})

    %BoundedAuthorityProtocol.V2.Grant{
      key_id: @issuer_key_id,
      issuer: @issuer,
      grant_id: "urn:example:grant:v2-1",
      audiences: [@audience],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: thumbprint,
      operations: [
        %BoundedAuthorityProtocol.V2.Operation{
          name: "transfer",
          selectors: [
            {:gte, ["amount"], {:integer, 50}},
            {:lte, ["amount"], {:integer, 5000}}
          ]
        }
      ]
    }
  end

  defp signed_grant do
    {:ok, input} = V2.grant_signing_input(grant(), %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [issuer_private(), :ed25519])
    {:ok, compact} = V2.assemble_compact(input, signature)
    {compact, issuer_public()}
  end

  defp issuer_public, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<1::256>>), 0)
  defp issuer_private, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<1::256>>), 1)
  defp holder_public, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<2::256>>), 0)
  defp holder_private, do: elem(:crypto.generate_key(:eddsa, :ed25519, <<2::256>>), 1)

  defp trusted(public), do: %TrustedIssuer{key_id: @issuer_key_id, public_key: public}

  defp expected_grant do
    %ExpectedGrant{
      issuer: @issuer,
      audience: @audience,
      evaluation_time: 1_500,
      clock_skew: 30,
      bounds: %{}
    }
  end
end
