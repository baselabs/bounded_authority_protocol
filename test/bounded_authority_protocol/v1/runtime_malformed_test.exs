defmodule BoundedAuthorityProtocol.V1.RuntimeMalformedTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1

  alias BoundedAuthorityProtocol.V1.{
    Bounds,
    Credentials,
    ExpectedRequest,
    Grant,
    Operation,
    Proof,
    TrustedIssuer
  }

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "producer structs reject malformed container and selector shapes without raising" do
    fixture = fixture!()
    grant = grant(fixture)
    [operation] = grant.operations

    assert {:error, :invalid} = V1.grant_signing_input(%{}, %{})
    assert {:error, :invalid} = V1.decode_grant(nil, %{})
    assert {:error, :invalid} = V1.grant_signing_input(%{grant | audiences: :invalid}, %{})
    assert {:error, :invalid} = V1.grant_signing_input(%{grant | operations: :invalid}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(%{grant | operations: [operation | :invalid_tail]}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(
               %{grant | operations: [%{operation | selectors: [:invalid]}]},
               %{}
             )

    assert {:error, :invalid} =
             V1.grant_signing_input(
               %{grant | operations: [%{operation | selectors: [{:equals, :invalid, :null}]}]},
               %{}
             )

    proof = proof(fixture)
    assert {:ok, _input} = V1.proof_signing_input(%{proof | nonce: nil}, %{})
    assert {:error, :invalid} = V1.proof_signing_input(%{proof | invocation_id: "short"}, %{})
  end

  test "chain, anchor, transition, and archive public boundaries fail fixed on malformed terms" do
    assert {:error, :invalid} = V1.encode_consumption_entry(%{}, %{})
    assert {:error, :invalid} = V1.encode_consumption_entry(:invalid, %{})
    assert {:error, :invalid} = V1.check_chain(%{}, %{})
    assert {:error, :invalid} = V1.check_chain(:invalid, :invalid)
    assert {:error, :invalid} = V1.boundary_anchor_signing_input(%{}, %{})
    assert {:error, :invalid} = V1.key_transition_signing_input(%{}, %{})
    assert {:error, :invalid} = V1.encode_anchored_export(%{}, %{})
    assert {:error, :invalid} = V1.verify_historical_anchor(nil, %{}, %{})
    assert {:error, :invalid} = V1.verify_key_transition(nil, %{}, %{}, %{})
    assert {:error, :invalid} = V1.verify_anchored_export(%{}, %{}, %{})
  end

  test "bounded decoders reject malformed nested runtime shapes" do
    fixture = fixture!()
    grant = fixture["grant"]["compact"]
    proof = fixture["proof"]["compact"]

    invalid_grants = [
      replace_json(grant, 1, &Map.put(&1, "aud", [1])),
      replace_json(grant, 1, &Map.put(&1, "operations", [nil])),
      replace_json(grant, 1, fn payload ->
        put_in(payload, ["operations", Access.at(0), "selectors"], [nil])
      end),
      replace_json(grant, 1, fn payload ->
        put_in(payload, ["operations", Access.at(0), "selectors"], [%{"kind" => "bogus"}])
      end)
    ]

    Enum.each(invalid_grants, fn invalid ->
      assert {:error, :invalid} = V1.decode_grant(invalid, %{})
    end)

    assert {:error, :invalid} =
             proof
             |> replace_json(1, &Map.put(&1, "nonce", 1))
             |> V1.decode_proof(%{})
  end

  test "expected request rejects malformed UUID and nonce expectation shapes" do
    fixture = fixture!()

    credentials = %Credentials{
      grant: fixture["grant"]["compact"],
      proof: fixture["proof"]["compact"]
    }

    expected = expected_request(fixture)

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{expected | invocation_id: "short"})

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{expected | nonce: nil})
  end

  defp grant(fixture) do
    payload = fixture["grant"]["payload"]

    %Grant{
      key_id: fixture["grant"]["header"]["kid"],
      issuer: payload["iss"],
      grant_id: payload["jti"],
      audiences: payload["aud"],
      issued_at: payload["iat"],
      not_before: payload["nbf"],
      expires_at: payload["exp"],
      holder_thumbprint: Base.url_decode64!(payload["cnf"]["jkt"], padding: false),
      operations: [%Operation{name: "read_record", selectors: [:all]}]
    }
  end

  defp proof(fixture) do
    payload = fixture["proof"]["payload"]

    %Proof{
      holder_public_key:
        Base.url_decode64!(fixture["public_keys"]["holder"]["raw_base64url"], padding: false),
      proof_id: payload["jti"],
      method: payload["htm"],
      target_uri: payload["htu"],
      issued_at: payload["iat"],
      nonce: payload["nonce"],
      invocation_id: payload["ba_inv"],
      operation: payload["ba_op"],
      grant_compact: fixture["grant"]["compact"],
      cast_arguments: arguments()
    }
  end

  defp expected_request(fixture) do
    context = fixture["expected_context"]

    %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{
        key_id: context["trusted_issuer"]["key_id"],
        public_key:
          Base.url_decode64!(context["trusted_issuer"]["public_key_base64url"], padding: false)
      },
      issuer: context["issuer"],
      audience: context["audience"],
      method: context["method"],
      target_uri: context["target_uri"],
      invocation_id: context["invocation_id"],
      operation: context["operation"],
      cast_arguments: arguments(),
      evaluation_time: context["evaluation_time"],
      clock_skew: context["clock_skew"],
      proof_max_age: context["proof_max_age"],
      nonce: {:required, context["nonce"]["required"]},
      bounds: Bounds.maximum()
    }
  end

  defp arguments do
    {:object,
     [
       {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
       {"limit", {:integer, 10}}
     ]}
  end

  defp replace_json(compact, index, update) do
    compact
    |> String.split(".")
    |> List.update_at(index, fn segment ->
      segment
      |> Base.url_decode64!(padding: false)
      |> :json.decode()
      |> update.()
      |> :json.encode()
      |> IO.iodata_to_binary()
      |> Base.url_encode64(padding: false)
    end)
    |> Enum.join(".")
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
