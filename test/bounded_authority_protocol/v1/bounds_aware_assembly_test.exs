defmodule BoundedAuthorityProtocol.V1.BoundsAwareAssemblyTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V1.Proof

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "public bounds-aware assembly is byte-identical for every current-v1 signing kind" do
    for {kind, signing_input, signature} <- signing_cases() do
      assert {:ok, compact} = V1.assemble_compact(signing_input, signature)
      assert {:ok, ^compact} = V1.assemble_compact(signing_input, signature, %{}), inspect(kind)

      assert {:ok, ^compact} =
               V1.assemble_compact(signing_input, signature, Bounds.maximum()),
             inspect(kind)
    end
  end

  test "public bounds-aware assembly rejects every kind above tightened segment or compact bounds" do
    for {kind, signing_input, signature} <- signing_cases() do
      segment_limit =
        min(byte_size(signing_input.protected_segment), byte_size(signing_input.payload_segment)) -
          1

      assert {:error, :invalid} =
               V1.assemble_compact(signing_input, signature, %{
                 encoded_segment_bytes: segment_limit
               }),
             inspect({kind, :encoded_segment_bytes})

      assert {:ok, compact} = V1.assemble_compact(signing_input, signature)

      assert {:error, :invalid} =
               V1.assemble_compact(signing_input, signature, %{
                 compact_bytes: byte_size(compact) - 1
               }),
             inspect({kind, :compact_bytes})
    end
  end

  test "bounds-aware assembly does not activate successor-major delegated grants" do
    fixture = fixture!()
    {:ok, signing_input} = V1.grant_signing_input(grant(fixture), %{})
    signature = Base.url_decode64!(fixture["grant"]["signature_base64url"], padding: false)

    delegated_type =
      replace_signing_input_json(signing_input, :protected_segment, fn header ->
        Map.put(header, "typ", "ba+cap-delegated")
      end)

    delegated_claim =
      replace_signing_input_json(signing_input, :payload_segment, fn payload ->
        Map.put(
          payload,
          "ba_dlg",
          Base.url_encode64(:crypto.hash(:sha256, "parent"), padding: false)
        )
      end)

    for invalid <- [delegated_type, delegated_claim] do
      assert {:error, :invalid} = V1.assemble_compact(invalid, signature, %{})

      compact = invalid.message <> "." <> Base.url_encode64(signature, padding: false)
      assert {:error, :invalid} = V1.decode_grant(compact, %{})
    end
  end

  defp signing_cases do
    fixture = fixture!()
    {:ok, grant_input} = V1.grant_signing_input(grant(fixture), %{})
    {:ok, proof_input} = V1.proof_signing_input(proof(fixture), %{})

    {current_public, current_private} =
      :crypto.generate_key(:eddsa, :ed25519, <<1::unsigned-integer-size(256)>>)

    {next_public, _next_private} =
      :crypto.generate_key(:eddsa, :ed25519, <<2::unsigned-integer-size(256)>>)

    {:ok, anchor_input} =
      V1.boundary_anchor_signing_input(
        %BoundaryAnchor{
          anchor_id: "urn:example:anchor:bounds-aware",
          anchored_at: 1_700_000_000,
          chain_id: "urn:example:chain:bounds-aware",
          sequence: 0,
          chain_hash: <<0::256>>,
          key_id: "archive-key-a",
          public_key: current_public
        },
        %{}
      )

    {:ok, transition_input} =
      V1.key_transition_signing_input(
        %KeyTransition{
          transition_id: "urn:example:transition:bounds-aware",
          chain_id: "urn:example:chain:bounds-aware",
          effective_at: 1_700_000_100,
          current_key_id: "archive-key-a",
          current_public_key: current_public,
          next_key_id: "archive-key-b",
          next_public_key: next_public
        },
        %{}
      )

    [
      {:grant, grant_input,
       Base.url_decode64!(fixture["grant"]["signature_base64url"], padding: false)},
      {:proof, proof_input,
       Base.url_decode64!(fixture["proof"]["signature_base64url"], padding: false)},
      {:boundary_anchor, anchor_input,
       :crypto.sign(:eddsa, :none, anchor_input.message, [current_private, :ed25519])},
      {:key_transition, transition_input,
       :crypto.sign(:eddsa, :none, transition_input.message, [current_private, :ed25519])}
    ]
  end

  defp replace_signing_input_json(signing_input, field, transform) do
    segment = Map.fetch!(signing_input, field)

    replacement =
      segment
      |> Base.url_decode64!(padding: false)
      |> :json.decode()
      |> transform.()
      |> :json.encode()
      |> IO.iodata_to_binary()
      |> Base.url_encode64(padding: false)

    signing_input = Map.replace!(signing_input, field, replacement)

    %{
      signing_input
      | message: signing_input.protected_segment <> "." <> signing_input.payload_segment
    }
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
      operations: [
        %Operation{
          name: "read_record",
          selectors: [
            {:equals, ["record", "region"], {:string, "us-east"}},
            {:one_of, ["record", "tier"], [{:string, "gold"}, {:string, "platinum"}]},
            :all
          ]
        }
      ]
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
      cast_arguments:
        {:object,
         [
           {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
           {"limit", {:integer, 10}}
         ]}
    }
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
