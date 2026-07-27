defmodule BoundedAuthorityProtocol.V1.CompactJwsTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V1.Proof

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "grant producer returns the exact standard RFC 7515 signing input" do
    fixture = fixture!()

    assert {:ok, signing_input} = V1.grant_signing_input(grant(fixture), %{})
    assert signing_input.kind == :grant
    assert signing_input.protected_segment == fixture["grant"]["protected_segment"]
    assert signing_input.payload_segment == fixture["grant"]["payload_segment"]
    assert signing_input.message == fixture["grant"]["signing_input"]
    refute String.starts_with?(signing_input.message, "BAP1-GRANT")

    assert signing_input.message ==
             signing_input.protected_segment <> "." <> signing_input.payload_segment
  end

  test "proof producer returns the exact standard RFC 7515 signing input" do
    fixture = fixture!()

    assert {:ok, signing_input} = V1.proof_signing_input(proof(fixture), %{})
    assert signing_input.kind == :proof
    assert signing_input.protected_segment == fixture["proof"]["protected_segment"]
    assert signing_input.payload_segment == fixture["proof"]["payload_segment"]
    assert signing_input.message == fixture["proof"]["signing_input"]
    refute String.starts_with?(signing_input.message, "BAP1-PROOF")
  end

  test "assembly accepts only a validated signing input and exactly 64 signature bytes" do
    fixture = fixture!()
    {:ok, signing_input} = V1.grant_signing_input(grant(fixture), %{})
    signature = Base.url_decode64!(fixture["grant"]["signature_base64url"], padding: false)

    assert {:ok, compact} = V1.assemble_compact(signing_input, signature)
    assert compact == fixture["grant"]["compact"]

    assert {:error, :invalid} = V1.assemble_compact(signing_input, binary_part(signature, 0, 63))
    assert {:error, :invalid} = V1.assemble_compact(signing_input, signature <> <<0>>)
    assert {:error, :invalid} = V1.assemble_compact(%{}, signature)
  end

  test "forged signing-input fields are revalidated" do
    fixture = fixture!()
    {:ok, signing_input} = V1.grant_signing_input(grant(fixture), %{})
    signature = Base.url_decode64!(fixture["grant"]["signature_base64url"], padding: false)

    assert {:error, :invalid} =
             V1.assemble_compact(%{signing_input | message: <<"forged">>}, signature)

    assert {:error, :invalid} =
             V1.assemble_compact(%{signing_input | kind: :proof}, signature)
  end

  defp grant(fixture) do
    payload = fixture["grant"]["payload"]

    operation =
      struct!(Operation,
        name: "read_record",
        selectors: [
          {:equals, ["record", "region"], {:string, "us-east"}},
          {:one_of, ["record", "tier"], [{:string, "gold"}, {:string, "platinum"}]},
          :all
        ]
      )

    struct!(Grant,
      key_id: fixture["grant"]["header"]["kid"],
      issuer: payload["iss"],
      grant_id: payload["jti"],
      audiences: payload["aud"],
      issued_at: payload["iat"],
      not_before: payload["nbf"],
      expires_at: payload["exp"],
      holder_thumbprint: Base.url_decode64!(payload["cnf"]["jkt"], padding: false),
      operations: [operation]
    )
  end

  defp proof(fixture) do
    payload = fixture["proof"]["payload"]

    struct!(Proof,
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
    )
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
