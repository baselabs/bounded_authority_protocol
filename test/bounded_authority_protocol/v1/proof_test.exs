defmodule BoundedAuthorityProtocol.V1.ProofTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Proof

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "bounded proof decode returns exact explicitly unverified data" do
    fixture = fixture!()

    assert {:ok, decoded} = V1.decode_proof(fixture["proof"]["compact"], %{})
    assert decoded.version == 1
    assert decoded.proof_id == "proof-2026-07-27-001"
    assert decoded.method == "POST"
    assert decoded.target_uri == "https://api.example.test/invoke"
    assert decoded.issued_at == 1_735_689_660
    assert decoded.nonce == "challenge-001"
    assert decoded.invocation_id == "123e4567-e89b-42d3-a456-426614174000"
    assert decoded.operation == "read_record"
    assert byte_size(decoded.grant_hash) == 32
    assert byte_size(decoded.request_hash) == 32
    assert byte_size(decoded.holder_public_key) == 32
    assert byte_size(decoded.holder_thumbprint) == 32
    assert decoded.verification == :not_evaluated
  end

  test "proof header and claims reject algorithm confusion, smuggling, and private JWK data" do
    fixture = fixture!()
    compact = fixture["proof"]["compact"]

    for invalid <- [
          replace_json(compact, 0, &Map.put(&1, "alg", "ES256")),
          replace_json(compact, 0, &Map.put(&1, "typ", "JWT")),
          replace_json(compact, 0, &Map.put(&1, "kid", "holder")),
          replace_json(compact, 0, &put_in(&1, ["jwk", "d"], "AAAA")),
          replace_json(compact, 0, &put_in(&1, ["jwk", "crv"], "X25519")),
          replace_json(compact, 1, &Map.put(&1, "v", 2)),
          replace_json(compact, 1, &Map.put(&1, "extra", true)),
          replace_json(compact, 1, &Map.put(&1, "htm", "post")),
          replace_json(compact, 1, &Map.put(&1, "htu", "http://api.example.test/invoke")),
          replace_json(compact, 1, &Map.put(&1, "ath", "not-a-digest")),
          replace_json(compact, 1, &Map.put(&1, "ba_req", "not-a-digest"))
        ] do
      assert {:error, :invalid} = V1.decode_proof(invalid, %{})
    end
  end

  test "producer derives JWK, ath, and ba_req and accepts no precomputed digest field" do
    fixture = fixture!()

    assert {:ok, signing_input} = V1.proof_signing_input(proof(fixture), %{})

    payload =
      signing_input.payload_segment
      |> Base.url_decode64!(padding: false)
      |> :json.decode()

    assert payload["ath"] == fixture["grant"]["ath"]
    assert payload["ba_req"] == fixture["request"]["ba_req"]
    assert signing_input.protected_segment == fixture["proof"]["protected_segment"]
    assert signing_input.payload_segment == fixture["proof"]["payload_segment"]
  end

  test "proof semantic maxima accept exact values and reject maximum plus one" do
    fixture = fixture!()
    proof = proof(fixture)

    assert {:ok, _input} =
             V1.proof_signing_input(%{proof | nonce: String.duplicate("n", 512)}, %{})

    assert {:error, :invalid} =
             V1.proof_signing_input(%{proof | nonce: String.duplicate("n", 513)}, %{})

    assert {:ok, _input} =
             V1.proof_signing_input(%{proof | method: String.duplicate("A", 32)}, %{})

    assert {:error, :invalid} =
             V1.proof_signing_input(%{proof | method: String.duplicate("A", 33)}, %{})

    assert {:error, :invalid} =
             V1.proof_signing_input(
               %{proof | holder_public_key: proof.holder_public_key <> <<0>>},
               %{}
             )
  end

  test "malformed types and forged bounds return only the fixed error" do
    fixture = fixture!()

    assert {:error, :invalid} = V1.decode_proof(nil, %{})
    assert {:error, :invalid} = V1.decode_proof(fixture["proof"]["compact"], %{compact_bytes: 1})
    assert {:error, :invalid} = V1.proof_signing_input(%{}, %{})
    assert {:error, :invalid} = V1.proof_signing_input(proof(fixture), %{proof_max_age: 301})
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

  defp replace_json(compact, index, update) do
    segment = compact |> String.split(".") |> Enum.at(index)
    json = segment |> Base.url_decode64!(padding: false) |> :json.decode()

    compact
    |> String.split(".")
    |> List.replace_at(
      index,
      update.(json)
      |> :json.encode()
      |> IO.iodata_to_binary()
      |> Base.url_encode64(padding: false)
    )
    |> Enum.join(".")
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
