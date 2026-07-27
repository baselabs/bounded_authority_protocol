defmodule BoundedAuthorityProtocol.V1.EnvelopeTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "combined raw verification returns exact redacted non-authorizing envelope facts" do
    fixture = fixture!()

    assert {:ok, facts} =
             V1.check_envelope(credentials(fixture), expected_request(fixture))

    expected = fixture["expected"]["envelope_facts"]
    assert facts.version == expected["version"]
    assert facts.issuer == expected["issuer"]
    assert facts.grant_id == expected["grant_id"]
    assert facts.proof_id == expected["proof_id"]
    assert facts.matched_audience == expected["matched_audience"]
    assert facts.invocation_id == expected["invocation_id"]
    assert facts.operation == expected["operation"]
    assert facts.target_uri == expected["target_uri"]
    assert facts.issued_at == expected["issued_at"]
    assert facts.not_before == expected["not_before"]
    assert facts.expires_at == expected["expires_at"]
    assert facts.proof_issued_at == expected["proof_issued_at"]
    assert facts.authorization == :not_evaluated

    assert Base.url_encode64(facts.issuer_key_fingerprint, padding: false) ==
             expected["issuer_key_fingerprint_base64url"]

    assert Base.url_encode64(facts.holder_thumbprint, padding: false) ==
             expected["holder_thumbprint_base64url"]

    assert Base.url_encode64(facts.grant_hash, padding: false) ==
             expected["grant_hash_base64url"]

    assert Base.url_encode64(facts.request_hash, padding: false) ==
             expected["request_hash_base64url"]

    assert inspect(facts) == "#BoundedAuthorityProtocol.V1.EnvelopeFacts<redacted>"
  end

  test "meaningful protected, payload, and signature byte tampering fails closed" do
    fixture = fixture!()
    credentials = credentials(fixture)
    expected = expected_request(fixture)

    for tampered <- [
          %{credentials | grant: flip_segment(credentials.grant, 0)},
          %{credentials | grant: flip_segment(credentials.grant, 1)},
          %{credentials | grant: flip_segment(credentials.grant, 2)},
          %{credentials | proof: flip_segment(credentials.proof, 0)},
          %{credentials | proof: flip_segment(credentials.proof, 1)},
          %{credentials | proof: flip_segment(credentials.proof, 2)}
        ] do
      assert {:error, :invalid} = V1.check_envelope(tampered, expected)
    end
  end

  test "correctly signed received member-order variants remain valid" do
    fixture = fixture!()
    variant = fixture["received_member_order_variant"]

    credentials =
      struct!(Credentials,
        grant: variant["grant"]["compact"],
        proof: variant["proof"]["compact"]
      )

    assert {:ok, facts} = V1.check_envelope(credentials, expected_request(fixture))
    assert facts.grant_id == fixture["grant"]["payload"]["jti"]
    assert facts.proof_id == fixture["proof"]["payload"]["jti"]

    assert facts.grant_hash ==
             :crypto.hash(:sha256, variant["grant"]["compact"])
  end

  test "every server-derived request binding and nonce mode is exact" do
    fixture = fixture!()
    credentials = credentials(fixture)
    expected = expected_request(fixture)

    for invalid <- [
          %{expected | method: "GET"},
          %{expected | target_uri: "https://api.example.test/other"},
          %{expected | target_uri: "HTTP://api.example.test/invoke"},
          %{expected | invocation_id: "123e4567-e89b-42d3-a456-426614174001"},
          %{expected | operation: "write_record"},
          %{expected | cast_arguments: {:object, [{"limit", {:integer, 11}}]}},
          %{expected | nonce: :not_required},
          %{expected | nonce: {:required, "wrong"}},
          %{expected | clock_skew: 61},
          %{expected | proof_max_age: 301}
        ] do
      assert {:error, :invalid} = V1.check_envelope(credentials, invalid)
    end
  end

  test "correctly signed proof from a different holder fails the grant confirmation binding" do
    fixture = fixture!()

    credentials =
      struct!(Credentials,
        grant: fixture["grant"]["compact"],
        proof: fixture["negative_cases"]["wrong_holder"]["proof"]["compact"]
      )

    assert {:error, :invalid} =
             V1.check_envelope(credentials, expected_request(fixture))
  end

  test "correctly signed matching request digests still fail denied equals and one-of selectors" do
    fixture = fixture!()

    for {name, selector_case} <- fixture["negative_cases"]["selector_denied"] do
      credentials =
        struct!(Credentials,
          grant: fixture["grant"]["compact"],
          proof: selector_case["proof"]["compact"]
        )

      expected = %{
        expected_request(fixture)
        | cast_arguments: tagged(selector_case["typed_cast_arguments"])
      }

      assert {:error, :invalid} = V1.check_envelope(credentials, expected), name
    end
  end

  test "correctly signed nonce-absent proof is valid only when nonce is not required" do
    fixture = fixture!()

    credentials =
      struct!(Credentials,
        grant: fixture["grant"]["compact"],
        proof: fixture["positive_cases"]["nonce_absent"]["proof"]["compact"]
      )

    expected = %{expected_request(fixture) | nonce: :not_required}

    assert {:ok, facts} = V1.check_envelope(credentials, expected)
    assert facts.proof_id == "proof-2026-07-27-nonce-absent"

    assert {:error, :invalid} =
             V1.check_envelope(
               credentials,
               %{expected | nonce: {:required, fixture["expected_context"]["nonce"]["required"]}}
             )
  end

  test "proof age boundaries are inclusive and maximum plus one is invalid" do
    fixture = fixture!()
    credentials = credentials(fixture)
    expected = expected_request(fixture)

    earliest_now =
      fixture["proof"]["payload"]["iat"] + expected.proof_max_age + expected.clock_skew

    latest_now = fixture["proof"]["payload"]["iat"] - expected.clock_skew

    assert {:ok, _facts} =
             V1.check_envelope(credentials, %{expected | evaluation_time: earliest_now})

    assert {:ok, _facts} =
             V1.check_envelope(credentials, %{expected | evaluation_time: latest_now})

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{expected | evaluation_time: earliest_now + 1})

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{expected | evaluation_time: latest_now - 1})
  end

  test "facts and decoded intermediates are never accepted as credentials" do
    fixture = fixture!()
    expected_request = expected_request(fixture)
    trusted = expected_request.trusted_issuer

    expected_grant =
      struct!(ExpectedGrant,
        issuer: expected_request.issuer,
        audience: expected_request.audience,
        evaluation_time: expected_request.evaluation_time,
        clock_skew: expected_request.clock_skew,
        bounds: Bounds.maximum()
      )

    {:ok, grant_facts} =
      V1.verify_grant(fixture["grant"]["compact"], trusted, expected_grant)

    {:ok, decoded_grant} = V1.decode_grant(fixture["grant"]["compact"], %{})
    {:ok, decoded_proof} = V1.decode_proof(fixture["proof"]["compact"], %{})

    for invalid <- [
          %{},
          grant_facts,
          decoded_grant,
          decoded_proof,
          struct!(Credentials, grant: grant_facts, proof: fixture["proof"]["compact"]),
          struct!(Credentials, grant: fixture["grant"]["compact"], proof: decoded_proof)
        ] do
      assert {:error, :invalid} = V1.check_envelope(invalid, expected_request)
    end
  end

  test "forged expected structs cannot widen bounds or bypass field validation" do
    fixture = fixture!()
    credentials = credentials(fixture)
    expected = expected_request(fixture)

    for invalid <- [
          %{expected | trusted_issuer: %{expected.trusted_issuer | public_key: <<0>>}},
          %{expected | bounds: %{compact_bytes: 65_537}},
          %{expected | method: "post"},
          %{expected | target_uri: "https://API.example.test/invoke"},
          %{expected | invocation_id: String.upcase(expected.invocation_id)}
        ] do
      assert {:error, :invalid} = V1.check_envelope(credentials, invalid)
    end
  end

  defp credentials(fixture) do
    struct!(Credentials,
      grant: fixture["grant"]["compact"],
      proof: fixture["proof"]["compact"]
    )
  end

  defp expected_request(fixture) do
    context = fixture["expected_context"]

    trusted_issuer =
      struct!(TrustedIssuer,
        key_id: context["trusted_issuer"]["key_id"],
        public_key:
          Base.url_decode64!(context["trusted_issuer"]["public_key_base64url"], padding: false)
      )

    struct!(ExpectedRequest,
      trusted_issuer: trusted_issuer,
      issuer: context["issuer"],
      audience: context["audience"],
      method: context["method"],
      target_uri: context["target_uri"],
      invocation_id: context["invocation_id"],
      operation: context["operation"],
      cast_arguments:
        {:object,
         [
           {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
           {"limit", {:integer, 10}}
         ]},
      evaluation_time: context["evaluation_time"],
      clock_skew: context["clock_skew"],
      proof_max_age: context["proof_max_age"],
      nonce: {:required, context["nonce"]["required"]},
      bounds: Bounds.maximum()
    )
  end

  defp flip_segment(compact, index) do
    segments = String.split(compact, ".")
    segment = Enum.at(segments, index)
    <<first, rest::binary>> = segment
    replacement = if first == ?A, do: ?B, else: ?A
    List.replace_at(segments, index, <<replacement, rest::binary>>) |> Enum.join(".")
  end

  defp tagged(["null"]), do: :null
  defp tagged(["boolean", value]), do: {:boolean, value}
  defp tagged(["integer", value]), do: {:integer, value}
  defp tagged(["float", value]), do: {:float, value / 1}
  defp tagged(["string", value]), do: {:string, value}
  defp tagged(["array", values]), do: {:array, Enum.map(values, &tagged/1)}

  defp tagged(["object", members]) do
    {:object, Enum.map(members, fn {key, value} -> {key, tagged(value)} end)}
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
