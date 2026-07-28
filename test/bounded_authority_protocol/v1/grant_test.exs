defmodule BoundedAuthorityProtocol.V1.GrantTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @fixture_path Path.expand(
                  "../../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )

  test "bounded decode returns exact explicitly unverified grant data" do
    fixture = fixture!()

    assert {:ok, decoded} = V1.decode_grant(fixture["grant"]["compact"], %{})
    assert decoded.version == 1
    assert decoded.key_id == "issuer-2026-07"
    assert decoded.issuer == "https://issuer.example"
    assert decoded.grant_id == "grant-2026-07-27-001"
    assert decoded.audiences == ["consumer-instance-01"]
    assert decoded.issued_at == 1_735_689_600
    assert decoded.not_before == 1_735_689_500
    assert decoded.expires_at == 1_735_693_200
    assert byte_size(decoded.holder_thumbprint) == 32
    assert decoded.verification == :not_evaluated
  end

  test "bounded decode accepts the scalar JWT audience form" do
    fixture = fixture!()

    compact =
      replace_json(fixture["grant"]["compact"], 1, fn payload ->
        Map.put(payload, "aud", "consumer-instance-01")
      end)

    assert {:ok, decoded} = V1.decode_grant(compact, %{})
    assert decoded.audiences == ["consumer-instance-01"]
  end

  test "standalone raw grant verification returns exact redacted non-authorizing facts" do
    fixture = fixture!()

    assert {:ok, facts} =
             V1.verify_grant(
               fixture["grant"]["compact"],
               trusted_issuer(fixture),
               expected_grant(fixture)
             )

    expected = fixture["expected"]["grant_facts"]
    assert facts.version == expected["version"]
    assert facts.issuer == expected["issuer"]
    assert facts.grant_id == expected["grant_id"]
    assert facts.matched_audience == expected["matched_audience"]
    assert facts.issued_at == expected["issued_at"]
    assert facts.not_before == expected["not_before"]
    assert facts.expires_at == expected["expires_at"]
    assert facts.authorization == :not_evaluated

    assert Base.url_encode64(facts.issuer_key_fingerprint, padding: false) ==
             expected["issuer_key_fingerprint_base64url"]

    assert Base.url_encode64(facts.holder_thumbprint, padding: false) ==
             expected["holder_thumbprint_base64url"]

    assert inspect(facts) == "#BoundedAuthorityProtocol.V1.GrantFacts<redacted>"
  end

  test "all grant headers and claims are closed before verification" do
    fixture = fixture!()
    compact = fixture["grant"]["compact"]

    for invalid <- [
          replace_json(compact, 0, &Map.put(&1, "alg", "HS256")),
          replace_json(compact, 0, &Map.put(&1, "typ", "JWT")),
          replace_json(compact, 0, &Map.put(&1, "crit", ["alg"])),
          replace_json(compact, 1, &Map.put(&1, "v", 2)),
          replace_json(compact, 1, &Map.put(&1, "extra", true)),
          replace_json(compact, 1, &Map.put(&1, "aud", [])),
          replace_json(compact, 1, &Map.put(&1, "aud", 1)),
          replace_json(compact, 1, &Map.put(&1, "iss", "bad: space")),
          replace_json(compact, 1, &Map.put(&1, "jti", "bad: space")),
          replace_json(compact, 1, &Map.put(&1, "aud", ["bad: space"])),
          replace_json(compact, 1, &put_in(&1, ["cnf", "jkt"], "not-a-digest")),
          replace_json(compact, 1, &Map.put(&1, "operations", []))
        ] do
      assert {:error, :invalid} = V1.decode_grant(invalid, %{})
    end

    duplicate_payload =
      ~s({"v":1,"v":1,"iss":"https://issuer.example","jti":"g","aud":"a","iat":1,"nbf":1,"exp":2,"cnf":{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"operations":[{"name":"op","selectors":[{"kind":"all"}]}]})

    assert {:error, :invalid} =
             V1.decode_grant(replace_segment(compact, 1, duplicate_payload), %{})
  end

  test "issuer, key, audience, and every caller time boundary fail closed" do
    fixture = fixture!()
    compact = fixture["grant"]["compact"]
    issuer = trusted_issuer(fixture)
    expected = expected_grant(fixture)

    assert {:error, :invalid} =
             V1.verify_grant(compact, %{issuer | key_id: "other"}, expected)

    assert {:error, :invalid} =
             V1.verify_grant(
               compact,
               %{issuer | public_key: :binary.copy(<<0>>, 32)},
               expected
             )

    assert {:error, :invalid} =
             V1.verify_grant(compact, issuer, %{expected | issuer: "https://other.example"})

    assert {:error, :invalid} =
             V1.verify_grant(compact, issuer, %{expected | audience: "other"})

    assert {:ok, _facts} =
             V1.verify_grant(compact, issuer, %{expected | evaluation_time: 1_735_689_600})

    assert {:error, :invalid} =
             V1.verify_grant(compact, issuer, %{expected | evaluation_time: 1_735_693_205})
  end

  test "producer rejects incoherent signed times and exact semantic maxima plus one" do
    fixture = fixture!()
    grant = grant(fixture)

    assert {:ok, _input} =
             V1.grant_signing_input(%{grant | issued_at: grant.expires_at - 1}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(%{grant | issued_at: grant.expires_at}, %{})

    assert {:ok, _input} =
             V1.grant_signing_input(%{grant | not_before: grant.expires_at - 1}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(%{grant | not_before: grant.expires_at}, %{})

    assert {:ok, _input} =
             V1.grant_signing_input(%{grant | issuer: String.duplicate("a", 512)}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(%{grant | issuer: String.duplicate("a", 513)}, %{})

    audiences = Enum.map(1..64, &"audience-#{&1}")
    assert {:ok, _input} = V1.grant_signing_input(%{grant | audiences: audiences}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(%{grant | audiences: audiences ++ ["audience-65"]}, %{})

    operations =
      Enum.map(1..64, fn index ->
        struct!(Operation, name: "operation_#{index}", selectors: [:all])
      end)

    assert {:ok, _input} = V1.grant_signing_input(%{grant | operations: operations}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(
               %{
                 grant
                 | operations:
                     operations ++
                       [struct!(Operation, name: "operation_65", selectors: [:all])]
               },
               %{}
             )

    selectors = Enum.map(1..64, &{:equals, ["member_#{&1}"], {:integer, &1}})
    operation = struct!(Operation, name: "read_record", selectors: selectors)

    assert {:ok, _input} = V1.grant_signing_input(%{grant | operations: [operation]}, %{})

    assert {:error, :invalid} =
             V1.grant_signing_input(
               %{
                 grant
                 | operations: [
                     %{operation | selectors: selectors ++ [{:equals, ["overflow"], :null}]}
                   ]
               },
               %{}
             )
  end

  test "signed grant time cases freeze every inclusive and strict evaluation boundary" do
    fixture = fixture!()
    issuer = trusted_issuer(fixture)
    expected = expected_grant(fixture)

    for time_case <- fixture["grant_time_cases"] do
      result = V1.verify_grant(time_case["grant"]["compact"], issuer, expected)

      case time_case["expected_verdict"] do
        "valid" -> assert {:ok, _facts} = result
        "invalid" -> assert {:error, :invalid} = result
      end
    end
  end

  test "facts, decoded values, maps, and forged bounds are never credentials" do
    fixture = fixture!()
    {:ok, decoded} = V1.decode_grant(fixture["grant"]["compact"], %{})

    {:ok, facts} =
      V1.verify_grant(
        fixture["grant"]["compact"],
        trusted_issuer(fixture),
        expected_grant(fixture)
      )

    assert {:error, :invalid} =
             V1.verify_grant(decoded, trusted_issuer(fixture), expected_grant(fixture))

    assert {:error, :invalid} =
             V1.verify_grant(facts, trusted_issuer(fixture), expected_grant(fixture))

    assert {:error, :invalid} =
             V1.verify_grant(%{}, trusted_issuer(fixture), expected_grant(fixture))

    expected = expected_grant(fixture)

    assert {:error, :invalid} =
             V1.verify_grant(
               fixture["grant"]["compact"],
               trusted_issuer(fixture),
               %{expected | bounds: %{compact_bytes: 65_537}}
             )
  end

  defp trusted_issuer(fixture) do
    context = fixture["expected_context"]["trusted_issuer"]

    struct!(TrustedIssuer,
      key_id: context["key_id"],
      public_key: Base.url_decode64!(context["public_key_base64url"], padding: false)
    )
  end

  defp expected_grant(fixture) do
    context = fixture["expected_context"]

    struct!(ExpectedGrant,
      issuer: context["issuer"],
      audience: context["audience"],
      evaluation_time: context["evaluation_time"],
      clock_skew: context["clock_skew"],
      bounds: Bounds.maximum()
    )
  end

  defp grant(fixture) do
    payload = fixture["grant"]["payload"]

    operation =
      struct!(Operation,
        name: "read_record",
        selectors: [:all]
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

  defp replace_json(compact, index, update) do
    [protected, payload, signature] = String.split(compact, ".")
    segments = [protected, payload, signature]
    json = segments |> Enum.at(index) |> Base.url_decode64!(padding: false) |> :json.decode()
    replace_segment(compact, index, update.(json) |> :json.encode() |> IO.iodata_to_binary())
  end

  defp replace_segment(compact, index, json) do
    compact
    |> String.split(".")
    |> List.replace_at(index, Base.url_encode64(json, padding: false))
    |> Enum.join(".")
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
