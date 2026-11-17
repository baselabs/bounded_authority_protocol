defmodule BoundedAuthorityProtocol.SdkRenderingFixturesTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion
  alias BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation

  @root Path.expand("../..", __DIR__)
  @canonical Path.join(@root, "test/fixtures/sdk_rendering")
  @names ~w(decoded-rendering.json decoded-wire-rendering.json decoded-binary-rendering.json)
  @copies ~w(sdks/python/tests/fixtures sdks/rust/tests/fixtures sdks/go/testdata)
  @majors [
    {1, BoundedAuthorityProtocol.V1},
    {2, BoundedAuthorityProtocol.V2},
    {3, BoundedAuthorityProtocol.V3}
  ]

  test "constructed decoded fixtures match reference inspection for every row" do
    expected = fixture!("decoded-rendering.json")

    actual =
      for {version, major} <- @majors,
          {kind, value} <- [
            {"grant", grant(major, version)},
            {"proof", proof(major, version)}
          ],
          into: %{} do
        rendered = inspect(value)
        assert inspect(value, limit: 5, printable_limit: 0) == rendered
        {kind <> Integer.to_string(version), rendered}
      end

    actual =
      Map.merge(actual, %{
        "attestation" => inspect(attestation()),
        "content" => inspect(content()),
        "handbuilt:operation" =>
          BoundedAuthorityProtocol.DiagnosticRendering.render([
            %BoundedAuthorityProtocol.V1.Operation{name: %{}, selectors: 1}
          ])
      })

    floats =
      for {"float:" <> number = key, _expected} <- expected, into: %{} do
        {key, BoundedAuthorityProtocol.DiagnosticRendering.render(String.to_float(number))}
      end

    assert Map.merge(actual, floats) == expected
    assert inspect(attestation(), limit: 0) == expected["attestation"]
    assert inspect(content(), limit: 0) == expected["content"]
  end

  test "wire fixtures match reference decoding and inspection for every row" do
    rows = fixture!("decoded-wire-rendering.json")
    expected_pairs = for {version, _} <- @majors, kind <- ~w(grant proof), do: {version, kind}
    actual_pairs = Enum.map(rows, &{&1["major"], &1["kind"]})

    assert MapSet.new(actual_pairs) == MapSet.new(expected_pairs),
           "wire fixture must cover every major and kind"

    for row <- rows do
      major = Map.fetch!(Map.new(@majors), row["major"])

      result =
        case row["kind"] do
          "grant" -> major.decode_grant(row["compact"], %{})
          "proof" -> major.decode_proof(row["compact"], %{})
        end

      assert {:ok, decoded} = result
      assert inspect(decoded) == row["expected"]
      assert inspect(decoded, limit: 5) == row["expected"]

      assert inspect(decoded, limit: 0, printable_limit: 0, width: 1, pretty: true) ==
               row["expected"]
    end
  end

  test "binary fixtures match reference inspection for every row" do
    rows = fixture!("decoded-binary-rendering.json")
    assert is_list(rows) and rows != [], "binary fixture must be non-empty"

    for row <- rows do
      binary = Base.decode16!(row["hex"], case: :mixed)
      assert BoundedAuthorityProtocol.DiagnosticRendering.render(binary) == row["expected"]
    end
  end

  test "every SDK carries byte-identical copies of every canonical fixture" do
    assert Enum.sort(File.ls!(@canonical)) == Enum.sort(@names),
           "canonical directory must contain exactly the three fixture names"

    for directory <- @copies do
      names =
        @root
        |> Path.join(directory)
        |> Path.join("decoded-*rendering*.json")
        |> Path.wildcard()
        |> Enum.map(&Path.basename/1)

      assert Enum.sort(names) == Enum.sort(@names),
             "#{directory} must contain exactly the three rendering fixture names"
    end

    for name <- @names do
      refute File.exists?(Path.join([@root, "sdks", name]))
    end

    for name <- @names, directory <- @copies do
      path = Path.join([@root, directory, name])
      assert File.read(path) == {:ok, File.read!(Path.join(@canonical, name))}, path
    end
  end

  defp fixture!(name), do: @canonical |> Path.join(name) |> File.read!() |> Jason.decode!()

  defp grant(major, version) do
    struct!(Module.concat(major, DecodedGrant),
      version: version,
      key_id: "kid",
      issuer: "issuer",
      grant_id: "grant",
      audiences: ["aud"],
      issued_at: 1,
      not_before: 2,
      expires_at: 3,
      holder_thumbprint: <<0::256>>,
      operations: [struct!(Module.concat(major, Operation), name: "read", selectors: [:all])],
      verification: :not_evaluated
    )
  end

  defp proof(major, version) do
    struct!(Module.concat(major, DecodedProof),
      version: version,
      proof_id: "proof",
      method: "POST",
      target_uri: "https://example.test/",
      issued_at: 1,
      nonce: "hidden-nonce",
      invocation_id: "invocation",
      operation: "read",
      grant_hash: <<0::256>>,
      request_hash: <<0::256>>,
      holder_public_key: <<0::256>>,
      holder_thumbprint: <<0::256>>,
      verification: :not_evaluated
    )
  end

  defp attestation do
    %DecodedAttestation{
      version: 1,
      attestor_key_id: "attestor",
      jti: "jti",
      key_id: "subject",
      public_key: <<0::256>>,
      role: "issuer",
      nbf: 1,
      exp: 2,
      verification: :not_evaluated
    }
  end

  defp content do
    %DecodedContentAssertion{
      version: 1,
      attestor_key_id: "hidden-attestor",
      jti: "hidden-content",
      iss: "hidden-issuer",
      aud: "hidden-aud",
      sub: "hidden-sub",
      profile: "hidden-profile",
      profile_digest: <<0::256>>,
      content_digest: <<0::256>>,
      gen: 1,
      prev: <<0::256>>,
      iat: 1,
      nbf: 1,
      exp: 2,
      verification: :not_evaluated
    }
  end
end
