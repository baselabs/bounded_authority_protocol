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
        {kind <> Integer.to_string(version), inspect(value)}
      end

    actual =
      Map.merge(actual, %{
        "attestation" => inspect(attestation()),
        "content" => inspect(content())
      })

    assert actual == expected
  end

  test "wire fixtures match reference decoding and inspection for every row" do
    for row <- fixture!("decoded-wire-rendering.json") do
      major = Map.fetch!(Map.new(@majors), row["major"])

      result =
        case row["kind"] do
          "grant" -> major.decode_grant(row["compact"], %{})
          "proof" -> major.decode_proof(row["compact"], %{})
        end

      assert {:ok, decoded} = result
      assert inspect(decoded) == row["expected"]
    end
  end

  test "binary fixtures match reference inspection for every row" do
    for row <- fixture!("decoded-binary-rendering.json") do
      assert inspect(Base.decode16!(row["hex"], case: :mixed)) == row["expected"]
    end
  end

  test "every SDK carries byte-identical copies of every canonical fixture" do
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
