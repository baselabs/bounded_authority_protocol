defmodule BoundedAuthorityProtocol.Conformance.GrantHolderProofVectorTest do
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)
  @script Path.join(@root, "conformance/bap03_independent.mjs")
  @fixture Path.join(@root, "priv/conformance/v1/vectors/grant-holder-proof.json")
  @manifest Path.join(@root, "priv/conformance/v1/vectors/manifest.json")

  test "independent Node verifier recomputes every public byte and verdict" do
    {output, 0} = run_node([])

    assert output =~ "bap03 independent verification: ok"

    assert output =~
             "vectors=3 public_key_fingerprints=9 tamper_cases=7 duplicate_cases=1 uri_cases=18"
  end

  test "fixture contains no private key or seed field" do
    fixture = json!(@fixture)
    keys = collect_keys(fixture)

    refute "d" in keys
    refute Enum.any?(keys, &String.contains?(&1, "private_key"))
    refute Enum.any?(keys, &String.contains?(&1, "seed"))
    assert fixture["provenance"]["private_material_tracked"] == false
  end

  test "manifest is an exact sorted set of independently derived fingerprints" do
    manifest = json!(@manifest)

    assert manifest["canonical_public_key_fingerprints"] == [
             "0qPOlfSr_giHdRaDK18shLtG5DoQL1a2nrHVDeWruJI",
             "B_luRLoL5T-YfqSCot-qLaUVewraSBu-qaEWqXfMRHI",
             "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk",
             "TolqHySkTC69-Y7DUVNJP7JPn31VXHfk37ytoM0MZXM",
             "b5dejonEMNbWuAUspTppNgiUa6QUXdzk40kdsDcWK6g",
             "gajR1zhnSjnHaH8LRAxglMF1t6aNiIRwljRrGC66UuI",
             "jNqoeV3u-yTgM-aDSbR90dRdNvOP0aD0J6_anyf0NRI",
             "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
             "ux6kGmd8C56UOZy4dXGjmqLHQO3PuOmQ5dg89lEO-Ag"
           ]

    assert manifest["canonical_public_key_fingerprints"] ==
             Enum.sort(Enum.uniq(manifest["canonical_public_key_fingerprints"]))

    assert manifest["verifier_public_key_fingerprints"] == %{
             "bap03_independent.mjs" => [
               "0qPOlfSr_giHdRaDK18shLtG5DoQL1a2nrHVDeWruJI",
               "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk",
               "b5dejonEMNbWuAUspTppNgiUa6QUXdzk40kdsDcWK6g",
               "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
             ],
             "chain_archive_independent.mjs" => [
               "B_luRLoL5T-YfqSCot-qLaUVewraSBu-qaEWqXfMRHI",
               "TolqHySkTC69-Y7DUVNJP7JPn31VXHfk37ytoM0MZXM",
               "gajR1zhnSjnHaH8LRAxglMF1t6aNiIRwljRrGC66UuI",
               "jNqoeV3u-yTgM-aDSbR90dRdNvOP0aD0J6_anyf0NRI",
               "ux6kGmd8C56UOZy4dXGjmqLHQO3PuOmQ5dg89lEO-Ag"
             ]
           }
  end

  test "removing a listed fingerprint fails while its keyed fixture remains reachable" do
    manifest = update_in(json!(@manifest), ["canonical_public_key_fingerprints"], &tl/1)

    with_temp_json(manifest, fn path ->
      {output, 1} = run_node(["--manifest", path])
      assert output =~ "manifest public-key fingerprint set mismatch"
    end)
  end

  test "adding an unreferenced fingerprint fails the opposite census direction" do
    manifest =
      update_in(
        json!(@manifest),
        ["canonical_public_key_fingerprints"],
        &(&1 ++ [String.duplicate("A", 43)])
      )

    with_temp_json(manifest, fn path ->
      {output, 1} = run_node(["--manifest", path])
      assert output =~ "manifest public-key fingerprint set mismatch"
    end)
  end

  test "removing a required discovery root cannot narrow the census" do
    manifest = update_in(json!(@manifest), ["discovery_roots"], &tl/1)

    with_temp_json(manifest, fn path ->
      {output, 1} = run_node(["--manifest", path])
      assert output =~ "manifest discovery roots mismatch"
    end)
  end

  test "moving a reached key to the other verifier fails import-boundary ownership" do
    manifest = json!(@manifest)
    [moved | retained] = manifest["verifier_public_key_fingerprints"]["bap03_independent.mjs"]

    manifest =
      manifest
      |> put_in(["verifier_public_key_fingerprints", "bap03_independent.mjs"], retained)
      |> update_in(
        ["verifier_public_key_fingerprints", "chain_archive_independent.mjs"],
        &Enum.sort([moved | &1])
      )

    with_temp_json(manifest, fn path ->
      {output, 1} = run_node(["--manifest", path])
      assert output =~ "manifest verifier import set mismatch"
    end)
  end

  test "alternate hex public-key representation cannot escape the census" do
    holder = json!(@fixture)["public_keys"]["holder"]["raw_base64url"]
    <<first, rest::binary>> = Base.url_decode64!(holder, padding: false)
    raw = <<Bitwise.bxor(first, 1), rest::binary>>

    with_temp_json(%{"verification_key" => Base.encode16(raw, case: :lower)}, fn path ->
      {output, 1} = run_node(["--scan", path])
      assert output =~ "declared/observed public-key set mismatch"
    end)
  end

  test "private key material under an alternate sk label fails closed" do
    holder = json!(@fixture)["public_keys"]["holder"]["raw_base64url"]

    with_temp_json(%{"sk" => holder}, fn path ->
      {output, 1} = run_node(["--scan", path])
      assert output =~ "private key material"
    end)
  end

  test "one exact-byte drift makes the independent verifier exit nonzero" do
    fixture =
      update_in(
        json!(@fixture),
        ["grant", "payload_segment"],
        &String.replace_suffix(&1, String.last(&1), "A")
      )

    with_temp_json(fixture, fn path ->
      {output, 1} = run_node(["--fixture", path])
      assert output =~ "grant payload bytes mismatch"
    end)
  end

  test "independent verifier imports no project code" do
    source = File.read!(@script)

    refute source =~ "BoundedAuthorityProtocol"
    refute source =~ ~r/from\s+["'][^"']*lib\//
    refute source =~ ~r/import\s+["'][^"']*mix/
    assert source =~ ~s(from "node:crypto")
  end

  defp run_node(arguments) do
    System.cmd("node", [@script | arguments], stderr_to_stdout: true)
  end

  defp with_temp_json(value, function) do
    path =
      Path.join(
        System.tmp_dir!(),
        "bap03-vector-#{System.unique_integer([:positive, :monotonic])}.json"
      )

    File.write!(path, :json.encode(value))

    try do
      function.(path)
    after
      File.rm(path)
    end
  end

  defp json!(path) do
    path
    |> File.read!()
    |> :json.decode()
  end

  defp collect_keys(value) when is_map(value) do
    Enum.flat_map(value, fn {key, child} -> [key | collect_keys(child)] end)
  end

  defp collect_keys(value) when is_list(value), do: Enum.flat_map(value, &collect_keys/1)
  defp collect_keys(_value), do: []
end
