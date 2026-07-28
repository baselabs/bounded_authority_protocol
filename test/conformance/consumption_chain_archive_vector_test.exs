defmodule BoundedAuthorityProtocol.Conformance.ConsumptionChainArchiveVectorTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.AnchoredExportFacts
  alias BoundedAuthorityProtocol.V1.ArchivedObject
  alias BoundedAuthorityProtocol.V1.ChainFacts
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedAnchoredExport
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.HistoricalKeyChain
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @root Path.expand("../..", __DIR__)
  @script Path.join(@root, "conformance/chain_archive_independent.mjs")
  @fixture Path.join(
             @root,
             "priv/conformance/v1/vectors/consumption-chain-archive.json"
           )
  @manifest Path.join(@root, "priv/conformance/v1/vectors/manifest.json")
  @semantic_fixture Path.join(
                      @root,
                      "priv/conformance/v1/vectors/chain-semantic-edge.json"
                    )

  test "independent Node verifier recomputes archives, rollover, census, and tamper verdicts" do
    assert {output, 0} = run_node(@fixture, @manifest)

    assert output =~
             "bap04 independent verification: ok archives=3 boundary_adversaries=2 " <>
               "chain_cases=2 public_key_fingerprints=11 tamper_cases=49 semantic_cases=7"
  end

  test "published verdict drift and valid opaque object-version mismatch fail independently" do
    fixture = fixture!()
    drifted = put_in(fixture, ["verdicts", "canonical_cases"], "invalid")

    with_temp_json(drifted, fn path ->
      assert {output, 1} = run_node(path, @manifest)
      assert output =~ "canonical-case verdict"
    end)

    archive = hd(fixture["archives"])

    facts_drift =
      put_in(
        fixture,
        ["archives", Access.at(0), "facts", "anchored_export", "row_count"],
        archive["chain"]["row_count"] + 1
      )

    with_temp_json(facts_drift, fn path ->
      assert {output, 1} = run_node(path, @manifest)
      assert output =~ "exact facts"
    end)

    assert {:error, :invalid} =
             V1.verify_anchored_export(
               %{archived(archive) | version: archive["object_version"] <> "-observed-drift"},
               historical_chain(archive),
               expected_archive(archive)
             )
  end

  test "independent verifier rejects duplicate outer corpus and manifest members" do
    fixture = File.read!(@fixture)

    duplicated_fixture =
      String.replace(
        fixture,
        ~s("format": "bounded-authority-protocol-v1-consumption-chain-archive"),
        ~s("format": "shadow", "format": "bounded-authority-protocol-v1-consumption-chain-archive"),
        global: false
      )

    with_temp_bytes(duplicated_fixture, fn path ->
      assert {output, 1} = run_node(path, @manifest)
      assert output =~ "duplicate JSON member format"
    end)

    manifest = File.read!(@manifest)

    duplicated_manifest =
      String.replace(
        manifest,
        ~s("format": "bounded-authority-protocol-v1-vector-manifest"),
        ~s("format": "shadow", "format": "bounded-authority-protocol-v1-vector-manifest"),
        global: false
      )

    with_temp_bytes(duplicated_manifest, fn path ->
      assert {output, 1} = run_node(@fixture, path)
      assert output =~ "duplicate JSON member format"
    end)
  end

  test "independent verifier rejects self-identifying Ed25519 private DER under an unknown label" do
    private_der =
      Base.encode64(
        <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22,
          0x04, 0x20, 0::256>>
      )

    fixture =
      fixture!()
      |> put_in(["provenance", "signing_material"], private_der)

    with_temp_json(fixture, fn path ->
      assert {output, 1} = run_node(path, @manifest)
      assert output =~ "private Ed25519 DER material"
    end)
  end

  test "signed semantic-edge fixture proves inclusive rollover and fail-closed genesis and chain identity" do
    fixture = json!(@semantic_fixture)
    valid = fixture["valid_same_id_equal_time_archive"]

    assert {:ok,
            %AnchoredExportFacts{
              end_anchored_at: 7000,
              transition_count: 1
            } = valid_facts} = verify_archive(valid)

    assert fact_json(valid_facts) == valid["facts"]["anchored_export"]

    cross = fixture["signed_cross_chain_archive"]
    [current, next] = historical_chain(cross).keys
    [transition] = cross["transitions"]

    assert {:ok, _facts} =
             V1.verify_key_transition(
               transition["compact"],
               current,
               next,
               expected_transition(transition)
             )

    assert {:error, :invalid} = verify_archive(cross)

    reverse = fixture["signed_reverse_time_archive"]
    [reverse_current, reverse_next] = historical_chain(reverse).keys
    [reverse_transition] = reverse["transitions"]

    assert {:ok, _facts} =
             V1.verify_historical_anchor(
               reverse["start_anchor"]["compact"],
               reverse_current,
               expected_anchor(reverse["start_anchor"])
             )

    assert {:ok, _facts} =
             V1.verify_key_transition(
               reverse_transition["compact"],
               reverse_current,
               reverse_next,
               expected_transition(reverse_transition)
             )

    assert {:ok, _facts} =
             V1.verify_historical_anchor(
               reverse["end_anchor"]["compact"],
               reverse_next,
               expected_anchor(reverse["end_anchor"])
             )

    assert {:error, :invalid} = verify_archive(reverse)

    invalid_anchor = fixture["signed_invalid_genesis_anchor"]
    key = historical_key(invalid_anchor["historical_key"])

    assert {:error, :invalid} =
             V1.verify_historical_anchor(
               invalid_anchor["anchor"]["compact"],
               key,
               expected_anchor(invalid_anchor["anchor"])
             )

    invalid_chain = fixture["invalid_genesis_chain"]

    assert {:error, :invalid} =
             V1.check_chain(
               %ChainInput{rows: Enum.map(invalid_chain["rows"], &b64!/1)},
               expected_chain(invalid_chain["expected"])
             )

    for name <- [
          "signed_transition_before_start_archive",
          "signed_transition_after_end_archive"
        ] do
      chronology = fixture[name]
      [current, next] = historical_chain(chronology).keys
      [transition] = chronology["transitions"]

      assert {:ok, _facts} =
               V1.verify_historical_anchor(
                 chronology["start_anchor"]["compact"],
                 current,
                 expected_anchor(chronology["start_anchor"])
               )

      assert {:ok, _facts} =
               V1.verify_key_transition(
                 transition["compact"],
                 current,
                 next,
                 expected_transition(transition)
               )

      assert {:ok, _facts} =
               V1.verify_historical_anchor(
                 chronology["end_anchor"]["compact"],
                 next,
                 expected_anchor(chronology["end_anchor"])
               )

      assert {:error, :invalid} = verify_archive(chronology)
    end
  end

  test "public fixture drives genesis, continuation, and every raw archive verifier path" do
    fixture = fixture!()

    for name <- ["genesis", "continuation"] do
      chain = fixture["chains"][name]

      assert {:ok, %ChainFacts{trust: :not_evaluated} = facts} =
               V1.check_chain(
                 %ChainInput{rows: Enum.map(chain["rows"], &b64!/1)},
                 expected_chain(chain["expected"])
               )

      assert fact_json(facts) == chain["facts"]
    end

    for archive <- fixture["archives"] ++ fixture["boundary_adversaries"] do
      keys = historical_chain(archive).keys

      assert {:ok, start_anchor_facts} =
               V1.verify_historical_anchor(
                 archive["start_anchor"]["compact"],
                 hd(keys),
                 expected_anchor(archive["start_anchor"])
               ),
             "#{archive["name"]} start anchor"

      transition_facts =
        archive["transitions"]
        |> Enum.zip(Enum.zip(keys, tl(keys)))
        |> Enum.map(fn {transition, {current, next}} ->
          assert {:ok, facts} =
                   V1.verify_key_transition(
                     transition["compact"],
                     current,
                     next,
                     expected_transition(transition)
                   ),
                 "#{archive["name"]} #{transition["transition_id"]}"

          facts
        end)

      assert {:ok, end_anchor_facts} =
               V1.verify_historical_anchor(
                 archive["end_anchor"]["compact"],
                 List.last(keys),
                 expected_anchor(archive["end_anchor"])
               ),
             "#{archive["name"]} end anchor"

      result = verify_archive(archive)

      assert match?(
               {:ok,
                %AnchoredExportFacts{
                  verification: :anchored_export,
                  trust: :not_evaluated,
                  authorization: :not_evaluated
                }},
               result
             ),
             archive["name"]

      {:ok, facts} = result

      assert inspect(facts) == "#BoundedAuthorityProtocol.V1.AnchoredExportFacts<redacted>"

      assert archive["facts"] == %{
               "chain" => expected_chain_fact_json(archive["chain"]),
               "start_anchor" => fact_json(start_anchor_facts),
               "transitions" => Enum.map(transition_facts, &fact_json/1),
               "end_anchor" => fact_json(end_anchor_facts),
               "anchored_export" => fact_json(facts)
             }
    end
  end

  test "separately signed shortened and relinked artifacts fail full caller boundaries" do
    fixture = fixture!()
    full_chain = expected_chain(fixture["chains"]["genesis"]["expected"])

    for archive <- fixture["boundary_adversaries"] do
      expected = expected_archive(archive)

      assert {:error, :invalid} =
               V1.verify_anchored_export(
                 archived(archive),
                 historical_chain(archive),
                 %{expected | chain: full_chain}
               )
    end
  end

  test "fixture contains no retained private key, seed, PEM, or DER material" do
    fixtures = [fixture!(), json!(@semantic_fixture)]
    keys = Enum.flat_map(fixtures, &collect_keys/1)
    source = File.read!(@fixture) <> File.read!(@semantic_fixture)

    refute "d" in keys
    refute "sk" in keys
    refute Enum.any?(keys, &String.contains?(&1, "private_key"))
    refute Enum.any?(keys, &String.contains?(&1, "seed"))
    refute source =~ "PRIVATE KEY"
    refute source =~ "BEGIN PRIVATE"
    refute Enum.any?(fixtures, &contains_ed25519_private_der?/1)
    assert Enum.all?(fixtures, &(&1["provenance"]["private_material_tracked"] == false))
  end

  test "manifest removal and unreachable addition each fail the independent census" do
    manifest = json!(@manifest)

    removed =
      update_in(manifest, ["canonical_public_key_fingerprints"], fn [_first | rest] -> rest end)

    with_temp_json(removed, fn path ->
      assert {output, 1} = run_node(@fixture, path)
      assert output =~ "manifest public-key fingerprint set mismatch"
    end)

    added =
      update_in(
        manifest,
        ["canonical_public_key_fingerprints"],
        &Enum.sort(&1 ++ [String.duplicate("A", 43)])
      )

    with_temp_json(added, fn path ->
      assert {output, 1} = run_node(@fixture, path)
      assert output =~ "manifest public-key fingerprint set mismatch"
    end)
  end

  test "moving a reached key to the other verifier fails import-boundary ownership" do
    manifest = json!(@manifest)

    [moved | retained] =
      manifest["verifier_public_key_fingerprints"]["chain_archive_independent.mjs"]

    manifest =
      manifest
      |> put_in(
        ["verifier_public_key_fingerprints", "chain_archive_independent.mjs"],
        retained
      )
      |> update_in(
        ["verifier_public_key_fingerprints", "bap03_independent.mjs"],
        &Enum.sort([moved | &1])
      )

    with_temp_json(manifest, fn path ->
      assert {output, 1} = run_node(@fixture, path)
      assert output =~ "manifest verifier import set mismatch"
    end)
  end

  test "independent verifier imports no project implementation" do
    source = File.read!(@script)

    refute source =~ "BoundedAuthorityProtocol"
    refute source =~ ~r/from\s+["'][^"']*lib\//
    refute source =~ ~r/import\s+["'][^"']*mix/
    assert source =~ ~s(from "node:crypto")
    assert source =~ "importedPublicKeyFingerprints.add"
  end

  defp verify_archive(archive) do
    V1.verify_anchored_export(
      archived(archive),
      historical_chain(archive),
      expected_archive(archive)
    )
  end

  defp archived(archive) do
    %ArchivedObject{
      chunks: split_archive(b64!(archive["archive_base64url"]), []),
      version: archive["object_version"]
    }
  end

  defp split_archive(<<>>, chunks), do: Enum.reverse(chunks)

  defp split_archive(bytes, chunks) do
    width = min(17, byte_size(bytes))
    <<chunk::binary-size(width), rest::binary>> = bytes
    split_archive(rest, [chunk | chunks])
  end

  defp expected_archive(archive) do
    %ExpectedAnchoredExport{
      chain: expected_chain(archive["chain"]),
      start_anchor: expected_anchor(archive["start_anchor"]),
      transitions: Enum.map(archive["transitions"], &expected_transition/1),
      end_anchor: expected_anchor(archive["end_anchor"]),
      digest: b64!(archive["archive_digest"]),
      object_version: archive["object_version"],
      bounds: %{}
    }
  end

  defp expected_chain(value) do
    %ExpectedChain{
      chain_id: value["chain_id"],
      first_sequence: value["first_sequence"],
      last_sequence: value["last_sequence"],
      row_count: value["row_count"],
      previous_hash: b64!(value["previous_hash"]),
      last_hash: b64!(value["last_hash"]),
      bounds: %{}
    }
  end

  defp expected_anchor(value) do
    %ExpectedAnchor{
      anchor_id: value["anchor_id"],
      anchored_at: value["anchored_at"],
      chain_id: value["chain_id"],
      sequence: value["sequence"],
      chain_hash: b64!(value["chain_hash"]),
      key_id: value["key_id"],
      key_fingerprint: b64!(value["key_fingerprint"]),
      bounds: %{}
    }
  end

  defp expected_transition(value) do
    %ExpectedKeyTransition{
      transition_id: value["transition_id"],
      chain_id: value["chain_id"],
      effective_at: value["effective_at"],
      current_key_id: value["current_key_id"],
      current_key_fingerprint: b64!(value["current_key_fingerprint"]),
      next_key_id: value["next_key_id"],
      next_key_fingerprint: b64!(value["next_key_fingerprint"]),
      bounds: %{}
    }
  end

  defp historical_chain(archive) do
    %HistoricalKeyChain{
      keys: Enum.map(archive["historical_keys"], &historical_key/1)
    }
  end

  defp historical_key(value) do
    %HistoricalPublicKey{
      key_id: value["key_id"],
      public_key: b64!(value["public_key"]),
      valid_from: value["valid_from"],
      valid_before:
        if(value["valid_before"] == :null, do: :unbounded, else: value["valid_before"])
    }
  end

  defp run_node(fixture, manifest) do
    System.cmd("node", [@script, fixture, manifest], stderr_to_stdout: true)
  end

  defp expected_chain_fact_json(chain) do
    %{
      "version" => 1,
      "chain_id" => chain["chain_id"],
      "first_sequence" => chain["first_sequence"],
      "last_sequence" => chain["last_sequence"],
      "row_count" => chain["row_count"],
      "previous_hash" => chain["previous_hash"],
      "last_hash" => chain["last_hash"],
      "verification" => "boundary_consistent",
      "trust" => "not_evaluated"
    }
  end

  @binary_fact_fields [
    :chain_hash,
    :current_key_fingerprint,
    :digest,
    :end_key_fingerprint,
    :key_fingerprint,
    :last_hash,
    :next_key_fingerprint,
    :previous_hash,
    :start_key_fingerprint
  ]

  defp fact_json(struct) do
    struct
    |> Map.from_struct()
    |> Map.new(fn {key, value} ->
      encoded =
        cond do
          key in @binary_fact_fields -> Base.url_encode64(value, padding: false)
          is_atom(value) -> Atom.to_string(value)
          true -> value
        end

      {Atom.to_string(key), encoded}
    end)
  end

  defp with_temp_json(value, function) do
    with_temp_bytes(:json.encode(value), function)
  end

  defp with_temp_bytes(bytes, function) do
    path =
      Path.join(
        System.tmp_dir!(),
        "bap04-vector-#{System.unique_integer([:positive, :monotonic])}.json"
      )

    File.write!(path, bytes)

    try do
      function.(path)
    after
      File.rm(path)
    end
  end

  defp fixture!, do: json!(@fixture)
  defp json!(path), do: path |> File.read!() |> :json.decode()
  defp b64!(value), do: Base.url_decode64!(value, padding: false)

  defp collect_keys(value) when is_map(value) do
    Enum.flat_map(value, fn {key, child} -> [key | collect_keys(child)] end)
  end

  defp collect_keys(value) when is_list(value), do: Enum.flat_map(value, &collect_keys/1)
  defp collect_keys(_value), do: []

  defp contains_ed25519_private_der?(value) when is_map(value),
    do: Enum.any?(value, fn {_key, child} -> contains_ed25519_private_der?(child) end)

  defp contains_ed25519_private_der?(value) when is_list(value) do
    encoded =
      if length(value) >= 48 and
           Enum.all?(value, &(is_integer(&1) and &1 >= 0 and &1 <= 255)) do
        [IO.iodata_to_binary(value)]
      else
        []
      end

    Enum.any?(encoded, &ed25519_private_der?/1) or
      Enum.any?(value, &contains_ed25519_private_der?/1)
  end

  defp contains_ed25519_private_der?(value) when is_binary(value) do
    candidates =
      []
      |> maybe_decode_hex(value)
      |> maybe_decode_base64(value)
      |> maybe_decode_base64url(value)

    Enum.any?(candidates, &ed25519_private_der?/1)
  end

  defp contains_ed25519_private_der?(_value), do: false

  defp maybe_decode_hex(candidates, value) do
    if byte_size(value) >= 96 and rem(byte_size(value), 2) == 0 and
         String.match?(value, ~r/\A[0-9A-Fa-f]+\z/) do
      [Base.decode16!(value, case: :mixed) | candidates]
    else
      candidates
    end
  end

  defp maybe_decode_base64(candidates, value) do
    if byte_size(value) >= 64 and rem(byte_size(value), 4) == 0 and
         String.match?(value, ~r/\A[A-Za-z0-9+\/]+={0,2}\z/) do
      case Base.decode64(value) do
        {:ok, decoded} -> [decoded | candidates]
        :error -> candidates
      end
    else
      candidates
    end
  end

  defp maybe_decode_base64url(candidates, value) do
    if byte_size(value) >= 64 and String.match?(value, ~r/\A[A-Za-z0-9_-]+\z/) do
      case Base.url_decode64(value, padding: false) do
        {:ok, decoded} -> [decoded | candidates]
        :error -> candidates
      end
    else
      candidates
    end
  end

  defp ed25519_private_der?(bytes) do
    oid = <<0x06, 0x03, 0x2B, 0x65, 0x70>>
    nested_private_octets = <<0x04, 0x22, 0x04, 0x20>>

    with true <- byte_size(bytes) >= 48,
         <<0x30, _rest::binary>> <- bytes,
         {oid_position, _} <- :binary.match(bytes, oid),
         {octets_position, _} <- :binary.match(bytes, nested_private_octets) do
      octets_position > oid_position
    else
      _failure -> false
    end
  end
end
