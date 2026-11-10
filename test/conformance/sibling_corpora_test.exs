defmodule BoundedAuthorityProtocol.Conformance.SiblingCorporaTest do
  @moduledoc """
  The CLI's loaders and runners for the three sibling-profile corpora (local-loopback HTTP, role
  attestation, content assertion): the shipped corpora load and agree in full; every case can
  disagree when its declared verdict is flipped; and every malformed index, file, case and
  override fails closed. Maps are edited in memory with their index digests recomputed, so each
  failure is the loader's or runner's own rule, not a hash mismatch.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @root "priv/conformance"
  @loopback "#{@root}/application-profiles/local-loopback-http/v1"
  @role "#{@root}/attestation-profiles/role-attestation/v1"
  @content "#{@root}/attestation-profiles/content-assertion/v1"

  defp corpus_map(dir) do
    for name <- File.ls!(dir), into: %{}, do: {name, File.read!(Path.join(dir, name))}
  end

  # Replace (or drop, with nil) one file and recompute its index digest.
  defp put_file(map, path, bytes) do
    index = :json.decode(map["index.json"])

    files =
      for %{"path" => p} = entry <- index["files"] do
        if p == path,
          do: %{entry | "sha256" => Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)},
          else: entry
      end

    map
    |> Map.put(path, bytes)
    |> Map.put("index.json", IO.iodata_to_binary(:json.encode(%{index | "files" => files})))
  end

  defp put_json(map, path, fun),
    do: put_file(map, path, IO.iodata_to_binary(:json.encode(fun.(:json.decode(map[path])))))

  defp put_index(map, fun),
    do:
      Map.put(
        map,
        "index.json",
        IO.iodata_to_binary(:json.encode(fun.(:json.decode(map["index.json"]))))
      )

  defp results(corpus), do: corpus |> Runner.run() |> Enum.flat_map(&elem(&1, 1))

  defp run_cases(corpus, path, cases), do: results(%{corpus | cases: [{path, cases}]})

  defp loaded(dir) do
    {:ok, corpus} = Corpus.load_any(corpus_map(dir))
    corpus
  end

  describe "the shipped sibling corpora" do
    for {dir, major, total} <- [
          {@loopback, :local_loopback_http, 46},
          {@role, :role_attestation, 40},
          {@content, :content_assertion, 154}
        ] do
      test "#{major} loads, runs every case and agrees completely" do
        corpus = loaded(unquote(dir))
        assert corpus.major == unquote(major)
        assert corpus.total_cases == unquote(total)
        runs = Runner.run(corpus)
        assert Enum.all?(Enum.flat_map(runs, &elem(&1, 1)), & &1.agree)

        assert %Report{agreement: true, exit_status: 0, total: unquote(total)} =
                 Report.build(corpus, runs)
      end
    end

    test "each loader accepts only its own corpus" do
      for {loader, own} <- [
            {&Corpus.load_local_loopback_http/1, @loopback},
            {&Corpus.load_role_attestation/1, @role},
            {&Corpus.load_content_assertion/1, @content}
          ],
          dir <- [@loopback, @role, @content] do
        assert match?({:ok, _corpus}, loader.(corpus_map(dir))) == (dir == own)
        assert loader.(:not_a_map) == {:error, :invalid}
      end
    end
  end

  describe "every case can disagree" do
    test "local-loopback: flipped URI and proof verdicts and a tampered certified proof" do
      corpus = loaded(@loopback)
      [{"profile.json", profile_cases}, {"proof-cases.json", proof_cases}] = corpus.cases

      flipped =
        Enum.map(profile_cases, fn
          %{"kind" => "uri"} = c -> %{c | "valid" => not c["valid"]}
          %{"kind" => "certified_proof"} = c -> %{c | "compact" => c["compact"] <> "A"}
        end)

      assert Enum.all?(run_cases(corpus, "profile.json", flipped), &(not &1.agree))

      flipped = Enum.map(proof_cases, &%{&1 | "decode_local" => not &1["decode_local"]})
      assert Enum.all?(run_cases(corpus, "proof-cases.json", flipped), &(not &1.agree))
    end

    test "role attestation: flipped decode and v1-grant verdicts" do
      corpus = loaded(@role)
      [{path, cases}] = corpus.cases
      flipped = Enum.map(cases, &%{&1 | "decode" => not &1["decode"]})
      assert Enum.all?(run_cases(corpus, path, flipped), &(not &1.agree))

      flipped = Enum.map(cases, &Map.put(&1, "v1_grant", not Map.get(&1, "v1_grant", false)))
      assert Enum.all?(run_cases(corpus, path, flipped), &(not &1.agree))
    end

    test "content assertion: flipped digest, decode and predecessor verdicts" do
      corpus = loaded(@content)

      flip = fn
        "valid" -> "invalid"
        "invalid" -> "valid"
      end

      for {path, cases} <- corpus.cases do
        flipped =
          Enum.map(cases, fn
            %{"kind" => "digest"} = c ->
              put_in(c, ["expected", "verdict"], flip.(c["expected"]["verdict"]))

            %{"kind" => "assertion"} = c ->
              put_in(c, ["expected", "decode"], flip.(c["expected"]["decode"]))

            %{"kind" => "successor"} = c ->
              put_in(c, ["expected", "predecessor"], flip.(c["expected"]["predecessor"]))
          end)

        assert Enum.all?(run_cases(corpus, path, flipped), &(not &1.agree)), path
      end
    end
  end

  test "declared paths are plain relative paths" do
    assert Corpus.declared_paths(~s({"files":[{"path":"a/b.json"}]})) == {:ok, ["a/b.json"]}
    assert Corpus.declared_paths(~s({"files":[{"path":"a\\u0000b.json"}]})) == {:error, :invalid}
    assert Corpus.declared_paths(:not_bytes) == {:error, :invalid}
  end

  describe "malformed sibling indexes and files fail closed" do
    test "index shape, file list and profile identity" do
      map = corpus_map(@loopback)

      for edit <- [
            &Map.put(&1, "extra", 1),
            &Map.put(&1, "revision", 2),
            &Map.put(&1, "files", "not-a-list"),
            &Map.update!(&1, "files", fn [first | rest] -> [Map.put(first, "x", 1) | rest] end),
            &Map.update!(&1, "files", fn files -> Enum.reverse(files) end)
          ] do
        assert Corpus.load_local_loopback_http(put_index(map, edit)) == {:error, :invalid}
      end

      assert Corpus.load_local_loopback_http(
               put_json(map, "profile.json", &Map.put(&1, "revision", 2))
             ) ==
               {:error, :invalid}

      assert Corpus.load_local_loopback_http(Map.put(map, "stray.json", "{}")) ==
               {:error, :invalid}
    end

    test "case files must be arrays of cases with ids, unique and counted" do
      map = corpus_map(@loopback)

      assert Corpus.load_local_loopback_http(put_file(map, "proof-cases.json", "{}")) ==
               {:error, :invalid}

      assert Corpus.load_local_loopback_http(
               put_json(map, "proof-cases.json", fn [first | rest] ->
                 [Map.delete(first, "id") | rest]
               end)
             ) == {:error, :invalid}

      assert Corpus.load_local_loopback_http(put_json(map, "proof-cases.json", &tl/1)) ==
               {:error, :invalid}

      assert Corpus.load_local_loopback_http(
               put_json(map, "proof-cases.json", fn [first, _second | rest] ->
                 [first, first | rest]
               end)
             ) == {:error, :invalid}

      role = corpus_map(@role)

      assert Corpus.load_role_attestation(put_json(role, "attestation-cases.json", &tl/1)) ==
               {:error, :invalid}
    end

    test "content assertion: private-material flag and the profile's bound content file" do
      map = corpus_map(@content)

      assert Corpus.load_content_assertion(
               put_index(map, &Map.put(&1, "private_material_tracked", true))
             ) ==
               {:error, :invalid}

      assert Corpus.load_content_assertion(
               put_json(
                 map,
                 "profile.json",
                 &put_in(&1, ["content", "sha256"], String.duplicate("0", 64))
               )
             ) == {:error, :invalid}

      assert Corpus.load_content_assertion(
               put_json(map, "profile.json", &Map.delete(&1, "content"))
             ) ==
               {:error, :invalid}
    end

    test "a certified-proof entry that is not an object becomes a disagreeing case" do
      map = put_json(corpus_map(@loopback), "profile.json", &put_in(&1, ["proofs", "broken"], 1))
      {:ok, corpus} = Corpus.load_local_loopback_http(map)
      broken = Enum.find(results(corpus), &(&1.case_id == "proofs/broken"))
      refute broken.agree
    end
  end

  describe "malformed sibling cases never agree" do
    test "local-loopback cases" do
      corpus = loaded(@loopback)
      [{_, [uri | _]}, {_, [proof | _]}] = corpus.cases

      for c <- [
            Map.delete(uri, "valid"),
            %{proof | "compact" => 1},
            Map.put(proof, "expected_overrides", %{"unknown" => 1}),
            Map.put(proof, "expected_overrides", %{"trusted_issuer_public_key" => "!"}),
            %{proof | "kind" => "unknown"}
          ] do
        assert [%{agree: false}] = run_cases(corpus, "p", [c])
      end
    end

    test "role-attestation cases" do
      corpus = loaded(@role)
      [{_, [c | _]}] = corpus.cases

      for c <- [
            %{c | "compact" => 1},
            Map.put(c, "expected_overrides", %{"unknown" => 1}),
            Map.put(c, "expected_overrides", "not-a-map")
          ] do
        assert [%{agree: false}] = run_cases(corpus, "p", [c])
      end
    end

    test "content-assertion cases" do
      corpus = loaded(@content)
      cases = Enum.flat_map(corpus.cases, &elem(&1, 1))
      digest = Enum.find(cases, &(&1["kind"] == "digest"))

      assertion =
        Enum.find(cases, &(&1["kind"] == "assertion" and &1["expected"]["decode"] == "valid"))

      successor = Enum.find(cases, &(&1["kind"] == "successor"))

      [header, payload, _signature] = String.split(assertion["compact"], ".")
      high_s = Base.url_encode64(:binary.copy(<<0xFF>>, 64), padding: false)

      for c <- [
            %{digest | "input" => %{}},
            %{digest | "input" => %{"content_file" => "missing.raw"}},
            %{digest | "input" => Map.put(digest["input"], "bounds", %{"unknown" => 1})},
            %{digest | "input" => Map.put(digest["input"], "bounds", "not-a-map")},
            %{assertion | "compact" => 1},
            Map.put(assertion, "attestor", "nobody"),
            Map.put(assertion, "legacy_accepts", "not-a-list"),
            # Decodes (the signature is not checked at decode) but cannot be re-assembled: the
            # producer refuses a non-canonical signature.
            %{assertion | "compact" => Enum.join([header, payload, high_s], ".")},
            Map.put(successor, "bounds", "not-a-map"),
            %{successor | "predecessor" => Map.delete(successor["predecessor"], "compact")}
          ] do
        assert [%{agree: false}] = run_cases(corpus, "p", [c]),
               inspect(Map.take(c, ["id", "input"]))
      end
    end

    test "successor fact overrides are a closed set" do
      corpus = loaded(@content)
      cases = Enum.flat_map(corpus.cases, &elem(&1, 1))

      relation_case =
        Enum.find(cases, &(&1["kind"] == "successor" and &1["expected"]["relation"] == "valid"))

      for overrides <- [
            "not-a-map",
            %{"unknown" => 1},
            %{"digest" => "!"},
            %{"trust" => "unknown"}
          ] do
        c = put_in(relation_case, ["successor", "facts_overrides"], overrides)
        assert [%{agree: false}] = run_cases(corpus, "p", [c]), inspect(overrides)
      end
    end
  end

  describe "the report requires the exact census" do
    setup do
      corpus = loaded(@role)
      {:ok, corpus: corpus, runs: Runner.run(corpus)}
    end

    test "complete results agree", %{corpus: corpus, runs: runs} do
      assert Corpus.complete?(corpus, runs)
      assert Report.build(corpus, runs).exit_status == 0
    end

    test "a dropped result fails", %{corpus: corpus, runs: [{path, [_dropped | rest]}]} do
      refute_complete(corpus, [{path, rest}])
    end

    test "a dropped result replaced by a duplicate fails",
         %{corpus: corpus, runs: [{path, [_dropped, second | rest]}]} do
      refute_complete(corpus, [{path, [second, second | rest]}])
    end

    test "a foreign case id fails", %{corpus: corpus, runs: [{path, [first | rest]}]} do
      refute_complete(corpus, [{path, [%{first | case_id: "foreign"} | rest]}])
    end

    test "a result under the wrong file fails", %{corpus: corpus, runs: [{_path, results}]} do
      refute_complete(corpus, [{"profile.json", results}])
    end

    test "an extra result fails", %{corpus: corpus, runs: [{path, results}]} do
      refute_complete(corpus, [{path, results}, {path, [hd(results)]}])
    end
  end

  defp refute_complete(corpus, runs) do
    refute Corpus.complete?(corpus, runs)
    report = Report.build(corpus, runs)
    assert report.agreement == false
    assert report.exit_status == 1
    # Every remaining result still agrees: completeness, not a verdict, fails the run.
    assert report.disagreed == 0
  end
end
