defmodule BoundedAuthorityProtocol.Conformance.ProducerCanonicalityCorpusTest do
  @moduledoc """
  The additive producer-canonicality corpus (`bap-producer-canonicality/1`, erratum 3) runs
  through the conformance loader, runner and CLI, and every case matches its expected verdict.

  Compact assembly and anchored-export encoding are producer surfaces: they refuse a signature
  that no conforming signer emits (ES256 `r` or `s` out of range, or high-S; Ed25519 `S >= L`,
  or `R` non-canonical or of small order) and emit every accepted signature's bytes unchanged.

  The corpus identity is pinned: the SHA-256 of the exact `index.json` bytes is asserted before
  any case runs, and the CLI carries the same pin. Every existing certified corpus index stays
  byte-identical.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Cli
  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @root Path.expand("../../priv/conformance/producer-canonicality", __DIR__)
  @index_sha256 "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601"

  @families %{
    "ed25519-assemble" => 44,
    "ed25519-export-encode" => 4,
    "es256-assemble" => 24,
    "es256-export-encode" => 3
  }

  # Every existing certified corpus index, by the SHA-256 of its exact bytes.
  @existing_indexes [
    {"priv/conformance/v1/corpus/index.json",
     "4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b"},
    {"priv/conformance/v2/corpus/index.json",
     "6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0"},
    {"priv/conformance/v3/corpus/index.json",
     "a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c"},
    {"priv/conformance/v1/vectors/manifest.json",
     "a77fb4e20e945d612186fd0a4ed1473436b4beaad0af56f9c28837b5c32345bd"},
    {"priv/conformance/strict-ed25519/index.json",
     "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9"},
    {"priv/conformance/application-profiles/local-loopback-http/v1/index.json",
     "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4"},
    {"priv/conformance/attestation-profiles/role-attestation/v1/index.json",
     "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"},
    {"priv/conformance/attestation-profiles/content-assertion/v1/index.json",
     "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"}
  ]

  setup_all do
    map = read_corpus(@root)
    assert sha256(Map.fetch!(map, "index.json")) == @index_sha256

    {:ok, corpus} = Corpus.load_producer_canonicality(map)

    results =
      for {path, file_results} <- Runner.run(corpus),
          [_cases, family, _name] = String.split(path, "/"),
          result <- file_results,
          do: Map.put(result, :family, family)

    %{map: map, corpus: corpus, results: results}
  end

  test "the loaded corpus is the certified one and its counts match the index", %{
    corpus: corpus,
    results: results
  } do
    assert corpus.major == :producer_canonicality
    assert sha256(corpus.index_bytes) == @index_sha256
    assert corpus.index["total_cases"] == 75
    assert corpus.index["families"] == @families
    assert length(results) == 75
    assert Enum.frequencies_by(results, & &1.family) == @families

    verdicts =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.frequencies_by(& &1["expected"]["verdict"])

    assert verdicts == %{"invalid" => 60, "valid" => 15}
  end

  for {family, count} <- @families do
    @tag family: family
    test "every #{family} case matches its expected verdict (#{count} cases)", %{
      results: results
    } do
      family_results = Enum.filter(results, &(&1.family == unquote(family)))
      assert length(family_results) == unquote(count)
      disagreements = for %{agree: false, case_id: id} <- family_results, do: id
      assert disagreements == []
    end
  end

  test "the report agrees on every case", %{corpus: corpus} do
    results = Runner.run(corpus)
    report = Report.build(corpus, results)
    assert %Report{agreement: true, exit_status: 0, total: 75, disagreed: 0} = report

    assert {:ok, bytes} = Report.to_bytes(corpus, results)

    assert bytes =~
             ~s("format":"bounded-authority-protocol-producer-canonicality-conformance-report")
  end

  test "the CLI verifies the certified producer corpus and refuses a non-certified copy" do
    report = Path.join(tmp_dir("producer-cli-report"), "report.json")
    assert Cli.run(["--corpus", @root, "--report", report]) == 0
    assert File.read!(report) =~ ~s("agreement":true)

    copy = tmp_dir("producer-cli-noncertified")
    File.cp_r!(@root, copy)
    index_path = Path.join(copy, "index.json")
    File.write!(index_path, File.read!(index_path) <> "\n")
    assert {:ok, _corpus} = copy |> read_corpus() |> Corpus.load_producer_canonicality()
    assert Cli.run(["--corpus", copy, "--report", Path.join(copy, "r.json")]) == 1
  end

  test "integrity: a flipped byte, a missing file, an extra file and a count drift fail closed",
       %{map: map} do
    path = "cases/es256-assemble/assemble.json"
    <<first, rest::binary>> = Map.fetch!(map, path)

    assert {:error, :invalid} =
             Corpus.load_producer_canonicality(
               Map.put(map, path, <<Bitwise.bxor(first, 1), rest::binary>>)
             )

    assert {:error, :invalid} = Corpus.load_producer_canonicality(Map.delete(map, path))

    assert {:error, :invalid} =
             Corpus.load_producer_canonicality(Map.put(map, "cases/extra.json", "{}"))

    assert {:error, :invalid} = Corpus.load_producer_canonicality(Map.delete(map, "profile.json"))
    assert {:error, :invalid} = Corpus.load_producer_canonicality(:not_a_map)

    drifted =
      String.replace(Map.fetch!(map, "index.json"), ~s("total_cases":75), ~s("total_cases":74))

    assert drifted != Map.fetch!(map, "index.json")

    assert {:error, :invalid} =
             Corpus.load_producer_canonicality(Map.put(map, "index.json", drifted))

    # Each loader accepts only its own index format.
    assert {:error, :invalid} = Corpus.load(map)
    assert {:error, :invalid} = Corpus.load_strict_ed25519(map)

    assert {:error, :invalid} =
             Corpus.load_producer_canonicality(read_corpus("priv/conformance/strict-ed25519"))
  end

  test "a wrong expected verdict is a disagreement, not a pass", %{corpus: corpus} do
    flipped =
      Enum.map(corpus.cases, fn {path, cases} ->
        {path, Enum.map(cases, &flip_expectation/1)}
      end)

    all = corpus |> Map.put(:cases, flipped) |> Runner.run() |> Enum.flat_map(&elem(&1, 1))
    assert length(all) == 75
    assert Enum.all?(all, &(&1.agree == false))
  end

  test "a case naming no known major or profile is a disagreement", %{corpus: corpus} do
    # A valid case: an unknown major or profile returns the closed error, which disagrees.
    {path, case_obj} =
      Enum.find_value(corpus.cases, fn {path, cases} ->
        Enum.find_value(cases, &(&1["expected"]["verdict"] == "valid" and {path, &1}))
      end)

    unknown = [
      case_obj |> Map.delete("major") |> Map.put("profile", "bap-unknown/1"),
      case_obj |> Map.delete("major") |> Map.delete("profile"),
      case_obj |> Map.put("major", 4)
    ]

    results = Runner.run(%{corpus | cases: [{path, unknown}]})
    assert [{^path, [%{agree: false}, %{agree: false}, %{agree: false}]}] = results
  end

  test "the valid cases emit the signature bytes unchanged", %{corpus: corpus} do
    valid =
      for {_path, cases} <- corpus.cases,
          %{"expected" => %{"verdict" => "valid"}} = case_obj <- cases,
          do: case_obj

    assert length(valid) == 15

    for %{"input" => input, "expected" => %{"compact" => compact}} <- valid do
      assert compact ==
               input["protected_segment"] <>
                 "." <> input["payload_segment"] <> "." <> input["signature"]
    end
  end

  test "every existing certified corpus index is byte-identical to its pin" do
    for {path, pin} <- @existing_indexes do
      assert path |> File.read!() |> sha256() == pin, path
    end
  end

  # --- helpers ---------------------------------------------------------------------------

  defp flip_expectation(%{"expected" => %{"verdict" => "valid"} = expected} = case_obj),
    do: %{case_obj | "expected" => %{expected | "verdict" => "invalid"}}

  defp flip_expectation(%{"expected" => %{"verdict" => "invalid"} = expected} = case_obj),
    do: %{case_obj | "expected" => %{expected | "verdict" => "valid"}}

  defp read_corpus(root) do
    root
    |> Path.join("**/*")
    |> Path.wildcard()
    |> Enum.reject(&File.dir?/1)
    |> Map.new(&{Path.relative_to(&1, root), File.read!(&1)})
  end

  defp tmp_dir(label) do
    dir = Path.join(System.tmp_dir!(), "#{label}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end

  defp sha256(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
