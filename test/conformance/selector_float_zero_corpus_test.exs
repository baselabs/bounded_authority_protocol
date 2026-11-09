defmodule BoundedAuthorityProtocol.Conformance.SelectorFloatZeroCorpusTest do
  @moduledoc """
  The additive selector float-zero corpus (`bap-selector-float-zero/1`, erratum 6) runs through
  the conformance loader, runner and CLI, and every case matches its expected verdict.

  Grant decode rejects an `equals` value or `one_of` member holding a float-tagged zero, on every
  contract-major; producers refuse every float-tagged integral selector value; range bounds keep
  their numeric comparison. The corpus identity is pinned here and in the CLI, and every existing
  certified corpus index stays byte-identical.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Cli
  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @root Path.expand("../../priv/conformance/selector-float-zero", __DIR__)
  @index_sha256 "97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003"
  @families %{"envelope" => 35, "grant-decode" => 78, "grant-signing-input" => 48}
  @total 161

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
    {"priv/conformance/producer-canonicality/index.json",
     "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601"},
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
    {:ok, corpus} = Corpus.load_selector_float_zero(map)

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
    assert corpus.major == :selector_float_zero
    assert corpus.index["total_cases"] == @total
    assert corpus.index["families"] == @families
    assert length(results) == @total
    assert Enum.frequencies_by(results, & &1.family) == @families

    cases = Enum.flat_map(corpus.cases, &elem(&1, 1))

    assert Enum.frequencies_by(cases, & &1["expected"]["verdict"]) == %{
             "invalid" => 98,
             "valid" => 63
           }

    assert Enum.frequencies_by(cases, & &1["major"]) == %{1 => 43, 2 => 59, 3 => 59}
  end

  for {family, count} <- @families do
    test "every #{family} case matches its expected verdict (#{count} cases)", %{results: results} do
      family_results = Enum.filter(results, &(&1.family == unquote(family)))
      assert length(family_results) == unquote(count)
      assert for(%{agree: false, case_id: id} <- family_results, do: id) == []
    end
  end

  test "the report agrees on every case", %{corpus: corpus} do
    results = Runner.run(corpus)
    assert %Report{agreement: true, exit_status: 0, total: @total} = Report.build(corpus, results)
    assert {:ok, bytes} = Report.to_bytes(corpus, results)

    assert bytes =~
             ~s("format":"bounded-authority-protocol-selector-float-zero-conformance-report")
  end

  test "the CLI verifies the certified corpus and refuses a non-certified copy" do
    report = Path.join(tmp_dir("float-zero-cli-report"), "report.json")
    assert Cli.run(["--corpus", @root, "--report", report]) == 0
    assert File.read!(report) =~ ~s("agreement":true)

    copy = tmp_dir("float-zero-cli-noncertified")
    File.cp_r!(@root, copy)
    index_path = Path.join(copy, "index.json")
    File.write!(index_path, File.read!(index_path) <> "\n")
    assert {:ok, _corpus} = copy |> read_corpus() |> Corpus.load_selector_float_zero()
    assert Cli.run(["--corpus", copy, "--report", Path.join(copy, "r.json")]) == 1
  end

  test "integrity: a flipped byte, a missing file and a foreign corpus fail closed", %{map: map} do
    path = "cases/grant-decode/major-1.json"
    <<first, rest::binary>> = Map.fetch!(map, path)
    flipped = Map.put(map, path, <<Bitwise.bxor(first, 1), rest::binary>>)

    assert {:error, :invalid} = Corpus.load_selector_float_zero(flipped)
    assert {:error, :invalid} = Corpus.load_selector_float_zero(Map.delete(map, path))
    assert {:error, :invalid} = Corpus.load_selector_float_zero(:not_a_map)
    assert {:error, :invalid} = Corpus.load(map)
    assert {:error, :invalid} = Corpus.load_producer_canonicality(map)

    assert {:error, :invalid} =
             Corpus.load_selector_float_zero(
               read_corpus("priv/conformance/producer-canonicality")
             )
  end

  test "a wrong expected verdict or an unknown major is a disagreement", %{corpus: corpus} do
    flipped =
      Enum.map(corpus.cases, fn {path, cases} -> {path, Enum.map(cases, &flip_expectation/1)} end)

    all = corpus |> Map.put(:cases, flipped) |> Runner.run() |> Enum.flat_map(&elem(&1, 1))
    assert length(all) == @total
    assert Enum.all?(all, &(&1.agree == false))

    {path, [case_obj | _]} = hd(corpus.cases)
    unknown = [Map.put(case_obj, "major", 4), Map.delete(case_obj, "major")]

    assert [{^path, [%{agree: false}, %{agree: false}]}] =
             Runner.run(%{corpus | cases: [{path, unknown}]})
  end

  test "malformed typed JSON text is a disagreement, never a pass", %{corpus: corpus} do
    cases = Enum.flat_map(corpus.cases, &elem(&1, 1))
    signing = Enum.find(cases, &match?(%{"input" => %{"operations_json" => _}}, &1))

    envelope =
      Enum.find(cases, &match?(%{"input" => %{"expected" => %{"cast_arguments_json" => _}}}, &1))

    broken = [
      put_in(signing, ["input", "operations_json"], "[{"),
      put_in(envelope, ["input", "expected", "cast_arguments_json"], "-0.0.0")
    ]

    for broken_case <- broken do
      flipped = put_in(broken_case, ["expected"], %{"verdict" => "invalid"})
      assert [{"p", [%{agree: false}]}] = Runner.run(%{corpus | cases: [{"p", [broken_case]}]})
      assert [{"p", [%{agree: false}]}] = Runner.run(%{corpus | cases: [{"p", [flipped]}]})
    end
  end

  test "every existing certified corpus index is byte-identical to its pin" do
    for {path, pin} <- @existing_indexes,
        do: assert(path |> File.read!() |> sha256() == pin, path)
  end

  defp flip_expectation(%{"expected" => %{"verdict" => "valid"}} = case_obj),
    do: put_in(case_obj, ["expected"], %{"verdict" => "invalid"})

  defp flip_expectation(%{"expected" => %{"verdict" => "invalid"}} = case_obj),
    do: put_in(case_obj, ["expected"], %{"verdict" => "valid", "key_id" => "issuer"})

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
