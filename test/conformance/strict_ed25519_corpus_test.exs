defmodule BoundedAuthorityProtocol.Conformance.StrictEd25519CorpusTest do
  @moduledoc """
  The additive strict-Ed25519 corpus (`bap-strict-ed25519/1`) runs through the conformance
  loader, runner and CLI, and every case matches its expected verdict.

  The corpus identity is pinned: the SHA-256 of the exact `index.json` bytes is asserted
  before any case runs, and the CLI carries the same pin. Every existing certified corpus index
  stays byte-identical, because the strict cases live only in this new corpus.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Cli
  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @moduletag timeout: 300_000

  @root Path.expand("../../priv/conformance/strict-ed25519", __DIR__)
  @index_sha256 "0cfae60706387c8436735fd0282c3b7bed270105f6ec57e654cf1ccf3c80180c"

  @families %{
    "anchored-export" => 16,
    "boundary-anchor" => 62,
    "ca1" => 31,
    "differential" => 1024,
    "envelope" => 122,
    "grant-verify" => 62,
    "jcs-utf8" => 82,
    "jwk" => 360,
    "key-acceptance" => 158,
    "key-transition" => 164,
    "loopback" => 31,
    "primitive" => 185,
    "ra1" => 82,
    "taming" => 12
  }

  # Every existing certified corpus index, by the SHA-256 of its exact bytes. The v1, v2 and v3
  # values are the CLI's certified pins; the sibling-profile values are the pins their own
  # corpus tests assert; the v1 vector manifest is pinned at its committed bytes.
  @existing_indexes [
    {"priv/conformance/v1/corpus/index.json",
     "4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b"},
    {"priv/conformance/v2/corpus/index.json",
     "6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0"},
    {"priv/conformance/v3/corpus/index.json",
     "a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c"},
    {"priv/conformance/v1/vectors/manifest.json",
     "a77fb4e20e945d612186fd0a4ed1473436b4beaad0af56f9c28837b5c32345bd"},
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

    {:ok, corpus} = Corpus.load_strict_ed25519(map)

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
    assert corpus.major == :strict_ed25519
    assert sha256(corpus.index_bytes) == @index_sha256
    assert corpus.index["total_cases"] == 2391
    assert corpus.index["families"] == @families
    assert length(results) == 2391

    observed = Enum.frequencies_by(results, & &1.family)
    assert observed == @families
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
    assert %Report{agreement: true, exit_status: 0, total: 2391, disagreed: 0} = report

    assert {:ok, bytes} = Report.to_bytes(corpus, results)
    assert bytes =~ ~s("format":"bounded-authority-protocol-strict-ed25519-conformance-report")
  end

  test "the CLI verifies the certified strict corpus and refuses a non-certified copy" do
    report = Path.join(tmp_dir("strict-cli-report"), "report.json")
    assert Cli.run(["--corpus", @root, "--report", report]) == 0
    assert File.read!(report) =~ ~s("agreement":true)

    # Insignificant index whitespace keeps the corpus self-consistent but changes its
    # identity, so the CLI pin alone must fail it closed.
    copy = tmp_dir("strict-cli-noncertified")
    File.cp_r!(@root, copy)
    index_path = Path.join(copy, "index.json")
    File.write!(index_path, File.read!(index_path) <> "\n")
    assert {:ok, _corpus} = copy |> read_corpus() |> Corpus.load_strict_ed25519()
    assert Cli.run(["--corpus", copy, "--report", Path.join(copy, "r.json")]) == 1
  end

  test "integrity: a flipped byte, a missing file, an extra file and a count drift fail closed",
       %{map: map} do
    path = "cases/primitive/verify-strict.json"
    bytes = Map.fetch!(map, path)
    <<first, rest::binary>> = bytes

    assert {:error, :invalid} =
             Corpus.load_strict_ed25519(
               Map.put(map, path, <<Bitwise.bxor(first, 1), rest::binary>>)
             )

    assert {:error, :invalid} = Corpus.load_strict_ed25519(Map.delete(map, path))
    assert {:error, :invalid} = Corpus.load_strict_ed25519(Map.put(map, "cases/extra.json", "{}"))
    assert {:error, :invalid} = Corpus.load_strict_ed25519(Map.delete(map, "profile.json"))

    drifted =
      String.replace(
        Map.fetch!(map, "index.json"),
        ~s("total_cases":2391),
        ~s("total_cases":2300)
      )

    assert drifted != Map.fetch!(map, "index.json")
    assert {:error, :invalid} = Corpus.load_strict_ed25519(Map.put(map, "index.json", drifted))

    # Each loader accepts only its own index format.
    assert {:error, :invalid} = Corpus.load(map)

    assert {:error, :invalid} =
             Corpus.load_strict_ed25519(read_corpus("priv/conformance/v1/corpus"))
  end

  test "a wrong expected verdict is a disagreement, not a pass", %{corpus: corpus} do
    flipped =
      Enum.map(corpus.cases, fn {path, cases} ->
        {path, Enum.map(cases, &flip_expectation/1)}
      end)

    results = Runner.run(%{corpus | cases: flipped})
    all = Enum.flat_map(results, &elem(&1, 1))
    assert length(all) == 2391
    assert Enum.all?(all, &(&1.agree == false))
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

  defp flip_expectation(%{"surface" => "content_assertion", "expected" => expected} = case_obj),
    do: %{case_obj | "expected" => Map.new(expected, fn {key, value} -> {key, flip(value)} end)}

  defp flip_expectation(%{"surface" => "local_loopback_http"} = case_obj),
    do: Map.update!(case_obj, "envelope_local", &(not &1))

  defp flip_expectation(%{"surface" => "role_attestation"} = case_obj),
    do: Map.update!(case_obj, "verify", &(not &1))

  defp flip("valid"), do: "invalid"
  defp flip("invalid"), do: "valid"

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
