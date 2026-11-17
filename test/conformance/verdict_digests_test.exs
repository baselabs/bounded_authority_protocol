Code.require_file("../../scripts/corpus_verdicts.exs", __DIR__)

defmodule BoundedAuthorityProtocol.Conformance.VerdictDigestsTest do
  use ExUnit.Case, async: true
  alias BoundedAuthorityProtocol.Conformance.{Corpus, Runner}
  alias BoundedAuthorityProtocol.{CorpusCatalog, CorpusVerdicts}

  test "all computed outcomes bind every certified ID in index order" do
    manifest = :json.decode(File.read!("priv/conformance/verdict-digests.json"))

    for entry <- CorpusCatalog.entries() do
      root = entry.source

      files =
        Map.new(Path.wildcard("#{root}/**/*") |> Enum.filter(&File.regular?/1), fn path ->
          {Path.relative_to(path, root), File.read!(path)}
        end)

      {:ok, corpus} = Corpus.load_any(files)
      computed = Runner.computed(corpus)
      assert length(computed) == MapSet.size(MapSet.new(computed, &elem(&1, 0)))
      results = Map.new(computed, fn {id, file, value} -> {id, {file, value}} end)
      cases = CorpusVerdicts.cases(root, :json.decode(files["index.json"]))
      assert map_size(results) == length(cases)

      pairs =
        Enum.map(cases, fn {path, case_obj} ->
          {^path, actual} = Map.fetch!(results, case_obj["id"])

          assert CorpusVerdicts.canonical(actual) ==
                   CorpusVerdicts.canonical(
                     CorpusVerdicts.outcome(
                       case_obj,
                       Path.relative_to(root, "priv/conformance"),
                       path
                     )
                   ),
                 case_obj["id"]

          [case_obj["id"], actual]
        end)

      key = Path.relative_to(root, "priv/conformance")

      assert CorpusVerdicts.digest(pairs) ==
               manifest["corpora"][key]["verdict_digest_sha256_base64url"],
             key
    end
  end

  test "the generated manifest rejects stale bytes and undeclared outcome shapes" do
    assert CorpusVerdicts.outcome(%{"expected" => nil}, "v1/corpus", "case.json") == nil
    expected = CorpusVerdicts.manifest()
    assert expected == File.read!("priv/conformance/verdict-digests.json")

    assert_raise RuntimeError, "case has neither expected nor a declared outcome schema", fn ->
      CorpusVerdicts.outcome(%{"id" => "unknown"}, "v1/corpus", "case.json")
    end

    assert_raise KeyError, fn ->
      CorpusVerdicts.outcome(
        %{"decode" => true},
        "attestation-profiles/role-attestation/v1",
        "attestation-cases.json"
      )
    end

    assert_raise RuntimeError, "invalid URI declares normalized", fn ->
      CorpusVerdicts.outcome(
        %{"valid" => false, "normalized" => "http://127.0.0.1:1/"},
        "application-profiles/local-loopback-http/v1",
        "profile.json"
      )
    end
  end

  test "computed content outcomes fail closed on missing content and malformed context" do
    root = "priv/conformance/attestation-profiles/content-assertion/v1"

    files =
      Map.new(Path.wildcard("#{root}/**/*") |> Enum.filter(&File.regular?/1), fn path ->
        {Path.relative_to(path, root), File.read!(path)}
      end)

    {:ok, corpus} = Corpus.load_any(files)

    cases = [
      %{
        "id" => "missing-content",
        "kind" => "digest",
        "input" => %{"content_file" => "missing.raw"}
      },
      %{"id" => "malformed-limits", "kind" => "assertion", "bounds" => false},
      %{
        "id" => "malformed-context",
        "kind" => "assertion",
        "expected_overrides" => false
      }
    ]

    assert Runner.computed(%{corpus | cases: [{"malformed.json", cases}]}) == [
             {"missing-content", "malformed.json", %{"verdict" => "invalid"}},
             {"malformed-limits", "malformed.json",
              %{"decode" => "invalid", "verify" => "invalid"}},
             {"malformed-context", "malformed.json",
              %{"decode" => "invalid", "verify" => "invalid"}}
           ]
  end

  test "computed producer outcomes fail closed on malformed assembly input" do
    root = "priv/conformance/producer-canonicality"

    files =
      Map.new(Path.wildcard("#{root}/**/*") |> Enum.filter(&File.regular?/1), fn path ->
        {Path.relative_to(path, root), File.read!(path)}
      end)

    {:ok, corpus} = Corpus.load_any(files)

    case_obj = %{
      "id" => "missing-protected-segment",
      "profile" => "bap-application-proof/local-loopback-http/1",
      "input" => %{"payload_segment" => "e30", "signature" => "AA"},
      "expected" => %{"verdict" => "valid"}
    }

    assert Runner.computed(%{corpus | cases: [{"malformed.json", [case_obj]}]}) == [
             {"missing-protected-segment", "malformed.json", %{"verdict" => "invalid"}}
           ]
  end
end
