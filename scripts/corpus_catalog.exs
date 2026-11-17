defmodule BoundedAuthorityProtocol.CorpusCatalog do
  @moduledoc false
  @root Path.expand("..", __DIR__)
  @cli "lib/bounded_authority_protocol/conformance/cli.ex"

  # Tooling metadata for the CLI's complete certification map. Both rotation gates consume
  # this catalog. Exact key-set equality below makes adding a CLI corpus without its tooling
  # metadata a failure; filesystem discovery also rejects an unregistered SDK snapshot.
  @entries [
    {1, "v1/corpus", "corpus", "run.py", "run.rs", "conformance/run_test.go"},
    {2, "v2/corpus", "corpus-v2", "run_v2.py", "run_v2.rs", "conformance/v2_test.go"},
    {3, "v3/corpus", "corpus-v3", "run_v3.py", "run_v3.rs", "conformance/v3_test.go"},
    {:strict_ed25519, "strict-ed25519", "corpus-strict", "run_strict.py", "run_strict.rs",
     "conformance/strict_test.go"},
    {:producer_canonicality, "producer-canonicality", "corpus-producer-canonicality",
     "run_producer_canonicality.py", "run_producer_canonicality.rs",
     "conformance/producer_canonicality_test.go"},
    {:selector_float_zero, "selector-float-zero", "corpus-selector-float-zero",
     "run_selector_float_zero.py", "run_selector_float_zero.rs",
     "conformance/selector_float_zero_test.go"},
    {:local_loopback_http, "application-profiles/local-loopback-http/v1", nil,
     "../test_local_loopback_http.py", "../tests/local_loopback_http.rs",
     "local_loopback_http_test.go"},
    {:role_attestation, "attestation-profiles/role-attestation/v1", nil,
     "../test_role_attestation.py", "../tests/role_attestation.rs", "role_attestation_test.go"},
    {:content_assertion, "attestation-profiles/content-assertion/v1", nil,
     "../test_content_assertion.py", "../tests/content_assertion.rs",
     "content_assertion_corpus_test.go"}
  ]

  @runner_pin ~r/(?m)^\s*(?:const\s+)?(?:_?CERTIFIED_INDEX_SHA(?:256)?|CONTENT_CORPUS_INDEX_SHA256|\w*[Cc]ertified\w*IndexSHA256)\b[^=\n]*=\s*"([^"]*)"/

  def root, do: @root
  def cli, do: @cli
  def runner_pin, do: @runner_pin

  def entries do
    pins = certified_pins()
    keys = Enum.map(@entries, &elem(&1, 0)) |> MapSet.new()

    if keys != MapSet.new(Map.keys(pins)),
      do: raise("corpus catalog differs from CLI certification map")

    Enum.map(@entries, fn {key, source, snapshot, python, rust, go} ->
      %{
        key: key,
        source: "priv/conformance/" <> source,
        snapshot: snapshot,
        certified: Map.fetch!(pins, key),
        runners: [
          Path.join("sdks/python/tests/conformance", python) |> Path.expand(@root),
          Path.join("sdks/rust/conformance", rust) |> Path.expand(@root),
          Path.join("sdks/go", go) |> Path.expand(@root)
        ]
      }
    end)
  end

  def snapshots do
    expected =
      for sdk <- Path.wildcard(Path.join(@root, "sdks/*/conformance")),
          entry <- entries(),
          entry.snapshot != nil do
        {Path.join(sdk, entry.snapshot), Path.join(@root, entry.source)}
      end

    observed = Path.wildcard(Path.join(@root, "sdks/*/conformance/corpus*"))
    known = MapSet.new(Enum.map(expected, &elem(&1, 0)))
    unknown = Enum.reject(observed, &MapSet.member?(known, &1))
    if unknown != [], do: raise("uncatalogued SDK snapshots: #{inspect(unknown)}")
    expected
  end

  def digests(entry) do
    digest = :crypto.hash(:sha256, File.read!(Path.join([@root, entry.source, "index.json"])))

    %{
      hex: Base.encode16(digest, case: :lower),
      base64url: Base.url_encode64(digest, padding: false)
    }
  end

  defp certified_pins do
    ast = @root |> Path.join(@cli) |> File.read!() |> Code.string_to_quoted!()

    {_, maps} =
      Macro.prewalk(ast, [], fn
        {:@, _, [{:certified_index_sha256, _, [{:%{}, _, pairs}]}]} = node, acc ->
          {node, [Map.new(pairs) | acc]}

        node, acc ->
          {node, acc}
      end)

    case maps do
      [pins] -> pins
      _ -> raise "expected one literal CLI certification map"
    end
  end
end
