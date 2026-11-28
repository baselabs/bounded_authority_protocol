defmodule BoundedAuthorityProtocol.CorpusCatalog do
  @moduledoc false
  @root Path.expand("..", __DIR__)
  @cli "lib/bounded_authority_protocol/conformance/cli.ex"

  # Tooling metadata for the CLI's complete certification map. Both rotation gates consume
  # this catalog. Exact key-set equality below makes adding a CLI corpus without its tooling
  # metadata a failure; filesystem discovery also rejects an unregistered SDK snapshot.
  @entries [
    {1, "v1/corpus", "run.py", "run.rs", "conformance/run_test.go"},
    {2, "v2/corpus", "run_v2.py", "run_v2.rs", "conformance/v2_test.go"},
    {3, "v3/corpus", "run_v3.py", "run_v3.rs", "conformance/v3_test.go"},
    {:strict_ed25519, "strict-ed25519", "run_strict.py", "run_strict.rs",
     "conformance/strict_test.go"},
    {:string_or_uri, "string-or-uri", "run_strict.py", "run_strict.rs",
     "conformance/strict_test.go"},
    {:producer_canonicality, "producer-canonicality", "run_producer_canonicality.py",
     "run_producer_canonicality.rs", "conformance/producer_canonicality_test.go"},
    {:selector_float_zero, "selector-float-zero", "run_selector_float_zero.py",
     "run_selector_float_zero.rs", "conformance/selector_float_zero_test.go"},
    {:local_loopback_http, "application-profiles/local-loopback-http/v1",
     "../test_local_loopback_http.py", "../tests/local_loopback_http.rs",
     "local_loopback_http_test.go"},
    {:role_attestation, "attestation-profiles/role-attestation/v1", "../test_role_attestation.py",
     "../tests/role_attestation.rs", "role_attestation_test.go"},
    {:content_assertion, "attestation-profiles/content-assertion/v1",
     "../test_content_assertion.py", "../tests/content_assertion.rs",
     "content_assertion_corpus_test.go"},
    {:content_assertion_es256, "attestation-profiles/content-assertion-es256/v1", nil},
    {:holder_custody_attestation, "attestation-profiles/holder-custody-attestation/v1", nil},
    {:action_approval, "content-profiles/action-approval/v1", nil}
  ]

  @runner_pin ~r/(?m)^\s*(?:const\s+)?(?:_?CERTIFIED_INDEX_SHA(?:256)?|CONTENT_CORPUS_INDEX_SHA256|\w*[Cc]ertified\w*IndexSHA256)\b[^=\n]*=\s*"([^"]*)"/

  # Independently maintained certification evidence. Rotation must never edit these files.
  # A string key names a preservation artifact outside the CLI certification map.
  @preservation [
    {"test/bounded_authority_protocol/action_approval/corpus_test.exs",
     [{:action_approval, :hex, 1}, {:content_assertion_es256, :hex, 1}]},
    {"sdks/python/candidate/test_profiles.py",
     [{:action_approval, :hex, 1}, {:content_assertion_es256, :hex, 1}]},
    {"sdks/rust/conformance/run_approval.rs",
     [{:action_approval, :hex, 1}, {:content_assertion_es256, :hex, 1}]},
    {"sdks/go/action_approval_corpus_test.go", [{:action_approval, :hex, 1}]},
    {"sdks/go/content_assertion_es256_corpus_test.go", [{:content_assertion_es256, :hex, 1}]},
    {"scripts/check_role_attestation.exs", [{:role_attestation, :hex, 1}]},
    {"test/bounded_authority_protocol/application_profile/local_loopback_http/v1_test.exs",
     [{:local_loopback_http, :hex, 1}]},
    {"test/bounded_authority_protocol/content_assertion/corpus_test.exs",
     [{:content_assertion, :hex, 1}]},
    {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
     [{:role_attestation, :hex, 1}]},
    {"test/conformance/corpus_independent_test.exs",
     [{:strict_ed25519, :hex, 1}, {:selector_float_zero, :hex, 1}]},
    {"test/conformance/producer_canonicality_corpus_test.exs",
     [
       {:producer_canonicality, :hex, 1},
       {1, :hex, 1},
       {2, :hex, 1},
       {3, :hex, 1},
       {"priv/conformance/v1/vectors/manifest.json", :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:local_loopback_http, :hex, 1},
       {:role_attestation, :hex, 1},
       {:content_assertion, :hex, 1}
     ]},
    {"test/conformance/selector_float_zero_corpus_test.exs",
     [
       {:selector_float_zero, :hex, 1},
       {1, :hex, 1},
       {2, :hex, 1},
       {3, :hex, 1},
       {"priv/conformance/v1/vectors/manifest.json", :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:producer_canonicality, :hex, 1},
       {:local_loopback_http, :hex, 1},
       {:role_attestation, :hex, 1},
       {:content_assertion, :hex, 1}
     ]},
    {"test/conformance/strict_ed25519_corpus_test.exs",
     [
       {:strict_ed25519, :hex, 1},
       {1, :hex, 1},
       {2, :hex, 1},
       {3, :hex, 1},
       {"priv/conformance/v1/vectors/manifest.json", :hex, 1},
       {:local_loopback_http, :hex, 1},
       {:role_attestation, :hex, 1},
       {:content_assertion, :hex, 1}
     ]},
    {"conformance/corpus_independent.mjs", [{:selector_float_zero, :hex, 1}]}
  ]

  # Published explanations must match certification, but require an explicit editorial update.
  @prose [
    {"spec/bap-action-approval-v1.md", [{:action_approval, :hex, 1}]},
    {"spec/bap-content-assertion-es256-v1.md", [{:content_assertion_es256, :hex, 1}]},
    {"spec/bap-holder-custody-attestation-v1.md", [{:holder_custody_attestation, :hex, 1}]},
    # Released changelog sections record the digest each release certified; history is never
    # rewritten, so a rotation edits this entry, not the changelog.
    {"CHANGELOG.md",
     [
       {:selector_float_zero, :hex, 1},
       {:producer_canonicality, :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:content_assertion, :hex, 1},
       {2, :hex, 1},
       {:local_loopback_http, :hex, 1}
     ]},
    {"spec/bap-content-assertion-v1.md", [{:content_assertion, :hex, 1}]},
    {"spec/bap-local-loopback-http-v1.md", [{:local_loopback_http, :hex, 1}]},
    {"spec/bap-role-attestation-v1.md", [{:role_attestation, :hex, 1}]},
    {"spec/bap-v1.md", [{:strict_ed25519, :hex, 1}]},
    {"spec/bap-v2.md", [{:selector_float_zero, :hex, 1}, {:strict_ed25519, :hex, 1}]},
    {"spec/bap-v3.md", [{:producer_canonicality, :hex, 1}, {:selector_float_zero, :hex, 1}]},
    {"docs/design/conformance-contract.md",
     [{:strict_ed25519, :hex, 1}, {:producer_canonicality, :hex, 1}]},
    {"docs/design/content-assertion-requirement-map.md",
     [
       {:content_assertion, :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:producer_canonicality, :hex, 1}
     ]},
    {"docs/design/interoperability-report.md",
     [
       {1, :base64url, 1},
       {1, :hex, 1},
       {:local_loopback_http, :hex, 1},
       {2, :hex, 1},
       {3, :hex, 1},
       {:role_attestation, :hex, 1},
       {:content_assertion, :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:producer_canonicality, :hex, 1},
       {:selector_float_zero, :hex, 1}
     ]},
    {"docs/design/local-loopback-http-requirement-map.md",
     [{:strict_ed25519, :hex, 1}, {:producer_canonicality, :hex, 1}]},
    {"docs/design/requirement-map.md",
     [
       {:selector_float_zero, :hex, 7},
       {:producer_canonicality, :hex, 2},
       {:strict_ed25519, :hex, 1}
     ]},
    {"docs/design/role-attestation-requirement-map.md",
     [{:role_attestation, :hex, 1}, {:strict_ed25519, :hex, 1}, {:producer_canonicality, :hex, 1}]},
    {"docs/errata.md",
     [
       {:strict_ed25519, :hex, 1},
       {:producer_canonicality, :hex, 1},
       {:selector_float_zero, :hex, 1},
       {:string_or_uri, :hex, 1}
     ]},
    {"docs/guides/implementers-guide.md",
     [
       {:local_loopback_http, :hex, 1},
       {:role_attestation, :hex, 1},
       {:content_assertion, :hex, 1},
       {:strict_ed25519, :hex, 1},
       {:producer_canonicality, :hex, 1},
       {:selector_float_zero, :hex, 1}
     ]},
    {"docs/protocol-v1.md", [{:strict_ed25519, :hex, 1}]},
    {"sdks/README.md", [{:strict_ed25519, :hex, 1}]},
    {"sdks/go/conformance/selector_float_zero_test.go", [{:selector_float_zero, :hex, 1}]}
  ]

  def preservation, do: @preservation
  def prose, do: @prose
  def reference_files, do: Enum.map(@preservation ++ @prose, &elem(&1, 0))

  def reference_digest(key, encoding) when is_binary(key) do
    digest = :crypto.hash(:sha256, File.read!(Path.join(@root, key)))

    case encoding do
      :hex -> Base.encode16(digest, case: :lower)
      :base64url -> Base.url_encode64(digest, padding: false)
    end
  end

  def reference_digest(key, encoding) do
    entries() |> Enum.find(&(&1.key == key)) |> digests() |> Map.fetch!(encoding)
  end

  def root, do: @root
  def cli, do: @cli

  def runner_pin(:string_or_uri),
    do:
      ~r/(?m)^(?:const )?(?:STRING_OR_URI_INDEX_SHA256|stringOrURICorpusIndexSHA256)\b[^=\n]*=\s*"([^"]*)"/

  def runner_pin(_key), do: @runner_pin

  def entries do
    pins = certified_pins()
    keys = Enum.map(@entries, &elem(&1, 0)) |> MapSet.new()

    if keys != MapSet.new(Map.keys(pins)),
      do: raise("corpus catalog differs from CLI certification map")

    Enum.map(@entries, fn entry ->
      {key, source, runners} = snapshot_runners(entry)

      %{
        key: key,
        source: "priv/conformance/" <> source,
        certified: Map.fetch!(pins, key),
        runners: Enum.map(runners, &Path.expand(&1, @root))
      }
    end)
  end

  # These paths identify the standalone snapshot runners. Separate source-checkout SDK tests
  # for approval and ES256 assertions pin their inputs as independent preservation evidence.
  defp snapshot_runners({key, source, nil}), do: {key, source, []}

  defp snapshot_runners({key, source, python, rust, go}) do
    {key, source,
     [
       Path.join("sdks/python/tests/conformance", python),
       Path.join("sdks/rust/conformance", rust),
       Path.join("sdks/go", go)
     ]}
  end

  def snapshots do
    for sdk <- ["python", "rust", "go"] do
      {Path.join(@root, "sdks/#{sdk}/conformance/priv/conformance"),
       Path.join(@root, "priv/conformance")}
    end
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
