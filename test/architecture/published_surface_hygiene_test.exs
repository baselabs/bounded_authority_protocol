Code.require_file("../../test_support/portable.ex", __DIR__)

defmodule BoundedAuthorityProtocol.PublishedSurfaceHygieneTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.TestSupport.Portable

  # Published-surface hygiene gate (2026-09-14): the Hex package and its rendered docs must
  # carry no internal authoring-tooling vocabulary. The class escaped once — the changelog and
  # four ADRs shipped naming local harness paths and AI-vendor review peers — and was
  # neutralized before the next release; this gate makes the class red-capable instead of a
  # one-time sweep. The scanned set mirrors the mix.exs package `files` boundary (ROADMAP is outside that
  # boundary and is asserted absent from the scan). Explicit authoring-tool names are banned.
  @banned [
    ~r/\bkimosabe\b/i,
    ~r/\bcodex\b/i,
    ~r/\bclaude\b/i,
    ~r/\bglm\b/i,
    ~r/\bzcode\b/i,
    ~r/\bsubagent\b/i
  ]

  @roots [
    "lib",
    "spec",
    "priv/conformance/v1/corpus",
    "priv/conformance/v1/schemas",
    "priv/conformance/v1/vectors",
    "priv/conformance/v2/corpus",
    "priv/conformance/v3/corpus",
    "priv/conformance/application-profiles/local-loopback-http/v1",
    "priv/conformance/attestation-profiles/role-attestation/v1",
    "priv/conformance/attestation-profiles/content-assertion/v1",
    "priv/conformance/strict-ed25519",
    "priv/conformance/producer-canonicality",
    ".formatter.exs",
    "mix.exs",
    "README.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "usage-rules.md",
    "docs/protocol-v1.md",
    "docs/errata.md",
    "docs/governance.md",
    "docs/guides/README.md",
    "docs/guides/getting-started.md",
    "docs/guides/implementers-guide.md",
    "docs/guides/upgrading.md",
    "docs/livebooks/bap-walkthrough.livemd",
    "docs/deployment/go-sdk.md",
    "docs/deployment/python-sdk.md",
    "docs/deployment/rust-sdk.md",
    "docs/deployment/typescript-sdk.md",
    "docs/design/conformance-contract.md",
    "docs/design/interoperability-report.md",
    "docs/design/protocol-charter.md",
    "docs/design/registries.md",
    "docs/design/requirement-map.md",
    "docs/design/local-loopback-http-requirement-map.md",
    "docs/design/role-attestation-requirement-map.md",
    "docs/design/content-assertion-requirement-map.md",
    "docs/design/standards-track.md",
    "docs/design/threat-model.md"
  ]

  test "the published package surface carries no internal authoring-tooling vocabulary" do
    violations =
      for root <- @roots,
          path <- wildcard(root),
          file = File.read!(path),
          banned <- @banned,
          match = Regex.run(banned, file),
          uniq: true,
          do: "#{path}: #{inspect(banned.source)} matched #{inspect(hd(match))}"

    assert violations == [],
           "internal tooling vocabulary in the published surface:\n#{Enum.join(violations, "\n")}"
  end

  test "the banned set is red-capable (a planted term is caught on every pattern)" do
    planted = [
      "a kimosabe note",
      "codex reviewed",
      "claude reviewed",
      "glm lens",
      "zcode host",
      "a subagent dispatch"
    ]

    for text <- planted do
      assert Enum.any?(@banned, &Regex.match?(&1, text)),
             "planted text not caught by any banned pattern: #{inspect(text)}"
    end

    # The legitimate cryptographic vocabulary must NOT match.
    refute Enum.any?(@banned, &Regex.match?(&1, "an attacker forges every message"))
    refute Enum.any?(@banned, &Regex.match?(&1, "the forge of the signature"))
  end

  test "scan roots match the package declaration and exclude the unshipped roadmap" do
    assert MapSet.new(@roots) == MapSet.new(Mix.Project.config()[:package][:files])
    refute "docs/ROADMAP.md" in Enum.flat_map(@roots, &wildcard/1)
  end

  test "hidden files under a package root are scanned" do
    root = Path.join(System.tmp_dir!(), "bap-hygiene-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    path = Path.join(root, ".hidden.md")
    File.write!(path, "a kimosabe note")
    assert path in wildcard(root)
    assert Enum.any?(@banned, &Regex.match?(&1, File.read!(path)))
  end

  defp wildcard(root) do
    case File.stat(root) do
      {:ok, %{type: :directory}} ->
        Portable.ls_r(root) |> Enum.filter(&File.regular?/1)

      {:ok, %{type: :regular}} ->
        [root]

      _ ->
        []
    end
  end
end
