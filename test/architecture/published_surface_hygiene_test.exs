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
    "priv/conformance/selector-float-zero",
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
    "docs/guides/choosing-a-profile.md",
    "docs/guides/recipes.md",
    "docs/guides/evidence.md",
    "docs/guides/troubleshooting.md",
    "docs/guides/api-stability.md",
    "docs/guides/other-languages.md",
    "docs/guides/glossary.md",
    "docs/guides/faq.md",
    "docs/guides/cheatsheet.cheatmd",
    "docs/livebooks/service-integration.livemd",
    "docs/livebooks/chains-and-archives.livemd",
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

  # Decision records are local and unpublished, so a shipped file or HexDocs page that cites one
  # by number points the reader at nothing. Shipped text states the rule itself or links a
  # shipped section (a specification, governance, or the errata registry).
  @adr_citation ~r/\bADR[ -]?0\d/

  test "no shipped file or HexDocs page cites a decision record by number" do
    violations =
      for path <- shipped_and_extras(),
          line <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
          {text, number} = line,
          Regex.match?(@adr_citation, text),
          do: "#{path}:#{number}: #{String.trim(text)}"

    assert violations == [],
           "decision-record citations in the published surface:\n#{Enum.join(violations, "\n")}"
  end

  test "the decision-record check is red-capable" do
    for text <- ["see ADR 0040", "(ADR-0015)", "ADR 0021 §2"] do
      assert Regex.match?(@adr_citation, text), text
    end

    refute Regex.match?(@adr_citation, "a GRADR 01 token")
  end

  test "no HexDocs page starts with YAML front matter" do
    violations = for path <- extras(), front_matter?(File.read!(path)), do: path
    assert violations == [], "front matter renders as text on HexDocs: #{inspect(violations)}"
    assert front_matter?("---\ntitle: x\n---\n# Heading\n")
    refute front_matter?("# Heading\n\n---\n")
  end

  # Prose names the wire contract "contract-major N" and the package "package 1.x" or a release
  # number. A bare "v1" in guide prose is ambiguous between the two, so it is refused outside
  # code, inline code, and link targets.
  @guide_prose ["README.md", "usage-rules.md", "docs/guides", "docs/livebooks"]

  test "guide prose never says a bare v1, v2, or v3" do
    violations =
      for root <- @guide_prose,
          path <- wildcard(root),
          Path.extname(path) in [".md", ".cheatmd", ".livemd"],
          {line, number} <- path |> File.read!() |> prose_lines(),
          [token] <- Regex.scan(~r/\b[vV][1-9]\b/, line),
          do: "#{path}:#{number}: #{token} in #{inspect(String.trim(line))}"

    assert violations == [],
           ~s{say "contract-major N" (wire) or "package 1.x" (Hex), not a bare major:\n} <>
             Enum.join(violations, "\n")
  end

  test "the bare-major prose check is red-capable and skips code" do
    markdown = """
    The v1 envelope verifies.

    ```elixir
    alias BoundedAuthorityProtocol.V1
    ```

    Call `V1.verify_grant/3` or read [the spec](spec/bap-v1.md) for contract-major 1.
    """

    assert [{"The v1 envelope verifies.", 1}] =
             markdown |> prose_lines() |> Enum.filter(&(elem(&1, 0) =~ ~r/\b[vV][1-9]\b/))
  end

  defp extras do
    for extra <- Mix.Project.config()[:docs][:extras] do
      case extra do
        {path, _options} -> path
        path -> path
      end
    end
  end

  defp shipped_and_extras do
    @roots |> Enum.flat_map(&wildcard/1) |> Enum.concat(extras()) |> Enum.uniq()
  end

  defp front_matter?(source), do: String.starts_with?(source, "---\n")

  # Lines of prose with fenced blocks, HTML comments, inline code, link targets, and URLs removed.
  defp prose_lines(markdown) do
    {lines, _fenced?} =
      markdown
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.map_reduce(false, fn {line, number}, fenced? ->
        cond do
          String.starts_with?(String.trim_leading(line), "```") -> {nil, not fenced?}
          fenced? -> {nil, fenced?}
          true -> {{strip_code_and_links(line), number}, fenced?}
        end
      end)

    Enum.reject(lines, &is_nil/1)
  end

  defp strip_code_and_links(line) do
    line
    |> String.replace(~r/<!--.*?-->/, "")
    |> String.replace(~r/`[^`]*`/, "")
    |> String.replace(~r/\]\([^)]*\)/, "]")
    |> String.replace(~r/https?:\/\/\S+/, "")
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
