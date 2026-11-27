Code.require_file("../../test_support/portable.ex", __DIR__)

defmodule BoundedAuthorityProtocol.PublishedSurfaceHygieneTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.TestSupport.Portable

  # Published-surface hygiene gate (2026-09-14): the Hex package and its rendered docs must
  # carry no internal authoring-tooling vocabulary. The class escaped once (the changelog and
  # four internal design documents shipped naming local harness paths and AI-vendor peers) and was
  # neutralized before the next release; this gate makes the class red-capable instead of a
  # one-time sweep. The scanned set mirrors the mix.exs package `files` boundary (ROADMAP is outside that
  # boundary and is asserted absent from the scan). Explicit authoring-tool names are banned.
  @banned [
    ~r/\bcodex\b/i,
    ~r/\bclaude\b/i,
    ~r/\bglm\b/i,
    ~r/\bzcode\b/i,
    ~r/\bsubagent\b/i
  ]

  @roots [
    "lib",
    "spec",
    "priv/conformance/verdict-digests.json",
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
    "priv/conformance/string-or-uri",
    ".formatter.exs",
    "mix.exs",
    "README.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "IPR.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "TRADEMARKS.md",
    "usage-rules.md",
    "docs/protocol-v1.md",
    "docs/errata.md",
    "docs/governance.md",
    "docs/guides/README.md",
    "docs/guides/getting-started.md",
    "docs/guides/choosing-a-profile.md",
    "docs/guides/recipes.md",
    "docs/guides/evidence.md",
    "docs/guides/troubleshooting.md",
    "docs/guides/api-stability.md",
    "docs/guides/upgrading.md",
    "docs/guides/implementers-guide.md",
    "docs/guides/other-languages.md",
    "docs/guides/glossary.md",
    "docs/guides/faq.md",
    "docs/guides/cheatsheet.cheatmd",
    "docs/notebooks/bap-walkthrough.livemd",
    "docs/notebooks/service-integration.livemd",
    "docs/notebooks/chains-and-archives.livemd",
    "docs/design/conformance-contract.md",
    "docs/design/corpus-verdict-digests.md",
    "docs/design/interoperability-report.md",
    "docs/design/protocol-charter.md",
    "docs/design/registries.md",
    "docs/design/requirement-map.md",
    "docs/design/local-loopback-http-requirement-map.md",
    "docs/design/role-attestation-requirement-map.md",
    "docs/design/content-assertion-requirement-map.md",
    "docs/design/standards-track.md",
    "docs/design/threat-model.md",
    "docs/guides/notebooks.md",
    "docs/guides/grants-and-holder-proofs.md",
    "docs/guides/trusted-keys-and-rotation.md",
    "docs/guides/tagged-arguments-and-selectors.md",
    "docs/guides/nonce-and-time-policy.md",
    "docs/guides/facts-and-authorization.md",
    "docs/guides/framework-integration.md",
    "docs/guides/integration-security.md",
    "docs/guides/operations.md",
    "docs/guides/observability.md",
    "docs/guides/errors.md",
    "docs/guides/testing-your-integration.md",
    "docs/notebooks/content-lineage.livemd",
    "docs/notebooks/local-loopback.livemd",
    "docs/notebooks/role-attestations.livemd",
    "docs/notebooks/strict-crypto.livemd",
    "docs/notebooks/range-selectors.livemd",
    "docs/notebooks/es256-signing.livemd",
    "docs/deployment/go-sdk.md",
    "docs/deployment/python-sdk.md",
    "docs/deployment/rust-sdk.md",
    "docs/deployment/typescript-sdk.md",
    "spec/bap-content-assertion-v1.md",
    "spec/bap-local-loopback-http-v1.md",
    "spec/bap-role-attestation-v1.md",
    "spec/bap-v1.md",
    "spec/bap-v2.md",
    "spec/bap-v3.md",
    "spec/diagnostic-rendering.md",
    "docs/design/iana/README.md",
    "docs/design/iana/jwt-claims.md",
    "docs/design/iana/media-types.md",
    "docs/design/iana/jwt-claims.json",
    "docs/design/iana/media-types.json",
    "docs/design/successor-major-charter.md",
    "docs/standards/submissions.md",
    "docs/notebooks/registry.json"
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
    File.write!(path, "codex reviewed")
    assert path in wildcard(root)
    assert Enum.any?(@banned, &Regex.match?(&1, File.read!(path)))
  end

  # Public text states each rule itself or links a tracked specification. Scan all tracked
  # text, including SDK sources, tests, hidden configuration, scripts, and site files.
  # Split spellings keep the checker and its positive examples inside their own scan.
  @unpublished_reference ~r/\bA[D]Rs?(?:\b|\d{4}\b)|\b(?:architecture[ -]+)?decision[ -]+records?\b/i

  test "no tracked public text depends on unpublished design references" do
    violations = unpublished_references(tracked_public_files())

    assert violations == [],
           "unpublished design references in public text:\n#{Enum.join(violations, "\n")}"
  end

  test "the unpublished-reference check rejects numbered, plural, and general forms" do
    abbreviation = "A" <> "DR"
    full_name = "decision" <> " record"

    for text <- [
          "see #{abbreviation} 0014",
          "(#{abbreviation}-0014)",
          "#{abbreviation}0014",
          "#{abbreviation}s",
          "#{abbreviation}",
          "#{full_name} 0014",
          "#{full_name}s",
          "architecture-#{String.replace(full_name, " ", "-")}"
        ] do
      assert Regex.match?(@unpublished_reference, text), text
      assert Regex.match?(@unpublished_reference, String.downcase(text)), text
    end

    refute Regex.match?(@unpublished_reference, "a GRADR 01 token")
    refute Regex.match?(@unpublished_reference, "spec/bap-v1.md §15")
  end

  test "the tracked scan covers SDKs and catches a citation planted in a source file" do
    paths = tracked_public_files()

    for path <- [
          "sdks/go/archive.go",
          "sdks/python/tests/test_permissiveness.py",
          "sdks/rust/src/facts.rs",
          "sdks/rust/.config/nextest.toml",
          ".github/workflows/ci.yml",
          "scripts/check_sdk_publish_infra.sh",
          "site/index.html",
          "test/architecture/published_surface_hygiene_test.exs"
        ] do
      assert path in paths, path
    end

    root = Path.join(System.tmp_dir!(), "bap-public-text-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(root) end)
    path = Path.join(root, "sdks/go/archive.go")
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, "// Canonical archive framing (spec/bap-v1.md §15).\n")
    assert unpublished_references([path]) == []
    File.write!(path, "// See A" <> "DR 0014.\n")
    assert [violation] = unpublished_references([path])
    assert String.starts_with?(violation, "#{path}:1:")
  end

  test "tracked narrative text uses punctuation without long dashes" do
    dash = <<0x2014::utf8>>

    violations =
      for path <- tracked_public_files(),
          not corpus_data?(path),
          {line, number} <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
          String.contains?(line, dash),
          do: "#{path}:#{number}: #{String.trim(line)}"

    assert violations == [], "rewrite narrative punctuation:\n#{Enum.join(violations, "\n")}"
    assert String.contains?("A rule" <> dash <> "an explanation", dash)
    refute String.contains?("A rule: an explanation", dash)
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
  @guide_prose ["README.md", "usage-rules.md", "docs/guides", "docs/notebooks"]

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

  defp tracked_public_files do
    {files, 0} = System.cmd("git", ["ls-files", "-z"])

    files
    |> String.split(<<0>>, trim: true)
    |> Enum.filter(&(File.regular?(&1) and String.valid?(File.read!(&1))))
  end

  defp unpublished_references(paths) do
    for path <- paths,
        {line, number} <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
        Regex.match?(@unpublished_reference, line),
        do: "#{path}:#{number}: #{String.trim(line)}"
  end

  # Certified corpus bytes are protocol data, not narrative. Never rewrite or exempt
  # authored SDK sources or tests, including those beside the vendored snapshots.
  defp corpus_data?(path) do
    String.starts_with?(path, "priv/conformance/") or
      Regex.match?(~r{^sdks/[^/]+/conformance/priv/conformance/}, path)
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
