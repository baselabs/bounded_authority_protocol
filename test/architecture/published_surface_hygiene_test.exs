defmodule BoundedAuthorityProtocol.PublishedSurfaceHygieneTest do
  @moduledoc false
  use ExUnit.Case, async: true

  # Published-surface hygiene gate (2026-09-14): the Hex package and its rendered docs must
  # carry no internal authoring-tooling vocabulary. The class escaped once — the changelog and
  # four ADRs shipped naming local harness paths and AI-vendor review peers — and was
  # neutralized before the next release; this gate makes the class red-capable instead of a
  # one-time sweep. The scanned set mirrors the mix.exs package `files` boundary (the one
  # deliberate exclusion is docs/ROADMAP.md, which does not ship and legitimately carries
  # internal status vocabulary). "forge" as a WORD is legitimate cryptographic vocabulary
  # (spec/formal/attacker-model.md: an attacker "forges" messages) — only the legacy
  # `.forge/` PATH form is banned.
  @banned [
    ~r/\bkimosabe\b/i,
    ~r/\.forge\//i,
    ~r/\bforge-era\b/i,
    ~r/\bcodex\b/i,
    ~r/\bclaude\b/i,
    ~r/\bglm\b/i,
    ~r/\bzcode\b/i,
    ~r/\bsubagent\b/i
  ]

  @roots [
    "lib",
    "priv/conformance",
    "spec",
    "docs/adr",
    "docs/design",
    "docs/guides",
    "docs/deployment",
    "docs/livebooks",
    "docs/protocol-v1.md",
    "docs/release-candidate-contract.md",
    "docs/errata.md",
    "docs/governance.md",
    "mix.exs",
    ".formatter.exs",
    "README.md",
    "CHANGELOG.md",
    "usage-rules.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE"
  ]

  test "the published package surface carries no internal authoring-tooling vocabulary" do
    violations =
      for root <- @roots,
          path <- wildcard(root),
          path != "docs/ROADMAP.md",
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
      "see .forge/critical-surfaces",
      "a forge-era artifact",
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

  defp wildcard(root) do
    case File.stat(root) do
      {:ok, %{type: :directory}} -> Path.wildcard("#{root}/**/*") |> Enum.filter(&File.regular?/1)
      {:ok, %{type: :regular}} -> [root]
      _ -> []
    end
  end
end
