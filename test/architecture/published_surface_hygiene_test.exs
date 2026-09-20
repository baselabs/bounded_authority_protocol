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
  # boundary and is asserted absent from the scan). "forge" as a WORD is legitimate cryptographic vocabulary
  # (spec/formal/attacker-model.md: an attacker "forges" messages). The legacy path form
  # and explicit authoring-tool phrases are banned.
  @banned [
    ~r/\bkimosabe\b/i,
    ~r/\.forge\//i,
    ~r/\bforge-era\b/i,
    ~r/\bforge (?:whitelist|skill)\b/i,
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
    "priv/conformance/application-profiles/local-loopback-http/v1",
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
    "docs/adr/0001-public-protocol-verifier-boundary.md",
    "docs/adr/0002-normative-v1-parsing-profile.md",
    "docs/adr/0003-standard-jws-and-verified-grant-results.md",
    "docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md",
    "docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md",
    "docs/adr/0006-standards-evolution-suite-identity-and-delegation-posture.md",
    "docs/adr/0007-normative-requirement-identifiers.md",
    "docs/adr/0008-release-candidate-contract.md",
    "docs/adr/0009-cryptographic-suite-succession-and-cross-suite-evidence-longevity.md",
    "docs/adr/0010-delegation-with-attenuation.md",
    "docs/adr/0011-published-governance.md",
    "docs/adr/0012-security-release-accelerated-deprecation-window.md",
    "docs/adr/0013-capability-authorization-extension.md",
    "docs/adr/0014-cross-language-verifier-sdks.md",
    "docs/adr/0015-sdk-graduation-and-publish-topology.md",
    "docs/adr/0016-offline-eligible-grant-claims.md",
    "docs/adr/0017-inter-sdk-behavioral-contract.md",
    "docs/adr/0018-sdk-bounds-contract.md",
    "docs/adr/0019-corpus-artifact-distribution.md",
    "docs/adr/0020-bounds-aware-assembly-and-issuer-reauthorization-posture.md",
    "docs/adr/0021-v1-all-selector-recognized-shapes-erratum.md",
    "docs/adr/0022-durable-contract-identities.md",
    "docs/adr/0027-byte-distinct-application-proof-profiles.md",
    "docs/adr/0028-range-selector-kinds.md",
    "docs/adr/0029-budget-window-posture.md",
    "docs/adr/0030-v2-contract-major-activation.md",
    "docs/adr/0031-self-enforcing-toolchain-and-tri-platform-build-bar.md",
    "docs/adr/0032-dependency-currency-gate.md",
    "docs/protocol-v1.md",
    "docs/release-candidate-contract.md",
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
    "docs/design/iana",
    "docs/design/interoperability-report.md",
    "docs/design/offline-authorization-requirements.md",
    "docs/design/protocol-charter.md",
    "docs/design/registries.md",
    "docs/design/requirement-map.md",
    "docs/design/successor-major-charter.md",
    "docs/design/local-loopback-http-requirement-map.md",
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
      "see .forge/critical-surfaces",
      "a forge-era artifact",
      "per the forge whitelist",
      "the forge skill rules",
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
