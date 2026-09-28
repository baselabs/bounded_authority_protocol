defmodule BoundedAuthorityProtocol.DocsCurrencyTest do
  @moduledoc """
  Pins the public documentation surfaces to CURRENT facts: the source candidate versus the latest
  released CHANGELOG version, release-facing cross-references, the SDK count, the conformance case
  count, the supply-chain artifact filename derivation (no hardcoded version strings remain in the
  workflow), and the spec Doc-Revision cross-references. A stale count, drifted filename, source
  candidate behind the release, or release-surface mismatch reds here with the surface named.
  """

  use ExUnit.Case, async: true

  @version Mix.Project.config() |> Keyword.fetch!(:version)

  @case_count 283
  @spec_revision 1

  defp release_state(changelog, candidate_version) do
    released_version =
      case Regex.run(~r/^## \[(\d+\.\d+\.\d+)\](?:\s+[^\n]*)?$/m, changelog,
             capture: :all_but_first
           ) do
        [version] -> version
        nil -> flunk("CHANGELOG must contain a numeric release heading")
      end

    comparison = Version.compare(candidate_version, released_version)
    released_heading = "## [#{released_version}]"
    {released_position, _length} = :binary.match(changelog, released_heading)

    unreleased_precedes_release? =
      case :binary.match(changelog, "## [Unreleased]") do
        {unreleased_position, _length} -> unreleased_position < released_position
        :nomatch -> false
      end

    errors =
      []
      |> then(fn errors ->
        if comparison == :lt do
          [
            "source candidate #{candidate_version} must not trail released version #{released_version}"
            | errors
          ]
        else
          errors
        end
      end)
      |> then(fn errors ->
        if comparison == :gt and not unreleased_precedes_release? do
          [
            "CHANGELOG must carry an Unreleased section before #{released_heading} while source candidate #{candidate_version} is ahead"
            | errors
          ]
        else
          errors
        end
      end)

    {released_version, Enum.reverse(errors)}
  end

  defp previous_version(version) do
    parsed = Version.parse!(version)

    cond do
      parsed.patch > 0 -> "#{parsed.major}.#{parsed.minor}.#{parsed.patch - 1}"
      parsed.minor > 0 -> "#{parsed.major}.#{parsed.minor - 1}.0"
      parsed.major > 0 -> "#{parsed.major - 1}.0.0"
      true -> flunk("cannot construct a version below #{version}")
    end
  end

  defp next_version(version) do
    parsed = Version.parse!(version)
    "#{parsed.major}.#{parsed.minor}.#{parsed.patch + 1}"
  end

  test "the source candidate is not behind the latest release and carries Unreleased when ahead" do
    changelog = File.read!("CHANGELOG.md")
    {released_version, errors} = release_state(changelog, @version)

    assert errors == [], Enum.join(errors, "\n")
    assert Version.compare(@version, released_version) in [:eq, :gt]
  end

  test "the package-versus-release guard rejects both failure directions using the live changelog" do
    changelog = File.read!("CHANGELOG.md")
    {released_version, []} = release_state(changelog, @version)

    {_released_version, behind_errors} =
      release_state(changelog, previous_version(released_version))

    assert Enum.any?(behind_errors, &String.contains?(&1, "must not trail released version"))

    changelog_without_unreleased =
      String.replace(changelog, "## [Unreleased]", "## [Draft]", global: false)

    {_released_version, ahead_errors} =
      release_state(changelog_without_unreleased, next_version(released_version))

    assert Enum.any?(ahead_errors, &String.contains?(&1, "must carry an Unreleased section"))
  end

  test "every live release surface derives from the latest released version" do
    changelog = File.read!("CHANGELOG.md")
    {released_version, []} = release_state(changelog, @version)
    [major, minor, _patch] = String.split(released_version, ".")
    series = "#{major}.#{minor}"
    requirement = "~> #{released_version}"

    expectations = [
      {"README install", "README.md", "{:bounded_authority_protocol, \"#{requirement}\"}"},
      {"getting-started install", "docs/guides/getting-started.md",
       "{:bounded_authority_protocol, \"#{requirement}\"}"},
      {"Livebook install", "docs/livebooks/bap-walkthrough.livemd",
       "{:bounded_authority_protocol, \"#{requirement}\"}"},
      {"security support", "SECURITY.md", "`#{series}.x` source release line is supported"},
      {"security current", "SECURITY.md",
       "`v#{released_version}` is the current tagged source release"},
      {"usage rules install", "usage-rules.md",
       "{:bounded_authority_protocol, \"#{requirement}\"}"}
    ]

    mismatches =
      for {label, path, expected} <- expectations,
          source = File.read!(path),
          not String.contains?(source, expected),
          do: "#{label}: #{path} must contain #{inspect(expected)}"

    assert mismatches == [], Enum.join(mismatches, "\n")
  end

  test "release docs do not present the source tag as an immutable package identity" do
    changelog = File.read!("CHANGELOG.md")
    {released_version, []} = release_state(changelog, @version)

    for version <- Enum.uniq([released_version, @version]),
        path <- [
          "README.md",
          "docs/guides/getting-started.md",
          "docs/livebooks/bap-walkthrough.livemd"
        ] do
      refute File.read!(path) =~
               ~r/bounded_authority_protocol,[\s\S]{0,120}tag: "v#{Regex.escape(version)}"/,
             "#{path} must not prescribe v#{version} as a package dependency"
    end
  end

  test "the sdks README names all four SDKs" do
    readme = File.read!("sdks/README.md")

    # Three SDKs are authored in this repository; the fourth (TypeScript) graduated to its own
    # repository on first publication (ADR 0015) and is named by its published identity.
    for sdk <- ["python/", "rust/", "go/"] do
      assert readme =~ "[`#{sdk}`]",
             "sdks/README.md must list the #{sdk} SDK"
    end

    assert readme =~ "@bounded-authority-protocol/verifier",
           "sdks/README.md must name the graduated TypeScript SDK's published npm scope"

    assert readme =~ "baselabs/bounded_authority_protocol_typescript",
           "sdks/README.md must point at the graduated TypeScript repository"

    refute readme =~ "[`typescript/`]",
           "sdks/README.md must not link a typescript/ directory — the SDK graduated (ADR 0015)"

    refute readme =~ "@bounded-authority/verifier",
           "sdks/README.md must not cite the retired npm scope"
  end

  test "consumer-facing counts match the certified corpus" do
    index = File.read!("priv/conformance/v1/corpus/index.json")
    assert index =~ "\"total_cases\":#{@case_count}"

    for surface <- ["sdks/README.md", "README.md"] do
      source = File.read!(surface)

      if source =~ "283" do
        assert true
      else
        # Only fail when the doc names a DIFFERENT count
        refute source =~ ~r/\b2\d\d cases\b/,
               "#{surface} names a stale case count (the corpus carries #{@case_count})"
      end
    end
  end

  test "the supply-chain workflow derives the artifact name — no hardcoded version strings" do
    workflow = File.read!(".github/workflows/supply-chain.yml")

    assert workflow =~ "@version",
           "supply-chain.yml must derive the artifact name from mix.exs @version"

    refute workflow =~ ~r/bounded_authority_protocol-\d+\.\d+\.\d+\.tar/,
           "supply-chain.yml contains a hardcoded versioned artifact filename — the quiet-mislabel class"
  end

  test "the derived view's footer names the spec revision" do
    derived = File.read!("docs/protocol-v1.md")

    assert derived =~ "Generated from `spec/bap-v1.md` rev #{@spec_revision}",
           "the derived view's footer must name the spec authority and its revision"
  end

  test "the interoperability report's cited figures match the live corpus identity" do
    report = File.read!("docs/design/interoperability-report.md")

    # The certified digest (both encodings) and the revision integer come from the same
    # machine sources the corpus.digests gate uses.
    {:ok, index_bytes} = File.read("priv/conformance/v1/corpus/index.json")
    digest = :crypto.hash(:sha256, index_bytes)
    b64 = Base.url_encode64(digest, padding: false)
    hex = Base.encode16(digest, case: :lower)
    revision = File.read!("priv/conformance/v1/corpus/revision.json")

    assert report =~ b64, "the report must cite the certified index digest (#{b64})"
    assert report =~ hex, "the report must cite the hex form (#{hex})"
    assert report =~ "corpus revision 1"
    assert revision =~ ~s("revision":1)
    assert report =~ "283/283 agreed"
    assert report =~ "283 cases"
    assert report =~ "28 surfaces"
    assert report =~ "11 keys"
  end

  test "the interoperability report cites the certified application-profile corpus" do
    report = File.read!("docs/design/interoperability-report.md")

    index_bytes =
      File.read!("priv/conformance/application-profiles/local-loopback-http/v1/index.json")

    index = :json.decode(index_bytes)
    digest = :crypto.hash(:sha256, index_bytes) |> Base.encode16(case: :lower)

    assert report =~ digest
    assert report =~ "#{index["uri_cases"]}/#{index["uri_cases"]} URI cases"
    assert report =~ "#{index["proof_cases"]}/#{index["proof_cases"]} proof cases"
    assert report =~ index["profile"]
  end

  test "the spec pins its Doc-Revision and the companions agree" do
    spec = File.read!("spec/bap-v1.md")
    assert spec =~ "Document revision: rev #{@spec_revision}"

    for companion <- ["spec/formal/attacker-model.md", "spec/formal/proverif/bap-core.pv"] do
      assert File.read!(companion) =~ "rev #{@spec_revision}",
             "#{companion} must pin the spec revision it was written against"
    end
  end
end
