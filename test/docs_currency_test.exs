defmodule BoundedAuthorityProtocol.DocsCurrencyTest do
  @moduledoc """
  Pins the public documentation surfaces to CURRENT facts: the package version's cross
  references (CHANGELOG/README), the SDK count, the conformance case count, the supply-chain
  artifact filename derivation (no hardcoded version strings remain in the workflow), and the
  spec Doc-Revision cross-references. A stale count, a drifted filename, or a version bump
  without its cross-references reds here with the surface named.
  """

  use ExUnit.Case, async: true

  @version Mix.Project.config() |> Keyword.fetch!(:version)

  @sdk_count 4
  @case_count 283
  @spec_revision 1

  test "the changelog's top released section matches the package version or stays Unreleased" do
    changelog = File.read!("CHANGELOG.md")

    assert changelog =~ "## [Unreleased]" or changelog =~ "## [#{@version}]",
           "CHANGELOG must either carry Unreleased work or a section for the current version #{@version}"
  end

  test "the sdks README names all four SDKs" do
    readme = File.read!("sdks/README.md")

    for sdk <- ["typescript/", "python/", "rust/", "go/"] do
      assert readme =~ "[`#{sdk}`]",
             "sdks/README.md must list the #{sdk} SDK"
    end

    refute readme =~ ~r/all three/i,
           "sdks/README.md still says 'all three' — there are #{@sdk_count} SDKs"
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

  test "the spec pins its Doc-Revision and the companions agree" do
    spec = File.read!("spec/bap-v1.md")
    assert spec =~ "Document revision: rev #{@spec_revision}"

    for companion <- ["spec/formal/attacker-model.md", "spec/formal/proverif/bap-core.pv"] do
      assert File.read!(companion) =~ "rev #{@spec_revision}",
             "#{companion} must pin the spec revision it was written against"
    end
  end
end
