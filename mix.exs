defmodule BoundedAuthorityProtocol.MixProject do
  use Mix.Project

  @version "0.1.2"
  @source_url "https://github.com/baselabs/bounded_authority_protocol"

  def project do
    [
      app: :bounded_authority_protocol,
      version: @version,
      elixir: "~> 1.18",
      deps: deps(),
      package: package(),
      docs: docs(),
      aliases: aliases(),
      escript: [
        main_module: BoundedAuthorityProtocol.Conformance.Cli.Main,
        name: "bounded_authority_conformance"
      ],
      name: "Bounded Authority Protocol",
      description:
        "Deterministic protocol verification for cryptographically bounded " <>
          "proof-of-possession authority.",
      source_url: @source_url,
      homepage_url: @source_url,
      test_coverage: [
        summary: [threshold: 100],
        ignore_modules: [BoundedAuthorityProtocol.Conformance.Cli.Main]
      ],
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts"
      ]
    ]
  end

  def cli do
    [
      preferred_envs: [
        architecture: :test,
        audit: :test,
        "verification.performance": :test,
        "chain_archive.performance": :test,
        "chain_archive.mutations": :test,
        "conformance.mutations": :test,
        "conformance.verify": :test,
        "license.check": :test,
        "package.check": :test,
        quality: :test,
        "release.candidate": :test,
        "sbom.check": :test,
        "sbom.generate": :test
      ]
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40.3", only: [:dev, :test], runtime: false},
      {:jsonschex, "~> 0.8.1", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:sbom, "~> 0.10.0", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["rjpalermo"],
      files: [
        "lib",
        "priv/conformance/v1/corpus",
        "priv/conformance/v1/schemas",
        "priv/conformance/v1/vectors",
        ".formatter.exs",
        "mix.exs",
        "README.md",
        "CHANGELOG.md",
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
        "docs/protocol-v1.md",
        "docs/release-candidate-contract.md",
        "docs/errata.md",
        "docs/governance.md",
        "docs/design/conformance-contract.md",
        "docs/design/offline-authorization-requirements.md",
        "docs/design/protocol-charter.md",
        "docs/design/registries.md",
        "docs/design/requirement-map.md",
        "docs/design/standards-track.md",
        "docs/design/threat-model.md"
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Security policy" => "#{@source_url}/blob/main/SECURITY.md"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "usage-rules.md",
        "docs/protocol-v1.md",
        "docs/release-candidate-contract.md",
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
        "docs/errata.md",
        "docs/governance.md",
        "docs/design/conformance-contract.md",
        "docs/design/offline-authorization-requirements.md",
        "docs/design/protocol-charter.md",
        "docs/design/registries.md",
        "docs/design/requirement-map.md",
        "docs/design/standards-track.md",
        "docs/design/threat-model.md"
      ]
    ]
  end

  defp aliases do
    [
      architecture: [
        "compile --warnings-as-errors",
        "cmd elixir scripts/check_architecture.exs"
      ],
      audit: [
        "deps.unlock --check-unused",
        "hex.audit",
        "deps.audit",
        "sbom.generate",
        "license.check",
        "sbom.check"
      ],
      "verification.performance": [
        "run --no-start scripts/check_verification_performance.exs"
      ],
      "chain_archive.performance": [
        "run --no-start scripts/check_chain_archive_performance.exs"
      ],
      "chain_archive.mutations": [
        "run --no-start scripts/check_chain_archive_mutations.exs"
      ],
      "conformance.mutations": [
        "run --no-start scripts/check_conformance_mutations.exs"
      ],
      "conformance.verify": [
        "escript.build",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/v1/corpus"
      ],
      "corpus.digests": ["run --no-start scripts/regen_corpus_digests.exs"],
      "spec.facts": ["run --no-start scripts/check_spec_facts.exs"],
      "spec_facts.mutations": ["run --no-start scripts/check_spec_facts_mutations.exs"],
      "license.check": [
        "cmd elixir scripts/check_dependency_licenses.exs artifacts/tooling.cdx.json"
      ],
      "package.check": ["run --no-start scripts/check_package.exs"],
      "release.candidate": ["run --no-start scripts/check_release_candidate.exs"],
      "sbom.generate": [
        &prepare_artifacts/1,
        "cmd mix sbom.cyclonedx --only prod --exclude-system-dependencies --classification library --schema 1.6 --format json --output artifacts/release.cdx.json --force",
        "cmd elixir scripts/prune_release_sbom.exs artifacts/release.cdx.json",
        "cmd mix sbom.cyclonedx --exclude-system-dependencies --classification library --schema 1.6 --format json --output artifacts/tooling.cdx.json --force"
      ],
      "sbom.check": [
        "cmd elixir scripts/check_sbom.exs artifacts/release.cdx.json artifacts/tooling.cdx.json"
      ],
      quality: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "architecture",
        "corpus.digests",
        "spec.facts",
        "credo --strict",
        "verification.performance",
        "chain_archive.performance",
        "test --cover --seed 42",
        "dialyzer",
        "docs --warnings-as-errors",
        "audit",
        "package.check",
        "release.candidate",
        "chain_archive.mutations",
        "conformance.mutations",
        "conformance.verify",
        "spec_facts.mutations"
      ]
    ]
  end

  defp prepare_artifacts(_args), do: File.mkdir_p!("artifacts")
end
