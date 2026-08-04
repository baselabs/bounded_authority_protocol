defmodule BoundedAuthorityProtocol.MixProject do
  use Mix.Project

  @version "0.1.0"
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
        "bap03.performance": :test,
        "bap04.performance": :test,
        "chain_archive.mutations": :test,
        "conformance.mutations": :test,
        "conformance.verify": :test,
        "license.check": :test,
        "package.check": :test,
        quality: :test,
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
        "docs/protocol-v1.md",
        "docs/errata.md",
        "docs/design/conformance-contract.md",
        "docs/design/protocol-charter.md",
        "docs/design/registries.md",
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
        "docs/adr/0001-public-protocol-verifier-boundary.md",
        "docs/adr/0002-normative-v1-parsing-profile.md",
        "docs/adr/0003-standard-jws-and-verified-grant-results.md",
        "docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md",
        "docs/adr/0005-portable-conformance-corpus-and-verifier-cli.md",
        "docs/adr/0006-standards-evolution-suite-identity-and-delegation-posture.md",
        "docs/errata.md",
        "docs/design/conformance-contract.md",
        "docs/design/protocol-charter.md",
        "docs/design/registries.md",
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
      "bap03.performance": [
        "run --no-start scripts/check_bap03_performance.exs"
      ],
      "bap04.performance": [
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
      "license.check": [
        "cmd elixir scripts/check_dependency_licenses.exs artifacts/tooling.cdx.json"
      ],
      "package.check": ["run --no-start scripts/check_package.exs"],
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
        "credo --strict",
        "bap03.performance",
        "bap04.performance",
        "test --cover --seed 42",
        "dialyzer",
        "docs --warnings-as-errors",
        "audit",
        "package.check",
        "chain_archive.mutations",
        "conformance.mutations",
        "conformance.verify"
      ]
    ]
  end

  defp prepare_artifacts(_args), do: File.mkdir_p!("artifacts")
end
