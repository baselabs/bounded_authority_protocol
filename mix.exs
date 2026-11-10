defmodule BoundedAuthorityProtocol.MixProject do
  use Mix.Project

  @version "0.9.1"
  @source_url "https://github.com/baselabs/bounded_authority_protocol"

  def project do
    [
      app: :bounded_authority_protocol,
      version: @version,
      # Lockstep rule: this range, config/config.exs's supported-OTP set,
      # .tool-versions, and the CI compatibility lanes in .github/workflows/ci.yml
      # move together in ONE commit. The range admits Elixir 1.18-1.20; Mix refuses
      # anything outside it at compile. The supported-OTP set ({27, 28, 29}) is
      # floor-limited by the stdlib :json module (OTP 27+), not by Elixir builds.
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
        "privacy.hooks": :test,
        "release.candidate": :test,
        secrets: :test,
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
      # Pre-1.0: a minor release can change validation, so take minors one Dependabot PR at
      # a time and let the corpus schema gates decide.
      {:jsonschex, "~> 0.11.0", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      # scripts/generate_sbom.exs runs through mix run --no-start and calls SBoM.CLI
      # after explicit startup; hex_core stays code-only so its :ssh dependency
      # is never started on the ubuntu-24.04 supply-chain runners.
      {:sbom, "~> 0.12.1", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["rjpalermo"],
      files: [
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
        "docs/livebooks/bap-walkthrough.livemd",
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
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Security policy" => "#{@source_url}/blob/main/SECURITY.md"
      }
    ]
  end

  # HexDocs reading path: start here, then guides, then reference, then the normative specs.
  # The extras order is the sidebar order inside each group.
  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      # The API stability page names the excluded internals; they are hidden, so never link them.
      skip_code_autolink_to: [
        "BoundedAuthorityProtocol.V1.Runtime",
        "BoundedAuthorityProtocol.V2.Runtime",
        "BoundedAuthorityProtocol.V3.Runtime",
        "BoundedAuthorityProtocol.Conformance.Corpus",
        "BoundedAuthorityProtocol.Conformance.Runner",
        "BoundedAuthorityProtocol.Conformance.Report",
        "BoundedAuthorityProtocol.Conformance.Cli.Main",
        "BoundedAuthorityProtocol.V1.Jwk.thumbprint_digest_unchecked/1",
        "BoundedAuthorityProtocol.Ed25519.signature_gate?/1",
        "BoundedAuthorityProtocol.Ed25519.strict_gate?/2",
        "BoundedAuthorityProtocol.V1.Selector.float_zero_free?/1",
        "BoundedAuthorityProtocol.V1.Selector.integral_float_free?/1",
        "BoundedAuthorityProtocol.V1.Selector.match_all/3",
        "BoundedAuthorityProtocol.V1.Selector.semantic_equal?/2",
        "BoundedAuthorityProtocol.V2.Selector.float_zero_free?/1",
        "BoundedAuthorityProtocol.V2.Selector.integral_float_free?/1",
        "BoundedAuthorityProtocol.V2.Selector.match_all/3",
        "BoundedAuthorityProtocol.V2.Selector.semantic_equal?/2",
        "BoundedAuthorityProtocol.V3.Selector.float_zero_free?/1",
        "BoundedAuthorityProtocol.V3.Selector.integral_float_free?/1",
        "BoundedAuthorityProtocol.V3.Selector.match_all/3",
        "BoundedAuthorityProtocol.V3.Selector.semantic_equal?/2"
      ],
      extras: [
        {"README.md", [title: "Overview"]},
        "docs/guides/getting-started.md",
        {"docs/livebooks/bap-walkthrough.livemd", [title: "Livebook: protocol walkthrough"]},
        {"docs/livebooks/service-integration.livemd", [title: "Livebook: service integration"]},
        {"docs/livebooks/chains-and-archives.livemd", [title: "Livebook: chains and archives"]},
        {"docs/guides/cheatsheet.cheatmd", [title: "Cheatsheet"]},
        "docs/guides/choosing-a-profile.md",
        "docs/guides/recipes.md",
        "docs/guides/evidence.md",
        "docs/guides/troubleshooting.md",
        "usage-rules.md",
        "docs/guides/upgrading.md",
        "docs/guides/implementers-guide.md",
        "docs/guides/other-languages.md",
        "docs/guides/api-stability.md",
        "docs/guides/glossary.md",
        "docs/guides/faq.md",
        "docs/design/protocol-charter.md",
        "docs/design/threat-model.md",
        "docs/design/registries.md",
        "spec/bap-v1.md",
        "spec/bap-v2.md",
        "spec/bap-v3.md",
        "spec/bap-local-loopback-http-v1.md",
        "spec/bap-role-attestation-v1.md",
        "spec/bap-content-assertion-v1.md",
        "docs/design/conformance-contract.md",
        "docs/design/requirement-map.md",
        "docs/design/local-loopback-http-requirement-map.md",
        "docs/design/role-attestation-requirement-map.md",
        "docs/design/content-assertion-requirement-map.md",
        "docs/design/interoperability-report.md",
        "docs/governance.md",
        "docs/errata.md",
        "docs/design/standards-track.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "LICENSE",
        "NOTICE"
      ],
      groups_for_extras: [
        "Start here": [
          "README.md",
          "docs/guides/getting-started.md",
          ~r"^docs/livebooks/",
          "docs/guides/cheatsheet.cheatmd"
        ],
        Guides: [
          "docs/guides/choosing-a-profile.md",
          "docs/guides/recipes.md",
          "docs/guides/evidence.md",
          "docs/guides/troubleshooting.md",
          "usage-rules.md",
          "docs/guides/upgrading.md",
          "docs/guides/implementers-guide.md",
          "docs/guides/other-languages.md"
        ],
        Reference: [
          "docs/guides/api-stability.md",
          "docs/guides/glossary.md",
          "docs/guides/faq.md",
          "docs/design/protocol-charter.md",
          "docs/design/threat-model.md",
          "docs/design/registries.md"
        ],
        Specifications: [~r"^spec/"],
        "Conformance and governance": [
          "docs/design/conformance-contract.md",
          ~r"^docs/design/.*requirement-map\.md$",
          "docs/design/interoperability-report.md",
          "docs/governance.md",
          "docs/errata.md",
          "docs/design/standards-track.md"
        ],
        Project: [
          "CHANGELOG.md",
          "SECURITY.md",
          "CONTRIBUTING.md",
          "CODE_OF_CONDUCT.md",
          "LICENSE",
          "NOTICE"
        ]
      ],
      groups_for_modules: [
        "Shared types": ~r"^BoundedAuthorityProtocol\.V1\.(Json|Jcs|Base64Url|Jwk|Uri|Bounds)$",
        "Contract-major 1": ~r"^BoundedAuthorityProtocol\.V1(\.|$)",
        "Contract-major 2": ~r"^BoundedAuthorityProtocol\.V2(\.|$)",
        "Contract-major 3": ~r"^BoundedAuthorityProtocol\.V3(\.|$)",
        "Signature suites": ~r"^BoundedAuthorityProtocol\.(Ed25519|Es256)$",
        "Sibling profiles": [
          ~r"^BoundedAuthorityProtocol\.ApplicationProfile\.",
          ~r"^BoundedAuthorityProtocol\.RoleAttestation\.",
          ~r"^BoundedAuthorityProtocol\.ContentAssertion\."
        ],
        Conformance: ~r"^BoundedAuthorityProtocol\.Conformance\."
      ],
      groups_for_docs: [
        Producers: &(facade_group(&1) == :producers),
        Decoders: &(facade_group(&1) == :decoders),
        Verifiers: &(facade_group(&1) == :verifiers)
      ]
    ]
  end

  # The contract-major and sibling-profile facades group their functions by role on HexDocs.
  defp facade_group(%{module: module, kind: :function, name: name}) do
    name = Atom.to_string(name)

    cond do
      not facade?(inspect(module)) -> nil
      String.starts_with?(name, ["verify_", "check_"]) -> :verifiers
      String.starts_with?(name, ["decode_", "untrusted_"]) -> :decoders
      true -> :producers
    end
  end

  defp facade_group(_metadata), do: nil

  defp facade?(module),
    do:
      module =~
        ~r"^BoundedAuthorityProtocol\.((ApplicationProfile\.LocalLoopbackHttp|RoleAttestation|ContentAssertion)\.)?V\d$"

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
        "cmd ./bounded_authority_conformance --corpus priv/conformance/v1/corpus",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/v2/corpus",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/v3/corpus",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/strict-ed25519",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/producer-canonicality",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/selector-float-zero",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/application-profiles/local-loopback-http/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/role-attestation/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/content-assertion/v1"
      ],
      "local_loopback_http.verify": [
        "run scripts/check_local_loopback_http.exs",
        "run --no-start scripts/check_local_loopback_http_mutations.exs"
      ],
      "content_assertion.mutations": [
        "run --no-start scripts/check_content_assertion_mutations.exs"
      ],
      "content_assertion.verify": ["run --no-start scripts/check_content_assertion.exs"],
      "role_attestation.verify": ["run scripts/check_role_attestation.exs"],
      "corpus.digests": ["run --no-start scripts/regen_corpus_digests.exs"],
      "corpus.sync": ["run --no-start scripts/check_corpus_sync.exs"],
      "spec.facts": ["run --no-start scripts/check_spec_facts.exs"],
      "docs.links": ["run --no-start scripts/check_doc_links.exs"],
      "spec.examples": ["run --no-start spec/tools/build_examples.exs"],
      "spec.render": ["run --no-start spec/tools/render_derived.exs"],
      secrets: ["cmd scripts/secret_scan.sh"],
      "privacy.hooks": ["cmd python3 scripts/test_private_identifier_guard.py"],
      formal: ["cmd env BAP_FORMAL_OPTIONAL=1 scripts/run_formal.sh"],
      "spec_facts.mutations": ["run --no-start scripts/check_spec_facts_mutations.exs"],
      "license.check": [
        "cmd elixir scripts/check_dependency_licenses.exs artifacts/tooling.cdx.json"
      ],
      "package.check": ["run --no-start scripts/check_package.exs"],
      "release.candidate": ["run --no-start scripts/check_release_candidate.exs"],
      "sbom.generate": [
        &prepare_artifacts/1,
        "cmd mix run --no-start scripts/generate_sbom.exs --only prod --exclude-system-dependencies --classification library --schema 1.6 --format json --output artifacts/release.cdx.json --force",
        "cmd elixir scripts/prune_release_sbom.exs artifacts/release.cdx.json",
        "cmd mix run --no-start scripts/generate_sbom.exs --exclude-system-dependencies --classification library --schema 1.6 --format json --output artifacts/tooling.cdx.json --force"
      ],
      "sbom.check": [
        "cmd elixir scripts/check_sbom.exs artifacts/release.cdx.json artifacts/tooling.cdx.json"
      ],
      quality: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "architecture",
        "secrets",
        "privacy.hooks",
        "corpus.sync",
        "corpus.digests",
        "spec.facts",
        "spec.examples",
        "spec.render",
        "formal",
        "credo --strict",
        "verification.performance",
        "chain_archive.performance",
        "test --cover --seed 42",
        "dialyzer",
        "docs --warnings-as-errors",
        "docs.links",
        "audit",
        "package.check",
        "release.candidate",
        "chain_archive.mutations",
        "conformance.mutations",
        "conformance.verify",
        "local_loopback_http.verify",
        "role_attestation.verify",
        "content_assertion.verify",
        "content_assertion.mutations",
        "spec_facts.mutations"
      ]
    ]
  end

  defp prepare_artifacts(_args), do: File.mkdir_p!("artifacts")
end
