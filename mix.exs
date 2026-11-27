defmodule BoundedAuthorityProtocol.MixProject do
  use Mix.Project

  @version "1.1.0"
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
      docs: qualified_docs(docs(), System.get_env("HEX_DOCS_SOURCE_REF")),
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
      # Files under test/fixtures/ belong to generated consumer projects, not this suite.
      test_ignore_filters: [&String.starts_with?(&1, "test/fixtures/")],
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
        "corpus.verdicts": :test,
        "corpus.distribution.mutations": :test,
        "license.check": :test,
        "package.check": :test,
        quality: :test,
        "quality.source": :test,
        "quality.corpus": :test,
        "quality.tests": :test,
        "quality.conformance": :test,
        "quality.mutations": :test,
        "quality.package": :test,
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
        "TRADEMARKS.md",
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
        "docs/design/holder-custody-attestation-requirement-map.md",
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
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Security policy" => "#{@source_url}/blob/main/SECURITY.md"
      }
    ]
  end

  # Release qualification builds the HTML docs with source links to the qualified commit.
  defp qualified_docs(docs, nil), do: docs

  defp qualified_docs(docs, source_ref),
    do: Keyword.merge(docs, source_ref: source_ref, formatters: ["html"])

  # HexDocs reading path: start here, then guides, then reference, then the normative specs.
  # The extras order is the sidebar order inside each group.
  defp docs do
    [
      main: "readme",
      assets: %{"spec/profiles" => "profiles"},
      source_ref: "v#{@version}",
      source_url: @source_url,
      # The API stability page names the excluded internals; they are hidden, so never link them.
      skip_code_autolink_to: [
        "BoundedAuthorityProtocol.DiagnosticRendering",
        "BoundedAuthorityProtocol.V1.Runtime",
        "BoundedAuthorityProtocol.V2.Runtime",
        "BoundedAuthorityProtocol.V3.Runtime",
        "BoundedAuthorityProtocol.Conformance.Corpus",
        "BoundedAuthorityProtocol.Conformance.Runner",
        "BoundedAuthorityProtocol.Conformance.Report",
        "BoundedAuthorityProtocol.Conformance.Candidate",
        "BoundedAuthorityProtocol.Conformance.Cli.Main",
        "BoundedAuthorityProtocol.HolderCustodyAttestation.V1.Codec",
        "BoundedAuthorityProtocol.V1.Jwk.thumbprint_digest_unchecked/1",
        "BoundedAuthorityProtocol.V1.Json.decode_approval_record/3",
        "BoundedAuthorityProtocol.V1.Jcs.encode_approval_record/4",
        "BoundedAuthorityProtocol.V1.Jcs.escaped_string_bytes/2",
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
        "README.md",
        "docs/guides/getting-started.md",
        "docs/guides/choosing-a-profile.md",
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
        "docs/guides/recipes.md",
        "docs/guides/testing-your-integration.md",
        "docs/guides/troubleshooting.md",
        "docs/guides/evidence.md",
        "docs/notebooks/bap-walkthrough.livemd",
        "docs/notebooks/chains-and-archives.livemd",
        "docs/notebooks/content-lineage.livemd",
        "docs/notebooks/local-loopback.livemd",
        "docs/notebooks/role-attestations.livemd",
        "docs/notebooks/service-integration.livemd",
        "docs/notebooks/strict-crypto.livemd",
        "docs/notebooks/range-selectors.livemd",
        "docs/notebooks/es256-signing.livemd",
        "docs/guides/cheatsheet.cheatmd",
        "docs/guides/api-stability.md",
        "docs/guides/glossary.md",
        "docs/guides/faq.md",
        "docs/guides/upgrading.md",
        "docs/guides/other-languages.md",
        "usage-rules.md",
        "docs/deployment/go-sdk.md",
        "docs/deployment/python-sdk.md",
        "docs/deployment/rust-sdk.md",
        "docs/deployment/typescript-sdk.md",
        "docs/guides/implementers-guide.md",
        "spec/bap-content-assertion-v1.md",
        "spec/bap-content-assertion-es256-v1.md",
        "spec/bap-action-approval-v1.md",
        "spec/bap-local-loopback-http-v1.md",
        "spec/bap-role-attestation-v1.md",
        "spec/bap-holder-custody-attestation-v1.md",
        "spec/bap-v1.md",
        "spec/bap-v2.md",
        "spec/bap-v3.md",
        "spec/diagnostic-rendering.md",
        "docs/design/conformance-contract.md",
        "docs/design/content-assertion-requirement-map.md",
        "docs/design/corpus-verdict-digests.md",
        {"docs/design/iana/README.md", filename: "iana-registrations"},
        "docs/design/iana/jwt-claims.md",
        "docs/design/iana/media-types.md",
        "docs/design/interoperability-report.md",
        "docs/design/local-loopback-http-requirement-map.md",
        "docs/design/protocol-charter.md",
        "docs/design/registries.md",
        "docs/design/requirement-map.md",
        "docs/design/role-attestation-requirement-map.md",
        "docs/design/holder-custody-attestation-requirement-map.md",
        "docs/design/standards-track.md",
        "docs/design/successor-major-charter.md",
        "docs/design/threat-model.md",
        "docs/standards/submissions.md",
        "docs/governance.md",
        "docs/errata.md",
        {"docs/guides/README.md", filename: "guides-index"},
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "IPR.md",
        "TRADEMARKS.md",
        "CODE_OF_CONDUCT.md",
        "LICENSE",
        "NOTICE"
      ],
      groups_for_extras: [
        Start: [
          "README.md",
          "docs/guides/getting-started.md",
          "docs/guides/choosing-a-profile.md",
          "docs/guides/notebooks.md"
        ],
        Concepts: [
          "docs/guides/grants-and-holder-proofs.md",
          "docs/guides/trusted-keys-and-rotation.md",
          "docs/guides/tagged-arguments-and-selectors.md",
          "docs/guides/nonce-and-time-policy.md",
          "docs/guides/facts-and-authorization.md"
        ],
        "Integrate and operate": [
          "docs/guides/framework-integration.md",
          "docs/guides/integration-security.md",
          "docs/guides/operations.md",
          "docs/guides/observability.md",
          "docs/guides/errors.md",
          "docs/guides/recipes.md",
          "docs/guides/testing-your-integration.md",
          "docs/guides/troubleshooting.md"
        ],
        "Profiles and evidence": [
          "docs/guides/evidence.md"
        ],
        Notebooks: [
          "docs/notebooks/bap-walkthrough.livemd",
          "docs/notebooks/chains-and-archives.livemd",
          "docs/notebooks/content-lineage.livemd",
          "docs/notebooks/local-loopback.livemd",
          "docs/notebooks/role-attestations.livemd",
          "docs/notebooks/service-integration.livemd",
          "docs/notebooks/strict-crypto.livemd",
          "docs/notebooks/range-selectors.livemd",
          "docs/notebooks/es256-signing.livemd"
        ],
        Reference: [
          "docs/guides/cheatsheet.cheatmd",
          "docs/guides/api-stability.md",
          "docs/guides/glossary.md",
          "docs/guides/faq.md",
          "docs/guides/upgrading.md",
          "docs/guides/other-languages.md",
          "usage-rules.md",
          "docs/deployment/go-sdk.md",
          "docs/deployment/python-sdk.md",
          "docs/deployment/rust-sdk.md",
          "docs/deployment/typescript-sdk.md"
        ],
        Implementers: [
          "docs/guides/implementers-guide.md",
          "spec/bap-content-assertion-v1.md",
          "spec/bap-content-assertion-es256-v1.md",
          "spec/bap-action-approval-v1.md",
          "spec/bap-local-loopback-http-v1.md",
          "spec/bap-role-attestation-v1.md",
          "spec/bap-holder-custody-attestation-v1.md",
          "spec/bap-v1.md",
          "spec/bap-v2.md",
          "spec/bap-v3.md",
          "spec/diagnostic-rendering.md",
          "docs/design/conformance-contract.md",
          "docs/design/content-assertion-requirement-map.md",
          "docs/design/corpus-verdict-digests.md",
          "docs/design/iana/README.md",
          "docs/design/iana/jwt-claims.md",
          "docs/design/iana/media-types.md",
          "docs/design/interoperability-report.md",
          "docs/design/local-loopback-http-requirement-map.md",
          "docs/design/protocol-charter.md",
          "docs/design/registries.md",
          "docs/design/requirement-map.md",
          "docs/design/role-attestation-requirement-map.md",
          "docs/design/holder-custody-attestation-requirement-map.md",
          "docs/design/standards-track.md",
          "docs/design/successor-major-charter.md",
          "docs/design/threat-model.md",
          "docs/standards/submissions.md"
        ],
        Project: [
          "docs/governance.md",
          "docs/errata.md",
          "docs/guides/README.md",
          "CHANGELOG.md",
          "SECURITY.md",
          "CONTRIBUTING.md",
          "IPR.md",
          "TRADEMARKS.md",
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
          ~r"^BoundedAuthorityProtocol\.HolderCustodyAttestation\.",
          ~r"^BoundedAuthorityProtocol\.ContentAssertion\.",
          ~r"^BoundedAuthorityProtocol\.ActionApproval\."
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
        ~r"^BoundedAuthorityProtocol\.((ApplicationProfile\.LocalLoopbackHttp|RoleAttestation|HolderCustodyAttestation|ContentAssertion(\.ES256)?|ActionApproval)\.)?V\d$"

  defp aliases do
    [
      architecture: [
        "compile --warnings-as-errors",
        "run --no-start scripts/check_architecture.exs"
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
        "cmd ./bounded_authority_conformance --corpus priv/conformance/string-or-uri",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/application-profiles/local-loopback-http/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/role-attestation/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/content-assertion/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/content-assertion-es256/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/attestation-profiles/holder-custody-attestation/v1",
        "cmd ./bounded_authority_conformance --corpus priv/conformance/content-profiles/action-approval/v1"
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
      "corpus.verdicts": [
        "run --no-start scripts/regen_verdict_digests.exs",
        "cmd mix test test/conformance/verdict_digests_test.exs test/conformance/verdict_digest_gate_test.exs"
      ],
      "corpus.generators": [
        "cmd node conformance/generators/build_corpus.mjs --verify --major 1",
        "cmd node conformance/generators/build_corpus.mjs --verify --major 2",
        "cmd node conformance/generators/build_corpus.mjs --verify --major 3",
        "cmd node conformance/generators/build_strict_ed25519.mjs --verify",
        "cmd node conformance/generators/build_producer_canonicality.mjs --verify",
        "cmd node conformance/generators/build_selector_float_zero.mjs --verify",
        "cmd python3 scripts/build_content_assertion_corpus.py --verify",
        "cmd uv sync --project sdks/python --locked --no-dev --no-install-project",
        "cmd uv run --project sdks/python --no-sync python scripts/build_approval_corpora.py --verify",
        "cmd uv run --project sdks/python --no-sync python -B scripts/build_holder_custody_corpus.py --verify"
      ],
      "corpus.distribution.mutations": [
        "cmd mix test test/corpus_tooling_test.exs",
        "cmd python3 scripts/check_corpus_distribution_mutations.py"
      ],
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
      "quality.source": [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "architecture",
        "secrets",
        "privacy.hooks",
        "spec.facts",
        "spec.examples",
        "spec.render",
        "formal",
        "credo --strict",
        "dialyzer",
        "docs --warnings-as-errors",
        "docs.links"
      ],
      "quality.corpus": [
        "corpus.sync",
        "corpus.digests",
        "corpus.verdicts",
        "corpus.generators",
        "corpus.distribution.mutations"
      ],
      "quality.tests": [
        "verification.performance",
        "chain_archive.performance",
        "test --cover --seed 42"
      ],
      "quality.conformance": [
        "conformance.verify",
        "local_loopback_http.verify",
        "role_attestation.verify",
        "content_assertion.verify",
        "cmd mix test test/bounded_authority_protocol/action_approval/corpus_test.exs --seed 42",
        "conformance.mutations"
      ],
      "quality.mutations": [
        "chain_archive.mutations",
        "content_assertion.mutations",
        "run --no-start scripts/check_approval_mutations.exs",
        "spec_facts.mutations"
      ],
      "quality.package": [
        "audit",
        "package.check",
        "release.candidate"
      ],
      quality: [
        "quality.source",
        "quality.corpus",
        "quality.tests",
        "quality.conformance",
        "quality.mutations",
        "quality.package"
      ]
    ]
  end

  defp prepare_artifacts(_args), do: File.mkdir_p!("artifacts")
end
