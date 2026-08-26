defmodule BoundedAuthorityProtocol.Test.DurableIdentifierPolicy do
  @moduledoc false

  @owned_roots ["lib", "priv", "scripts", "sdks", "test", "test_support", "docs"]
  @requirement_surfaces ~w(B64 BOUNDS CHAIN CLAIM CORE DIGEST EVO EXPORT HEADER JSON LOCATOR SCHEMA SELECTOR SIGNING URI VERIFY)
  @wire_domains ~w(BAP1-ARCHIVE BAP1-CHAIN BAP1-GRANT BAP1-PROOF BAP1-REQUEST)
  @external_v1_paths MapSet.new([
                       "lib/bounded_authority_protocol/conformance/corpus.ex",
                       "lib/bounded_authority_protocol/conformance/report.ex",
                       "lib/bounded_authority_protocol/conformance/runner.ex",
                       "scripts/check_chain_archive_performance.exs",
                       "scripts/check_verification_performance.exs",
                       "scripts/check_spec_facts.exs",
                       "spec/tools/build_examples.exs",
                       "test/architecture/purity_test.exs",
                       "test/docs_guides_test.exs",
                       "test/spec_facts_test.exs"
                     ])
  @requirement_ids "test/fixtures/durable_identifier_requirements.txt"
                   |> File.read!()
                   |> String.split()
                   |> MapSet.new()
  @non_version_hump_stems [
    "B",
    "Base",
    "ED",
    "Ed",
    "HEX",
    "HTTP",
    "Hex",
    "Http",
    "IPV",
    "IPv",
    "Ipv",
    "RFC",
    "ROW",
    "Rfc",
    "S",
    "SHA",
    "SIG",
    "TLS",
    "UTF",
    "Tls",
    "Utf",
    "Z"
  ]

  def check(%{path: path, kind: kind, name: name}) do
    if contract_identity?(path, kind, name) do
      :ok
    else
      if lifecycle_bearing?(name),
        do: {:error, :implementation_lifecycle_identifier},
        else: :ok
    end
  end

  def owned_tree_findings do
    tracked = tracked_files()

    path_findings =
      for path <- tracked,
          Enum.any?(@owned_roots, &under_root?(path, &1)),
          segment <- Path.split(path),
          name = Path.rootname(segment),
          {:error, :implementation_lifecycle_identifier} <- [
            check(%{path: path, kind: :path, name: name})
          ],
          do: %{path: path, kind: :path, name: name}

    source_findings =
      for path <- tracked,
          Enum.any?(["lib", "scripts", "test", "test_support"], &under_root?(path, &1)),
          Path.extname(path) in [".ex", ".exs"],
          {kind, name} <- elixir_identifiers(path),
          {:error, :implementation_lifecycle_identifier} <- [
            check(%{path: path, kind: kind, name: name})
          ],
          do: %{path: path, kind: kind, name: name}

    sdk_findings =
      for path <- tracked,
          under_root?(path, "sdks"),
          Path.extname(path) in [".go", ".py", ".rs", ".ts"],
          {kind, name} <- sdk_identifiers(path),
          {:error, :implementation_lifecycle_identifier} <- [
            check(%{path: path, kind: kind, name: name})
          ],
          do: %{path: path, kind: kind, name: name}

    contract_findings =
      for observation <- contract_observations(),
          {:error, :implementation_lifecycle_identifier} <- [check(observation)],
          do: observation

    Enum.uniq(path_findings ++ source_findings ++ sdk_findings ++ contract_findings)
  end

  def contract_observations do
    tracked = tracked_files()

    elixir_modules =
      for path <- tracked,
          Path.extname(path) in [".ex", ".exs"],
          {kind, name} <- elixir_identifiers(path),
          kind in [:module, :external_wire_module],
          String.starts_with?(name, "BoundedAuthorityProtocol.V"),
          do: %{path: path, kind: kind, name: name}

    content =
      tracked
      |> Enum.filter(&contract_content_surface?/1)
      |> Enum.flat_map(fn path ->
        case File.read(path) do
          {:ok, source} -> content_observations(path, source)
          _ -> []
        end
      end)

    Enum.uniq(elixir_modules ++ content)
  end

  def check_source(path, source) do
    source
    |> identifiers_from_source(path)
    |> Enum.find_value(:ok, fn {kind, name} ->
      case check(%{path: path, kind: kind, name: name}) do
        :ok -> false
        error -> error
      end
    end)
  end

  defp tracked_files do
    {output, 0} =
      System.cmd("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])

    String.split(output, <<0>>, trim: true)
  end

  defp under_root?(path, root), do: path == root or String.starts_with?(path, root <> "/")

  defp contract_identity?("mix.exs", :package_source_ref, ~S(source_ref: "v#{@version}")),
    do: true

  defp contract_identity?(path, :wire_suite, "BAP1-Ed25519-SHA256"),
    do: contract_content_surface?(path)

  defp contract_identity?(path, :wire_domain, name),
    do: name in @wire_domains and contract_content_surface?(path)

  defp contract_identity?(path, :wire_field, ~s("v": 1)),
    do: contract_content_surface?(path)

  defp contract_identity?(path, :external_wire_module, "BoundedAuthorityProtocol.V1"),
    do: external_namespace_path?(path)

  defp contract_identity?("scripts/check_package.exs", :atom, "V1"), do: true

  defp contract_identity?(path, :requirement_id, name) do
    case Regex.run(~r/\AREQ1-([A-Z0-9]+)-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/, name) do
      [_, surface] ->
        contract_content_surface?(path) and surface in @requirement_surfaces and
          MapSet.member?(@requirement_ids, name)

      _ ->
        false
    end
  end

  defp contract_identity?(path, :path, name),
    do: current_major_path?(path, name)

  defp contract_identity?(path, :module, name) do
    ((name == "BoundedAuthorityProtocol.V1" or
        String.starts_with?(name, "BoundedAuthorityProtocol.V1.")) and
       current_major_source_path?(path)) or
      (name == "BoundedAuthorityProtocol.Conformance.V1SchemaTest" and
         path == "test/conformance/v1_schema_test.exs")
  end

  defp contract_identity?("sdks/rust/src/lib.rs", :sdk_identifier, "v1"), do: true

  defp contract_identity?(_path, _kind, _name), do: false

  defp current_major_path?(path, "v1"), do: current_major_source_path?(path)

  defp current_major_path?(path, name) do
    {path, name} in [
      {"docs/protocol-v1.md", "protocol-v1"},
      {"docs/adr/0002-normative-v1-parsing-profile.md", "0002-normative-v1-parsing-profile"},
      {"docs/adr/0021-v1-all-selector-recognized-shapes-erratum.md",
       "0021-v1-all-selector-recognized-shapes-erratum"},
      {"test/conformance/v1_schema_test.exs", "v1_schema_test"}
    ]
  end

  defp current_major_source_path?(path) do
    Regex.match?(~r"\Alib/bounded_authority_protocol/v1(?:\.ex|/)", path) or
      String.starts_with?(path, "test/bounded_authority_protocol/v1/") or
      String.starts_with?(path, "priv/conformance/v1/") or
      path in [
        "sdks/go/v1.go",
        "sdks/python/src/bounded_authority_verifier/v1.py",
        "sdks/rust/src/v1.rs",
        "sdks/typescript/src/v1.ts"
      ]
  end

  defp elixir_identifiers(path) do
    source = File.read!(path)
    identifiers_from_source(source, path)
  end

  defp identifiers_from_source(source, path) do
    ast = Code.string_to_quoted!(source, file: path)

    {_ast, acc} =
      ast
      |> strip_docs()
      |> Macro.prewalk([], &collect/2)

    {_ast, atoms} =
      ast
      |> strip_docs()
      |> strip_aliases()
      |> Macro.prewalk([], fn
        atom, names when is_atom(atom) and not is_boolean(atom) and not is_nil(atom) ->
          {atom, [{:atom, Atom.to_string(atom)} | names]}

        node, names ->
          {node, names}
      end)

    Enum.uniq(Enum.reverse(acc) ++ Enum.reverse(atoms))
  end

  defp strip_docs(ast) do
    Macro.prewalk(ast, fn
      {:@, _, [{doc, _, [_body]}]} when doc in [:moduledoc, :doc, :typedoc, :shortdoc] ->
        {:@, [], [{doc, [], [true]}]}

      other ->
        other
    end)
  end

  defp strip_aliases(ast) do
    Macro.prewalk(ast, fn
      {:__aliases__, _, _} -> {:alias_reference, [], []}
      other -> other
    end)
  end

  defp collect({kind, _, [name | _]} = node, acc)
       when kind in [:test, :describe] and is_binary(name),
       do: {node, [{:test_name, name} | acc]}

  defp collect({:defmodule, _, [{:__aliases__, _, segments} | _]} = node, acc)
       when is_list(segments),
       do: {node, [{:module, Enum.map_join(segments, ".", &Atom.to_string/1)} | acc]}

  defp collect({:__aliases__, _, segments} = node, acc) when is_list(segments) do
    if Enum.all?(segments, &is_atom/1) do
      collect_external_alias(node, segments, acc)
    else
      {node, acc}
    end
  end

  defp collect({kind, _, [{name, _, _} | _]} = node, acc)
       when kind in [:def, :defp, :defmacro, :defmacrop] and is_atom(name),
       do: {node, [{:function, Atom.to_string(name)} | acc]}

  defp collect(node, acc), do: {node, acc}

  defp collect_external_alias(node, segments, acc) do
    name = Enum.map_join(segments, ".", &Atom.to_string/1)

    case Regex.run(~r/\A(BoundedAuthorityProtocol\.V\d+)(?:\.|\z)/, name) do
      [_, namespace] -> {node, [{:external_wire_module, namespace} | acc]}
      _ -> {node, acc}
    end
  end

  defp sdk_identifiers(path) do
    source = File.read!(path)

    patterns = [
      ~r/^\s*(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)/m,
      ~r/^\s*(?:func\s+(?:\([^)]*\)\s*)?|type\s+)([A-Za-z_][A-Za-z0-9_]*)/m,
      ~r/^\s*(?:pub\s+)?(?:fn|struct|enum|mod|const)\s+([A-Za-z_][A-Za-z0-9_]*)/m,
      ~r/^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/m,
      ~r/^\s*(?:(?:public|private|protected|static|async)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;]*\)\s*(?:\{|:)/m
    ]

    for pattern <- patterns,
        [name] <- Regex.scan(pattern, source, capture: :all_but_first),
        name not in ["if", "for", "while", "switch", "catch"],
        do: {:sdk_identifier, name}
  end

  defp contract_content_surface?(path) do
    path == "mix.exs" or
      path == "usage-rules.md" or
      path == "docs/protocol-v1.md" or
      String.starts_with?(path, "docs/design/") or
      String.starts_with?(path, "lib/") or
      String.starts_with?(path, "priv/conformance/") or
      String.starts_with?(path, "scripts/") or
      String.starts_with?(path, "sdks/")
  end

  defp external_namespace_path?(path) do
    current_major_source_path?(path) or
      MapSet.member?(@external_v1_paths, path) or
      path == "scripts/check_package.exs" or
      String.starts_with?(path, "test/conformance/") or
      String.starts_with?(path, "test/property/") or
      String.starts_with?(path, "test/fuzz/")
  end

  defp content_observations(path, source) do
    package =
      Regex.scan(~r/source_ref:\s*"v(?:#\{@version\}|\d+)"/, source)
      |> Enum.map(fn [name] -> %{path: path, kind: :package_source_ref, name: name} end)

    suites =
      Regex.scan(~r/\bBAP\d+-Ed25519-SHA256\b/, source)
      |> Enum.map(fn [name] -> %{path: path, kind: :wire_suite, name: name} end)

    domains =
      Regex.scan(~r/\bBAP\d+-(?:ARCHIVE|CHAIN|GRANT|PROOF|REQUEST)\b/, source)
      |> Enum.map(fn [name] -> %{path: path, kind: :wire_domain, name: name} end)

    requirements =
      Regex.scan(
        ~r/\bREQ\d+-[A-Z0-9]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?![a-z0-9-])/,
        source
      )
      |> Enum.map(fn [name] -> %{path: path, kind: :requirement_id, name: name} end)

    wire_fields =
      Regex.scan(~r/"v"\s*:\s*(\d+)/, source, capture: :all_but_first)
      |> Enum.map(fn [major] -> %{path: path, kind: :wire_field, name: ~s("v": #{major})} end)

    package ++ suites ++ domains ++ requirements ++ wire_fields
  end

  defp lifecycle_bearing?(name) do
    Regex.match?(~r/(^|[._\/-])v\d/i, name) or
      Regex.match?(~r/[a-z0-9]V\d/, name) or
      Regex.match?(~r/(^|[^A-Za-z0-9])BAP[-_]?\d+[A-Za-z]?(?=$|[^A-Za-z0-9])/i, name) or
      Regex.match?(
        ~r/(^|[^A-Za-z0-9])(?:phase|task|slice|sprint|step|work[-_ ]?order)[-_ ]?\d+[A-Za-z]?(?=$|[^A-Za-z0-9])/i,
        name
      ) or
      Regex.match?(
        ~r/(^|[^A-Za-z0-9])[TQFCDBNWR]\d+[A-Za-z]?(?:\.\d+[A-Za-z]?)?(?=$|[^A-Za-z0-9])/,
        name
      ) or
      Regex.match?(~r/§\d+/, name) or
      Regex.match?(~r/\bsource_ref\b.*\bv(?:#\{@version\}|\d)/i, name) or
      version_hump_digit?(name)
  end

  defp version_hump_digit?(name) do
    ~r/[A-Z]+[a-z]*\d+/
    |> Regex.scan(name)
    |> Enum.map(fn [word] -> Regex.replace(~r/\d+\z/, word, "") end)
    |> Enum.any?(&(&1 not in @non_version_hump_stems))
  end
end
