Code.require_file("../test_support/documentation.ex", __DIR__)
System.put_env("BAP_LIVEBOOK_NO_MAIN", "1")
Code.require_file("../scripts/check_livebooks.exs", __DIR__)
System.delete_env("BAP_LIVEBOOK_NO_MAIN")

defmodule BoundedAuthorityProtocol.DocumentationContractTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.Documentation
  alias BoundedAuthorityProtocol.LivebookCheck

  test "every docs page is generated or excluded with a specific reason" do
    extras = Enum.map(Mix.Project.config()[:docs][:extras], &extra_path/1)
    exclusions = File.read!("docs/exdoc-exclusions.json") |> :json.decode()
    pages = Path.wildcard("docs/**/*.{md,cheatmd,livemd,mdx}")

    included = Enum.filter(extras, &String.starts_with?(&1, "docs/"))
    assert Enum.sort(pages) == Enum.sort(included ++ Map.keys(exclusions))

    for {path, reason} <- exclusions do
      assert File.regular?(path)
      assert is_binary(reason) and byte_size(reason) >= 30
      refute path in extras
    end

    groups = Mix.Project.config()[:docs][:groups_for_extras]

    assert Enum.map(groups, fn {name, _} -> to_string(name) end) == [
             "Start",
             "Concepts",
             "Integrate and operate",
             "Profiles and evidence",
             "Notebooks",
             "Reference",
             "Implementers",
             "Project"
           ]

    assert Enum.sort(Enum.flat_map(groups, &elem(&1, 1))) == Enum.sort(extras)
    assert "IPR.md" in extras
    assert "TRADEMARKS.md" in extras
    assert File.read!("README.md") =~ "](TRADEMARKS.md)"
    assert byte_size(File.read!("README.md")) < 50_000
  end

  test "the protocol and SDK ports identify their steward and link their IP statements" do
    products = [
      {".", "Bounded Authority Protocol (bounded_authority_protocol)"},
      {"sdks/go", "github.com/baselabs/bounded_authority_protocol_go"},
      {"sdks/python", "bounded-authority-protocol-verifier"},
      {"sdks/rust", "bounded-authority-protocol"}
    ]

    for {directory, product} <- products do
      notice_header = """
      #{product}
      Copyright 2026 BaseLabs Holdings LLC

      This product includes software developed by BaseLabs Holdings LLC
      (https://github.com/baselabs).
      """

      assert String.starts_with?(File.read!(Path.join(directory, "NOTICE")), notice_header)

      assert File.read!(Path.join(directory, "LICENSE")) =~
               "   Copyright 2026 BaseLabs Holdings LLC\n"

      assert File.read!(Path.join(directory, "README.md")) =~
               "](IPR.md) for contributions and use of the name."
    end

    contributing = File.read!("CONTRIBUTING.md")
    assert contributing =~ "Developer Certificate of Origin sign-off (`git commit -s`)"
    assert contributing =~ "](IPR.md)."
  end

  test "CommonMark sample discovery handles nested, indented and longer fences" do
    source = """
    ~~~elixir
    1 + 1
    ~~~

    > ````elixir
    > :ok
    > ````

        :indented
    """

    assert [{"elixir", first}, {"elixir", second}, {"", third}] = Documentation.blocks(source)
    assert String.trim(first) == "1 + 1"
    assert String.trim(second) == ":ok"
    assert String.trim(third) == ":indented"
  end

  test "every relative source link and heading anchor resolves" do
    failures =
      for path <- surfaces(),
          href <- links(path),
          error <- link_errors(path, href),
          do: error

    assert failures == [], Enum.join(failures, "\n")
    assert link_errors("README.md", "docs/no-such-document.md") != []
    assert link_errors("README.md", "README.md#no-such-anchor") != []
  end

  @tag :git_history
  test "release launch URLs name notebooks present at their release tag or candidate HEAD" do
    version = Mix.Project.config()[:version]
    release_ref = "baselabs_bounded_authority_protocol-v#{version}"
    tag = "refs/tags/#{release_ref}"

    # Publication refuses an existing tag; before publication HEAD is the tree it will name.
    {_output, tag_status} = System.cmd("git", ["rev-parse", "-q", "--verify", "#{tag}^{commit}"])

    {source_ref, source_case} =
      if tag_status == 0 do
        {tag, "release tag #{release_ref}"}
      else
        {"HEAD", "untagged release candidate #{release_ref} at HEAD"}
      end

    paths = ["README.md" | Path.wildcard("docs/notebooks/**/*.livemd")]

    for path <- paths do
      launches = Regex.scan(~r{https://livebook.dev/run\?url=([^)\s]+)}, File.read!(path))
      assert launches != [], "#{path} needs a launch URL"

      for [_, encoded] <- launches do
        uri = encoded |> URI.decode() |> URI.parse()
        assert uri.host == "github.com"

        assert ["", "baselabs", "bounded_authority_protocol", "blob", ref | file] =
                 String.split(uri.path, "/")

        assert ref == release_ref, "#{path}: expected #{release_ref} URL for #{source_case}"
        target = Enum.join(file, "/")
        assert Path.extname(target) == ".livemd", "#{path}: non-notebook URL for #{source_case}"

        if Path.extname(path) == ".livemd" do
          assert target == path, "#{path}: launch must name its own notebook for #{source_case}"
        end

        {output, status} =
          System.cmd("git", ["cat-file", "-e", "#{source_ref}:#{target}"], stderr_to_stdout: true)

        assert status == 0,
               "#{path}: missing import #{source_ref}:#{target} (#{source_case}): #{output}"
      end
    end
  end

  test "every notebook installs the exact registry version and is directly linked" do
    version = Mix.Project.config()[:version]
    index = File.read!("docs/guides/notebooks.md")

    for {name, entry} <- LivebookCheck.registry!(File.cwd!()) do
      path = "docs/notebooks/#{name}"
      source = File.read!(path)
      assert entry["release_launch"] == name
      assert source =~ ~s|Mix.install([{:bounded_authority_protocol, "== #{version}"}])|
      assert source =~ ~s(<!-- livebook:{"persist_outputs":true} -->)
      assert LivebookCheck.parse!(source, entry["outputs"]) != []
      assert File.read!("README.md") =~ "(#{path})"
      assert File.read!("docs/guides/getting-started.md") =~ "(../notebooks/#{name})"
      assert path in Enum.map(Mix.Project.config()[:docs][:extras], &extra_path/1)

      native_cells = for {"elixir", code} <- Documentation.blocks(source), do: code
      assert length(native_cells) == entry["outputs"]

      row =
        index
        |> String.split("\n")
        |> Enum.find(&String.contains?(&1, "(../notebooks/#{name})"))

      assert row, "#{name}: missing notebook index row"
      assert String.ends_with?(row, "| #{entry["outputs"]} |"), "#{name}: stale output count"
    end
  end

  test "each notebook step has a heading, explanation, and one executable cell" do
    for {name, _entry} <- LivebookCheck.registry!(File.cwd!()) do
      source = File.read!("docs/notebooks/#{name}")
      [introduction | steps] = String.split(source, ~r/^## /m)
      refute Enum.any?(Documentation.blocks(introduction), &(elem(&1, 0) == "elixir"))
      assert steps != []

      for step <- steps do
        [heading, body] = String.split(step, "\n", parts: 2)
        location = "#{name}: #{heading}"

        assert [{"elixir", _code}] =
                 Enum.filter(Documentation.blocks(body), &(elem(&1, 0) == "elixir"))

        [explanation | _] = String.split(body, "```elixir", parts: 2)
        refute String.trim(explanation) == "", "#{location}: explain the step before the cell"
      end
    end
  end

  test "native SDK samples and manifests cannot escape their execution jobs" do
    native =
      for path <- surfaces(),
          {language, code} <- Documentation.blocks(File.read!(path)),
          language in ["python", "go", "rust", "toml"],
          do: {path, language, code}

    for {path, language, _code} <- native do
      expected =
        if language == "toml",
          do: "docs/deployment/rust-sdk.md",
          else: "sdks/#{language}/README.md"

      assert path == expected, "#{path}: #{language} sample needs an executing consumer"
    end

    for language <- ["go", "rust"] do
      assert [{_, ^language, _}] = Enum.filter(native, &(elem(&1, 1) == language))
    end

    python_readme = File.read!("sdks/python/README.md")
    sample_pattern = ~r/<!-- (sdk-\S+) -->\s*```python\n(.*?)\n```/s

    assert [["sdk-quickstart:python", quickstart], ["sdk-example:action-approval", approval]] =
             Regex.scan(sample_pattern, python_readme, capture: :all_but_first)

    python_samples = for {_, "python", code} <- native, do: String.trim_trailing(code)
    assert python_samples == Enum.map([quickstart, approval], &String.trim_trailing/1)

    assert length(Enum.filter(native, &(elem(&1, 1) == "toml"))) == 2
    workflow = File.read!(".github/workflows/sdks.yml")

    for sdk <- ["go", "rust"] do
      assert workflow =~ "scripts/check_sdk_install.py #{sdk}"
    end

    python_steps = YamlElixir.read_from_string!(workflow)["jobs"]["sdks-conformance"]["steps"]
    candidate_suite = "python -m pytest -c sdks/python/pyproject.toml sdks/python/candidate -q"
    assert Enum.any?(python_steps, &(&1["run"] == "python scripts/check_sdk_install.py python"))
    assert Enum.any?(python_steps, &(&1["run"] == candidate_suite))

    candidate = File.read!("sdks/python/candidate/test_approval_example.py")
    assert candidate =~ ~s{block(readme, "sdk-example:action-approval", "python")}
    assert candidate =~ "exec(source, inputs)"

    runner = File.read!("scripts/check_sdk_install.py")
    assert runner =~ ~s{[("path", None)] if sdk == "rust"}
    assert runner =~ ~s(os.environ["GITHUB_SHA"])
    assert runner =~ "tomllib.loads(manifest)"
    assert runner =~ "direct_url.json"
  end

  test "local notebooks qualify; published notebooks run after upload without a key" do
    jobs = YamlElixir.read_from_file!(".github/workflows/ci.yml")["jobs"]
    local = jobs["livebooks-local"]
    assert "livebooks-local" in jobs["qualified"]["needs"]
    assert local["runs-on"] == "ubuntu-24.04"
    assert Enum.any?(local["steps"], &(&1["run"] == "elixir scripts/check_livebooks.exs --local"))

    # Qualification never installs this package from Hex: a version commit names a
    # version Hex does not serve yet, so it could never land.
    refute File.read!(".github/workflows/ci.yml") =~ "--published"

    publish = YamlElixir.read_from_file!(".github/workflows/publish.yml")["jobs"]
    published = publish["published-livebooks"]
    assert published["needs"] == "read-back"
    assert published["if"] == publish["upload"]["if"]

    checkout =
      Enum.find(published["steps"], &String.starts_with?(&1["uses"] || "", "actions/checkout@"))

    assert checkout["with"]["ref"] == "${{ inputs.release_commit }}"
    assert published["runs-on"] == "ubuntu-24.04"
    refute Map.has_key?(published, "environment")
    refute inspect(published) =~ "secrets."

    assert Enum.any?(
             published["steps"],
             &(&1["run"] == "elixir scripts/check_livebooks.exs --published")
           )
  end

  test "result-family descriptions follow the compiled public specifications" do
    modules = [
      BoundedAuthorityProtocol.V1,
      BoundedAuthorityProtocol.V2,
      BoundedAuthorityProtocol.V3,
      BoundedAuthorityProtocol.V1.Json,
      BoundedAuthorityProtocol.V1.Jcs,
      BoundedAuthorityProtocol.V1.Bounds,
      BoundedAuthorityProtocol.V1.Base64Url,
      BoundedAuthorityProtocol.V1.Uri,
      BoundedAuthorityProtocol.V1.Jwk,
      BoundedAuthorityProtocol.V3.EcJwk,
      BoundedAuthorityProtocol.Ed25519,
      BoundedAuthorityProtocol.Es256,
      BoundedAuthorityProtocol.RoleAttestation.V1,
      BoundedAuthorityProtocol.HolderCustodyAttestation.V1,
      BoundedAuthorityProtocol.ContentAssertion.V1,
      BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1
    ]

    for module <- modules do
      {:docs_v1, _, _, _, _, _, docs} = Code.fetch_docs(module)
      {:ok, specs} = Code.Typespec.fetch_specs(module)

      for {{:function, name, arity}, _, _, %{"en" => _}, _} <- docs do
        {{^name, ^arity}, alternatives} = List.keyfind(specs, {name, arity}, 0)

        signature =
          Enum.map_join(
            alternatives,
            "\n",
            &(Code.Typespec.spec_to_quoted(name, &1) |> Macro.to_string())
          )

        cond do
          module == BoundedAuthorityProtocol.V1.Bounds and name == :maximum ->
            refute signature =~ "{:error,"

          module in [BoundedAuthorityProtocol.Ed25519, BoundedAuthorityProtocol.Es256] and
              name not in [:normalize_low_s, :der_to_raw] ->
            assert signature =~ "boolean()"

          name == :verify_successor ->
            assert signature =~ ":ok | {:error, :invalid}"
            refute signature =~ "{:ok,"

          true ->
            assert signature =~ "{:ok,"
            assert signature =~ "{:error, :invalid}"

            errors = Regex.scan(~r/\{:error,\s*([^}]+)\}/, signature, capture: :all_but_first)
            assert Enum.uniq(List.flatten(errors)) == [":invalid"]
        end
      end
    end

    for path <- [
          "README.md",
          "lib/bounded_authority_protocol.ex",
          "docs/guides/api-stability.md",
          "docs/guides/faq.md"
        ] do
      text = File.read!(path)
      assert text =~ "verify_successor/3", path
      assert text =~ ":ok", path
      assert text =~ ~r/boolean/i, path
    end
  end

  test "the errors reference covers the complete CLI closed set and public protocol error" do
    source = File.read!("lib/bounded_authority_protocol/conformance/cli.ex")
    [_, messages] = Regex.run(~r/@messages %\{(.*?)\n  \}/s, source)
    actual = Regex.scan(~r/^\s+(\w+):/m, messages, capture: :all_but_first) |> List.flatten()
    reference = File.read!("docs/guides/errors.md")

    documented =
      Regex.scan(~r/^\| `:(\w+)` \|/m, reference, capture: :all_but_first) |> List.flatten()

    assert Enum.sort(actual) == Enum.sort(documented)
    assert reference =~ "`{:error, :invalid}`"
    assert reference =~ "`false`"
    assert reference =~ "`Bounds.maximum/0`"
    assert reference =~ "producer"
    assert reference =~ "archive"
    assert reference =~ "Local-loopback"
  end

  test "deployment, SDK and site claims stay current with their source contracts" do
    python = File.read!("docs/deployment/python-sdk.md")
    readme = File.read!("sdks/python/README.md")

    for text <- [python, readme] do
      assert text =~ "slotted"
      assert text =~ "read-only"
      assert text =~ "redacted"
      refute text =~ "prints every field"
    end

    [_, go] = Regex.run(~r/^go (\d+\.\d+)$/m, File.read!("sdks/go/go.mod"))
    go_readme = File.read!("sdks/go/README.md")
    assert go_readme =~ "Go **#{go}** or later"
    assert go_readme =~ "exactly Go **#{go}.0**"
    refute File.read!("sdks/README.md") =~ "## Known gaps"
    assert File.read!("docs/deployment/typescript-sdk.md") =~ "bap-selector-float-zero/1"
    assert File.read!("docs/deployment/typescript-sdk.md") =~ "161"
    refute File.read!("CHANGELOG.md") =~ "90-minute"
    site = File.read!("site/index.html")
    version = Mix.Project.config()[:version]
    assert site =~ "https://hexdocs.pm/bounded_authority_protocol/#{version}/"
    assert site =~ "getting-started.html"
    assert site =~ "livebook.dev/run"
    refute site =~ "the Elixir reference"
    assert site =~ "Holder-side"

    security = File.read!("SECURITY.md")
    assert security =~ "kci/"
    assert security =~ ~r/source commit/i
    assert security =~ "gh attestation verify"
  end

  test "registration material stays with implementers and describes registrations precisely" do
    implementers = Keyword.fetch!(Mix.Project.config()[:docs][:groups_for_extras], :Implementers)

    for path <- Path.wildcard("docs/design/iana/*.md") do
      assert path in implementers
    end

    for path <- surfaces() ++ ["CHANGELOG.md"] ++ Path.wildcard("spec/*.md") do
      refute File.read!(path) =~ ~r/\b(?:patents?|filings?|filed|ready[- ]to[- ]file)\b/i, path
    end
  end

  defp extra_path({path, _options}), do: path
  defp extra_path(path), do: path

  defp surfaces do
    root_pages = [
      "README.md",
      "SECURITY.md",
      "CONTRIBUTING.md",
      "IPR.md",
      "TRADEMARKS.md",
      "usage-rules.md",
      "sdks/README.md"
    ]

    (root_pages ++
       Path.wildcard("docs/**/*.{md,cheatmd,livemd}") ++
       Path.wildcard("sdks/*/{README,IPR}.md"))
    |> Enum.sort()
  end

  defp links(path) do
    {_status, ast, _messages} = EarmarkParser.as_ast(File.read!(path))
    collect_links(ast)
  end

  defp collect_links(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &collect_links/1)

  defp collect_links({tag, attributes, children, _}) when tag in ["a", "img"] do
    key = if tag == "a", do: "href", else: "src"
    value = List.keyfind(attributes, key, 0, {key, ""}) |> elem(1)
    [value | collect_links(children)]
  end

  defp collect_links({_tag, _attributes, children, _}), do: collect_links(children)
  defp collect_links(_), do: []

  defp link_errors(path, href) do
    uri = URI.parse(href)

    if uri.scheme || uri.host || String.starts_with?(href, "/"),
      do: [],
      else: relative_link_errors(path, href, uri)
  end

  defp relative_link_errors(path, href, uri) do
    target =
      if uri.path in [nil, ""],
        do: path,
        else: Path.expand(URI.decode(uri.path), Path.dirname(Path.expand(path)))

    cond do
      not File.exists?(target) -> ["#{path}: missing relative link #{href}"]
      missing_anchor?(target, uri.fragment) -> ["#{path}: missing anchor #{href}"]
      true -> []
    end
  end

  defp missing_anchor?(_target, nil), do: false

  defp missing_anchor?(target, fragment),
    do:
      Path.extname(target) in [".md", ".cheatmd", ".livemd"] and
        URI.decode(fragment) not in anchors(target)

  defp anchors(path) do
    source = File.read!(path)
    {_status, ast, _messages} = EarmarkParser.as_ast(source)
    headings = headings(ast)

    {slugs, _counts} =
      Enum.map_reduce(headings, %{}, fn heading, counts ->
        base =
          heading
          |> String.downcase()
          |> String.replace(~r/[^\p{L}\p{N}_\s-]/u, "")
          |> String.replace(~r/\s/u, "-")

        number = Map.get(counts, base, 0)
        slug = if number == 0, do: base, else: "#{base}-#{number}"
        {slug, Map.put(counts, base, number + 1)}
      end)

    explicit =
      Regex.scan(~r/(?:id|name)="([^"]+)"/, source, capture: :all_but_first) |> List.flatten()

    slugs ++ explicit
  end

  defp headings(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &headings/1)

  defp headings({tag, _, children, _}) when tag in ["h1", "h2", "h3", "h4", "h5", "h6"],
    do: [plain(children)]

  defp headings({_tag, _, children, _}), do: headings(children)
  defp headings(_), do: []

  defp plain(nodes) when is_list(nodes), do: Enum.map_join(nodes, &plain/1)
  defp plain({_tag, _, children, _}), do: plain(children)
  defp plain(text) when is_binary(text), do: text
end
