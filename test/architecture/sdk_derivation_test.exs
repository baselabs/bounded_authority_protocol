defmodule BoundedAuthorityProtocol.SdkDerivationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)
  @sdks [
    {"python", "purity_check.py", "python3", "src/bounded_authority_verifier/probe.py", "#"},
    {"rust", "purity_check.sh", "bash", "src/probe.rs", "//"},
    {"go", "purity_check.sh", "bash", "probe.go", "//"}
  ]
  @citations [
    {"lib/bounded_authority_protocol/v1/grant.ex", "reference source citation"},
    {"LIB\\BOUNDED_AUTHORITY_PROTOCOL", "reference source citation"},
    {"Lib/Bounded_Authority_Protocol", "reference source citation"},
    {"grant.ex", "reference source citation"},
    {"CHECK.EXS", "reference source citation"},
    {"mix.exs", "reference source citation"},
    {"V1.Selector.float_zero_free?/1", "reference function citation"},
    {"URI.new/1", "reference function citation"},
    {"URI.new/1.", "reference function citation"},
    {"URI.new?/1", "reference function citation"},
    {"URI.new!/1", "reference function citation"},
    {"Module.Nested.function/12", "reference function citation"},
    {"ContextValidation.historical_key/2", "reference function citation"},
    {"float_zero_free?/1", "reference function citation"},
    {"validate!/2", "reference function citation"},
    {"%TrustedIssuer{", "reference struct citation"},
    {"%BoundedAuthorityProtocol.V1.DecodedGrant{", "reference struct citation"},
    {"Elixir reference", "reference authority phrase"},
    {"ELIXIR REFERENCE", "reference authority phrase"},
    {"reference implementation", "reference authority phrase"},
    {"Reference Implementation", "reference authority phrase"},
    {"Elixir\nreference", "reference authority phrase"},
    {"reference\nimplementation", "reference authority phrase"}
  ]
  @allowed """
  BoundedAuthorityProtocol is the contract namespace (ex. in diagnostics).
  #BoundedAuthorityProtocol.V1.GrantFacts<redacted>
  n/2, s > n/2, a/b, https://example.test/URI.new/1, docs/URI.new/1
  C:\\docs\\URI.new/1, URI.new/1.md, reference verdict, cross-reference
  Derived from the spec and certified corpus, not from sibling-SDK or reference source (ADR 0014 D5).
  """
  @generated ~w(.git .venv __pycache__ .mypy_cache .pytest_cache .ruff_cache target dist build node_modules example.egg-info)

  test "all SDKs carry the same derivation rules" do
    blocks =
      for {sdk, checker, _, _, _} <- @sdks do
        text = File.read!(Path.join([@root, "sdks", sdk, "tools", checker]))
        [_, block] = Regex.run(~r/# BEGIN DERIVATION RULES\n(.*?)# END DERIVATION RULES/s, text)
        block
      end

    assert length(Enum.uniq(blocks)) == 1
  end

  test "top-level SDK documents satisfy the derivation rules" do
    for {sdk, checker, command, _, _} <- @sdks do
      path = Path.join([@root, "sdks", sdk, "tools", checker])
      assert {_, 0} = run(command, path, ["--derivation-top-level", Path.join(@root, "sdks")])
    end
  end

  for {sdk, checker, command, source, comment} <- @sdks do
    @sdk sdk
    @checker checker
    @command command
    @source source
    @comment comment

    test "#{sdk} derivation guard scans every authored location and rejects every citation class" do
      {root, checker} = scratch(@sdk, @checker, @source, @comment)
      File.write!(Path.join(root, "README.md"), @allowed)
      assert {_, 0} = run(@command, checker)

      paths = [
        @source,
        "tests/citation.txt",
        "tools/citation.txt",
        "docs/citation.md",
        "README.md",
        ".hidden/citation",
        "tools/#{@checker}"
      ]

      for path <- paths, {citation, message} <- @citations do
        plant(root, path, "\n#{@comment} #{citation}\n", fn ->
          {output, status} = run(@command, checker)
          assert status == 1, "#{@sdk} accepted #{citation} in #{path}: #{output}"
          assert output =~ "#{path}:"
          assert output =~ message
        end)
      end

      assert {_, 0} = run(@command, checker)
    end

    test "#{sdk} rendering exceptions use only exact fixture paths" do
      {root, checker} = scratch(@sdk, @checker, @source, @comment)
      directory = if @sdk == "go", do: "testdata", else: "tests/fixtures"

      for name <-
            ~w(decoded-rendering.json decoded-wire-rendering.json decoded-binary-rendering.json) do
        path = "#{directory}/#{name}"

        plant(root, path, "%BoundedAuthorityProtocol.V1.DecodedGrant{", fn ->
          assert {_, 0} = run(@command, checker)
        end)

        # Fixture exceptions cover notation only, never paths, functions, or authority claims.
        for {citation, message} <- @citations, message != "reference struct citation" do
          plant(root, path, citation, fn ->
            {output, status} = run(@command, checker)
            assert status == 1
            assert output =~ message
          end)
        end

        for other <- ["nested/#{path}", "#{directory}/stale-#{name}", "docs/#{name}"] do
          plant(root, other, "%BoundedAuthorityProtocol.V1.DecodedGrant{", fn ->
            {output, status} = run(@command, checker)
            assert status == 1
            assert output =~ "reference struct citation"
          end)
        end
      end
    end

    test "#{sdk} generated state is pruned consistently" do
      {root, checker} = scratch(@sdk, @checker, @source, @comment)

      for directory <- @generated do
        plant(root, "nested/#{directory}/citation.txt", "URI.new/1", fn ->
          assert {_, 0} = run(@command, checker)
        end)
      end
    end

    test "#{sdk} top-level scan rejects every citation class and ignores nested SDKs" do
      {root, checker} = scratch(@sdk, @checker, @source, @comment)
      File.write!(Path.join(root, "README.md"), @allowed)
      args = ["--derivation-top-level", root]
      assert {_, 0} = run(@command, checker, args)

      for {citation, message} <- @citations do
        plant(root, "README.md", citation, fn ->
          {output, status} = run(@command, checker, args)
          assert status == 1
          assert output =~ "README.md:"
          assert output =~ message
        end)
      end

      plant(root, "nested/citation.txt", "URI.new/1", fn ->
        assert {_, 0} = run(@command, checker, args)
      end)
    end
  end

  defp scratch(sdk, checker, source, comment) do
    root =
      Path.join(System.tmp_dir!(), "bap-derivation-#{sdk}-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(root) end)
    target = Path.join(root, "tools/#{checker}")
    File.mkdir_p!(Path.dirname(target))
    File.cp!(Path.join([@root, "sdks", sdk, "tools", checker]), target)
    File.mkdir_p!(Path.dirname(Path.join(root, source)))
    File.write!(Path.join(root, source), "#{comment} Pure source fixture\n")
    {root, target}
  end

  defp plant(root, relative, citation, check) do
    target = Path.join(root, relative)
    File.mkdir_p!(Path.dirname(target))
    original = File.read(target)

    contents =
      case original do
        {:ok, contents} -> contents
        {:error, :enoent} -> ""
      end

    try do
      File.write!(target, contents <> citation)
      check.()
    after
      case original do
        {:ok, contents} -> File.write!(target, contents)
        {:error, :enoent} -> File.rm!(target)
      end
    end
  end

  defp run(command, checker, args \\ []) do
    System.cmd(command, [checker | args], stderr_to_stdout: true)
  end
end
