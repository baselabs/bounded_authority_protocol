Code.require_file("../test_support/documentation.ex", __DIR__)

defmodule BoundedAuthorityProtocol.DocsSamplesTest do
  @moduledoc """
  Runs the README quickstart and protocol-only guide blocks in order against this package,
  pinning each block's final value. Recipes run separately in DocsConsumerTest with real Plug.
  Dependency blocks (`deps`) are project configuration and are exercised by the fresh consumer.

  The prose is checked too: after each block, the text before the next block must state the
  block's value as "The value is `TERM`", "The final value is `TERM`", "The result is `TERM`",
  or, for a list, "Each entry is `TERM`". Each stated term is evaluated and compared with the
  block's actual value, so a renamed function, a changed struct field, a moved verdict, or a
  stale sentence reds here with the document named.
  """

  use ExUnit.Case, async: true

  @invalid {:error, :invalid}

  test "the README quickstart runs and ends with the redacted envelope facts" do
    assert values("README.md") == [{"publish_article", :not_evaluated}]
    assert claim_errors("README.md", File.read!("README.md")) == []
  end

  test "the README approval example runs against durable host and destination stores" do
    readme = File.read!("README.md")
    [_, section] = String.split(readme, "## Verifying a grant before issuing it\n")
    [section | _] = String.split(section, "\n## ", parts: 2)
    assert [{"bash", command}] = BoundedAuthorityProtocol.Documentation.blocks(section)
    assert ["mix", "run", "docs/examples/action-approval.exs" = example] = String.split(command)
    assert {:ok, _binding} = Code.eval_file(example)
  end

  test "every getting-started block runs, in order, with the value the prose states" do
    path = "docs/guides/getting-started.md"

    assert values(path) == [
             32,
             3,
             3,
             {"restart_service", "grant-restart-001", :not_evaluated},
             {"grant-restart-001", :not_evaluated},
             [@invalid, @invalid, @invalid],
             {"https://issuer.example", ["https://deploy.example"], 1_800_003_600},
             {"grant-restart-001", "grant-restart-002"},
             {true, true}
           ]

    assert claim_errors(path, File.read!(path)) == []
  end

  test "every recursively discovered authored guide sample runs with its stated value" do
    paths = Path.wildcard("docs/**/*.{md,cheatmd}") ++ ["usage-rules.md"]

    for path <- paths,
        path not in [
          "docs/protocol-v1.md",
          "docs/guides/recipes.md",
          "docs/guides/getting-started.md"
        ] do
      # The generated specification mirror has no authored integration samples. Recipes run
      # in the real Plug consumer; the first integration is pinned independently above.
      {blocks, _deps} = elixir_blocks(File.read!(path))
      if blocks != [], do: assert(claim_errors(path, File.read!(path)) == [])
    end
  end

  test "the block extractor sees every elixir block and skips only the dependency block" do
    {blocks, skipped} = elixir_blocks(File.read!("docs/guides/getting-started.md"))
    assert length(blocks) == 9
    assert [deps] = skipped
    assert deps =~ "{:bounded_authority_protocol,"
  end

  test "the prose check is red-capable: a wrong or missing stated value is reported" do
    path = "docs/guides/getting-started.md"
    markdown = File.read!(path)

    wrong_value =
      String.replace(markdown, "The value is `{true, true}`", "The value is `{true, false}`")

    assert [error] = claim_errors(path, wrong_value)
    assert error =~ "{true, false}"

    wrong_entry =
      String.replace(
        markdown,
        "Each entry is `{:error, :invalid}`",
        "Each entry is `{:ok, :valid}`"
      )

    assert [_error] = claim_errors(path, wrong_entry)

    no_claim = String.replace(markdown, "The value is `32`: ", "")
    assert [error] = claim_errors(path, no_claim)
    assert error =~ "states no value"

    readme =
      String.replace(File.read!("README.md"), ~s("publish_article", :not), ~s("other", :not))

    assert [_error] = claim_errors("README.md", readme)
  end

  defp values(path), do: path |> File.read!() |> run_markdown(path) |> Enum.map(&elem(&1, 0))

  # Runs the blocks and returns, per block, its value and the prose that follows it.
  defp run_markdown(markdown, path) do
    {blocks, _deps} = elixir_blocks(markdown)
    assert blocks != [], "#{path} has no runnable elixir block"

    # Aliases from an earlier block stay in scope for later ones, as in an IEx session.
    {{values, _state}, warnings} =
      ExUnit.CaptureIO.with_io(:stderr, fn ->
        Enum.map_reduce(blocks, {[], Code.env_for_eval(file: path)}, fn block, {binding, env} ->
          quoted = Code.string_to_quoted!(block, file: path)
          {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
          {value, {binding, env}}
        end)
      end)

    assert unexpected_warnings(warnings) == [], "#{path} compiles with warnings:\n#{warnings}"
    Enum.zip(values, prose_after_blocks(markdown))
  end

  defp unexpected_warnings(output) do
    output
    |> String.split("\n")
    |> Enum.filter(&String.contains?(&1, "warning:"))
  end

  defp claim_errors(path, markdown) do
    for {{value, prose}, index} <- Enum.with_index(run_markdown(markdown, path), 1),
        error <- block_claim_errors(value, prose),
        do: "#{path} block #{index}: #{error}"
  end

  defp block_claim_errors(value, prose) do
    whole =
      Regex.scan(~r/\b(?:value|result) is\s+`([^`]+)`/, prose, capture: :all_but_first)
      |> List.flatten()

    each =
      Regex.scan(~r/\bEach entry is\s+`([^`]+)`/, prose, capture: :all_but_first)
      |> List.flatten()

    if whole == [] and each == [] do
      ["states no value"]
    else
      whole_errors =
        for term <- whole, evaluate(term) != value, do: "states `#{term}`, got #{inspect(value)}"

      each_errors =
        for term <- each,
            not (is_list(value) and Enum.all?(value, &(&1 == evaluate(term)))),
            do: "states each entry `#{term}`, got #{inspect(value)}"

      whole_errors ++ each_errors
    end
  end

  defp evaluate(term) do
    {value, _binding} = Code.eval_string(term)
    value
  end

  defp elixir_blocks(markdown) do
    markdown
    |> BoundedAuthorityProtocol.Documentation.blocks()
    |> Enum.flat_map(fn
      {"elixir", code} -> [code]
      _ -> []
    end)
    |> Enum.split_with(&(not deps_block?(&1)))
  end

  defp deps_block?(block), do: block =~ ~r/\bdefp? deps do\b/

  defp prose_after_blocks(markdown) do
    markdown
    |> BoundedAuthorityProtocol.Documentation.examples()
    |> Enum.reject(fn {code, _prose} -> deps_block?(code) end)
    |> Enum.map(&elem(&1, 1))
  end
end
