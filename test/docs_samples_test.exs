defmodule BoundedAuthorityProtocol.DocsSamplesTest do
  @moduledoc """
  Runs the Elixir code blocks of the README quickstart and every guide, in order, against this
  package, and pins the value each block ends with. Only a dependency block (`deps`) is skipped,
  because it is project configuration rather than code.

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

  # Every guide page with Elixir code. Each runs top to bottom in one binding, and every block's
  # value must equal the value the prose states after it.
  @guides [
    "docs/guides/recipes.md",
    "docs/guides/evidence.md",
    "docs/guides/troubleshooting.md",
    "docs/guides/cheatsheet.cheatmd"
  ]

  for path <- @guides do
    test "every block of #{path} runs with the value its prose states" do
      path = unquote(path)
      {blocks, _deps} = elixir_blocks(File.read!(path))
      assert blocks != [], "#{path} has no runnable elixir block"
      assert claim_errors(path, File.read!(path)) == []
    end
  end

  test "every guide page with an elixir block is executed here" do
    executed = MapSet.new(["docs/guides/getting-started.md" | @guides])

    with_code =
      for path <- Path.wildcard("docs/guides/*.{md,cheatmd}"),
          match?({[_ | _], _deps}, path |> File.read!() |> elixir_blocks()),
          do: path

    assert Enum.reject(with_code, &MapSet.member?(executed, &1)) == []
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

  # The Plug recipe calls Plug.Conn, which this package does not depend on; the compiler's
  # "is undefined" warning for exactly that module is expected. Any other warning fails.
  defp unexpected_warnings(output) do
    output
    |> String.split("\n")
    |> Enum.filter(&String.contains?(&1, "warning:"))
    |> Enum.reject(
      &(&1 =~ ~r/warning: Plug\.Conn\.\w+\/\d is undefined \(module Plug\.Conn is not available/)
    )
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
    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(markdown, capture: :all_but_first)
    |> Enum.map(fn [block] -> block end)
    |> Enum.split_with(&(not deps_block?(&1)))
  end

  defp deps_block?(block), do: block =~ ~r/\bdefp? deps do\b/

  # The text after each runnable block, up to the next elixir block (or the end).
  defp prose_after_blocks(markdown) do
    [_before | parts] = String.split(markdown, ~r/^```elixir\n/m)

    parts
    |> Enum.map(fn part ->
      [block, after_block] = String.split(part, ~r/^```$/m, parts: 2)
      {block, after_block}
    end)
    |> Enum.reject(fn {block, _after} -> deps_block?(block) end)
    |> Enum.map(fn {_block, after_block} -> after_block end)
  end
end
