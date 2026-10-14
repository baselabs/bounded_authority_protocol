defmodule BoundedAuthorityProtocol.DocsSamplesTest do
  @moduledoc """
  Runs the Elixir code blocks of the README quickstart and the getting-started guide, in order,
  against this package, and pins the value each block ends with. Only the dependency block
  (`deps`) is skipped, because it is project configuration rather than code. A renamed function,
  a changed struct field, or a moved verdict reds here with the document named.
  """

  use ExUnit.Case, async: true

  @invalid {:error, :invalid}

  test "the README quickstart runs and ends with the redacted envelope facts" do
    assert run_blocks("README.md") == [{"publish_article", :not_evaluated}]
  end

  test "every getting-started block runs, in order, with the value the prose states" do
    assert run_blocks("docs/guides/getting-started.md") == [
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
  end

  test "the block extractor sees every elixir block and skips only the dependency block" do
    {blocks, skipped} = elixir_blocks(File.read!("docs/guides/getting-started.md"))
    assert length(blocks) == 9
    assert [deps] = skipped
    assert deps =~ "{:bounded_authority_protocol,"
  end

  defp run_blocks(path) do
    {blocks, [_deps]} = path |> File.read!() |> elixir_blocks()
    assert blocks != [], "#{path} has no runnable elixir block"

    # Aliases from an earlier block stay in scope for later ones, as in an IEx session.
    {values, _state} =
      Enum.map_reduce(blocks, {[], Code.env_for_eval(file: path)}, fn block, {binding, env} ->
        quoted = Code.string_to_quoted!(block, file: path)
        {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
        {value, {binding, env}}
      end)

    values
  end

  defp elixir_blocks(markdown) do
    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(markdown, capture: :all_but_first)
    |> Enum.map(fn [block] -> block end)
    |> Enum.split_with(&(not (&1 =~ ~r/\bdefp? deps do\b/)))
  end
end
