defmodule BoundedAuthorityProtocol.TestSupport.LivebookHarness do
  @moduledoc """
  Runs a Livebook notebook (`.livemd`) top to bottom, as Livebook does, and checks every code
  cell against the expected value its prose states.

  The setup cell (the one `Mix.install/1` call, which must be the first code cell) is skipped:
  the caller supplies the package, either the checkout under `mix test` or the unpacked
  release archive in the package gate. Every other `elixir` cell is evaluated in order with one
  shared binding and environment, and must be followed, before the next cell, by at least one
  expectation:

    * ``The cell returns `TERM`.``: the cell's value equals (`===`) `TERM`;
    * ``The cell's value matches `PATTERN`.``: the value matches `PATTERN` (for values that hold
      fresh key or signature bytes);
    * a paragraph ending in `The cell returns:` or `The cell's value matches:` followed by an
      `elixir` block marked `<!-- livebook:{"force_markdown":true} -->` (Livebook shows it as
      text, never runs it), for values too long for one line.

  Terms and patterns are evaluated in the notebook's own binding after the cell, so they can
  name notebook variables or pin them (`^grant_compact`). A notebook with no expectations, a
  cell without one, a cell that raises, and a value that differs from its expectation are each
  reported, with the notebook path and the cell's first line.

  The module uses only the Elixir standard library, so the package gate can load it into a
  consumer project of the unpacked archive.
  """

  @force_markdown ~s(<!-- livebook:{"force_markdown":true} -->)
  @value_var :livebook_harness_value

  @doc "Checks every notebook under `directory`; prints a summary and halts non-zero on failure."
  def gate!(directory) do
    paths = directory |> Path.join("*.livemd") |> Path.wildcard() |> Enum.sort()

    errors =
      if paths == [],
        do: ["no notebooks under #{directory}"],
        else: Enum.flat_map(paths, &check_file/1)

    if errors == [] do
      IO.puts("livebook harness: #{length(paths)} notebooks agree with their stated values")
    else
      IO.puts(:stderr, Enum.join(["livebook harness failed:" | errors], "\n"))
      System.halt(1)
    end
  end

  @doc "Returns the errors for the notebook at `path` (`[]` when every cell agrees)."
  def check_file(path), do: path |> File.read!() |> check(path)

  @doc "Returns the errors for notebook `source`, reported under the name `path`."
  def check(source, path) do
    case run(source, path) do
      {:ok, _binding} -> []
      {:error, errors} -> errors
    end
  end

  @doc """
  Evaluates notebook `source` and checks every expectation. Returns `{:ok, binding}` with the
  notebook's final binding, or `{:error, errors}`.
  """
  def run(source, path) do
    case parse(source) do
      {:ok, cells} -> evaluate(cells, path)
      {:error, reasons} -> {:error, Enum.map(reasons, &"#{path}: #{&1}")}
    end
  end

  @doc """
  Returns the code of the notebook's `Mix.install` setup cell. The registry read-back
  (scripts/livebook_registry_readback.exs) evaluates it to install the published release.
  """
  def setup_code(source) do
    blocks = source |> String.split("\n") |> Enum.with_index(1) |> blocks()

    case for({:cell, code, _line} <- blocks, code =~ "Mix.install(", do: code) do
      [code] -> {:ok, code}
      _other -> {:error, "must have exactly one Mix.install setup cell"}
    end
  end

  @doc """
  Splits `source` into its evaluated cells, each `%{code, line, expectations}`, after checking
  the setup cell and that every cell states an expectation.
  """
  def parse(source) do
    blocks = source |> String.split("\n") |> Enum.with_index(1) |> blocks()

    {setup, cells} =
      Enum.split_with(
        for({:cell, code, line, after_cell} <- attach(blocks), do: {code, line, after_cell}),
        fn {code, _line, _after} -> code =~ "Mix.install(" end
      )

    cells =
      Enum.map(cells, fn {code, line, after_cell} ->
        %{code: code, line: line, expectations: expectations(after_cell)}
      end)

    errors =
      setup_errors(setup, blocks) ++
        if(Enum.all?(cells, &(&1.expectations == [])),
          do: ["states no expected values"],
          else: []
        ) ++
        for(
          %{line: line, expectations: expectations} <- cells,
          error <- expectation_errors(expectations),
          do: "cell at line #{line}: #{error}"
        ) ++
        for(
          %{line: line, expectations: []} <- cells,
          do: "cell at line #{line} states no expected value"
        )

    if errors == [], do: {:ok, cells}, else: {:error, Enum.uniq(errors)}
  end

  defp setup_errors([{_code, line, _after}], blocks) do
    case Enum.find(blocks, &match?({:cell, _code, _line}, &1)) do
      {:cell, _code, ^line} -> []
      _other -> ["the Mix.install setup cell must be the first code cell"]
    end
  end

  defp setup_errors(setup, _blocks),
    do: ["must have exactly one Mix.install setup cell, found #{length(setup)}"]

  # Line-level scan into {:prose, text}, {:cell, code, line}, {:expected, code, line} and
  # {:other_fence}. A fence is an expectation block only when the line before it is the
  # force_markdown marker.
  defp blocks(lines), do: blocks(lines, nil, [])

  defp blocks([], _previous, acc), do: Enum.reverse(acc)

  defp blocks([{"```elixir", number} | rest], previous, acc) do
    {body, rest} = fence_body(rest, [])
    kind = if previous == @force_markdown, do: :expected, else: :cell
    blocks(rest, nil, [{kind, body, number + 1} | acc])
  end

  defp blocks([{"```" <> _info, _number} | rest], _previous, acc) do
    {_body, rest} = fence_body(rest, [])
    blocks(rest, nil, [{:other_fence} | acc])
  end

  defp blocks([{line, _number} | rest], previous, acc) do
    previous = if String.trim(line) == "", do: previous, else: line
    blocks(rest, previous, [{:prose, line} | acc])
  end

  defp fence_body([{"```", _number} | rest], body), do: {body |> Enum.reverse() |> join(), rest}
  defp fence_body([{line, _number} | rest], body), do: fence_body(rest, [line | body])
  defp fence_body([], body), do: {body |> Enum.reverse() |> join(), []}

  defp join(lines), do: Enum.join(lines, "\n")

  # Attaches to each cell the prose and expectation blocks that follow it, up to the next cell.
  defp attach(blocks) do
    {cells, current} =
      Enum.reduce(blocks, {[], nil}, fn
        {:cell, code, line}, {cells, current} ->
          {push(cells, current), {code, line, []}}

        _block, {cells, nil} ->
          {cells, nil}

        block, {cells, {code, line, after_cell}} ->
          {cells, {code, line, [block | after_cell]}}
      end)

    cells |> push(current) |> Enum.reverse()
  end

  defp push(cells, nil), do: cells

  defp push(cells, {code, line, after_cell}),
    do: [{:cell, code, line, Enum.reverse(after_cell)} | cells]

  defp expectations(after_cell) do
    {expectations, prose} =
      Enum.reduce(after_cell, {[], []}, fn
        {:prose, line}, {expectations, prose} ->
          {expectations, [line | prose]}

        {:expected, code, line}, {expectations, prose} ->
          {[block_expectation(code, line, prose) | expectations], prose}

        {:other_fence}, acc ->
          acc
      end)

    text = prose |> Enum.reverse() |> join()

    inline =
      for(
        {kind, regex} <- [
          equal: ~r/The cell returns\s+`([^`]+)`/,
          match: ~r/The cell's value matches\s+`([^`]+)`/
        ],
        [term] <- Regex.scan(regex, text, capture: :all_but_first),
        do: {kind, term}
      )

    inline ++ Enum.reverse(expectations)
  end

  defp block_expectation(code, line, prose_before) do
    # prose_before is newest-first; skip blank lines and the force_markdown marker itself.
    lead =
      prose_before
      |> Enum.map(&String.trim/1)
      |> Enum.find("", &(&1 not in ["", @force_markdown]))

    cond do
      String.ends_with?(lead, "The cell returns:") -> {:equal, code}
      String.ends_with?(lead, "The cell's value matches:") -> {:match, code}
      true -> {:invalid, "the expectation block at line #{line} follows no " <> introduction()}
    end
  end

  defp introduction, do: "\"The cell returns:\" or \"The cell's value matches:\""

  defp expectation_errors(expectations) do
    for {kind, detail} <- expectations,
        error <- expectation_error(kind, detail),
        do: error
  end

  defp expectation_error(:invalid, reason), do: [reason]

  defp expectation_error(_kind, term) do
    case Code.string_to_quoted(term) do
      {:ok, _quoted} -> []
      {:error, _reason} -> ["expectation `#{term}` is not valid Elixir"]
    end
  end

  defp evaluate(cells, path) do
    initial = {:ok, [], Code.env_for_eval(file: path), []}

    {status, binding, _env, errors} =
      Enum.reduce(cells, initial, &evaluate_step(&1, &2, path))

    if status == :ok and errors == [], do: {:ok, binding}, else: {:error, errors}
  end

  # A cell that raises halts the notebook: every later cell depends on the shared binding.
  defp evaluate_step(_cell, {:halted, _binding, _env, _errors} = halted, _path), do: halted

  defp evaluate_step(cell, {:ok, binding, env, errors}, path) do
    case evaluate_cell(cell, binding, env, path) do
      {:ok, value, binding, env} ->
        cell_errors =
          for {kind, term} <- cell.expectations,
              error <- compare(kind, term, value, binding, env, path),
              do: "#{path}: cell at line #{cell.line}: #{error}"

        {:ok, binding, env, errors ++ cell_errors}

      {:error, message} ->
        {:halted, binding, env,
         errors ++ ["#{path}: cell at line #{cell.line} raised: #{message}"]}
    end
  end

  defp evaluate_cell(%{code: code, line: line}, binding, env, path) do
    quoted = Code.string_to_quoted!(code, file: path, line: line)
    {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
    {:ok, value, binding, env}
  rescue
    exception -> {:error, Exception.format_banner(:error, exception, __STACKTRACE__)}
  catch
    kind, reason -> {:error, Exception.format_banner(kind, reason, __STACKTRACE__)}
  end

  defp compare(kind, term, value, binding, env, path) do
    quoted = Code.string_to_quoted!(term, file: path)
    value_var = {@value_var, [], nil}

    check =
      case kind do
        :equal -> quote(do: unquote(value_var) === unquote(quoted))
        :match -> quote(do: match?(unquote(quoted), unquote(value_var)))
      end

    {agrees?, _binding, _env} =
      Code.eval_quoted_with_env(check, Keyword.put(binding, @value_var, value), env)

    if agrees?,
      do: [],
      else: ["states #{describe(kind)} `#{term}`, got #{inspect(value, limit: 25)}"]
  rescue
    exception -> ["expectation `#{term}` raised: #{Exception.message(exception)}"]
  end

  defp describe(:equal), do: "it returns"
  defp describe(:match), do: "its value matches"
end
