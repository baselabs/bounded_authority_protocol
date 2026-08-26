defmodule BoundedAuthorityProtocol.RegenCorpusDigests do
  # Corpus digest regeneration + drift check (spec-decoupling L1, ADR 0019 atomic-landing tooling).
  #
  # The certified corpus identity is the SHA-256 of priv/conformance/v1/corpus/index.json. It is
  # machine-pinned in SIX constants — the four SDK conformance runners in their native encodings
  # (base64url: TypeScript, Go; hex: Python, Rust — encodings stay as-is) plus the two Elixir
  # pins (the CLI's fail-closed certified-corpus assertion and its test mirror). A rotation that
  # misses any one of them leaves a runner bound to a stale corpus or the Elixir verifier red;
  # per the cli.ex rotation contract they all move in the same change, and this script is the one
  # command that does it.
  #
  # Usage:
  #   mix corpus.digests                # CHECK (default): exits red on any drifted/missing pin
  #   elixir scripts/regen_corpus_digests.exs --write   # rewrite all six constants in place
  #
  # The check is wired into `mix quality` (corpus.digests leg). Anchors are value-independent
  # (line-prefix matches on each declaration), each must match exactly one line, and every
  # extracted value is shape-checked (hex = 64 lowercase hex chars; base64url = 43 unpadded
  # chars) so an anchor that drifts onto the wrong line fails loudly instead of silently.

  @root Path.expand("..", __DIR__)
  @index_path Path.join(@root, "priv/conformance/v1/corpus/index.json")

  # Single-line declarations: {file, encoding, line prefix, line suffix}. The Rust pin is
  # two-line and handled separately below.
  @single_line_pins [
    {"sdks/typescript/conformance/run.ts", :base64url, "const CERTIFIED_INDEX_SHA = \"", "\";"},
    {"sdks/go/conformance/run_test.go", :base64url, "const certifiedIndexSHA256 = \"", "\""},
    {"sdks/python/tests/conformance/run.py", :hex, "CERTIFIED_INDEX_SHA = \"", "\""},
    {"lib/bounded_authority_protocol/conformance/cli.ex", :base64url,
     "@certified_index_sha256 \"", "\""},
    {"test/conformance/cli_test.exs", :base64url, "@certified_index_sha256 \"", "\""}
  ]

  @rust_pin_file "sdks/rust/conformance/run.rs"
  @rust_pin_marker "const CERTIFIED_INDEX_SHA: &str ="

  def run(argv) do
    case argv do
      [] -> check()
      ["--write"] -> write_all()
      _ -> raise "usage: mix corpus.digests | elixir scripts/regen_corpus_digests.exs --write"
    end
  end

  # --- check -----------------------------------------------------------------

  defp check do
    digests = digests()
    pin_count = length(@single_line_pins) + 1

    problems =
      Enum.flat_map(@single_line_pins, &check_single_pin(&1, digests)) ++
        check_rust_pin(digests)

    case problems do
      [] ->
        IO.puts("corpus digests: ok pins=#{pin_count} hex=#{digests.hex}")
        IO.puts("corpus digests: base64url=#{digests.base64url}")

      problems ->
        raise "corpus digest pin check FAILED:\n" <> Enum.join(problems, "\n")
    end
  end

  defp check_single_pin({file, encoding, prefix, suffix}, digests) do
    expected = expected_for(encoding, digests)

    case locate_pin(file, prefix, suffix) do
      {:ok, value} -> shape_problems(encoding, value, file, expected)
      {:error, reason} -> ["#{file}: #{reason}"]
    end
  end

  defp check_rust_pin(digests) do
    case locate_rust_pin() do
      {:ok, value} -> shape_problems(:hex, value, @rust_pin_file, digests.hex)
      {:error, reason} -> ["#{@rust_pin_file}: #{reason}"]
    end
  end

  defp expected_for(:hex, digests), do: digests.hex
  defp expected_for(:base64url, digests), do: digests.base64url

  defp shape_problems(encoding, value, file, expected) do
    cond do
      not well_shaped?(encoding, value) ->
        ["#{file}: pinned value is not a well-formed #{encoding} SHA-256: #{inspect(value)}"]

      value != expected ->
        ["#{file}: pinned #{encoding} digest drifted\n  pinned: #{value}\n  actual: #{expected}"]

      true ->
        []
    end
  end

  @hex_graphemes Enum.map(?a..?f, &<<&1>>) ++ Enum.map(?0..?9, &<<&1>>)

  @base64url_graphemes Enum.map(?A..?Z, &<<&1>>) ++
                         Enum.map(?a..?z, &<<&1>>) ++
                         Enum.map(?0..?9, &<<&1>>) ++ ["_", "-"]

  defp well_shaped?(:hex, value) do
    byte_size(value) == 64 and Enum.all?(String.graphemes(value), &(&1 in @hex_graphemes))
  end

  defp well_shaped?(:base64url, value) do
    alphabet = MapSet.new(@base64url_graphemes)

    byte_size(value) == 43 and
      value |> String.graphemes() |> Enum.all?(&MapSet.member?(alphabet, &1))
  end

  # --- write -----------------------------------------------------------------

  defp write_all do
    digests = digests()

    Enum.each(@single_line_pins, fn {file, encoding, prefix, suffix} ->
      expected = expected_for(encoding, digests)

      case rewrite_pin_line(file, prefix, suffix, prefix <> expected <> suffix) do
        :ok -> IO.puts("rewrote #{file} (#{encoding})")
        {:error, reason} -> raise "#{file}: #{reason}"
      end
    end)

    case rewrite_rust_line("    \"#{digests.hex}\";") do
      :ok -> IO.puts("rewrote #{@rust_pin_file} (hex)")
      {:error, reason} -> raise "#{@rust_pin_file}: #{reason}"
    end

    IO.puts("corpus digests: rewrote #{length(@single_line_pins) + 1} pins")
    check()
  end

  # --- pin location (shared by check and write) -------------------------------

  # Finds the unique declaration line and extracts the pinned value between prefix and suffix.
  defp locate_pin(file, prefix, suffix) do
    with {:ok, contents} <- read(Path.join(@root, file)) do
      locate_pin_in(contents, prefix, suffix)
    end
  end

  # Leading whitespace is stripped before the prefix test (the Elixir pins are indented), and the
  # rewrite preserves each declaration's original indentation.
  defp locate_pin_in(contents, prefix, suffix) do
    lines = String.split(contents, "\n")
    matches = Enum.filter(lines, &String.starts_with?(String.trim_leading(&1), prefix))

    case matches do
      [line] ->
        extract_value(String.trim_leading(line), prefix, suffix)

      [] ->
        {:error, "no line starts with #{inspect(prefix)} (pin deleted or renamed?)"}

      _ ->
        {:error, "multiple lines start with #{inspect(prefix)} (ambiguous anchor)"}
    end
  end

  defp extract_value(line, prefix, suffix) do
    prefix_length = String.length(prefix)
    suffix_length = String.length(suffix)
    value_length = String.length(line) - prefix_length - suffix_length

    cond do
      not String.ends_with?(line, suffix) ->
        {:error, "declaration does not close with #{inspect(suffix)}: #{inspect(line)}"}

      value_length <= 0 ->
        {:error, "declaration carries no value: #{inspect(line)}"}

      true ->
        {:ok, String.slice(line, prefix_length, value_length)}
    end
  end

  defp rewrite_pin_line(file, prefix, suffix, new_line) do
    path = Path.join(@root, file)

    with {:ok, contents} <- read(path),
         {:ok, _value} <- locate_pin_in(contents, prefix, suffix) do
      matcher = fn line -> String.starts_with?(String.trim_leading(line), prefix) end
      write_rewritten(path, contents, matcher, new_line, nil, &prepend_indent/2)
    end
  end

  # The Rust constant is the marker line followed by an indented string literal on the next line.
  defp locate_rust_pin do
    with {:ok, contents} <- read(Path.join(@root, @rust_pin_file)) do
      case rust_marker_index(contents) do
        {:ok, index} ->
          value_line = value_line_after(contents, index)
          extract_value(value_line, "    \"", "\";")

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp rewrite_rust_line(new_line) do
    path = Path.join(@root, @rust_pin_file)

    with {:ok, contents} <- read(path),
         {:ok, _value} <- locate_rust_pin(),
         {:ok, index} <- rust_marker_index(contents) do
      write_rewritten(path, contents, fn _line -> false end, new_line, index + 1)
    end
  end

  defp rust_marker_index(contents) do
    lines = String.split(contents, "\n")

    case Enum.with_index(lines) |> Enum.filter(fn {line, _i} -> line == @rust_pin_marker end) do
      [{_line, index}] -> {:ok, index}
      [] -> {:error, "no exact #{@rust_pin_marker} line (pin deleted or renamed?)"}
      _ -> {:error, "multiple #{@rust_pin_marker} lines (ambiguous anchor)"}
    end
  end

  defp value_line_after(contents, marker_index) do
    contents |> String.split("\n") |> Enum.at(marker_index + 1, "")
  end

  # Rewrites every line matching `matcher` (or exactly the line at `at_index`) to `new_line`,
  # optionally re-indenting via `indent` (identity for column-0 declarations).
  defp write_rewritten(
         path,
         contents,
         matcher,
         new_line,
         at_index,
         indent \\ fn _line, replacement -> replacement end
       ) do
    lines = String.split(contents, "\n")

    rewritten =
      lines
      |> Enum.with_index()
      |> Enum.map(fn {line, i} ->
        cond do
          not is_nil(at_index) and i == at_index -> indent.(line, new_line)
          is_nil(at_index) and matcher.(line) -> indent.(line, new_line)
          true -> line
        end
      end)

    File.write!(path, Enum.join(rewritten, "\n"))
    :ok
  end

  defp prepend_indent(line, replacement) do
    case Regex.run(~r/\A[ \t]*/, line) do
      [indent] -> indent <> replacement
      nil -> replacement
    end
  end

  # --- corpus digest -----------------------------------------------------------

  defp digests do
    case File.read(@index_path) do
      {:ok, bytes} ->
        digest = :crypto.hash(:sha256, bytes)

        %{
          hex: Base.encode16(digest, case: :lower),
          base64url: Base.url_encode64(digest, padding: false)
        }

      {:error, reason} ->
        raise "cannot read corpus index #{@index_path}: #{inspect(reason)}"
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, "cannot read #{path}: #{inspect(reason)}"}
    end
  end
end

BoundedAuthorityProtocol.RegenCorpusDigests.run(System.argv())
