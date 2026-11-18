defmodule BoundedAuthorityProtocol.LivebookCheck do
  @moduledoc false

  @package :bounded_authority_protocol
  @output "<!-- livebook:{\"output\":true} -->"

  def main([mode]) when mode in ["--local", "--published"] do
    root = File.cwd!()
    registry = registry!(root)

    for {name, entry} <- Enum.sort(registry) do
      scratch = Path.join(System.tmp_dir!(), "bap-livebook-#{System.unique_integer([:positive])}")
      install = Path.join(scratch, "install")
      working = Path.join(scratch, "work")
      File.mkdir_p!(working)

      try do
        {output, status} =
          System.cmd(
            System.find_executable("elixir") || raise("elixir unavailable"),
            [__ENV__.file, "--notebook", root, name, mode, Integer.to_string(entry["outputs"])],
            cd: working,
            env: [
              {"MIX_INSTALL_DIR", install},
              {"MIX_ENV", "dev"},
              {"MIX_BUILD_PATH", nil},
              {"MIX_DEPS_PATH", nil},
              {"MIX_LOCKFILE", nil},
              {"BAP_LIVEBOOK_NO_MAIN", nil}
            ],
            stderr_to_stdout: true
          )

        IO.write(output)
        if status != 0, do: raise("#{name}: notebook failed, exit #{status}")
        if File.ls!(working) != [], do: raise("#{name}: notebook left residue")
      after
        File.rm_rf!(scratch)
        if File.exists?(scratch), do: raise("notebook cleanup failed")
      end
    end
  end

  def main(["--notebook", root, name, mode, count]) when mode in ["--local", "--published"] do
    path = Path.join([root, "docs/notebooks", name])
    source = File.read!(path)
    cells = parse!(source, String.to_integer(count))
    version = version!(root)
    expected_setup = "Mix.install([{:bounded_authority_protocol, \"== #{version}\"}])"

    unless String.trim(hd(cells).code) == expected_setup do
      raise "#{path}: setup must install exactly the registry-facing version #{version}"
    end

    setup =
      if mode == "--local" do
        "Mix.install([{:bounded_authority_protocol, path: #{inspect(root)}}])"
      else
        hd(cells).code
      end

    cells = [%{hd(cells) | code: setup} | tl(cells)]

    evaluate!(cells, path, fn index ->
      if index == 1, do: assert_package!(root, version, mode)
    end)

    IO.puts("LIVEBOOK_PASS #{name} outputs=#{count} mode=#{mode}")
  end

  def main(_), do: raise("usage: elixir scripts/check_livebooks.exs --local | --published")

  def registry!(root) do
    registry = root |> Path.join("docs/notebooks/registry.json") |> File.read!() |> :json.decode()

    files =
      root
      |> Path.join("docs/notebooks/**/*.livemd")
      |> Path.wildcard()
      |> Enum.map(&Path.relative_to(&1, Path.join(root, "docs/notebooks")))
      |> Enum.sort()

    if files == [] or Enum.sort(Map.keys(registry)) != files,
      do: raise("notebook registry differs from files")

    registry
  end

  # A line scanner handles CommonMark backtick and tilde fences, including longer fences and
  # up to three leading spaces. A persisted output must follow each executable cell.
  def parse!(source, count) do
    blocks = fences!(String.split(source, "\n"), 1, [])

    cells =
      blocks
      |> Enum.with_index()
      |> Enum.flat_map(fn
        {%{language: "elixir"} = cell, index} ->
          case Enum.at(blocks, index + 1) do
            %{language: "", output?: true, code: output} -> [%{cell | expected: output}]
            _ -> raise("cell at line #{cell.line}: missing persisted output")
          end

        _ ->
          []
      end)

    outputs = Enum.count(blocks, & &1.output?)

    if cells == [] or length(cells) != count or outputs != count,
      do: raise("expected #{count} cells and persisted outputs, got #{length(cells)}/#{outputs}")

    installs = Enum.count(cells, &String.contains?(&1.code, "Mix.install("))

    unless installs == 1 and hd(cells).code =~ "Mix.install(",
      do: raise("exactly one Mix.install setup cell must be first")

    cells
  end

  defp fences!([], _line, acc), do: Enum.reverse(acc)

  defp fences!([line | rest], number, acc) do
    case Regex.run(~r/^ {0,3}(`{3,}|~{3,})([^`]*)$/, line) do
      [_, fence, language] ->
        {body, remaining, next} = body!(rest, number + 1, fence, [])
        output? = match?([%{marker?: true} | _], acc)
        acc = Enum.reject(acc, &Map.get(&1, :marker?, false))

        block = %{
          code: Enum.join(body, "\n"),
          language: String.trim(language),
          line: number + 1,
          output?: output?,
          expected: nil
        }

        fences!(remaining, next, [block | acc])

      _ ->
        acc = if String.trim(line) == @output, do: [%{marker?: true} | acc], else: acc
        fences!(rest, number + 1, acc)
    end
  end

  defp body!([], _number, _fence, _acc), do: raise("unclosed notebook fence")

  defp body!([line | rest], number, fence, acc) do
    character = Regex.escape(String.first(fence))
    minimum = String.length(fence)
    closing = Regex.compile!("^ {0,3}#{character}{#{minimum},}\\s*$")

    if Regex.match?(closing, line) do
      {Enum.reverse(acc), rest, number + 1}
    else
      body!(rest, number + 1, fence, [line | acc])
    end
  end

  def evaluate!(cells, path, after_cell \\ fn _ -> :ok end) do
    initial = {[], Code.env_for_eval(file: path)}

    Enum.with_index(cells, 1)
    |> Enum.reduce(initial, fn {cell, index}, {binding, environment} ->
      quoted = Code.string_to_quoted!(cell.code, file: path, line: cell.line)
      {value, binding, environment} = Code.eval_quoted_with_env(quoted, binding, environment)
      {expected, []} = Code.eval_string(cell.expected)
      unless value === expected, do: raise("#{path}: cell #{index}: persisted output mismatch")
      after_cell.(index)
      {binding, environment}
    end)
  end

  def version!(root) do
    [_, version] = Regex.run(~r/@version "([^"]+)"/, File.read!(Path.join(root, "mix.exs")))
    version
  end

  defp assert_package!(root, version, mode) do
    actual = Application.spec(@package, :vsn) |> to_string()
    unless actual == version, do: raise("loaded version #{actual}, expected #{version}")

    source =
      Module.concat(["BoundedAuthorityProtocol"])
      |> apply(:module_info, [:compile])
      |> Keyword.fetch!(:source)
      |> to_string()
      |> Path.expand()

    install = System.fetch_env!("MIX_INSTALL_DIR") |> Path.expand()

    if mode == "--local" do
      unless source == Path.join(root, "lib/bounded_authority_protocol.ex"),
        do: raise("local mode loaded another source")
    else
      unless String.starts_with?(source, install <> "/"),
        do: raise("published mode loaded outside the fresh registry install")

      locks = Path.wildcard(Path.join(install, "**/mix.lock"))

      entries =
        Enum.flat_map(locks, fn lock ->
          {terms, []} = Code.eval_file(lock)

          case terms[@package] do
            {:hex, @package, ^version, _, _, _, "hexpm", checksum} -> [checksum]
            _ -> []
          end
        end)

      unless entries != [], do: raise("published package is not an exact hexpm dependency")

      {response, 0} =
        System.cmd("curl", [
          "--fail",
          "--silent",
          "--show-error",
          "--retry",
          "3",
          "https://hex.pm/api/packages/bounded_authority_protocol/releases/#{version}"
        ])

      registry = :json.decode(response)

      unless Enum.all?(entries, &(&1 == registry["checksum"])),
        do: raise("resolved Hex checksum differs from registry release")
    end

    IO.puts("LIVEBOOK_PACKAGE bounded_authority_protocol=#{actual} origin=#{mode}")
  end
end

if System.get_env("BAP_LIVEBOOK_NO_MAIN") != "1" do
  BoundedAuthorityProtocol.LivebookCheck.main(System.argv())
end
