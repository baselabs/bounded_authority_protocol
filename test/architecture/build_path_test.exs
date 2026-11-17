Code.require_file("../../tools/build_path.exs", __DIR__)

defmodule BoundedAuthorityProtocol.BuildPathTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.BuildPath

  test "the active Mix project owns its cached build path" do
    assert BuildPath.resolve(File.cwd!()) == Mix.Project.build_path()
  end

  # Mix applies preferred_envs to its own VM and never exports MIX_ENV, so a `cmd` child
  # resolves the dev build while the alias compiled the test build.
  test "aliases that resolve the active build path run inside Mix" do
    assert cmd_build_path_steps(Mix.Project.config()[:aliases]) == []
  end

  test "the alias guard rejects a cmd child that loads the build path transitively" do
    sources = %{
      "scripts/check.exs" => ~s|Code.require_file("../tools/gate.exs", __DIR__)|,
      "tools/gate.exs" => ~s|Code.require_file("build_path.exs", __DIR__)|
    }

    for entry <- ["cmd elixir scripts/check.exs", "cmd mix run --no-start scripts/check.exs"] do
      assert cmd_build_path_steps([gate: [entry]], sources) == [{:gate, entry}]
    end

    assert cmd_build_path_steps([gate: ["run --no-start scripts/check.exs"]], sources) == []
    assert cmd_build_path_steps([gate: ["cmd elixir scripts/other.exs"]], %{}) == []
  end

  test "standalone tools resolve paths without a running Mix project" do
    root = Path.join(System.tmp_dir!(), "bap-standalone-build")
    helper = Path.expand("../../tools/build_path.exs", __DIR__)

    code =
      "IO.puts(BoundedAuthorityProtocol.BuildPath.resolve(System.fetch_env!(\"BAP_BUILD_TEST_ROOT\")))"

    assert {output, 0} =
             System.cmd("elixir", ["-r", helper, "-e", code],
               env: [
                 {"BAP_BUILD_TEST_ROOT", root},
                 {"MIX_ENV", "prod"},
                 {"MIX_BUILD_ROOT", "custom-build"},
                 {"MIX_BUILD_PATH", nil}
               ],
               stderr_to_stdout: true
             )

    assert String.trim(output) == Path.join(root, "custom-build/prod")
  end

  test "standalone checkouts share environment precedence and scratch builds stay isolated" do
    keys = ["MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_ENV"]
    original = Enum.map(keys, &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(original, fn
        {key, nil} -> System.delete_env(key)
        {key, value} -> System.put_env(key, value)
      end)
    end)

    root = Path.join(System.tmp_dir!(), "bap-build-path")
    Enum.each(keys, &System.delete_env/1)
    assert BuildPath.resolve(root, "test") == Path.join(root, "_build/test")
    assert BuildPath.resolve(root) == Path.join(root, "_build/#{Mix.env()}")
    System.put_env("MIX_BUILD_ROOT", "custom")
    assert BuildPath.resolve(root, "test") == Path.join(root, "custom/test")
    System.put_env("MIX_BUILD_ROOT", Path.join(root, "absolute"))
    assert BuildPath.resolve(root, "prod") == Path.join(root, "absolute/prod")
    System.put_env("MIX_BUILD_PATH", "explicit")
    assert BuildPath.resolve(root, "test") == Path.join(root, "explicit")
    assert BuildPath.storage_root(root) == Path.join(root, "explicit")
    System.put_env("MIX_BUILD_PATH", Path.join(root, "absolute-explicit"))
    assert BuildPath.resolve(root, "test") == Path.join(root, "absolute-explicit")
    assert BuildPath.isolated(root, "test") == Path.join(root, "build/test")
  end

  defp cmd_build_path_steps(aliases, sources \\ nil) do
    for {name, entries} <- aliases,
        entry <- List.wrap(entries),
        is_binary(entry),
        String.starts_with?(entry, "cmd "),
        script <- OptionParser.split(entry),
        String.ends_with?(script, ".exs"),
        loads_build_path?(script, sources, []),
        uniq: true,
        do: {name, entry}
  end

  defp loads_build_path?(file, sources, seen) do
    file = Path.relative_to_cwd(Path.expand(file))

    cond do
      file == "tools/build_path.exs" ->
        true

      file in seen ->
        false

      true ->
        case source(file, sources) do
          nil ->
            false

          text ->
            {_ast, required} =
              Macro.prewalk(Code.string_to_quoted!(text), [], fn
                {{:., _, [{:__aliases__, _, [:Code]}, :require_file]}, _,
                 [path, {:__DIR__, _, _}]} = node,
                acc
                when is_binary(path) ->
                  {node, [Path.join(Path.dirname(file), path) | acc]}

                node, acc ->
                  {node, acc}
              end)

            Enum.any?(required, &loads_build_path?(&1, sources, [file | seen]))
        end
    end
  end

  defp source(file, nil), do: if(File.regular?(file), do: File.read!(file))
  defp source(file, sources), do: Map.get(sources, file)
end
