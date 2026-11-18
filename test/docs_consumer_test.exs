defmodule BoundedAuthorityProtocol.DocsConsumerTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 240_000

  test "the guide creates a fresh release consumer and real Plug exercises the recipes" do
    root = File.cwd!()

    scratch =
      Path.join(System.tmp_dir!(), "bap-docs-consumer-#{System.unique_integer([:positive])}")

    File.mkdir!(scratch)

    try do
      archive = Path.join(scratch, "release.tar")
      command!("mix", ["hex.build", "--output", archive], root)
      package = Path.join(scratch, "package")
      Hex.Tar.unpack!(archive, package)
      guide = File.read!(Path.join(package, "docs/guides/getting-started.md"))
      [_, create] = Regex.run(~r/<!-- reader-create -->\s*```sh\n(.*?)```/s, guide)
      [new, cd] = String.split(String.trim(create), "\n")
      ["mix" | args] = String.split(new)
      command!("mix", args, scratch)
      ["cd", project] = String.split(cd)
      consumer = Path.join(scratch, project)
      assert File.dir?(consumer)

      [_, deps] = Regex.run(~r/```elixir\n(defp deps do\n.*?\nend)\n```/s, guide)
      [{:bounded_authority_protocol, requirement}] = dependency_terms(deps)
      assert Version.match?(Mix.Project.config()[:version], requirement)
      # Substitute only the release source, not the guide's dependency shape or commands.
      local_deps = String.replace(deps, inspect(requirement), "path: #{inspect(package)}")
      mixfile = Path.join(consumer, "mix.exs")
      generated = File.read!(mixfile)
      edited = Regex.replace(~r/  defp deps do\n.*?\n  end/s, generated, indent(local_deps))
      assert edited != generated
      File.write!(mixfile, edited)

      [_, start] = Regex.run(~r/<!-- reader-start -->\s*```sh\n(.*?)```/s, guide)
      [fetch, iex] = String.split(String.trim(start), "\n")
      ["mix" | fetch_args] = String.split(fetch)
      command!("mix", fetch_args, consumer)
      assert iex == "iex -S mix"

      code =
        for {"elixir", block} <- BoundedAuthorityProtocol.Documentation.blocks(guide),
            not String.starts_with?(block, "defp deps"),
            do: block

      assert length(code) == 9

      File.write!(
        Path.join(consumer, "reader.exs"),
        Enum.join(code, "\n") <> "\nIO.puts(\"BAP_READER_COMPLETE\")\n"
      )

      output = command!("sh", ["-c", iex <> " < reader.exs"], consumer)
      assert output =~ "Interactive Elixir"
      assert output =~ "BAP_READER_COMPLETE"
      refute output =~ "** ("
      refute output =~ "warning:"

      # Plug belongs only to this consumer. The unpacked protocol has zero runtime deps.
      File.write!(
        mixfile,
        String.replace(
          edited,
          "[{:bounded_authority_protocol,",
          "[{:plug, \"~> 1.20\"}, {:bounded_authority_protocol,"
        )
      )

      command!("mix", fetch_args, consumer)

      examples =
        package
        |> Path.join("docs/guides/recipes.md")
        |> File.read!()
        |> BoundedAuthorityProtocol.Documentation.examples()

      File.write!(Path.join(consumer, "recipes.etf"), :erlang.term_to_binary(examples))

      File.cp!(
        Path.join(root, "test/fixtures/docs_consumer/middleware_suite.exs"),
        Path.join(consumer, "test/middleware_test.exs")
      )

      output =
        command!("mix", ["test", "test/middleware_test.exs", "--warnings-as-errors"], consumer)

      assert output =~ "1 test, 0 failures" or output =~ "1 passed"
    after
      File.rm_rf!(scratch)
    end
  end

  defp dependency_terms(fragment) do
    {result, _} =
      Code.eval_string(
        "(fn -> " <> String.replace(fragment, ~r/^defp deps do\n|\nend$/, "") <> " end).()"
      )

    result
  end

  defp indent(text), do: text |> String.split("\n") |> Enum.map_join("\n", &("  " <> &1))

  defp command!(command, args, directory) do
    mix_env = if List.first(args) == "test", do: "test", else: "dev"

    env = [
      {"MIX_ENV", mix_env},
      {"MIX_BUILD_PATH", nil},
      {"MIX_DEPS_PATH", nil},
      {"MIX_LOCKFILE", nil}
    ]

    {output, status} = System.cmd(command, args, cd: directory, env: env, stderr_to_stdout: true)
    assert status == 0, "#{command} #{Enum.join(args, " ")} failed:\n#{output}"
    refute output =~ "warning:", output
    output
  end
end
