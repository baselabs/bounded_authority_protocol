defmodule BoundedAuthorityProtocol.QualityAliasTest do
  use ExUnit.Case, async: true

  @full_suite {[:quality, :"quality.tests"], "test --cover --seed 42"}
  @fixture_suite {[:quality], "test --cover --seed 42"}
  @quality_stages ~w(quality.source quality.corpus quality.tests quality.conformance quality.mutations quality.package)
  @quality_commands [
    "format --check-formatted",
    "compile --warnings-as-errors",
    "architecture",
    "secrets",
    "privacy.hooks",
    "corpus.sync",
    "corpus.digests",
    "corpus.verdicts",
    "corpus.generators",
    "corpus.distribution.mutations",
    "spec.facts",
    "spec.examples",
    "spec.render",
    "formal",
    "credo --strict",
    "verification.performance",
    "chain_archive.performance",
    "test --cover --seed 42",
    "dialyzer",
    "docs --warnings-as-errors",
    "docs.links",
    "audit",
    "package.check",
    "release.candidate",
    "chain_archive.mutations",
    "conformance.mutations",
    "conformance.verify",
    "local_loopback_http.verify",
    "role_attestation.verify",
    "content_assertion.verify",
    "content_assertion.mutations",
    "spec_facts.mutations"
  ]

  test "quality reserves the in-VM test task for the seeded coverage suite" do
    assert in_vm_tests(Mix.Project.config()[:aliases], project_sources()) == [@full_suite]
  end

  test "quality composes each CI stage and preserves every original command exactly once" do
    aliases = Mix.Project.config()[:aliases]
    assert aliases[:quality] == @quality_stages

    commands =
      Enum.flat_map(@quality_stages, &Keyword.fetch!(aliases, String.to_existing_atom(&1)))

    assert length(commands) == 32
    assert Enum.frequencies(commands) == Enum.frequencies(@quality_commands)

    for stage <- @quality_stages do
      assert BoundedAuthorityProtocol.MixProject.cli()[:preferred_envs][
               String.to_existing_atom(stage)
             ] == :test
    end
  end

  test "each CI stage reserves in-VM tests for the one seeded coverage suite" do
    aliases = Mix.Project.config()[:aliases]
    sources = project_sources()

    for stage <- @quality_stages do
      expected =
        if stage == "quality.tests",
          do: [{[:"quality.tests"], "test --cover --seed 42"}],
          else: []

      assert in_vm_tests(aliases, sources, stage) == expected, stage
    end
  end

  test "the guard rejects the pre-fix aliases, including transitive invocations" do
    aliases = [
      quality: ["corpus.verdicts", "distribution", "test --cover --seed 42"],
      "corpus.verdicts": [
        "run --no-start scripts/regen_verdict_digests.exs",
        "test test/conformance/verdict_digests_test.exs test/conformance/verdict_digest_gate_test.exs"
      ],
      distribution: ["corpus.distribution.mutations"],
      "corpus.distribution.mutations": ["test test/corpus_tooling_test.exs"]
    ]

    assert [
             {[:quality, :"corpus.verdicts"], "test test/conformance/" <> _},
             {[:quality, :distribution, :"corpus.distribution.mutations"],
              "test test/corpus_tooling_test.exs"},
             @fixture_suite
           ] = in_vm_tests(aliases, %{"scripts/regen_verdict_digests.exs" => ":ok"})

    fixed =
      for {name, commands} <- aliases do
        {name,
         Enum.map(commands, fn
           "test test/" <> files -> "cmd mix test test/" <> files
           command -> command
         end)}
      end

    assert in_vm_tests(fixed, %{"scripts/regen_verdict_digests.exs" => ":ok"}) == [@fixture_suite]
  end

  test "composite tasks cannot hide in-VM test invocations" do
    aliases = [
      quality: ["do format, nested --flag", "test --cover --seed 42"],
      nested: ["test hidden.exs"]
    ]

    assert [{[:quality, :nested], "test hidden.exs"}, @fixture_suite] = in_vm_tests(aliases)

    assert in_vm_tests(Keyword.put(aliases, :nested, ["cmd mix test hidden.exs"])) == [
             @fixture_suite
           ]
  end

  test "run scripts cannot hide any direct Mix test entry point" do
    for call <- [
          ~s|Mix.Task.run("test", ["hidden.exs"])|,
          ~s|Mix.Task.rerun("test", [])|,
          "Mix.Tasks.Test.run([])"
        ] do
      aliases = [quality: ["run --no-start scripts/check.exs", "test --cover --seed 42"]]
      sources = %{"scripts/check.exs" => call}

      assert [{[:quality, "scripts/check.exs"], "test (" <> _}, @fixture_suite] =
               in_vm_tests(aliases, sources)

      assert in_vm_tests(aliases, %{"scripts/check.exs" => ":ok"}) == [@fixture_suite]
    end
  end

  test "local custom tasks and their transitive scripts are inspected" do
    for directory <- ["lib/mix/tasks", "scripts"],
        call <- [
          ~s|Mix.Task.run("test", [])|,
          ~s|Mix.Task.rerun("test", [])|,
          "Mix.Tasks.Test.run([])"
        ] do
      file = directory <> "/hidden.ex"
      aliases = [quality: ["hidden", "test --cover --seed 42"]]
      sources = %{file => "defmodule Mix.Tasks.Hidden do\ndef run(_), do: #{call}\nend"}

      assert [{[:quality, "hidden", ^file], "test (" <> _}, @fixture_suite] =
               in_vm_tests(aliases, sources)

      assert in_vm_tests(aliases, %{
               file => "defmodule Mix.Tasks.Hidden do\ndef run(_), do: :ok\nend"
             }) == [@fixture_suite]
    end

    sources = %{
      "lib/mix/tasks/hidden.ex" =>
        ~s|defmodule Mix.Tasks.Hidden do\ndef run(_), do: Mix.Task.run("run", ["scripts/probe.exs"])\nend|,
      "scripts/probe.exs" => ~s|Mix.Task.rerun("test", [])|
    }

    assert [{_, "test (" <> _}, @fixture_suite] =
             in_vm_tests([quality: ["hidden", "test --cover --seed 42"]], sources)
  end

  test "opaque alias functions cannot hide another in-VM test invocation" do
    assert_raise ExUnit.AssertionError, fn ->
      in_vm_tests(quality: [fn _ -> :ok end, "test --cover --seed 42"])
    end
  end

  defp project_sources do
    ["lib/mix/tasks/**/*.{ex,exs}", "scripts/**/*.ex", "**/*.exs"]
    |> Enum.flat_map(&Path.wildcard/1)
    |> Enum.reject(&(hd(Path.split(&1)) in ["_build", "deps", "sdks", "test"]))
    |> Map.new(&{&1, File.read!(&1)})
  end

  defp in_vm_tests(aliases, sources \\ %{}, task \\ "quality") do
    graph = %{aliases: Map.new(aliases), sources: sources, tasks: local_tasks(sources)}
    expand(task, graph, [])
  end

  defp local_tasks(sources) do
    Enum.reduce(sources, %{}, fn {file, source}, tasks ->
      {_ast, tasks} =
        Macro.prewalk(Code.string_to_quoted!(source), tasks, fn
          {:defmodule, _, [{:__aliases__, _, [:Mix, :Tasks | parts]}, _]} = node, acc ->
            name = Enum.map_join(parts, ".", &Macro.underscore(Atom.to_string(&1)))
            {node, Map.put(acc, name, file)}

          node, acc ->
            {node, acc}
        end)

      tasks
    end)
  end

  defp expand(command, graph, parents) do
    [task | args] = OptionParser.split(command)
    alias_name = Enum.find(Map.keys(graph.aliases), &(Atom.to_string(&1) == task))

    cond do
      alias_name != nil ->
        refute alias_name in parents, "cyclic quality alias: #{inspect(parents ++ [alias_name])}"
        path = parents ++ [alias_name]

        graph.aliases
        |> Map.fetch!(alias_name)
        |> List.wrap()
        |> Enum.flat_map(fn
          entry when is_binary(entry) ->
            expand(entry, graph, path)

          callback when is_function(callback, 1) ->
            # This existing callback only creates the SBOM output directory.
            assert alias_name == :"sbom.generate"

            assert Function.info(callback, :module) ==
                     {:module, BoundedAuthorityProtocol.MixProject}

            assert Function.info(callback, :name) == {:name, :prepare_artifacts}
            []
        end)

      task == "do" ->
        command
        |> String.replace_prefix("do ", "")
        |> String.split(~r/\s*,\s*/)
        |> Enum.flat_map(&expand(&1, graph, parents))

      task == "test" ->
        [{parents, command}]

      task == "run" ->
        args
        |> Enum.filter(&String.ends_with?(&1, ".exs"))
        |> Enum.flat_map(&inspect_source(&1, graph, parents))

      Map.has_key?(graph.tasks, task) ->
        refute task in parents, "cyclic local Mix task: #{inspect(parents ++ [task])}"
        inspect_source(Map.fetch!(graph.tasks, task), graph, parents ++ [task])

      true ->
        []
    end
  end

  defp inspect_source(file, graph, parents) do
    # Fixtures provide their complete graph. Real sources are collected from both task roots.
    case Map.fetch(graph.sources, file) do
      :error ->
        flunk("quality references an uninspected script: #{file}")

      {:ok, source} ->
        source_calls(source, file, graph, parents)
    end
  end

  defp source_calls(source, file, graph, parents) do
    refute file in parents, "cyclic Mix script: #{inspect(parents ++ [file])}"
    path = parents ++ [file]

    {_ast, calls} =
      Macro.prewalk(Code.string_to_quoted!(source), [], fn
        {{:., _, [{:__aliases__, _, [:Mix, :Task]}, fun]}, _, [task | rest]} = node, acc
        when fun in [:run, :rerun] and is_binary(task) ->
          args = literal_arguments(rest)
          entry = Enum.join([task | args], " ")

          found =
            if task == "test",
              do: [{path, "test (#{file}: #{fun})"}],
              else: expand(entry, graph, path)

          {node, acc ++ found}

        {{:., _, [{:__aliases__, _, [:Mix, :Tasks, :Test]}, :run]}, _, _} = node, acc ->
          {node, acc ++ [{path, "test (#{file}: Mix.Tasks.Test.run)"}]}

        node, acc ->
          {node, acc}
      end)

    calls
  end

  defp literal_arguments([values]) when is_list(values), do: Enum.filter(values, &is_binary/1)
  defp literal_arguments(_), do: []
end
