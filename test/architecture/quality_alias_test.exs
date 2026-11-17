defmodule BoundedAuthorityProtocol.QualityAliasTest do
  use ExUnit.Case, async: true

  @full_suite {[:quality], "test --cover --seed 42"}

  test "quality reserves the in-VM test task for the seeded coverage suite" do
    assert in_vm_tests(Mix.Project.config()[:aliases]) == [@full_suite]
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
             @full_suite
           ] = in_vm_tests(aliases)

    fixed =
      for {name, commands} <- aliases do
        {name,
         Enum.map(commands, fn
           "test test/" <> files -> "cmd mix test test/" <> files
           command -> command
         end)}
      end

    assert in_vm_tests(fixed) == [@full_suite]
  end

  test "opaque alias functions cannot hide another in-VM test invocation" do
    assert_raise ExUnit.AssertionError, fn ->
      in_vm_tests(quality: [fn _ -> :ok end, "test --cover --seed 42"])
    end
  end

  defp in_vm_tests(aliases), do: expand(:quality, Map.new(aliases), [])

  defp expand(name, aliases, parents) do
    refute name in parents, "cyclic quality alias: #{inspect(parents ++ [name])}"
    path = parents ++ [name]

    aliases
    |> Map.fetch!(name)
    |> List.wrap()
    |> Enum.flat_map(fn
      command when is_binary(command) ->
        [task | _args] = OptionParser.split(command)
        alias_name = Enum.find(Map.keys(aliases), &(Atom.to_string(&1) == task))

        cond do
          alias_name != nil -> expand(alias_name, aliases, path)
          task == "test" -> [{path, command}]
          true -> []
        end

      command when is_function(command, 1) ->
        # This existing callback only creates the SBOM output directory.
        assert name == :"sbom.generate"
        assert Function.info(command, :module) == {:module, BoundedAuthorityProtocol.MixProject}
        assert Function.info(command, :name) == {:name, :prepare_artifacts}
        []
    end)
  end
end
