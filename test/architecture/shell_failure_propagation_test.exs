defmodule BoundedAuthorityProtocol.ShellFailurePropagationTest do
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)

  test "workflow steps and tracked shell scripts propagate command failures" do
    workflows = Path.wildcard(Path.join(@root, ".github/workflows/*.{yml,yaml}"))
    assert workflows != []

    for path <- workflows do
      workflow = YamlElixir.read_from_file!(path)
      assert get_in(workflow, ["defaults", "run", "shell"]) == "bash", path

      for {_name, job} <- workflow["jobs"],
          step <- job["steps"] || [],
          Map.has_key?(step, "run") do
        shell = step["shell"] || get_in(job, ["defaults", "run", "shell"]) || "bash"
        assert shell == "bash", "#{path}: run steps must keep the Bash default"
      end
    end

    actions = Path.wildcard(Path.join(@root, ".github/actions/**/action.{yml,yaml}"))

    for path <- actions do
      action = YamlElixir.read_from_file!(path)

      if get_in(action, ["runs", "using"]) == "composite" do
        for step <- action["runs"]["steps"], Map.has_key?(step, "run") do
          assert step["shell"] == "bash", "#{path}: composite run steps need an explicit shell"
        end
      end
    end

    {tracked, status} = System.cmd("git", ["ls-files", "-z"], cd: @root)
    assert status == 0

    scripts =
      for relative <- String.split(tracked, <<0>>, trim: true),
          path = Path.join(@root, relative),
          source = File.read!(path),
          shell_script?(relative, source),
          do: {path, source}

    assert scripts != []

    for {path, source} <- scripts do
      assert String.starts_with?(source, "#!/usr/bin/env bash\n"), path

      first_statement =
        source
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.find(&(&1 != "" and not String.starts_with?(&1, "#")))

      assert first_statement != nil, path
      assert first_statement =~ ~r/^set -euo pipefail(?:\s+.*)?$/, path
    end

    sources = Enum.map(workflows ++ actions, &{&1, File.read!(&1)}) ++ scripts

    for {path, source} <- sources do
      source = String.replace(source, ~r/\\\r?\n/, " ")
      refute source =~ ~r/\|\|\s*(?:true\b|:(?=[\s;)]|$))/, path
      refute String.contains?(source, "<("), "#{path}: capture process output before checking it"

      # Keep quoted, multiline arguments together, including continuations. Checking the
      # command text also catches substitutions nested inside another argument expansion.
      for [command] <-
            Regex.scan(
              ~r/\b(?:echo\b|for\s+[a-zA-Z_][a-zA-Z0-9_]*\s+in\b)(?:[^"'\\;\n]|\\.|"[^"]*"|'[^']*')*/,
              source
            ) do
        refute String.contains?(command, "$("), "#{path}: capture output before echo or for"
      end

      refute source =~ ~r/\blocal\s+[^\n;]*\$\(/,
             "#{path}: declare locals separately from command substitution assignments"
    end
  end

  defp shell_script?(path, source) do
    Path.extname(path) == ".sh" or String.starts_with?(path, "scripts/hooks/") or
      Regex.match?(~r/\A\#![^\n]*\b(?:ba)?sh(?:\s|\z)/, source)
  end
end
