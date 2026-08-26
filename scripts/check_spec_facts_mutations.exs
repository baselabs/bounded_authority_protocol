defmodule BoundedAuthorityProtocol.SpecFactsMutationGate do
  # Spec-facts mutation battery (spec-decoupling L2). Mirrors scripts/check_conformance_mutations.exs:
  # for each entry, isolate a scratch copy of the repo, apply exactly one source mutation at a
  # one-match anchor, run the targeted gate/test command, and raise `mutation survived` when a
  # check that should go red stays green. Baseline non-vacuity: the UNMUTATED command must run
  # green in a clean scratch first, so a deleted target cannot score as "caught".
  #
  # Calibration self-proof (the inverted-assertion leg, documented per doctrine): the entry
  # `bounds-implementation-digit` targets test/spec_facts_test.exs's rule-1 assertion
  # (`value == bounds[field]`). In a throwaway scratch copy that assertion was NEUTERED once
  # (`value == value`) while the source mutation (depth 32 -> 33) was applied; the mutated test
  # then STAYED GREEN — exactly the condition run_mutation/1 refuses:
  #
  #   calibration proof: exit=0 (green = mutation SURVIVED under the neutered assertion)
  #   Result: 1 passed, 1 excluded
  #
  # so the battery raises `** (RuntimeError) mutation survived: bounds-implementation-digit`
  # (never silent). The assertion was restored; the shipped entry is caught (red). The
  # planted-privacy-canary mutation from the gate's landing is intentionally NOT a battery
  # entry: the canary sweep's red-capability is proven inside the privacy gate's own
  # calibration tests (it needs the real git worktree, which a scratch copy does not have —
  # the same reason rule 9 no-ops outside a worktree).

  @root Path.expand("..", __DIR__)

  @mutations [
    %{
      # A digit changed in the authority's bounds table (the spec since the authority swap)
      # diverges the extraction from the frozen baseline (rule 1b).
      name: "spec-bounds-digit",
      path: "spec/bap-v1.md",
      from: "| nesting depth | 32 |",
      to: "| nesting depth | 33 |",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    },
    %{
      # A digit changed in the live Bounds implementation diverges the extracted table from the
      # live dump (rule 1, test-time). The is_binary guard keeps `value` referenced so the
      # mutated source still compiles under --warnings-as-errors.
      name: "bounds-implementation-digit",
      path: "lib/bounded_authority_protocol/v1/bounds.ex",
      from: "    depth: 32,",
      to: "    depth: 33,",
      command: ["mix", "test", "test/spec_facts_test.exs:57"]
    },
    %{
      # A softened requirement statement (unlisted -> listed) diverges from the frozen statement
      # hashes (rule 4) and the gate names the id.
      name: "map-statement-softening",
      path: "docs/design/requirement-map.md",
      from: "rejects every unlisted member/value/encoding/extension",
      to: "rejects every listed member/value/encoding/extension",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    },
    %{
      # A stale cited count diverges from the live index applicability (rule 5).
      name: "map-cited-count",
      path: "docs/design/requirement-map.md",
      from: "index.json check_envelope.invalid_request=3",
      to: "index.json check_envelope.invalid_request=4",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    },
    %{
      # A stale corpus-revision citation diverges from the sidecar integer (rule 6).
      name: "map-revision-citation",
      path: "docs/design/requirement-map.md",
      from: "**Corpus revision for every row:** `1`",
      to: "**Corpus revision for every row:** `2`",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    },
    %{
      # A deleted anchor breaks the closed anchor set (extraction fails, anchor named).
      name: "deleted-anchor",
      path: "spec/bap-v1.md",
      from: "<!-- facts:bounds -->\n",
      to: "\n",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    },
    %{
      # An unmarked optional-unobserved spec member: renaming the one_of coverage mark must turn
      # rule 2 red (the marks file is load-bearing, not decorative). The nonce mark is untouched,
      # so the mutation is surgical on one member and the JSON stays valid.
      name: "coverage-mark-removal",
      path: "spec/facts/coverage-v1.json",
      from: "{\"member\":\"one_of\"",
      to: "{\"member\":\"one_of_renamed\"",
      command: ["mix", "run", "--no-start", "scripts/check_spec_facts.exs"]
    }
  ]

  @copy_paths [
    ".formatter.exs",
    ".tool-versions",
    "conformance",
    "docs",
    "lib",
    "mix.exs",
    "mix.lock",
    "priv",
    "scripts",
    "spec",
    "test",
    "test_support",
    "tools"
  ]

  def run do
    Enum.each(@mutations, &run_mutation/1)
    IO.puts("spec facts mutation gate: ok mutations=#{length(@mutations)}")
  end

  defp run_mutation(mutation) do
    baseline_green!(mutation)

    scratch =
      Path.join(
        System.tmp_dir!(),
        "spec-facts-mutation-#{System.pid()}-#{mutation.name}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir!(scratch)

    try do
      Enum.each(@copy_paths, &copy_path(&1, scratch))
      File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
      copy_build(scratch)
      mutate_once!(Path.join(scratch, mutation.path), mutation.from, mutation.to)

      {output, status} =
        System.cmd(hd(mutation.command), command_args(mutation.command),
          cd: scratch,
          env: [{"MIX_ENV", "test"}],
          stderr_to_stdout: true
        )

      if status == 0 do
        raise "mutation survived: #{mutation.name}\n#{output}"
      end

      IO.puts("mutation caught: #{mutation.name}")
    after
      File.rm_rf!(scratch)
    end
  end

  # Baseline non-vacuity: before any mutation, the entry's UNMUTATED command must run green in a
  # clean scratch (a deleted or drifted target would otherwise score a red as "caught").
  # Cached per unique command so shared targets pay the baseline once per battery run.
  defp baseline_green!(mutation) do
    key = {:baseline_green, mutation.command}

    if Process.get(key) != :ok do
      scratch =
        Path.join(
          System.tmp_dir!(),
          "spec-facts-baseline-#{System.pid()}-#{System.unique_integer([:positive, :monotonic])}"
        )

      File.mkdir!(scratch)

      try do
        Enum.each(@copy_paths, &copy_path(&1, scratch))
        File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
        copy_build(scratch)

        {output, status} =
          System.cmd(hd(mutation.command), command_args(mutation.command),
            cd: scratch,
            env: [{"MIX_ENV", "test"}],
            stderr_to_stdout: true
          )

        if status != 0 do
          raise "baseline not green for #{mutation.name}: the unmutated target command exited " <>
                  "#{status}, so a post-mutation red cannot be attributed to the mutation\n#{output}"
        end

        Process.put(key, :ok)
      after
        File.rm_rf!(scratch)
      end
    end

    :ok
  end

  defp command_args(["mix", "test" | rest]), do: ["test" | rest] ++ ["--max-cases", "1"]
  defp command_args(["mix", "run" | rest]), do: ["run" | rest]

  defp copy_path(relative, scratch) do
    source = Path.join(@root, relative)
    target = Path.join(scratch, relative)
    File.mkdir_p!(Path.dirname(target))
    {:ok, _copied} = File.cp_r(source, target)
  end

  defp copy_build(scratch) do
    source = Path.join(@root, "_build/test")

    if File.dir?(source) do
      target = Path.join(scratch, "_build/test")
      File.mkdir_p!(Path.dirname(target))
      {:ok, _copied} = File.cp_r(source, target)
    end
  end

  defp mutate_once!(path, source, replacement) do
    contents = File.read!(path)

    if count(contents, source) != 1 do
      raise "mutation anchor is not exact: #{path}"
    end

    File.write!(path, String.replace(contents, source, replacement))
  end

  defp count(contents, source) do
    contents
    |> :binary.matches(source)
    |> length()
  end
end

BoundedAuthorityProtocol.SpecFactsMutationGate.run()
