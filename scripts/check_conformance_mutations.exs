defmodule BoundedAuthorityProtocol.ConformanceMutationGate do
  # BAP-05 Task 6 — conformance mutation battery (gate-integrity layer).
  #
  # Mirrors scripts/check_chain_archive_mutations.exs: for each entry, isolate a scratch copy of
  # the repo, apply exactly one source mutation at a one-match anchor, run the targeted test
  # command, and raise `mutation survived` when a test that should go red stays green instead. A
  # vacuous battery (an anchor that matches nothing, or a mutation no test catches) is precisely
  # the quiet class the conformance design exists to kill — every entry below is a load-bearing
  # check wired to a specific red.
  #
  # Calibration self-proof: the entry `calibration-case-id-removal` is a real caught mutation
  # (its targeted test asserts {:error, :invalid} on a duplicate case id; disabling the check
  # lets the load succeed, so the assertion fails and the test goes red). To prove the
  # `mutation survived` raise path is itself live, the assertion was inverted once in a throwaway
  # scratch copy (expecting {:ok, _} instead of {:error, :invalid}); the mutated load then
  # returned {:ok, _} and the test STAYED GREEN:
  #
  #   calibration proof: status=0 (0 = green = mutation SURVIVED under inverted assertion)
  #   Result: 1 passed, 35 excluded
  #
  # A green target under mutation is exactly the condition run_mutation/1 refuses — it raises
  # `** (RuntimeError) mutation survived: calibration-case-id-removal` (never silent). The
  # assertion was restored; the shipped entry is caught (red) and the battery is green end-to-end.

  @root Path.expand("..", __DIR__)

  # Each entry carries the full targeted command verbatim. `mix test` commands get
  # `--max-cases 1` appended (serial, deterministic, fastest single-file run); `mix architecture`
  # does NOT (it proxies args to `elixir scripts/check_architecture.exs`, which exits 2 on any
  # unknown flag — so appending would make every architecture entry spuriously red).
  @mutations [
    # --- C1 purity carve-out proofs (per-file keying) -------------------------
    %{
      # A planted System.halt(0) in cli.ex (the carve-out module that must NOT halt) turns the
      # architecture gate red: the cli.ex allowance is {File,_}/{IO,_}/{Path,_} only, never
      # System. Proves the carve-out allowance is keyed per-file.
      name: "cli-halt-inversion",
      path: "lib/bounded_authority_protocol/conformance/cli.ex",
      from: "  def run(argv) do\n",
      to: "  def run(argv) do\n    System.halt(0)\n",
      command: ["mix", "architecture"]
    },
    %{
      # A planted File.write/2 in cli/main.ex (NOT allowed there) turns the gate red: cli/main.ex
      # is allowed {System,:halt} and {Cli,:run} only. Proves per-file keying (File.write is
      # allowed in cli.ex but NOT in cli/main.ex).
      name: "cli-io-widening",
      path: "lib/bounded_authority_protocol/conformance/cli/main.ex",
      from: "  def main(argv) do\n    System.halt(Cli.run(argv))\n  end\n",
      to:
        "  def main(argv) do\n    File.write(\"x\", \"y\")\n    System.halt(Cli.run(argv))\n  end\n",
      command: ["mix", "architecture"]
    },
    %{
      # A reference to the Cli carve-out from a NON-conformance module (v1.ex) turns the gate red.
      # The mechanism is the existing module-allowance discipline (not a named special rule): the
      # planted `@conformance_cli Cli` references the bare `Cli` root, which is not in v1.ex's
      # approved_source_modules nor the always-allowed list, so node_violations fires
      # `forbidden module Cli` (:unapproved_runtime). The full `BoundedAuthorityProtocol.*` root
      # is blanket-allowed, so the bare short alias is what makes the mutation bite. Proves the
      # carve-out is unreachable from the protocol core.
      name: "cli-reachability",
      path: "lib/bounded_authority_protocol/v1.ex",
      from: "  alias BoundedAuthorityProtocol.V1.Base64Url",
      to:
        "  alias BoundedAuthorityProtocol.Conformance.Cli\n  @conformance_cli Cli\n  alias BoundedAuthorityProtocol.V1.Base64Url",
      command: ["mix", "architecture"]
    },
    # --- V1 corpus integrity: counts + hashes --------------------------------
    %{
      # Disabling the total_cases agreement check (the ^total pin) lets a corpus whose index
      # total_cases disagrees with the files load successfully. Targeted test plants total_cases
      # = 999 and asserts {:error, :invalid}; with the pin gone the load returns {:ok, _}.
      name: "corpus-count-check-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "      {:ok, ^total} -> :ok",
      to: "      {:ok, _} -> :ok",
      command: ["mix", "test", "test/conformance/corpus_test.exs:473"]
    },
    %{
      # Disabling the per-file SHA-256 equality (always-true guard) lets a corpus with a stale
      # index hash load. Targeted test rewrites one case-file hash in the index and asserts
      # {:error, :invalid}; with the guard gone the load returns {:ok, _}.
      name: "corpus-hash-check-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "           true <- sha256_b64(bytes) == hash do",
      to: "           true <- true do",
      command: ["mix", "test", "test/conformance/corpus_test.exs:438"]
    },
    # --- V3 corpus integrity: exact file-set equality -------------------------
    %{
      # Disabling exact file-set equality (always-true branch) lets a corpus with an unlisted file
      # (present in the map, absent from the index) load. The unlisted-file direction is the one
      # ONLY this check catches: a missing declared file is rejected earlier by load_files, but an
      # unlisted extra file is invisible to counts/hashes/case_ids/applicability, so it reaches
      # verify_file_set alone. Targeted test adds an unlisted file and asserts {:error, :invalid};
      # with the equality gone the load returns {:ok, _}.
      name: "corpus-fileset-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "    if MapSet.equal?(declared, present),",
      to: "    if true,",
      command: ["mix", "test", "test/conformance/corpus_test.exs:465"]
    },
    # --- V2 corpus integrity: applicability required cells --------------------
    %{
      # Disabling the required-cell count match (declared >=1 must equal observed) lets a corpus
      # whose declared required count disagrees with the executed count load. Targeted test
      # declares json.decode/valid=5 (1 executed) and asserts {:error, :invalid}; with the match
      # gone the load returns {:ok, _}.
      name: "applicability-required-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "      n when is_integer(n) and n >= 1 -> observed_count == n",
      to: "      n when is_integer(n) and n >= 1 -> true",
      command: ["mix", "test", "test/conformance/corpus_test.exs:508"]
    },
    # --- Q25 corpus integrity: tamper verbatim-vs-derived equality ------------
    %{
      # Disabling the tamper verbatim-vs-derived byte equality (always-true) lets a tamper case
      # whose verbatim artifact disagrees with the re-derived tampered bytes load. Targeted test
      # builds such a mismatched tamper and asserts {:error, :invalid}; with the equality gone the
      # load returns {:ok, _}.
      name: "tamper-verbatim-equality-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "      derived == verbatim_bytes",
      to: "      true",
      command: ["mix", "test", "test/conformance/corpus_test.exs:564"]
    },
    # --- independent runner verdict agreement ---------------------------------
    %{
      # Disabling verdict agreement in the independent Node runner (agree() returns false for every
      # case) turns every shipped case into a disagreement. Targeted test asserts the shipped
      # corpus yields agreed=180 disagreed=0; with agreement disabled it yields agreed=0
      # disagreed=180. Mutated in the isolated copy only.
      name: "runner-verdict-agreement-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  if (expected.verdict === \"invalid\") return actual === INVALID;\n  if (expected.verdict === \"valid\") {",
      to:
        "  if (expected.verdict === \"invalid\") return false;\n  if (expected.verdict === \"valid\") return false;\n  if (expected.verdict === \"valid\") {",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    # --- runner reject-vs-error typing (InvalidError whitelist) ---------------
    %{
      # A runner BUG (a non-InvalidError throw) on an INVALID-only path must ABORT the run, never be
      # laundered into agreement. The plant fires ONLY when Ed25519 verification FAILS — the
      # verify-grant invalid_key case reaches it; every valid case passes the assert. A regression
      # from the InvalidError whitelist back to a blanket `catch { actual = INVALID }` would SWALLOW
      # the ReferenceError to INVALID (the case is invalid-expected) and stay GREEN — which is
      # exactly the vacuity this entry catches (design C1; plan-review F2 invalid-only calibration).
      name: "runner-reject-typing",
      path: "conformance/corpus_independent.mjs",
      from:
        "  assert(verifyEd25519(pub, jws.message, jws.signature), \"verify_grant: Ed25519 signature\");",
      to:
        "  if (!verifyEd25519(pub, jws.message, jws.signature)) throw new ReferenceError(\"planted runner bug on invalid path\");",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    # --- two-boundary census: verification-import truth -----------------------
    %{
      # Deleting the real createPublicKey verification-import tracking makes the two-boundary census
      # unable to prove the runner ACTUALLY imported the verification keys — the verification-import
      # assertion reds (a valid verification key was never imported at node:crypto). Defeats finding
      # 4b's discovery-only-census vacuity (a census that stays green even if nothing is imported).
      name: "census-verification-import",
      path: "conformance/corpus_independent.mjs",
      from:
        "  importedPublicKeyFingerprints.add(fp);\n  verificationImportedFingerprints.add(fp);",
      to: "  importedPublicKeyFingerprints.add(fp);",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    # --- calibration self-proof (battery raises on a green-under-mutation) ----
    %{
      # A real caught mutation used to prove the raise path: disabling case-id uniqueness lets a
      # corpus with a duplicate id load. Targeted test asserts {:error, :invalid}; with the check
      # gone the load returns {:ok, _} and the test goes red. See the module doc for the
      # calibration self-proof: inverting that assertion once made the test stay green and the
      # battery raised `mutation survived: calibration-case-id-removal`.
      name: "calibration-case-id-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from:
        "    if length(all_ids) == MapSet.size(MapSet.new(all_ids)) and Enum.all?(all_ids, &is_binary/1),",
      to: "    if true,",
      command: ["mix", "test", "test/conformance/corpus_test.exs:555"]
    }
  ]

  @copy_paths [
    ".formatter.exs",
    ".tool-versions",
    "conformance",
    "lib",
    "mix.exs",
    "mix.lock",
    "priv",
    "scripts",
    "test",
    "tools"
  ]

  def run do
    Enum.each(@mutations, &run_mutation/1)
    IO.puts("bap05 mutation gate: ok mutations=#{length(@mutations)}")
  end

  defp run_mutation(mutation) do
    scratch =
      Path.join(
        System.tmp_dir!(),
        "bap05-mutation-#{mutation.name}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(scratch)

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

      # NOTE: command_args/1 returns the full argument list (task name + args) for the executable
      # named by hd(mutation.command). For `mix test` it appends `--max-cases 1` (serial, fastest
      # single-file run); for `mix architecture` it returns the task bare (the alias proxies extra
      # args to `elixir scripts/check_architecture.exs`, which exits 2 on any unknown flag).

      if status == 0 do
        raise "mutation survived: #{mutation.name}\n#{output}"
      end

      IO.puts("mutation caught: #{mutation.name}")
    after
      File.rm_rf!(scratch)
    end
  end

  # Returns the full argument list following the executable (hd of mutation.command). `mix test`
  # runs are serialized (`--max-cases 1`) for deterministic, fastest single-file execution.
  # `mix architecture` is returned bare: its alias proxies extra args to
  # `elixir scripts/check_architecture.exs`, which exits 2 on any unknown flag — so appending
  # anything would make every architecture entry spuriously red.
  defp command_args(["mix", "test" | rest]) do
    ["test" | rest] ++ ["--max-cases", "1"]
  end

  defp command_args(["mix", "architecture" | _rest]) do
    ["architecture"]
  end

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

BoundedAuthorityProtocol.ConformanceMutationGate.run()
