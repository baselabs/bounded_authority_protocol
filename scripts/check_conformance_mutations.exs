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
    # --- v2 range-selector + cross-major activation proofs (BAP-21 / ADR 0030) ----
    %{
      # Strictness mutation: the inclusive lte comparison flipped to strict reddens the
      # boundary-equal corpus case (argument == bound must PASS for inclusive kinds).
      name: "v2-selector-lte-strict",
      path: "lib/bounded_authority_protocol/v2/selector.ex",
      from: "  defp lte?({:integer, left}, {:integer, right}), do: left <= right\n",
      to: "  defp lte?({:integer, left}, {:integer, right}), do: left < right\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Same-tag domain removed: the cross-tag fall-through compares numerically, so the
      # integer-bound/float-argument corpus case flips to valid.
      name: "v2-selector-same-tag-removed",
      path: "lib/bounded_authority_protocol/v2/selector.ex",
      from:
        "  defp lte?(_left, _right), do: false\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?(_left, _right), do: false",
      to:
        "  defp lte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left <= right\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left >= right",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Kind swap: decoding lte as gte and gte as lte (both clauses swapped, so
      # range-bearing grants still decode — evaluated under the flipped kind)
      # flips the exceeded/unmet reject cases.
      name: "v2-selector-kinds-swapped",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "      {:ok,\n       %{\n         \"kind\" => {:string, \"lte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end\n\n      {:ok,\n       %{\n         \"kind\" => {:string, \"gte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:gte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end",
      to:
        "      {:ok,\n       %{\n         \"kind\" => {:string, \"lte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:gte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end\n\n      {:ok,\n       %{\n         \"kind\" => {:string, \"gte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Numeric-bound check dropped at decode: a string lte bound now decodes, so the
      # non-numeric-bound corpus cases flip to valid.
      name: "v2-selector-non-numeric-bound-accepted",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}",
      to:
        "             true <- path != [],\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Cross-major downgrade: the v2 grant decode accepting v:1 reddens the cross-major
      # corpus cases (a v1 grant must stay invalid under v2 — no downgrade path).
      name: "v2-cross-major-grant-v-accepted",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "         true <- valid_key_id?(key_id, bounds),\n         {:integer, 2} <- payload[\"v\"],\n         {:string, issuer} <- payload[\"iss\"],",
      to:
        "         true <- valid_key_id?(key_id, bounds),\n         true <- payload[\"v\"] in [{:integer, 1}, {:integer, 2}],\n         {:string, issuer} <- payload[\"iss\"],",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Domain-separator downgrade: BAP2-REQUEST\\0 flipped to BAP1 reddens every
      # request-digest corpus case (the digest is prefix-bound).
      name: "v2-request-digest-prefix-downgraded",
      path: "lib/bounded_authority_protocol/v2/request_digest.ex",
      from: "  @prefix <<\"BAP2-REQUEST\", 0>>\n",
      to: "  @prefix <<\"BAP1-REQUEST\", 0>>\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Same-tag domain removed: the cross-tag fall-through compares numerically, so the
      # integer-bound/float-argument corpus case flips to valid.
      name: "v2-selector-same-tag-removed",
      path: "lib/bounded_authority_protocol/v2/selector.ex",
      from:
        "  defp lte?(_left, _right), do: false\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?(_left, _right), do: false",
      to:
        "  defp lte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left <= right\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left >= right",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Kind swap: decoding lte as gte and gte as lte (both clauses swapped, so
      # range-bearing grants still decode — evaluated under the flipped kind)
      # flips the exceeded/unmet reject cases.
      name: "v2-selector-kinds-swapped",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "      {:ok,\n       %{\n         \"kind\" => {:string, \"lte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end\n\n      {:ok,\n       %{\n         \"kind\" => {:string, \"gte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:gte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end",
      to:
        "      {:ok,\n       %{\n         \"kind\" => {:string, \"lte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:gte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end\n\n      {:ok,\n       %{\n         \"kind\" => {:string, \"gte\"},\n         \"path\" => {:array, path_values},\n         \"value\" => bound\n       }} ->\n        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),\n             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}\n        else\n          _failure -> {:error, :invalid}\n        end",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Numeric-bound check dropped at decode: a string lte bound now decodes, so the
      # non-numeric-bound corpus cases flip to valid.
      name: "v2-selector-non-numeric-bound-accepted",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "             true <- path != [],\n             true <- numeric_bound?(bound),\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}",
      to:
        "             true <- path != [],\n             {:ok, _encoded} <- Jcs.encode(bound, bounds) do\n          {:ok, {:lte, path, bound}}",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Cross-major downgrade: the v2 grant decode accepting v:1 reddens the cross-major
      # corpus cases (a v1 grant must stay invalid under v2 — no downgrade path).
      name: "v2-cross-major-grant-v-accepted",
      path: "lib/bounded_authority_protocol/v2/runtime.ex",
      from:
        "         true <- valid_key_id?(key_id, bounds),\n         {:integer, 2} <- payload[\"v\"],\n         {:string, issuer} <- payload[\"iss\"],",
      to:
        "         true <- valid_key_id?(key_id, bounds),\n         true <- payload[\"v\"] in [{:integer, 1}, {:integer, 2}],\n         {:string, issuer} <- payload[\"iss\"],",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    %{
      # Domain-separator downgrade: BAP2-REQUEST\\0 flipped to BAP1 reddens every
      # request-digest corpus case (the digest is prefix-bound).
      name: "v2-request-digest-prefix-downgraded",
      path: "lib/bounded_authority_protocol/v2/request_digest.ex",
      from: "  @prefix <<\"BAP2-REQUEST\", 0>>\n",
      to: "  @prefix <<\"BAP1-REQUEST\", 0>>\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v2 corpus (in-VM)"}
    },
    # --- v3 ES256 suite activation proofs (BAP-22 / ADR 0035) ------------------
    %{
      # Canonicality: dropping the low-S half-order rule lets the high-S corpus case
      # (a genuinely verifying high-S signature — backend malleability, probe-observed)
      # pass precheck and verify, so verify-grant-v3-invalid-signature-high-s agrees as
      # valid, disagreeing with the corpus.
      name: "v3-signature-low-s-removed",
      path: "lib/bounded_authority_protocol/v3/es256.ex",
      from: "    ri > 0 and ri < @n and si > 0 and si <= @half_n\n",
      to: "    ri > 0 and ri < @n and si > 0\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
    %{
      # Same-tag domain removed (the v2 mirror under v3's selector module): the
      # cross-tag fall-through compares numerically, so both cross-tag corpus cases
      # (integer-bound/float-argument and float-bound/integer-argument) flip to valid.
      name: "v3-selector-range-cross-tag-accepted",
      path: "lib/bounded_authority_protocol/v3/selector.ex",
      from:
        "  defp lte?(_left, _right), do: false\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?(_left, _right), do: false",
      to:
        "  defp lte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left <= right\n\n  defp gte?({:integer, left}, {:integer, right}), do: left >= right\n  defp gte?({:float, left}, {:float, right}), do: left >= right\n  defp gte?({_tag, left}, {_other, right}), do: is_number(left) and is_number(right) and left >= right",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
    %{
      # Curve pin removed: any string crv decodes, so jwk-decode-public-invalid-crv-p384
      # (valid P-256 coordinates under crv P-384) flips to valid.
      name: "v3-jwk-curve-accepted",
      path: "lib/bounded_authority_protocol/v3/ec_jwk.ex",
      from: "            \"crv\" => {:string, \"P-256\"},",
      to: "            \"crv\" => {:string, _curve},",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
    %{
      # Thumbprint member set: the preimage without y changes every EC thumbprint, so the
      # jwk thumbprint/encode valid cases disagree with their pinned expected outputs.
      name: "v3-thumbprint-member-set-wrong",
      path: "lib/bounded_authority_protocol/v3/ec_jwk.ex",
      from: ~S|      ~s(","y":") <> Base.url_encode64(y, padding: false) <> ~s("})|,
      to: ~S|      ~s("})|,
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
    %{
      # Cross-major downgrade (the v2 mirror under v3 constants): the v3 grant decode
      # accepting v:1/v:2 reddens both cross-major corpus cases.
      name: "v3-cross-major-grant-header-and-v-accepted",
      path: "lib/bounded_authority_protocol/v3/runtime.ex",
      from:
        "    with {:string, \"ES256\"} <- header[\"alg\"],\n         {:string, \"ba+cap\"} <- header[\"typ\"],\n         {:string, key_id} <- header[\"kid\"],\n         true <- valid_key_id?(key_id, bounds),\n         {:integer, 3} <- payload[\"v\"],",
      to:
        "    with true <- header[\"alg\"] in [{:string, \"ES256\"}, {:string, \"EdDSA\"}],\n         {:string, \"ba+cap\"} <- header[\"typ\"],\n         {:string, key_id} <- header[\"kid\"],\n         true <- valid_key_id?(key_id, bounds),\n         true <- payload[\"v\"] in [{:integer, 1}, {:integer, 2}, {:integer, 3}],",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
    %{
      # Domain-separator downgrade: BAP3-REQUEST\0 flipped to BAP1 reddens every
      # request-digest corpus case (the digest is prefix-bound).
      name: "v3-request-digest-prefix-downgraded",
      path: "lib/bounded_authority_protocol/v3/request_digest.ex",
      from: "  @prefix <<\"BAP3-REQUEST\", 0>>\n",
      to: "  @prefix <<\"BAP1-REQUEST\", 0>>\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped v3 corpus (in-VM)"}
    },
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
      # A BARE-ALIAS reference to the Cli carve-out from a NON-conformance module (v1.ex) turns the
      # gate red via the existing module-allowance discipline: the planted `Cli.run([])` (behind a
      # function-scoped alias) references the bare `Cli` root, which is not approved for v1.ex, so
      # node_violations fires `forbidden module/call Cli` (:unapproved_runtime). Planted as a USED
      # call in a function body (compiles clean, no unused-attribute warning), so the ARCHITECTURE
      # GATE — not the compiler — is what reds (plan-review F6). Proves the carve-out is unreachable
      # from the protocol core.
      name: "cli-reachability",
      path: "lib/bounded_authority_protocol/v1.ex",
      from: "  def untrusted_key_locator(compact, limits) when is_binary(compact) do\n",
      to:
        "  def untrusted_key_locator(compact, limits) when is_binary(compact) do\n    alias BoundedAuthorityProtocol.Conformance.Cli\n    Cli.run([])\n",
      command: ["mix", "architecture"]
    },
    %{
      # A FULLY-QUALIFIED reference to the Cli carve-out from v1.ex turns the gate red via the
      # reverse-reachability extension added this slice. `BoundedAuthorityProtocol.Conformance.Cli`
      # carries the `BoundedAuthorityProtocol` root, which the blanket passthrough would otherwise
      # allow; conformance_cli_leak? closes it for the fully-qualified form from outside conformance/.
      # Planted as a USED call so the GATE (not the compiler) is what reds. Guard-family sibling of
      # the bare-alias entry (the same carve-out reachable two ways); both node_violations
      # passthroughs — the alias case and the MFA/mfa_category case — are swept.
      name: "cli-reachability-fq",
      path: "lib/bounded_authority_protocol/v1.ex",
      from: "  def untrusted_key_locator(compact, limits) when is_binary(compact) do\n",
      to:
        "  def untrusted_key_locator(compact, limits) when is_binary(compact) do\n    BoundedAuthorityProtocol.Conformance.Cli.run([])\n",
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
      target:
        {"test/conformance/corpus_test.exs",
         "an index total_cases that disagrees with the files is rejected"}
    },
    %{
      # Disabling the per-file SHA-256 equality (always-true guard) lets a corpus with a stale
      # index hash load. Targeted test rewrites one case-file hash in the index and asserts
      # {:error, :invalid}; with the guard gone the load returns {:ok, _}.
      name: "corpus-hash-check-removal",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from: "           true <- sha256_b64(bytes) == hash do",
      to: "           true <- true do",
      target:
        {"test/conformance/corpus_test.exs",
         "a tampered case byte (hash mismatch) is rejected at corpus load"}
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
      target:
        {"test/conformance/corpus_test.exs",
         "an unlisted case file (present in corpus, absent from index) is rejected"}
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
      target:
        {"test/conformance/corpus_test.exs",
         "a required applicability cell declared but with zero executed cases is rejected"}
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
      target:
        {"test/conformance/corpus_test.exs",
         "a tamper case whose verbatim artifact disagrees with the derived bytes is rejected"}
    },
    # --- independent runner verdict agreement ---------------------------------
    %{
      # Disabling verdict agreement in the independent Node runner (agree() returns false for every
      # case) turns every shipped case into a disagreement. Targeted test asserts the shipped
      # corpus yields agreed=259 disagreed=0; with agreement disabled it yields agreed=0
      # disagreed=259. Mutated in the isolated copy only.
      name: "runner-verdict-agreement-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  if (expected.verdict === \"invalid\") return actual === INVALID;\n  if (expected.verdict === \"valid\") {",
      to:
        "  if (expected.verdict === \"invalid\") return false;\n  if (expected.verdict === \"valid\") return false;\n  if (expected.verdict === \"valid\") {",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
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
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
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
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- Task 2: tamper target resolution (audit binds to the addressed bytes) -
    %{
      # The compact-target audit must resolve input.compact, NOT default to input.text. This
      # mutation makes the "compact" target fall back to text resolution — the exact bug the
      # `target` field exists to prevent — so a compact-target tamper case (which carries no
      # input.text) fails to resolve, the verbatim-vs-derived audit mismatches, and the corpus
      # fails to load. The positive compact-target test asserts {:ok, _}; under the mutation the
      # load returns {:error, :invalid} and the test goes red. Proves target resolution is
      # load-bearing (the audit binds to the addressed artifact, not a fixed field).
      name: "tamper-target-binding",
      path: "lib/bounded_authority_protocol/conformance/corpus.ex",
      from:
        "      t when t in [\"compact\", \"grant\", \"proof\"] -> string_target_bytes(input, t)",
      to: "      t when t in [\"compact\", \"grant\", \"proof\"] -> text_target_bytes(input)",
      target:
        {"test/conformance/corpus_test.exs",
         "a compact-target tamper re-derives against input.compact (not input.text) and loads"}
    },
    %{
      # The independent Node runner's verbatim-vs-derived tamper audit must run at load. Removing
      # the verifyTampers call lets a corpus whose tamper verbatim disagrees with the re-derived
      # bytes load and "agree". Targeted test feeds a corrupted-verbatim corpus (its index hash
      # re-synced so the SHA-256 gate passes and the tamper audit is what fires) and asserts exit 1;
      # with the audit gone the runner exits 0 and the test goes red.
      name: "node-tamper-audit-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  // Tamper verbatim-vs-derived audit (mirrors the official loader; a mismatch aborts the run).\n  verifyTampers(cases);",
      to: "  // tamper audit disabled (mutation)",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "exit 1 when a tamper case's verbatim disagrees with the re-derived bytes (tamper audit)"}
    },
    # --- Task 3: per-invariant-family rejection proofs ------------------------
    %{
      # decode_grant performs NO signature verification, so its alg pin is the ONLY check that
      # rejects an alg:"none" header. Removing it lets grant-decode-invalid-algorithm-none decode
      # to a valid projection -> it agrees as valid -> the runner disagrees with the corpus (which
      # declares it invalid) -> the agreement test reds. Proves the algorithm pin is load-bearing.
      name: "alg-header-reject",
      path: "conformance/corpus_independent.mjs",
      from:
        "  assert(header.alg === \"EdDSA\" && header.typ === \"ba+cap\", \"decode_grant header values\");",
      to: "  assert(header.typ === \"ba+cap\", \"decode_grant header values\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Disabling the proof Ed25519 verification lets a meaningful-byte signature tamper pass:
      # check-envelope-tamper-proof-signature-byte then agrees as valid, disagreeing with the
      # corpus. Proves the signature check catches a tampered signature byte.
      name: "tamper-reject",
      path: "conformance/corpus_independent.mjs",
      from:
        "  assert(verifyEd25519(holderPub, proofJws.message, proofJws.signature), \"check_envelope: proof signature\");",
      to: "  assert(true, \"check_envelope: proof signature\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Disabling the method binding lets check-envelope-invalid-request-method (a mismatched
      # expected.method) agree as valid -> disagreement. Proves the request method binding is
      # verified (the gap this slice's vectors surfaced and the runner now closes).
      name: "envelope-binding-reject",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(proofPayload.htm === method, \"check_envelope: method\");",
      to: "  assert(true, \"check_envelope: method\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Disabling the nonce binding (a distinct mechanism from the ===-equality bindings) lets
      # check-envelope-invalid-nonce-required (expected {required: n} while the proof carries no
      # nonce) verify -> it agrees as valid -> disagreement. Proves the nonce binding is verified.
      name: "envelope-nonce-reject",
      path: "conformance/corpus_independent.mjs",
      from:
        "    assert(proofPayload.nonce === expNonce.required, \"check_envelope: nonce mismatch\");",
      to: "    assert(true, \"check_envelope: nonce mismatch\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Disabling the per-row previous-link check (comparing row.previous to itself always passes)
      # lets check-chain-invalid-encoding-broken-link (a corrupted `previous`, last_hash re-derived
      # to match) verify as a self-consistent chain -> it agrees as valid -> disagreement. Proves
      # the hash-chain link verification is load-bearing.
      name: "chain-link-reject",
      path: "conformance/corpus_independent.mjs",
      from: "equalBytes(strictB64(row.previous, 32), previous, ",
      to: "equalBytes(strictB64(row.previous, 32), strictB64(row.previous, 32), ",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Disabling the object-version binding lets verify-anchored-export-invalid-claim-version (a
      # mismatched expected.object_version) verify -> it agrees as valid -> disagreement. Proves the
      # archive object-version binding is verified.
      name: "archive-invalid-reject",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(version === objectVersion, \"verify_anchored_export: object version\");",
      to: "  assert(true, \"verify_anchored_export: object version\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # The Node tamper audit's extended-target resolution must bind "compact" to input.compact
      # (not fall back to input.text). This mutation resolves the compact target via input.text —
      # the real compact-target tamper cases (verify-grant/anchor/transition/proof signature-byte
      # tampers) carry no input.text, so the audit throws at load and the runner exits nonzero,
      # reddening the agreement test. Proves the independent Node extended-target resolution is
      # load-bearing (Task 2 review finding B: the Node compact/grant/proof/rows/chunks paths).
      name: "node-tamper-target-compact",
      path: "conformance/corpus_independent.mjs",
      from:
        "      if (typeof input.compact === \"string\") return Buffer.from(input.compact, \"utf8\");",
      to: "      if (typeof input.text === \"string\") return Buffer.from(input.text, \"utf8\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- Task 4: json.decode structural-limit boundary rejection -------------
    %{
      # Loosening the object-name (key) byte ceiling in the Node decoder lets
      # json-decode-key_bytes-maximum-plus-one (a 129-byte key) decode as valid -> it agrees valid,
      # disagreeing with the corpus (which declares it invalid). Proves the key_bytes limit — added
      # to the Node runner this slice — is load-bearing.
      name: "json-decode-key-bytes-loosen",
      path: "conformance/corpus_independent.mjs",
      from:
        "    assert(Buffer.byteLength(name, \"utf8\") <= 128, \"json object-name byte bound\");",
      to:
        "    assert(Buffer.byteLength(name, \"utf8\") <= 129, \"json object-name byte bound\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Loosening the string-value byte ceiling lets json-decode-string_bytes-maximum-plus-one (an
      # 8193-byte string value) decode as valid -> disagreement. Proves the string_bytes limit — now
      # measured on the DECODED value's UTF-8 bytes (not the quoted literal) this slice — is
      # load-bearing at the boundary.
      name: "json-decode-string-bytes-loosen",
      path: "conformance/corpus_independent.mjs",
      from:
        "        assert(Buffer.byteLength(parsed, \"utf8\") <= 8192, \"json string byte bound\");",
      to:
        "        assert(Buffer.byteLength(parsed, \"utf8\") <= 8193, \"json string byte bound\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- check_envelope selector binding (BAP-05 selector remediation) --------
    %{
      # Neutralizing the check_envelope selector match (runtime.ex:498) makes the OFFICIAL verifier
      # ACCEPT check-envelope-invalid-selector (its grant carries an `equals ["record","id"] "rec-1"`
      # selector that the case's rec-2 cast_arguments fail). The Node runner still rejects it, so the
      # shipped-corpus CLI reports a disagreement and Cli.run returns nonzero -> cli_test:42 (exit 0
      # on the shipped corpus) goes red. The `is_nil` guard keeps `operation` referenced so the
      # mutated source still compiles under --warnings-as-errors (selectors are always a non-empty
      # list after decode, so the bypass branch always fires). FAMILY: this is the SOLE selector
      # enforcement point on the check_envelope path (`grep Selector.match_all lib/` -> one hit).
      name: "check-envelope-selector-reject-removal",
      path: "lib/bounded_authority_protocol/v1/runtime.ex",
      from:
        "         :ok <- Selector.match_all(operation.selectors, expected.cast_arguments, bounds),\n",
      to:
        "         :ok <-\n           (if is_nil(operation.selectors),\n              do: Selector.match_all(operation.selectors, expected.cast_arguments, bounds),\n              else: :ok),\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped corpus (in-VM)"}
    },
    # --- check_envelope authority bindings (BAP-05 selector closeout) ----------
    # Each binding below is the SOLE rejecter of one shipped invalid_claim case, so neutralizing it
    # flips that case to accept, the Node runner still rejects, and the shipped corpus disagrees ->
    # cli_test:42 goes red. Before these cases existed the whole corpus stayed green under every one
    # of these mutations (the closeout lenses proved that blindness mechanically).
    %{
      # Holder binding (proof-of-possession): without it ANY holder's validly-signed proof is
      # accepted against a grant issued to a different holder. Isolated by
      # check-envelope-invalid-claim-holder-binding.
      name: "check-envelope-holder-binding-removal",
      path: "lib/bounded_authority_protocol/v1/runtime.ex",
      from: "    with true <- secure_equal?(proof.holder_thumbprint, grant.holder_thumbprint),\n",
      to:
        "    with true <-\n           (if is_nil(proof.holder_thumbprint),\n              do: secure_equal?(proof.holder_thumbprint, grant.holder_thumbprint),\n              else: true),\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped corpus (in-VM)"}
    },
    %{
      # Grant binding (`ath`): without it a proof minted over one grant is replayable against a
      # different grant held by the same holder — scope widening. Isolated by
      # check-envelope-invalid-claim-grant-binding.
      name: "check-envelope-ath-binding-removal",
      path: "lib/bounded_authority_protocol/v1/runtime.ex",
      from: "         true <- secure_equal?(proof.grant_hash, grant_hash),\n",
      to:
        "         true <-\n           (if is_nil(proof.grant_hash),\n              do: secure_equal?(proof.grant_hash, grant_hash),\n              else: true),\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped corpus (in-VM)"}
    },
    %{
      # Request-argument binding (`ba_req`): without it a proof is replayable with different cast
      # arguments — argument substitution. Isolated by
      # check-envelope-invalid-claim-request-arguments.
      name: "check-envelope-request-digest-binding-removal",
      path: "lib/bounded_authority_protocol/v1/runtime.ex",
      from: "         true <- secure_equal?(proof.request_hash, request_hash),\n",
      to:
        "         true <-\n           (if is_nil(proof.request_hash),\n              do: secure_equal?(proof.request_hash, request_hash),\n              else: true),\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped corpus (in-VM)"}
    },
    %{
      # Operation binding (`ba_op`): the request digest is computed over the SERVER-derived
      # expected.operation, never over proof.ba_op, so this line is the ONLY constraint on the
      # holder-signed ba_op claim — it is NOT subsumed by ba_req. Without it a dishonest producer
      # signs ba_op "write" alongside a ba_req over "read" and the false claim rides into
      # EnvelopeFacts.operation unchecked. Isolated by
      # check-envelope-invalid-claim-operation-binding, whose proof is exactly that shape (the
      # producer facade cannot build it, which is why this binding was unexercised until now).
      name: "check-envelope-operation-binding-removal",
      path: "lib/bounded_authority_protocol/v1/runtime.ex",
      from: "         true <- secure_equal?(proof.operation, expected.operation),\n",
      to:
        "         true <-\n           (if is_nil(proof.operation),\n              do: secure_equal?(proof.operation, expected.operation),\n              else: true),\n",
      target: {"test/conformance/cli_test.exs", "exit 0 on the shipped corpus (in-VM)"}
    },
    %{
      # Node-side selector PATH validation. The official rejects an empty selector path at grant
      # decode; without validSelectorPath the independent runner treats [] as "the root", matches
      # check-envelope-invalid-selector-empty-path (whose value IS the whole cast_arguments), and
      # accepts what the official refuses -> the runner reports a disagreement and exits 1. This is
      # what makes the matcher's shape hardening falsifiable rather than defensive code no gate can
      # prove: with the mutation applied the runner reports
      # `agreed=219 disagreed=1 ... disagreements: check-envelope-invalid-selector-empty-path`.
      # TARGET: this mutates the NODE runner, so it targets the Node runner test. cli_test:42 is
      # structurally blind here — that test runs the official Elixir CLI against the corpus's
      # expected verdicts and never executes corpus_independent.mjs (proven: this entry SURVIVED
      # while pointed at cli_test:42, and is caught pointed here).
      name: "check-envelope-node-selector-path-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  if (!Array.isArray(path) || path.length < 1 || path.length > MAXIMA.path_segments) return false;\n",
      to: "  if (!Array.isArray(path)) return false;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- independent-runner permissiveness (BAP-05 selector closeout, round 4) -
    # Each entry deletes one guard that keeps the Node runner from being MORE PERMISSIVE than the
    # official. Removing any of them makes the runner accept a grant the official refuses, so the
    # corpus disagrees and the runner test goes red. These target the Node runner test, never
    # cli_test:42, which runs the official CLI and cannot observe a .mjs change.
    %{
      # `cnf` is a closed map in the official; without this the runner accepts an extra member.
      name: "node-check-envelope-cnf-closed-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  exactKeys(grantPayload.cnf, [\"jkt\"], \"check_envelope grant cnf\");\n",
      to: "\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Operation names are printable ASCII in the official (valid_operation?).
      name: "node-operation-name-charset-removal",
      path: "conformance/corpus_independent.mjs",
      from: "    /^[\\x20-\\x7E]*$/.test(name)\n",
      to: "    true\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # The official enforces global operation-name uniqueness (unique?).
      name: "node-duplicate-operation-name-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  assert(new Set(names).size === names.length, `${context}: duplicate operation name`);\n",
      to: "  void names;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # The official validates EVERY operation's selectors, not just the requested one.
      name: "node-nonmatching-operation-selector-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from: "    for (const selector of op.selectors) validSelectorShape(selector, context);\n",
      to: "\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Protocol strings must be valid UTF-8 (String.valid?); a byte-length check accepts a lone
      # surrogate the official rejects.
      name: "node-selector-path-utf8-validity-removal",
      path: "conformance/corpus_independent.mjs",
      from: "      wellFormedString(segment) &&\n",
      to: "      typeof segment === \"string\" &&\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # On a plain {} the tagged projection loses a `__proto__` member to the prototype setter, so
      # two distinct values canonicalize identically and the selector wrongly matches.
      name: "node-tagged-projection-prototype-safety-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  const obj = Object.create(null);\n",
      to: "  const obj = {};\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Selector values must satisfy the protocol JSON bounds (official: Jcs.encode(value, bounds)).
      # Without this the runner accepts a grant whose selector value exceeds object_members.
      name: "node-selector-value-json-bounds-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function withinJsonBounds(value, level = 0) {\n",
      to: "function withinJsonBounds(value, level = 0) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # The official matches `all` on an OPEN pattern, so kind:"all" decodes as :all on ANY of the
      # three closed member sets. Requiring members === "kind" makes the runner STRICTER than the
      # official — it would reject a conforming grant. The valid fixture
      # check-envelope-valid-selector-all-with-extra-members flips to invalid under this mutation.
      name: "node-selector-all-open-pattern-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  if (selector.kind === \"all\") return;\n",
      to: "  if (selector.kind === \"all\" && members === \"kind\") return;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Selector-value magnitude. The official caps |value| at 9007199254740991; without this the
      # runner accepts a grant carrying 2^53, which the official rejects at decode.
      name: "node-selector-value-magnitude-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "      Number.isFinite(value) &&\n      Math.abs(value) <= MAXIMA.integer_magnitude\n    );",
      to: "      Number.isFinite(value)\n    );",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Object member keys have NO one-byte floor in the official ({"":1} is accepted, probed
      # directly). Re-adding a floor makes the runner STRICTER than the official and flips the
      # valid empty-object-key fixture to invalid.
      name: "node-selector-value-empty-key-floor-reintroduction",
      path: "conformance/corpus_independent.mjs",
      from:
        "      wellFormedString(k) &&\n      Buffer.byteLength(k, \"utf8\") <= MAXIMA.key_bytes &&\n",
      to:
        "      wellFormedString(k) &&\n      Buffer.byteLength(k, \"utf8\") >= 1 &&\n      Buffer.byteLength(k, \"utf8\") <= MAXIMA.key_bytes &&\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- payload field-validation mirror (decode surfaces) --------------------
    # Each validator mirrors a decode_grant_fields/decode_proof_fields check the runner did not
    # have. The cases live on decode_grant/decode_proof (no expected context to mask the
    # validator), so neutralizing one makes the runner accept a grant/proof the official
    # decoder rejects -> corpus disagreement -> the Node runner test goes red.
    %{
      # valid_identifier?: 1..identifier_bytes + StringOrUri; catches empty jti and non-URI iss.
      name: "node-decode-valid-identifier-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function validIdentifier(value) {\n",
      to: "function validIdentifier(value) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # valid_method?: token charset; catches a method with a space.
      name: "node-decode-valid-method-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function validMethod(value) {\n",
      to: "function validMethod(value) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # valid_uuid?: exact UUID shape; catches a non-UUID ba_inv.
      name: "node-decode-valid-uuid-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function validUuid(value) {\n",
      to: "function validUuid(value) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # coherent_times?: iat<exp and nbf<exp; catches iat >= exp.
      name: "node-decode-coherent-times-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function coherentTimes(iat, nbf, exp) {\n",
      to: "function coherentTimes(iat, nbf, exp) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # decode_audiences: count bound + per-element validity + uniqueness; catches over-max and duplicate aud.
      name: "node-decode-audiences-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function decodeAudiences(aud) {\n",
      to: "function decodeAudiences(aud) {\n  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # decode_proof requires htu already normalized (Uri.normalize(htu) === htu); check_envelope
      # reaches this via equality to the expected target_uri, but decode has no expected.
      name: "node-decode-proof-htu-normalization-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(normalized === payload.htu, \"decode_proof: htu normalized\");\n",
      to: "  void normalized;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # StringOrURI structure: the official gates iss/jti/aud on URI.new (numeric port, terminated
      # IPv6, single @) beyond the byte check. Without validUriAuthority the runner accepts
      # http://a:b (non-numeric port) which the official rejects.
      name: "node-decode-string-or-uri-authority-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  return validUriAuthority(rest.slice(2).split(/[/?#]/, 1)[0]);\n",
      to: "  return true;\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # Optional proof nonce: present must be a well-formed string of 1..nonce_bytes
      # (official optional_nonce -> valid_nonce?). Without this the runner accepts an empty nonce.
      name: "node-decode-proof-nonce-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  if (payload.nonce !== undefined) {\n",
      to: "  if (false) {\n",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
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
      target: {"test/conformance/corpus_test.exs", "a duplicate case id across files is rejected"}
    },
    # --- runner permissiveness residuals: the four closed permissive gaps + the guard family -----
    %{
      # withinJsonBounds per-node-type depth: reverting the SCALAR depth to `level < depth` (the old
      # uniform-gate strictness) rejects request-digest-exact-bound-value-depth's deep integer scalar
      # in the typed projection -> the valid 15-deep case decodes INVALID -> disagreement. Proves the
      # scalar<=depth / container<depth distinction is load-bearing (not the old uniform gate).
      name: "runner-withinjsonbounds-scalar-depth",
      path: "conformance/corpus_independent.mjs",
      from: "level <= MAXIMA.depth &&\n      Number.isFinite(value) &&",
      to: "level < MAXIMA.depth &&\n      Number.isFinite(value) &&",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # isInteger magnitude: dropping the |value| <= integer_magnitude bound lets a proof with
      # iat = 2^53 decode valid -> decode-proof-maximum-plus-one-iat-magnitude disagrees (official
      # rejects at Json.decode magnitude). Proves the magnitude bound on integer claims is real.
      name: "runner-isinteger-magnitude",
      path: "conformance/corpus_independent.mjs",
      from: "Number.isInteger(value) &&\n    Math.abs(value) <= MAXIMA.integer_magnitude",
      to: "Number.isInteger(value)",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # requestDigest total_nodes: removing the typed-projection node bound lets a value-carried
      # cast_arguments exceeding 4096 typed nodes produce a digest -> request-digest-maximum-plus-one-
      # total-nodes disagrees (official request_digest rejects). The typed projection triples nodes,
      # so this is expressible while the raw stays under the loader's own node ceiling.
      name: "runner-requestdigest-total-nodes",
      path: "conformance/corpus_independent.mjs",
      from:
        "if (countJsonNodes(projected) > MAXIMA.total_nodes) fail(\"request_digest: total_nodes\");",
      to: "// total_nodes check removed (mutation)",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # requestDigest jcs_bytes: removing the canonical byte bound lets a typed projection exceeding
      # jcs_bytes (65536) produce a digest -> request-digest-maximum-plus-one-jcs-bytes disagrees.
      name: "runner-requestdigest-jcs-bytes",
      path: "conformance/corpus_independent.mjs",
      from:
        "if (Buffer.byteLength(jcs, \"utf8\") > MAXIMA.jcs_bytes) fail(\"request_digest: jcs_bytes\");",
      to: "// jcs_bytes check removed (mutation)",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # requestDigest operation validation: neutering valid_operation? lets a 129-byte operation
      # produce a digest -> request-digest-maximum-plus-one-operation disagrees (official rejects an
      # over-length / non-printable operation before hashing).
      name: "runner-requestdigest-operation",
      path: "conformance/corpus_independent.mjs",
      from: "assert(validOperationName(operation), \"request_digest: operation\");",
      to: "assert(true, \"request_digest: operation\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # parseCanonicalJson whole-payload depth: neutering the container-depth gate lets a grant whose
      # payload nests past depth 32 decode -> decode-grant-maximum-plus-one-payload-depth disagrees
      # (official rejects the deep payload at Json.decode). Closes the whole-payload depth
      # permissiveness the runner previously left open (parseCanonicalJson had no depth bound).
      name: "runner-parsecanonical-payload-depth",
      path: "conformance/corpus_independent.mjs",
      from: "assert(containerDepth(value) <= MAXIMA.depth, `${context}: depth`);",
      to: "assert(true, `${context}: depth`);",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    %{
      # jsonDecode per-node-type depth — the guard-family sibling of withinJsonBounds and the ACTUAL
      # C4 content. The official Json.decode bounds only CONTAINERS (start_container level <= depth),
      # never scalars, so a 32-deep scalar-inner nest is valid. Re-introducing a per-SCALAR depth
      # check in decodeValue (the pre-fix bug) rejects that scalar at depth 33 -> ONLY
      # json-decode-exact-bound-depth-scalar-inner disagrees (the pre-existing empty-inner exact-bound
      # case never reaches a scalar at the boundary, so it does NOT catch this — which is exactly why
      # the scalar-inner case was added). The too-STRICT direction that silently fails a conforming
      # verifier. (The container-entry offset is separately guarded by the empty-inner differential.)
      name: "runner-jsondecode-scalar-depth",
      path: "conformance/corpus_independent.mjs",
      from: "    skipWhitespace();\n    assert(index < text.length, \"json value\");",
      to:
        "    assert(depth <= 32, \"json depth bound\");\n    skipWhitespace();\n    assert(index < text.length, \"json value\");",
      target:
        {"test/conformance/corpus_independent_test.exs",
         "independent runner agrees on every shipped corpus case (repo mode)"}
    },
    # --- Role-attestation sibling profile (BAP-23 / ADR 0036) ------------------
    %{
      # Self-attestation material check removed: the attestor thumbprint equaling the subject
      # thumbprint no longer rejects, so the self-attestation-same-material corpus case verifies.
      name: "role-attestation-self-material-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from:
        "         true <- not FixedBytes.equal?(attestor_fingerprint, subject_fingerprint),\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Self-attestation key-id check removed: the same-key-id corpus case verifies.
      name: "role-attestation-self-kid-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- parsed.key_id != attestor.key_id,\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Window containment upper bound removed: an exp beyond the attestor key's valid_before
      # (the retired-key backdating attack) verifies.
      name: "role-attestation-containment-exp-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from:
        "         true <-\n           attestor.valid_before == :unbounded or\n             parsed.exp <= attestor.valid_before,\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Window containment lower bound removed: an nbf before the attestor window opens verifies.
      name: "role-attestation-containment-nbf-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- parsed.nbf >= attestor.valid_from,\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # now-window check removed: now == exp (and now < nbf) no longer reject.
      name: "role-attestation-now-window-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- parsed.nbf <= expected.now and expected.now < parsed.exp,\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Attestor kid binding removed: a header kid naming another attestor verifies.
      name: "role-attestation-kid-binding-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- parsed.attestor_key_id == attestor.key_id,\n",
      to: "         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Subject binding removed: subject key_id and raw public_key equality no longer checked.
      name: "role-attestation-subject-binding-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from:
        "         true <- parsed.key_id == expected.subject_key_id,\n         true <- FixedBytes.equal?(parsed.public_key, expected.subject_public_key),\n",
      to: "         true <- true,\n         true <- true,\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Closed role set widened: any binary role decodes and verifies.
      name: "role-attestation-role-closed-set-widened",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- valid_role?(role),\n",
      to: "         true <- is_binary(role),\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Payload canonical-byte equality removed: non-canonical member order, duplicate members,
      # and the float v lexeme all decode.
      name: "role-attestation-canonical-bytes-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from: "         true <- payload_bytes == canonical_payload do\n",
      to: "         true <- true do\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
    },
    %{
      # Signature verification removed: any 64-byte signature verifies.
      name: "role-attestation-signature-removed",
      path: "lib/bounded_authority_protocol/role_attestation/v1/codec.ex",
      from:
        "         true <- verify_signature(parsed.message, parsed.signature, attestor.public_key) do\n",
      to: "         true <- true do\n",
      target:
        {"test/bounded_authority_protocol/role_attestation/v1_test.exs",
         "the certified language-neutral corpus drives decode and verify verdicts"}
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
    "test_support",
    "tools"
  ]

  def run do
    Enum.each(@mutations, &run_mutation/1)
    IO.puts("conformance mutation gate: ok mutations=#{length(@mutations)}")
  end

  defp run_mutation(mutation) do
    baseline_green!(mutation)

    scratch =
      Path.join(
        System.tmp_dir!(),
        "conformance-mutation-#{System.pid()}-#{mutation.name}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir!(scratch)

    try do
      Enum.each(@copy_paths, &copy_path(&1, scratch))
      File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
      copy_build(scratch)
      mutate_once!(Path.join(scratch, mutation.path), mutation.from, mutation.to)

      {output, status} =
        System.cmd(hd(command_for(mutation)), command_args(command_for(mutation)),
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

  # Baseline non-vacuity: before any mutation, the entry's UNMUTATED command must run green in a
  # clean scratch. Without this, a deleted or drifted target test makes `mix test` exit non-zero
  # ("did not match any file"/"no tests executed") and the battery scores the red as "caught" —
  # the deleted-test false-green the 2026-08-20 gate-integrity review named. Cached per unique
  # command so shared targets pay the baseline once per battery run.
  defp baseline_green!(mutation) do
    key = {:baseline_green, mutation.name}

    if Process.get(key) != :ok do
      scratch =
        Path.join(
          System.tmp_dir!(),
          "conformance-baseline-#{System.pid()}-#{System.unique_integer([:positive, :monotonic])}"
        )

      File.mkdir!(scratch)

      try do
        Enum.each(@copy_paths, &copy_path(&1, scratch))
        File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
        copy_build(scratch)

        {output, status} =
          System.cmd(hd(command_for(mutation)), command_args(command_for(mutation)),
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

  # Returns the full argument list following the executable (hd of mutation.command). `mix test`
  # runs are serialized (`--max-cases 1`) for deterministic, fastest single-file execution.
  # `mix architecture` is returned bare: its alias proxies extra args to
  # `elixir scripts/check_architecture.exs`, which exits 2 on any unknown flag — so appending
  # anything would make every architecture entry spuriously red.

  # Name-resolved test targeting: line pins drifted three separate times (edits anywhere
  # above the target silently re-pointed them); targets now carry the TEST NAME and the
  # line is resolved against the (scratch) file at run time. Unresolvable => raise, not
  # a silently-green gate.
  defp command_for(%{target: {path, test_name}}) do
    ["mix", "test", "#{path}:#{test_line!(path, test_name)}"]
  end

  defp command_for(%{command: command}), do: command

  defp test_line!(path, test_name) do
    prefix = ~s(test "#{test_name}")

    case path
         |> File.read!()
         |> String.split("\n")
         |> Enum.find_index(&String.contains?(&1, prefix)) do
      nil -> raise "mutation target test not found in #{path}: #{test_name}"
      index -> index + 1
    end
  end

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
