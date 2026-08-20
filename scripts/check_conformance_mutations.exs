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
      # corpus yields agreed=259 disagreed=0; with agreement disabled it yields agreed=0
      # disagreed=259. Mutated in the isolated copy only.
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
      command: ["mix", "test", "test/conformance/corpus_test.exs:649"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:74"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Disabling the method binding lets check-envelope-invalid-request-method (a mismatched
      # expected.method) agree as valid -> disagreement. Proves the request method binding is
      # verified (the gap this slice's vectors surfaced and the runner now closes).
      name: "envelope-binding-reject",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(proofPayload.htm === method, \"check_envelope: method\");",
      to: "  assert(true, \"check_envelope: method\");",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Disabling the object-version binding lets verify-anchored-export-invalid-claim-version (a
      # mismatched expected.object_version) verify -> it agrees as valid -> disagreement. Proves the
      # archive object-version binding is verified.
      name: "archive-invalid-reject",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(version === objectVersion, \"verify_anchored_export: object version\");",
      to: "  assert(true, \"verify_anchored_export: object version\");",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    # --- check_envelope selector binding (BAP-05 selector remediation) --------
    %{
      # Neutralizing the check_envelope selector match (runtime.ex:498) makes the OFFICIAL verifier
      # ACCEPT check-envelope-invalid-selector (its grant carries an `equals ["record","id"] "rec-1"`
      # selector that the case's rec-2 cast_arguments fail). The Node runner still rejects it, so the
      # shipped-corpus CLI reports a disagreement and Cli.run returns nonzero -> cli_test:36 (exit 0
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
      command: ["mix", "test", "test/conformance/cli_test.exs:38"]
    },
    # --- check_envelope authority bindings (BAP-05 selector closeout) ----------
    # Each binding below is the SOLE rejecter of one shipped invalid_claim case, so neutralizing it
    # flips that case to accept, the Node runner still rejects, and the shipped corpus disagrees ->
    # cli_test:36 goes red. Before these cases existed the whole corpus stayed green under every one
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
      command: ["mix", "test", "test/conformance/cli_test.exs:38"]
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
      command: ["mix", "test", "test/conformance/cli_test.exs:38"]
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
      command: ["mix", "test", "test/conformance/cli_test.exs:38"]
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
      command: ["mix", "test", "test/conformance/cli_test.exs:38"]
    },
    %{
      # Node-side selector PATH validation. The official rejects an empty selector path at grant
      # decode; without validSelectorPath the independent runner treats [] as "the root", matches
      # check-envelope-invalid-selector-empty-path (whose value IS the whole cast_arguments), and
      # accepts what the official refuses -> the runner reports a disagreement and exits 1. This is
      # what makes the matcher's shape hardening falsifiable rather than defensive code no gate can
      # prove: with the mutation applied the runner reports
      # `agreed=219 disagreed=1 ... disagreements: check-envelope-invalid-selector-empty-path`.
      # TARGET: this mutates the NODE runner, so it targets the Node runner test. cli_test:36 is
      # structurally blind here — that test runs the official Elixir CLI against the corpus's
      # expected verdicts and never executes corpus_independent.mjs (proven: this entry SURVIVED
      # while pointed at cli_test:36, and is caught pointed here).
      name: "check-envelope-node-selector-path-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  if (!Array.isArray(path) || path.length < 1 || path.length > MAXIMA.path_segments) return false;\n",
      to: "  if (!Array.isArray(path)) return false;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    # --- independent-runner permissiveness (BAP-05 selector closeout, round 4) -
    # Each entry deletes one guard that keeps the Node runner from being MORE PERMISSIVE than the
    # official. Removing any of them makes the runner accept a grant the official refuses, so the
    # corpus disagrees and the runner test goes red. These target the Node runner test, never
    # cli_test:36, which runs the official CLI and cannot observe a .mjs change.
    %{
      # `cnf` is a closed map in the official; without this the runner accepts an extra member.
      name: "node-check-envelope-cnf-closed-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  exactKeys(grantPayload.cnf, [\"jkt\"], \"check_envelope grant cnf\");\n",
      to: "\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Operation names are printable ASCII in the official (valid_operation?).
      name: "node-operation-name-charset-removal",
      path: "conformance/corpus_independent.mjs",
      from: "    /^[\\x20-\\x7E]*$/.test(name)\n",
      to: "    true\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # The official enforces global operation-name uniqueness (unique?).
      name: "node-duplicate-operation-name-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "  assert(new Set(names).size === names.length, `${context}: duplicate operation name`);\n",
      to: "  void names;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # The official validates EVERY operation's selectors, not just the requested one.
      name: "node-nonmatching-operation-selector-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from: "    for (const selector of op.selectors) validSelectorShape(selector, context);\n",
      to: "\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Protocol strings must be valid UTF-8 (String.valid?); a byte-length check accepts a lone
      # surrogate the official rejects.
      name: "node-selector-path-utf8-validity-removal",
      path: "conformance/corpus_independent.mjs",
      from: "      wellFormedString(segment) &&\n",
      to: "      typeof segment === \"string\" &&\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # On a plain {} the tagged projection loses a `__proto__` member to the prototype setter, so
      # two distinct values canonicalize identically and the selector wrongly matches.
      name: "node-tagged-projection-prototype-safety-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  const obj = Object.create(null);\n",
      to: "  const obj = {};\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Selector values must satisfy the protocol JSON bounds (official: Jcs.encode(value, bounds)).
      # Without this the runner accepts a grant whose selector value exceeds object_members.
      name: "node-selector-value-json-bounds-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function withinJsonBounds(value, level = 0) {\n",
      to: "function withinJsonBounds(value, level = 0) {\n  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Selector-value magnitude. The official caps |value| at 9007199254740991; without this the
      # runner accepts a grant carrying 2^53, which the official rejects at decode.
      name: "node-selector-value-magnitude-removal",
      path: "conformance/corpus_independent.mjs",
      from:
        "      Number.isFinite(value) &&\n      Math.abs(value) <= MAXIMA.integer_magnitude\n    );",
      to: "      Number.isFinite(value)\n    );",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # valid_method?: token charset; catches a method with a space.
      name: "node-decode-valid-method-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function validMethod(value) {\n",
      to: "function validMethod(value) {\n  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # valid_uuid?: exact UUID shape; catches a non-UUID ba_inv.
      name: "node-decode-valid-uuid-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function validUuid(value) {\n",
      to: "function validUuid(value) {\n  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # coherent_times?: iat<exp and nbf<exp; catches iat >= exp.
      name: "node-decode-coherent-times-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function coherentTimes(iat, nbf, exp) {\n",
      to: "function coherentTimes(iat, nbf, exp) {\n  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # decode_audiences: count bound + per-element validity + uniqueness; catches over-max and duplicate aud.
      name: "node-decode-audiences-removal",
      path: "conformance/corpus_independent.mjs",
      from: "function decodeAudiences(aud) {\n",
      to: "function decodeAudiences(aud) {\n  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # decode_proof requires htu already normalized (Uri.normalize(htu) === htu); check_envelope
      # reaches this via equality to the expected target_uri, but decode has no expected.
      name: "node-decode-proof-htu-normalization-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  assert(normalized === payload.htu, \"decode_proof: htu normalized\");\n",
      to: "  void normalized;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # StringOrURI structure: the official gates iss/jti/aud on URI.new (numeric port, terminated
      # IPv6, single @) beyond the byte check. Without validUriAuthority the runner accepts
      # http://a:b (non-numeric port) which the official rejects.
      name: "node-decode-string-or-uri-authority-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  return validUriAuthority(rest.slice(2).split(/[/?#]/, 1)[0]);\n",
      to: "  return true;\n",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # Optional proof nonce: present must be a well-formed string of 1..nonce_bytes
      # (official optional_nonce -> valid_nonce?). Without this the runner accepts an empty nonce.
      name: "node-decode-proof-nonce-validation-removal",
      path: "conformance/corpus_independent.mjs",
      from: "  if (payload.nonce !== undefined) {\n",
      to: "  if (false) {\n",
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # isInteger magnitude: dropping the |value| <= integer_magnitude bound lets a proof with
      # iat = 2^53 decode valid -> decode-proof-maximum-plus-one-iat-magnitude disagrees (official
      # rejects at Json.decode magnitude). Proves the magnitude bound on integer claims is real.
      name: "runner-isinteger-magnitude",
      path: "conformance/corpus_independent.mjs",
      from: "Number.isInteger(value) &&\n    Math.abs(value) <= MAXIMA.integer_magnitude",
      to: "Number.isInteger(value)",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # requestDigest jcs_bytes: removing the canonical byte bound lets a typed projection exceeding
      # jcs_bytes (65536) produce a digest -> request-digest-maximum-plus-one-jcs-bytes disagrees.
      name: "runner-requestdigest-jcs-bytes",
      path: "conformance/corpus_independent.mjs",
      from:
        "if (Buffer.byteLength(jcs, \"utf8\") > MAXIMA.jcs_bytes) fail(\"request_digest: jcs_bytes\");",
      to: "// jcs_bytes check removed (mutation)",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
    },
    %{
      # requestDigest operation validation: neutering valid_operation? lets a 129-byte operation
      # produce a digest -> request-digest-maximum-plus-one-operation disagrees (official rejects an
      # over-length / non-printable operation before hashing).
      name: "runner-requestdigest-operation",
      path: "conformance/corpus_independent.mjs",
      from: "assert(validOperationName(operation), \"request_digest: operation\");",
      to: "assert(true, \"request_digest: operation\");",
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
      command: ["mix", "test", "test/conformance/corpus_independent_test.exs:17"]
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
    IO.puts("conformance mutation gate: ok mutations=#{length(@mutations)}")
  end

  defp run_mutation(mutation) do
    baseline_green!(mutation)

    scratch =
      Path.join(
        System.tmp_dir!(),
        "conformance-mutation-#{mutation.name}-#{System.unique_integer([:positive, :monotonic])}"
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

  # Baseline non-vacuity: before any mutation, the entry's UNMUTATED command must run green in a
  # clean scratch. Without this, a deleted or drifted target test makes `mix test` exit non-zero
  # ("did not match any file"/"no tests executed") and the battery scores the red as "caught" —
  # the deleted-test false-green the 2026-08-20 gate-integrity review named. Cached per unique
  # command so shared targets pay the baseline once per battery run.
  defp baseline_green!(mutation) do
    key = {:baseline_green, mutation.command}

    if Process.get(key) != :ok do
      scratch =
        Path.join(
          System.tmp_dir!(),
          "conformance-baseline-#{System.unique_integer([:positive, :monotonic])}"
        )

      File.mkdir_p!(scratch)

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
