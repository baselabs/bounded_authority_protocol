defmodule BoundedAuthorityProtocol.ChainArchiveMutationGate do
  @root Path.expand("..", __DIR__)

  @mutations [
    %{
      name: "canonical-row-equality",
      path: "lib/bounded_authority_protocol/v1/consumption_chain.ex",
      from: "{:ok, %EncodedConsumptionEntry{bytes: ^bytes} = encoded} <- encode(entry, bounds)",
      to: "{:ok, %EncodedConsumptionEntry{} = encoded} <- encode(entry, bounds)",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/consumption_chain_test.exs"]
    },
    %{
      name: "row-domain-prefix",
      path: "lib/bounded_authority_protocol/v1/consumption_chain.ex",
      from: ~s(@domain "BAP1-CHAIN\\0"),
      to: ~s(@domain "BAP1-CHAIN!"),
      command: ["mix", "test", "test/bounded_authority_protocol/v1/consumption_chain_test.exs"]
    },
    %{
      name: "sequence-progression",
      path: "lib/bounded_authority_protocol/v1/consumption_chain.ex",
      from: "true <- entry.sequence == sequence,",
      to: "true <- is_integer(entry.sequence),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/consumption_chain_test.exs"]
    },
    %{
      name: "predecessor-link",
      path: "lib/bounded_authority_protocol/v1/consumption_chain.ex",
      from: "true <- FixedBytes.equal?(entry.previous_hash, prior_hash) do",
      to: "true <- byte_size(entry.previous_hash) == byte_size(prior_hash) do",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/consumption_chain_test.exs"]
    },
    %{
      name: "caller-head",
      path: "lib/bounded_authority_protocol/v1/consumption_chain.ex",
      from: "true <- FixedBytes.equal?(final_hash, expected.last_hash) do",
      to: "true <- byte_size(final_hash) == byte_size(expected.last_hash) do",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/consumption_chain_test.exs"]
    },
    %{
      name: "archive-digest",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "true <- FixedBytes.equal?(digest, expected.digest),",
      to: "true <- byte_size(digest) == byte_size(expected.digest),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "object-version",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "observed == expected do",
      to: "is_binary(observed) do",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "archive-exact-eof",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "true <- eof?(state) do",
      to: "true <- is_tuple(state) do",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "start-caller-boundary",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "true <- start_anchor.sequence == chain.first_sequence - 1,",
      to: "true <- is_integer(start_anchor.sequence),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "end-caller-boundary",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "true <- end_anchor.sequence == chain.last_sequence,",
      to: "true <- is_integer(end_anchor.sequence),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "raw-archive-input",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "def verify(_archived, _key_chain, _expected), do: {:error, :invalid}",
      to:
        "def verify(%EncodedAnchoredExport{} = archived, key_chain, expected),\n    do:\n      verify(\n        %ArchivedObject{chunks: archived.chunks, version: expected.object_version},\n        key_chain,\n        expected\n      )\n\n  def verify(_archived, _key_chain, _expected), do: {:error, :invalid}",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "archive-transition-chain-identity",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from:
        "defp transitions_match_chain?(\n         [%ExpectedKeyTransition{chain_id: chain_id} | rest],\n         chain_id\n       ),",
      to:
        "defp transitions_match_chain?(\n         [%ExpectedKeyTransition{chain_id: chain_id} | rest],\n         _expected_chain_id\n       ),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "inclusive-end-transition-time",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "defp chronological_end?(value, previous), do: value >= previous",
      to: "defp chronological_end?(value, previous), do: value > previous",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "cross-anchor-chronology",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "defp chronological_end?(value, previous), do: value >= previous",
      to: "defp chronological_end?(_value, _previous), do: true",
      command: [
        "mix",
        "test",
        "test/conformance/consumption_chain_archive_vector_test.exs"
      ]
    },
    %{
      name: "transition-order",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from: "defp strictly_after?(value, previous), do: value > previous",
      to: "defp strictly_after?(_value, _previous), do: true",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "transition-continuity",
      path: "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
      from:
        "defp current_key_matches?(left_id, left_fingerprint, right_id, right_fingerprint),\n    do: left_id == right_id and FixedBytes.equal?(left_fingerprint, right_fingerprint)",
      to:
        "defp current_key_matches?(_left_id, _left_fingerprint, _right_id, _right_fingerprint),\n    do: true",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/anchored_export_test.exs"]
    },
    %{
      name: "transition-signature",
      path: "lib/bounded_authority_protocol/v1/key_transition_codec.ex",
      from:
        ":crypto.verify(\n             :eddsa,\n             :none,\n             parsed.message,\n             parsed.signature,\n             [current_key.public_key, :ed25519]\n           )",
      to: "is_binary(parsed.signature)",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/key_transition_test.exs"]
    },
    %{
      name: "transition-current-window",
      path: "lib/bounded_authority_protocol/v1/key_transition_codec.ex",
      from: "true <- inside_window?(parsed.effective_at, current_key),",
      to: "true <- is_integer(parsed.effective_at),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/key_transition_test.exs"]
    },
    %{
      name: "transition-next-window",
      path: "lib/bounded_authority_protocol/v1/key_transition_codec.ex",
      from: "true <- inside_window?(parsed.effective_at, next_key),",
      to: "true <- is_integer(parsed.effective_at),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/key_transition_test.exs"]
    },
    %{
      name: "anchor-genesis-zero-hash",
      path: "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
      from: "(anchor.sequence != 0 or FixedBytes.equal?(anchor.chain_hash, @zero_hash))",
      to: "is_binary(anchor.chain_hash)",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/boundary_anchor_test.exs"]
    },
    %{
      name: "anchor-nonnegative-sequence",
      path: "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
      from: "is_integer(value) and value >= 0 and value <= bounds.integer_magnitude",
      to: "is_integer(value) and value <= bounds.integer_magnitude",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/boundary_anchor_test.exs"]
    },
    %{
      name: "expected-anchor-genesis-zero-hash",
      path: "lib/bounded_authority_protocol/v1/context_validation.ex",
      from: "(expected.sequence != 0 or FixedBytes.equal?(expected.chain_hash, @zero_hash))",
      to: "is_binary(expected.chain_hash)",
      command: [
        "mix",
        "test",
        "test/bounded_authority_protocol/v1/context_validation_test.exs"
      ]
    },
    %{
      name: "expected-anchor-nonnegative-sequence",
      path: "lib/bounded_authority_protocol/v1/context_validation.ex",
      from: "is_integer(value) and value >= 0 and value <= bounds.integer_magnitude",
      to: "is_integer(value) and value <= bounds.integer_magnitude",
      command: [
        "mix",
        "test",
        "test/bounded_authority_protocol/v1/context_validation_test.exs"
      ]
    },
    %{
      name: "distinct-transition-fingerprints",
      path: "lib/bounded_authority_protocol/v1/context_validation.ex",
      from: "if FixedBytes.equal?(current, next), do: {:error, :invalid}, else: :ok",
      to: "if false, do: {:error, :invalid}, else: :ok",
      command: [
        "mix",
        "test",
        "test/bounded_authority_protocol/v1/context_validation_test.exs"
      ]
    },
    %{
      name: "historical-lower-edge",
      path: "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
      from: "key.valid_from <= time and",
      to: "key.valid_from < time and",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/boundary_anchor_test.exs"]
    },
    %{
      name: "historical-upper-edge",
      path: "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
      from: "time < key.valid_before)",
      to: "time <= key.valid_before)",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/boundary_anchor_test.exs"]
    },
    %{
      name: "derived-anchor-fingerprint",
      path: "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
      from: "true <- FixedBytes.equal?(parsed.key_fingerprint, expected.key_fingerprint),",
      to: "true <- byte_size(parsed.key_fingerprint) == byte_size(expected.key_fingerprint),",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/boundary_anchor_test.exs"]
    },
    %{
      name: "constant-time-compare",
      path: "lib/bounded_authority_protocol/v1/fixed_bytes.ex",
      from: ":crypto.hash_equals(left, right)",
      to: "left == right",
      command: ["mix", "test", "test/architecture/purity_test.exs"]
    },
    %{
      name: "immutable-cryptographic-widths",
      path: "lib/bounded_authority_protocol/v1/bounds.ex",
      from: "@fixed_width_keys [:digest_bytes, :public_key_bytes, :signature_bytes]",
      to: "@fixed_width_keys []",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/bounds_test.exs"]
    },
    %{
      name: "strict-string-or-uri-percent-escapes",
      path: "lib/bounded_authority_protocol/v1/string_or_uri.ex",
      from: "hexadecimal?(first) and hexadecimal?(second) and uri_bytes?(rest)",
      to: "uri_bytes?(rest)",
      command: ["mix", "test", "test/bounded_authority_protocol/v1/string_or_uri_test.exs"]
    },
    %{
      name: "manifest-removal-direction",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|canonical(declared) === canonical(verifierUnion),|,
      to: ~S|declared.every((value) => verifierUnion.includes(value)),|,
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "manifest-addition-direction",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|canonical(declared) === canonical(verifierUnion),|,
      to: ~S|verifierUnion.every((value) => declared.includes(value)),|,
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "crypto-import-census",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|importedPublicKeyFingerprints.add(fingerprint(raw).toString("base64url"));|,
      to: ~S|fingerprint(raw);|,
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "grant_proof-own-json-members",
      path: "conformance/grant_proof_independent.mjs",
      from: "const value = Object.create(null);",
      to: "const value = {};",
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-pem",
      path: "conformance/grant_proof_independent.mjs",
      from: ~S"!/-----BEGIN (?:ENCRYPTED |ED25519 )?PRIVATE KEY-----/.test(value)",
      to: ~S"!/-----BEGIN (?:ENCRYPTED |ED25519 )?PRIVATE MATERIAL-----/.test(value)",
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-der-byte-array",
      path: "conformance/grant_proof_independent.mjs",
      from: "value.length >= 48 &&",
      to: "value.length >= 49 &&",
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-der-hex",
      path: "conformance/grant_proof_independent.mjs",
      from: ~S|/^[0-9A-Fa-f]{96,}$/.test(value)|,
      to: ~S|/^[0-9A-Fa-f]{97,}$/.test(value)|,
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-der-base64",
      path: "conformance/grant_proof_independent.mjs",
      from: "value.length >= 64 && value.length % 4 === 0",
      to: "value.length >= 65 && value.length % 4 === 0",
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-der-base64url",
      path: "conformance/grant_proof_independent.mjs",
      from: ~S|/^[A-Za-z0-9_-]{64,}$/.test(value)|,
      to: ~S|/^[A-Za-z0-9_-]{65,}$/.test(value)|,
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "grant_proof-private-der-key-type",
      path: "conformance/grant_proof_independent.mjs",
      from: ~S|return key.asymmetricKeyType === "ed25519";|,
      to: "return false;",
      command: ["mix", "test", "test/conformance/grant_holder_proof_vector_test.exs"]
    },
    %{
      name: "chain_archive-own-json-members",
      path: "conformance/chain_archive_independent.mjs",
      from: "const value = Object.create(null);",
      to: "const value = {};",
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-pem",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S"!/-----BEGIN (?:ENCRYPTED |ED25519 )?PRIVATE KEY-----/.test(value)",
      to: ~S"!/-----BEGIN (?:ENCRYPTED |ED25519 )?PRIVATE MATERIAL-----/.test(value)",
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-der-byte-array",
      path: "conformance/chain_archive_independent.mjs",
      from: "value.length >= 48 &&",
      to: "value.length >= 49 &&",
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-der-hex",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|/^[0-9A-Fa-f]{96,}$/.test(value)|,
      to: ~S|/^[0-9A-Fa-f]{97,}$/.test(value)|,
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-der-base64",
      path: "conformance/chain_archive_independent.mjs",
      from: "value.length >= 64 && value.length % 4 === 0",
      to: "value.length >= 65 && value.length % 4 === 0",
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-der-base64url",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|/^[A-Za-z0-9_-]{64,}$/.test(value)|,
      to: ~S|/^[A-Za-z0-9_-]{65,}$/.test(value)|,
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    },
    %{
      name: "chain_archive-private-der-key-type",
      path: "conformance/chain_archive_independent.mjs",
      from: ~S|return key.asymmetricKeyType === "ed25519";|,
      to: "return false;",
      command: ["mix", "test", "test/conformance/consumption_chain_archive_vector_test.exs"]
    }
  ]

  @copy_paths [
    ".formatter.exs",
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
    IO.puts("chain_archive mutation gate: ok mutations=#{length(@mutations)}")
  end

  defp run_mutation(mutation) do
    baseline_green!(mutation)

    scratch =
      Path.join(
        System.tmp_dir!(),
        "chain_archive-mutation-#{mutation.name}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(scratch)

    try do
      Enum.each(@copy_paths, &copy_path(&1, scratch))
      File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
      copy_build(scratch)
      mutate_once!(Path.join(scratch, mutation.path), mutation.from, mutation.to)

      {output, status} =
        System.cmd(hd(mutation.command), tl(mutation.command) ++ ["--max-cases", "1"],
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
  # clean scratch. Without this, a deleted or drifted target test makes `mix test` exit non-zero
  # and the battery scores the red as "caught" — the deleted-test false-green the 2026-08-20
  # gate-integrity review named. Cached per unique command so shared targets pay once per run.
  defp baseline_green!(mutation) do
    key = {:baseline_green, mutation.command}

    if Process.get(key) != :ok do
      scratch =
        Path.join(
          System.tmp_dir!(),
          "chain_archive-baseline-#{System.unique_integer([:positive, :monotonic])}"
        )

      File.mkdir_p!(scratch)

      try do
        Enum.each(@copy_paths, &copy_path(&1, scratch))
        File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
        copy_build(scratch)

        {output, status} =
          System.cmd(hd(mutation.command), tl(mutation.command) ++ ["--max-cases", "1"],
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

BoundedAuthorityProtocol.ChainArchiveMutationGate.run()
