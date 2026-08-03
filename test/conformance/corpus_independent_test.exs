defmodule BoundedAuthorityProtocol.Conformance.CorpusIndependentTest do
  @moduledoc """
  Drives the independent Node second-implementation runner (`corpus_independent.mjs`) against the
  shipped corpus and tampered copies. The runner recomputes every corpus verdict from scratch
  (node:* only) and checks agreement with the case-declared expectations; this is what makes the
  corpus *normative* (a value that only round-trips the official Elixir implementation is not
  normative until an independent runner agrees — design note `conformance-contract.md:38-48`).
  """

  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)
  @script Path.join(@root, "conformance/corpus_independent.mjs")
  @corpus Path.join(@root, "priv/conformance/v1/corpus")
  @manifest Path.join(@root, "priv/conformance/v1/vectors/manifest.json")

  test "independent runner agrees on every shipped corpus case (repo mode)" do
    {output, 0} = run_node([@corpus, "--manifest", @manifest])

    assert output =~ "corpus_independent: agreed=218 disagreed=0 total=218"
    assert output =~ "census_keys=8 declared=8 partition=wired"
  end

  test "independent runner agrees in published mode (no --manifest; index self-census)" do
    {output, 0} = run_node([@corpus])

    assert output =~ "corpus_independent: agreed=218 disagreed=0 total=218"
    assert output =~ "census_keys=8 declared=8"
  end

  test "published-set sufficiency: a tree containing ONLY the published corpus agrees" do
    # Copy the corpus alone into an isolated tree and run the runner from there — proving the
    # published corpus set is self-sufficient (no vectors dir, no schemas, no conformance/ source
    # needed at verify time). The corpus index references only its own cases + .raw sidecars.
    dir =
      Path.join(
        System.tmp_dir!(),
        "bap-corpus-ind-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.cp_r!(@corpus, dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    {output, 0} = run_node([dir])

    assert output =~ "corpus_independent: agreed=218 disagreed=0 total=218"
  end

  test "exit 1 on a byte-flipped case file (integrity failure)" do
    dir = corpus_copy([&flip_one_case_byte/1])
    on_exit(fn -> File.rm_rf!(dir) end)

    {output, 1} = run_node([dir])
    # A byte flip trips either the SHA-256 check or a verdict disagreement.
    assert output =~ "corpus_independent: error:"
  end

  test "exit 1 on a dropped case file (set mismatch)" do
    dir = corpus_copy([&drop_one_case_file/1])
    on_exit(fn -> File.rm_rf!(dir) end)

    {output, 1} = run_node([dir])
    assert output =~ "corpus_independent: error:"
  end

  test "exit 1 on a tampered index count (count mismatch)" do
    dir = corpus_copy([&decrement_index_count/1])
    on_exit(fn -> File.rm_rf!(dir) end)

    {output, 1} = run_node([dir])
    assert output =~ "corpus_independent: error:"
  end

  test "exit 1 when a tamper case's verbatim disagrees with the re-derived bytes (tamper audit)" do
    # Corrupt an existing tamper case's verbatim so it no longer equals base-with-one-flip, and
    # re-sync the index hash so the per-file SHA-256 check passes and the tamper audit is what
    # reds. This is the independent (Node) second implementation of the Q25 verbatim-vs-derived
    # check DISAGREEING on a known-bad input.
    dir = corpus_copy([&corrupt_tamper_verbatim/1])
    on_exit(fn -> File.rm_rf!(dir) end)

    {output, 1} = run_node([dir])
    assert output =~ "tamper verbatim != derived"
  end

  test "independent runner imports no project code (node:* only)" do
    source = File.read!(@script)

    refute source =~ "BoundedAuthorityProtocol"
    refute source =~ ~r/from\s+["'][^"']*lib\//
    refute source =~ ~r/import\s+["'][^"']*mix/
    assert source =~ ~s(from "node:crypto")
  end

  test "invalid arguments exit nonzero with a usage line" do
    {output, code} = run_node([])

    assert code != 0
    assert output =~ "usage" or output =~ "corpus_independent: error"
  end

  # --- helpers --------------------------------------------------------------

  defp run_node(arguments) do
    System.cmd("node", [@script | arguments], stderr_to_stdout: true)
  end

  defp corpus_copy(tampers) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "bap-corpus-ind-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.cp_r!(@corpus, dir)

    for tamper <- tampers, do: tamper.(dir)

    dir
  end

  defp flip_one_case_byte(dir) do
    case_file =
      Path.wildcard(Path.join(dir, "cases/**/*.json"))
      |> List.first()

    bytes = File.read!(case_file)
    pos = div(byte_size(bytes), 2)
    <<pre::binary-size(^pos), byte, rest::binary>> = bytes
    File.write!(case_file, <<pre::binary, Bitwise.bxor(byte, 0x01), rest::binary>>)
  end

  defp drop_one_case_file(dir) do
    case_file =
      Path.wildcard(Path.join(dir, "cases/**/*.json"))
      |> List.first()

    File.rm!(case_file)
  end

  # Flip a SECOND byte of the uri.normalize tamper case's verbatim ("ittps..." -> "iutps...") so
  # it no longer equals the base with the single documented flip, then update the file's index
  # hash so the tamper audit — not the SHA-256 gate — is the check that reds.
  defp corrupt_tamper_verbatim(dir) do
    case_path = Path.join(dir, "cases/uri/normalize.json")
    index_path = Path.join(dir, "index.json")

    original = File.read!(case_path)

    corrupted =
      String.replace(original, "ittps://example.com/a", "iutps://example.com/a", global: false)

    File.write!(case_path, corrupted)

    index = File.read!(index_path)
    File.write!(index_path, String.replace(index, sha256_b64(original), sha256_b64(corrupted)))
  end

  defp sha256_b64(bytes), do: Base.url_encode64(:crypto.hash(:sha256, bytes), padding: false)

  defp decrement_index_count(dir) do
    index_path = Path.join(dir, "index.json")
    bytes = File.read!(index_path)

    tampered =
      String.replace(
        bytes,
        ~r/"total_cases":\s*(\d+)/,
        fn full ->
          [_, n] = Regex.run(~r/"total_cases":\s*(\d+)/, full)
          ~s("total_cases": #{String.to_integer(n) - 1})
        end,
        global: false
      )

    File.write!(index_path, tampered)
  end
end
