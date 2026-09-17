Code.require_file("../../test_support/portable.ex", __DIR__)

defmodule BoundedAuthorityProtocol.Conformance.CliTest do
  @moduledoc """
  In-VM `Cli.run/1` unit tests (the 100%-coverage path — `System.cmd` runs earn no coverage)
  plus escript integration tests (the built binary driven end-to-end). The CLI does I/O and
  argv parsing only; every judgment delegates to the pure `Corpus`/`Runner`/`Report` core.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.Conformance.Cli
  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.TestSupport.Portable

  @moduletag timeout: 600_000

  @escript_path Path.expand("../../bounded_authority_conformance", __DIR__)
  @shipped_corpus Path.expand("../../priv/conformance/v1/corpus", __DIR__)
  @shipped_v2_corpus Path.expand("../../priv/conformance/v2/corpus", __DIR__)

  # --- in-VM Cli.run/1 unit tests (the coverage path) -----------------------

  test "exit 2 on missing --corpus" do
    assert Cli.run([]) == 2
    assert Cli.run(["--report", "x"]) == 2
  end

  test "exit 2 on an unknown flag" do
    assert Cli.run(["--bogus", "v", "--corpus", @shipped_corpus]) == 2
  end

  test "exit 2 on a --corpus without a value" do
    assert Cli.run(["--corpus"]) == 2
  end

  test "exit 2 on a --report without a value" do
    assert Cli.run(["--corpus", @shipped_corpus, "--report"]) == 2
  end

  test "exit 0 on the shipped corpus (in-VM)" do
    assert Cli.run(["--corpus", @shipped_corpus]) == 0
  end

  test "exit 0 on the shipped v2 corpus (in-VM)" do
    assert Cli.run(["--corpus", @shipped_v2_corpus]) == 0
  end

  # --- ADR 0014 D4: the certified-corpus pin (index-SHA) ---------------------
  # The pin fails closed on any corpus that is NOT the certified snapshot, and the certified value
  # is NOT caller-overridable (no seam). Proven WITHOUT a seam: a corpus whose index.json carries
  # insignificant trailing whitespace still decodes, verifies, and agrees (integrity is over the
  # parsed index, not its raw bytes) — but its raw-byte index SHA differs, so it is exactly the
  # "not the certified corpus" case a shrunken/regenerated-index corpus embodies. Corpus.load
  # accepts it AND the identity differs AND run/1 exits 1 ⟹ the pin (not integrity) caught it.

  @certified_index_sha256 %{
    1 => "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs",
    2 => "beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A"
  }

  defp whitespace_perturbed_corpus do
    dst = unique_tmp("cli-noncertified") |> Path.dirname()
    File.cp_r!(@shipped_corpus, dst)
    index = Path.join(dst, "index.json")
    File.write!(index, File.read!(index) <> "\n")
    dst
  end

  test "a non-certified corpus (different index SHA) still loads + agrees but the pin fails it closed" do
    dir = whitespace_perturbed_corpus()
    on_exit(fn -> File.rm_rf!(dir) end)

    # 1. Integrity + agreement still pass: Corpus.load accepts the perturbed index...
    map =
      dir
      |> Path.join("**/*")
      |> Portable.wildcard()
      |> Enum.reject(&File.dir?/1)
      |> Map.new(fn p -> {Path.relative_to(p, dir), File.read!(p)} end)

    assert {:ok, corpus} = Corpus.load(map)

    # 2. ...but its raw-byte index identity differs from the certified snapshot...
    refute Report.index_identity(corpus.index_bytes) == @certified_index_sha256[corpus.major]

    # 3. ...so run/1 fails it closed. Integrity green + identity differs + exit 1 ⟹ the pin caught
    # it (not integrity). Neutering assert_certified_corpus makes this return 0 (mutation-proven).
    assert Cli.run(["--corpus", dir]) == 1
  end

  test "exit 0 with --report writes a deterministic report that binds the index digest" do
    tmp = unique_tmp("cli-report")
    on_exit(fn -> File.rm_rf!(Path.dirname(tmp)) end)

    assert Cli.run(["--corpus", @shipped_corpus, "--report", tmp]) == 0
    assert File.exists?(tmp)
    first = File.read!(tmp)

    # Run again to a second path and confirm byte-identical output.
    tmp2 = unique_tmp("cli-report-2")
    on_exit(fn -> File.rm_rf!(Path.dirname(tmp2)) end)
    assert Cli.run(["--corpus", @shipped_corpus, "--report", tmp2]) == 0
    assert File.read!(tmp2) == first

    # The report carries the index SHA-256 identity.
    assert first =~ ~s("index_sha256_base64url")
  end

  test "exit 1 on a byte-flipped case file (tampered tmp copy)" do
    corpus = tampered_corpus_copy(&flip_one_case_byte/1)
    on_exit(fn -> File.rm_rf!(corpus) end)
    assert Cli.run(["--corpus", corpus]) == 1
  end

  test "exit 1 on a dropped case file (set mismatch)" do
    corpus = tampered_corpus_copy(&drop_one_case_file/1)
    on_exit(fn -> File.rm_rf!(corpus) end)
    assert Cli.run(["--corpus", corpus]) == 1
  end

  test "exit 1 on a dropped case from a file (count mismatch)" do
    corpus = tampered_corpus_copy(&drop_one_case_from_file/1)
    on_exit(fn -> File.rm_rf!(corpus) end)
    assert Cli.run(["--corpus", corpus]) == 1
  end

  test "the v2 pin fails closed on a v2 corpus with a perturbed index (major-keyed certification)" do
    dst = unique_tmp("cli-v2-noncertified") |> Path.dirname()
    File.cp_r!(@shipped_v2_corpus, dst)
    index = Path.join(dst, "index.json")
    File.write!(index, File.read!(index) <> "\n")
    on_exit(fn -> File.rm_rf!(dst) end)

    map =
      dst
      |> Path.join("**/*")
      |> Portable.wildcard()
      |> Enum.reject(&File.dir?/1)
      |> Map.new(fn p -> {Path.relative_to(p, dst), File.read!(p)} end)

    assert {:ok, corpus} = Corpus.load(map)
    assert corpus.major == 2
    refute Report.index_identity(corpus.index_bytes) == @certified_index_sha256[2]
    assert Cli.run(["--corpus", dst]) == 1
  end

  test "a v1 corpus whose index declares a v2 format is rejected (no cross-major corpus)" do
    dst = unique_tmp("cli-cross-major") |> Path.dirname()
    File.cp_r!(@shipped_corpus, dst)
    index = Path.join(dst, "index.json")

    File.write!(
      index,
      String.replace(
        File.read!(index),
        "-v1-conformance-corpus-index",
        "-v2-conformance-corpus-index"
      )
    )

    on_exit(fn -> File.rm_rf!(dst) end)

    assert Cli.run(["--corpus", dst]) == 1
  end

  test "exit 1 on a nonexistent corpus directory" do
    assert Cli.run([
             "--corpus",
             Path.join(
               System.tmp_dir!(),
               "bap-cli-does-not-exist-#{System.unique_integer([:positive])}"
             )
           ]) == 1
  end

  test "exit 1 when the --report write fails (unwritable path is not swallowed)" do
    # The corpus agrees (would be exit 0), but the report cannot be written: File.write returns
    # {:error, :enoent} for a path under a nonexistent parent dir. A swallowed write would exit 0
    # with no report on disk; the fail-closed contract makes it exit 1.
    unwritable =
      Path.join(
        Path.join(
          System.tmp_dir!(),
          "bap-cli-missing-parent-#{System.unique_integer([:positive])}"
        ),
        "report.json"
      )

    assert Cli.run(["--corpus", @shipped_corpus, "--report", unwritable]) == 1
    refute File.exists?(unwritable)
  end

  # chmod-based unreadability has no Windows equivalent (File.chmod there only toggles the
  # read-only bit and does not fail File.read); the error arm stays covered on every POSIX lane.
  unless Portable.windows?() do
    test "exit 1 when a corpus file is unreadable (File.read error arm)" do
      # A corpus copy with one file chmod'd 0000 -> File.read fails -> exit 1 (closed). chmod is
      # the only reliable way to make File.read fail on an existing path inside a copy we own.
      corpus = tampered_corpus_copy(&make_one_file_unreadable/1)

      on_exit(fn ->
        restore_readability(corpus)
        File.rm_rf!(corpus)
      end)

      assert Cli.run(["--corpus", corpus]) == 1
    end
  end

  # --- escript integration tests (end-to-end exit contract) -----------------

  @tag :escript
  test "escript exit 0 on the shipped corpus and byte-identical report across runs" do
    build_escript!()

    {out0, 0} =
      Portable.cmd("escript", [@escript_path, "--corpus", @shipped_corpus],
        stderr_to_stdout: true
      )

    assert out0 =~ ~s("agreement":true)

    {out1, 0} =
      Portable.cmd("escript", [@escript_path, "--corpus", @shipped_corpus],
        stderr_to_stdout: true
      )

    assert out1 == out0
  end

  @tag :escript
  test "escript exit 2 on missing --corpus" do
    build_escript!()
    {out, 2} = Portable.cmd("escript", [@escript_path], stderr_to_stdout: true)
    assert out =~ "usage"
    refute out =~ ~s("agreement")
  end

  @tag :escript
  test "escript exit 1 on a tampered corpus" do
    build_escript!()
    corpus = tampered_corpus_copy(&flip_one_case_byte/1)
    clean_dir(corpus)

    {_out, 1} =
      Portable.cmd("escript", [@escript_path, "--corpus", corpus], stderr_to_stdout: true)
  end

  # Direct executability of the BUILT artifact (shebang + exec bit) is a POSIX property;
  # on Windows the escript runs via the escript command (Portable.cmd above).
  unless Portable.windows?() do
    @tag :escript
    test "the built escript is directly executable (POSIX exec of the shebang file)" do
      build_escript!()

      {out, 0} = System.cmd(@escript_path, ["--corpus", @shipped_corpus], stderr_to_stdout: true)
      assert out =~ ~s("agreement":true)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp unique_tmp(prefix) do
    dir = Path.join(System.tmp_dir!(), "bap-cli-#{prefix}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    Path.join(dir, "report.json")
  end

  defp clean_dir(path) do
    on_exit(fn ->
      try do
        File.rm_rf!(path)
      rescue
        # Tolerate a stray non-owner file left by the escript process; the OS temp sweep reclaims it.
        File.Error -> :ok
      end
    end)
  end

  defp build_escript! do
    # Built once per test process; Mix.Task.run is idempotent within a VM.
    Mix.Task.run("escript.build", [])
  end

  defp tampered_corpus_copy(tamper) do
    src = @shipped_corpus
    dir = Path.join(System.tmp_dir!(), "bap-cli-tamper-#{System.unique_integer([:positive])}")
    File.cp_r!(src, dir)
    tamper.(dir)
    dir
  end

  defp flip_one_case_byte(dir) do
    case_file =
      Portable.wildcard(Path.join(dir, "cases/**/*.json"))
      |> List.first()

    bytes = File.read!(case_file)
    # Flip a byte in the middle of the file (avoid the format/provenance prefix).
    pos = div(byte_size(bytes), 2)
    <<pre::binary-size(^pos), byte, rest::binary>> = bytes
    tampered = <<pre::binary, Bitwise.bxor(byte, 0x01), rest::binary>>
    File.write!(case_file, tampered)
  end

  unless Portable.windows?() do
    defp make_one_file_unreadable(dir) do
      case_file =
        Portable.wildcard(Path.join(dir, "cases/**/*.json"))
        |> List.first()

      File.chmod!(case_file, 0o000)
    end

    defp restore_readability(dir) do
      Portable.wildcard(Path.join(dir, "**/*.json"))
      |> Enum.each(fn f ->
        try do
          File.chmod!(f, 0o644)
        rescue
          File.Error -> :ok
        end
      end)
    end
  end

  defp drop_one_case_file(dir) do
    case_file =
      Portable.wildcard(Path.join(dir, "cases/**/*.json"))
      |> List.first()

    File.rm!(case_file)
  end

  defp drop_one_case_from_file(dir) do
    # Count-mismatch class: shrink the index total_cases by 1 without removing a file.
    index_path = Path.join(dir, "index.json")
    bytes = File.read!(index_path)

    tampered =
      String.replace(
        bytes,
        ~r/"total_cases":\s*(\d+)/,
        fn _full ->
          [_, n] = Regex.run(~r/"total_cases":\s*(\d+)/, bytes)
          ~s("total_cases": #{String.to_integer(n) - 1})
        end,
        global: false
      )

    File.write!(index_path, tampered)
  end
end
