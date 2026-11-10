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
  @shipped_v3_corpus Path.expand("../../priv/conformance/v3/corpus", __DIR__)
  @priv_conformance Path.expand("../../priv/conformance", __DIR__)
  @role_corpus Path.expand(
                 "../../priv/conformance/attestation-profiles/role-attestation/v1",
                 __DIR__
               )

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

  test "exit 0 on the shipped v3 corpus (in-VM)" do
    assert Cli.run(["--corpus", @shipped_v3_corpus]) == 0
  end

  # --- the certified-corpus pin (index-SHA) -----------------------------------
  # The pin fails closed on any corpus that is NOT the certified snapshot, and the certified value
  # is NOT caller-overridable (no seam). Proven WITHOUT a seam: a corpus whose index.json carries
  # insignificant trailing whitespace still decodes, verifies, and agrees (integrity is over the
  # parsed index, not its raw bytes) — but its raw-byte index SHA differs, so it is exactly the
  # "not the certified corpus" case a shrunken/regenerated-index corpus embodies. Corpus.load
  # accepts it AND the identity differs AND run/1 exits 1 ⟹ the pin (not integrity) caught it.

  @certified_index_sha256 %{
    1 => "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs",
    2 => "beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A",
    3 => "pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw"
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
      |> Portable.ls_r()
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
      |> Portable.ls_r()
      |> Map.new(fn p -> {Path.relative_to(p, dst), File.read!(p)} end)

    assert {:ok, corpus} = Corpus.load(map)
    assert corpus.major == 2
    refute Report.index_identity(corpus.index_bytes) == @certified_index_sha256[2]
    assert Cli.run(["--corpus", dst]) == 1
  end

  test "the v3 pin fails closed on a v3 corpus with a perturbed index (major-keyed certification)" do
    dst = unique_tmp("cli-v3-noncertified") |> Path.dirname()
    File.cp_r!(@shipped_v3_corpus, dst)
    index = Path.join(dst, "index.json")
    File.write!(index, File.read!(index) <> "\n")
    on_exit(fn -> File.rm_rf!(dst) end)

    map =
      dst
      |> Portable.ls_r()
      |> Map.new(fn p -> {Path.relative_to(p, dst), File.read!(p)} end)

    assert {:ok, corpus} = Corpus.load(map)
    assert corpus.major == 3
    refute Report.index_identity(corpus.index_bytes) == @certified_index_sha256[3]
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

  # --- help, version, stderr -------------------------------------------------

  test "--help and -h print the usage to stdout and exit 0" do
    for flag <- ["--help", "-h"] do
      out = ExUnit.CaptureIO.capture_io(fn -> assert Cli.run([flag]) == 0 end)
      assert out =~ "usage: bounded_authority_conformance --corpus DIR"
    end
  end

  test "--version prints the package version and exits 0" do
    out = ExUnit.CaptureIO.capture_io(fn -> assert Cli.run(["--version"]) == 0 end)
    assert out == Mix.Project.config()[:version] <> "\n"
  end

  test "a usage error prints the usage to stderr, not stdout, and exits 2" do
    err =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        assert ExUnit.CaptureIO.capture_io(fn -> assert Cli.run(["--bogus"]) == 2 end) == ""
      end)

    assert err =~ "usage:"
  end

  test "a failure writes one value-free line to stderr and no report" do
    corpus = tampered_corpus_copy(&flip_one_case_byte/1)
    on_exit(fn -> File.rm_rf!(corpus) end)

    {out, err} = run_captured(["--corpus", corpus])
    assert out == ""
    assert err == "bounded_authority_conformance: the corpus failed integrity verification\n"
    refute err =~ corpus
  end

  test "every packaged corpus verifies with a newline-terminated report of its full census" do
    for {dir, format, total} <- [
          {"v1/corpus", "v1", nil},
          {"v2/corpus", "v2", nil},
          {"v3/corpus", "v3", nil},
          {"strict-ed25519", "strict-ed25519", nil},
          {"producer-canonicality", "producer-canonicality", nil},
          {"selector-float-zero", "selector-float-zero", 161},
          {"application-profiles/local-loopback-http/v1", "local-loopback-http", 46},
          {"attestation-profiles/role-attestation/v1", "role-attestation", 40},
          {"attestation-profiles/content-assertion/v1", "content-assertion", 154}
        ] do
      path = Path.join(@priv_conformance, dir)
      {out, err} = run_captured(["--corpus", path])
      assert err == "", dir
      assert String.ends_with?(out, "}\n"), dir
      report = :json.decode(out)

      assert Map.keys(report) |> Enum.sort() ==
               ~w(agreed agreement disagreed exit_status format index_sha256_base64url total)

      assert report["format"] == "bounded-authority-protocol-#{format}-conformance-report"
      assert report["agreement"] == true and report["exit_status"] == 0
      assert report["disagreed"] == 0 and report["agreed"] == report["total"]

      expected_total =
        total || :json.decode(File.read!(Path.join(path, "index.json")))["total_cases"]

      assert report["total"] == expected_total, dir
    end
  end

  # --- what the CLI reads -----------------------------------------------------

  test "a symbolic link anywhere inside the corpus is refused, even to an identical file" do
    for target <- [:case_file, :index, :directory] do
      dir = sibling_copy()
      on_exit(fn -> File.rm_rf!(dir) end)

      case target do
        :case_file ->
          path = Path.join(dir, "attestation-cases.json")
          File.rm!(path)
          File.ln_s!(Path.expand(Path.join(@role_corpus, "attestation-cases.json")), path)

        :index ->
          path = Path.join(dir, "index.json")
          File.rm!(path)
          File.ln_s!(Path.expand(Path.join(@role_corpus, "index.json")), path)

        :directory ->
          File.ln_s!(System.tmp_dir!(), Path.join(dir, "linked"))
      end

      {_out, err} = run_captured(["--corpus", dir])
      assert err =~ "symbolic link", inspect(target)
    end
  end

  test "a file the index does not name is refused, at any depth" do
    for extra <- ["stray.json", "nested/deeper/stray.raw"] do
      dir = sibling_copy()
      on_exit(fn -> File.rm_rf!(dir) end)
      path = Path.join(dir, extra)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, "{}")
      {_out, err} = run_captured(["--corpus", dir])
      assert err =~ "does not name", extra
    end
  end

  test "files over 1 MiB and directories over 4096 entries are refused before reading" do
    dir = sibling_copy()
    on_exit(fn -> File.rm_rf!(dir) end)
    File.write!(Path.join(dir, "attestation-cases.json"), :binary.copy(" ", 1_048_577))
    {_out, err} = run_captured(["--corpus", dir])
    assert err =~ "exceeds the 1 MiB limit"

    dir = sibling_copy()
    on_exit(fn -> File.rm_rf!(dir) end)
    many = Path.join(dir, "many")
    File.mkdir_p!(many)
    for n <- 1..4_096, do: File.write!(Path.join(many, "#{n}"), "")
    {_out, err} = run_captured(["--corpus", dir])
    assert err =~ "4096 entries"
  end

  test "an index that is not JSON, or names an unsafe path, is refused" do
    for index <- [
          "not json",
          ~s({"files":"nope"}),
          ~s({"files":[{"path":"../escape.json"}]}),
          ~s({"files":[{"path":"/absolute.json"}]}),
          ~s({"files":[{"path":"a/./b.json"}]}),
          ~s({"files":[{"path":"a\\\\b.json"}]}),
          ~s({"files":[{"path":"index.json"}]}),
          ~s({"files":[{"path":"a.json"},{"path":"a.json"}]}),
          ~s({"files":[{"name":"a.json"}]})
        ] do
      dir = sibling_copy()
      on_exit(fn -> File.rm_rf!(dir) end)
      File.write!(Path.join(dir, "index.json"), index)
      {_out, err} = run_captured(["--corpus", dir])
      assert err =~ "index is missing, malformed or names an unsafe path", index
    end
  end

  test "an unreadable subdirectory or a missing corpus directory is refused" do
    dir = sibling_copy()
    locked = Path.join(dir, "locked")
    File.mkdir_p!(locked)
    File.chmod!(locked, 0o000)

    on_exit(fn ->
      File.chmod(locked, 0o755)
      File.rm_rf!(dir)
    end)

    {_out, err} = run_captured(["--corpus", dir])
    assert err =~ "cannot read"

    {_out, err} = run_captured(["--corpus", Path.join(dir, "absent")])
    assert err =~ "cannot read"
  end

  test "a sibling corpus that is internally consistent but not certified fails closed" do
    dir = sibling_copy()
    on_exit(fn -> File.rm_rf!(dir) end)
    index = Path.join(dir, "index.json")
    File.write!(index, File.read!(index) <> "\n")
    {_out, err} = run_captured(["--corpus", dir])
    assert err =~ "not a certified corpus"
  end

  defp sibling_copy do
    dir = Path.join(System.tmp_dir!(), "bap-cli-sibling-#{System.unique_integer([:positive])}")
    File.cp_r!(@role_corpus, dir)
    dir
  end

  defp run_captured(argv) do
    parent = self()

    err =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        out = ExUnit.CaptureIO.capture_io(fn -> send(parent, {:status, Cli.run(argv)}) end)
        send(parent, {:out, out})
      end)

    assert_received {:status, status}
    assert_received {:out, out}
    assert status in [0, 1]
    assert status == 0 == (err == "")
    {out, err}
  end

  # --- escript integration tests (end-to-end exit contract) -----------------

  @tag :escript
  test "escript exit 0 on the shipped corpus and byte-identical report across runs" do
    build_escript!()

    {out0, 0} =
      System.cmd("escript", [@escript_path, "--corpus", @shipped_corpus], stderr_to_stdout: true)

    assert out0 =~ ~s("agreement":true)

    {out1, 0} =
      System.cmd("escript", [@escript_path, "--corpus", @shipped_corpus], stderr_to_stdout: true)

    assert out1 == out0
  end

  @tag :escript
  test "escript exit 2 on missing --corpus" do
    build_escript!()
    {out, 2} = System.cmd("escript", [@escript_path], stderr_to_stdout: true)
    assert out =~ "usage"
    refute out =~ ~s("agreement")
  end

  @tag :escript
  test "escript exit 1 on a tampered corpus" do
    build_escript!()
    corpus = tampered_corpus_copy(&flip_one_case_byte/1)
    clean_dir(corpus)

    {_out, 1} =
      System.cmd("escript", [@escript_path, "--corpus", corpus], stderr_to_stdout: true)
  end

  @tag :escript
  test "the built escript is directly executable (POSIX exec of the shebang file)" do
    build_escript!()

    {out, 0} = System.cmd(@escript_path, ["--corpus", @shipped_corpus], stderr_to_stdout: true)
    assert out =~ ~s("agreement":true)
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
      Portable.ls_r(dir)
      |> Enum.filter(&String.ends_with?(&1, ".json"))
      |> Enum.sort()
      |> List.first()

    bytes = File.read!(case_file)
    # Flip a byte in the middle of the file (avoid the format/provenance prefix).
    pos = div(byte_size(bytes), 2)
    <<pre::binary-size(^pos), byte, rest::binary>> = bytes
    tampered = <<pre::binary, Bitwise.bxor(byte, 0x01), rest::binary>>
    File.write!(case_file, tampered)
  end

  defp make_one_file_unreadable(dir) do
    case_file =
      Portable.ls_r(dir)
      |> Enum.filter(&String.ends_with?(&1, ".json"))
      |> Enum.sort()
      |> List.first()

    File.chmod!(case_file, 0o000)
  end

  defp restore_readability(dir) do
    Portable.ls_r(dir)
    |> Enum.filter(&String.ends_with?(&1, ".json"))
    |> Enum.each(fn f ->
      try do
        File.chmod!(f, 0o644)
      rescue
        File.Error -> :ok
      end
    end)
  end

  defp drop_one_case_file(dir) do
    case_file =
      Portable.ls_r(dir)
      |> Enum.filter(&String.ends_with?(&1, ".json"))
      |> Enum.sort()
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
