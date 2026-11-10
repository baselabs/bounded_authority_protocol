defmodule BoundedAuthorityProtocol.Conformance.Cli do
  @moduledoc """
  Deterministic offline verifier CLI for every packaged conformance corpus.

  Run it as the `bounded_authority_conformance` escript or call `run/1` from Elixir. Both take the
  same arguments and return the same exit status; `run/1` never halts the VM.

      bounded_authority_conformance --corpus DIR [--report PATH]
      bounded_authority_conformance --help
      bounded_authority_conformance --version

  ## Corpora

  `--corpus DIR` is required. `DIR` is one corpus directory, the one holding its `index.json`.
  The CLI recognizes the corpus from its index; there is no flag per corpus. Inside the package
  (`Application.app_dir(:bounded_authority_protocol, "priv/conformance")`, or
  `deps/bounded_authority_protocol/priv/conformance` in a Mix project) they are:

  | Directory | Corpus |
  |---|---|
  | `v1/corpus`, `v2/corpus`, `v3/corpus` | contract-majors 1, 2 and 3 |
  | `strict-ed25519` | strict Ed25519 (`bap-strict-ed25519/1`) |
  | `producer-canonicality` | producer canonicality (`bap-producer-canonicality/1`) |
  | `selector-float-zero` | selector float zero (`bap-selector-float-zero/1`) |
  | `application-profiles/local-loopback-http/v1` | local-loopback HTTP proofs |
  | `attestation-profiles/role-attestation/v1` | role attestations |
  | `attestation-profiles/content-assertion/v1` | content assertions |

  Each directory must be exactly the certified corpus this release was built against: its
  `index.json` bytes must hash to the pinned identity, so a regenerated or edited corpus fails
  even when it is internally consistent.

  ## What it reads

  The CLI reads `index.json`, then only the files the index names. It refuses, with exit 1:

  - a symbolic link, device or other non-regular entry anywhere inside `DIR`;
  - any file inside `DIR` that the index does not name;
  - an index path that is absolute or contains an empty, `.` or `..` segment;
  - a file larger than 1 MiB, or more than 4,096 entries under `DIR`.

  `DIR` itself, and the directories above it, may be reached through symbolic links (Mix links
  `_build/*/lib/*/priv` to the package's `priv`).

  ## Exit status

  - `0`: complete agreement. Every named file is present with its SHA-256, the counts match, and
    the executed cases are exactly the certified census (unique case ids, the same id set and
    count as the index, each case executed from the file that declares it), every one agreeing
    with its expected verdict and bytes.
  - `1`: anything else: a disagreement, an incomplete or padded run, an integrity or
    certification failure, a refused or unreadable file, or a report that cannot be written.
  - `2`: a usage error: `--corpus` missing, an unknown flag, or a flag without its value.

  `--help` and `--version` print to standard output and exit 0.

  ## Output

  The report goes to `--report PATH`, or to standard output when the flag is absent. It is one
  line of RFC 8785 (JCS) JSON followed by a newline, with exactly these members:

  - `format`: `"bounded-authority-protocol-<corpus>-conformance-report"`, where `<corpus>` is
    `v1`, `v2`, `v3`, `strict-ed25519`, `producer-canonicality`, `selector-float-zero`,
    `local-loopback-http`, `role-attestation` or `content-assertion`;
  - `agreement`: `true` only for exit 0;
  - `exit_status`: `0` or `1`, the status the run returns when the report is written;
  - `total`, `agreed`, `disagreed`: case counts;
  - `index_sha256_base64url`: base64url SHA-256 of the exact `index.json` bytes.

  These members, the flags and the exit statuses are a stable contract of package 1.x. A failure
  before a report exists (usage, refusal, integrity, certification) writes no report.

  Every failure writes one line to standard error naming its class, for example
  `bounded_authority_conformance: the corpus directory holds a file the index does not name`. The
  line never contains a path, a case id or corpus bytes. Usage errors print the usage text to
  standard error.

  ## Purity

  This module is the package's one I/O carve-out: argument parsing, reading the corpus directory
  and writing the report. Every judgment (integrity, certification, case execution, agreement and
  completeness, report bytes) is made by the package's pure internal core. No clock, network,
  randomness or trust selection is involved.
  """

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @version Keyword.fetch!(Mix.Project.config(), :version)

  @usage """
  usage: bounded_authority_conformance --corpus DIR [--report PATH]
         bounded_authority_conformance --help | --version

  Verifies one packaged conformance corpus directory (the one holding index.json) and writes a
  JSON report to PATH or standard output. Exit 0: complete agreement; 1: any disagreement,
  incomplete run, integrity, certification or I/O failure; 2: usage error.
  """

  @prefix "bounded_authority_conformance: "

  # Ceilings on what the CLI will read: the largest packaged file is 65,537 bytes and the largest
  # corpus has a few hundred entries.
  @max_file_bytes 1_048_576
  @max_entries 4_096

  # The certified corpus identities: base64url SHA-256 of the exact index.json bytes this verifier
  # was certified against, keyed by corpus. The SDK runners pin the identical values. This closes
  # the gap a self-consistent but regenerated corpus (for example a shrunken case set with a
  # matching index) would otherwise pass through. To rotate a corpus, bump its constant and every
  # SDK runner's pin in the same change (scripts/regen_corpus_digests.exs). The contract-major 3 pin
  # stays the closing entry: scripts/regen_corpus_digests.exs locates each contract-major pin by its
  # exact single-line shape.
  @certified_index_sha256 %{
    :strict_ed25519 => "cyEX3-GIG1U5mBJqlSSpW_sRcSV-OI1UMKCgmfIofLk",
    :producer_canonicality => "me5vu_MnWLA9RjBkf3IdjU40nwYo2GBJPWZ_5udixgE",
    :selector_float_zero => "l_16mc2_OswKePW6HGVW4jpj4K1m9TPjH9afgtxfMAM",
    :local_loopback_http => "EPxM8Fr_zdyeY0D_OSwkfiWrA4zZOPJVeCmnzmOxpeQ",
    :role_attestation => "vlJ1xpU5oPMXNCQv8ApITC-FXzkYHFVonYsPZxGV1io",
    :content_assertion => "FLdDbM98yR_s5SoVeMN2DfZyCpNJTRR-5atSPiziGHY",
    1 => "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs",
    2 => "beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A",
    3 => "pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw"
  }

  @messages %{
    unreadable: "cannot read the corpus directory or one of its named files",
    not_regular: "the corpus directory holds a symbolic link or another non-regular entry",
    unlisted: "the corpus directory holds a file the index does not name",
    oversized: "a corpus file exceeds the 1 MiB limit or the directory exceeds 4096 entries",
    index: "the corpus index is missing, malformed or names an unsafe path",
    integrity: "the corpus failed integrity verification",
    uncertified: "the corpus is not a certified corpus for this release",
    report: "the report could not be written",
    invalid: "the report could not be encoded",
    disagreement: "the corpus run did not reach complete agreement"
  }

  @doc """
  Runs the CLI against `argv` and returns the exit status (0, 1 or 2). See the module
  documentation for the arguments, the files read, the report and the exit statuses.

  It does not halt; the escript's entry point halts with the returned status. The certified index
  identities are fixed in this module and cannot be supplied by the caller.
  """
  @spec run([binary()]) :: 0 | 1 | 2
  def run(argv) do
    case parse(argv) do
      {:ok, corpus_dir, report_path} ->
        verify(corpus_dir, report_path)

      :help ->
        IO.binwrite(@usage)
        0

      :version ->
        IO.binwrite(@version <> "\n")
        0

      :usage ->
        IO.binwrite(:stderr, @usage)
        2
    end
  end

  defp parse(["--help" | _rest]), do: :help
  defp parse(["-h" | _rest]), do: :help
  defp parse(["--version"]), do: :version

  defp parse(argv) do
    case parse_args(argv, %{corpus: nil, report: nil}) do
      {:ok, %{corpus: nil}} -> :usage
      {:ok, %{corpus: dir, report: report}} -> {:ok, dir, report}
      :usage -> :usage
    end
  end

  defp parse_args([], acc), do: {:ok, acc}
  defp parse_args(["--corpus", dir | rest], acc), do: parse_args(rest, %{acc | corpus: dir})
  defp parse_args(["--report", path | rest], acc), do: parse_args(rest, %{acc | report: path})
  defp parse_args(_argv, _acc), do: :usage

  defp verify(corpus_dir, report_path) do
    with {:ok, map} <- read_corpus(corpus_dir),
         {:ok, corpus} <- load(map),
         :ok <- certified(corpus),
         results = Runner.run(corpus),
         report = Report.build(corpus, results),
         {:ok, bytes} <- Report.to_bytes(corpus, results),
         :ok <- write_report(bytes <> "\n", report_path) do
      if report.exit_status == 0, do: 0, else: fail(:disagreement)
    else
      {:error, class} -> fail(class)
    end
  end

  defp fail(class) do
    IO.binwrite(:stderr, @prefix <> Map.get(@messages, class) <> "\n")
    1
  end

  defp load(map) do
    case Corpus.load_any(map) do
      {:ok, corpus} -> {:ok, corpus}
      {:error, :invalid} -> {:error, :integrity}
    end
  end

  # Fail closed unless the loaded corpus is the exact certified snapshot. The loaders prove
  # internal consistency; this proves the corpus is the one the verifier was certified against.
  defp certified(corpus) do
    if Report.index_identity(corpus.index_bytes) ==
         Map.get(@certified_index_sha256, corpus.major),
       do: :ok,
       else: {:error, :uncertified}
  end

  # Read index.json, take the paths it names, refuse anything else in the directory, then read
  # only those paths. Entries are inspected with lstat, so a symbolic link is never followed.
  defp read_corpus(dir) do
    with {:ok, index_bytes} <- read_regular(dir, "index.json"),
         {:ok, declared} <- declared_paths(index_bytes),
         {:ok, present, _count} <- scan(dir, "", 0),
         :ok <- only_declared(present, declared) do
      read_declared(dir, declared, %{"index.json" => index_bytes})
    end
  end

  defp declared_paths(index_bytes) do
    case Corpus.declared_paths(index_bytes) do
      {:ok, paths} -> {:ok, paths}
      {:error, :invalid} -> {:error, :index}
    end
  end

  defp only_declared(present, declared) do
    case Corpus.only_declared(present, declared) do
      :ok -> :ok
      {:error, :invalid} -> {:error, :unlisted}
    end
  end

  defp scan(dir, prefix, count) do
    case File.ls(Path.join(dir, prefix)) do
      {:ok, entries} -> scan_entries(dir, prefix, entries, [], count)
      {:error, _reason} -> {:error, :unreadable}
    end
  end

  defp scan_entries(_dir, _prefix, [], acc, count), do: {:ok, acc, count}

  defp scan_entries(_dir, _prefix, _entries, _acc, count) when count >= @max_entries,
    do: {:error, :oversized}

  defp scan_entries(dir, prefix, [entry | rest], acc, count) do
    relative = join(prefix, entry)

    case File.lstat(Path.join(dir, relative)) do
      {:ok, %File.Stat{type: :regular}} ->
        scan_entries(dir, prefix, rest, [relative | acc], count + 1)

      {:ok, %File.Stat{type: :directory}} ->
        with {:ok, nested, count} <- scan(dir, relative, count + 1) do
          scan_entries(dir, prefix, rest, nested ++ acc, count)
        end

      _other ->
        {:error, :not_regular}
    end
  end

  defp read_declared(_dir, [], map), do: {:ok, map}

  defp read_declared(dir, [path | rest], map) do
    with {:ok, bytes} <- read_regular(dir, path) do
      read_declared(dir, rest, Map.put(map, path, bytes))
    end
  end

  # A named file must be a regular file (never a link) within the size cap, checked before it is
  # read.
  defp read_regular(dir, relative) do
    path = Path.join(dir, relative)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_file_bytes -> read(path)
      {:ok, %File.Stat{type: :regular}} -> {:error, :oversized}
      {:ok, %File.Stat{}} -> {:error, :not_regular}
      {:error, _reason} -> {:error, :unreadable}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, _reason} -> {:error, :unreadable}
    end
  end

  defp join("", entry), do: entry
  defp join(prefix, entry), do: prefix <> "/" <> entry

  defp write_report(bytes, nil), do: IO.binwrite(bytes)

  defp write_report(bytes, path) do
    case File.write(path, bytes) do
      :ok -> :ok
      {:error, _reason} -> {:error, :report}
    end
  end
end
