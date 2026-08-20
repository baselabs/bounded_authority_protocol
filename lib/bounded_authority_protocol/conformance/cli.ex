defmodule BoundedAuthorityProtocol.Conformance.Cli do
  @moduledoc """
  Deterministic offline verifier CLI for the v1 conformance corpus.

  This is the package's I/O carve-out: argv parsing, `File.read`/`File.ls` to load a corpus
  directory, and report output (`IO.binwrite`/`File.write`). Every judgment — corpus integrity,
  case execution, agreement, report bytes — delegates to the PURE core
  (`Corpus`/`Runner`/`Report`). No clock, network, randomness, or trust selection here or in the
  pure core it calls.

  ## Exit contract

  - `0` — complete agreement: every index file present, no unlisted file, every SHA-256 equal,
    every count equal, every required applicability cell nonempty, every `n/a` cell empty, every
    case verdict and producer output byte equal to expectation.
  - `1` — any disagreement, missing file, count mismatch, or integrity failure.
  - `2` — usage error (missing required `--corpus`, unknown flag, missing value).

  `--corpus DIR` is REQUIRED (no default — a wrong-corpus run that exits 0 is a quiet
  misverification path in the tool built to eliminate quiet misverification).
  """

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner

  @usage "usage: bounded_authority_conformance --corpus DIR [--report PATH]\n"

  # The certified corpus identity (ADR 0014 D4): base64url SHA-256 of the exact index.json bytes
  # this verifier was certified against. The three SDK runners pin the identical value; this closes
  # the parity gap so `mix conformance.verify` fails closed on a corpus that is internally
  # self-consistent but is NOT the certified corpus (e.g. a regenerated index over a shrunken case
  # set — which passes integrity + agreement, so nothing else here would catch it). To rotate the
  # corpus, bump this constant AND every SDK runner's CERTIFIED_INDEX_SHA in the same change.
  @certified_index_sha256 "paxzYcUI0rtVxsowRaXMBuxKP2T2WQQhQQjG8QxwTcw"

  @doc """
  Runs the CLI against `argv` and returns the contract exit status (0/1/2).

  Does NOT halt — the escript entry `Main.main/1` calls `System.halt(Cli.run(argv))`. The corpus
  directory is loaded via `File.ls`/`File.read` into the `%{path => binary}` map the pure
  `Corpus.load/1` consumes (paths relative to the corpus dir, e.g. "cases/json/decode.json").

  The optional second argument overrides the certified index SHA-256; it exists ONLY so the pin's
  non-vacuity is unit-testable (feed a mismatched expectation, observe exit 1). The escript entry
  always calls `run/1`, so production verification always binds the real `@certified_index_sha256`
  — this seam cannot weaken the pin in any shipped path.
  """
  @spec run([binary()]) :: 0 | 1 | 2
  @spec run([binary()], binary()) :: 0 | 1 | 2
  def run(argv, certified_index \\ @certified_index_sha256) do
    case parse(argv) do
      {:ok, corpus_dir, report_path} ->
        load_and_run(corpus_dir, report_path, certified_index)

      :usage ->
        IO.binwrite(@usage)
        2
    end
  end

  defp parse(argv) do
    case parse_args(argv, %{corpus: nil, report: nil}) do
      {:ok, %{corpus: nil}} -> :usage
      {:ok, %{corpus: dir, report: report}} -> {:ok, dir, report}
      :usage -> :usage
    end
  end

  defp parse_args([], acc), do: {:ok, acc}

  defp parse_args(["--corpus", dir | rest], acc), do: parse_args(rest, %{acc | corpus: dir})

  defp parse_args(["--corpus"], _acc), do: :usage

  defp parse_args(["--report", path | rest], acc), do: parse_args(rest, %{acc | report: path})

  defp parse_args(["--report"], _acc), do: :usage

  defp parse_args([_unknown | _rest], _acc), do: :usage

  defp load_and_run(corpus_dir, report_path, certified_index) do
    with {:ok, map} <- read_corpus_dir(corpus_dir),
         {:ok, corpus} <- Corpus.load(map),
         :ok <- assert_certified_corpus(corpus, certified_index),
         results <- Runner.run(corpus),
         {:ok, bytes} <- Report.to_bytes(corpus, results),
         :ok <- write_report(bytes, report_path) do
      report = Report.build(corpus, results)
      report.exit_status
    else
      # Any integrity or load failure, a NON-CERTIFIED corpus, a report-encoding failure, OR a
      # failed report write is exit 1 (closed). A swallowed --report write would exit 0 with no
      # report on disk — a quiet failure of the evidence artifact in the tool built to eliminate
      # quiet failure.
      _ -> 1
    end
  end

  # ADR 0014 D4: fail closed unless the loaded corpus is the exact certified snapshot. Corpus.load
  # proves internal self-consistency; this proves the corpus IS the one the verifier was certified
  # against, so a regenerated-index shrunken corpus (self-consistent, all present cases agree) does
  # not pass verification.
  defp assert_certified_corpus(corpus, certified_index) do
    if Report.index_identity(corpus.index_bytes) == certified_index do
      :ok
    else
      {:error, :uncertified_corpus}
    end
  end

  # Recursively walk the corpus dir, keying each file by its path relative to the corpus root
  # (forward-slash joined), matching the index's "cases/<area>/<file>.json" references.
  defp read_corpus_dir(dir) do
    case File.ls(dir) do
      {:ok, entries} -> walk(dir, entries, "")
      {:error, _} -> {:error, :invalid}
    end
  end

  defp walk(_dir, [], _prefix), do: {:ok, %{}}

  defp walk(dir, [entry | rest], prefix) do
    full = Path.join(dir, entry)
    rel = if prefix == "", do: entry, else: Path.join(prefix, entry)

    if File.dir?(full) do
      with {:ok, sub} <- File.ls(full),
           {:ok, walked} <- walk(full, sub, rel),
           {:ok, acc} <- walk(dir, rest, prefix) do
        {:ok, Map.merge(walked, acc)}
      else
        {:error, _} -> {:error, :invalid}
      end
    else
      with {:ok, bytes} <- File.read(full),
           {:ok, acc} <- walk(dir, rest, prefix) do
        {:ok, Map.put(acc, rel, bytes)}
      else
        {:error, _} -> {:error, :invalid}
      end
    end
  end

  defp write_report(bytes, nil) do
    IO.binwrite(bytes)
  end

  defp write_report(bytes, path) do
    File.write(path, bytes)
  end
end
