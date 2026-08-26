defmodule BoundedAuthorityProtocol.CorpusSyncGate do
  # Corpus vendored-snapshot sync gate (spec-decoupling L1; ADR 0019 intra-repo drift check,
  # NOT a distribution artifact). The Rust and Go SDKs vendor self-contained corpus snapshots;
  # a byte drift between the certified corpus and either snapshot is exactly the silent-drift
  # class their startup SHA assertion exists to catch at RUNTIME — this gate catches it at
  # COMMIT time instead, before a red SDK suite or a confusing rotation.

  @snapshots [
    "sdks/rust/conformance/corpus",
    "sdks/go/conformance/corpus"
  ]

  @source "priv/conformance/v1/corpus"

  def run do
    problems =
      Enum.flat_map(@snapshots, fn snapshot ->
        compare(@source, snapshot)
      end)

    case problems do
      [] ->
        IO.puts(
          "corpus sync gate: ok snapshots=#{length(@snapshots)} byte-identical to #{@source}"
        )

      problems ->
        IO.puts(:stderr, "corpus sync gate FAILED:\n" <> Enum.join(problems, "\n"))
        System.halt(1)
    end
  end

  # Byte-compare two directories, every file, BOTH directions.
  defp compare(source_dir, snapshot_dir) do
    source = files_of(source_dir)
    snapshot = files_of(snapshot_dir)

    only_source = MapSet.difference(source, snapshot) |> Enum.sort()
    only_snapshot = MapSet.difference(snapshot, source) |> Enum.sort()

    content =
      source
      |> MapSet.intersection(snapshot)
      |> Enum.sort()
      |> Enum.flat_map(fn rel ->
        a = File.read!(Path.join(source_dir, rel))
        b = File.read!(Path.join(snapshot_dir, rel))

        if a == b,
          do: [],
          else: ["#{snapshot_dir}/#{rel}: content differs from the certified corpus"]
      end)

    Enum.map(
      only_source,
      &"#{snapshot_dir}/#{&1}: present in the certified corpus, MISSING from the snapshot"
    ) ++
      Enum.map(
        only_snapshot,
        &"#{snapshot_dir}/#{&1}: present in the snapshot, ABSENT from the certified corpus"
      ) ++
      content
  end

  defp files_of(dir) do
    walk(dir, dir)
  end

  defp walk(dir, root) do
    case File.ls(dir) do
      {:ok, entries} ->
        Enum.flat_map(entries, fn entry ->
          full = Path.join(dir, entry)

          if File.dir?(full) do
            walk(full, root)
          else
            [String.trim_leading(full, root <> "/")]
          end
        end)
        |> MapSet.new()

      _ ->
        MapSet.new()
    end
  end
end

BoundedAuthorityProtocol.CorpusSyncGate.run()
