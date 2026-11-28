Code.require_file("corpus_catalog.exs", __DIR__)

defmodule BoundedAuthorityProtocol.CorpusDistribution do
  @moduledoc false
  alias BoundedAuthorityProtocol.CorpusCatalog, as: Catalog

  def files!(root), do: walk!(root, root) |> MapSet.new()

  defp walk!(path, root) do
    case File.lstat!(path).type do
      :directory -> Enum.flat_map(File.ls!(path), &walk!(Path.join(path, &1), root))
      :regular -> [Path.relative_to(path, root)]
      type -> raise "nonregular corpus input #{path}: #{type}"
    end
  end

  defp compare_files!(source, snapshot, entries) do
    for relative <- entries do
      unless File.read!(Path.join(source, relative)) == File.read!(Path.join(snapshot, relative)),
        do: raise("#{snapshot}/#{relative}: content differs from the Hex corpus")
    end
  end

  def inventory!(package_root, source_root \\ Catalog.root()) do
    shipped = files!(Path.join(package_root, "priv/conformance"))
    source = files!(Path.join(source_root, "priv/conformance"))
    unless shipped == source, do: raise("Hex corpus inventory differs from source tree")

    # Read the independent exact package census without executing the consumer build gate.
    checker = source_root |> Path.join("scripts/check_package.exs") |> File.read!()
    ast = Code.string_to_quoted!(checker)

    {_, [census]} =
      Macro.prewalk(ast, [], fn
        {:@, _, [{:expected_files, _, [value]}]} = node, acc -> {node, [value | acc]}
        node, acc -> {node, acc}
      end)

    {_, declared} =
      Macro.prewalk(census, [], fn
        "priv/conformance/" <> path = node, acc -> {node, [path | acc]}
        node, acc -> {node, acc}
      end)

    declared = MapSet.new(declared)
    unless declared == shipped, do: raise("check_package corpus inventory differs from Hex build")

    observed =
      package_root
      |> Path.join("priv/conformance/**/index.json")
      |> Path.wildcard()
      |> Enum.map(
        &(Path.dirname(&1)
          |> Path.relative_to(Path.join(package_root, "priv/conformance")))
      )
      |> MapSet.new()

    certified =
      Catalog.entries()
      |> Enum.map(&Path.relative_to(&1.source, "priv/conformance"))
      |> MapSet.new()

    unless observed == certified,
      do: raise("Hex corpus inventory differs from CLI certification map")

    shipped
  end

  def check!(package_root, source_root \\ Catalog.root()) do
    shipped = inventory!(package_root, source_root)
    source = Path.join(package_root, "priv/conformance")
    source_tree = Path.join(source_root, "priv/conformance")
    compare_files!(source, source_tree, shipped)

    entries = Catalog.entries()

    {snapshotted, unsnapshotted} = Enum.split_with(entries, &(&1.runners != []))
    snapshot_corpora = corpus_paths(snapshotted)
    unsnapshotted_prefixes = Enum.map(corpus_paths(unsnapshotted), &(&1 <> "/"))

    sdk_files =
      shipped
      |> Enum.reject(&String.starts_with?(&1, unsnapshotted_prefixes))
      |> MapSet.new()

    sdk_manifest =
      source
      |> Path.join("verdict-digests.json")
      |> File.read!()
      |> :json.decode()
      |> Map.update!("corpora", &Map.take(&1, snapshot_corpora))
      |> encode_manifest()

    for sdk <- ["python", "rust", "go"] do
      old = Path.wildcard(Path.join(source_root, "sdks/#{sdk}/conformance/corpus*"))
      if old != [], do: raise("uncatalogued SDK snapshots: #{inspect(old)}")
      snapshot = Path.join(source_root, "sdks/#{sdk}/conformance/priv/conformance")

      unless files!(snapshot) == sdk_files, do: raise("corpus file set mismatch: #{snapshot}")

      compare_files!(source, snapshot, MapSet.delete(sdk_files, "verdict-digests.json"))

      unless File.read!(Path.join(snapshot, "verdict-digests.json")) == sdk_manifest,
        do: raise("#{snapshot}/verdict-digests.json: content differs from the Hex corpus projection")
    end
  end

  defp corpus_paths(entries), do: Enum.map(entries, &Path.relative_to(&1.source, "priv/conformance"))

  # Manifest keys and string values are ASCII; sorted keys give the JCS projection.
  defp encode_manifest(manifest) do
    manifest
    |> :json.encode(fn
      map, encode when is_map(map) -> :json.encode_key_value_list(Enum.sort(map), encode)
      value, encode -> :json.encode_value(value, encode)
    end)
    |> IO.iodata_to_binary()
  end

  def with_package!(fun) do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "bap-corpus-package-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(tmp)

    try do
      archive = Path.join(tmp, "package.tar")

      {output, status} =
        System.cmd("mix", ["hex.build", "--output", archive],
          cd: Catalog.root(),
          stderr_to_stdout: true
        )

      if status != 0, do: raise("Hex corpus build failed: #{output}")
      unpacked = Path.join(tmp, "unpacked")
      apply(Hex.Tar, :unpack!, [archive, unpacked])
      fun.(unpacked)
    after
      File.rm_rf!(tmp)
    end
  end
end
