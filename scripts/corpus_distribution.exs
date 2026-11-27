Code.require_file("corpus_catalog.exs", __DIR__)

defmodule BoundedAuthorityProtocol.CorpusDistribution do
  @moduledoc false
  alias BoundedAuthorityProtocol.CorpusCatalog, as: Catalog

  # These source-only candidates join the Hex and SDK inventory when every
  # maintained runner can execute their complete case sets.
  @candidate_roots [
    "attestation-profiles/content-assertion-es256/v1/",
    "attestation-profiles/holder-custody-attestation/v1/",
    "content-profiles/action-approval/v1/"
  ]

  def files!(root), do: walk!(root, root) |> MapSet.new()

  defp walk!(path, root) do
    case File.lstat!(path).type do
      :directory -> Enum.flat_map(File.ls!(path), &walk!(Path.join(path, &1), root))
      :regular -> [Path.relative_to(path, root)]
      type -> raise "nonregular corpus input #{path}: #{type}"
    end
  end

  def compare!(source, snapshot) do
    compare_files!(source, snapshot, files!(snapshot))
  end

  defp compare_files!(source, snapshot, snapshot_files) do
    source_files = files!(source)
    unless source_files == snapshot_files, do: raise("corpus file set mismatch: #{snapshot}")

    for relative <- source_files do
      unless File.read!(Path.join(source, relative)) == File.read!(Path.join(snapshot, relative)),
        do: raise("#{snapshot}/#{relative}: content differs from the Hex corpus")
    end
  end

  def inventory!(package_root, source_root \\ Catalog.root()) do
    shipped = files!(Path.join(package_root, "priv/conformance"))
    source = release_source_files(Path.join(source_root, "priv/conformance"))
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
    inventory!(package_root, source_root)
    source = Path.join(package_root, "priv/conformance")
    source_tree = Path.join(source_root, "priv/conformance")
    compare_files!(source, source_tree, release_source_files(source_tree))

    for sdk <- ["python", "rust", "go"] do
      old = Path.wildcard(Path.join(source_root, "sdks/#{sdk}/conformance/corpus*"))
      if old != [], do: raise("uncatalogued SDK snapshots: #{inspect(old)}")
      compare!(source, Path.join(source_root, "sdks/#{sdk}/conformance/priv/conformance"))
    end
  end

  defp release_source_files(root) do
    root
    |> files!()
    |> Enum.reject(&String.starts_with?(&1, @candidate_roots))
    |> MapSet.new()
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
