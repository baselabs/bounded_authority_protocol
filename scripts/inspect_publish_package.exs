# Inspect the archive just built by publish.yml against mix.exs, before publication.
config = Mix.Project.config()
name = to_string(Keyword.fetch!(config, :app))
version = Keyword.fetch!(config, :version)
archive_path =
  case System.argv() do
    [] -> "#{name}-#{version}.tar"
    [path] -> path
  end

archive = String.to_charlist(archive_path)

{:ok, outer_files} = :erl_tar.table(archive)

unless Enum.sort(Enum.map(outer_files, &to_string/1)) ==
         ["CHECKSUM", "VERSION", "contents.tar.gz", "metadata.config"] do
  raise "unexpected Hex archive structure"
end

scratch = Path.join(System.tmp_dir!(), "publish-package-#{System.unique_integer([:positive])}")

File.mkdir!(scratch)

try do
  :ok = :erl_tar.extract(archive, [{:cwd, String.to_charlist(scratch)}])
  {:ok, terms} = :file.consult(String.to_charlist(Path.join(scratch, "metadata.config")))
  metadata = Map.new(terms)

  unless map_size(metadata) == length(terms) and metadata["name"] == name and
           metadata["app"] == name and metadata["version"] == version do
    raise "Hex metadata identity differs from mix.exs"
  end

  expected =
    config
    |> Keyword.fetch!(:package)
    |> Keyword.fetch!(:files)
    |> Enum.flat_map(fn path ->
      pattern = if File.dir?(path), do: Path.join(path, "**/*"), else: path
      Path.wildcard(pattern, match_dot: true)
    end)
    |> Enum.filter(&File.regular?/1)
    |> Enum.sort()

  {:ok, contents} =
    :erl_tar.extract(String.to_charlist(Path.join(scratch, "contents.tar.gz")), [
      :compressed,
      :memory
    ])

  actual = Enum.sort(Enum.map(contents, fn {path, _bytes} -> to_string(path) end))

  unless expected != [] and actual == expected and Enum.sort(metadata["files"]) == expected do
    raise "Hex archive file inventory differs from mix.exs package files"
  end

  for {path, bytes} <- contents do
    unless File.read!(to_string(path)) == bytes do
      raise "Hex archive bytes differ from the source tree: #{path}"
    end
  end

  IO.puts("Hex package identity, metadata, inventory and source bytes agree with mix.exs")
after
  File.rm_rf!(scratch)
end
