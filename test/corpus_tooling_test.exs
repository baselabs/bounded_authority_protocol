Code.require_file("../scripts/corpus_distribution.exs", __DIR__)

defmodule BoundedAuthorityProtocol.CorpusToolingTest do
  use ExUnit.Case, async: false
  alias BoundedAuthorityProtocol.CorpusCatalog, as: Catalog

  @moduletag timeout: 300_000

  setup_all do
    package =
      Path.join(System.tmp_dir!(), "bap-tooling-hex-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(package) end)

    BoundedAuthorityProtocol.CorpusDistribution.with_package!(fn unpacked ->
      File.cp_r!(unpacked, package)
    end)

    %{package: package}
  end

  setup context do
    root =
      Path.join(System.tmp_dir!(), "bap-corpus-tooling-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(root) end)

    files =
      [
        Catalog.cli(),
        "test/conformance/cli_test.exs",
        "priv/conformance",
        "scripts/check_package.exs"
      ] ++
        Catalog.reference_files() ++
        Enum.map(
          ["corpus_catalog", "corpus_distribution", "regen_corpus_digests"],
          &"scripts/#{&1}.exs"
        )

    for relative <- files do
      copy(Path.join(Catalog.root(), relative), Path.join(root, relative))
    end

    for entry <- Catalog.entries() do
      copy(Path.join(Catalog.root(), entry.source), Path.join(root, entry.source))

      for runner <- entry.runners do
        copy(runner, Path.join(root, Path.relative_to(runner, Catalog.root())))
      end
    end

    for {snapshot, _source} <- Catalog.snapshots() do
      copy(snapshot, Path.join(root, Path.relative_to(snapshot, Catalog.root())))
    end

    # The quotation scan reads the git source tree, so the copy is a repository too.
    {_, 0} = System.cmd("git", ["init", "--quiet"], cd: root)

    File.write!(
      Path.join(root, "scripts/check_corpus_sync.exs"),
      "Code.require_file(\"corpus_distribution.exs\", __DIR__)\nBoundedAuthorityProtocol.CorpusDistribution.check!(" <>
        inspect(context.package) <> ")\n"
    )

    %{root: root}
  end

  test "sync rejects byte drift in each strict-Ed25519 snapshot", %{root: root} do
    assert {_, 0} = run(root, "check_corpus_sync")

    for sdk <- ["python", "rust", "go"] do
      path = Path.join(root, "sdks/#{sdk}/conformance/priv/conformance/strict-ed25519/index.json")
      original = File.read!(path)
      File.write!(path, original <> "\n")
      {output, status} = run(root, "check_corpus_sync")
      assert status != 0

      assert output =~
               "#{sdk}/conformance/priv/conformance/strict-ed25519/index.json: content differs"

      File.write!(path, original)
    end
  end

  test "every corpus runner pin is checked, including sibling profiles", %{root: root} do
    assert {_, 0} = run(root, "regen_corpus_digests")

    for entry <- Catalog.entries(), runner <- entry.runners do
      path = Path.join(root, Path.relative_to(runner, Catalog.root()))
      original = File.read!(path)
      [declaration, digest] = Regex.run(Catalog.runner_pin(entry.key), original)
      bad = String.replace(declaration, digest, String.duplicate("0", byte_size(digest)))
      File.write!(path, String.replace(original, declaration, bad, global: false))
      {output, status} = run(root, "regen_corpus_digests")
      assert status != 0
      assert output =~ "corpus digest drift"
      File.write!(path, original)
    end
  end

  test "rotation updates all corpora, SDK pins, and Elixir mirrors", %{root: root} do
    for entry <- Catalog.entries() do
      path = Path.join([root, entry.source, "index.json"])
      File.write!(path, File.read!(path) <> "\n")
    end

    {output, status} = run(root, "regen_corpus_digests")
    assert status != 0
    assert output =~ "corpus digest drift"

    preserved =
      for {relative, _pins} <- Catalog.preservation(),
          into: %{},
          do: {relative, File.read!(Path.join(root, relative))}

    {output, status} = run(root, "regen_corpus_digests", ["--write"])
    assert status != 0
    assert output =~ "hand-kept preservation corpus digest drift"
    assert output =~ "prose corpus digest drift"
    refute output =~ "corpus digest drift ("
    for {relative, bytes} <- preserved, do: assert(File.read!(Path.join(root, relative)) == bytes)
    cli = File.read!(Path.join(root, Catalog.cli()))

    for entry <- Catalog.entries() do
      bytes = File.read!(Path.join([root, entry.source, "index.json"]))
      digest = :crypto.hash(:sha256, bytes)
      assert cli =~ Base.url_encode64(digest, padding: false)

      for runner <- entry.runners do
        [_, actual] =
          Regex.run(
            Catalog.runner_pin(entry.key),
            File.read!(Path.join(root, Path.relative_to(runner, Catalog.root())))
          )

        assert actual in [
                 Base.encode16(digest, case: :lower),
                 Base.url_encode64(digest, padding: false)
               ]
      end
    end

    # Rotation changes source pins, never independently certified corpus bytes.
    for entry <- Catalog.entries() do
      relative = Path.join(entry.source, "index.json")

      assert File.read!(Path.join(root, relative)) ==
               File.read!(Path.join(Catalog.root(), relative)) <> "\n"
    end
  end

  test "every preservation pin and prose quotation is checked but never written", %{root: root} do
    for {class, references} <- [
          {"hand-kept preservation", Catalog.preservation()},
          {"prose", Catalog.prose()}
        ],
        {relative, pins} <- references,
        {key, encoding, _count} <- pins do
      path = Path.join(root, relative)
      original = File.read!(path)
      expected = Catalog.reference_digest(key, encoding)

      mutated =
        String.replace(original, expected, String.duplicate("0", byte_size(expected)),
          global: false
        )

      File.write!(path, mutated)
      {output, status} = run(root, "regen_corpus_digests")
      assert status != 0
      assert output =~ "#{relative}: #{class} corpus digest drift"
      {_, status} = run(root, "regen_corpus_digests", ["--write"])
      assert status != 0
      assert File.read!(path) == mutated
      File.write!(path, original)
    end
  end

  test "new certified digest quotations require classification anywhere in the tree",
       %{root: root} do
    for relative <- ["docs/new-corpus-reference.md", "NEW-NOTE.md", "priv/new-reference.json"] do
      path = Path.join(root, relative)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, Catalog.reference_digest(1, :hex))
      {output, status} = run(root, "regen_corpus_digests")
      assert status != 0
      assert output =~ "#{relative}: uncatalogued certified digest quotation"
      File.rm!(path)
    end

    assert {_, 0} = run(root, "regen_corpus_digests")
  end

  test "an uncatalogued CLI certification or SDK snapshot fails closed", %{root: root} do
    cli = Path.join(root, Catalog.cli())
    original = File.read!(cli)

    File.write!(
      cli,
      String.replace(
        original,
        "@certified_index_sha256 %{",
        "@certified_index_sha256 %{99 => \"" <> String.duplicate("0", 43) <> "\","
      )
    )

    {output, status} = run(root, "regen_corpus_digests")
    assert status != 0
    assert output =~ "catalog differs from CLI"
    File.write!(cli, original)
    File.mkdir_p!(Path.join(root, "sdks/go/conformance/corpus-unknown"))
    {output, status} = run(root, "check_corpus_sync")
    assert status != 0
    assert output =~ "uncatalogued SDK snapshots"
  end

  test "distribution rejects file drift, omissions, and two missing directories", %{root: root} do
    assert {_, 0} = run(root, "check_corpus_sync")
    base = "sdks/python/conformance/priv/conformance/v1/corpus"

    for {name, relative, mutation, message} <- [
          {"case byte", "#{base}/cases/uri/normalize.json", :change, "content differs"},
          {"raw byte", "#{base}/cases/json/decode-string_bytes-exact.raw", :change,
           "content differs"},
          {"missing file", "#{base}/cases/uri/normalize.json", :remove, "file set mismatch"},
          {"extra file", "#{base}/extra.json", :extra, "file set mismatch"},
          {"SDK manifest byte drift",
           "sdks/python/conformance/priv/conformance/verdict-digests.json", :change,
           "verdict-digests.json: content differs"},
          {"omitted inventory entry", "scripts/check_package.exs", :inventory,
           "check_package corpus inventory differs"}
        ] do
      path = Path.join(root, relative)
      original = if File.exists?(path), do: File.read!(path), else: nil

      case mutation do
        :change ->
          File.write!(path, original <> " ")

        :remove ->
          File.rm!(path)

        :extra ->
          File.write!(path, "{}")

        :inventory ->
          File.write!(
            path,
            String.replace(original, "\"priv/conformance/verdict-digests.json\",", "")
          )
      end

      {output, status} = run(root, "check_corpus_sync")
      assert status != 0, name
      assert output =~ message, output
      IO.puts("RED #{name}: #{message}")
      if original, do: File.write!(path, original), else: File.rm!(path)
      assert {_, 0} = run(root, "check_corpus_sync")
      IO.puts("GREEN #{name}: restored")
    end

    for relative <- ["priv/conformance/v1/corpus", base],
        do: File.rm_rf!(Path.join(root, relative))

    {output, status} = run(root, "check_corpus_sync")
    assert status != 0
    assert output =~ "Hex corpus inventory differs from source tree"
    IO.puts("RED both directories missing: Hex corpus inventory differs from source tree")

    for relative <- ["priv/conformance/v1/corpus", base],
        do: copy(Path.join(Catalog.root(), relative), Path.join(root, relative))

    assert {_, 0} = run(root, "check_corpus_sync")
    IO.puts("GREEN both directories missing: restored")
  end

  defp run(root, script, args \\ []) do
    System.cmd("elixir", ["scripts/#{script}.exs" | args], cd: root, stderr_to_stdout: true)
  end

  defp copy(source, target) do
    File.mkdir_p!(Path.dirname(target))
    File.cp_r!(source, target)
  end
end
