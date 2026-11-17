Code.require_file("corpus_catalog.exs", __DIR__)

defmodule BoundedAuthorityProtocol.RegenCorpusDigests do
  @moduledoc false
  alias BoundedAuthorityProtocol.CorpusCatalog, as: Catalog

  def run(argv) when argv in [[], ["--write"]] do
    entries = Catalog.entries()
    # All metadata and anchors are checked before a write. A deleted/renamed/ambiguous runner
    # pin must fail loudly, including sibling profiles and the strict-Ed25519 corpus.
    pins = Enum.flat_map(entries, &pins/1)

    if argv == ["--write"] do
      # Only declarations owned by this tool rotate. Independent evidence and prose
      # are checked below and require an explicit, separately reviewed edit.
      # A stale runner pin can predate the CLI pin. Its checked declaration anchor still rotates.
      Enum.each(pins, fn {path, regex, old, expected} ->
        contents = File.read!(path)
        [declaration] = Regex.run(regex, contents, capture: :first)
        replacement = String.replace(declaration, old, expected)
        File.write!(path, String.replace(contents, declaration, replacement, global: false))
      end)
    end

    automatic_problems =
      entries
      |> Enum.flat_map(&pins/1)
      |> Enum.flat_map(fn {path, _regex, actual, expected} ->
        if actual == expected,
          do: [],
          else: [
            "#{Path.relative_to(path, Catalog.root())}: corpus digest drift (#{actual} != #{expected})"
          ]
      end)

    preservation_problems = reference_problems(Catalog.preservation(), "hand-kept preservation")
    prose_problems = reference_problems(Catalog.prose(), "prose")

    problems =
      automatic_problems ++ preservation_problems ++ prose_problems ++ uncatalogued(entries)

    IO.puts(
      "corpus digest classes: automatic=#{length(pins)} hand-kept preservation=#{count(Catalog.preservation())} prose=#{count(Catalog.prose())}"
    )

    if problems != [], do: raise("corpus digest pin check FAILED:\n" <> Enum.join(problems, "\n"))
    IO.puts("corpus digests: ok corpora=#{length(entries)} pins=#{length(pins)}")
  end

  def run(_),
    do: raise("usage: mix corpus.digests | elixir scripts/regen_corpus_digests.exs --write")

  defp count(references) do
    for({_path, pins} <- references, {_key, _encoding, count} <- pins, do: count)
    |> Enum.sum()
  end

  defp reference_problems(references, class) do
    for {relative, pins} <- references,
        contents = File.read!(Path.join(Catalog.root(), relative)),
        {key, encoding, count} <- pins,
        expected = Catalog.reference_digest(key, encoding),
        actual = length(:binary.matches(contents, expected)),
        actual != count do
      "#{relative}: #{class} corpus digest drift for #{inspect(key)} (expected #{count} matching quotations, found #{actual}); edit by hand"
    end
  end

  # Discover new quotations throughout the public source tree. Existing references have
  # exact per-file counts above, so a changed, removed, or duplicated quotation also fails.
  defp uncatalogued(entries) do
    references = Catalog.preservation() ++ Catalog.prose()
    automatic = Enum.flat_map(entries, &pins/1)

    classified =
      Enum.map(automatic, fn {path, _regex, actual, _expected} ->
        {Path.relative_to(path, Catalog.root()), actual, 1}
      end) ++
        for {path, pins} <- references, {key, encoding, count} <- pins do
          {path, Catalog.reference_digest(key, encoding), count}
        end

    expected =
      Enum.reduce(classified, %{}, fn {path, digest, count}, acc ->
        Map.update(acc, {path, digest}, count, &(&1 + count))
      end)

    known =
      for(entry <- entries, value <- Map.values(Catalog.digests(entry)), do: value) ++
        Enum.map(entries, & &1.certified) ++ Enum.map(classified, &elem(&1, 1))

    known = Enum.uniq(known)

    for relative <- source_tree(),
        contents = File.read!(Path.join(Catalog.root(), relative)),
        digest <- known,
        actual = length(:binary.matches(contents, digest)),
        actual > Map.get(expected, {relative, digest}, 0) do
      "#{relative}: uncatalogued certified digest quotation; classify as automatic, hand-kept preservation, or prose"
    end
  end

  # The public source tree: every file git tracks or would track (untracked but not ignored),
  # at any depth and of any type, so a new quotation is found before it is staged.
  defp source_tree do
    {output, 0} =
      System.cmd("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cd: Catalog.root()
      )

    output
    |> String.split(<<0>>, trim: true)
    |> Enum.filter(&File.regular?(Path.join(Catalog.root(), &1)))
  end

  defp pins(entry) do
    digests = Catalog.digests(entry)
    prefix = if is_atom(entry.key), do: ":#{entry.key}", else: Integer.to_string(entry.key)
    cli_regex = Regex.compile!("(?m)^\\s*" <> Regex.escape(prefix) <> " => \\\"([^\\\"]*)\\\"")
    cli_pin = pin(Path.join(Catalog.root(), Catalog.cli()), cli_regex, digests, :base64url)

    mirrors =
      if is_integer(entry.key) do
        [
          pin(
            Path.join(Catalog.root(), "test/conformance/cli_test.exs"),
            cli_regex,
            digests,
            :base64url
          )
        ]
      else
        []
      end

    [cli_pin | mirrors ++ Enum.map(entry.runners, &pin(&1, Catalog.runner_pin(), digests, :auto))]
  end

  defp pin(path, regex, digests, encoding) do
    case Regex.scan(regex, File.read!(path), capture: :all_but_first) do
      [[value]] ->
        encoding =
          if encoding == :auto,
            do: if(byte_size(value) == 64, do: :hex, else: :base64url),
            else: encoding

        shape = if encoding == :hex, do: ~r/\A[0-9a-f]{64}\z/, else: ~r/\A[A-Za-z0-9_-]{43}\z/
        unless Regex.match?(shape, value), do: raise("malformed corpus digest in #{path}")
        {path, regex, value, Map.fetch!(digests, encoding)}

      matches ->
        raise "expected one corpus pin in #{path}, found #{length(matches)}"
    end
  end
end

BoundedAuthorityProtocol.RegenCorpusDigests.run(System.argv())
