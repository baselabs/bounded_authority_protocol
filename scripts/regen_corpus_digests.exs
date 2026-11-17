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
      replacements =
        Enum.flat_map(entries, fn entry ->
          old = Base.url_decode64!(entry.certified, padding: false)
          new = Catalog.digests(entry)
          [{entry.certified, new.base64url}, {Base.encode16(old, case: :lower), new.hex}]
        end)

      # Rotate test mirrors, preservation pins and independent runners with the certified pin,
      # as well as all SDK runners. Exact literal replacement never alters corpus JSON bytes.
      sources =
        for root <- ["lib", "test", "sdks", "conformance"],
            path <- Path.wildcard(Path.join([Catalog.root(), root, "**/*"])),
            Path.extname(path) in [".ex", ".exs", ".rs", ".go", ".py", ".mjs"],
            not String.contains?(path, ["/.venv/", "/target/"]) do
          path
        end

      Enum.each(sources, fn path ->
        original = File.read!(path)

        rewritten =
          Enum.reduce(replacements, original, fn {old, new}, text ->
            String.replace(text, old, new)
          end)

        if rewritten != original, do: File.write!(path, rewritten)
      end)

      # A stale runner pin can predate the CLI pin. Its checked declaration anchor still rotates.
      Enum.each(pins, fn {path, regex, old, expected} ->
        contents = File.read!(path)
        [declaration] = Regex.run(regex, contents, capture: :first)
        replacement = String.replace(declaration, old, expected)
        File.write!(path, String.replace(contents, declaration, replacement, global: false))
      end)
    end

    problems =
      entries
      |> Enum.flat_map(&pins/1)
      |> Enum.flat_map(fn {path, _regex, actual, expected} ->
        if actual == expected,
          do: [],
          else: [
            "#{Path.relative_to(path, Catalog.root())}: corpus digest drift (#{actual} != #{expected})"
          ]
      end)

    if problems != [], do: raise("corpus digest pin check FAILED:\n" <> Enum.join(problems, "\n"))
    IO.puts("corpus digests: ok corpora=#{length(entries)} pins=#{length(pins)}")
  end

  def run(_),
    do: raise("usage: mix corpus.digests | elixir scripts/regen_corpus_digests.exs --write")

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
