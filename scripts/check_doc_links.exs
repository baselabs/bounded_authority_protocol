defmodule BoundedAuthorityProtocol.CheckDocLinks do
  # Link check over the built HexDocs (`mix docs` output in doc/). Every local `href` and `src`
  # in every generated page must resolve: `page.html` to an existing page, `page.html#anchor` or
  # `#anchor` to an element carrying that `id` in the target page, and any other local target
  # (scripts, stylesheets, images, the EPUB) to an existing file. A heading anchor that Markdown
  # renders differently on HexDocs than on GitHub (for example a kramdown `{#id}` attribute,
  # which ExDoc prints literally) fails here.
  #
  # ExDoc references docs_config.js from every page; HexDocs serves it per package (the version
  # selector), so a local build never contains it. It is the only target allowed to be absent.
  #
  # Usage (after `mix docs`):
  #   mix run --no-start scripts/check_doc_links.exs            # checks doc/
  #   mix run --no-start scripts/check_doc_links.exs DIR        # checks DIR
  #
  # Before checking, the script proves itself red-capable on a planted page with one dangling
  # anchor, one missing page and one missing script; if any goes unreported, the gate fails.

  @hosted_by_hexdocs ["docs_config.js"]

  def run(argv) do
    self_test!()

    dir =
      case argv do
        [] -> "doc"
        [dir] -> dir
      end

    case check(dir) do
      {0, _links, []} ->
        IO.puts(:stderr, "doc links: no HTML pages under #{dir}; run mix docs first")
        System.halt(1)

      {pages, links, []} ->
        IO.puts("doc links: ok pages=#{pages} local_links=#{links}")

      {_pages, _links, problems} ->
        Enum.each(problems, &IO.puts(:stderr, "doc links: #{&1}"))
        IO.puts(:stderr, "doc links: #{length(problems)} unresolved local link(s)")
        System.halt(1)
    end
  end

  def check(dir) do
    pages =
      dir
      |> Path.join("*.html")
      |> Path.wildcard()
      |> Map.new(fn path -> {Path.basename(path), File.read!(path)} end)

    ids = Map.new(pages, fn {name, html} -> {name, ids(html)} end)

    {links, problems} =
      pages
      |> Enum.sort()
      |> Enum.flat_map(fn {name, html} -> Enum.map(links(html), &{name, &1}) end)
      |> Enum.reduce({0, []}, fn {name, link}, acc -> tally(acc, dir, name, link, ids) end)

    {map_size(pages), links, problems |> Enum.uniq() |> Enum.sort()}
  end

  defp links(html) do
    ~r/\s(?:href|src)="([^"]*)"/
    |> Regex.scan(html, capture: :all_but_first)
    |> List.flatten()
  end

  defp ids(html) do
    ~r/\s(?:id|name)="([^"]+)"/
    |> Regex.scan(html, capture: :all_but_first)
    |> List.flatten()
    |> MapSet.new()
  end

  defp tally({count, problems}, dir, name, link, ids) do
    case resolve(dir, name, link, ids) do
      :skip -> {count, problems}
      :ok -> {count + 1, problems}
      {:error, reason} -> {count + 1, ["#{name}: #{link} (#{reason})" | problems]}
    end
  end

  defp resolve(dir, page, link, ids) do
    uri = URI.parse(link)

    cond do
      link == "" or uri.scheme != nil or uri.host != nil ->
        :skip

      uri.path in [nil, ""] ->
        anchor(page, uri.fragment || "", ids)

      uri.path in @hosted_by_hexdocs and uri.fragment == nil ->
        :skip

      String.ends_with?(uri.path, ".html") ->
        resolve_page(URI.decode(uri.path), uri.fragment, ids)

      File.regular?(Path.join(dir, URI.decode(uri.path))) ->
        :ok

      true ->
        {:error, "missing file"}
    end
  end

  defp resolve_page(target, fragment, ids) do
    cond do
      not Map.has_key?(ids, target) -> {:error, "missing page"}
      fragment in [nil, ""] -> :ok
      true -> anchor(target, fragment, ids)
    end
  end

  defp anchor(page, fragment, ids) do
    fragment = URI.decode(fragment)

    if fragment == "" or fragment == "content" or MapSet.member?(Map.fetch!(ids, page), fragment),
      do: :ok,
      else: {:error, "missing anchor"}
  end

  defp self_test! do
    dir =
      Path.join(System.tmp_dir!(), "bap-doc-links-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)

    File.write!(Path.join(dir, "a.html"), """
    <h2 id="present">x</h2>
    <a href="#present">ok</a> <a href="b.html#here">ok</a>
    <a href="b.html#absent">dangling anchor</a> <a href="gone.html">missing page</a>
    <link rel="stylesheet" href="dist/present.css"> <img src="https://example.com/x.png">
    <script src="docs_config.js"></script> <script src="dist/missing.js"></script>
    """)

    File.write!(Path.join(dir, "b.html"), ~s(<a id="here"></a>))
    File.mkdir_p!(Path.join(dir, "dist"))
    File.write!(Path.join(dir, "dist/present.css"), "")
    {2, 6, problems} = check(dir)
    File.rm_rf!(dir)

    unless problems == [
             "a.html: b.html#absent (missing anchor)",
             "a.html: dist/missing.js (missing file)",
             "a.html: gone.html (missing page)"
           ] do
      IO.puts(
        :stderr,
        "doc links: self-test did not report the planted defects: #{inspect(problems)}"
      )

      System.halt(1)
    end
  end
end

BoundedAuthorityProtocol.CheckDocLinks.run(System.argv())
