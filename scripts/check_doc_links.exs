defmodule BoundedAuthorityProtocol.CheckDocLinks do
  # Link check over the built HexDocs (`mix docs` output in doc/). Every local link in every
  # generated page must resolve: `href="page.html"` to an existing page, and
  # `href="page.html#anchor"` or `href="#anchor"` to an element carrying that `id` in the target
  # page. A heading anchor that Markdown renders differently on HexDocs than on GitHub (for
  # example a kramdown `{#id}` attribute, which ExDoc prints literally) fails here.
  #
  # Usage (after `mix docs`):
  #   mix run --no-start scripts/check_doc_links.exs            # checks doc/
  #   mix run --no-start scripts/check_doc_links.exs DIR        # checks DIR
  #
  # Before checking, the script proves itself red-capable on a planted page with one dangling
  # anchor and one missing page; if either goes unreported, the gate fails.

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
      Enum.reduce(Enum.sort(pages), {0, []}, fn {name, html}, acc ->
        html
        |> hrefs()
        |> Enum.reduce(acc, fn href, {count, problems} ->
          case resolve(name, href, ids) do
            :skip -> {count, problems}
            :ok -> {count + 1, problems}
            {:error, reason} -> {count + 1, ["#{name}: #{href} (#{reason})" | problems]}
          end
        end)
      end)

    {map_size(pages), links, problems |> Enum.uniq() |> Enum.sort()}
  end

  defp hrefs(html) do
    ~r/\shref="([^"]*)"/
    |> Regex.scan(html, capture: :all_but_first)
    |> List.flatten()
  end

  defp ids(html) do
    ~r/\s(?:id|name)="([^"]+)"/
    |> Regex.scan(html, capture: :all_but_first)
    |> List.flatten()
    |> MapSet.new()
  end

  defp resolve(page, href, ids) do
    cond do
      href == "" or String.starts_with?(href, ["http://", "https://", "mailto:", "//"]) ->
        :skip

      String.starts_with?(href, "#") ->
        anchor(page, String.trim_leading(href, "#"), ids)

      true ->
        [target | fragment] = String.split(href, "#", parts: 2)

        cond do
          not String.ends_with?(target, ".html") ->
            :skip

          not Map.has_key?(ids, target) ->
            {:error, "missing page"}

          fragment == [] or fragment == [""] ->
            :ok

          true ->
            anchor(target, hd(fragment), ids)
        end
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
    """)

    File.write!(Path.join(dir, "b.html"), ~s(<a id="here"></a>))
    {2, 4, problems} = check(dir)
    File.rm_rf!(dir)

    unless problems == [
             "a.html: b.html#absent (missing anchor)",
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
