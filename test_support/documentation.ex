defmodule BoundedAuthorityProtocol.Documentation do
  @moduledoc false

  # Use the same CommonMark parser as ExDoc. Indented and nested code, longer backtick
  # fences, and tilde fences cannot escape sample discovery.
  def blocks(markdown) do
    {_status, ast, _messages} = EarmarkParser.as_ast(markdown)
    collect(ast)
  end

  def examples(markdown, language \\ "elixir") do
    blocks = for {^language, code} <- blocks(markdown), do: code

    {following, _remaining} =
      Enum.map_reduce(blocks, markdown, fn code, remaining ->
        [_before, after_code] = String.split(remaining, String.trim_trailing(code), parts: 2)
        {after_code, after_code}
      end)

    prose =
      Enum.with_index(following)
      |> Enum.map(fn {after_code, index} ->
        case Enum.at(blocks, index + 1) do
          nil -> after_code
          next -> after_code |> String.split(String.trim_trailing(next), parts: 2) |> hd()
        end
      end)

    Enum.zip(blocks, prose)
  end

  defp collect(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &collect/1)

  defp collect({"pre", _, [{"code", attributes, children, _}], _}) do
    language =
      attributes
      |> List.keyfind("class", 0, {"class", ""})
      |> elem(1)
      |> String.replace_prefix("language-", "")
      |> String.split()
      |> List.first("")

    [{language, IO.iodata_to_binary(children)}]
  end

  defp collect({_tag, _attributes, children, _metadata}), do: collect(children)
  defp collect(_text), do: []
end
