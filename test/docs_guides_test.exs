defmodule BoundedAuthorityProtocol.GuidesTest do
  # The implementer's guide's dispatch table must match the LIVE corpus surface enumeration
  # (its acceptance criterion). A surface added to the corpus without the guide (or vice
  # versa) reds here with both sides named.

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.{Bounds, Json}

  @guide Path.expand("../docs/guides/implementers-guide.md", __DIR__)
  @index Path.expand("../priv/conformance/v1/corpus/index.json", __DIR__)

  test "the guide's dispatch table matches the corpus surface enumeration" do
    {:ok, tagged} = Json.decode(File.read!(@index), Bounds.maximum())
    members = tagged |> elem(1)
    {"applicability", {:object, leaves}} = List.keyfind(members, "applicability", 0)
    corpus_surfaces = Enum.map(leaves, &elem(&1, 0)) |> MapSet.new()

    guide = File.read!(@guide)

    table =
      guide |> String.split("## 3. The dispatch table") |> Enum.at(1) |> String.split("## 4.")

    guide_surfaces =
      table
      |> hd()
      |> String.split("\n")
      |> Enum.filter(&String.starts_with?(&1, "|"))
      |> Enum.flat_map(&Regex.scan(~r/`([a-z0-9_.]+)`/, &1))
      |> Enum.map(fn [_, name] -> name end)
      |> MapSet.new()

    missing_from_guide = MapSet.difference(corpus_surfaces, guide_surfaces) |> Enum.sort()
    unknown_in_guide = MapSet.difference(guide_surfaces, corpus_surfaces) |> Enum.sort()

    assert missing_from_guide == [],
           "corpus surfaces absent from the guide's table: #{inspect(missing_from_guide)}"

    assert unknown_in_guide == [],
           "guide table names non-surface tokens as surfaces: #{inspect(unknown_in_guide)}"

    assert MapSet.size(corpus_surfaces) == 28
  end
end
