Code.require_file("../../tools/architecture_gate.exs", __DIR__)

defmodule BoundedAuthorityProtocol.ApiStabilityPageTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ArchitectureGate

  # The "API stability and versioning" page promises a module list to adopters. The architecture
  # gate pins the same surface in code. A module added to one and not the other reds here.
  @page "docs/guides/api-stability.md"

  test "the page's stable modules are exactly the gate's stable surface" do
    page = section_modules(File.read!(@page), "## Stable surface")
    gate = MapSet.new(ArchitectureGate.stable_modules())

    assert MapSet.difference(gate, page) |> Enum.sort() == [],
           "stable in the gate but missing from #{@page}"

    assert MapSet.difference(page, gate) |> Enum.sort() == [],
           "listed as stable in #{@page} but not pinned by the gate"
  end

  test "every exclusion the gate names is listed as not covered" do
    page = File.read!(@page) |> section("## Not covered")

    missing =
      for name <- ArchitectureGate.excluded_surface(),
          not String.contains?(page, "`#{name}`"),
          do: name

    assert missing == [], "#{@page} does not list these exclusions: #{inspect(missing)}"
  end

  test "every stable module is documented and every exclusion is hidden" do
    undocumented =
      for name <- ArchitectureGate.stable_modules(),
          module = Module.concat([name]),
          not is_map(moduledoc(module)),
          do: name

    assert undocumented == []

    visible =
      for name <- ArchitectureGate.excluded_surface(),
          not String.contains?(name, "/"),
          module = Module.concat([name]),
          Code.ensure_loaded?(module),
          moduledoc(module) != :hidden,
          do: name

    assert visible == []
  end

  test "the section reader is red-capable" do
    markdown = "## Stable surface\n\n- `BoundedAuthorityProtocol.V9`\n\n## Not covered\n\n- `X`\n"

    assert section_modules(markdown, "## Stable surface") ==
             MapSet.new(["BoundedAuthorityProtocol.V9"])
  end

  # The moduledoc entry of the module's docs chunk: a map when documented, :hidden when hidden.
  defp moduledoc(module) do
    case Code.fetch_docs(module) do
      docs when is_tuple(docs) -> elem(docs, 4)
      _missing -> :none
    end
  end

  defp section(markdown, heading) do
    [_before, rest] = String.split(markdown, heading <> "\n", parts: 2)
    rest |> String.split(~r/^## /m, parts: 2) |> hd()
  end

  defp section_modules(markdown, heading) do
    ~r/`(BoundedAuthorityProtocol(?:\.[A-Z][A-Za-z0-9]*)*)`/
    |> Regex.scan(section(markdown, heading), capture: :all_but_first)
    |> List.flatten()
    |> MapSet.new()
  end
end
