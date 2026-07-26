defmodule BoundedAuthorityProtocol.ReleaseSbomPruner do
  @moduledoc false

  def run!([path]) do
    document = path |> File.read!() |> JSON.decode!()
    root_ref = get_in(document, ["metadata", "component", "bom-ref"])

    unless is_binary(root_ref) do
      fail!("release SBOM has no root component reference")
    end

    edges =
      document
      |> Map.get("dependencies", [])
      |> Map.new(fn dependency ->
        {Map.fetch!(dependency, "ref"), Map.get(dependency, "dependsOn", [])}
      end)

    unless Map.has_key?(edges, root_ref) do
      fail!("release SBOM has no root dependency graph entry")
    end

    reachable = reachable_refs(edges, [root_ref], MapSet.new())

    components =
      document
      |> Map.get("components", [])
      |> Enum.filter(&(Map.get(&1, "bom-ref") in reachable))

    dependencies =
      document
      |> Map.get("dependencies", [])
      |> Enum.filter(&(Map.get(&1, "ref") in reachable))
      |> Enum.map(fn dependency ->
        Map.update(dependency, "dependsOn", [], &Enum.filter(&1, fn ref -> ref in reachable end))
      end)

    pruned =
      document
      |> Map.put("components", components)
      |> Map.put("dependencies", dependencies)

    File.write!(path, JSON.encode!(pruned))
    IO.puts("pruned release SBOM to the production dependency closure")
  end

  def run!(_arguments) do
    IO.puts(:stderr, "usage: elixir scripts/prune_release_sbom.exs PATH")
    System.halt(2)
  end

  defp reachable_refs(_edges, [], seen), do: seen

  defp reachable_refs(edges, [next | rest], seen) do
    if MapSet.member?(seen, next) do
      reachable_refs(edges, rest, seen)
    else
      reachable_refs(edges, Map.get(edges, next, []) ++ rest, MapSet.put(seen, next))
    end
  end

  defp fail!(message), do: raise("release SBOM pruning failed: #{message}")
end

BoundedAuthorityProtocol.ReleaseSbomPruner.run!(System.argv())
