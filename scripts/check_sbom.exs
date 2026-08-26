defmodule BoundedAuthorityProtocol.SbomCheck do
  @moduledoc false

  @name "bounded_authority_protocol"

  def run!([release_path, tooling_path]) do
    release = load_and_check_document!(release_path)
    tooling = load_and_check_document!(tooling_path)

    check_root!(release, release_path)
    check_root!(tooling, tooling_path)
    check_release_closure!(release)
    check_tooling_graph!(tooling)

    IO.puts(
      "CycloneDX SBOM boundary passed; release runtime dependencies=0, " <>
        "tooling components=#{length(Map.get(tooling, "components", []))}"
    )
  end

  def run!(_arguments) do
    IO.puts(
      :stderr,
      "usage: elixir scripts/check_sbom.exs RELEASE_SBOM TOOLING_SBOM"
    )

    System.halt(2)
  end

  defp load_and_check_document!(path) do
    document = path |> File.read!() |> JSON.decode!()

    unless document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6" and
             document["version"] == 1 do
      fail!("#{path} is not a CycloneDX 1.6 version-1 document")
    end

    document
  end

  defp check_root!(document, path) do
    component = get_in(document, ["metadata", "component"]) || %{}
    license_ids = license_ids(component)

    checks = [
      {component["name"] == @name, "name"},
      {component["version"] == mix_exs_version(), "version"},
      {component["type"] == "library", "type"},
      {license_ids == ["Apache-2.0"], "license"},
      {is_binary(component["bom-ref"]), "bom-ref"},
      {is_binary(component["purl"]), "purl"}
    ]

    Enum.each(checks, fn {passed?, field} ->
      unless passed?, do: fail!("#{path} has invalid root #{field}")
    end)
  end

  defp check_release_closure!(document) do
    components = Map.get(document, "components", [])
    root_ref = get_in(document, ["metadata", "component", "bom-ref"])
    dependencies = Map.get(document, "dependencies", [])

    unless components == [] do
      fail!("release SBOM contains external runtime components")
    end

    unless dependencies == [%{"ref" => root_ref, "dependsOn" => []}] or
             dependencies == [%{"ref" => root_ref}] do
      fail!("release SBOM root dependency closure is not empty")
    end
  end

  defp check_tooling_graph!(document) do
    root_ref = get_in(document, ["metadata", "component", "bom-ref"])
    components = Map.get(document, "components", [])
    component_refs = components |> Enum.map(&Map.fetch!(&1, "bom-ref")) |> MapSet.new()

    if MapSet.size(component_refs) != length(components) do
      fail!("tooling SBOM contains duplicate component references")
    end

    dependencies = Map.get(document, "dependencies", [])

    edges =
      Map.new(dependencies, fn dependency ->
        {Map.fetch!(dependency, "ref"), Map.get(dependency, "dependsOn", [])}
      end)

    known_refs = MapSet.put(component_refs, root_ref)

    Enum.each(edges, fn {from, targets} ->
      unless MapSet.member?(known_refs, from) do
        fail!("tooling SBOM dependency source #{from} has no component")
      end

      Enum.each(targets, fn target ->
        unless MapSet.member?(known_refs, target) do
          fail!("tooling SBOM dependency target #{target} has no component")
        end
      end)
    end)

    reachable = reachable_refs(edges, [root_ref], MapSet.new())

    unless reachable == known_refs do
      missing = MapSet.difference(known_refs, reachable) |> Enum.sort()
      fail!("tooling SBOM contains unreachable components #{inspect(missing)}")
    end
  end

  defp reachable_refs(_edges, [], seen), do: seen

  defp reachable_refs(edges, [next | rest], seen) do
    if MapSet.member?(seen, next) do
      reachable_refs(edges, rest, seen)
    else
      reachable_refs(edges, Map.get(edges, next, []) ++ rest, MapSet.put(seen, next))
    end
  end

  defp license_ids(component) do
    component
    |> Map.get("licenses", [])
    |> Enum.flat_map(fn
      %{"license" => %{"id" => identifier}} -> [identifier]
      _other -> []
    end)
  end

  # The package version derived from mix.exs (works under `elixir script` invocation where
  # Mix.Project is not alive — the same derivation the supply-chain workflow uses).
  defp mix_exs_version do
    root = Path.expand("..", __DIR__)

    case File.read(Path.join(root, "mix.exs")) do
      {:ok, source} ->
        case Regex.run(~r/@version\s+"([^"]+)"/, source) do
          [_, version] -> version
          _ -> raise "cannot derive the package version from mix.exs"
        end

      _ ->
        raise "cannot read mix.exs to derive the package version"
    end
  end

  defp fail!(message), do: raise("SBOM check failed: #{message}")
end

BoundedAuthorityProtocol.SbomCheck.run!(System.argv())
