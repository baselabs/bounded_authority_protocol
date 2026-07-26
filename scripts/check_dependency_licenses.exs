defmodule BoundedAuthorityProtocol.DependencyLicenseCheck do
  @moduledoc false

  @root Path.expand("..", __DIR__)
  @direct_tools MapSet.new(~w(credo dialyxir ex_doc mix_audit sbom))

  def run!([sbom_path]) do
    allowed = load_allowed_licenses!()
    overrides = load_overrides!()
    document = sbom_path |> File.read!() |> JSON.decode!()
    components = Map.get(document, "components", [])

    names = components |> Enum.map(&Map.fetch!(&1, "name")) |> MapSet.new()
    missing_tools = MapSet.difference(@direct_tools, names)

    unless MapSet.size(missing_tools) == 0 do
      fail!("tooling SBOM is missing direct tools #{inspect(Enum.sort(missing_tools))}")
    end

    Enum.each(components, &check_component!(&1, allowed, overrides))

    unused_overrides = Map.keys(overrides) -- Enum.to_list(names)

    unless unused_overrides == [] do
      fail!("unused dependency license overrides #{inspect(Enum.sort(unused_overrides))}")
    end

    IO.puts("dependency license boundary passed for #{length(components)} components")
  end

  def run!(_arguments) do
    IO.puts(:stderr, "usage: elixir scripts/check_dependency_licenses.exs TOOLING_SBOM")
    System.halt(2)
  end

  defp check_component!(component, allowed, overrides) do
    name = Map.fetch!(component, "name")
    licenses = declared_licenses(component)

    if licenses == [] do
      fail!("#{name} has no declared license")
    end

    normalized =
      Enum.map(licenses, fn declared ->
        case Map.fetch(overrides, name) do
          {:ok, override} ->
            unless declared == override.declared do
              fail!(
                "#{name} override expected #{inspect(override.declared)}, " <>
                  "got #{inspect(declared)}"
              )
            end

            verify_override_hash!(name, override)
            override.normalized

          :error ->
            declared
        end
      end)

    rejected = Enum.reject(normalized, &MapSet.member?(allowed, &1))

    unless rejected == [] do
      fail!("#{name} has unapproved licenses #{inspect(rejected)}")
    end
  end

  defp declared_licenses(component) do
    component
    |> Map.get("licenses", [])
    |> Enum.flat_map(fn
      %{"license" => %{"id" => identifier}} when is_binary(identifier) ->
        [identifier]

      %{"expression" => expression} when is_binary(expression) ->
        Regex.scan(~r/[A-Za-z0-9][A-Za-z0-9.+-]*/, expression)
        |> List.flatten()
        |> Enum.reject(&(&1 in ["AND", "OR", "WITH"]))

      _other ->
        []
    end)
  end

  defp verify_override_hash!(name, override) do
    path = Path.join([@root, "deps", name, "LICENSE"])

    actual =
      path
      |> File.read!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    unless actual == override.sha256 do
      fail!("#{name} license file hash changed; expected #{override.sha256}, got #{actual}")
    end
  end

  defp load_allowed_licenses! do
    @root
    |> Path.join("compliance/allowed-spdx-licenses.txt")
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> MapSet.new()
  end

  defp load_overrides! do
    @root
    |> Path.join("compliance/dependency-license-overrides.tsv")
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.map(fn line ->
      case String.split(line, "\t") do
        [name, declared, normalized, sha256] ->
          {name, %{declared: declared, normalized: normalized, sha256: sha256}}

        _other ->
          fail!("invalid dependency license override row #{inspect(line)}")
      end
    end)
    |> Map.new()
  end

  defp fail!(message), do: raise("dependency license check failed: #{message}")
end

BoundedAuthorityProtocol.DependencyLicenseCheck.run!(System.argv())
