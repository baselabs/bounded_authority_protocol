Code.require_file("../../tools/architecture_gate.exs", __DIR__)

defmodule BoundedAuthorityProtocol.Architecture.StableSurfacePinTest do
  @moduledoc """
  The package 1.x stable surface pinned in the architecture gate matches the compiled package:
  every documented module is listed, every listed module is documented, every stable struct's
  field set equals its pin, and every exclusion names something that exists and is hidden.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ArchitectureGate

  @root BoundedAuthorityProtocol

  defp compiled_modules do
    {:ok, modules} = :application.get_key(:bounded_authority_protocol, :modules)
    modules
  end

  defp documented?(module) do
    case Code.fetch_docs(module) do
      {_docs_chunk, _anno, _language, _format, :hidden, _metadata, _docs} -> false
      {_docs_chunk, _anno, _language, _format, _moduledoc, _metadata, _docs} -> true
    end
  end

  defp name(module), do: module |> Atom.to_string() |> String.replace_prefix("Elixir.", "")

  defp struct_fields(module) do
    Code.ensure_loaded!(module)

    if function_exported?(module, :__struct__, 0),
      do: module.__struct__() |> Map.from_struct() |> Map.keys() |> Enum.sort(),
      else: nil
  end

  # Field-set disagreements between the pins and the compiled structs, by module name.
  defp field_violations(pins, actual) do
    for name <- Enum.sort(Enum.uniq(Map.keys(pins) ++ Map.keys(actual))),
        Map.get(pins, name) != Map.get(actual, name),
        do: name
  end

  defp actual_struct_fields do
    for name <- ArchitectureGate.stable_modules(),
        fields = struct_fields(Module.concat([name])),
        fields != nil,
        into: %{},
        do: {name, fields}
  end

  test "the stable modules are exactly the documented modules" do
    documented =
      for module <- compiled_modules(), module != @root, documented?(module), do: name(module)

    assert Enum.sort(documented) == Enum.sort(ArchitectureGate.stable_modules())
  end

  test "every stable struct's field set equals its pin" do
    assert field_violations(ArchitectureGate.public_struct_fields(), actual_struct_fields()) == []
  end

  test "the field pin goes red when a struct gains, loses or renames a field" do
    actual = actual_struct_fields()
    bounds = "BoundedAuthorityProtocol.V1.Bounds"

    for changed <- [
          [:added_bound | actual[bounds]],
          tl(actual[bounds]),
          [:renamed | tl(actual[bounds])]
        ] do
      assert field_violations(
               ArchitectureGate.public_struct_fields(),
               Map.put(actual, bounds, Enum.sort(changed))
             ) == [bounds]
    end

    assert field_violations(
             Map.delete(ArchitectureGate.public_struct_fields(), bounds),
             actual
           ) == [bounds]
  end

  test "every exclusion names a hidden module or a hidden function of a stable module" do
    for entry <- ArchitectureGate.excluded_surface() do
      case Regex.run(~r{^(.+)\.([^.]+)/(\d+)$}, entry) do
        [_entry, module_name, function, arity] ->
          assert module_name in ArchitectureGate.stable_modules(), entry
          module = Code.ensure_loaded!(Module.concat([module_name]))
          arity = String.to_integer(arity)
          function = String.to_existing_atom(function)
          assert function_exported?(module, function, arity), entry
          {_docs_chunk, _, _, _, _, _, docs} = Code.fetch_docs(module)
          assert [:hidden] == for({{:function, ^function, ^arity}, _, _, doc, _} <- docs, do: doc)

        nil ->
          module = Module.concat([entry])
          assert {:module, ^module} = Code.ensure_loaded(module)
          refute documented?(module), entry
      end
    end
  end

  test "the role-attestation façade exports are pinned like the other sibling façades" do
    assert "Elixir.BoundedAuthorityProtocol.RoleAttestation.V1.beam" in ArchitectureGate.pinned_beams()
  end
end
