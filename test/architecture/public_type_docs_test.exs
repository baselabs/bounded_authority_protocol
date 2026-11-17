defmodule BoundedAuthorityProtocol.PublicTypeDocsTest do
  use ExUnit.Case, async: true

  test "every public type in a visible module has a typedoc" do
    {:ok, modules} = :application.get_key(:bounded_authority_protocol, :modules)

    missing =
      for module <- modules,
          {:docs_v1, _, _, _, module_doc, _, entries} = Code.fetch_docs(module),
          is_map(module_doc),
          {{kind, name, arity}, _, _, doc, _} <- entries,
          kind in [:type, :opaque],
          not documented?(doc),
          do: {module, name, arity}

    assert missing == [], "Public types missing @typedoc: #{inspect(missing)}"
  end

  test "the coverage predicate rejects absent, hidden, and empty type documentation" do
    refute documented?(:none)
    refute documented?(:hidden)
    refute documented?(%{"en" => "  "})
    assert documented?(%{"en" => "A bounded selector."})
  end

  defp documented?(%{"en" => text}) when is_binary(text), do: String.trim(text) != ""
  defp documented?(_doc), do: false
end
