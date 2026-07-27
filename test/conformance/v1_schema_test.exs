defmodule BoundedAuthorityProtocol.Conformance.V1SchemaTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Json

  @schemas Path.expand("../../priv/conformance/v1/schemas", __DIR__)

  test "tracked v1 schemas are complete JSON values under the normative decoder" do
    for name <- ["grant-header.schema.json", "json-value.schema.json"] do
      bytes = File.read!(Path.join(@schemas, name))
      assert {:ok, {:object, _members}} = Json.decode(bytes)
    end
  end

  test "the JSON schema has one non-overlapping numeric branch with exact profile bounds" do
    bytes = File.read!(Path.join(@schemas, "json-value.schema.json"))
    assert {:ok, {:object, root}} = Json.decode(bytes)
    assert {:array, branches} = member!(root, "oneOf")

    numeric =
      Enum.filter(branches, fn
        {:object, members} -> member(members, "type") == {:string, "number"}
        _other -> false
      end)

    assert [
             {:object,
              [
                {"type", {:string, "number"}},
                {"minimum", {:integer, -9_007_199_254_740_991}},
                {"maximum", {:integer, 9_007_199_254_740_991}}
              ]}
           ] = numeric

    assert schema_accepts?(branches, 1)
    assert schema_accepts?(branches, 9_007_199_254_740_991)
    assert schema_accepts?(branches, -9_007_199_254_740_991)
    refute schema_accepts?(branches, 9_007_199_254_740_992)
    refute schema_accepts?(branches, -9_007_199_254_740_992)
  end

  defp schema_accepts?(branches, value) do
    Enum.count(branches, &branch_accepts?(&1, value)) == 1
  end

  defp branch_accepts?({:object, members}, value) when is_integer(value) or is_float(value) do
    case member(members, "type") do
      {:string, "number"} ->
        {:integer, minimum} = member!(members, "minimum")
        {:integer, maximum} = member!(members, "maximum")
        value >= minimum and value <= maximum

      {:string, "integer"} ->
        is_integer(value)

      _other ->
        false
    end
  end

  defp branch_accepts?(_branch, _value), do: false

  defp member!(members, name) do
    case member(members, name) do
      nil -> flunk("missing schema member #{name}")
      value -> value
    end
  end

  defp member(members, name) do
    case List.keyfind(members, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end
end
