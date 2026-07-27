defmodule BoundedAuthorityProtocol.Conformance.V1SchemaTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Json
  alias JSONSchex.Draft202012.Schemas, as: Draft202012Schemas

  @schemas Path.expand("../../priv/conformance/v1/schemas", __DIR__)

  test "tracked v1 schemas are complete JSON values under the normative decoder" do
    for name <- ["grant-header.schema.json", "json-value.schema.json"] do
      bytes = File.read!(Path.join(@schemas, name))
      assert {:ok, {:object, _members}} = Json.decode(bytes)
    end
  end

  test "a Draft 2020-12 validator accepts both schemas against the canonical meta-schema" do
    {:ok, meta_schema} =
      Draft202012Schemas.fetch("https://json-schema.org/draft/2020-12/schema")

    {:ok, compiled_meta_schema} = JSONSchex.compile(meta_schema)

    for name <- ["grant-header.schema.json", "json-value.schema.json"] do
      schema = schema!(name)
      assert :ok = JSONSchex.validate(compiled_meta_schema, schema)
      assert {:ok, _compiled_schema} = JSONSchex.compile(schema)
    end

    malformed = schema!("json-value.schema.json") |> Map.put("type", "not-a-schema-type")
    assert {:error, _errors} = JSONSchex.validate(compiled_meta_schema, malformed)
  end

  test "the grant-header schema enforces its complete closed instance contract" do
    {:ok, schema} = JSONSchex.compile(schema!("grant-header.schema.json"))
    valid = %{"alg" => "EdDSA", "typ" => "ba+cap", "kid" => "A._~-9"}

    assert :ok = JSONSchex.validate(schema, valid)

    for invalid <- [
          Map.delete(valid, "kid"),
          Map.put(valid, "extra", true),
          Map.put(valid, "alg", "HS256"),
          Map.put(valid, "typ", "JWT"),
          Map.put(valid, "kid", ""),
          Map.put(valid, "kid", "a/b"),
          Map.put(valid, "kid", String.duplicate("a", 129))
        ] do
      assert {:error, _errors} = JSONSchex.validate(schema, invalid)
    end
  end

  test "the JSON-value schema enforces structural and numeric boundaries" do
    {:ok, schema} = JSONSchex.compile(schema!("json-value.schema.json"))

    for valid <- [
          nil,
          true,
          1,
          9_007_199_254_740_991,
          -9_007_199_254_740_991,
          "value",
          [1, %{"nested" => false}],
          %{"value" => [1, 2]}
        ] do
      assert :ok = JSONSchex.validate(schema, valid)
    end

    for invalid <- [
          9_007_199_254_740_992,
          -9_007_199_254_740_992,
          List.duplicate(nil, 257),
          Map.new(1..65, &{Integer.to_string(&1), nil}),
          %{String.duplicate("a", 129) => nil}
        ] do
      assert {:error, _errors} = JSONSchex.validate(schema, invalid)
    end
  end

  test "the structural schema is paired with normative UTF-8 byte enforcement" do
    json_schema = schema!("json-value.schema.json")
    grant_schema = schema!("grant-header.schema.json")
    {:ok, schema} = JSONSchex.compile(json_schema)
    multibyte = String.duplicate("é", 8_192)
    multibyte_key = String.duplicate("é", 128)

    assert %{"x-bap-maximum-utf8-bytes" => 8_192} =
             Enum.find(json_schema["oneOf"], &(&1["type"] == "string"))

    assert %{
             "propertyNames" => %{
               "maxLength" => 128,
               "x-bap-maximum-utf8-bytes" => 128
             }
           } = Enum.find(json_schema["oneOf"], &(&1["type"] == "object"))

    assert grant_schema["properties"]["kid"]["x-bap-maximum-utf8-bytes"] == 128
    assert :ok = JSONSchex.validate(schema, multibyte)
    assert {:error, :invalid} = Json.decode(:json.encode(multibyte))
    assert :ok = JSONSchex.validate(schema, %{multibyte_key => nil})
    assert {:error, :invalid} = Json.decode(:json.encode(%{multibyte_key => nil}))
  end

  defp schema!(name) do
    @schemas
    |> Path.join(name)
    |> File.read!()
    |> :json.decode()
  end
end
