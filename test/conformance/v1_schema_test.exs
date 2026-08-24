defmodule BoundedAuthorityProtocol.Conformance.V1SchemaTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Json
  alias JSONSchex.Draft202012.Schemas, as: Draft202012Schemas

  @schemas Path.expand("../../priv/conformance/v1/schemas", __DIR__)
  @fixture_path Path.expand(
                  "../../priv/conformance/v1/vectors/grant-holder-proof.json",
                  __DIR__
                )
  @schema_names [
    "anchored-export-header.schema.json",
    "boundary-anchor-header.schema.json",
    "boundary-anchor-payload.schema.json",
    "conformance-case.schema.json",
    "consumption-row.schema.json",
    "corpus-index.schema.json",
    "grant-header.schema.json",
    "grant-payload.schema.json",
    "json-value.schema.json",
    "key-transition-payload.schema.json",
    "proof-header.schema.json",
    "proof-payload.schema.json",
    "public-okp-jwk.schema.json",
    "selector.schema.json"
  ]

  test "every tracked v1 schema is one complete value under the normative byte decoder" do
    for name <- @schema_names do
      bytes = File.read!(Path.join(@schemas, name))
      assert {:ok, {:object, _members}} = Json.decode(bytes)
    end
  end

  test "canonical Draft 2020-12 meta-schema accepts and compiles every tracked schema" do
    {:ok, meta_schema} =
      Draft202012Schemas.fetch("https://json-schema.org/draft/2020-12/schema")

    {:ok, compiled_meta_schema} = JSONSchex.compile(meta_schema)

    for name <- @schema_names do
      schema = schema!(name)
      assert :ok = JSONSchex.validate(compiled_meta_schema, schema)
      assert {:ok, _compiled_schema} = JSONSchex.compile(schema)
    end

    malformed = schema!("json-value.schema.json") |> Map.put("type", "not-a-schema-type")
    assert {:error, _errors} = JSONSchex.validate(compiled_meta_schema, malformed)
  end

  test "grant protected header is exact and closed" do
    schema = compiled!("grant-header.schema.json")
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

  test "public JWK and proof protected header reject every private or alternate member" do
    fixture = fixture!()
    jwk = fixture["public_keys"]["holder"]["jwk"]
    header = fixture["proof"]["header"]
    jwk_schema = compiled!("public-okp-jwk.schema.json")
    header_schema = compiled!("proof-header.schema.json")

    assert :ok = JSONSchex.validate(jwk_schema, jwk)
    assert :ok = JSONSchex.validate(header_schema, header)

    for invalid <- [
          Map.put(jwk, "d", "private"),
          Map.put(jwk, "kid", "hint"),
          Map.put(jwk, "crv", "X25519"),
          Map.put(jwk, "kty", "EC"),
          Map.put(jwk, "x", String.replace_suffix(jwk["x"], "w", "x"))
        ] do
      assert {:error, _errors} = JSONSchex.validate(jwk_schema, invalid)
    end

    for invalid <- [
          Map.put(header, "d", "private"),
          Map.put(header, "crit", ["jwk"]),
          Map.put(header, "alg", "none"),
          Map.put(header, "typ", "JWT"),
          put_in(header, ["jwk", "d"], "private")
        ] do
      assert {:error, _errors} = JSONSchex.validate(header_schema, invalid)
    end
  end

  test "grant and proof payload schemas are exact closed structural contracts" do
    fixture = fixture!()
    grant = fixture["grant"]["payload"]
    proof = fixture["proof"]["payload"]
    grant_schema = compiled!("grant-payload.schema.json")
    proof_schema = compiled!("proof-payload.schema.json")

    assert :ok = JSONSchex.validate(grant_schema, grant)
    assert :ok = JSONSchex.validate(proof_schema, proof)
    assert :ok = JSONSchex.validate(proof_schema, Map.put(proof, "htm", "report-v2"))

    for invalid <- [
          Map.delete(grant, "cnf"),
          Map.put(grant, "v", 2),
          Map.put(grant, "extra", true),
          Map.put(grant, "aud", []),
          Map.put(grant, "aud", ["same", "same"]),
          put_in(grant, ["operations"], []),
          put_in(grant, ["cnf", "jkt"], "not-a-digest")
        ] do
      assert {:error, _errors} = JSONSchex.validate(grant_schema, invalid)
    end

    for invalid <- [
          Map.delete(proof, "ath"),
          Map.put(proof, "v", 2),
          Map.put(proof, "extra", true),
          Map.put(proof, "htm", "POST /"),
          Map.put(proof, "htu", "http://api.example.test/invoke"),
          Map.put(proof, "ba_inv", String.upcase(proof["ba_inv"])),
          Map.put(proof, "ath", "not-a-digest"),
          Map.put(proof, "nonce", "")
        ] do
      assert {:error, _errors} = JSONSchex.validate(proof_schema, invalid)
    end
  end

  test "selector schemas preserve the three recognized member sets and structural maxima" do
    schema = compiled!("selector.schema.json")
    grant_schema = compiled!("grant-payload.schema.json")
    grant = fixture!()["grant"]["payload"]
    [operation | remaining_operations] = grant["operations"]

    valid = [
      %{"kind" => "all"},
      %{"kind" => "all", "path" => false, "value" => nil},
      %{"kind" => "all", "path" => 7, "values" => "inert"},
      %{"kind" => "equals", "path" => ["record", "region"], "value" => "us-east"},
      %{"kind" => "one_of", "path" => ["tier"], "values" => ["gold", "platinum"]}
    ]

    for selector <- valid do
      assert :ok = JSONSchex.validate(schema, selector)

      grant_with_selector =
        Map.put(grant, "operations", [
          Map.put(operation, "selectors", [selector]) | remaining_operations
        ])

      assert :ok = JSONSchex.validate(grant_schema, grant_with_selector)
    end

    for invalid <- [
          %{"kind" => "all", "path" => []},
          %{"kind" => "all", "value" => nil},
          %{"kind" => "all", "values" => []},
          %{"kind" => "all", "path" => [], "value" => nil, "values" => []},
          %{"kind" => "all", "extra" => nil},
          %{"kind" => "equals", "path" => [], "value" => nil},
          %{"kind" => "one_of", "path" => ["tier"], "values" => []},
          %{"kind" => "unknown"},
          %{
            "kind" => "equals",
            "path" => List.duplicate("x", 33),
            "value" => nil
          },
          %{
            "kind" => "one_of",
            "path" => ["x"],
            "values" => List.duplicate(nil, 257)
          }
        ] do
      assert {:error, _errors} = JSONSchex.validate(schema, invalid)

      grant_with_selector =
        Map.put(grant, "operations", [
          Map.put(operation, "selectors", [invalid]) | remaining_operations
        ])

      assert {:error, _errors} = JSONSchex.validate(grant_schema, grant_with_selector)
    end
  end

  test "chain, anchor, transition, and archive schemas are closed exact structures" do
    digest = String.duplicate("A", 43)

    row = %{
      "v" => 1,
      "chain_id" => "urn:example:chain",
      "sequence" => 1,
      "previous" => digest,
      "commitment" => digest
    }

    anchor_header = %{"alg" => "EdDSA", "typ" => "ba+chain-anchor", "kid" => "archive-key-a"}

    anchor_payload = %{
      "v" => 1,
      "anchor_id" => "urn:example:anchor:start",
      "anchored_at" => 1_999,
      "chain_id" => "urn:example:chain",
      "sequence" => 0,
      "chain_hash" => digest,
      "key_fingerprint" => digest
    }

    transition = %{
      "v" => 1,
      "transition_id" => "urn:example:transition:a-b",
      "chain_id" => "urn:example:chain",
      "effective_at" => 2_000,
      "from_key_fingerprint" => digest,
      "to_key_id" => "archive-key-b",
      "to_key_fingerprint" => digest
    }

    archive_header = %{
      "v" => 1,
      "chain_id" => "urn:example:chain",
      "first_sequence" => 1,
      "last_sequence" => 1,
      "row_count" => 1,
      "transition_count" => 0,
      "previous_hash" => digest,
      "last_hash" => digest
    }

    pairs = [
      {"consumption-row.schema.json", row, "v"},
      {"boundary-anchor-header.schema.json", anchor_header, "kid"},
      {"boundary-anchor-payload.schema.json", anchor_payload, "v"},
      {"key-transition-payload.schema.json", transition, "v"},
      {"anchored-export-header.schema.json", archive_header, "v"}
    ]

    for {name, valid, required_key} <- pairs do
      schema = compiled!(name)
      assert :ok = JSONSchex.validate(schema, valid)
      assert {:error, _errors} = JSONSchex.validate(schema, Map.put(valid, "extra", true))
      assert {:error, _errors} = JSONSchex.validate(schema, Map.delete(valid, required_key))
    end

    assert {:error, _errors} =
             JSONSchex.validate(compiled!("boundary-anchor-payload.schema.json"), %{
               anchor_payload
               | "sequence" => -1
             })

    assert {:error, _errors} =
             JSONSchex.validate(compiled!("anchored-export-header.schema.json"), %{
               archive_header
               | "row_count" => 65_537
             })
  end

  test "JSON-value schema is structural while normative decoder owns byte limits" do
    json_schema = schema!("json-value.schema.json")
    grant_schema = schema!("grant-header.schema.json")
    schema = compiled!("json-value.schema.json")
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

  test "schema numeric structure cannot replace the raw-lexeme decoder gate" do
    schema = compiled!("json-value.schema.json")

    assert :ok = JSONSchex.validate(schema, 9_007_199_254_740_991)
    assert {:error, _errors} = JSONSchex.validate(schema, 9_007_199_254_740_992)

    overlong = "1" <> String.duplicate("0", 63)
    assert {:error, :invalid} = Json.decode(overlong)
  end

  defp compiled!(name) do
    {:ok, schema} = JSONSchex.compile(schema!(name))
    schema
  end

  defp schema!(name) do
    @schemas
    |> Path.join(name)
    |> File.read!()
    |> :json.decode()
  end

  defp fixture! do
    @fixture_path
    |> File.read!()
    |> :json.decode()
  end
end
