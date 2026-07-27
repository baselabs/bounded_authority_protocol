defmodule BoundedAuthorityProtocol.V1.JsonTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Json

  test "preserves object order and returns the closed algebra without atomizing names" do
    assert {:ok,
            {:object,
             [
               {"z", {:integer, 1}},
               {"a", {:array, [{:boolean, true}, :null, {:string, "x"}]}}
             ]}} = Json.decode(~s({"z":1,"a":[true,null,"x"]}))
  end

  test "rejects duplicate names before map conversion at every nesting shape" do
    for bytes <- [
          ~s({"a":1,"a":2}),
          ~s({"outer":{"a":1,"a":2}}),
          ~s([{"a":1,"a":2}]),
          ~s({"outer":[{"a":1,"a":2}]})
        ] do
      assert {:error, :invalid} = Json.decode(bytes)
    end
  end

  test "accepts exact depth then rejects one level beyond it" do
    assert {:ok, {:array, [{:array, [{:integer, 0}]}]}} =
             Json.decode("[[0]]", %{depth: 2})

    assert {:error, :invalid} = Json.decode("[[[0]]]", %{depth: 2})
  end

  test "enforces raw bytes, member, item, node, key, and string limits on both sides" do
    assert {:ok, {:string, "ab"}} = Json.decode(~s("ab"), %{json_bytes: 4, string_bytes: 2})
    assert {:error, :invalid} = Json.decode(~s("abc"), %{json_bytes: 4})
    assert {:error, :invalid} = Json.decode(~s("abc"), %{string_bytes: 2})

    assert {:ok, {:object, [{"ab", {:integer, 1}}]}} =
             Json.decode(~s({"ab":1}), %{key_bytes: 2, object_members: 1})

    assert {:error, :invalid} = Json.decode(~s({"abc":1}), %{key_bytes: 2})
    assert {:error, :invalid} = Json.decode(~s({"a":1,"b":2}), %{object_members: 1})
    assert {:ok, {:array, [{:integer, 1}]}} = Json.decode("[1]", %{array_items: 1})
    assert {:error, :invalid} = Json.decode("[1,2]", %{array_items: 1})
    assert {:ok, {:array, [{:integer, 1}]}} = Json.decode("[1]", %{total_nodes: 2})
    assert {:error, :invalid} = Json.decode("[1]", %{total_nodes: 1})
  end

  test "enforces number lexeme and symmetric numeric magnitude" do
    maximum = 9_007_199_254_740_991
    minimum = -maximum

    assert {:ok, {:integer, ^maximum}} = Json.decode(Integer.to_string(maximum))
    assert {:ok, {:integer, ^minimum}} = Json.decode(Integer.to_string(minimum))
    assert {:error, :invalid} = Json.decode(Integer.to_string(maximum + 1))
    assert {:error, :invalid} = Json.decode(Integer.to_string(-maximum - 1))

    assert {:ok, {:float, positive}} = Json.decode("9007199254740991.0")
    assert positive == 9_007_199_254_740_991.0
    assert {:ok, {:float, negative}} = Json.decode("-9007199254740991.0")
    assert negative == -9_007_199_254_740_991.0
    assert {:error, :invalid} = Json.decode("9007199254740992.0")
    assert {:error, :invalid} = Json.decode("-9007199254740992.0")
    assert {:error, :invalid} = Json.decode("9007199254740991.1")
    assert {:error, :invalid} = Json.decode("-9007199254740991.1")
    assert {:ok, {:float, _value}} = Json.decode("9007199254740990.9")
    assert {:ok, {:float, _value}} = Json.decode("-9007199254740990.9")
    assert {:ok, {:float, 1.0}} = Json.decode("1e0", %{float_magnitude: 1})
    assert {:error, :invalid} = Json.decode("1.1", %{float_magnitude: 1})

    assert {:ok, {:float, 100.0}} =
             Json.decode("1e2", %{number_lexeme_bytes: 3})

    assert {:ok, {:float, 100.0}} = Json.decode("1e+2")

    exact_lexeme = "1e-" <> String.duplicate("0", 60) <> "1"
    assert byte_size(exact_lexeme) == 64
    assert {:ok, {:float, 0.1}} = Json.decode(exact_lexeme)

    overlong_lexeme = "1e-" <> String.duplicate("0", 61) <> "1"
    assert byte_size(overlong_lexeme) == 65
    assert {:error, :invalid} = Json.decode(overlong_lexeme)

    assert {:error, :invalid} = Json.decode("123", %{number_lexeme_bytes: 2})
  end

  test "rejects malformed values at root, object, and array nesting levels" do
    for bytes <- [
          "",
          "{",
          "[",
          ~s({"a":}),
          ~s({"a":[1,]}),
          ~s([{"a":1,}]),
          "-x",
          "true false",
          <<?", 0xFF, ?">>
        ] do
      assert {:error, :invalid} = Json.decode(bytes)
    end
  end

  test "rejects non-binary input" do
    assert {:error, :invalid} = Json.decode(:not_binary)
  end

  test "raw-number preflight mutation is caught by the exact-magnitude boundary" do
    path = Path.expand("../../../lib/bounded_authority_protocol/v1/json.ex", __DIR__)
    source = File.read!(path)

    mutant =
      source
      |> String.replace(
        "defmodule BoundedAuthorityProtocol.V1.Json do",
        "defmodule BoundedAuthorityProtocol.V1.JsonWithoutRawNumberPreflight do",
        global: false
      )
      |> String.replace(
        "if number_lexemes_valid?(bytes, bounds) do",
        "if number_lexemes_valid?(bytes, bounds) or true do",
        global: false
      )

    assert mutant != source
    modules = Code.compile_string(mutant, path) |> Enum.map(&elem(&1, 0))

    on_exit(fn ->
      Enum.each(modules, fn module ->
        :code.purge(module)
        :code.delete(module)
      end)
    end)

    assert {:error, :invalid} = Json.decode("9007199254740991.1")

    mutant_module = BoundedAuthorityProtocol.V1.JsonWithoutRawNumberPreflight
    mutant_decode = Function.capture(mutant_module, :decode, 1)

    assert {:ok, {:float, 9_007_199_254_740_991.0}} =
             mutant_decode.("9007199254740991.1")
  end

  test "numeric lexeme scanning stops after maximum plus one bytes and the guard is mutation-red" do
    path = Path.expand("../../../lib/bounded_authority_protocol/v1/json.ex", __DIR__)
    source = File.read!(path)
    current_module = BoundedAuthorityProtocol.V1.JsonScanInstrumentation
    unbounded_module = BoundedAuthorityProtocol.V1.JsonUnboundedScanInstrumentation

    current_source = instrument_number_scan(source, current_module, :current_number_scan)

    unbounded_source =
      source
      |> String.replace(
        "defp number_candidate_length(_bytes, length, maximum) when length > maximum, do: :too_long",
        "defp number_candidate_length(_bytes, length, maximum)\n" <>
          "       when length > maximum + 65_536,\n" <>
          "       do: :too_long",
        global: false
      )
      |> instrument_number_scan(unbounded_module, :unbounded_number_scan)

    assert current_source != source
    assert unbounded_source != current_source

    modules =
      Code.compile_string(current_source, path) ++ Code.compile_string(unbounded_source, path)

    on_exit(fn ->
      Enum.each(modules, fn {module, _bytecode} ->
        :code.purge(module)
        :code.delete(module)
      end)
    end)

    token = String.duplicate("1", 100)

    assert scan_message_count(current_module, :current_number_scan, token) == 65
    assert scan_message_count(unbounded_module, :unbounded_number_scan, token) == 100
  end

  test "escape tracking exposes following over-limit numbers and is mutation-red" do
    inputs = [
      ~S(["quote: \"",9007199254740991.1]),
      ~S(["slash: \\",9007199254740991.1])
    ]

    for bytes <- inputs do
      assert {:error, :invalid} = Json.decode(bytes)
    end

    path = Path.expand("../../../lib/bounded_authority_protocol/v1/json.ex", __DIR__)
    source = File.read!(path)

    mutant =
      source
      |> String.replace(
        "defmodule BoundedAuthorityProtocol.V1.Json do",
        "defmodule BoundedAuthorityProtocol.V1.JsonWithoutEscapeTracking do",
        global: false
      )
      |> String.replace(
        "defp scan_string(<<?\\\\, _escaped, rest::binary>>, bounds), do: scan_string(rest, bounds)",
        "defp scan_string(<<?\\\\, _escaped, _rest::binary>>, _bounds), do: true",
        global: false
      )

    assert mutant != source
    modules = Code.compile_string(mutant, path) |> Enum.map(&elem(&1, 0))

    on_exit(fn ->
      Enum.each(modules, fn module ->
        :code.purge(module)
        :code.delete(module)
      end)
    end)

    mutant_decode =
      Function.capture(BoundedAuthorityProtocol.V1.JsonWithoutEscapeTracking, :decode, 1)

    for bytes <- inputs do
      assert {:ok, {:array, [{:string, _string}, {:float, 9_007_199_254_740_991.0}]}} =
               mutant_decode.(bytes)
    end
  end

  test "generated malformed-input fuzz corpus terminates with a closed result" do
    alphabet = [0, 1, 9, 10, 13, 34, 44, 48, 58, 91, 92, 93, 123, 125, 127, 128, 255]

    for first <- alphabet, second <- alphabet, third <- alphabet do
      candidate = <<first, second, third>>
      result = Json.decode(candidate, %{json_bytes: 64})
      assert match?({:ok, _value}, result) or result == {:error, :invalid}
    end

    structures = ["", "{", "[", "0", ~s("x"), ~s({"a":[0]}), "[[[]]]", ~s({"a":{"b":[]}})]

    for left <- structures, right <- structures, byte <- alphabet do
      result = Json.decode(left <> <<byte>> <> right, %{json_bytes: 64, depth: 4})
      assert match?({:ok, _value}, result) or result == {:error, :invalid}
    end
  end

  defp instrument_number_scan(source, module, tag) do
    source
    |> String.replace(
      "defmodule BoundedAuthorityProtocol.V1.Json do",
      "defmodule #{inspect(module)} do",
      global: false
    )
    |> String.replace(
      "defp number_candidate_length(<<_byte, rest::binary>>, length, maximum),\n" <>
        "    do: number_candidate_length(rest, length + 1, maximum)",
      "defp number_candidate_length(<<_byte, rest::binary>>, length, maximum) do\n" <>
        "    send(self(), #{inspect(tag)})\n" <>
        "    number_candidate_length(rest, length + 1, maximum)\n" <>
        "  end",
      global: false
    )
  end

  defp scan_message_count(module, tag, token) do
    decoder = Function.capture(module, :decode, 2)
    assert {:error, :invalid} = decoder.(token, %{json_bytes: 128, number_lexeme_bytes: 64})
    drain_scan_messages(tag, 0)
  end

  defp drain_scan_messages(tag, count) do
    receive do
      ^tag -> drain_scan_messages(tag, count + 1)
    after
      0 -> count
    end
  end
end
