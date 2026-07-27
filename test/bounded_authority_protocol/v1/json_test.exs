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
          "true false",
          <<?", 0xFF, ?">>
        ] do
      assert {:error, :invalid} = Json.decode(bytes)
    end
  end

  test "rejects non-binary input" do
    assert {:error, :invalid} = Json.decode(:not_binary)
  end

  test "deterministic malformed-input sweep terminates with a closed result" do
    seeds = ["", "{", "[", "0", ~s("x"), ~s({"a":[0]})]

    for seed <- seeds, byte <- 0..255 do
      candidate = seed <> <<byte>>
      result = Json.decode(candidate, %{json_bytes: 64})
      assert match?({:ok, _value}, result) or result == {:error, :invalid}
    end
  end
end
