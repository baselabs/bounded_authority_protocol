defmodule BoundedAuthorityProtocol.V1.JsonFromTermTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.{Bounds, Json}

  test "maps every scalar without changing its numeric tag" do
    for {term, tagged} <- [
          {nil, :null},
          {true, {:boolean, true}},
          {false, {:boolean, false}},
          {0, {:integer, 0}},
          {-4, {:integer, -4}},
          {4.0, {:float, 4.0}},
          {-0.0, {:float, -0.0}},
          {1.5, {:float, 1.5}},
          {"", {:string, ""}},
          {"雪", {:string, "雪"}}
        ] do
      assert Json.from_term(term) === {:ok, tagged}
    end
  end

  test "preserves array order and sorts nested object names after converting atom keys" do
    term = %{z: [nil, false, 4.0, %{"b" => 2, :a => "first"}], a: %{}}

    assert {:ok,
            {:object,
             [
               {"a", {:object, []}},
               {"z",
                {:array,
                 [
                   :null,
                   {:boolean, false},
                   {:float, 4.0},
                   {:object, [{"a", {:string, "first"}}, {"b", {:integer, 2}}]}
                 ]}}
             ]}} = Json.from_term(term)

    assert {:ok, {:array, []}} = Json.from_term([])
    assert {:ok, {:object, [{"", :null}]}} = Json.from_term(%{"" => nil})

    assert {:ok, {:object, [{"\uE000", :null}, {"\u{10000}", :null}]}} =
             Json.from_term(%{"\u{10000}" => nil, "\uE000" => nil})

    assert {:ok, {:object, [{"__struct__", :null}]}} =
             Json.from_term(%{"__struct__" => nil})
  end

  test "rejects colliding names at every nesting shape" do
    collision = %{:a => 1, "a" => 2}

    for term <- [collision, [collision], %{outer: collision}, %{outer: [collision]}] do
      assert {:error, :invalid} = Json.from_term(term)
    end
  end

  test "rejects all unsupported values at root and inside containers" do
    invalid = [
      :other,
      :null,
      {},
      {:integer, 1},
      [a: 1],
      [nil | :tail],
      [true, false | "tail"],
      <<1::1>>,
      <<0xFF>>,
      <<0xC0, 0x80>>,
      <<0xED, 0xA0, 0x80>>,
      self(),
      make_ref(),
      fn -> :ok end,
      &Enum.reverse/1,
      ~D[2026-01-01],
      ~U[2026-01-01 00:00:00Z],
      MapSet.new(),
      %{__struct__: nil},
      %{__struct__: "unknown"}
    ]

    for term <- invalid ++ :erlang.ports(), wrapped <- [term, [term], %{value: term}] do
      assert {:error, :invalid} = Json.from_term(wrapped)
    end
  end

  test "rejects invalid object keys without stringifying them" do
    for key <- [nil, true, false, 1, 1.0, {}, [], <<1::1>>, <<0xFF>>, self(), make_ref()] do
      assert {:error, :invalid} = Json.from_term(%{key => nil})
    end
  end

  test "coerces tightening maps and validates hand-built bounds" do
    assert {:ok, {:integer, 1}} = Json.from_term(1, %Bounds{integer_magnitude: 1})

    for limits <- [
          nil,
          [],
          [depth: 1],
          %{unknown: 1},
          %{depth: 0},
          %{depth: -1},
          %{depth: 1.0},
          %{depth: 33},
          %{signature_bytes: 1},
          %Bounds{depth: 0},
          %Bounds{total_nodes: "one"}
        ] do
      assert {:error, :invalid} = Json.from_term(nil, limits)
    end
  end

  test "applies the decoder depth ceiling to arrays, objects, and empty containers" do
    for {at_limit, over_limit} <- [
          {[[0]], [[[0]]]},
          {%{a: %{b: 0}}, %{a: %{b: %{c: 0}}}},
          {[%{a: 0}], [%{a: []}]},
          {[[]], [[[]]]},
          {%{a: %{}}, %{a: %{b: %{}}}}
        ] do
      assert {:ok, _value} = Json.from_term(at_limit, %{depth: 2})
      assert {:error, :invalid} = Json.from_term(over_limit, %{depth: 2})
    end

    assert {:ok, {:array, []}} = Json.from_term([], %{depth: 1})
    assert {:ok, {:object, []}} = Json.from_term(%{}, %{depth: 1})
  end

  test "bounds each container independently at the exact item and member counts" do
    assert {:ok, {:array, [{:integer, 1}]}} = Json.from_term([1], %{array_items: 1})
    assert {:error, :invalid} = Json.from_term([1, 2], %{array_items: 1})
    assert {:error, :invalid} = Json.from_term(%{a: [1, 2]}, %{array_items: 1})

    assert {:ok, {:object, [{"a", :null}]}} =
             Json.from_term(%{a: nil}, %{object_members: 1})

    assert {:error, :invalid} = Json.from_term(%{a: nil, b: nil}, %{object_members: 1})
    assert {:error, :invalid} = Json.from_term([%{a: nil, b: nil}], %{object_members: 1})
    assert {:ok, _value} = Json.from_term([%{a: nil}, %{b: nil}], %{object_members: 1})
  end

  test "counts all containers and values as nodes, excluding object keys" do
    for scalar <- [nil, false, 0, 0.0, "x", [], %{}] do
      assert {:ok, _value} = Json.from_term(scalar, %{total_nodes: 1})
    end

    for term <- [[1], %{a: 1}] do
      assert {:ok, _value} = Json.from_term(term, %{total_nodes: 2})
      assert {:error, :invalid} = Json.from_term(term, %{total_nodes: 1})
    end

    for term <- [[[], %{}], %{a: [], b: %{}}, [%{a: nil}]] do
      assert {:ok, _value} = Json.from_term(term, %{total_nodes: 3})
      assert {:error, :invalid} = Json.from_term(term, %{total_nodes: 2})
    end

    term = [%{a: nil}, %{b: nil}]
    assert {:ok, _value} = Json.from_term(term, %{total_nodes: 5})
    assert {:error, :invalid} = Json.from_term(term, %{total_nodes: 4})
  end

  test "bounds UTF-8 string and key bytes separately, including converted atom keys" do
    assert {:ok, {:string, "é"}} = Json.from_term("é", %{string_bytes: 2})
    assert {:error, :invalid} = Json.from_term("éa", %{string_bytes: 2})
    assert {:error, :invalid} = Json.from_term(["éa"], %{string_bytes: 2})
    assert {:ok, _value} = Json.from_term(%{"é" => nil}, %{key_bytes: 2, string_bytes: 1})
    assert {:error, :invalid} = Json.from_term(%{"éa" => nil}, %{key_bytes: 2})
    assert {:ok, _value} = Json.from_term(%{é: nil}, %{key_bytes: 2})
    assert {:error, :invalid} = Json.from_term(%{éa: nil}, %{key_bytes: 2})
    assert {:ok, _value} = Json.from_term(%{a: "é"}, %{key_bytes: 1, string_bytes: 2})
  end

  test "applies symmetric integer and float magnitude ceilings without retagging" do
    for maximum <- [1, 9_007_199_254_740_991], sign <- [-1, 1] do
      integer = sign * maximum
      float = integer * 1.0

      assert {:ok, {:integer, ^integer}} =
               Json.from_term(integer, %{integer_magnitude: maximum})

      assert {:ok, {:float, ^float}} = Json.from_term(float, %{float_magnitude: maximum})

      assert {:error, :invalid} =
               Json.from_term(sign * (maximum + 1), %{integer_magnitude: maximum})

      assert {:error, :invalid} =
               Json.from_term(sign * (maximum + 1.0), %{float_magnitude: maximum})
    end

    assert {:error, :invalid} = Json.from_term(-1.5, %{float_magnitude: 1})
    assert {:error, :invalid} = Json.from_term(1.5, %{float_magnitude: 1})
    assert {:ok, {:integer, 2}} = Json.from_term(2, %{float_magnitude: 1})
    assert {:ok, {:float, 2.0}} = Json.from_term(2.0, %{integer_magnitude: 1})
  end

  test "text-only ceilings do not constrain terms" do
    assert {:ok, {:object, [{"number", {:integer, 123}}, {"text", {:string, "abc"}}]}} =
             Json.from_term(%{text: "abc", number: 123}, %{
               json_bytes: 1,
               number_lexeme_bytes: 1
             })

    assert {:ok, {:float, 12.5}} =
             Json.from_term(12.5, %{json_bytes: 1, number_lexeme_bytes: 1})
  end

  test "enforces each structural hard maximum at its exact boundary and one beyond" do
    nested = fn levels -> Enum.reduce(1..levels, nil, fn _level, value -> [value] end) end
    object = fn count -> Map.new(1..count, &{Integer.to_string(&1), nil}) end
    nodes = List.duplicate(List.duplicate(nil, 255), 15)

    for {at_limit, over_limit} <- [
          {nested.(32), nested.(33)},
          {object.(64), object.(65)},
          {List.duplicate(nil, 256), List.duplicate(nil, 257)},
          {String.duplicate("a", 8_192), String.duplicate("a", 8_193)},
          {%{String.duplicate("k", 128) => nil}, %{String.duplicate("k", 129) => nil}},
          {nodes ++ [List.duplicate(nil, 254)], nodes ++ [List.duplicate(nil, 255)]}
        ] do
      assert {:ok, _value} = Json.from_term(at_limit)
      assert {:error, :invalid} = Json.from_term(over_limit)
    end
  end
end
