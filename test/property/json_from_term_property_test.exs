defmodule BoundedAuthorityProtocol.Property.JsonFromTermPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.{Bounds, Jcs, Json}

  property "arbitrary terms and limits return only a tagged success or the closed error" do
    check all(value <- term(), limits <- term(), max_runs: 500) do
      for bounds <- [%{}, %{depth: 2, total_nodes: 3}, limits] do
        result = Json.from_term(value, bounds)
        assert result == {:error, :invalid} or match?({:ok, _value}, result)
      end
    end
  end

  property "decoded values survive plain-term projection with identical JCS bytes" do
    check all(term <- json_term(), max_runs: 300) do
      bytes = :json.encode(term) |> IO.iodata_to_binary()
      assert {:ok, decoded} = Json.decode(bytes)
      assert {:ok, converted} = Json.from_term(plain(decoded))
      assert Jcs.encode(converted, %{}) == Jcs.encode(decoded, %{})
      assert {:ok, _bytes} = Jcs.encode(converted, %{})
    end
  end

  property "term conversion and decoding agree under every applicable tightened ceiling" do
    check all(term <- json_term(), limits <- limits(), max_runs: 300) do
      bytes = :json.encode(term) |> IO.iodata_to_binary()

      case Json.decode(bytes, limits) do
        {:ok, decoded} ->
          assert {:ok, converted} = Json.from_term(term, limits)
          assert converted == sorted(decoded)

        {:error, :invalid} ->
          assert {:error, :invalid} = Json.from_term(term, limits)
      end
    end
  end

  test "arbitrary accepted JSON bytes retain canonical bytes after projection" do
    for bytes <- [
          "null",
          "false",
          "-0.0",
          "4.0",
          "1e0",
          "1e-50",
          ~s({"z":[],"a":[true,{"b":"é","a":null}]}),
          ~s({"\\u0000":"\\uFEFF","":""})
        ] do
      assert {:ok, decoded} = Json.decode(bytes)
      assert {:ok, converted} = Json.from_term(plain(decoded), Bounds.maximum())
      assert {:ok, canonical} = Jcs.encode(decoded, %{})
      assert Jcs.encode(converted, %{}) == {:ok, canonical}
    end
  end

  defp json_term do
    scalar =
      one_of([
        constant(nil),
        boolean(),
        integer(-1_000..1_000),
        map(integer(-1_000..1_000), &(&1 + 0.5)),
        string(:printable, max_length: 8)
      ])

    tree(scalar, fn child ->
      one_of([
        list_of(child, max_length: 3),
        map_of(string(:alphanumeric, max_length: 4), child, max_length: 3)
      ])
    end)
    |> resize(12)
  end

  defp limits do
    # The decoder's string callback also visits keys. Generated names fit both byte ceilings;
    # separate boundary tests establish that term keys use key_bytes independently.
    optional_map(%{
      depth: integer(1..5),
      object_members: integer(1..3),
      array_items: integer(1..3),
      total_nodes: integer(1..30),
      string_bytes: integer(4..8),
      key_bytes: integer(1..4),
      integer_magnitude: integer(1..1_000),
      float_magnitude: integer(1..1_000)
    })
  end

  defp plain(:null), do: nil
  defp plain({tag, value}) when tag in [:boolean, :integer, :float, :string], do: value
  defp plain({:array, items}), do: Enum.map(items, &plain/1)
  defp plain({:object, members}), do: Map.new(members, fn {key, value} -> {key, plain(value)} end)

  defp sorted({:object, members}),
    do: {:object, members |> Enum.map(fn {key, value} -> {key, sorted(value)} end) |> Enum.sort()}

  defp sorted({:array, items}), do: {:array, Enum.map(items, &sorted/1)}
  defp sorted(scalar), do: scalar
end
