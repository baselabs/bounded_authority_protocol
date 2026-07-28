defmodule BoundedAuthorityProtocol.V1.JcsTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Jcs

  test "RFC 8785 Appendix B binary64 cases use ECMAScript number text" do
    for {bits, expected} <- [
          {0x0000000000000000, "0"},
          {0x8000000000000000, "0"},
          {0x0000000000000001, "5e-324"},
          {0x8000000000000001, "-5e-324"},
          {0x3EB0C6F7A0B5ED8C, "9.999999999999997e-7"},
          {0x3EB0C6F7A0B5ED8D, "0.000001"},
          {0x41B3DE4355555553, "333333333.3333332"},
          {0x41B3DE4355555554, "333333333.33333325"},
          {0x41B3DE4355555555, "333333333.3333333"},
          {0x41B3DE4355555556, "333333333.3333334"},
          {0x41B3DE4355555557, "333333333.33333343"},
          {0xBECBF647612F3696, "-0.0000033333333333333333"},
          {0x43143FF3C1CB0959, "1424953923781206.2"}
        ] do
      <<value::float-64>> = <<bits::unsigned-64>>
      assert {:ok, ^expected} = Jcs.encode({:float, value}, %{})
    end

    for bits <- [
          0x7FEFFFFFFFFFFFFF,
          0xFFEFFFFFFFFFFFFF,
          0x4340000000000000,
          0xC340000000000000
        ] do
      <<value::float-64>> = <<bits::unsigned-64>>
      assert {:error, :invalid} = Jcs.encode({:float, value}, %{})
    end
  end

  test "strings use exact RFC 8785 escaping without Unicode normalization" do
    value = {:string, <<0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x0F, ?", ?\\, ?/, "é"::utf8>>}

    assert {:ok, ~s("\\b\\t\\n\\f\\r\\u000f\\"\\\\/é")} = Jcs.encode(value, %{})
    assert {:ok, ~s("é")} = Jcs.encode({:string, "e\u0301"}, %{})
    refute elem(Jcs.encode({:string, "e\u0301"}, %{}), 1) == ~s("é")
    assert {:error, :invalid} = Jcs.encode({:string, <<0xFF>>}, %{})
  end

  test "object names sort recursively by unsigned UTF-16 code units" do
    value =
      {:object,
       [
         {"\uFB33", :null},
         {"😀", :null},
         {"€", :null},
         {"1", :null},
         {"\r", :null},
         {"ö", :null},
         {"\u0080", :null}
       ]}

    assert {:ok, encoded} = Jcs.encode(value, %{})

    assert encoded ==
             "{\"\\r\":null,\"1\":null,\"\u0080\":null,\"ö\":null,\"€\":null,\"😀\":null,\"דּ\":null}"
  end

  test "arrays preserve order while nested objects canonicalize independently" do
    value =
      {:array,
       [
         {:object, [{"z", {:integer, 1}}, {"a", {:integer, 2}}]},
         {:object, [{"b", {:boolean, true}}, {"a", :null}]}
       ]}

    assert {:ok, ~s([{"a":2,"z":1},{"a":null,"b":true}])} = Jcs.encode(value, %{})
  end

  test "JCS output accepts the exact 65,536-byte bound and rejects maximum plus one" do
    exact_strings =
      List.duplicate({:string, String.duplicate("a", 253)}, 255) ++
        [{:string, String.duplicate("a", 252)}]

    over_strings =
      List.duplicate({:string, String.duplicate("a", 253)}, 256)

    assert {:ok, exact} = Jcs.encode({:array, exact_strings}, %{})
    assert byte_size(exact) == 65_536
    assert {:error, :invalid} = Jcs.encode({:array, over_strings}, %{})
  end

  test "all failures are the fixed public error" do
    assert {:error, :invalid} = Jcs.encode(%{}, %{})
    assert {:error, :invalid} = Jcs.encode({:object, [{"x", :null}, {"x", :null}]}, %{})
    assert {:error, :invalid} = Jcs.encode({:array, []}, %{jcs_bytes: 0})
    assert {:error, :invalid} = Jcs.encode({:object, [{:not_binary, :null}]}, %{})
    assert {:error, :invalid} = Jcs.encode({:array, List.duplicate(:null, 257)}, %{})
    assert {:ok, "1"} = Jcs.encode({:float, 1.0}, %{})
  end
end
