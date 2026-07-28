defmodule BoundedAuthorityProtocol.V1.RequestDigestTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1

  @expected "7u9_1J2PhcGEn_iqJFeAsqiko0xtIGTdKBNvYmisc0E"

  test "request digest matches the independent exact preimage" do
    arguments =
      {:object,
       [
         {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
         {"limit", {:integer, 10}}
       ]}

    assert {:ok, @expected} = V1.request_digest("read_record", arguments, %{})

    canonical =
      ~s(["read_record",["object",{"limit":["integer",10],"record":["object",{"region":["string","us-east"],"tier":["string","gold"]}]}]])

    expected =
      :crypto.hash(:sha256, ["BAP1-REQUEST\0", canonical])
      |> Base.url_encode64(padding: false)

    assert expected == @expected

    refute :crypto.hash(:sha256, canonical)
           |> Base.url_encode64(padding: false) == @expected
  end

  test "all tagged JSON root shapes are valid request arguments" do
    for {arguments, canonical} <- [
          {:null, ~s(["read_record",["null"]])},
          {{:boolean, true}, ~s(["read_record",["boolean",true]])},
          {{:integer, 1}, ~s(["read_record",["integer",1]])},
          {{:float, 1.5}, ~s(["read_record",["float",1.5]])},
          {{:string, "value"}, ~s(["read_record",["string","value"]])},
          {{:array, [{:integer, 1}]}, ~s(["read_record",["array",[["integer",1]]]])},
          {{:object, [{"value", {:integer, 1}}]},
           ~s(["read_record",["object",{"value":["integer",1]}]])}
        ] do
      expected =
        :crypto.hash(:sha256, ["BAP1-REQUEST\0", canonical])
        |> Base.url_encode64(padding: false)

      assert {:ok, ^expected} = V1.request_digest("read_record", arguments, %{})
    end

    assert {:ok, integral_float} = V1.request_digest("read_record", {:float, 1.0}, %{})

    expected_integral_float =
      :crypto.hash(:sha256, ["BAP1-REQUEST\0", ~s(["read_record",["float",1]])])
      |> Base.url_encode64(padding: false)

    assert integral_float == expected_integral_float
  end

  test "object member order is semantic while arrays and scalar tags remain exact" do
    left =
      {:object,
       [
         {"b", {:array, [{:integer, 1}, {:float, 1.0}]}},
         {"a", {:object, [{"y", :null}, {"x", {:boolean, true}}]}}
       ]}

    right =
      {:object,
       [
         {"a", {:object, [{"x", {:boolean, true}}, {"y", :null}]}},
         {"b", {:array, [{:integer, 1}, {:float, 1.0}]}}
       ]}

    reordered_array =
      {:object,
       [
         {"a", {:object, [{"x", {:boolean, true}}, {"y", :null}]}},
         {"b", {:array, [{:float, 1.0}, {:integer, 1}]}}
       ]}

    assert V1.request_digest("op", left, %{}) == V1.request_digest("op", right, %{})
    refute V1.request_digest("op", left, %{}) == V1.request_digest("op", reordered_array, %{})

    refute V1.request_digest("op", {:integer, 1}, %{}) ==
             V1.request_digest("op", {:float, 1.0}, %{})
  end

  test "operation-name bound accepts exactly 128 bytes and rejects maximum plus one" do
    assert {:ok, _digest} = V1.request_digest(String.duplicate("a", 128), :null, %{})
    assert {:error, :invalid} = V1.request_digest(String.duplicate("a", 129), :null, %{})
    assert {:error, :invalid} = V1.request_digest("line\nbreak", :null, %{})
  end

  test "malformed values and widening bounds always return the fixed error" do
    assert {:error, :invalid} = V1.request_digest(:operation, :null, %{})
    assert {:error, :invalid} = V1.request_digest("op", nil, %{})
    assert {:error, :invalid} = V1.request_digest("op", :null, %{jcs_bytes: 65_537})
    assert {:error, :invalid} = V1.request_digest("op", :null, %{unknown: 1})

    assert {:error, :invalid} =
             V1.request_digest("op", {:array, [{:integer, 1} | :invalid_tail]}, %{})

    assert {:error, :invalid} =
             V1.request_digest(
               "op",
               {:object, [{"value", {:integer, 1}} | :invalid_tail]},
               %{}
             )
  end
end
