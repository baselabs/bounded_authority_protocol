defmodule BoundedAuthorityProtocol.V2.RequestDigestTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V2
  alias BoundedAuthorityProtocol.V2.RequestDigest

  # The v2 profile hashes the identical canonical argument projection under the
  # BAP2-REQUEST domain separator, so every v2 digest must differ from v1's.
  @canonical ~s(["read_record",["object",{"limit":["integer",10],"record":["object",{"region":["string","us-east"],"tier":["string","gold"]}]}]])

  test "digest is domain-separated from v1 over identical canonical bytes" do
    arguments =
      {:object,
       [
         {"record", {:object, [{"tier", {:string, "gold"}}, {"region", {:string, "us-east"}}]}},
         {"limit", {:integer, 10}}
       ]}

    assert {:ok, v2_digest} = V2.request_digest("read_record", arguments, %{})
    assert {:ok, v1_digest} = V1.request_digest("read_record", arguments, %{})
    refute v2_digest == v1_digest

    expected =
      :crypto.hash(:sha256, ["BAP2-REQUEST\0", @canonical])
      |> Base.url_encode64(padding: false)

    assert v2_digest == expected
    assert v1_digest != expected

    refute :crypto.hash(:sha256, @canonical) |> Base.url_encode64(padding: false) == v2_digest
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
        :crypto.hash(:sha256, ["BAP2-REQUEST\0", canonical])
        |> Base.url_encode64(padding: false)

      assert {:ok, ^expected} = V2.request_digest("read_record", arguments, %{})
    end

    assert {:ok, integral_float} = V2.request_digest("read_record", {:float, 1.0}, %{})

    expected_integral_float =
      :crypto.hash(:sha256, ["BAP2-REQUEST\0", ~s(["read_record",["float",1]])])
      |> Base.url_encode64(padding: false)

    assert integral_float == expected_integral_float
  end

  test "typed projection preserves the distinction between integer and float tags" do
    assert {:ok, integer_digest} = V2.request_digest("op", {:integer, 1}, %{})
    assert {:ok, float_digest} = V2.request_digest("op", {:float, 1.0}, %{})

    refute integer_digest == float_digest

    assert {:ok, nested_integer} =
             V2.request_digest("op", {:array, [{:integer, 1}]}, %{})

    assert {:ok, nested_float} = V2.request_digest("op", {:array, [{:float, 1.0}]}, %{})

    refute nested_integer == nested_float
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

    assert V2.request_digest("op", left, %{}) == V2.request_digest("op", right, %{})
    refute V2.request_digest("op", left, %{}) == V2.request_digest("op", reordered_array, %{})
  end

  test "operation-name bound accepts exactly 128 bytes and rejects maximum plus one" do
    assert {:ok, _digest} = V2.request_digest(String.duplicate("a", 128), :null, %{})
    assert {:error, :invalid} = V2.request_digest(String.duplicate("a", 129), :null, %{})
    assert {:error, :invalid} = V2.request_digest("line\nbreak", :null, %{})
  end

  test "malformed values and widening bounds always return the fixed error" do
    assert {:error, :invalid} = V2.request_digest(:operation, :null, %{})
    assert {:error, :invalid} = V2.request_digest("op", nil, %{})
    assert {:error, :invalid} = V2.request_digest("op", {:integer, :not_an_integer}, %{})
    assert {:error, :invalid} = V2.request_digest("op", :null, %{jcs_bytes: 65_537})
    assert {:error, :invalid} = V2.request_digest("op", :null, %{unknown: 1})

    assert {:error, :invalid} =
             V2.request_digest("op", {:array, [{:integer, 1} | :invalid_tail]}, %{})

    assert {:error, :invalid} =
             V2.request_digest("op", {:array, [:invalid_member]}, %{})

    assert {:error, :invalid} =
             V2.request_digest(
               "op",
               {:object, [{"value", {:integer, 1}} | :invalid_tail]},
               %{}
             )

    assert {:error, :invalid} = V2.request_digest("op", {:object, [{1, :null}]}, %{})
  end

  test "digest_raw returns the raw 32-byte digest and the fixed error on failure" do
    assert {:ok, encoded} = V2.request_digest("read_record", {:integer, 1}, %{})
    assert {:ok, raw} = RequestDigest.digest_raw("read_record", {:integer, 1}, %{})

    assert byte_size(raw) == 32
    assert raw == :crypto.hash(:sha256, ["BAP2-REQUEST\0", ~s(["read_record",["integer",1]])])
    assert Base.url_encode64(raw, padding: false) == encoded

    assert {:error, :invalid} = RequestDigest.digest_raw(:operation, :null, %{})
    assert {:error, :invalid} = RequestDigest.digest_raw("op", nil, %{})
  end
end
