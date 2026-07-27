defmodule BoundedAuthorityProtocol.V1.Base64UrlTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Base64Url

  test "accepts canonical unpadded base64url at exact encoded and decoded limits" do
    assert {:ok, <<255>>} = Base64Url.decode(<<"_w">>)

    segment = Base.url_encode64(<<0, 1, 2>>, padding: false)

    assert {:ok, <<0, 1, 2>>} =
             Base64Url.decode(segment, %{encoded_segment_bytes: 4, decoded_segment_bytes: 3})
  end

  test "rejects both sides of encoded and decoded limits" do
    assert {:error, :invalid} =
             Base64Url.decode(<<"AA">>, %{encoded_segment_bytes: 1})

    assert {:error, :invalid} =
             Base64Url.decode(<<"AAAA">>, %{decoded_segment_bytes: 2})
  end

  test "rejects padding, standard alphabet, whitespace, impossible length, and nonzero pad bits" do
    for segment <- [<<"AA==">>, <<"+w">>, <<"A A">>, <<"A">>, <<"AB">>] do
      assert {:error, :invalid} = Base64Url.decode(segment)
    end
  end

  test "rejects non-binary input" do
    assert {:error, :invalid} = Base64Url.decode(:not_binary)
  end
end
