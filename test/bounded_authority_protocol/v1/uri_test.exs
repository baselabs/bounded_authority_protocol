defmodule BoundedAuthorityProtocol.V1.UriTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Uri

  test "RFC 3986 syntax normalization is restricted to hierarchical HTTPS DPoP targets" do
    for {input, expected} <- [
          {"HTTPS://Example.COM:443/a/./b/../c/%7euser/%2f", "https://example.com/a/c/~user/%2F"},
          {"https://EXAMPLE.com", "https://example.com/"},
          {"https://example.com:8443/a/../b", "https://example.com:8443/b"},
          {"https://example.com/a/%41/%3a", "https://example.com/a/A/%3A"}
        ] do
      assert {:ok, ^expected} = Uri.normalize(input, %{})
      assert {:ok, ^expected} = Uri.normalize(expected, %{})
    end
  end

  test "RFC 9449 target profile rejects every non-HTTPS or ambiguous authority form" do
    for invalid <- [
          "http://example.com/",
          "ftp://example.com/",
          "https:path",
          "https:///path",
          "https:///",
          "https://user@example.com/",
          "https://example.com/?query=1",
          "https://example.com/#fragment",
          "https://example.com/%",
          "https://example.com/%0",
          "https://example.com/%GG",
          "https://example.com:65536/",
          "https://example.com:\n/",
          "https://é.example/"
        ] do
      assert {:error, :invalid} = Uri.normalize(invalid, %{})
    end
  end

  test "URI byte bound accepts exactly 8,192 and rejects maximum plus one" do
    prefix = "https://a.example/"
    exact = prefix <> String.duplicate("a", 8_192 - byte_size(prefix))
    over = exact <> "a"

    assert byte_size(exact) == 8_192
    assert {:ok, ^exact} = Uri.normalize(exact, %{})
    assert {:error, :invalid} = Uri.normalize(over, %{})
  end

  test "all malformed types and limits return the fixed error" do
    assert {:error, :invalid} = Uri.normalize(nil, %{})
    assert {:error, :invalid} = Uri.normalize("https://example.com/", %{uri_bytes: 0})
    assert {:error, :invalid} = Uri.normalize("https://example.com/", %{unknown: 1})
  end
end
