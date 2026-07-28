defmodule BoundedAuthorityProtocol.V1.UriTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.Uri

  test "RFC 3986 syntax normalization is restricted to hierarchical HTTPS DPoP targets" do
    for {input, expected} <- [
          {"HTTPS://Example.COM:443/a/./b/../c/%7euser/%2f", "https://example.com/a/c/~user/%2F"},
          {"https://EXAMPLE.com", "https://example.com/"},
          {"https://example.com:8443/a/../b", "https://example.com:8443/b"},
          {"https://example.com/a/%41/%3a", "https://example.com/a/A/%3A"},
          {"https://[2001:DB8::1]:443/a", "https://[2001:db8::1]/a"},
          {"https://[v1.A:B]:8443/", "https://[v1.a:b]:8443/"},
          {"https://[V1.A:B]/", "https://[v1.a:b]/"},
          {"https://[1:2:3:4:5:6:7:8]/", "https://[1:2:3:4:5:6:7:8]/"},
          {"https://[::ffff:192.0.2.1]/", "https://[::ffff:192.0.2.1]/"},
          {"https://exa%6Dple.com/", "https://example.com/"},
          {"https://EXA%2fMPLE.com/", "https://exa%2Fmple.com/"},
          {"https://example.com/a/.", "https://example.com/a/"},
          {"https://example.com/a/..", "https://example.com/"},
          {"https://example.com/../a", "https://example.com/a"},
          {"https://192.0.2.1/", "https://192.0.2.1/"}
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
          "https://example.com:/",
          "https://[:::]/",
          "https://[::1",
          "https://[::1]suffix/",
          "https://[1::2::3]/",
          "https://[v.a]/",
          "https://[v1]/",
          "https://1.2.3/",
          "https://01.2.3.4/",
          "https://256.2.3.4/",
          "https://example.com:\n/",
          "https://example.com:1:2/",
          "https://exa{mple.com/",
          "https://example.com/[]",
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
    assert {:error, :invalid} = Uri.normalize("", %{})
    assert {:error, :invalid} = Uri.normalize(nil, %{})
    assert {:error, :invalid} = Uri.normalize("https://example.com/", %{uri_bytes: 0})
    assert {:error, :invalid} = Uri.normalize("https://example.com/", %{unknown: 1})
  end
end
