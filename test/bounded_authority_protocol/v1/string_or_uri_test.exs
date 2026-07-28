defmodule BoundedAuthorityProtocol.V1.StringOrUriTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1.StringOrUri

  test "accepts plain strings and exact RFC 3986 URI bytes" do
    assert StringOrUri.valid?("plain identifier")
    assert StringOrUri.valid?("urn:baselabs:bap:v1")
    assert StringOrUri.valid?("https://example.test/a%20b?x=1#fragment")
  end

  test "rejects malformed schemes, percent escapes, spaces, controls, and non-URI bytes" do
    for invalid <- [
          ":missing-scheme",
          "1bad:scheme",
          "x^:scheme",
          "x:%",
          "x:%0",
          "x:%zz",
          "https://example.test/a b",
          "x:\n",
          "x:é",
          <<255>>,
          :not_binary
        ] do
      refute StringOrUri.valid?(invalid)
    end
  end
end
