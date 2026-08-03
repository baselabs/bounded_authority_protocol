defmodule BoundedAuthorityProtocol.Property.Base64UrlPropertyTest do
  @moduledoc """
  base64url canonical round-trip + pad-bit rejection properties.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.{Base64Url, Bounds}

  @max_bounds Bounds.maximum()

  property "base64url round-trip: decoding a canonical base64url encoding recovers the bytes" do
    check all(
            bytes <- binary(min_length: 0, max_length: 256),
            max_runs: 200
          ) do
      encoded = Base.url_encode64(bytes, padding: false)
      assert Base64Url.decode(encoded, @max_bounds) == {:ok, bytes}
    end
  end

  property "base64url rejects padded input (the canonical form is unpadded)" do
    check all(
            bytes <- binary(min_length: 1, max_length: 64),
            max_runs: 100
          ) do
      # Append explicit padding to a canonical (unpadded) base64url encoding.
      encoded = Base.url_encode64(bytes, padding: false) <> "="
      assert Base64Url.decode(encoded, @max_bounds) == {:error, :invalid}
    end
  end

  property "base64url rejects alphabet violations" do
    check all(
            # Insert a character outside the base64url alphabet [A-Za-z0-9_-]
            bad_char <- member_of(["!", "@", "#", "$", "%", "^", "&", "*", "+", "/"]),
            prefix <- string(:alphanumeric, min_length: 2, max_length: 8),
            max_runs: 100
          ) do
      bad = prefix <> bad_char
      assert Base64Url.decode(bad, @max_bounds) == {:error, :invalid}
    end
  end
end
