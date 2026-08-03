defmodule BoundedAuthorityProtocol.Property.UriPropertyTest do
  @moduledoc """
  URI normalization idempotence + normalized-input acceptance properties (RFC 3986 §6).
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.{Bounds, Uri}

  @max_bounds Bounds.maximum()

  @normalizable_uris [
    "https://example.com/a",
    "https://example.com/a/~",
    "https://example.com:8443/a%2Fb",
    "https://[2001:db8::1]/",
    "https://192.0.2.1/"
  ]

  property "URI normalization is idempotent: normalize(normalize(x)) == normalize(x)" do
    check all(uri <- member_of(@normalizable_uris), max_runs: length(@normalizable_uris) * 5) do
      {:ok, first} = Uri.normalize(uri, @max_bounds)
      {:ok, second} = Uri.normalize(first, @max_bounds)
      assert first == second
    end
  end

  property "normalized input is accepted on re-normalization" do
    check all(uri <- member_of(@normalizable_uris), max_runs: length(@normalizable_uris) * 5) do
      {:ok, normalized} = Uri.normalize(uri, @max_bounds)
      assert match?({:ok, _}, Uri.normalize(normalized, @max_bounds))
    end
  end
end
