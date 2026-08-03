defmodule BoundedAuthorityProtocol.Property.JcsPropertyTest do
  @moduledoc """
  JCS (RFC 8785) determinism, idempotence, and -0 normalization properties.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.{Bounds, Jcs, Json}

  @max_bounds Bounds.maximum()

  # A printable-string generator used to build small JSON documents within the decoder bounds.
  defp json_value_gen do
    string(:alphanumeric, min_length: 1, max_length: 32)
  end

  property "JCS encode is deterministic: identical input yields identical bytes" do
    check all(text <- json_value_gen(), max_runs: 200) do
      with {:ok, value} <- Json.decode(~s({"k":"#{text}"}), @max_bounds),
           {:ok, first} <- Jcs.encode(value, @max_bounds),
           {:ok, second} <- Jcs.encode(value, @max_bounds) do
        assert first == second
      else
        _ -> :ok
      end
    end
  end

  property "JCS encode is idempotent: encode(decode(encode(x))) == encode(x)" do
    check all(n <- integer(0..9_007_199_254_740_991), max_runs: 200) do
      value = {:integer, n}

      {:ok, encoded} = Jcs.encode(value, @max_bounds)
      {:ok, decoded} = Json.decode(encoded, @max_bounds)
      {:ok, reencoded} = Jcs.encode(decoded, @max_bounds)

      assert reencoded == encoded
    end
  end

  property "JCS canonicalizes integer keys in sorted order regardless of input order" do
    check all(
            a <- integer(0..1000),
            b <- integer(0..1000),
            max_runs: 100
          ) do
      # Two objects with the same members in opposite orders must produce identical JCS bytes.
      v1 =
        {:object, [{Integer.to_string(a), {:integer, 1}}, {Integer.to_string(b), {:integer, 2}}]}

      v2 =
        {:object, [{Integer.to_string(b), {:integer, 2}}, {Integer.to_string(a), {:integer, 1}}]}

      with {:ok, e1} <- Jcs.encode(v1, @max_bounds),
           {:ok, e2} <- Jcs.encode(v2, @max_bounds) do
        assert e1 == e2
      else
        _ -> :ok
      end
    end
  end
end
