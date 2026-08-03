defmodule BoundedAuthorityProtocol.Property.FacadeClosurePropertyTest do
  @moduledoc """
  Facade closure: EVERY generated input (arbitrary bytes and near-valid mutated inputs) to every
  pure facade function returns {:ok, _} | {:error, :invalid} and NEVER raises. This is the
  fail-closed contract (AGENTS rule 3): the package's pure functions are total on their input
  domain — no input crashes them.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias BoundedAuthorityProtocol.V1.{Base64Url, Bounds, Jcs, Json, Uri}

  @max_bounds Bounds.maximum()

  property "Json.decode never raises on arbitrary bytes (returns {:ok,_} | {:error,:invalid})" do
    check all(bytes <- binary(min_length: 0, max_length: 512), max_runs: 500) do
      result = Json.decode(bytes, @max_bounds)
      assert result == {:error, :invalid} or match?({:ok, _}, result)
    end
  end

  property "Base64Url.decode never raises on arbitrary bytes" do
    check all(bytes <- binary(min_length: 0, max_length: 512), max_runs: 500) do
      result = Base64Url.decode(bytes, @max_bounds)
      assert result == {:error, :invalid} or match?({:ok, _}, result)
    end
  end

  property "Uri.normalize never raises on arbitrary bytes" do
    check all(bytes <- binary(min_length: 0, max_length: 512), max_runs: 500) do
      result = Uri.normalize(bytes, @max_bounds)
      assert result == {:error, :invalid} or match?({:ok, _}, result)
    end
  end

  property "Jcs.encode never raises on decoded-tagged values (returns {:ok,_} | {:error,:invalid})" do
    check all(n <- integer(-9_007_199_254_740_991..9_007_199_254_740_991), max_runs: 200) do
      result = Jcs.encode({:integer, n}, @max_bounds)
      assert result == {:error, :invalid} or match?({:ok, _}, result)
    end
  end

  property "Json.decode is total on near-valid mutations of a valid document" do
    valid = ~s({"k":1})

    check all(
            flip_pos <- integer(0..(byte_size(valid) - 1)),
            flip_byte <- integer(0..255),
            max_runs: 300
          ) do
      <<pre::binary-size(flip_pos), _byte, rest::binary>> = valid
      mutated = <<pre::binary, flip_byte, rest::binary>>

      result = Json.decode(mutated, @max_bounds)
      assert result == {:error, :invalid} or match?({:ok, _}, result)
    end
  end
end
