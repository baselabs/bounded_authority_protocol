defmodule BoundedAuthorityProtocol.V1.RequestDigest do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs

  @prefix <<"BAP1-REQUEST", 0>>

  @doc "Returns the canonical base64url SHA-256 request digest."
  @spec digest(binary(), BoundedAuthorityProtocol.V1.Json.value(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def digest(operation, cast_arguments, limits) when is_binary(operation) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- valid_operation?(operation, bounds),
         {:ok, projected} <- typed(cast_arguments),
         {:ok, canonical} <-
           Jcs.encode({:array, [{:string, operation}, projected]}, bounds) do
      {:ok, :crypto.hash(:sha256, [@prefix, canonical]) |> Base.url_encode64(padding: false)}
    else
      _failure -> {:error, :invalid}
    end
  end

  def digest(_operation, _cast_arguments, _limits), do: {:error, :invalid}

  @doc false
  @spec digest_raw(binary(), BoundedAuthorityProtocol.V1.Json.value(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def digest_raw(operation, cast_arguments, limits) do
    with {:ok, encoded} <- digest(operation, cast_arguments, limits),
         {:ok, raw} <- Base.url_decode64(encoded, padding: false) do
      {:ok, raw}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp typed(:null), do: {:ok, {:array, [{:string, "null"}]}}

  defp typed({:boolean, value}) when is_boolean(value),
    do: {:ok, {:array, [{:string, "boolean"}, {:boolean, value}]}}

  defp typed({:integer, value}) when is_integer(value),
    do: {:ok, {:array, [{:string, "integer"}, {:integer, value}]}}

  defp typed({:float, value}) when is_float(value),
    do: {:ok, {:array, [{:string, "float"}, {:float, value}]}}

  defp typed({:string, value}) when is_binary(value),
    do: {:ok, {:array, [{:string, "string"}, {:string, value}]}}

  defp typed({:array, values}) when is_list(values) do
    with {:ok, projected} <- map_values(values, []) do
      {:ok, {:array, [{:string, "array"}, {:array, projected}]}}
    end
  end

  defp typed({:object, members}) when is_list(members) do
    with {:ok, projected} <- map_members(members, []) do
      {:ok, {:array, [{:string, "object"}, {:object, projected}]}}
    end
  end

  defp typed(_value), do: {:error, :invalid}

  defp map_values([], accumulator), do: {:ok, Enum.reverse(accumulator)}

  defp map_values([value | rest], accumulator) do
    with {:ok, projected} <- typed(value) do
      map_values(rest, [projected | accumulator])
    end
  end

  defp map_values(_values, _accumulator), do: {:error, :invalid}

  defp map_members([], accumulator), do: {:ok, Enum.reverse(accumulator)}

  defp map_members([{key, value} | rest], accumulator) when is_binary(key) do
    with {:ok, projected} <- typed(value) do
      map_members(rest, [{key, projected} | accumulator])
    end
  end

  defp map_members(_members, _accumulator), do: {:error, :invalid}

  defp valid_operation?(operation, bounds) do
    byte_size(operation) in 1..bounds.operation_bytes and
      Enum.all?(:binary.bin_to_list(operation), &(&1 in 0x20..0x7E))
  end
end
