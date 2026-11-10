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
         {:ok, projected, _nodes} <- typed(cast_arguments, bounds, 1, 2),
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

  # The projection is bounded while it is built. Jcs.encode/2 later checks the projected tree
  # node by node; every check below is one of those checks, made before the walk descends, so the
  # accepted set and the digest bytes are unchanged while a hostile argument tree costs at most
  # the node budget to reject. Each input value becomes a wrapper array (at `level`) holding a
  # type tag and, except for null, the value or its container one level deeper; the children's
  # wrappers sit two levels deeper. `nodes` counts projected nodes so far, starting with the
  # outer `[operation, projection]` array and the operation string.
  defp typed(value, bounds, level, nodes) do
    nodes = nodes + 2

    if level < bounds.depth and nodes <= bounds.total_nodes,
      do: project(value, bounds, level, nodes),
      else: {:error, :invalid}
  end

  defp project(:null, _bounds, _level, nodes), do: {:ok, {:array, [{:string, "null"}]}, nodes}

  defp project({:boolean, value}, bounds, _level, nodes) when is_boolean(value),
    do: scalar("boolean", {:boolean, value}, bounds, nodes)

  defp project({:integer, value}, bounds, _level, nodes) when is_integer(value),
    do: scalar("integer", {:integer, value}, bounds, nodes)

  defp project({:float, value}, bounds, _level, nodes) when is_float(value),
    do: scalar("float", {:float, value}, bounds, nodes)

  defp project({:string, value}, bounds, _level, nodes)
       when is_binary(value) and byte_size(value) <= bounds.string_bytes,
       do: scalar("string", {:string, value}, bounds, nodes)

  defp project({:array, values}, bounds, level, nodes)
       when is_list(values) and level + 1 < bounds.depth and nodes < bounds.total_nodes do
    with {:ok, projected, nodes} <- map_values(values, bounds, level + 2, nodes + 1, 0, []) do
      {:ok, {:array, [{:string, "array"}, {:array, projected}]}, nodes}
    end
  end

  defp project({:object, members}, bounds, level, nodes)
       when is_list(members) and level + 1 < bounds.depth and nodes < bounds.total_nodes do
    with {:ok, projected, nodes} <- map_members(members, bounds, level + 2, nodes + 1, 0, []) do
      {:ok, {:array, [{:string, "object"}, {:object, projected}]}, nodes}
    end
  end

  defp project(_value, _bounds, _level, _nodes), do: {:error, :invalid}

  defp scalar(tag, value, bounds, nodes) when nodes < bounds.total_nodes,
    do: {:ok, {:array, [{:string, tag}, value]}, nodes + 1}

  defp scalar(_tag, _value, _bounds, _nodes), do: {:error, :invalid}

  defp map_values([], _bounds, _level, nodes, _count, accumulator),
    do: {:ok, Enum.reverse(accumulator), nodes}

  defp map_values([value | rest], bounds, level, nodes, count, accumulator)
       when count < bounds.array_items do
    with {:ok, projected, nodes} <- typed(value, bounds, level, nodes) do
      map_values(rest, bounds, level, nodes, count + 1, [projected | accumulator])
    end
  end

  defp map_values(_values, _bounds, _level, _nodes, _count, _accumulator), do: {:error, :invalid}

  defp map_members([], _bounds, _level, nodes, _count, accumulator),
    do: {:ok, Enum.reverse(accumulator), nodes}

  defp map_members([{key, value} | rest], bounds, level, nodes, count, accumulator)
       when is_binary(key) and byte_size(key) <= bounds.key_bytes and
              count < bounds.object_members do
    with {:ok, projected, nodes} <- typed(value, bounds, level, nodes) do
      map_members(rest, bounds, level, nodes, count + 1, [{key, projected} | accumulator])
    end
  end

  defp map_members(_members, _bounds, _level, _nodes, _count, _accumulator),
    do: {:error, :invalid}

  defp valid_operation?(operation, bounds) do
    byte_size(operation) in 1..bounds.operation_bytes and
      Enum.all?(:binary.bin_to_list(operation), &(&1 in 0x20..0x7E))
  end
end
