defmodule BoundedAuthorityProtocol.V1.Json do
  @moduledoc """
  Bounded JSON decoder preserving object order and rejecting duplicate names.

  The returned algebra is closed and never atomizes an input name.
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Violation

  defmodule JsonValue do
    @moduledoc false
    defstruct [:value, nodes: 1, depth: 0]
  end

  defmodule Root do
    @moduledoc false
    defstruct level: 0
  end

  defmodule Container do
    @moduledoc false
    defstruct [:kind, :level, values: [], seen: %{}, count: 0, nodes: 0, depth: 0]
  end

  @typedoc "Closed v1 JSON value algebra."
  @type value ::
          :null
          | {:boolean, boolean()}
          | {:integer, integer()}
          | {:float, float()}
          | {:string, binary()}
          | {:array, [value()]}
          | {:object, [{binary(), value()}]}

  @doc "Decodes one complete bounded JSON value."
  @spec decode(binary(), Bounds.t() | map()) :: {:ok, value()} | {:error, :invalid}
  def decode(bytes, limits \\ %{})

  def decode(bytes, limits) when is_binary(bytes) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(bytes) <= bounds.json_bytes do
      decode_bounded(bytes, bounds)
    else
      _failure -> {:error, :invalid}
    end
  end

  def decode(_bytes, _limits), do: {:error, :invalid}

  defp decode_bounded(bytes, bounds) do
    decoders = %{
      array_start: fn parent -> start_container(:array, parent, bounds) end,
      array_push: fn value, container -> push_array(value, container, bounds) end,
      array_finish: fn container, parent -> finish_container(container, parent, bounds) end,
      object_start: fn parent -> start_container(:object, parent, bounds) end,
      object_push: fn key, value, container -> push_object(key, value, container, bounds) end,
      object_finish: fn container, parent -> finish_container(container, parent, bounds) end,
      integer: fn token -> integer_node(token, bounds) end,
      float: fn token -> float_node(token, bounds) end,
      string: fn string -> string_node(string, bounds) end,
      null: %JsonValue{value: :null}
    }

    try do
      case :json.decode(bytes, %Root{}, decoders) do
        {value, _accumulator, rest} ->
          node = normalize_node(value)

          if whitespace_only?(rest) and node.nodes <= bounds.total_nodes do
            {:ok, node.value}
          else
            {:error, :invalid}
          end
      end
    rescue
      _error in [Violation, ArgumentError, ErlangError] -> {:error, :invalid}
    end
  end

  defp start_container(kind, parent, bounds) do
    level = parent_level(parent) + 1
    require_valid!(level <= bounds.depth)
    %Container{kind: kind, level: level}
  end

  defp push_array(value, %Container{kind: :array} = container, bounds) do
    node = normalize_node(value)
    count = container.count + 1
    nodes = container.nodes + node.nodes
    require_valid!(count <= bounds.array_items and nodes + 1 <= bounds.total_nodes)

    %{
      container
      | values: [node.value | container.values],
        count: count,
        nodes: nodes,
        depth: max(container.depth, node.depth)
    }
  end

  defp push_object(encoded_key, value, %Container{kind: :object} = container, bounds) do
    key = normalize_key(encoded_key)
    node = normalize_node(value)
    count = container.count + 1
    nodes = container.nodes + node.nodes

    require_valid!(
      is_binary(key) and byte_size(key) <= bounds.key_bytes and
        not Map.has_key?(container.seen, key) and count <= bounds.object_members and
        nodes + 1 <= bounds.total_nodes
    )

    %{
      container
      | values: [{key, node.value} | container.values],
        seen: Map.put(container.seen, key, true),
        count: count,
        nodes: nodes,
        depth: max(container.depth, node.depth)
    }
  end

  defp finish_container(container, parent, bounds) do
    node = %JsonValue{
      value: {container.kind, reverse(container.values, [])},
      nodes: container.nodes + 1,
      depth: container.depth + 1
    }

    require_valid!(node.nodes <= bounds.total_nodes and node.depth <= bounds.depth)
    {node, parent}
  end

  defp integer_node(token, bounds) do
    require_valid!(byte_size(token) <= bounds.number_lexeme_bytes)
    value = :erlang.binary_to_integer(token)
    require_valid!(value >= -bounds.integer_magnitude and value <= bounds.integer_magnitude)
    %JsonValue{value: {:integer, value}}
  end

  defp float_node(token, bounds) do
    require_valid!(byte_size(token) <= bounds.number_lexeme_bytes)
    value = :erlang.binary_to_float(token)
    require_valid!(value >= -bounds.float_magnitude and value <= bounds.float_magnitude)
    %JsonValue{value: {:float, value}}
  end

  defp string_node(string, bounds) do
    require_valid!(byte_size(string) <= bounds.string_bytes)
    %JsonValue{value: {:string, string}}
  end

  defp normalize_node(%JsonValue{} = node), do: node
  defp normalize_node(true), do: %JsonValue{value: {:boolean, true}}
  defp normalize_node(false), do: %JsonValue{value: {:boolean, false}}

  defp normalize_key(%JsonValue{value: {:string, key}}), do: key

  defp parent_level(%Root{level: level}), do: level
  defp parent_level(%Container{level: level}), do: level

  defp whitespace_only?(<<>>), do: true

  defp whitespace_only?(<<byte, rest::binary>>) when byte in [0x20, 0x09, 0x0A, 0x0D],
    do: whitespace_only?(rest)

  defp whitespace_only?(_rest), do: false

  defp reverse([], accumulator), do: accumulator
  defp reverse([head | tail], accumulator), do: reverse(tail, [head | accumulator])

  defp require_valid!(true), do: :ok
  defp require_valid!(false), do: raise(Violation)
end
