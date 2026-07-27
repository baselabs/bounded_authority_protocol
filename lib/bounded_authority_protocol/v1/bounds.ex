defmodule BoundedAuthorityProtocol.V1.Bounds do
  @moduledoc """
  Resource ceilings for the v1 wire profile.

  Callers may tighten these ceilings. They cannot widen the v1 profile.
  """

  @enforce_keys [
    :compact_bytes,
    :encoded_segment_bytes,
    :decoded_segment_bytes,
    :json_bytes,
    :depth,
    :object_members,
    :array_items,
    :total_nodes,
    :string_bytes,
    :key_bytes,
    :number_lexeme_bytes,
    :integer_magnitude,
    :float_magnitude,
    :kid_bytes
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          compact_bytes: pos_integer(),
          encoded_segment_bytes: pos_integer(),
          decoded_segment_bytes: pos_integer(),
          json_bytes: pos_integer(),
          depth: pos_integer(),
          object_members: pos_integer(),
          array_items: pos_integer(),
          total_nodes: pos_integer(),
          string_bytes: pos_integer(),
          key_bytes: pos_integer(),
          number_lexeme_bytes: pos_integer(),
          integer_magnitude: pos_integer(),
          float_magnitude: pos_integer(),
          kid_bytes: pos_integer()
        }

  @maximum %{
    compact_bytes: 65_536,
    encoded_segment_bytes: 32_768,
    decoded_segment_bytes: 24_576,
    json_bytes: 65_536,
    depth: 32,
    object_members: 64,
    array_items: 256,
    total_nodes: 4_096,
    string_bytes: 8_192,
    key_bytes: 128,
    number_lexeme_bytes: 64,
    integer_magnitude: 9_007_199_254_740_991,
    float_magnitude: 9_007_199_254_740_991,
    kid_bytes: 128
  }

  @doc "Returns the immutable v1 profile maxima."
  @spec maximum() :: t()
  def maximum, do: struct!(__MODULE__, @maximum)

  @doc "Builds bounds from a map of caller-supplied tightening overrides."
  @spec new(map()) :: {:ok, t()} | {:error, :invalid}
  def new(overrides \\ %{})

  def new(overrides) when is_map(overrides) do
    if valid_keys_and_values?(Map.to_list(overrides)) do
      {:ok, struct!(__MODULE__, Map.merge(@maximum, overrides))}
    else
      {:error, :invalid}
    end
  end

  def new(_overrides), do: {:error, :invalid}

  @spec coerce(t() | map()) :: {:ok, t()} | {:error, :invalid}
  def coerce(%__MODULE__{} = bounds) do
    bounds
    |> Map.from_struct()
    |> new()
  end

  def coerce(overrides), do: new(overrides)

  defp valid_keys_and_values?([]), do: true

  defp valid_keys_and_values?([{key, value} | rest]) do
    case Map.fetch(@maximum, key) do
      {:ok, maximum} when is_integer(maximum) ->
        valid_integer_override?(value, maximum) and valid_keys_and_values?(rest)

      :error ->
        false
    end
  end

  defp valid_integer_override?(value, maximum),
    do: is_integer(value) and value > 0 and value <= maximum
end
