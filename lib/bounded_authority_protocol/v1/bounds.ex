defmodule BoundedAuthorityProtocol.V1.Bounds do
  @moduledoc """
  Resource ceilings for the v1 wire profile.

  Callers may tighten resource ceilings. Cryptographic widths are immutable.
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
    :kid_bytes,
    :jcs_bytes,
    :uri_bytes,
    :identifier_bytes,
    :nonce_bytes,
    :method_bytes,
    :operation_bytes,
    :audiences,
    :operations,
    :selectors,
    :path_segments,
    :one_of_values,
    :public_key_bytes,
    :signature_bytes,
    :digest_bytes,
    :clock_skew,
    :proof_max_age,
    :chain_row_bytes,
    :chain_rows,
    :anchor_bytes,
    :archive_header_bytes,
    :archive_chunks,
    :archive_bytes,
    :object_version_bytes,
    :key_transitions
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
          kid_bytes: pos_integer(),
          jcs_bytes: pos_integer(),
          uri_bytes: pos_integer(),
          identifier_bytes: pos_integer(),
          nonce_bytes: pos_integer(),
          method_bytes: pos_integer(),
          operation_bytes: pos_integer(),
          audiences: pos_integer(),
          operations: pos_integer(),
          selectors: pos_integer(),
          path_segments: pos_integer(),
          one_of_values: pos_integer(),
          public_key_bytes: pos_integer(),
          signature_bytes: pos_integer(),
          digest_bytes: pos_integer(),
          clock_skew: pos_integer(),
          proof_max_age: pos_integer(),
          chain_row_bytes: pos_integer(),
          chain_rows: pos_integer(),
          anchor_bytes: pos_integer(),
          archive_header_bytes: pos_integer(),
          archive_chunks: pos_integer(),
          archive_bytes: pos_integer(),
          object_version_bytes: pos_integer(),
          key_transitions: pos_integer()
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
    kid_bytes: 128,
    jcs_bytes: 65_536,
    uri_bytes: 8_192,
    identifier_bytes: 512,
    nonce_bytes: 512,
    method_bytes: 32,
    operation_bytes: 128,
    audiences: 64,
    operations: 64,
    selectors: 64,
    path_segments: 32,
    one_of_values: 256,
    public_key_bytes: 32,
    signature_bytes: 64,
    digest_bytes: 32,
    clock_skew: 60,
    proof_max_age: 300,
    chain_row_bytes: 4_096,
    chain_rows: 65_536,
    anchor_bytes: 8_192,
    archive_header_bytes: 8_192,
    archive_chunks: 65_796,
    archive_bytes: 270_820_384,
    object_version_bytes: 512,
    key_transitions: 256
  }
  @fixed_width_keys [:digest_bytes, :public_key_bytes, :signature_bytes]

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
        valid_override?(key, value, maximum) and valid_keys_and_values?(rest)

      :error ->
        false
    end
  end

  defp valid_integer_override?(value, maximum),
    do: is_integer(value) and value > 0 and value <= maximum

  defp valid_override?(key, value, maximum) when key in @fixed_width_keys,
    do: value == maximum

  defp valid_override?(_key, value, maximum), do: valid_integer_override?(value, maximum)
end
