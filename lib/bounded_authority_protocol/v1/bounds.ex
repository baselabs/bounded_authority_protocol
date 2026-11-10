defmodule BoundedAuthorityProtocol.V1.Bounds do
  @moduledoc """
  Resource ceilings for every contract-major and sibling profile.

  Every public function that takes `limits` accepts either a `%Bounds{}` struct or a map of
  tightening overrides such as `%{depth: 8}`. An empty map means the profile maxima. Callers
  may tighten any ceiling to a smaller positive integer; nobody can widen one, and the three
  cryptographic widths (`public_key_bytes`, `signature_bytes`, `digest_bytes`) are fixed.

  Every field defaults to its profile maximum, so `%Bounds{}` equals `maximum/0` and
  `%Bounds{depth: 8}` tightens one ceiling. A struct built by hand is still validated:
  `coerce/1` (which every verifier calls) returns `{:error, :invalid}` for a widened, zero,
  negative, non-integer or fixed-width-changing value. A later minor release may add a field;
  it will default to its maximum, so existing `%Bounds{...}` literals keep compiling.

  ## Fields

  Units are bytes unless the field counts items or seconds.

  | Field | Maximum | What it bounds |
  |---|---:|---|
  | `compact_bytes` | 65,536 | bytes in one compact JWS (grant, proof, attestation or assertion) before decoding |
  | `content_bytes` | 65,536 | bytes of content hashed by the content-assertion profile's `content_digest/2` |
  | `encoded_segment_bytes` | 32,768 | bytes of one base64url segment before decoding |
  | `decoded_segment_bytes` | 24,576 | bytes of one base64url segment after decoding |
  | `json_bytes` | 65,536 | raw JSON bytes handed to the decoder |
  | `depth` | 32 | JSON nesting depth (the root container is level 0) |
  | `object_members` | 64 | members in one JSON object |
  | `array_items` | 256 | items in one JSON array |
  | `total_nodes` | 4,096 | JSON value nodes in one document, containers and scalars alike |
  | `string_bytes` | 8,192 | UTF-8 bytes in one JSON string |
  | `key_bytes` | 128 | UTF-8 bytes in one JSON object member name |
  | `number_lexeme_bytes` | 64 | bytes of one JSON number as written |
  | `integer_magnitude` | 9,007,199,254,740,991 | absolute value of a JSON integer (2^53 - 1) |
  | `float_magnitude` | 9,007,199,254,740,991 | absolute value of a JSON float |
  | `kid_bytes` | 128 | bytes of a JWS `kid` header value |
  | `jcs_bytes` | 65,536 | bytes of one RFC 8785 (JCS) serialization the library produces |
  | `uri_bytes` | 8,192 | bytes of a normalized target URI |
  | `identifier_bytes` | 512 | bytes of an issuer, audience or token identifier |
  | `nonce_bytes` | 512 | bytes of a proof nonce |
  | `method_bytes` | 32 | bytes of an HTTP method |
  | `operation_bytes` | 128 | bytes of an operation name |
  | `audiences` | 64 | audiences in one grant |
  | `operations` | 64 | operations in one grant |
  | `selectors` | 64 | selectors in one operation |
  | `path_segments` | 32 | segments in one selector path |
  | `one_of_values` | 256 | values in one `one_of` selector |
  | `public_key_bytes` | 32 | Ed25519 public-key width; fixed |
  | `signature_bytes` | 64 | Ed25519 signature width; fixed |
  | `digest_bytes` | 32 | SHA-256 digest width; fixed |
  | `clock_skew` | 60 | seconds of clock skew a caller may allow |
  | `proof_max_age` | 300 | seconds a proof may age |
  | `chain_row_bytes` | 4,096 | bytes of one canonical consumption-chain row |
  | `chain_rows` | 65,536 | consumption-chain rows in one checked range |
  | `anchor_bytes` | 8,192 | bytes of one boundary-anchor or key-transition compact |
  | `archive_header_bytes` | 8,192 | bytes of an anchored-export header |
  | `archive_chunks` | 65,796 | chunks in one anchored export |
  | `archive_bytes` | 270,820,384 | bytes of one anchored export |
  | `object_version_bytes` | 512 | bytes of an object-store version identifier |
  | `key_transitions` | 256 | historical key transitions in one export |
  """

  @maximum %{
    compact_bytes: 65_536,
    content_bytes: 65_536,
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

  defstruct Map.to_list(@maximum)

  @typedoc """
  Validated resource ceilings. Every field is a positive integer no larger than its profile
  maximum (see the table in the module documentation); the fixed widths equal their maxima.
  """
  @type t :: %__MODULE__{
          compact_bytes: pos_integer(),
          content_bytes: pos_integer(),
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

  @doc """
  Validates caller limits given either as a `Bounds` struct or as a map of tightening
  overrides, returning the complete struct. Every key must name a known bound, every value must
  be a positive integer no larger than its profile maximum, and the fixed widths cannot change;
  anything else returns `{:error, :invalid}`.
  """
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
