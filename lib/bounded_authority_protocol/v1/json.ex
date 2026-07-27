defmodule BoundedAuthorityProtocol.V1.Json do
  @moduledoc """
  Bounded JSON decoder preserving object order and rejecting duplicate names.

  Raw numeric lexemes are bounded and magnitude-checked before OTP conversion. The returned
  algebra is closed and never atomizes an input name.
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
    if number_lexemes_valid?(bytes, bounds) do
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
    else
      {:error, :invalid}
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
    value = :erlang.binary_to_integer(token)
    require_valid!(value >= -bounds.integer_magnitude and value <= bounds.integer_magnitude)
    %JsonValue{value: {:integer, value}}
  end

  defp float_node(token, bounds) do
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

  defp number_lexemes_valid?(bytes, bounds), do: scan_json(bytes, bounds)

  defp scan_json(<<>>, _bounds), do: true
  defp scan_json(<<?", rest::binary>>, bounds), do: scan_string(rest, bounds)

  defp scan_json(<<byte, _rest::binary>> = bytes, bounds)
       when byte == ?- or byte in ?0..?9 do
    case number_candidate_length(bytes, 0, bounds.number_lexeme_bytes) do
      {:ok, length} ->
        <<token::binary-size(^length), rest::binary>> = bytes

        valid_number_lexeme?(token, bounds) and scan_json(rest, bounds)

      :too_long ->
        false
    end
  end

  defp scan_json(<<_byte, rest::binary>>, bounds), do: scan_json(rest, bounds)

  defp scan_string(<<>>, _bounds), do: false
  defp scan_string(<<?\\, _escaped, rest::binary>>, bounds), do: scan_string(rest, bounds)
  defp scan_string(<<?", rest::binary>>, bounds), do: scan_json(rest, bounds)
  defp scan_string(<<_byte, rest::binary>>, bounds), do: scan_string(rest, bounds)

  defp number_candidate_length(_bytes, length, maximum) when length > maximum, do: :too_long
  defp number_candidate_length(<<>>, length, _maximum), do: {:ok, length}

  defp number_candidate_length(<<byte, _rest::binary>>, length, _maximum)
       when byte in [0x20, 0x09, 0x0A, 0x0D, 0x2C, 0x5D, 0x7D] do
    {:ok, length}
  end

  defp number_candidate_length(<<_byte, rest::binary>>, length, maximum),
    do: number_candidate_length(rest, length + 1, maximum)

  defp valid_number_lexeme?(token, bounds) do
    byte_size(token) <= bounds.number_lexeme_bytes and
      case parse_number_lexeme(token) do
        {:ok, integer_digits, fraction_digits, exponent} ->
          maximum =
            if float_lexeme?(token),
              do: bounds.float_magnitude,
              else: bounds.integer_magnitude

          magnitude_within?(
            integer_digits <> fraction_digits,
            byte_size(fraction_digits),
            exponent,
            maximum
          )

        :error ->
          false
      end
  end

  defp parse_number_lexeme(<<?-, rest::binary>>), do: parse_unsigned_number(rest)
  defp parse_number_lexeme(bytes), do: parse_unsigned_number(bytes)

  defp float_lexeme?(<<byte, _rest::binary>>) when byte in [?., ?e, ?E], do: true
  defp float_lexeme?(<<_byte, rest::binary>>), do: float_lexeme?(rest)
  defp float_lexeme?(<<>>), do: false

  defp parse_unsigned_number(bytes) do
    with {:ok, integer_digits, rest} <- take_integer_digits(bytes),
         {:ok, fraction_digits, rest} <- take_fraction_digits(rest),
         {:ok, exponent, <<>>} <- take_exponent(rest) do
      {:ok, integer_digits, fraction_digits, exponent}
    else
      _invalid -> :error
    end
  end

  defp take_integer_digits(<<?0, rest::binary>>), do: {:ok, <<"0">>, rest}

  defp take_integer_digits(<<byte, _rest::binary>> = bytes) when byte in ?1..?9 do
    length = digit_count(bytes, 0)
    <<digits::binary-size(^length), rest::binary>> = bytes
    {:ok, digits, rest}
  end

  defp take_integer_digits(_bytes), do: :error

  defp take_fraction_digits(<<?., rest::binary>>) do
    length = digit_count(rest, 0)

    if length > 0 do
      <<digits::binary-size(^length), remainder::binary>> = rest
      {:ok, digits, remainder}
    else
      :error
    end
  end

  defp take_fraction_digits(rest), do: {:ok, <<>>, rest}

  defp take_exponent(<<marker, rest::binary>>) when marker in [?e, ?E] do
    {sign, digits_and_rest} = exponent_sign(rest)
    length = digit_count(digits_and_rest, 0)

    if length > 0 do
      <<digits::binary-size(^length), remainder::binary>> = digits_and_rest
      {:ok, sign * :erlang.binary_to_integer(digits), remainder}
    else
      :error
    end
  end

  defp take_exponent(rest), do: {:ok, 0, rest}

  defp exponent_sign(<<?+, rest::binary>>), do: {1, rest}
  defp exponent_sign(<<?-, rest::binary>>), do: {-1, rest}
  defp exponent_sign(rest), do: {1, rest}

  defp digit_count(<<byte, rest::binary>>, count) when byte in ?0..?9,
    do: digit_count(rest, count + 1)

  defp digit_count(_rest, count), do: count

  defp magnitude_within?(digits, fraction_length, exponent, maximum) do
    case trim_leading_zeroes(digits) do
      <<>> ->
        true

      significant ->
        maximum_digits = :erlang.integer_to_binary(maximum)
        integer_length = byte_size(significant) + exponent - fraction_length

        cond do
          integer_length < byte_size(maximum_digits) ->
            true

          integer_length > byte_size(maximum_digits) ->
            false

          true ->
            compare_boundary(significant, maximum_digits)
        end
    end
  end

  defp compare_boundary(significant, maximum_digits) do
    maximum_length = byte_size(maximum_digits)

    {integer_part, fractional_part} =
      if byte_size(significant) >= maximum_length do
        {
          :erlang.binary_part(significant, 0, maximum_length),
          :erlang.binary_part(
            significant,
            maximum_length,
            byte_size(significant) - maximum_length
          )
        }
      else
        {
          significant <> :binary.copy(<<"0">>, maximum_length - byte_size(significant)),
          <<>>
        }
      end

    integer_part < maximum_digits or
      (integer_part == maximum_digits and zero_digits?(fractional_part))
  end

  defp trim_leading_zeroes(<<?0, rest::binary>>), do: trim_leading_zeroes(rest)
  defp trim_leading_zeroes(rest), do: rest

  defp zero_digits?(<<>>), do: true
  defp zero_digits?(<<?0, rest::binary>>), do: zero_digits?(rest)
  defp zero_digits?(_digits), do: false

  defp reverse([], accumulator), do: accumulator
  defp reverse([head | tail], accumulator), do: reverse(tail, [head | accumulator])

  defp require_valid!(true), do: :ok
  defp require_valid!(false), do: raise(Violation)
end
