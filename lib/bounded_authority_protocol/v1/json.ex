defmodule BoundedAuthorityProtocol.V1.Json do
  @moduledoc """
  Bounded JSON conversion rejecting duplicate binary names.

  `decode/2` preserves object order and returns the tagged, closed v1 algebra documented by
  `t:value/0`; it never atomizes an input name. Raw numeric lexemes are byte-bounded and
  exact-magnitude-checked before OTP conversion. Caller limits may only tighten the
  positive-integer hard maxima. Every failure is the fixed value-free `{:error, :invalid}`.

  `from_term/2` converts already-parsed, cast Elixir terms into the same algebra, sorting object
  members by binary name. It preserves numeric tags and applies the same structural bounds.

  Draft 2020-12 schemas shipped with the package describe structural shape. They do not replace
  this decoder's duplicate-name, raw-lexeme, UTF-8 byte, depth, node, or exact encoding checks.
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

  @doc """
  Decodes one complete bounded JSON value.

  ## Examples

      iex> BoundedAuthorityProtocol.V1.Json.decode("1", %{})
      {:ok, {:integer, 1}}
      iex> BoundedAuthorityProtocol.V1.Json.decode("1.0")
      {:ok, {:float, 1.0}}
      iex> BoundedAuthorityProtocol.V1.Json.decode(~s({"x":1,"x":2}), %{})
      {:error, :invalid}
  """
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

  @doc false
  def decode_approval_record(bytes, string_bytes, resource_count)
      when is_binary(bytes) and byte_size(bytes) <= 65_536 and string_bytes in 1..1_024 and
             resource_count in 1..4_096 do
    decode_bounded(bytes, %{
      depth: 2,
      object_members: 7,
      array_items: resource_count,
      total_nodes: resource_count + 8,
      string_bytes: max(string_bytes, 43),
      key_bytes: 15,
      number_lexeme_bytes: 1,
      integer_magnitude: 1,
      float_magnitude: 1
    })
  end

  def decode_approval_record(_, _, _), do: {:error, :invalid}

  @doc """
  Converts an already-parsed, cast Elixir term into one bounded tagged JSON value.

  Accepts `nil`, booleans, integers, floats, UTF-8 binaries, lists, and plain maps. Map keys
  must be binaries or atoms other than `nil`, `true`, and `false`; atom keys become strings.
  Object members are sorted by binary name, and colliding names are invalid. Structs,
  tuples, other atoms, improper lists, and all other terms are refused without coercion.
  Cast arguments to their declared types before conversion: `4.0` stays float-tagged.

  Limits accept a `Bounds` struct or tightening map, as in `decode/2`. Depth, object members,
  array items, total nodes, UTF-8 string and key bytes, and numeric magnitudes are bounded
  with the decoder's counting rules. `json_bytes` and `number_lexeme_bytes` bound raw text
  and do not apply to terms. Every failure returns the value-free `{:error, :invalid}`.
  The result is shared by all three contract-majors.

  ## Examples

      iex> BoundedAuthorityProtocol.V1.Json.from_term(%{rows: 4, ratio: 4.0})
      {:ok, {:object, [{"ratio", {:float, 4.0}}, {"rows", {:integer, 4}}]}}
      iex> BoundedAuthorityProtocol.V1.Json.from_term([nil, true, "ok"], %{array_items: 3})
      {:ok, {:array, [:null, {:boolean, true}, {:string, "ok"}]}}
      iex> BoundedAuthorityProtocol.V1.Json.from_term(%{:rows => 4, "rows" => 4})
      {:error, :invalid}
      iex> BoundedAuthorityProtocol.V1.Json.from_term("abc", %{string_bytes: 2})
      {:error, :invalid}
  """
  @spec from_term(term(), Bounds.t() | map()) :: {:ok, value()} | {:error, :invalid}
  def from_term(term, limits \\ %{}) do
    case Bounds.coerce(limits) do
      {:ok, bounds} ->
        try do
          %JsonValue{value: value} = term_node(term, %Root{}, bounds)
          {:ok, value}
        rescue
          _error in [Violation, ArgumentError, ErlangError] -> {:error, :invalid}
        end

      {:error, :invalid} ->
        {:error, :invalid}
    end
  end

  defp term_node(nil, _parent, _bounds), do: %JsonValue{value: :null}
  defp term_node(value, _parent, _bounds) when is_boolean(value), do: normalize_node(value)
  defp term_node(value, _parent, bounds) when is_integer(value), do: integer_node(value, bounds)
  defp term_node(value, _parent, bounds) when is_float(value), do: float_node(value, bounds)

  defp term_node(value, _parent, bounds) when is_binary(value), do: string_node(value, bounds)

  defp term_node(values, parent, bounds) when is_list(values) do
    container = start_container(:array, parent, bounds)
    {node, _parent} = finish_container(term_items(values, container, bounds), parent, bounds)
    node
  end

  defp term_node(%{__struct__: _}, _parent, _bounds), do: raise(Violation)

  defp term_node(%{} = map, parent, bounds) do
    require_valid!(map_size(map) <= bounds.object_members)
    container = start_container(:object, parent, bounds)
    container = term_members(Map.to_list(map), container, bounds)

    {%JsonValue{value: {:object, members}} = node, _parent} =
      finish_container(container, parent, bounds)

    %{node | value: {:object, Enum.sort(members)}}
  end

  defp term_node(_value, _parent, _bounds), do: raise(Violation)

  defp term_items([], container, _bounds), do: container

  defp term_items([value | rest], container, bounds) do
    node = term_node(value, container, bounds)
    term_items(rest, push_array(node, container, bounds), bounds)
  end

  defp term_items(_improper, _container, _bounds), do: raise(Violation)

  defp term_members([], container, _bounds), do: container

  defp term_members([{key, value} | rest], container, bounds) do
    name = term_key(key)
    encoded_key = %JsonValue{value: {:string, name}}
    node = term_node(value, container, bounds)
    term_members(rest, push_object(encoded_key, node, container, bounds), bounds)
  end

  defp term_key(key) when is_binary(key), do: key

  defp term_key(key) when is_atom(key) and key not in [nil, true, false],
    do: Atom.to_string(key)

  defp term_key(_key), do: raise(Violation)

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
      is_binary(key) and byte_size(key) <= bounds.key_bytes and String.valid?(key) and
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

  defp integer_node(token, bounds) when is_binary(token),
    do: integer_node(:erlang.binary_to_integer(token), bounds)

  defp integer_node(value, bounds) do
    require_valid!(value >= -bounds.integer_magnitude and value <= bounds.integer_magnitude)
    %JsonValue{value: {:integer, value}}
  end

  defp float_node(token, bounds) when is_binary(token),
    do: float_node(:erlang.binary_to_float(token), bounds)

  defp float_node(value, bounds) do
    require_valid!(value >= -bounds.float_magnitude and value <= bounds.float_magnitude)
    %JsonValue{value: {:float, value}}
  end

  defp string_node(string, bounds) do
    require_valid!(byte_size(string) <= bounds.string_bytes and String.valid?(string))
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
