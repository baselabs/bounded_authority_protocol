defmodule BoundedAuthorityProtocol.V1.Jcs do
  @moduledoc """
  Bounded RFC 8785 serialization for the closed v1 tagged JSON algebra.
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Violation

  @doc "Encodes one tagged JSON value as bounded RFC 8785 bytes."
  @spec encode(BoundedAuthorityProtocol.V1.Json.value(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def encode(value, limits) do
    case Bounds.coerce(limits) do
      {:ok, bounds} ->
        try do
          {encoded, _nodes} = encode_value(value, bounds, 0, 0)
          {:ok, :erlang.iolist_to_binary(encoded)}
        rescue
          _error in [Violation, ArgumentError, ErlangError] -> {:error, :invalid}
        end

      {:error, :invalid} ->
        {:error, :invalid}
    end
  end

  defp encode_value(:null, bounds, level, nodes) do
    require_valid!(level <= bounds.depth)
    {bounded(<<"null">>, bounds), next_node!(nodes, bounds)}
  end

  defp encode_value({:boolean, value}, bounds, level, nodes) when is_boolean(value) do
    require_valid!(level <= bounds.depth)
    encoded = if value, do: <<"true">>, else: <<"false">>
    {bounded(encoded, bounds), next_node!(nodes, bounds)}
  end

  defp encode_value({:integer, value}, bounds, level, nodes) when is_integer(value) do
    require_valid!(
      level <= bounds.depth and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude
    )

    {bounded(Integer.to_string(value), bounds), next_node!(nodes, bounds)}
  end

  defp encode_value({:float, value}, bounds, level, nodes) when is_float(value) do
    require_valid!(
      level <= bounds.depth and value >= -bounds.float_magnitude and
        value <= bounds.float_magnitude
    )

    {bounded(ecmascript_number(value), bounds), next_node!(nodes, bounds)}
  end

  defp encode_value({:string, value}, bounds, level, nodes) when is_binary(value) do
    require_valid!(
      level <= bounds.depth and byte_size(value) <= bounds.string_bytes and String.valid?(value)
    )

    {bounded(escape_string(value), bounds), next_node!(nodes, bounds)}
  end

  defp encode_value({:array, values}, bounds, level, nodes) when is_list(values) do
    require_valid!(level < bounds.depth and length_bounded?(values, bounds.array_items))
    nodes = next_node!(nodes, bounds)

    {parts, nodes} =
      Enum.map_reduce(values, nodes, fn value, count ->
        encode_value(value, bounds, level + 1, count)
      end)

    {bounded([?[, join(parts, ?,), ?]], bounds), nodes}
  end

  defp encode_value({:object, members}, bounds, level, nodes) when is_list(members) do
    require_valid!(level < bounds.depth and length_bounded?(members, bounds.object_members))
    nodes = next_node!(nodes, bounds)

    sorted =
      Enum.map(members, fn
        {key, value} when is_binary(key) ->
          require_valid!(byte_size(key) <= bounds.key_bytes and String.valid?(key))
          {utf16_key(key), key, value}

        _invalid ->
          raise Violation
      end)
      |> Enum.sort_by(&elem(&1, 0))

    keys = Enum.map(sorted, &elem(&1, 1))
    require_valid!(MapSet.size(MapSet.new(keys)) == length(keys))

    {parts, nodes} =
      Enum.map_reduce(sorted, nodes, fn {_sort_key, key, value}, count ->
        {encoded, next_count} = encode_value(value, bounds, level + 1, count)
        {[escape_string(key), ?:, encoded], next_count}
      end)

    {bounded([?{, join(parts, ?,), ?}], bounds), nodes}
  end

  defp encode_value(_value, _bounds, _level, _nodes), do: raise(Violation)

  defp next_node!(nodes, bounds) do
    next = nodes + 1
    require_valid!(next <= bounds.total_nodes)
    next
  end

  defp length_bounded?(values, maximum), do: length_bounded?(values, maximum, 0)
  defp length_bounded?([], _maximum, _count), do: true
  defp length_bounded?(_values, maximum, count) when count >= maximum, do: false

  defp length_bounded?([_value | rest], maximum, count),
    do: length_bounded?(rest, maximum, count + 1)

  defp bounded(iodata, bounds) do
    require_valid!(:erlang.iolist_size(iodata) <= bounds.jcs_bytes)
    iodata
  end

  defp join([], _separator), do: []
  defp join([part], _separator), do: part
  defp join([part | rest], separator), do: [part, separator, join(rest, separator)]

  defp utf16_key(key) do
    :unicode.characters_to_binary(key, :utf8, {:utf16, :big})
  end

  defp escape_string(value), do: [?", escape_codepoints(value), ?"]

  defp escape_codepoints(<<>>), do: []
  defp escape_codepoints(<<?", rest::binary>>), do: [<<"\\\"">> | escape_codepoints(rest)]
  defp escape_codepoints(<<?\\, rest::binary>>), do: [<<"\\\\">> | escape_codepoints(rest)]
  defp escape_codepoints(<<0x08, rest::binary>>), do: [<<"\\b">> | escape_codepoints(rest)]
  defp escape_codepoints(<<0x09, rest::binary>>), do: [<<"\\t">> | escape_codepoints(rest)]
  defp escape_codepoints(<<0x0A, rest::binary>>), do: [<<"\\n">> | escape_codepoints(rest)]
  defp escape_codepoints(<<0x0C, rest::binary>>), do: [<<"\\f">> | escape_codepoints(rest)]
  defp escape_codepoints(<<0x0D, rest::binary>>), do: [<<"\\r">> | escape_codepoints(rest)]

  defp escape_codepoints(<<byte, rest::binary>>) when byte < 0x20 do
    hex = byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
    [<<"\\u", hex::binary>> | escape_codepoints(rest)]
  end

  defp escape_codepoints(<<codepoint::utf8, rest::binary>>),
    do: [<<codepoint::utf8>> | escape_codepoints(rest)]

  defp ecmascript_number(value) when value == 0.0, do: <<"0">>

  defp ecmascript_number(value) do
    {sign, magnitude} =
      if value < 0.0 do
        {<<"-">>, -value}
      else
        {<<>>, value}
      end

    raw = :erlang.float_to_binary(magnitude, [:short])
    {mantissa, exponent} = split_exponent(raw)
    {digits, decimal_index} = decimal_digits(mantissa, exponent)
    digits = trim_trailing_zeroes(digits)
    scientific_exponent = decimal_index - 1

    body =
      if scientific_exponent < -6 or scientific_exponent >= 21 do
        scientific(digits, scientific_exponent)
      else
        fixed(digits, decimal_index)
      end

    sign <> body
  end

  defp split_exponent(raw) do
    case :binary.split(raw, <<"e">>) do
      [mantissa, exponent] -> {mantissa, :erlang.binary_to_integer(exponent)}
      [mantissa] -> {mantissa, 0}
    end
  end

  defp decimal_digits(mantissa, exponent) do
    [integer, fraction] = :binary.split(mantissa, <<".">>)
    {integer <> fraction, byte_size(integer) + exponent}
  end

  defp trim_trailing_zeroes(<<digit>>) when digit in ?0..?9, do: <<digit>>

  defp trim_trailing_zeroes(digits) do
    size = byte_size(digits)

    if :binary.at(digits, size - 1) == ?0 do
      trim_trailing_zeroes(binary_part(digits, 0, size - 1))
    else
      digits
    end
  end

  defp scientific(<<first, rest::binary>>, exponent) do
    mantissa = if rest == <<>>, do: <<first>>, else: <<first, ?., rest::binary>>
    sign = if exponent >= 0, do: <<"+">>, else: <<>>
    mantissa <> <<"e">> <> sign <> Integer.to_string(exponent)
  end

  defp fixed(digits, decimal_index) when decimal_index <= 0,
    do: <<"0.", :binary.copy(<<"0">>, -decimal_index)::binary, digits::binary>>

  defp fixed(digits, decimal_index) when decimal_index >= byte_size(digits),
    do: digits <> :binary.copy(<<"0">>, decimal_index - byte_size(digits))

  defp fixed(digits, decimal_index) do
    <<integer::binary-size(decimal_index), fraction::binary>> = digits
    <<integer::binary, ?., fraction::binary>>
  end

  defp require_valid!(true), do: :ok
  defp require_valid!(false), do: raise(Violation)
end
