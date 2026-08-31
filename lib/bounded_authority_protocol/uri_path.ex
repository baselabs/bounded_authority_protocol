defmodule BoundedAuthorityProtocol.UriPath do
  @moduledoc false

  @unreserved ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
  @sub_delims ~c"!$&'()*+,;="

  @spec normalize(binary()) :: {:ok, binary()} | {:error, :invalid}
  def normalize(<<>>), do: {:ok, <<"/">>}

  def normalize(<<?/, _rest::binary>> = path) do
    with {:ok, percent_normalized} <- normalize_bytes(path, []),
         normalized <- remove_dot_segments(percent_normalized, <<>>),
         true <- normalized != <<>> do
      {:ok, normalized}
    else
      _failure -> {:error, :invalid}
    end
  end

  def normalize(_path), do: {:error, :invalid}

  defp normalize_bytes(<<>>, accumulator),
    do: {:ok, accumulator |> Enum.reverse() |> :erlang.iolist_to_binary()}

  defp normalize_bytes(<<?%, high, low, rest::binary>>, accumulator)
       when high in ~c"0123456789ABCDEFabcdef" and low in ~c"0123456789ABCDEFabcdef" do
    byte = hex_value(high) * 16 + hex_value(low)

    encoded =
      if byte in @unreserved do
        <<byte>>
      else
        <<?%, upper_hex(high), upper_hex(low)>>
      end

    normalize_bytes(rest, [encoded | accumulator])
  end

  defp normalize_bytes(<<?%, _rest::binary>>, _accumulator), do: {:error, :invalid}

  defp normalize_bytes(<<byte, rest::binary>>, accumulator)
       when byte in @unreserved or byte in @sub_delims or byte in ~c"/:@" do
    normalize_bytes(rest, [<<byte>> | accumulator])
  end

  defp normalize_bytes(_path, _accumulator), do: {:error, :invalid}

  defp remove_dot_segments(<<"/./", rest::binary>>, output),
    do: remove_dot_segments(<<"/", rest::binary>>, output)

  defp remove_dot_segments(<<"/.">>, output), do: output <> <<"/">>

  defp remove_dot_segments(<<"/../", rest::binary>>, output),
    do: remove_dot_segments(<<"/", rest::binary>>, remove_last_segment(output))

  defp remove_dot_segments(<<"/..">>, output), do: remove_last_segment(output) <> <<"/">>
  defp remove_dot_segments(<<>>, output), do: output

  defp remove_dot_segments(path, output) do
    length = first_segment_length(path)
    <<segment::binary-size(^length), rest::binary>> = path
    remove_dot_segments(rest, output <> segment)
  end

  defp first_segment_length(<<?/, rest::binary>>), do: 1 + until_slash(rest, 0)
  defp until_slash(<<>>, count), do: count
  defp until_slash(<<?/, _rest::binary>>, count), do: count
  defp until_slash(<<_byte, rest::binary>>, count), do: until_slash(rest, count + 1)

  defp remove_last_segment(output) do
    case :binary.matches(output, <<"/">>) do
      [] ->
        <<>>

      matches ->
        {index, 1} = List.last(matches)
        binary_part(output, 0, index)
    end
  end

  defp hex_value(byte) when byte in ?0..?9, do: byte - ?0
  defp hex_value(byte) when byte in ?A..?F, do: byte - ?A + 10
  defp hex_value(byte) when byte in ?a..?f, do: byte - ?a + 10
  defp upper_hex(byte) when byte in ?a..?f, do: byte - 32
  defp upper_hex(byte), do: byte
end
