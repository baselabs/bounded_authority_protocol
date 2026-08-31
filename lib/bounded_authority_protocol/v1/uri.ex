defmodule BoundedAuthorityProtocol.V1.Uri do
  @moduledoc """
  Pure bounded normalization for hierarchical HTTPS DPoP target URIs.
  """

  alias BoundedAuthorityProtocol.UriPath
  alias BoundedAuthorityProtocol.V1.Bounds

  @unreserved ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
  @sub_delims ~c"!$&'()*+,;="

  @doc "Normalizes one bounded hierarchical HTTPS target URI."
  @spec normalize(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def normalize(uri, limits) when is_binary(uri) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(uri) <= bounds.uri_bytes,
         true <- ascii_uri?(uri),
         {:ok, authority, raw_path} <- split_https(uri),
         {:ok, host, port} <- normalize_authority(authority),
         {:ok, path} <- UriPath.normalize(raw_path),
         normalized <- build_uri(host, port, path),
         true <- byte_size(normalized) <= bounds.uri_bytes do
      {:ok, normalized}
    else
      _failure -> {:error, :invalid}
    end
  end

  def normalize(_uri, _limits), do: {:error, :invalid}

  defp ascii_uri?(<<>>), do: false

  defp ascii_uri?(uri) do
    Enum.all?(:binary.bin_to_list(uri), fn byte -> byte >= 0x21 and byte <= 0x7E end)
  end

  defp split_https(uri) do
    case :binary.match(uri, <<"://">>) do
      {index, 3} ->
        scheme = binary_part(uri, 0, index)
        rest = binary_part(uri, index + 3, byte_size(uri) - index - 3)

        with true <- ascii_downcase(scheme) == <<"https">>,
             false <- contains_any?(rest, [??, ?#]),
             {authority, path} <- split_authority_path(rest),
             true <- authority != <<>> do
          {:ok, authority, path}
        else
          _failure -> {:error, :invalid}
        end

      :nomatch ->
        {:error, :invalid}
    end
  end

  defp split_authority_path(rest) do
    case :binary.match(rest, <<"/">>) do
      {index, 1} ->
        {
          binary_part(rest, 0, index),
          binary_part(rest, index, byte_size(rest) - index)
        }

      :nomatch ->
        {rest, <<>>}
    end
  end

  defp normalize_authority(authority) do
    if :binary.match(authority, <<"@">>) != :nomatch do
      {:error, :invalid}
    else
      parse_host_port(authority)
    end
  end

  defp parse_host_port(<<?[, rest::binary>>) do
    case :binary.match(rest, <<"]">>) do
      {index, 1} ->
        host = binary_part(rest, 0, index)
        suffix = binary_part(rest, index + 1, byte_size(rest) - index - 1)

        with true <- valid_ip_literal?(host),
             {:ok, port} <- parse_port_suffix(suffix) do
          {:ok, <<?[, ascii_downcase(host)::binary, ?]>>, port}
        else
          _failure -> {:error, :invalid}
        end

      :nomatch ->
        {:error, :invalid}
    end
  end

  defp parse_host_port(authority) do
    case :binary.matches(authority, <<":">>) do
      [] ->
        normalize_registered_host(authority, nil)

      [{index, 1}] ->
        host = binary_part(authority, 0, index)
        port = binary_part(authority, index + 1, byte_size(authority) - index - 1)

        with {:ok, parsed_port} <- parse_port(port) do
          normalize_registered_host(host, parsed_port)
        end

      _multiple ->
        {:error, :invalid}
    end
  end

  defp normalize_registered_host(host, port) do
    if host != <<>> and valid_registered_host?(host) do
      {:ok, normalize_reg_name_bytes(host, []), port}
    else
      {:error, :invalid}
    end
  end

  defp normalize_reg_name_bytes(<<>>, accumulator),
    do: accumulator |> Enum.reverse() |> :erlang.iolist_to_binary()

  defp normalize_reg_name_bytes(<<?%, high, low, rest::binary>>, accumulator) do
    byte = hex_value(high) * 16 + hex_value(low)

    normalized =
      if byte in @unreserved do
        ascii_downcase(<<byte>>)
      else
        <<?%, upper_hex(high), upper_hex(low)>>
      end

    normalize_reg_name_bytes(rest, [normalized | accumulator])
  end

  defp normalize_reg_name_bytes(<<byte, rest::binary>>, accumulator) do
    normalize_reg_name_bytes(rest, [ascii_downcase(<<byte>>) | accumulator])
  end

  defp valid_registered_host?(host) do
    bytes = :binary.bin_to_list(host)

    if Enum.all?(bytes, &(&1 in ?0..?9 or &1 == ?.)) and ?. in bytes do
      valid_ipv4_tail?(host)
    else
      valid_reg_name_bytes?(host)
    end
  end

  defp valid_ip_literal?(<<?v, rest::binary>>), do: valid_ipv_future?(rest)
  defp valid_ip_literal?(<<?V, rest::binary>>), do: valid_ipv_future?(rest)
  defp valid_ip_literal?(host), do: valid_ipv6_literal?(host)

  defp valid_ipv_future?(value) do
    case :binary.split(value, <<".">>) do
      [version, address] ->
        version != <<>> and address != <<>> and
          Enum.all?(:binary.bin_to_list(version), &(&1 in ~c"0123456789ABCDEFabcdef")) and
          Enum.all?(:binary.bin_to_list(address), fn byte ->
            byte in @unreserved or byte in @sub_delims or byte == ?:
          end)

      _invalid ->
        false
    end
  end

  defp valid_reg_name_bytes?(<<>>), do: true

  defp valid_reg_name_bytes?(<<?%, high, low, rest::binary>>)
       when high in ~c"0123456789ABCDEFabcdef" and low in ~c"0123456789ABCDEFabcdef",
       do: valid_reg_name_bytes?(rest)

  defp valid_reg_name_bytes?(<<byte, rest::binary>>)
       when byte in @unreserved or byte in @sub_delims,
       do: valid_reg_name_bytes?(rest)

  defp valid_reg_name_bytes?(_host), do: false

  defp valid_ipv6_literal?(host) do
    case :binary.split(host, <<"::">>, [:global]) do
      [side] ->
        match?({:ok, 8}, ipv6_side_length(side))

      [left, right] ->
        with {:ok, left_length} <- ipv6_side_length(left),
             {:ok, right_length} <- ipv6_side_length(right) do
          left_length + right_length < 8
        else
          _failure -> false
        end

      _multiple_compressions ->
        false
    end
  end

  defp ipv6_side_length(<<>>), do: {:ok, 0}

  defp ipv6_side_length(side) do
    side
    |> :binary.split(<<":">>, [:global])
    |> ipv6_groups_length(0)
  end

  defp ipv6_groups_length([group], count) do
    if :binary.match(group, <<".">>) == :nomatch do
      if valid_hex_group?(group), do: {:ok, count + 1}, else: {:error, :invalid}
    else
      if valid_ipv4_tail?(group), do: {:ok, count + 2}, else: {:error, :invalid}
    end
  end

  defp ipv6_groups_length([group | rest], count) do
    if valid_hex_group?(group) do
      ipv6_groups_length(rest, count + 1)
    else
      {:error, :invalid}
    end
  end

  defp valid_hex_group?(group) do
    byte_size(group) in 1..4 and
      Enum.all?(:binary.bin_to_list(group), &(&1 in ~c"0123456789ABCDEFabcdef"))
  end

  defp valid_ipv4_tail?(tail) do
    case :binary.split(tail, <<".">>, [:global]) do
      [a, b, c, d] ->
        Enum.all?([a, b, c, d], &valid_ipv4_octet?/1)

      _invalid ->
        false
    end
  end

  defp valid_ipv4_octet?(octet) do
    octet != <<>> and byte_size(octet) <= 3 and
      Enum.all?(:binary.bin_to_list(octet), &(&1 in ?0..?9)) and
      (byte_size(octet) == 1 or :binary.at(octet, 0) != ?0) and
      :erlang.binary_to_integer(octet) <= 255
  end

  defp parse_port_suffix(<<>>), do: {:ok, nil}
  defp parse_port_suffix(<<?:, port::binary>>), do: parse_port(port)
  defp parse_port_suffix(_suffix), do: {:error, :invalid}

  defp parse_port(port) do
    if port != <<>> and Enum.all?(:binary.bin_to_list(port), &(&1 in ?0..?9)) do
      value = :erlang.binary_to_integer(port)
      if value in 1..65_535, do: {:ok, value}, else: {:error, :invalid}
    else
      {:error, :invalid}
    end
  end

  defp build_uri(host, port, path) when port in [nil, 443],
    do: <<"https://", host::binary, path::binary>>

  defp build_uri(host, port, path),
    do: <<"https://", host::binary, ?:, Integer.to_string(port)::binary, path::binary>>

  defp contains_any?(binary, bytes) do
    Enum.any?(bytes, fn byte -> :binary.match(binary, <<byte>>) != :nomatch end)
  end

  defp ascii_downcase(binary) do
    for <<byte <- binary>>, into: <<>> do
      if byte in ?A..?Z, do: <<byte + 32>>, else: <<byte>>
    end
  end

  defp hex_value(byte) when byte in ?0..?9, do: byte - ?0
  defp hex_value(byte) when byte in ?A..?F, do: byte - ?A + 10
  defp hex_value(byte) when byte in ?a..?f, do: byte - ?a + 10
  defp upper_hex(byte) when byte in ?a..?f, do: byte - 32
  defp upper_hex(byte), do: byte
end
