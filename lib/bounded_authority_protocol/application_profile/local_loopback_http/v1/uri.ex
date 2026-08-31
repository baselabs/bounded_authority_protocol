defmodule BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.Uri do
  @moduledoc false

  alias BoundedAuthorityProtocol.UriPath
  alias BoundedAuthorityProtocol.V1.Bounds

  @spec normalize(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def normalize(uri, limits) when is_binary(uri) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(uri) <= bounds.uri_bytes,
         true <- ascii_uri?(uri),
         {:ok, authority, raw_path} <- split_http(uri),
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

  defp split_http(uri) do
    case :binary.match(uri, <<"://">>) do
      {index, 3} ->
        scheme = binary_part(uri, 0, index)
        rest = binary_part(uri, index + 3, byte_size(uri) - index - 3)

        with true <- ascii_downcase(scheme) == <<"http">>,
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

  defp normalize_authority(<<"127.0.0.1">>), do: {:ok, "127.0.0.1", nil}
  defp normalize_authority(<<"[::1]">>), do: {:ok, "[::1]", nil}

  defp normalize_authority(<<"127.0.0.1:", port::binary>>),
    do: parse_port(port, "127.0.0.1")

  defp normalize_authority(<<"[::1]:", port::binary>>), do: parse_port(port, "[::1]")
  defp normalize_authority(_authority), do: {:error, :invalid}

  defp parse_port(port, host) do
    if port != <<>> and Enum.all?(:binary.bin_to_list(port), &(&1 in ?0..?9)) do
      value = :erlang.binary_to_integer(port)

      if value in 1..65_535,
        do: {:ok, host, value},
        else: {:error, :invalid}
    else
      {:error, :invalid}
    end
  end

  defp build_uri(host, port, path) when port in [nil, 80],
    do: <<"http://", host::binary, path::binary>>

  defp build_uri(host, port, path),
    do: <<"http://", host::binary, ?:, Integer.to_string(port)::binary, path::binary>>

  defp contains_any?(binary, bytes) do
    Enum.any?(bytes, fn byte -> :binary.match(binary, <<byte>>) != :nomatch end)
  end

  defp ascii_downcase(binary) do
    for <<byte <- binary>>, into: <<>> do
      if byte in ?A..?Z, do: <<byte + 32>>, else: <<byte>>
    end
  end
end
