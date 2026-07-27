defmodule BoundedAuthorityProtocol.V1 do
  @moduledoc "Explicit entry point for the immutable v1 wire profile."

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.KeyLocator

  @doc """
  Parses only the protected grant header and returns its untrusted `kid` hint.

  The complete compact input is bounded. Payload and signature segments are not decoded,
  interpreted, or independently size-checked.
  """
  @spec untrusted_key_locator(binary(), Bounds.t() | map()) ::
          {:ok, KeyLocator.t()} | {:error, :invalid}
  def untrusted_key_locator(compact, limits \\ %{})

  def untrusted_key_locator(compact, limits) when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(compact) <= bounds.compact_bytes,
         [protected, _payload, _signature] <- :binary.split(compact, <<".">>, [:global]),
         true <- byte_size(protected) <= bounds.encoded_segment_bytes,
         {:ok, header_bytes} <- Base64Url.decode(protected, bounds),
         {:ok, {:object, members}} <- Json.decode(header_bytes, bounds),
         {:ok, kid} <- closed_header(members, nil, nil, nil),
         true <- valid_kid?(kid, bounds.kid_bytes) do
      {:ok, %KeyLocator{kid: kid, trust: :not_evaluated}}
    else
      _failure -> {:error, :invalid}
    end
  end

  def untrusted_key_locator(_compact, _limits), do: {:error, :invalid}

  defp closed_header([], <<"EdDSA">>, <<"ba+cap">>, kid) when is_binary(kid), do: {:ok, kid}

  defp closed_header([{<<"alg">>, {:string, value}} | rest], nil, typ, kid),
    do: closed_header(rest, value, typ, kid)

  defp closed_header([{<<"typ">>, {:string, value}} | rest], alg, nil, kid),
    do: closed_header(rest, alg, value, kid)

  defp closed_header([{<<"kid">>, {:string, value}} | rest], alg, typ, nil),
    do: closed_header(rest, alg, typ, value)

  defp closed_header(_members, _alg, _typ, _kid), do: {:error, :invalid}

  defp valid_kid?(kid, maximum) when byte_size(kid) > 0 and byte_size(kid) <= maximum,
    do: kid_bytes?(kid)

  defp valid_kid?(_kid, _maximum), do: false

  defp kid_bytes?(<<>>), do: true

  defp kid_bytes?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~],
       do: kid_bytes?(rest)

  defp kid_bytes?(_kid), do: false
end
