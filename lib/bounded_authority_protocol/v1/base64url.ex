defmodule BoundedAuthorityProtocol.V1.Base64Url do
  @moduledoc """
  Strict bounded canonical base64url decoding for v1.

  `decode/2` accepts only the unpadded `A-Z`, `a-z`, `0-9`, `-`, and `_` alphabet, projects the
  decoded size before allocation, and requires byte-identical unpadded re-encoding. Caller limits
  may only tighten the positive-integer hard maxima. Success returns `{:ok, binary}`; every
  failure returns the fixed value-free `{:error, :invalid}`.
  """

  alias BoundedAuthorityProtocol.V1.Bounds

  @doc "Decodes a bounded canonical base64url segment."
  @spec decode(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def decode(segment, limits \\ %{})

  def decode(segment, limits) when is_binary(segment) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(segment) <= bounds.encoded_segment_bytes,
         true <- alphabet?(segment),
         {:ok, projected} <- projected_size(byte_size(segment)),
         true <- projected <= bounds.decoded_segment_bytes,
         {:ok, decoded} <- Base.url_decode64(segment, padding: false),
         true <- Base.url_encode64(decoded, padding: false) == segment do
      {:ok, decoded}
    else
      _failure -> {:error, :invalid}
    end
  end

  def decode(_segment, _limits), do: {:error, :invalid}

  defp projected_size(size) do
    case rem(size, 4) do
      0 -> {:ok, div(size, 4) * 3}
      2 -> {:ok, div(size, 4) * 3 + 1}
      3 -> {:ok, div(size, 4) * 3 + 2}
      1 -> {:error, :invalid}
    end
  end

  defp alphabet?(<<>>), do: true

  defp alphabet?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte == ?_ or byte == ?-,
       do: alphabet?(rest)

  defp alphabet?(_segment), do: false
end
