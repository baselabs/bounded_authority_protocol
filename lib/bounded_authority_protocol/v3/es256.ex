defmodule BoundedAuthorityProtocol.V3.Es256 do
  @moduledoc false

  # ES256 verification for the `BAP3-ES256-SHA256` suite: the RFC 7518 §3.4
  # raw `r || s` wire form (exactly 64 bytes, two fixed-width 32-byte unsigned
  # big-endian integers), with the canonicality rules the suite adds on top —
  # `0 < r < n`, `0 < s ≤ n/2` — validated before any backend call. DER is an
  # internal backend spelling only, derived by minimal-octet INTEGER encoding.

  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @half_n div(@n, 2)
  @scalar_bytes 32

  @doc false
  @spec valid_raw_signature?(binary()) :: boolean()
  def valid_raw_signature?(<<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>) do
    ri = :binary.decode_unsigned(r)
    si = :binary.decode_unsigned(s)
    ri > 0 and ri < @n and si > 0 and si <= @half_n
  end

  def valid_raw_signature?(_), do: false

  @doc false
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and is_binary(public_key) do
    if valid_raw_signature?(signature) do
      :crypto.verify(
        :ecdsa,
        :sha256,
        message,
        der_signature(signature),
        [public_key, :prime256v1]
      )
    else
      false
    end
  rescue
    _backend_failure -> false
  end

  def verify(_message, _signature, _public_key), do: false

  # Minimal DER ECDSA-Sig-Value: SEQUENCE(INTEGER r, INTEGER s) with
  # minimal-octet unsigned integers (a leading 0x00 when the high bit is set).
  defp der_signature(<<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>) do
    r_der = der_integer(r)
    s_der = der_integer(s)
    body = r_der <> s_der
    <<48, der_length(byte_size(body))::binary, body::binary>>
  end

  defp der_integer(bytes) do
    minimal = trim_leading_zeros(bytes, 0)
    first = :binary.first(minimal)

    content =
      if first >= 0x80 do
        <<0>> <> minimal
      else
        minimal
      end

    <<2, der_length(byte_size(content))::binary, content::binary>>
  end

  defp trim_leading_zeros(<<0, rest::binary>>, acc) when acc < @scalar_bytes - 1,
    do: trim_leading_zeros(rest, acc + 1)

  defp trim_leading_zeros(bytes, _acc) when bytes != <<>>,
    do: bytes

  # DER short-form length only: every encoded INTEGER content here is at most
  # @scalar_bytes + 1 = 33 bytes (a fixed-width scalar with a possible 0x00
  # sign guard), so the long form (length >= 128) is unreachable by
  # construction and deliberately not implemented.
  defp der_length(len) when len < 128, do: <<len>>
end
