defmodule BoundedAuthorityProtocol.Es256 do
  @moduledoc """
  ES256 (ECDSA P-256 with SHA-256) signature canonicality, public-key acceptance, strict
  verification, and producer utilities for the `BAP3-ES256-SHA256` suite.

  This module is the single owner of the ES256 scalar and point rules for every ES256 surface of
  the protocol. It is pure: no clock, randomness, process state, or I/O. It accepts public keys
  only; no function here takes, holds, or produces private key material. No function raises.

  ## Wire form

  A signature is the RFC 7518 §3.4 raw form `r || s`: exactly 64 bytes, two fixed-width 32-byte
  unsigned big-endian integers. A public key is the 65-byte uncompressed SEC1 point
  `0x04 || x || y`.

  ## Canonical signature

  `canonical_signature?/1` is the suite's signature rule (`spec/bap-v3.md` § 3.2):
  `0 < r < n` and `0 < s <= floor(n / 2)`, `n` the P-256 group order. Every verification surface
  applies it before the backend, and every producer surface (compact assembly, anchored-export
  encoding) refuses a signature that fails it (erratum 3).

  ## Producer utilities

  Normalization is the signer's duty. `normalize_low_s/1` maps a high-S signature `(r, s)` to
  its low-S twin `(r, n - s)`; `der_to_raw/1` converts a strict DER `ECDSA-Sig-Value` (the form
  most HSM, KMS, and secret-store signers return) to the raw wire form. A producer runs
  `der_to_raw/1`, then `normalize_low_s/1`, before compact assembly. The protocol's own producer
  surfaces never normalize: they refuse.

  A `true` result proves only that the bytes satisfy the rule. It never selects trusted keys or
  grants authority.
  """
  @moduledoc since: "0.9.0"

  # NIST P-256 (secp256r1): the group order n, the field prime p, and the curve constant b of
  # y^2 = x^3 - 3x + b (mod p).
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @half_n div(@n, 2)
  @p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @scalar_bytes 32

  @doc """
  Returns whether a raw 64-byte signature `r || s` is canonical: `0 < r < n` and
  `0 < s <= floor(n / 2)`. Any other input, including non-binary or wrong-size input, returns
  `false`.
  """
  @spec canonical_signature?(binary()) :: boolean()
  def canonical_signature?(<<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>) do
    ri = :binary.decode_unsigned(r)
    si = :binary.decode_unsigned(s)
    ri > 0 and ri < @n and si > 0 and si <= @half_n
  end

  def canonical_signature?(_signature), do: false

  @doc """
  Returns whether a 65-byte uncompressed SEC1 public key `0x04 || x || y` may enter a
  verification input: both coordinates are field elements (`< p`) and the point is on the
  curve. Any other input returns `false`.
  """
  @spec acceptable_public_key?(binary()) :: boolean()
  def acceptable_public_key?(<<4, x::unsigned-big-256, y::unsigned-big-256>>) do
    x < @p and y < @p and Integer.mod(y * y, @p) == Integer.mod(x * x * x - 3 * x + @b, @p)
  end

  def acceptable_public_key?(_public_key), do: false

  @doc """
  Verifies an ES256 signature strictly: the key must be acceptable, the signature canonical,
  and then the ECDSA equation must hold (checked by the `:crypto` backend over a minimal DER
  encoding of `r` and `s`). Any other input returns `false`; the function never raises.

  The backend runs only on a binary message, a canonical signature, and an on-curve key with
  coordinates below `p` (P-256 has prime order, so every such point is a valid public key):
  the inputs on which a backend raises never reach it.
  """
  @spec verify_strict(binary(), binary(), binary()) :: boolean()
  def verify_strict(message, signature, public_key) when is_binary(message) do
    canonical_signature?(signature) and acceptable_public_key?(public_key) and
      :crypto.verify(
        :ecdsa,
        :sha256,
        message,
        der_signature(signature),
        [public_key, :prime256v1]
      )
  end

  def verify_strict(_message, _signature, _public_key), do: false

  @doc """
  Maps a raw 64-byte signature to its low-S form: `(r, n - s)` when `s > floor(n / 2)`, and the
  same bytes otherwise. Idempotent.

  Returns `{:error, :invalid}` unless `0 < r < n` and `0 < s < n`. This is a producer utility
  for the signer; the protocol's producer surfaces never apply it.
  """
  @spec normalize_low_s(binary()) :: {:ok, binary()} | {:error, :invalid}
  def normalize_low_s(<<r::unsigned-big-256, s::unsigned-big-256>>)
      when r > 0 and r < @n and s > 0 and s < @n do
    low_s = if s > @half_n, do: @n - s, else: s
    {:ok, <<r::unsigned-big-256, low_s::unsigned-big-256>>}
  end

  def normalize_low_s(_signature), do: {:error, :invalid}

  @doc """
  Converts a strict DER `ECDSA-Sig-Value` (`SEQUENCE { INTEGER r, INTEGER s }`) to the raw
  64-byte `r || s` form.

  The encoding must be exact DER: single-byte lengths that match the content exactly (a valid
  signature's content is at most 70 bytes, so a long-form length never matches), minimal
  non-negative INTEGER encodings (a leading `0x00` only when the next byte has its high bit
  set), and no trailing bytes. Both scalars must lie in `0 < r < n` and `0 < s < n`. The output
  is not low-S normalized; pass it to `normalize_low_s/1`. Any other input returns
  `{:error, :invalid}`.
  """
  @spec der_to_raw(binary()) :: {:ok, binary()} | {:error, :invalid}
  def der_to_raw(<<0x30, length, content::binary-size(length)>>) do
    with {:ok, r, rest} <- der_integer(content),
         {:ok, s, <<>>} <- der_integer(rest),
         true <- r > 0 and r < @n and s > 0 and s < @n do
      {:ok, <<r::unsigned-big-256, s::unsigned-big-256>>}
    else
      _invalid -> {:error, :invalid}
    end
  end

  def der_to_raw(_der), do: {:error, :invalid}

  # One DER INTEGER of 1 to 33 content bytes, minimal and non-negative.
  defp der_integer(<<0x02, length, value::binary-size(length), rest::binary>>)
       when length >= 1 and length <= @scalar_bytes + 1 do
    if minimal_non_negative?(value),
      do: {:ok, :binary.decode_unsigned(value), rest},
      else: :error
  end

  defp der_integer(_bytes), do: :error

  # A leading 0x00 is allowed only before a byte with its high bit set; a leading byte with its
  # high bit set is a negative INTEGER. A 33-byte value is therefore exactly 0x00 followed by a
  # 32-byte magnitude with its high bit set.
  defp minimal_non_negative?(<<0>>), do: true
  defp minimal_non_negative?(<<0, next, _rest::binary>>), do: next >= 0x80
  defp minimal_non_negative?(<<first, _rest::binary>>), do: first < 0x80

  # Minimal DER ECDSA-Sig-Value: SEQUENCE(INTEGER r, INTEGER s) with minimal-octet unsigned
  # integers (a leading 0x00 when the high bit is set). Short-form lengths only: each INTEGER is
  # at most 33 content bytes, so the SEQUENCE content is at most 70 bytes.
  defp der_signature(<<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>) do
    body = der_encode_integer(r) <> der_encode_integer(s)
    <<0x30, byte_size(body), body::binary>>
  end

  defp der_encode_integer(bytes) do
    minimal = trim_leading_zeros(bytes)
    content = if :binary.first(minimal) >= 0x80, do: <<0>> <> minimal, else: minimal
    <<0x02, byte_size(content), content::binary>>
  end

  # Canonical signatures have r, s > 0, so at least one nonzero byte always remains.
  defp trim_leading_zeros(<<0, rest::binary>>), do: trim_leading_zeros(rest)
  defp trim_leading_zeros(bytes), do: bytes
end
