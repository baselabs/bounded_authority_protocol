defmodule BoundedAuthorityProtocol.V3.EcJwk do
  @moduledoc """
  Exact public P-256 EC JWK encoding, decoding, and RFC 7638 thumbprints for
  the `BAP3-ES256-SHA256` suite.

  The raw public key is the 65-byte uncompressed SEC1 point `0x04 || x || y`;
  the wire JWK is exactly `{"crv":"P-256","kty":"EC","x":…,"y":…}`. The decoded
  point is validated on-curve by pure arithmetic before any crypto backend
  call, so the closed rejection is deterministic across backends.
  """

  alias BoundedAuthorityProtocol.Es256
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @public_key_bytes 65
  @coordinate_bytes 32

  @doc "Encodes one raw 65-byte uncompressed SEC1 public key as the canonical public EC JWK."
  @spec encode_public(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def encode_public(public_key, limits) when is_binary(public_key) do
    with {:ok, _bounds} <- Bounds.coerce(limits),
         true <- byte_size(public_key) == @public_key_bytes,
         <<4>> <> rest <- public_key,
         <<x::binary-@coordinate_bytes, y::binary-@coordinate_bytes>> <- rest,
         true <- Es256.acceptable_public_key?(public_key) do
      {:ok, jwk_preimage(x, y)}
    else
      _failure -> {:error, :invalid}
    end
  end

  def encode_public(_public_key, _limits), do: {:error, :invalid}

  defp jwk_preimage(x, y) do
    ~s({"crv":"P-256","kty":"EC","x":") <>
      Base.url_encode64(x, padding: false) <>
      ~s(","y":") <> Base.url_encode64(y, padding: false) <> ~s("})
  end

  @doc "Decodes an exact public EC JWK to the raw 65-byte uncompressed SEC1 point."
  @spec decode_public(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def decode_public(jwk, limits) when is_binary(jwk) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(jwk) <= bounds.decoded_segment_bytes,
         {:ok, x, y} <- exact_members(jwk, bounds) do
      {:ok, <<4>> <> x <> y}
    else
      _failure -> {:error, :invalid}
    end
  end

  def decode_public(_jwk, _limits), do: {:error, :invalid}

  @doc "Returns the exact RFC 7638 public EC thumbprint preimage."
  @spec thumbprint_preimage(binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def thumbprint_preimage(jwk, limits) do
    with {:ok, public_key} <- decode_public(jwk, limits) do
      encode_public(public_key, limits)
    end
  end

  @doc "Returns the canonical base64url RFC 7638 thumbprint."
  @spec thumbprint(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def thumbprint(jwk, limits) do
    with {:ok, digest} <- thumbprint_raw(jwk, limits) do
      {:ok, Base.url_encode64(digest, padding: false)}
    end
  end

  @doc """
  Returns the raw 32-byte SHA-256 RFC 7638 thumbprint of an exact public EC JWK.

  This is the digest `thumbprint/2` base64url-encodes. The JWK must be the exact canonical
  member set `decode_public/2` accepts, carrying an on-curve P-256 point; anything else is
  `{:error, :invalid}`.

  ## Example

      iex> jwk =
      ...>   ~s({"crv":"P-256","kty":"EC","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"})
      iex> {:ok, digest} = BoundedAuthorityProtocol.V3.EcJwk.thumbprint_raw(jwk, %{})
      iex> Base.url_encode64(digest, padding: false)
      "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
  """
  @spec thumbprint_raw(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def thumbprint_raw(jwk, limits) do
    with {:ok, preimage} <- thumbprint_preimage(jwk, limits) do
      {:ok, :crypto.hash(:sha256, preimage)}
    end
  end

  @doc """
  Returns the raw 32-byte SHA-256 RFC 7638 thumbprint of a raw 65-byte uncompressed SEC1
  P-256 public key (`0x04 || x || y`).

  Equivalent to `encode_public/2` followed by `thumbprint_raw/2`. Use it to compute the
  holder confirmation a `BoundedAuthorityProtocol.V3.Grant` carries: pass the raw digest
  as `holder_thumbprint` (the producer base64url-encodes it into the `cnf.jkt` claim). A point that fails
  `BoundedAuthorityProtocol.Es256.acceptable_public_key?/1` is `{:error, :invalid}`.

  ## Example

      iex> public_key =
      ...>   Base.decode16!(
      ...>     "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" <>
      ...>       "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
      ...>   )
      iex> {:ok, digest} = BoundedAuthorityProtocol.V3.EcJwk.public_key_thumbprint_raw(public_key, %{})
      iex> Base.url_encode64(digest, padding: false)
      "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
  """
  @spec public_key_thumbprint_raw(binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def public_key_thumbprint_raw(public_key, limits) do
    with {:ok, jwk} <- encode_public(public_key, limits) do
      thumbprint_raw(jwk, limits)
    end
  end

  # Exact closed member set {crv, kty, x, y} with pinned values; canonical
  # fixed-width coordinates that are field elements and form an on-curve point.
  defp exact_members(jwk, bounds) do
    with {:ok, {:object, members}} <- Json.decode(jwk, bounds),
         {4,
          %{
            "crv" => {:string, "P-256"},
            "kty" => {:string, "EC"},
            "x" => {:string, x_encoded},
            "y" => {:string, y_encoded}
          }} <- {length(members), Map.new(members)},
         {:ok, x} <- Base64Url.decode(x_encoded, bounds),
         {:ok, y} <- Base64Url.decode(y_encoded, bounds),
         true <- byte_size(x) == @coordinate_bytes and byte_size(y) == @coordinate_bytes,
         true <- Es256.acceptable_public_key?(<<4>> <> x <> y) do
      {:ok, x, y}
    else
      _failure -> {:error, :invalid}
    end
  end
end
