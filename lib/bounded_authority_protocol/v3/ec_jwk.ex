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

  @doc false
  @spec thumbprint_raw(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def thumbprint_raw(jwk, limits) do
    with {:ok, preimage} <- thumbprint_preimage(jwk, limits) do
      {:ok, :crypto.hash(:sha256, preimage)}
    end
  end

  @doc false
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
