defmodule BoundedAuthorityProtocol.V1.Jwk do
  @moduledoc """
  Exact public Ed25519 JWK encoding, decoding, and RFC 7638 thumbprints.
  """

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @public_key_bytes 32

  @doc "Encodes one raw 32-byte Ed25519 public key as the canonical public OKP JWK."
  @spec encode_public(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def encode_public(public_key, limits) when is_binary(public_key) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <-
           byte_size(public_key) == @public_key_bytes and
             byte_size(public_key) <= bounds.public_key_bytes do
      x = Base.url_encode64(public_key, padding: false)
      {:ok, ~s({"crv":"Ed25519","kty":"OKP","x":"#{x}"})}
    else
      _failure -> {:error, :invalid}
    end
  end

  def encode_public(_public_key, _limits), do: {:error, :invalid}

  @doc "Decodes an exact public Ed25519 OKP JWK."
  @spec decode_public(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def decode_public(jwk, limits) when is_binary(jwk) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(jwk) <= bounds.decoded_segment_bytes,
         {:ok, {:object, members}} <- Json.decode(jwk, bounds),
         {:ok, x} <- exact_members(members),
         {:ok, public_key} <- Base64Url.decode(x, bounds),
         true <-
           byte_size(public_key) == @public_key_bytes and
             byte_size(public_key) <= bounds.public_key_bytes do
      {:ok, public_key}
    else
      _failure -> {:error, :invalid}
    end
  end

  def decode_public(_jwk, _limits), do: {:error, :invalid}

  @doc "Returns the exact RFC 7638 public OKP thumbprint preimage."
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

  defp exact_members(members) do
    if length(members) == 3 do
      case Map.new(members) do
        %{
          "crv" => {:string, "Ed25519"},
          "kty" => {:string, "OKP"},
          "x" => {:string, x}
        } ->
          {:ok, x}

        _invalid ->
          {:error, :invalid}
      end
    else
      {:error, :invalid}
    end
  end
end
