defmodule BoundedAuthorityProtocol.V1.CompactJws do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.SigningInput

  @signature_bytes 64

  @doc "Scans exactly three nonempty compact-JWS segments."
  @spec scan(binary(), Bounds.t() | map()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, :invalid}
  def scan(compact, limits) when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(compact) <= bounds.compact_bytes,
         {:ok, protected, rest} <- take_segment(compact, bounds),
         {:ok, payload, signature} <- take_segment(rest, bounds),
         true <- signature != <<>> and byte_size(signature) <= bounds.encoded_segment_bytes,
         :nomatch <- :binary.match(signature, <<".">>) do
      {:ok, {protected, payload, signature}}
    else
      _failure -> {:error, :invalid}
    end
  end

  def scan(_compact, _limits), do: {:error, :invalid}

  @doc "Assembles a validated signing input and exact 64-byte signature."
  @spec assemble(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble(%SigningInput{} = input, signature, limits) when is_binary(signature) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- valid_signing_input?(input, bounds),
         true <-
           byte_size(signature) == @signature_bytes and
             byte_size(signature) <= bounds.signature_bytes,
         signature_segment = Base.url_encode64(signature, padding: false),
         compact =
           input.protected_segment <> "." <> input.payload_segment <> "." <> signature_segment,
         true <- byte_size(compact) <= bounds.compact_bytes do
      {:ok, compact}
    else
      _failure -> {:error, :invalid}
    end
  end

  def assemble(_signing_input, _signature, _limits), do: {:error, :invalid}

  @doc "Returns canonical `ath` for one complete received compact grant."
  @spec ath(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def ath(compact, limits) do
    with {:ok, _segments} <- scan(compact, limits) do
      {:ok, :crypto.hash(:sha256, compact) |> Base.url_encode64(padding: false)}
    end
  end

  @doc false
  @spec hash(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  def hash(compact, limits) do
    with {:ok, _segments} <- scan(compact, limits) do
      {:ok, :crypto.hash(:sha256, compact)}
    end
  end

  defp take_segment(compact, bounds) do
    case :binary.match(compact, <<".">>) do
      {index, 1} when index > 0 and index <= bounds.encoded_segment_bytes ->
        rest_size = byte_size(compact) - index - 1
        <<segment::binary-size(index), ?., rest::binary-size(rest_size)>> = compact
        {:ok, segment, rest}

      _failure ->
        {:error, :invalid}
    end
  end

  defp valid_signing_input?(input, bounds) do
    valid_signing_input_fields?(input, bounds) and
      signing_kind_matches?(input.kind, input.protected_segment, bounds) and
      match?({:ok, _decoded}, Base64Url.decode(input.payload_segment, bounds))
  end

  defp valid_signing_input_fields?(input, bounds) do
    valid_kind_and_segments?(input) and valid_segment_bounds?(input, bounds) and
      input.message == input.protected_segment <> "." <> input.payload_segment
  end

  defp valid_kind_and_segments?(input) do
    input.kind in [:grant, :proof] and is_binary(input.protected_segment) and
      is_binary(input.payload_segment) and is_binary(input.message) and
      byte_size(input.protected_segment) > 0 and byte_size(input.payload_segment) > 0
  end

  defp valid_segment_bounds?(input, bounds) do
    byte_size(input.protected_segment) <= bounds.encoded_segment_bytes and
      byte_size(input.payload_segment) <= bounds.encoded_segment_bytes
  end

  defp signing_kind_matches?(kind, protected_segment, bounds) do
    with {:ok, protected} <- Base64Url.decode(protected_segment, bounds),
         {:ok, {:object, members}} <- Json.decode(protected, bounds) do
      exact_signing_header?(kind, members, bounds)
    else
      _failure -> false
    end
  end

  defp exact_signing_header?(:grant, members, bounds) when length(members) == 3 do
    case Map.new(members) do
      %{
        "alg" => {:string, "EdDSA"},
        "kid" => {:string, kid},
        "typ" => {:string, "ba+cap"}
      } ->
        byte_size(kid) > 0 and byte_size(kid) <= bounds.kid_bytes

      _invalid ->
        false
    end
  end

  defp exact_signing_header?(:proof, members, bounds) when length(members) == 3 do
    case Map.new(members) do
      %{
        "alg" => {:string, "EdDSA"},
        "jwk" => jwk,
        "typ" => {:string, "dpop+jwt"}
      } ->
        with {:ok, encoded_jwk} <- Jcs.encode(jwk, bounds),
             {:ok, _public_key} <- Jwk.decode_public(encoded_jwk, bounds) do
          true
        else
          _invalid -> false
        end

      _invalid ->
        false
    end
  end

  defp exact_signing_header?(_kind, _members, _bounds), do: false
end
