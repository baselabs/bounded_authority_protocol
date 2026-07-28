defmodule BoundedAuthorityProtocol.V1.BoundaryAnchorCodec do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.AnchorFacts
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.CompactJws
  alias BoundedAuthorityProtocol.V1.ContextValidation
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.StringOrUri

  @header_keys ~w(alg kid typ)
  @payload_keys ~w(anchor_id anchored_at chain_hash chain_id key_fingerprint sequence v)
  @zero_hash <<0::256>>

  @spec signing_input(BoundaryAnchor.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  def signing_input(%BoundaryAnchor{} = anchor, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         :ok <- validate_anchor(anchor, bounds),
         {:ok, fingerprint} <- Jwk.public_key_thumbprint_raw(anchor.public_key, bounds),
         {:ok, protected} <- Jcs.encode(header_json(anchor.key_id), bounds),
         {:ok, payload} <- Jcs.encode(payload_json(anchor, fingerprint), bounds) do
      build_signing_input(protected, payload, bounds)
    else
      _failure -> {:error, :invalid}
    end
  end

  def signing_input(_anchor, _limits), do: {:error, :invalid}

  @spec verify(binary(), HistoricalPublicKey.t(), ExpectedAnchor.t()) ::
          {:ok, AnchorFacts.t()} | {:error, :invalid}
  def verify(compact, %HistoricalPublicKey{} = key, %ExpectedAnchor{} = expected)
      when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_historical_key(key, bounds),
         :ok <- validate_expected(expected, bounds),
         {:ok, parsed} <- parse(compact, bounds),
         {:ok, fingerprint} <- Jwk.public_key_thumbprint_raw(key.public_key, bounds),
         true <- parsed.key_id == key.key_id,
         true <- parsed.key_id == expected.key_id,
         true <- parsed.anchor_id == expected.anchor_id,
         true <- parsed.anchored_at == expected.anchored_at,
         true <- parsed.chain_id == expected.chain_id,
         true <- parsed.sequence == expected.sequence,
         true <- FixedBytes.equal?(parsed.chain_hash, expected.chain_hash),
         true <- FixedBytes.equal?(parsed.key_fingerprint, fingerprint),
         true <- FixedBytes.equal?(parsed.key_fingerprint, expected.key_fingerprint),
         true <- inside_window?(parsed.anchored_at, key),
         true <- verify_signature(parsed.message, parsed.signature, key.public_key) do
      {:ok,
       %AnchorFacts{
         version: 1,
         anchor_id: parsed.anchor_id,
         anchored_at: parsed.anchored_at,
         chain_id: parsed.chain_id,
         sequence: parsed.sequence,
         chain_hash: parsed.chain_hash,
         key_fingerprint: fingerprint,
         verification: :signature_and_window,
         trust: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def verify(_compact, _key, _expected), do: {:error, :invalid}

  @doc false
  @spec parse(binary(), Bounds.t()) :: {:ok, map()} | {:error, :invalid}
  def parse(compact, %Bounds{} = bounds)
      when is_binary(compact) and byte_size(compact) > 0 and
             byte_size(compact) <= bounds.anchor_bytes do
    with {:ok, {protected_segment, payload_segment, signature_segment}} <-
           CompactJws.scan(compact, bounds),
         {:ok, protected_bytes} <- Base64Url.decode(protected_segment, bounds),
         {:ok, payload_bytes} <- Base64Url.decode(payload_segment, bounds),
         {:ok, signature} <- Base64Url.decode(signature_segment, bounds),
         true <- byte_size(signature) == bounds.signature_bytes,
         {:ok, {:object, header_members}} <- Json.decode(protected_bytes, bounds),
         {:ok, header} <- closed_map(header_members, @header_keys),
         {:string, "EdDSA"} <- header["alg"],
         {:string, "ba+chain-anchor"} <- header["typ"],
         {:string, key_id} <- header["kid"],
         true <- valid_key_id?(key_id, bounds),
         {:ok, canonical_header} <- Jcs.encode({:object, header_members}, bounds),
         true <- protected_bytes == canonical_header,
         {:ok, {:object, payload_members}} <- Json.decode(payload_bytes, bounds),
         {:ok, payload} <- closed_map(payload_members, @payload_keys),
         {:integer, 1} <- payload["v"],
         {:string, anchor_id} <- payload["anchor_id"],
         {:integer, anchored_at} <- payload["anchored_at"],
         {:string, chain_id} <- payload["chain_id"],
         {:integer, sequence} <- payload["sequence"],
         {:string, chain_hash_encoded} <- payload["chain_hash"],
         {:ok, chain_hash} <- Base64Url.decode(chain_hash_encoded, bounds),
         {:string, fingerprint_encoded} <- payload["key_fingerprint"],
         {:ok, key_fingerprint} <- Base64Url.decode(fingerprint_encoded, bounds),
         parsed_anchor = %BoundaryAnchor{
           anchor_id: anchor_id,
           anchored_at: anchored_at,
           chain_id: chain_id,
           sequence: sequence,
           chain_hash: chain_hash,
           key_id: key_id,
           public_key: <<0::256>>
         },
         :ok <- validate_anchor_fields(parsed_anchor, key_fingerprint, bounds),
         {:ok, canonical_payload} <- Jcs.encode({:object, payload_members}, bounds),
         true <- payload_bytes == canonical_payload do
      {:ok,
       %{
         anchor_id: anchor_id,
         anchored_at: anchored_at,
         chain_id: chain_id,
         sequence: sequence,
         chain_hash: chain_hash,
         key_id: key_id,
         key_fingerprint: key_fingerprint,
         message: protected_segment <> "." <> payload_segment,
         signature: signature
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def parse(_compact, _bounds), do: {:error, :invalid}

  defp build_signing_input(protected, payload, bounds) do
    protected_segment = Base.url_encode64(protected, padding: false)
    payload_segment = Base.url_encode64(payload, padding: false)
    message = protected_segment <> "." <> payload_segment

    if byte_size(protected_segment) <= bounds.encoded_segment_bytes and
         byte_size(payload_segment) <= bounds.encoded_segment_bytes and
         byte_size(message) + 1 + 86 <= bounds.anchor_bytes and
         byte_size(message) + 1 + 86 <= bounds.compact_bytes do
      {:ok,
       %SigningInput{
         kind: :boundary_anchor,
         protected_segment: protected_segment,
         payload_segment: payload_segment,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end

  defp validate_anchor(anchor, bounds) do
    with true <- is_binary(anchor.public_key),
         true <- byte_size(anchor.public_key) == bounds.public_key_bytes,
         :ok <-
           validate_anchor_fields(anchor, :crypto.hash(:sha256, anchor.public_key), bounds) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_anchor_fields(anchor, fingerprint, bounds) do
    if valid_anchor_identity?(anchor, bounds) and
         valid_anchor_binding?(anchor, fingerprint, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp valid_anchor_identity?(anchor, bounds),
    do:
      valid_identifier?(anchor.anchor_id, bounds) and valid_time?(anchor.anchored_at, bounds) and
        valid_identifier?(anchor.chain_id, bounds) and valid_key_id?(anchor.key_id, bounds)

  defp valid_anchor_binding?(anchor, fingerprint, bounds),
    do:
      valid_anchor_sequence?(anchor.sequence, bounds) and
        fixed_digest?(anchor.chain_hash, bounds) and fixed_digest?(fingerprint, bounds) and
        (anchor.sequence != 0 or FixedBytes.equal?(anchor.chain_hash, @zero_hash))

  defp validate_expected(expected, bounds),
    do: ContextValidation.expected_anchor(expected, bounds)

  defp validate_historical_key(key, bounds),
    do: ContextValidation.historical_key(key, bounds)

  defp inside_window?(time, key) do
    key.valid_from <= time and
      (key.valid_before == :unbounded or time < key.valid_before)
  end

  defp header_json(key_id) do
    {:object,
     [
       {"alg", {:string, "EdDSA"}},
       {"kid", {:string, key_id}},
       {"typ", {:string, "ba+chain-anchor"}}
     ]}
  end

  defp payload_json(anchor, fingerprint) do
    {:object,
     [
       {"anchor_id", {:string, anchor.anchor_id}},
       {"anchored_at", {:integer, anchor.anchored_at}},
       {"chain_hash", {:string, Base.url_encode64(anchor.chain_hash, padding: false)}},
       {"chain_id", {:string, anchor.chain_id}},
       {"key_fingerprint", {:string, Base.url_encode64(fingerprint, padding: false)}},
       {"sequence", {:integer, anchor.sequence}},
       {"v", {:integer, 1}}
     ]}
  end

  defp closed_map(members, keys) when is_list(members) do
    if length(members) == length(keys) and
         Enum.sort(Enum.map(members, &elem(&1, 0))) == Enum.sort(keys) do
      {:ok, Map.new(members)}
    else
      {:error, :invalid}
    end
  end

  defp verify_signature(message, signature, public_key) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  defp fixed_digest?(value, bounds),
    do: is_binary(value) and byte_size(value) == bounds.digest_bytes

  defp valid_anchor_sequence?(value, bounds),
    do: is_integer(value) and value >= 0 and value <= bounds.integer_magnitude

  defp valid_time?(value, bounds),
    do:
      is_integer(value) and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude

  defp valid_key_id?(value, bounds),
    do:
      is_binary(value) and byte_size(value) in 1..bounds.kid_bytes and
        ascii_key_id?(value)

  defp ascii_key_id?(<<>>), do: true

  defp ascii_key_id?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~],
       do: ascii_key_id?(rest)

  defp ascii_key_id?(_value), do: false

  defp valid_identifier?(value, bounds) do
    is_binary(value) and byte_size(value) in 1..bounds.identifier_bytes and String.valid?(value) and
      StringOrUri.valid?(value)
  end
end
