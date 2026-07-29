defmodule BoundedAuthorityProtocol.V1.KeyTransitionCodec do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.CompactJws
  alias BoundedAuthorityProtocol.V1.ContextValidation
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V1.KeyTransitionFacts
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.StringOrUri

  @header_keys ~w(alg kid typ)
  @payload_keys ~w(chain_id effective_at from_key_fingerprint to_key_fingerprint to_key_id transition_id v)

  @spec signing_input(KeyTransition.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  def signing_input(%KeyTransition{} = transition, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         :ok <- validate_transition_input(transition, bounds),
         {:ok, current_fingerprint} <-
           Jwk.public_key_thumbprint_raw(transition.current_public_key, bounds),
         {:ok, next_fingerprint} <-
           Jwk.public_key_thumbprint_raw(transition.next_public_key, bounds),
         {:ok, protected} <- Jcs.encode(header_json(transition.current_key_id), bounds),
         {:ok, payload} <-
           Jcs.encode(
             payload_json(transition, current_fingerprint, next_fingerprint),
             bounds
           ) do
      build_signing_input(protected, payload, bounds)
    else
      _failure -> {:error, :invalid}
    end
  end

  def signing_input(_transition, _limits), do: {:error, :invalid}

  @spec verify(
          binary(),
          HistoricalPublicKey.t(),
          HistoricalPublicKey.t(),
          ExpectedKeyTransition.t()
        ) :: {:ok, KeyTransitionFacts.t()} | {:error, :invalid}
  def verify(
        compact,
        %HistoricalPublicKey{} = current_key,
        %HistoricalPublicKey{} = next_key,
        %ExpectedKeyTransition{} = expected
      )
      when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_historical_key(current_key, bounds),
         :ok <- validate_historical_key(next_key, bounds),
         :ok <- validate_expected(expected, bounds),
         {:ok, parsed} <- parse(compact, bounds),
         {:ok, current_fingerprint} <-
           Jwk.public_key_thumbprint_raw(current_key.public_key, bounds),
         {:ok, next_fingerprint} <- Jwk.public_key_thumbprint_raw(next_key.public_key, bounds),
         true <- parsed.current_key_id == current_key.key_id,
         true <- parsed.current_key_id == expected.current_key_id,
         true <- parsed.next_key_id == next_key.key_id,
         true <- parsed.next_key_id == expected.next_key_id,
         true <- parsed.transition_id == expected.transition_id,
         true <- parsed.chain_id == expected.chain_id,
         true <- parsed.effective_at == expected.effective_at,
         true <- FixedBytes.equal?(parsed.current_key_fingerprint, current_fingerprint),
         true <-
           FixedBytes.equal?(
             parsed.current_key_fingerprint,
             expected.current_key_fingerprint
           ),
         true <- FixedBytes.equal?(parsed.next_key_fingerprint, next_fingerprint),
         true <-
           FixedBytes.equal?(parsed.next_key_fingerprint, expected.next_key_fingerprint),
         true <- inside_window?(parsed.effective_at, current_key),
         true <- inside_window?(parsed.effective_at, next_key),
         true <-
           :crypto.verify(
             :eddsa,
             :none,
             parsed.message,
             parsed.signature,
             [current_key.public_key, :ed25519]
           ) do
      {:ok,
       %KeyTransitionFacts{
         version: 1,
         transition_id: parsed.transition_id,
         effective_at: parsed.effective_at,
         chain_id: parsed.chain_id,
         current_key_fingerprint: current_fingerprint,
         next_key_fingerprint: next_fingerprint,
         verification: :authenticated_transition,
         trust: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def verify(_compact, _current_key, _next_key, _expected), do: {:error, :invalid}

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
         {:string, "ba+key-transition"} <- header["typ"],
         {:string, current_key_id} <- header["kid"],
         true <- valid_key_id?(current_key_id, bounds),
         {:ok, canonical_header} <- Jcs.encode({:object, header_members}, bounds),
         true <- protected_bytes == canonical_header,
         {:ok, {:object, payload_members}} <- Json.decode(payload_bytes, bounds),
         {:ok, payload} <- closed_map(payload_members, @payload_keys),
         {:integer, 1} <- payload["v"],
         {:string, transition_id} <- payload["transition_id"],
         {:string, chain_id} <- payload["chain_id"],
         {:integer, effective_at} <- payload["effective_at"],
         {:string, from_encoded} <- payload["from_key_fingerprint"],
         {:ok, current_key_fingerprint} <- Base64Url.decode(from_encoded, bounds),
         {:string, next_encoded} <- payload["to_key_fingerprint"],
         {:ok, next_key_fingerprint} <- Base64Url.decode(next_encoded, bounds),
         {:string, next_key_id} <- payload["to_key_id"],
         :ok <-
           validate_transition_fields(
             transition_id,
             chain_id,
             effective_at,
             current_key_id,
             current_key_fingerprint,
             next_key_id,
             next_key_fingerprint,
             bounds
           ),
         {:ok, canonical_payload} <- Jcs.encode({:object, payload_members}, bounds),
         true <- payload_bytes == canonical_payload do
      {:ok,
       %{
         transition_id: transition_id,
         chain_id: chain_id,
         effective_at: effective_at,
         current_key_id: current_key_id,
         current_key_fingerprint: current_key_fingerprint,
         next_key_id: next_key_id,
         next_key_fingerprint: next_key_fingerprint,
         message: protected_segment <> "." <> payload_segment,
         signature: signature
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def parse(_compact, _bounds), do: {:error, :invalid}

  defp validate_transition_input(transition, bounds) do
    with true <- is_binary(transition.current_public_key),
         true <- byte_size(transition.current_public_key) == bounds.public_key_bytes,
         true <- is_binary(transition.next_public_key),
         true <- byte_size(transition.next_public_key) == bounds.public_key_bytes,
         :ok <-
           validate_transition_fields(
             transition.transition_id,
             transition.chain_id,
             transition.effective_at,
             transition.current_key_id,
             :crypto.hash(:sha256, transition.current_public_key),
             transition.next_key_id,
             :crypto.hash(:sha256, transition.next_public_key),
             bounds
           ) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_expected(expected, bounds),
    do: ContextValidation.expected_transition(expected, bounds)

  defp validate_transition_fields(
         transition_id,
         chain_id,
         effective_at,
         current_key_id,
         current_fingerprint,
         next_key_id,
         next_fingerprint,
         bounds
       ) do
    if valid_identifier?(transition_id, bounds) and valid_identifier?(chain_id, bounds) and
         valid_time?(effective_at, bounds) and valid_key_id?(current_key_id, bounds) and
         valid_key_id?(next_key_id, bounds) do
      ContextValidation.distinct_fingerprints(current_fingerprint, next_fingerprint, bounds)
    else
      {:error, :invalid}
    end
  end

  defp validate_historical_key(key, bounds),
    do: ContextValidation.historical_key(key, bounds)

  defp inside_window?(time, key) do
    key.valid_from <= time and
      (key.valid_before == :unbounded or time < key.valid_before)
  end

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
         kind: :key_transition,
         protected_segment: protected_segment,
         payload_segment: payload_segment,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end

  defp header_json(key_id) do
    {:object,
     [
       {"alg", {:string, "EdDSA"}},
       {"kid", {:string, key_id}},
       {"typ", {:string, "ba+key-transition"}}
     ]}
  end

  defp payload_json(transition, current_fingerprint, next_fingerprint) do
    {:object,
     [
       {"chain_id", {:string, transition.chain_id}},
       {"effective_at", {:integer, transition.effective_at}},
       {"from_key_fingerprint",
        {:string, Base.url_encode64(current_fingerprint, padding: false)}},
       {"to_key_fingerprint", {:string, Base.url_encode64(next_fingerprint, padding: false)}},
       {"to_key_id", {:string, transition.next_key_id}},
       {"transition_id", {:string, transition.transition_id}},
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
