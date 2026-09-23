defmodule BoundedAuthorityProtocol.RoleAttestation.V1.Codec do
  @moduledoc false

  alias BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts
  alias BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation
  alias BoundedAuthorityProtocol.RoleAttestation.V1.ExpectedAttestation
  alias BoundedAuthorityProtocol.RoleAttestation.V1.RoleAttestation
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.CompactJws
  alias BoundedAuthorityProtocol.V1.ContextValidation
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.StringOrUri

  @header_keys ~w(alg kid typ)
  @payload_keys ~w(exp jti key_id nbf public_key role v)
  @roles ~w(issuer holder)
  @typ "ba+role-attestation"
  @public_key_bytes 32

  @spec signing_input(RoleAttestation.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  def signing_input(
        %RoleAttestation{
          attestor_key_id: _,
          jti: _,
          key_id: _,
          public_key: _,
          role: _,
          nbf: _,
          exp: _
        } = attestation,
        limits
      ) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         :ok <- validate_attestation(attestation, bounds),
         {:ok, protected} <- Jcs.encode(header_json(attestation.attestor_key_id), bounds),
         {:ok, payload} <- Jcs.encode(payload_json(attestation), bounds),
         true <- byte_size(protected) <= bounds.decoded_segment_bytes,
         true <- byte_size(payload) <= bounds.decoded_segment_bytes,
         {:ok, _header} <- Json.decode(protected, bounds),
         {:ok, _claims} <- Json.decode(payload, bounds) do
      build_signing_input(protected, payload, bounds)
    else
      _failure -> {:error, :invalid}
    end
  end

  def signing_input(_attestation, _limits), do: {:error, :invalid}

  @spec assemble(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble(
        %SigningInput{
          kind: :role_attestation,
          protected_segment: _,
          payload_segment: _,
          message: _
        } = signing_input,
        signature,
        limits
      ) do
    with {:ok, compact} <- CompactJws.assemble(signing_input, signature, limits),
         {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, _parsed} <- parse(compact, bounds) do
      {:ok, compact}
    else
      _failure -> {:error, :invalid}
    end
  end

  def assemble(_signing_input, _signature, _limits), do: {:error, :invalid}

  @spec decode(binary(), Bounds.t() | map()) ::
          {:ok, DecodedAttestation.t()} | {:error, :invalid}
  def decode(compact, limits) when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, parsed} <- parse(compact, bounds) do
      {:ok,
       %DecodedAttestation{
         version: 1,
         attestor_key_id: parsed.attestor_key_id,
         jti: parsed.jti,
         key_id: parsed.key_id,
         public_key: parsed.public_key,
         role: parsed.role,
         nbf: parsed.nbf,
         exp: parsed.exp,
         verification: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def decode(_compact, _limits), do: {:error, :invalid}

  @spec verify(binary(), ExpectedAttestation.t()) ::
          {:ok, AttestationFacts.t()} | {:error, :invalid}
  def verify(
        compact,
        %ExpectedAttestation{
          attestor: _,
          subject_key_id: _,
          subject_public_key: _,
          now: _,
          bounds: _
        } = expected
      )
      when is_binary(compact) do
    attestor = expected.attestor

    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_historical_key(attestor, bounds),
         :ok <- validate_subject(expected.subject_key_id, expected.subject_public_key, bounds),
         :ok <- validate_now(expected.now, bounds),
         {:ok, parsed} <- parse(compact, bounds),
         {:ok, attestor_fingerprint} <- Jwk.public_key_thumbprint_raw(attestor.public_key, bounds),
         {:ok, subject_fingerprint} <-
           Jwk.public_key_thumbprint_raw(expected.subject_public_key, bounds),
         true <- parsed.attestor_key_id == attestor.key_id,
         true <- parsed.key_id == expected.subject_key_id,
         true <- FixedBytes.equal?(parsed.public_key, expected.subject_public_key),
         true <- parsed.key_id != attestor.key_id,
         true <- not FixedBytes.equal?(attestor_fingerprint, subject_fingerprint),
         true <- parsed.nbf >= attestor.valid_from,
         true <-
           attestor.valid_before == :unbounded or
             parsed.exp <= attestor.valid_before,
         true <- parsed.nbf <= expected.now and expected.now < parsed.exp,
         true <- verify_signature(parsed.message, parsed.signature, attestor.public_key) do
      {:ok,
       %AttestationFacts{
         version: 1,
         attestor_key_id: attestor.key_id,
         attestor_key_fingerprint: attestor_fingerprint,
         subject_key_id: parsed.key_id,
         subject_key_fingerprint: subject_fingerprint,
         role: parsed.role,
         jti: parsed.jti,
         nbf: parsed.nbf,
         exp: parsed.exp,
         verification: :signature_and_window,
         trust: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def verify(_compact, _expected), do: {:error, :invalid}

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
         {:string, @typ} <- header["typ"],
         {:string, attestor_key_id} <- header["kid"],
         true <- valid_key_id?(attestor_key_id, bounds),
         {:ok, canonical_header} <- Jcs.encode({:object, header_members}, bounds),
         true <- protected_bytes == canonical_header,
         {:ok, {:object, payload_members}} <- Json.decode(payload_bytes, bounds),
         {:ok, payload} <- closed_map(payload_members, @payload_keys),
         {:integer, 1} <- payload["v"],
         {:string, jti} <- payload["jti"],
         true <- valid_identifier?(jti, bounds),
         {:string, key_id} <- payload["key_id"],
         true <- valid_key_id?(key_id, bounds),
         {:string, public_key_encoded} <- payload["public_key"],
         {:ok, public_key} <- Base64Url.decode(public_key_encoded, bounds),
         true <- byte_size(public_key) == @public_key_bytes,
         {:string, role} <- payload["role"],
         true <- role in @roles,
         {:integer, nbf} <- payload["nbf"],
         true <- valid_time?(nbf, bounds),
         {:integer, exp} <- payload["exp"],
         true <- valid_time?(exp, bounds),
         true <- nbf < exp,
         {:ok, canonical_payload} <- Jcs.encode({:object, payload_members}, bounds),
         true <- payload_bytes == canonical_payload do
      {:ok,
       %{
         attestor_key_id: attestor_key_id,
         jti: jti,
         key_id: key_id,
         public_key: public_key,
         role: role,
         nbf: nbf,
         exp: exp,
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
         kind: :role_attestation,
         protected_segment: protected_segment,
         payload_segment: payload_segment,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end

  defp validate_attestation(attestation, bounds) do
    if valid_key_id?(attestation.attestor_key_id, bounds) and
         valid_identifier?(attestation.jti, bounds) and
         valid_key_id?(attestation.key_id, bounds) and
         valid_public_key?(attestation.public_key, bounds) and
         valid_role?(attestation.role) and valid_time?(attestation.nbf, bounds) and
         valid_time?(attestation.exp, bounds) and attestation.nbf < attestation.exp do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_historical_key(
         %HistoricalPublicKey{key_id: _, public_key: _, valid_from: _, valid_before: _} = key,
         bounds
       ),
       do: ContextValidation.historical_key(key, bounds)

  defp validate_historical_key(_key, _bounds), do: {:error, :invalid}

  defp validate_subject(key_id, public_key, bounds) do
    if valid_key_id?(key_id, bounds) and valid_public_key?(public_key, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_now(now, bounds),
    do: if(valid_time?(now, bounds), do: :ok, else: {:error, :invalid})

  defp header_json(attestor_key_id) do
    {:object,
     [
       {"alg", {:string, "EdDSA"}},
       {"kid", {:string, attestor_key_id}},
       {"typ", {:string, @typ}}
     ]}
  end

  defp payload_json(attestation) do
    {:object,
     [
       {"exp", {:integer, attestation.exp}},
       {"jti", {:string, attestation.jti}},
       {"key_id", {:string, attestation.key_id}},
       {"nbf", {:integer, attestation.nbf}},
       {"public_key", {:string, Base.url_encode64(attestation.public_key, padding: false)}},
       {"role", {:string, attestation.role}},
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

  defp valid_public_key?(public_key, bounds),
    do:
      is_binary(public_key) and byte_size(public_key) == @public_key_bytes and
        byte_size(public_key) <= bounds.public_key_bytes

  defp valid_role?(role), do: is_binary(role) and role in @roles

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
