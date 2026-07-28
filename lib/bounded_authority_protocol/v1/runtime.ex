defmodule BoundedAuthorityProtocol.V1.Runtime do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.{
    Base64Url,
    Bounds,
    CompactJws,
    Credentials,
    DecodedGrant,
    DecodedProof,
    EnvelopeFacts,
    ExpectedGrant,
    ExpectedRequest,
    Grant,
    GrantFacts,
    Jcs,
    Json,
    Jwk,
    Operation,
    Proof,
    RequestDigest,
    Selector,
    SigningInput,
    TrustedIssuer,
    Uri
  }

  @grant_header_keys ~w(alg kid typ)
  @grant_payload_keys ~w(aud cnf exp iat iss jti nbf operations v)
  @proof_header_keys ~w(alg jwk typ)
  @proof_payload_keys ~w(ath ba_inv ba_op ba_req htm htu iat jti nonce v)
  @proof_payload_keys_without_nonce ~w(ath ba_inv ba_op ba_req htm htu iat jti v)
  @token_punctuation ~c"!#$%&'*+-.^_`|~"

  def grant_signing_input(%Grant{} = grant, limits) do
    fixed(fn ->
      with {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, header, payload} <- grant_json(grant, bounds),
           {:ok, protected} <- Jcs.encode(header, bounds),
           {:ok, payload_bytes} <- Jcs.encode(payload, bounds) do
        signing_input(:grant, protected, payload_bytes, bounds)
      end
    end)
  end

  def grant_signing_input(_grant, _limits), do: {:error, :invalid}

  def proof_signing_input(%Proof{} = proof, limits) do
    fixed(fn ->
      with {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, header, payload} <- proof_json(proof, bounds),
           {:ok, protected} <- Jcs.encode(header, bounds),
           {:ok, payload_bytes} <- Jcs.encode(payload, bounds) do
        signing_input(:proof, protected, payload_bytes, bounds)
      end
    end)
  end

  def proof_signing_input(_proof, _limits), do: {:error, :invalid}

  def assemble_compact(%SigningInput{} = input, signature, limits) when is_binary(signature) do
    fixed(fn ->
      with {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, compact} <- CompactJws.assemble(input, signature, bounds),
           :ok <- validate_assembled_compact(input.kind, compact, bounds) do
        {:ok, compact}
      end
    end)
  end

  def assemble_compact(_input, _signature, _limits), do: {:error, :invalid}

  def decode_grant(compact, limits) when is_binary(compact) do
    fixed(fn ->
      with {:ok, parsed} <- parse_grant(compact, limits) do
        {:ok, parsed.decoded}
      end
    end)
  end

  def decode_grant(_compact, _limits), do: {:error, :invalid}

  def decode_proof(compact, limits) when is_binary(compact) do
    fixed(fn ->
      with {:ok, parsed} <- parse_proof(compact, limits) do
        {:ok, parsed.decoded}
      end
    end)
  end

  def decode_proof(_compact, _limits), do: {:error, :invalid}

  def verify_grant(
        compact,
        %TrustedIssuer{} = trusted,
        %ExpectedGrant{} = expected
      )
      when is_binary(compact) do
    fixed(fn ->
      with {:ok, bounds} <- Bounds.coerce(expected.bounds),
           :ok <- validate_trusted_issuer(trusted, bounds),
           :ok <- validate_expected_grant(expected, bounds),
           {:ok, parsed} <- parse_grant(compact, bounds),
           :ok <- verify_grant_parsed(parsed, trusted, expected, bounds) do
        {:ok, grant_facts(parsed.decoded, trusted.public_key, expected.audience, bounds)}
      end
    end)
  end

  def verify_grant(_compact, _trusted, _expected), do: {:error, :invalid}

  def check_envelope(
        %Credentials{grant: grant, proof: proof},
        %ExpectedRequest{} = expected
      )
      when is_binary(grant) and is_binary(proof) do
    fixed(fn ->
      with {:ok, bounds} <- Bounds.coerce(expected.bounds),
           :ok <- validate_expected_request(expected, bounds),
           grant_expected = %ExpectedGrant{
             issuer: expected.issuer,
             audience: expected.audience,
             evaluation_time: expected.evaluation_time,
             clock_skew: expected.clock_skew,
             bounds: bounds
           },
           {:ok, grant_parsed} <- parse_grant(grant, bounds),
           :ok <-
             verify_grant_parsed(
               grant_parsed,
               expected.trusted_issuer,
               grant_expected,
               bounds
             ),
           {:ok, proof_parsed} <- parse_proof(proof, bounds),
           :ok <- verify_proof_parsed(proof_parsed, grant, grant_parsed, expected, bounds) do
        {:ok, envelope_facts(grant_parsed, proof_parsed, expected, bounds)}
      end
    end)
  end

  def check_envelope(_credentials, _expected), do: {:error, :invalid}

  defp parse_grant(compact, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, {protected_segment, payload_segment, signature_segment}} <-
           CompactJws.scan(compact, bounds),
         {:ok, protected_bytes} <- Base64Url.decode(protected_segment, bounds),
         {:ok, payload_bytes} <- Base64Url.decode(payload_segment, bounds),
         {:ok, signature} <- Base64Url.decode(signature_segment, bounds),
         true <- byte_size(signature) == bounds.signature_bytes,
         {:ok, {:object, header_members}} <- Json.decode(protected_bytes, bounds),
         {:ok, {:object, payload_members}} <- Json.decode(payload_bytes, bounds),
         {:ok, header} <- closed_map(header_members, @grant_header_keys),
         {:ok, payload} <- closed_map(payload_members, @grant_payload_keys),
         {:ok, decoded} <- decode_grant_fields(header, payload, bounds) do
      {:ok,
       %{
         decoded: decoded,
         signature: signature,
         message: protected_segment <> "." <> payload_segment
       }}
    end
  end

  defp parse_proof(compact, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, {protected_segment, payload_segment, signature_segment}} <-
           CompactJws.scan(compact, bounds),
         {:ok, protected_bytes} <- Base64Url.decode(protected_segment, bounds),
         {:ok, payload_bytes} <- Base64Url.decode(payload_segment, bounds),
         {:ok, signature} <- Base64Url.decode(signature_segment, bounds),
         true <- byte_size(signature) == bounds.signature_bytes,
         {:ok, {:object, header_members}} <- Json.decode(protected_bytes, bounds),
         {:ok, {:object, payload_members}} <- Json.decode(payload_bytes, bounds),
         {:ok, header} <- closed_map(header_members, @proof_header_keys),
         {:ok, payload} <-
           closed_map_one_of(payload_members, [
             @proof_payload_keys,
             @proof_payload_keys_without_nonce
           ]),
         {:ok, decoded} <- decode_proof_fields(header, payload, bounds) do
      {:ok,
       %{
         decoded: decoded,
         signature: signature,
         message: protected_segment <> "." <> payload_segment
       }}
    end
  end

  defp decode_grant_fields(header, payload, bounds) do
    with {:string, "EdDSA"} <- header["alg"],
         {:string, "ba+cap"} <- header["typ"],
         {:string, key_id} <- header["kid"],
         true <- valid_key_id?(key_id, bounds),
         {:integer, 1} <- payload["v"],
         {:string, issuer} <- payload["iss"],
         true <- valid_identifier?(issuer, bounds),
         {:string, grant_id} <- payload["jti"],
         true <- valid_identifier?(grant_id, bounds),
         {:ok, audiences} <- decode_audiences(payload["aud"], bounds),
         true <- unique?(audiences),
         {:integer, issued_at} <- payload["iat"],
         {:integer, not_before} <- payload["nbf"],
         {:integer, expires_at} <- payload["exp"],
         true <- coherent_times?(issued_at, not_before, expires_at),
         {:object, confirmation_members} <- payload["cnf"],
         {:ok, confirmation} <- closed_map(confirmation_members, ["jkt"]),
         {:string, holder_thumbprint_encoded} <- confirmation["jkt"],
         {:ok, holder_thumbprint} <- Base64Url.decode(holder_thumbprint_encoded, bounds),
         true <- byte_size(holder_thumbprint) == bounds.digest_bytes,
         {:array, operation_values} <- payload["operations"],
         {:ok, operations} <- operations(operation_values, bounds),
         true <- unique?(Enum.map(operations, & &1.name)) do
      {:ok,
       %DecodedGrant{
         version: 1,
         key_id: key_id,
         issuer: issuer,
         grant_id: grant_id,
         audiences: audiences,
         issued_at: issued_at,
         not_before: not_before,
         expires_at: expires_at,
         holder_thumbprint: holder_thumbprint,
         operations: operations,
         verification: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp decode_proof_fields(header, payload, bounds) do
    with {:string, "EdDSA"} <- header["alg"],
         {:string, "dpop+jwt"} <- header["typ"],
         {:object, jwk_members} <- header["jwk"],
         {:ok, jwk_bytes} <- Jcs.encode({:object, jwk_members}, bounds),
         {:ok, holder_public_key} <- Jwk.decode_public(jwk_bytes, bounds),
         {:ok, holder_thumbprint} <- Jwk.thumbprint_raw(jwk_bytes, bounds),
         {:integer, 1} <- payload["v"],
         {:string, proof_id} <- payload["jti"],
         true <- valid_identifier?(proof_id, bounds),
         {:string, method} <- payload["htm"],
         true <- valid_method?(method, bounds),
         {:string, target_uri} <- payload["htu"],
         {:ok, ^target_uri} <- Uri.normalize(target_uri, bounds),
         {:integer, issued_at} <- payload["iat"],
         {:ok, nonce} <- optional_nonce(payload, bounds),
         {:string, invocation_id} <- payload["ba_inv"],
         true <- valid_uuid?(invocation_id),
         {:string, operation} <- payload["ba_op"],
         true <- valid_operation?(operation, bounds),
         {:string, grant_hash_encoded} <- payload["ath"],
         {:ok, grant_hash} <- Base64Url.decode(grant_hash_encoded, bounds),
         true <- byte_size(grant_hash) == bounds.digest_bytes,
         {:string, request_hash_encoded} <- payload["ba_req"],
         {:ok, request_hash} <- Base64Url.decode(request_hash_encoded, bounds),
         true <- byte_size(request_hash) == bounds.digest_bytes do
      {:ok,
       %DecodedProof{
         version: 1,
         proof_id: proof_id,
         method: method,
         target_uri: target_uri,
         issued_at: issued_at,
         nonce: nonce,
         invocation_id: invocation_id,
         operation: operation,
         grant_hash: grant_hash,
         request_hash: request_hash,
         holder_public_key: holder_public_key,
         holder_thumbprint: holder_thumbprint,
         verification: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp grant_json(grant, bounds) do
    with true <- valid_key_id?(grant.key_id, bounds),
         true <- valid_identifier?(grant.issuer, bounds),
         true <- valid_identifier?(grant.grant_id, bounds),
         true <- valid_string_list?(grant.audiences, bounds.audiences, bounds.identifier_bytes),
         true <- unique?(grant.audiences),
         true <- coherent_times?(grant.issued_at, grant.not_before, grant.expires_at),
         true <-
           is_binary(grant.holder_thumbprint) and
             byte_size(grant.holder_thumbprint) == bounds.digest_bytes,
         {:ok, operation_values} <- encode_operations(grant.operations, bounds) do
      header =
        {:object,
         [
           {"alg", {:string, "EdDSA"}},
           {"kid", {:string, grant.key_id}},
           {"typ", {:string, "ba+cap"}}
         ]}

      payload =
        {:object,
         [
           {"aud", {:array, Enum.map(grant.audiences, &{:string, &1})}},
           {"cnf",
            {:object,
             [
               {"jkt", {:string, Base.url_encode64(grant.holder_thumbprint, padding: false)}}
             ]}},
           {"exp", {:integer, grant.expires_at}},
           {"iat", {:integer, grant.issued_at}},
           {"iss", {:string, grant.issuer}},
           {"jti", {:string, grant.grant_id}},
           {"nbf", {:integer, grant.not_before}},
           {"operations", {:array, operation_values}},
           {"v", {:integer, 1}}
         ]}

      {:ok, header, payload}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp proof_json(proof, bounds) do
    with true <-
           is_binary(proof.holder_public_key) and
             byte_size(proof.holder_public_key) == bounds.public_key_bytes,
         {:ok, jwk_bytes} <- Jwk.encode_public(proof.holder_public_key, bounds),
         {:ok, jwk} <- Json.decode(jwk_bytes, bounds),
         true <- valid_identifier?(proof.proof_id, bounds),
         true <- valid_method?(proof.method, bounds),
         {:ok, target_uri} <- Uri.normalize(proof.target_uri, bounds),
         true <- target_uri == proof.target_uri,
         true <- is_integer(proof.issued_at),
         true <- valid_optional_nonce?(proof.nonce, bounds),
         true <- valid_uuid?(proof.invocation_id),
         true <- valid_operation?(proof.operation, bounds),
         {:ok, grant_hash} <- CompactJws.ath(proof.grant_compact, bounds),
         {:ok, request_hash} <-
           RequestDigest.digest(proof.operation, proof.cast_arguments, bounds) do
      header =
        {:object,
         [
           {"alg", {:string, "EdDSA"}},
           {"jwk", jwk},
           {"typ", {:string, "dpop+jwt"}}
         ]}

      payload_members = [
        {"ath", {:string, grant_hash}},
        {"ba_inv", {:string, proof.invocation_id}},
        {"ba_op", {:string, proof.operation}},
        {"ba_req", {:string, request_hash}},
        {"htm", {:string, proof.method}},
        {"htu", {:string, target_uri}},
        {"iat", {:integer, proof.issued_at}},
        {"jti", {:string, proof.proof_id}},
        {"v", {:integer, 1}}
      ]

      payload_members =
        if is_binary(proof.nonce) do
          [{"nonce", {:string, proof.nonce}} | payload_members]
        else
          payload_members
        end

      {:ok, header, {:object, payload_members}}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp verify_grant_parsed(parsed, trusted, expected, bounds) do
    grant = parsed.decoded

    with true <- secure_equal?(grant.key_id, trusted.key_id),
         true <- secure_equal?(grant.issuer, expected.issuer),
         true <- Enum.any?(grant.audiences, &secure_equal?(&1, expected.audience)),
         true <- grant.issued_at <= expected.evaluation_time + expected.clock_skew,
         true <- grant.not_before <= expected.evaluation_time + expected.clock_skew,
         true <- grant.expires_at > expected.evaluation_time - expected.clock_skew,
         true <- verify_signature(parsed.message, parsed.signature, trusted.public_key),
         {:ok, _fingerprint} <- Jwk.public_key_thumbprint_raw(trusted.public_key, bounds) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp verify_proof_parsed(proof_parsed, grant_compact, grant_parsed, expected, bounds) do
    proof = proof_parsed.decoded
    grant = grant_parsed.decoded

    with true <- secure_equal?(proof.holder_thumbprint, grant.holder_thumbprint),
         {:ok, grant_hash} <- CompactJws.hash(grant_compact, bounds),
         true <- secure_equal?(proof.grant_hash, grant_hash),
         true <- secure_equal?(proof.method, expected.method),
         true <- secure_equal?(proof.target_uri, expected.target_uri),
         true <- secure_equal?(proof.invocation_id, expected.invocation_id),
         true <- secure_equal?(proof.operation, expected.operation),
         {:ok, request_hash} <-
           RequestDigest.digest_raw(expected.operation, expected.cast_arguments, bounds),
         true <- secure_equal?(proof.request_hash, request_hash),
         true <-
           proof.issued_at >=
             expected.evaluation_time - expected.proof_max_age - expected.clock_skew,
         true <- proof.issued_at <= expected.evaluation_time + expected.clock_skew,
         true <- nonce_matches?(proof.nonce, expected.nonce),
         {:ok, operation} <- unique_operation(grant.operations, expected.operation),
         :ok <- Selector.match_all(operation.selectors, expected.cast_arguments, bounds),
         true <-
           verify_signature(
             proof_parsed.message,
             proof_parsed.signature,
             proof.holder_public_key
           ) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_trusted_issuer(%TrustedIssuer{} = trusted, bounds) do
    if valid_key_id?(trusted.key_id, bounds) and is_binary(trusted.public_key) and
         byte_size(trusted.public_key) == bounds.public_key_bytes do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_expected_grant(%ExpectedGrant{} = expected, bounds) do
    if valid_identifier?(expected.issuer, bounds) and
         valid_identifier?(expected.audience, bounds) and is_integer(expected.evaluation_time) and
         is_integer(expected.clock_skew) and expected.clock_skew >= 0 and
         expected.clock_skew <= bounds.clock_skew do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_expected_request(%ExpectedRequest{} = expected, bounds) do
    grant_expected = %ExpectedGrant{
      issuer: expected.issuer,
      audience: expected.audience,
      evaluation_time: expected.evaluation_time,
      clock_skew: expected.clock_skew,
      bounds: bounds
    }

    with :ok <- validate_trusted_issuer(expected.trusted_issuer, bounds),
         :ok <- validate_expected_grant(grant_expected, bounds),
         true <- valid_method?(expected.method, bounds),
         {:ok, normalized_uri} <- Uri.normalize(expected.target_uri, bounds),
         true <- normalized_uri == expected.target_uri,
         true <- valid_uuid?(expected.invocation_id),
         true <- valid_operation?(expected.operation, bounds),
         {:ok, _digest} <-
           RequestDigest.digest_raw(expected.operation, expected.cast_arguments, bounds),
         true <-
           is_integer(expected.proof_max_age) and expected.proof_max_age > 0 and
             expected.proof_max_age <= bounds.proof_max_age,
         true <- valid_nonce_expectation?(expected.nonce, bounds) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp grant_facts(grant, public_key, audience, bounds) do
    {:ok, fingerprint} = Jwk.public_key_thumbprint_raw(public_key, bounds)

    %GrantFacts{
      version: 1,
      issuer: grant.issuer,
      grant_id: grant.grant_id,
      issuer_key_fingerprint: fingerprint,
      holder_thumbprint: grant.holder_thumbprint,
      matched_audience: audience,
      issued_at: grant.issued_at,
      not_before: grant.not_before,
      expires_at: grant.expires_at,
      authorization: :not_evaluated
    }
  end

  defp envelope_facts(grant_parsed, proof_parsed, expected, bounds) do
    grant = grant_parsed.decoded
    proof = proof_parsed.decoded
    {:ok, fingerprint} = Jwk.public_key_thumbprint_raw(expected.trusted_issuer.public_key, bounds)

    %EnvelopeFacts{
      version: 1,
      issuer: grant.issuer,
      grant_id: grant.grant_id,
      issuer_key_fingerprint: fingerprint,
      holder_thumbprint: grant.holder_thumbprint,
      matched_audience: expected.audience,
      issued_at: grant.issued_at,
      not_before: grant.not_before,
      expires_at: grant.expires_at,
      authorization: :not_evaluated,
      proof_id: proof.proof_id,
      invocation_id: proof.invocation_id,
      operation: proof.operation,
      target_uri: proof.target_uri,
      grant_hash: proof.grant_hash,
      request_hash: proof.request_hash,
      proof_issued_at: proof.issued_at
    }
  end

  defp signing_input(kind, protected_bytes, payload_bytes, bounds) do
    protected_segment = Base.url_encode64(protected_bytes, padding: false)
    payload_segment = Base.url_encode64(payload_bytes, padding: false)
    message = protected_segment <> "." <> payload_segment

    if byte_size(protected_segment) <= bounds.encoded_segment_bytes and
         byte_size(payload_segment) <= bounds.encoded_segment_bytes and
         byte_size(message) + 1 + 86 <= bounds.compact_bytes do
      {:ok,
       %SigningInput{
         kind: kind,
         protected_segment: protected_segment,
         payload_segment: payload_segment,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end

  defp encode_operations(operations, bounds) when is_list(operations) do
    with true <- nonempty_bounded?(operations, bounds.operations),
         true <- Enum.all?(operations, &match?(%Operation{}, &1)),
         true <- unique?(Enum.map(operations, & &1.name)) do
      map_ok(operations, &encode_operation(&1, bounds))
    else
      _failure -> {:error, :invalid}
    end
  end

  defp encode_operations(_operations, _bounds), do: {:error, :invalid}

  defp encode_operation(%Operation{name: name, selectors: selectors}, bounds) do
    with true <- valid_operation?(name, bounds),
         true <- nonempty_bounded?(selectors, bounds.selectors),
         {:ok, encoded_selectors} <- map_ok(selectors, &encode_selector(&1, bounds)) do
      {:ok,
       {:object,
        [
          {"name", {:string, name}},
          {"selectors", {:array, encoded_selectors}}
        ]}}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp encode_selector(:all, _bounds),
    do: {:ok, {:object, [{"kind", {:string, "all"}}]}}

  defp encode_selector({:equals, path, value}, bounds) do
    with true <- valid_path?(path, bounds),
         {:ok, _encoded} <- Jcs.encode(value, bounds) do
      {:ok,
       {:object,
        [
          {"kind", {:string, "equals"}},
          {"path", {:array, Enum.map(path, &{:string, &1})}},
          {"value", value}
        ]}}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp encode_selector({:one_of, path, values}, bounds) do
    with true <- valid_path?(path, bounds),
         true <- nonempty_bounded?(values, bounds.one_of_values),
         true <- Enum.all?(values, &match?({:ok, _}, Jcs.encode(&1, bounds))) do
      {:ok,
       {:object,
        [
          {"kind", {:string, "one_of"}},
          {"path", {:array, Enum.map(path, &{:string, &1})}},
          {"values", {:array, values}}
        ]}}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp encode_selector(_selector, _bounds), do: {:error, :invalid}

  defp operations(values, bounds) when is_list(values) do
    with true <- nonempty_bounded?(values, bounds.operations),
         {:ok, decoded} <- map_ok(values, &operation(&1, bounds)) do
      {:ok, decoded}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp operation({:object, members}, bounds) do
    with {:ok, operation} <- closed_map(members, ["name", "selectors"]),
         {:string, name} <- operation["name"],
         true <- valid_operation?(name, bounds),
         {:array, selector_values} <- operation["selectors"],
         true <- nonempty_bounded?(selector_values, bounds.selectors),
         {:ok, selectors} <- map_ok(selector_values, &selector(&1, bounds)) do
      {:ok, %Operation{name: name, selectors: selectors}}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp operation(_value, _bounds), do: {:error, :invalid}

  defp selector({:object, members}, bounds) do
    case closed_map_one_of(members, [
           ["kind"],
           ["kind", "path", "value"],
           ["kind", "path", "values"]
         ]) do
      {:ok, %{"kind" => {:string, "all"}}} ->
        {:ok, :all}

      {:ok,
       %{
         "kind" => {:string, "equals"},
         "path" => {:array, path_values},
         "value" => value
       }} ->
        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),
             true <- path != [],
             {:ok, _encoded} <- Jcs.encode(value, bounds) do
          {:ok, {:equals, path, value}}
        else
          _failure -> {:error, :invalid}
        end

      {:ok,
       %{
         "kind" => {:string, "one_of"},
         "path" => {:array, path_values},
         "values" => {:array, values}
       }} ->
        with {:ok, path} <- strings(path_values, bounds.path_segments, bounds.key_bytes),
             true <- path != [],
             true <- nonempty_bounded?(values, bounds.one_of_values),
             true <- Enum.all?(values, &match?({:ok, _}, Jcs.encode(&1, bounds))) do
          {:ok, {:one_of, path, values}}
        else
          _failure -> {:error, :invalid}
        end

      _failure ->
        {:error, :invalid}
    end
  end

  defp selector(_value, _bounds), do: {:error, :invalid}

  defp validate_assembled_compact(:grant, compact, bounds) do
    case parse_grant(compact, bounds) do
      {:ok, _parsed} -> :ok
      {:error, :invalid} -> {:error, :invalid}
    end
  end

  defp validate_assembled_compact(:proof, compact, bounds) do
    case parse_proof(compact, bounds) do
      {:ok, _parsed} -> :ok
      {:error, :invalid} -> {:error, :invalid}
    end
  end

  defp decode_audiences({:string, audience}, bounds) do
    if valid_identifier?(audience, bounds),
      do: {:ok, [audience]},
      else: {:error, :invalid}
  end

  defp decode_audiences({:array, audience_values}, bounds) do
    with {:ok, audiences} <-
           strings(audience_values, bounds.audiences, bounds.identifier_bytes),
         true <- Enum.all?(audiences, &valid_identifier?(&1, bounds)) do
      {:ok, audiences}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp decode_audiences(_value, _bounds), do: {:error, :invalid}

  defp closed_map(members, keys) when is_list(members) do
    if length(members) == length(keys) and
         Enum.sort(Enum.map(members, &elem(&1, 0))) == Enum.sort(keys) do
      {:ok, Map.new(members)}
    else
      {:error, :invalid}
    end
  end

  defp closed_map_one_of(members, alternatives) do
    Enum.find_value(alternatives, {:error, :invalid}, fn keys ->
      case closed_map(members, keys) do
        {:ok, map} -> {:ok, map}
        {:error, :invalid} -> false
      end
    end)
  end

  defp strings(values, maximum_count, maximum_bytes) when is_list(values) do
    if nonempty_bounded?(values, maximum_count) do
      map_ok(values, fn
        {:string, value}
        when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum_bytes ->
          valid_string(value)

        _invalid ->
          {:error, :invalid}
      end)
    else
      {:error, :invalid}
    end
  end

  defp valid_string(value) do
    if String.valid?(value), do: {:ok, value}, else: {:error, :invalid}
  end

  defp optional_nonce(payload, bounds) do
    case Map.fetch(payload, "nonce") do
      :error ->
        {:ok, nil}

      {:ok, {:string, nonce}} ->
        if valid_nonce?(nonce, bounds), do: {:ok, nonce}, else: {:error, :invalid}

      {:ok, _invalid} ->
        {:error, :invalid}
    end
  end

  defp unique_operation(operations, name) do
    Enum.find_value(operations, {:error, :invalid}, fn operation ->
      secure_equal?(operation.name, name) && {:ok, operation}
    end)
  end

  defp nonce_matches?(nil, :not_required), do: true
  defp nonce_matches?(nonce, {:required, expected}), do: secure_equal?(nonce, expected)
  defp nonce_matches?(_nonce, _expectation), do: false

  defp verify_signature(message, signature, public_key) do
    is_binary(message) and is_binary(signature) and byte_size(signature) == 64 and
      is_binary(public_key) and byte_size(public_key) == 32 and
      :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: :crypto.hash_equals(left, right)

  defp secure_equal?(_left, _right), do: false

  defp coherent_times?(issued_at, not_before, expires_at),
    do:
      is_integer(issued_at) and is_integer(not_before) and is_integer(expires_at) and
        issued_at < expires_at and not_before < expires_at

  defp valid_key_id?(value, bounds),
    do:
      is_binary(value) and byte_size(value) in 1..bounds.kid_bytes and
        ascii_bytes?(value, fn byte ->
          byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~]
        end)

  defp valid_identifier?(value, bounds),
    do:
      is_binary(value) and byte_size(value) in 1..bounds.identifier_bytes and
        String.valid?(value) and string_or_uri?(value)

  defp string_or_uri?(value) do
    if String.contains?(value, ":") do
      match?({:ok, %URI{}}, URI.new(value))
    else
      true
    end
  end

  defp valid_operation?(value, bounds),
    do:
      is_binary(value) and byte_size(value) in 1..bounds.operation_bytes and
        ascii_bytes?(value, &(&1 in 0x20..0x7E))

  defp valid_method?(value, bounds),
    do:
      is_binary(value) and byte_size(value) in 1..bounds.method_bytes and
        ascii_bytes?(value, fn byte ->
          byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in @token_punctuation
        end)

  defp valid_uuid?(
         <<a::binary-size(8), "-", b::binary-size(4), "-", version, c::binary-size(3), "-",
           variant, d::binary-size(3), "-", e::binary-size(12)>>
       ) do
    version in ?1..?5 and variant in ~c"89ab" and
      Enum.all?([a, b, c, d, e], &lower_hex?/1)
  end

  defp valid_uuid?(_value), do: false

  defp lower_hex?(value),
    do: ascii_bytes?(value, &(&1 in ?0..?9 or &1 in ?a..?f))

  defp valid_nonce_expectation?(:not_required, _bounds), do: true

  defp valid_nonce_expectation?({:required, nonce}, bounds),
    do: valid_nonce?(nonce, bounds)

  defp valid_nonce_expectation?(_value, _bounds), do: false

  defp valid_optional_nonce?(nil, _bounds), do: true
  defp valid_optional_nonce?(nonce, bounds), do: valid_nonce?(nonce, bounds)

  defp valid_nonce?(nonce, bounds),
    do: is_binary(nonce) and byte_size(nonce) in 1..bounds.nonce_bytes and String.valid?(nonce)

  defp valid_path?(path, bounds) when is_list(path),
    do:
      nonempty_bounded?(path, bounds.path_segments) and
        Enum.all?(path, fn member ->
          is_binary(member) and byte_size(member) in 1..bounds.key_bytes and String.valid?(member)
        end)

  defp valid_path?(_path, _bounds), do: false

  defp valid_string_list?(values, maximum_count, maximum_bytes) when is_list(values),
    do:
      nonempty_bounded?(values, maximum_count) and
        Enum.all?(values, fn value ->
          is_binary(value) and byte_size(value) in 1..maximum_bytes and String.valid?(value) and
            string_or_uri?(value)
        end)

  defp valid_string_list?(_values, _maximum_count, _maximum_bytes), do: false

  defp nonempty_bounded?([_ | _] = values, maximum),
    do: length(values) <= maximum

  defp nonempty_bounded?(_values, _maximum), do: false

  defp unique?(values), do: MapSet.size(MapSet.new(values)) == length(values)

  defp ascii_bytes?(value, predicate),
    do: value |> :binary.bin_to_list() |> Enum.all?(predicate)

  defp map_ok(values, mapper), do: map_ok(values, mapper, [])
  defp map_ok([], _mapper, accumulator), do: {:ok, Enum.reverse(accumulator)}

  defp map_ok([value | rest], mapper, accumulator) do
    with {:ok, mapped} <- mapper.(value) do
      map_ok(rest, mapper, [mapped | accumulator])
    end
  end

  defp fixed(fun) do
    fun.()
  rescue
    _error -> {:error, :invalid}
  end
end
