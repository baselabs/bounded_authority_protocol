defmodule BoundedAuthorityProtocol.ContentAssertion.V1.Codec do
  @moduledoc false

  alias BoundedAuthorityProtocol.ContentAssertion.V1.{
    ContentAssertion,
    ContentAssertionFacts,
    DecodedContentAssertion,
    ExpectedContentAssertion
  }

  alias BoundedAuthorityProtocol.V1.{
    Base64Url,
    Bounds,
    CompactJws,
    ContextValidation,
    FixedBytes,
    HistoricalPublicKey,
    Jcs,
    Json,
    Jwk,
    SigningInput,
    StringOrUri
  }

  @typ "ba+content-assertion"
  @strings [:jti, :iss, :aud, :sub, :profile]
  @digests [:profile_digest, :content_digest, :prev]
  @integers [:gen, :iat, :nbf, :exp]
  @claims @strings ++ @digests ++ @integers
  @payload_keys Enum.sort(["v" | Enum.map(@claims, &Atom.to_string/1)])
  @producer_fields Map.keys(ContentAssertion.__struct__())
  @facts_fields Map.keys(ContentAssertionFacts.__struct__())
  @expected_fields Map.keys(ExpectedContentAssertion.__struct__())
  @input_fields Map.keys(SigningInput.__struct__())
  @key_fields Map.keys(HistoricalPublicKey.__struct__())
  @zero <<0::256>>

  def signing_input(%ContentAssertion{} = value, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- shape?(value, @producer_fields, ContentAssertion),
         true <- valid_claims?(value, bounds),
         {:ok, header} <- Jcs.encode(header(value.attestor_key_id), bounds),
         {:ok, payload} <- Jcs.encode(payload(value), bounds),
         true <- byte_size(header) <= bounds.decoded_segment_bytes,
         true <- byte_size(payload) <= bounds.decoded_segment_bytes,
         {:ok, _} <- Json.decode(header, bounds),
         {:ok, _} <- Json.decode(payload, bounds) do
      build_input(header, payload, bounds)
    else
      _ -> {:error, :invalid}
    end
  end

  def signing_input(_, _), do: {:error, :invalid}

  def assemble(%SigningInput{kind: :content_assertion} = input, signature, limits) do
    with true <- shape?(input, @input_fields, SigningInput),
         {:ok, compact} <- CompactJws.assemble(input, signature, limits),
         {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, _} <- parse(compact, bounds) do
      {:ok, compact}
    else
      _ -> {:error, :invalid}
    end
  end

  def assemble(_, _, _), do: {:error, :invalid}

  def decode(compact, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         {:ok, parsed} <- parse(compact, bounds) do
      {:ok,
       struct!(
         DecodedContentAssertion,
         public_fields(parsed) |> Map.put(:verification, :not_evaluated)
       )}
    else
      _ -> {:error, :invalid}
    end
  end

  def verify(compact, %ExpectedContentAssertion{} = expected) do
    with true <- shape?(expected, @expected_fields, ExpectedContentAssertion),
         attestor = expected.attestor,
         {:ok, bounds} <- Bounds.coerce(expected.bounds),
         true <- valid_expected?(expected, bounds),
         :ok <- ContextValidation.historical_key(expected.attestor, bounds),
         {:ok, parsed} <- parse(compact, bounds),
         true <- expected_matches?(parsed, expected),
         true <- contained?(parsed, expected.attestor),
         true <- parsed.nbf <= expected.now and expected.now < parsed.exp,
         true <-
           :crypto.verify(:eddsa, :none, parsed.message, parsed.signature, [
             attestor.public_key,
             :ed25519
           ]),
         {:ok, fingerprint} <- Jwk.public_key_thumbprint_raw(attestor.public_key, bounds) do
      {:ok,
       struct!(
         ContentAssertionFacts,
         Map.merge(public_fields(parsed), %{
           attestor_key_fingerprint: fingerprint,
           digest: :crypto.hash(:sha256, compact),
           verification: :signature_and_window,
           trust: :not_evaluated
         })
       )}
    else
      _ -> {:error, :invalid}
    end
  end

  def verify(_, _), do: {:error, :invalid}

  def content_digest(bytes, limits) when is_binary(bytes) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(bytes) > 0 and byte_size(bytes) <= bounds.content_bytes do
      {:ok, :crypto.hash(:sha256, [<<"BAP1-CONTENT", 0>>, bytes])}
    else
      _ -> {:error, :invalid}
    end
  end

  def content_digest(_, _), do: {:error, :invalid}

  def assertion_digest(compact, limits) do
    with {:ok, bounds} <- Bounds.coerce(limits), {:ok, _} <- parse(compact, bounds) do
      CompactJws.hash(compact, bounds)
    else
      _ -> {:error, :invalid}
    end
  end

  def verify_successor(
        %ContentAssertionFacts{} = previous,
        %ContentAssertionFacts{} = next,
        limits
      ) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- valid_facts?(previous, bounds) and valid_facts?(next, bounds),
         true <-
           Enum.all?(
             [:iss, :aud, :sub, :profile],
             &(Map.fetch!(previous, &1) == Map.fetch!(next, &1))
           ),
         true <- FixedBytes.equal?(previous.profile_digest, next.profile_digest),
         true <- next.gen == previous.gen + 1,
         true <- FixedBytes.equal?(next.prev, previous.digest),
         true <- next.iat >= previous.iat,
         true <- next.jti != previous.jti do
      :ok
    else
      _ -> {:error, :invalid}
    end
  end

  def verify_successor(_, _, _), do: {:error, :invalid}

  defp parse(compact, bounds)
       when is_binary(compact) and byte_size(compact) > 0 and
              byte_size(compact) <= bounds.anchor_bytes do
    with {:ok, {h, p, s}} <- CompactJws.scan(compact, bounds),
         {:ok, header_bytes} <- Base64Url.decode(h, bounds),
         {:ok, payload_bytes} <- Base64Url.decode(p, bounds),
         {:ok, signature} <- Base64Url.decode(s, bounds),
         true <- byte_size(signature) == bounds.signature_bytes,
         {:ok, header} <- canonical_object(header_bytes, ~w(alg kid typ), bounds),
         {:string, "EdDSA"} <- header["alg"],
         {:string, @typ} <- header["typ"],
         {:string, kid} <- header["kid"],
         {:ok, claims} <- canonical_object(payload_bytes, @payload_keys, bounds),
         {:integer, 1} <- claims["v"],
         {:ok, values} <- decode_claims(claims, bounds),
         parsed =
           Map.merge(values, %{attestor_key_id: kid, message: h <> "." <> p, signature: signature}),
         true <- valid_claims?(parsed, bounds) do
      {:ok, parsed}
    else
      _ -> {:error, :invalid}
    end
  end

  defp parse(_, _), do: {:error, :invalid}

  defp decode_claims(claims, bounds) do
    Enum.reduce_while(@claims, {:ok, %{}}, fn key, {:ok, acc} ->
      case decode_claim(key, Map.fetch!(claims, Atom.to_string(key)), bounds) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        _ -> {:halt, {:error, :invalid}}
      end
    end)
  end

  defp decode_claim(key, {:string, value}, bounds) when key in @digests,
    do: Base64Url.decode(value, bounds)

  defp decode_claim(key, {:string, value}, _) when key in @strings, do: {:ok, value}
  defp decode_claim(key, {:integer, value}, _) when key in @integers, do: {:ok, value}
  defp decode_claim(_, _, _), do: {:error, :invalid}

  defp canonical_object(bytes, keys, bounds) do
    with {:ok, {:object, members} = value} <- Json.decode(bytes, bounds),
         true <- Enum.sort(Enum.map(members, &elem(&1, 0))) == keys,
         {:ok, canonical} <- Jcs.encode(value, bounds),
         true <- canonical == bytes do
      {:ok, Map.new(members)}
    else
      _ -> {:error, :invalid}
    end
  end

  defp valid_claims?(value, bounds) do
    valid_kid?(value.attestor_key_id, bounds) and
      Enum.all?(@strings, &identifier?(Map.fetch!(value, &1), bounds)) and
      Enum.all?(@digests, &digest?(Map.fetch!(value, &1))) and
      Enum.all?(@integers, &integer?(Map.fetch!(value, &1), bounds)) and
      value.gen >= 1 and value.gen == 1 == (value.prev == @zero) and
      value.iat <= value.nbf and value.nbf < value.exp
  end

  defp valid_expected?(e, bounds) do
    shape?(e.attestor, @key_fields, HistoricalPublicKey) and
      Enum.all?([:issuer, :audience, :subject, :profile], &identifier?(Map.fetch!(e, &1), bounds)) and
      digest?(e.profile_digest) and digest?(e.content_digest) and integer?(e.now, bounds)
  end

  defp expected_matches?(p, e) do
    key = e.attestor

    p.attestor_key_id == key.key_id and p.iss == e.issuer and p.aud == e.audience and
      p.sub == e.subject and p.profile == e.profile and
      FixedBytes.equal?(p.profile_digest, e.profile_digest) and
      FixedBytes.equal?(p.content_digest, e.content_digest)
  end

  defp contained?(p, key),
    do:
      p.iat >= key.valid_from and p.nbf >= key.valid_from and
        (key.valid_before == :unbounded or p.exp <= key.valid_before)

  defp valid_facts?(f, bounds) do
    shape?(f, @facts_fields, ContentAssertionFacts) and f.version == 1 and
      f.verification == :signature_and_window and f.trust == :not_evaluated and
      digest?(f.digest) and digest?(f.attestor_key_fingerprint) and valid_claims?(f, bounds)
  end

  defp shape?(value, fields, module) when is_map(value),
    do: Map.get(value, :__struct__) == module and Enum.sort(Map.keys(value)) == Enum.sort(fields)

  defp shape?(_, _, _), do: false

  defp digest?(value), do: is_binary(value) and byte_size(value) == 32

  defp integer?(value, bounds),
    do:
      is_integer(value) and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude

  defp identifier?(value, bounds),
    do:
      is_binary(value) and byte_size(value) > 0 and byte_size(value) <= bounds.identifier_bytes and
        String.valid?(value) and StringOrUri.valid?(value)

  defp valid_kid?(value, bounds),
    do:
      is_binary(value) and byte_size(value) > 0 and byte_size(value) <= bounds.kid_bytes and
        ascii_kid?(value)

  defp ascii_kid?(<<>>), do: true

  defp ascii_kid?(<<b, rest::binary>>)
       when b in ?A..?Z or b in ?a..?z or b in ?0..?9 or b in [?-, ?., ?_, ?~],
       do: ascii_kid?(rest)

  defp ascii_kid?(_), do: false

  defp header(kid),
    do:
      {:object, [{"alg", {:string, "EdDSA"}}, {"kid", {:string, kid}}, {"typ", {:string, @typ}}]}

  defp payload(value),
    do:
      {:object,
       [
         {"v", {:integer, 1}}
         | Enum.map(@claims, fn key ->
             {Atom.to_string(key), encode_claim(key, Map.fetch!(value, key))}
           end)
       ]}

  defp encode_claim(key, value) when key in @digests,
    do: {:string, Base.url_encode64(value, padding: false)}

  defp encode_claim(key, value) when key in @strings, do: {:string, value}
  defp encode_claim(_, value), do: {:integer, value}

  defp public_fields(parsed),
    do: parsed |> Map.take([:attestor_key_id | @claims]) |> Map.put(:version, 1)

  defp build_input(header, payload, bounds) do
    h = Base.url_encode64(header, padding: false)
    p = Base.url_encode64(payload, padding: false)
    message = h <> "." <> p
    compact_size = byte_size(message) + 1 + 86

    if byte_size(h) <= bounds.encoded_segment_bytes and
         byte_size(p) <= bounds.encoded_segment_bytes and
         compact_size <= bounds.compact_bytes and compact_size <= bounds.anchor_bytes do
      {:ok,
       %SigningInput{
         kind: :content_assertion,
         protected_segment: h,
         payload_segment: p,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end
end
