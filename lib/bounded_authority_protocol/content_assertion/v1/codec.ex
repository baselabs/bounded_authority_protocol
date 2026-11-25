defmodule BoundedAuthorityProtocol.ContentAssertion.V1.Codec do
  @moduledoc false

  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertion, as: EsAssertion
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts, as: EsFacts
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion, as: EsDecoded
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ExpectedContentAssertion, as: EsExpected

  alias BoundedAuthorityProtocol.ContentAssertion.V1.{
    ContentAssertion,
    ContentAssertionFacts,
    DecodedContentAssertion,
    ExpectedContentAssertion
  }

  alias BoundedAuthorityProtocol.{Ed25519, Es256}
  alias BoundedAuthorityProtocol.V3.{ContextValidation, EcJwk}

  alias BoundedAuthorityProtocol.V1.ContextValidation, as: EdContext

  alias BoundedAuthorityProtocol.V1.{
    Base64Url,
    Bounds,
    CompactJws,
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
  @es_producer_fields Map.keys(EsAssertion.__struct__())
  @es_expected_fields Map.keys(EsExpected.__struct__())
  @es_facts_fields Map.keys(EsFacts.__struct__())
  @facts_fields Map.keys(ContentAssertionFacts.__struct__())
  @expected_fields Map.keys(ExpectedContentAssertion.__struct__())
  @input_fields Map.keys(SigningInput.__struct__())
  @key_fields Map.keys(HistoricalPublicKey.__struct__())
  @zero <<0::256>>

  def signing_input(value, limits, suite \\ :eddsa) do
    result =
      with {:ok, bounds} <- Bounds.coerce(limits),
           true <- producer_shape?(value, suite),
           true <- valid_claims?(value, bounds),
           {:ok, header} <- Jcs.encode(header(value.attestor_key_id, suite), bounds),
           {:ok, payload} <- Jcs.encode(payload(value), bounds),
           true <- byte_size(header) <= bounds.decoded_segment_bytes,
           true <- byte_size(payload) <= bounds.decoded_segment_bytes,
           {:ok, _} <- Json.decode(header, bounds),
           {:ok, _} <- Json.decode(payload, bounds) do
        build_input(header, payload, bounds, suite)
      end

    stage(result, :invalid)
  end

  defp producer_shape?(value, :eddsa), do: shape?(value, @producer_fields, ContentAssertion)

  defp producer_shape?(value, :es256), do: shape?(value, @es_producer_fields, EsAssertion)

  def assemble(input, signature, limits, suite \\ :eddsa)

  def assemble(%SigningInput{kind: :content_assertion} = input, signature, limits, :eddsa) do
    result =
      with true <- shape?(input, @input_fields, SigningInput),
           {:ok, compact} <- CompactJws.assemble(input, signature, limits),
           {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, _} <- parse(compact, bounds) do
        {:ok, compact}
      end

    stage(result, :invalid)
  end

  def assemble(
        %SigningInput{kind: :content_assertion_es256} = input,
        signature,
        limits,
        :es256
      ) do
    result =
      with true <- shape?(input, @input_fields, SigningInput),
           {:ok, bounds} <- Bounds.coerce(limits),
           true <- bounded_segment?(input.protected_segment, bounds),
           true <- bounded_segment?(input.payload_segment, bounds),
           true <- input.message == input.protected_segment <> "." <> input.payload_segment,
           true <- Es256.canonical_signature?(signature),
           compact = input.message <> "." <> Base.url_encode64(signature, padding: false),
           {:ok, _} <- parse(compact, bounds, :es256) do
        {:ok, compact}
      end

    stage(result, :invalid)
  end

  def assemble(_, _, _, _), do: {:error, :invalid}

  defp bounded_segment?(value, bounds),
    do: is_binary(value) and byte_size(value) <= bounds.encoded_segment_bytes

  def decode(compact, limits, suite \\ :eddsa) do
    result =
      with {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, parsed} <- parse(compact, bounds, suite) do
        {:ok,
         struct!(
           decoded_type(suite),
           public_fields(parsed) |> Map.put(:verification, :not_evaluated)
         )}
      end

    stage(result, :invalid)
  end

  def verify(compact, expected, suite \\ :eddsa) do
    result =
      with true <- expected_shape?(expected, suite),
           attestor = expected.attestor,
           {:ok, bounds} <- Bounds.coerce(expected.bounds),
           true <- valid_expected?(expected, bounds),
           :ok <- historical_key(attestor, bounds, suite),
           {:ok, parsed} <- parse(compact, bounds, suite),
           :ok <- check(expected_matches?(parsed, expected), :context_mismatch),
           :ok <- key_window(parsed, attestor),
           :ok <- current_window(parsed, expected.now),
           :ok <- signature(parsed, attestor, suite),
           {:ok, fingerprint} <- fingerprint(attestor.public_key, bounds, suite) do
        {:ok, facts(parsed, compact, fingerprint, suite)}
      end

    stage(result, :invalid)
  end

  defp expected_shape?(value, :eddsa),
    do: shape?(value, @expected_fields, ExpectedContentAssertion)

  defp expected_shape?(value, :es256), do: shape?(value, @es_expected_fields, EsExpected)

  def historical_key(key, bounds, :eddsa), do: EdContext.historical_key(key, bounds)
  def historical_key(key, bounds, :es256), do: ContextValidation.historical_key(key, bounds)

  def fingerprint(key, bounds, :eddsa), do: Jwk.public_key_thumbprint_raw(key, bounds)
  def fingerprint(key, bounds, :es256), do: EcJwk.public_key_thumbprint_raw(key, bounds)

  def admitted_fingerprint(key, :eddsa) do
    result =
      with true <- Ed25519.torsion_free?(key) do
        fingerprint(key, %{}, :eddsa)
      end

    stage(result, :invalid)
  end

  def admitted_fingerprint(key, :es256) do
    with {:ok, preimage} <- EcJwk.encode_public(key, %{}) do
      {:ok, :crypto.hash(:sha256, preimage)}
    end
  end

  def signature(parsed, key, :eddsa) do
    verified = Ed25519.verify_strict(parsed.message, parsed.signature, key.public_key)
    check(verified, :bad_signature)
  end

  def signature(parsed, key, :es256) do
    verified = Es256.verify_strict(parsed.message, parsed.signature, key.public_key)
    check(verified, :bad_signature)
  end

  def key_window(parsed, key), do: check(contained?(parsed, key), :key_window)

  def current_window(parsed, now) do
    with :ok <- check(parsed.nbf <= now, :not_yet_valid) do
      check(now < parsed.exp, :expired)
    end
  end

  def facts(parsed, compact, fingerprint, suite) do
    struct!(
      facts_type(suite),
      Map.merge(public_fields(parsed), %{
        attestor_key_fingerprint: fingerprint,
        digest: :crypto.hash(:sha256, compact),
        verification: :signature_and_window,
        trust: :not_evaluated
      })
    )
  end

  defp check(true, _reason), do: :ok
  defp check(false, reason), do: {:error, reason}

  def content_digest(bytes, limits) when is_binary(bytes) do
    result =
      with {:ok, bounds} <- Bounds.coerce(limits),
           true <- byte_size(bytes) > 0 and byte_size(bytes) <= bounds.content_bytes do
        {:ok, :crypto.hash(:sha256, [<<"BAP1-CONTENT", 0>>, bytes])}
      end

    stage(result, :invalid)
  end

  def content_digest(_, _), do: {:error, :invalid}

  def assertion_digest(compact, limits, suite \\ :eddsa) do
    result =
      with {:ok, bounds} <- Bounds.coerce(limits),
           {:ok, _} <- parse(compact, bounds, suite) do
        {:ok, :crypto.hash(:sha256, compact)}
      end

    stage(result, :invalid)
  end

  def verify_successor(previous, next, limits, suite \\ :eddsa) do
    result =
      with {:ok, bounds} <- Bounds.coerce(limits),
           true <- valid_facts?(previous, bounds, suite) and valid_facts?(next, bounds, suite),
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
      end

    stage(result, :invalid)
  end

  def parse(compact, bounds, suite \\ :eddsa) do
    with {:ok, framed} <- frame(compact, bounds),
         :ok <- admit_suite(framed, suite) do
      parse_claims(framed, bounds)
    end
  end

  defp frame(compact, bounds)
       when is_binary(compact) and byte_size(compact) > 0 and
              byte_size(compact) <= bounds.anchor_bytes do
    result =
      with {:ok, {h, p, s}} <- CompactJws.scan(compact, bounds),
           {:ok, header_bytes} <- Base64Url.decode(h, bounds),
           {:ok, payload_bytes} <- Base64Url.decode(p, bounds),
           {:ok, signature} <- Base64Url.decode(s, bounds),
           true <- byte_size(signature) == bounds.signature_bytes,
           {:ok, header} <- canonical_object(header_bytes, ~w(alg kid typ), bounds),
           {:string, alg} <- header["alg"],
           {:string, typ} <- header["typ"],
           {:string, kid} <- header["kid"],
           true <- valid_kid?(kid, bounds) do
        {:ok, {alg, typ, kid, payload_bytes, h <> "." <> p, signature}}
      end

    stage(result, :malformed)
  end

  defp frame(_, _), do: {:error, :malformed}

  defp admit_suite({alg, typ, _, _, _, _}, suite),
    do: check({alg, typ} == suite_header(suite), :unsupported_algorithm)

  defp parse_claims({_, _, kid, payload_bytes, message, signature}, bounds) do
    result =
      with {:ok, claims} <- canonical_object(payload_bytes, @payload_keys, bounds),
           {:integer, 1} <- claims["v"],
           {:ok, values} <- decode_claims(claims, bounds),
           parsed =
             Map.merge(values, %{attestor_key_id: kid, message: message, signature: signature}),
           true <- valid_claims?(parsed, bounds) do
        {:ok, parsed}
      end

    stage(result, :malformed)
  end

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
      _failure -> {:error, :invalid}
    end
  end

  defp valid_claims?(value, bounds) do
    valid_kid?(value.attestor_key_id, bounds) and
      Enum.all?(@strings, &identifier?(Map.fetch!(value, &1), bounds)) and
      Enum.all?(@digests, &digest?(Map.fetch!(value, &1))) and
      Enum.all?(@integers, &integer?(Map.fetch!(value, &1), bounds)) and
      value.gen >= 1 and value.gen == 1 == FixedBytes.equal?(value.prev, @zero) and
      value.iat <= value.nbf and value.nbf < value.exp
  end

  defp valid_expected?(e, bounds) do
    identifiers = [:issuer, :audience, :subject, :profile]

    shape?(e.attestor, @key_fields, HistoricalPublicKey) and
      Enum.all?(identifiers, &identifier?(Map.fetch!(e, &1), bounds)) and
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

  defp valid_facts?(f, bounds, suite) do
    facts_shape?(f, suite) and f.version == 1 and
      f.verification == :signature_and_window and f.trust == :not_evaluated and
      digest?(f.digest) and digest?(f.attestor_key_fingerprint) and valid_claims?(f, bounds)
  end

  defp facts_shape?(f, :eddsa), do: shape?(f, @facts_fields, ContentAssertionFacts)

  defp facts_shape?(f, :es256), do: shape?(f, @es_facts_fields, EsFacts)

  defp facts_type(:eddsa), do: ContentAssertionFacts
  defp facts_type(:es256), do: EsFacts

  defp decoded_type(:eddsa), do: DecodedContentAssertion
  defp decoded_type(:es256), do: EsDecoded

  defp shape?(value, fields, module) when is_map(value),
    do: Map.get(value, :__struct__) == module and Enum.sort(Map.keys(value)) == Enum.sort(fields)

  defp shape?(_, _, _), do: false

  defp digest?(value), do: is_binary(value) and byte_size(value) == 32

  def integer?(value, bounds),
    do:
      is_integer(value) and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude

  def identifier?(value, bounds) do
    is_binary(value) and byte_size(value) > 0 and byte_size(value) <= bounds.identifier_bytes and
      String.valid?(value) and StringOrUri.valid?(value)
  end

  defp valid_kid?(value, bounds),
    do:
      is_binary(value) and byte_size(value) > 0 and byte_size(value) <= bounds.kid_bytes and
        ascii_kid?(value)

  defp ascii_kid?(<<>>), do: true

  defp ascii_kid?(<<b, rest::binary>>)
       when b in ?A..?Z or b in ?a..?z or b in ?0..?9 or b in [?-, ?., ?_, ?~],
       do: ascii_kid?(rest)

  defp ascii_kid?(_), do: false

  defp suite_header(:eddsa), do: {"EdDSA", @typ}
  defp suite_header(:es256), do: {"ES256", "ba+content-assertion-es256"}

  defp input_kind(:eddsa), do: :content_assertion
  defp input_kind(:es256), do: :content_assertion_es256

  defp header(kid, suite) do
    {alg, typ} = suite_header(suite)
    {:object, [{"alg", {:string, alg}}, {"kid", {:string, kid}}, {"typ", {:string, typ}}]}
  end

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

  defp build_input(header, payload, bounds, suite) do
    h = Base.url_encode64(header, padding: false)
    p = Base.url_encode64(payload, padding: false)
    message = h <> "." <> p
    compact_size = byte_size(message) + 1 + 86

    if byte_size(h) <= bounds.encoded_segment_bytes and
         byte_size(p) <= bounds.encoded_segment_bytes and
         compact_size <= bounds.compact_bytes and compact_size <= bounds.anchor_bytes do
      {:ok,
       %SigningInput{
         kind: input_kind(suite),
         protected_segment: h,
         payload_segment: p,
         message: message
       }}
    else
      {:error, :invalid}
    end
  end

  defp stage(:ok, _code), do: :ok
  defp stage({:ok, _} = result, _code), do: result
  defp stage(_, code), do: {:error, code}
end
