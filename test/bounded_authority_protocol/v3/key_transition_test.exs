defmodule BoundedAuthorityProtocol.V3.KeyTransitionTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V3, as: V3
  alias BoundedAuthorityProtocol.V3.EcJwk
  alias BoundedAuthorityProtocol.V3.KeyTransitionCodec
  alias BoundedAuthorityProtocol.V3.KeyTransitionFacts

  test "produces, assembles, and verifies a v3 authenticated standard-JWS key transition" do
    {current_public, current_private} = p256_keypair(<<2::256>>)
    {next_public, _next_private} = p256_keypair(<<3::256>>)
    transition = transition(current_public, next_public)

    assert {:ok, signing_input} = V3.key_transition_signing_input(transition, %{})
    assert signing_input.kind == :key_transition

    assert decode(signing_input.protected_segment) ==
             ~s({"alg":"ES256","kid":"archive-key-a","typ":"ba+key-transition"})

    {:ok, current_fingerprint} = EcJwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = EcJwk.public_key_thumbprint_raw(next_public, %{})

    assert decode(signing_input.payload_segment) ==
             ~s({"chain_id":"urn:example:chain","effective_at":2000,"from_key_fingerprint":"#{b64(current_fingerprint)}","to_key_fingerprint":"#{b64(next_fingerprint)}","to_key_id":"archive-key-b","transition_id":"urn:example:transition:a-b","v":3})

    signature = sign_es256(signing_input.message, current_private)
    assert {:ok, compact} = V3.assemble_compact(signing_input, signature)

    assert {:ok,
            %KeyTransitionFacts{
              version: 3,
              transition_id: "urn:example:transition:a-b",
              effective_at: 2000,
              chain_id: "urn:example:chain",
              current_key_fingerprint: ^current_fingerprint,
              next_key_fingerprint: ^next_fingerprint,
              verification: :authenticated_transition,
              trust: :not_evaluated
            } = facts} =
             V3.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert inspect(facts) == "#BoundedAuthorityProtocol.V3.KeyTransitionFacts<redacted>"
  end

  test "legacy-major Ed25519 transitions are rejected by the v3 codec" do
    {current_public, current_private} = legacy_ed25519_keypair(<<2::256>>)
    {next_public, _next_private} = legacy_ed25519_keypair(<<3::256>>)
    {:ok, current_fingerprint} = V1.Jwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = V1.Jwk.public_key_thumbprint_raw(next_public, %{})

    legacy_transition = transition(current_public, next_public)

    {:ok, v1_input} = V1.key_transition_signing_input(legacy_transition, %{})

    {:ok, v2_input} =
      BoundedAuthorityProtocol.V2.key_transition_signing_input(legacy_transition, %{})

    refute v2_input.message == v1_input.message

    v1_signature = :crypto.sign(:eddsa, :none, v1_input.message, [current_private, :ed25519])
    {:ok, v1_compact} = V1.assemble_compact(v1_input, v1_signature)
    v2_signature = :crypto.sign(:eddsa, :none, v2_input.message, [current_private, :ed25519])
    {:ok, v2_compact} = BoundedAuthorityProtocol.V2.assemble_compact(v2_input, v2_signature)

    assert {:ok, _v1_facts} =
             V1.verify_key_transition(
               v1_compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    for compact <- [v1_compact, v2_compact] do
      assert {:error, :invalid} =
               V3.verify_key_transition(
                 compact,
                 historical("archive-key-a", current_public, 1000, 3000),
                 historical("archive-key-b", next_public, 1500, :unbounded),
                 expected(current_fingerprint, next_fingerprint)
               )

      assert {:error, :invalid} = KeyTransitionCodec.parse(compact, Bounds.maximum())
    end
  end

  test "rejects unchanged keys, bad adjacent windows, wrong kind, fields, and signature sizes" do
    {current_public, current_private} = p256_keypair(<<2::256>>)
    {next_public, _next_private} = p256_keypair(<<3::256>>)
    {:ok, current_fingerprint} = EcJwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = EcJwk.public_key_thumbprint_raw(next_public, %{})

    # A transition must actually roll the key over: identical keys are rejected.
    assert {:error, :invalid} =
             V3.key_transition_signing_input(transition(current_public, current_public), %{})

    {:ok, input} = V3.key_transition_signing_input(transition(current_public, next_public), %{})
    signature = sign_es256(input.message, current_private)
    {:ok, compact} = V3.assemble_compact(input, signature)

    # Shrunken segment bounds force the transition assembly bound to fail closed.
    assert {:error, :invalid} =
             V3.key_transition_signing_input(
               transition(current_public, next_public),
               %{encoded_segment_bytes: 8}
             )

    [protected, payload, signature_segment] = String.split(compact, ".")
    <<first, rest::binary>> = decode(signature_segment)

    tampered_compact =
      protected <>
        "." <>
        payload <>
        "." <> Base.url_encode64(<<Bitwise.bxor(first, 1)>> <> rest, padding: false)

    assert {:error, :invalid} =
             V3.verify_key_transition(
               tampered_compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert {:error, :invalid} =
             V3.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 2000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert {:error, :invalid} =
             V3.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 2001, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert {:error, :invalid} =
             V3.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               %{expected(current_fingerprint, next_fingerprint) | next_key_id: "archive-key-c"}
             )

    assert {:error, :invalid} = V3.assemble_compact(%{input | kind: :boundary_anchor}, signature)
    assert {:error, :invalid} = V3.assemble_compact(input, binary_part(signature, 0, 63))
    assert {:error, :invalid} = V3.assemble_compact(input, signature <> <<0>>)

    malformed_payload =
      %{input | payload_segment: Base.url_encode64(~s({"v":3}), padding: false)}

    malformed_payload = %{
      malformed_payload
      | message: malformed_payload.protected_segment <> "." <> malformed_payload.payload_segment
    }

    assert {:error, :invalid} = V3.assemble_compact(malformed_payload, signature)

    assert {:error, :invalid} =
             V3.key_transition_signing_input(
               %{transition(current_public, next_public) | current_key_id: "bad key"},
               %{}
             )

    assert {:error, :invalid} =
             V3.key_transition_signing_input(
               %{transition(current_public, next_public) | transition_id: "x:%zz"},
               %{}
             )

    assert {:error, :invalid} = KeyTransitionCodec.signing_input(%{}, %{})
    assert {:error, :invalid} = KeyTransitionCodec.verify(:invalid, %{}, %{}, %{})
    assert {:error, :invalid} = KeyTransitionCodec.parse(:invalid, Bounds.maximum())
    assert {:error, :invalid} = KeyTransitionCodec.parse("", Bounds.maximum())
  end

  @ecdsa_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  defp sign_es256(message, priv) do
    der = :crypto.sign(:ecdsa, :sha256, message, [priv, :prime256v1])
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    s2 = if s > div(@ecdsa_n, 2), do: @ecdsa_n - s, else: s
    pad32(r) <> pad32(s2)
  end

  defp pad32(i) do
    b = :binary.encode_unsigned(i)
    :binary.copy(<<0>>, 32 - byte_size(b)) <> b
  end

  defp p256_keypair(seed) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :prime256v1, seed)
    {public_key, private_key}
  end

  defp legacy_ed25519_keypair(seed) do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519, seed)
    {public_key, private_key}
  end

  defp transition(current_public, next_public) do
    %KeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: "urn:example:chain",
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_public_key: current_public,
      next_key_id: "archive-key-b",
      next_public_key: next_public
    }
  end

  defp expected(current_fingerprint, next_fingerprint) do
    %ExpectedKeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: "urn:example:chain",
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_key_fingerprint: current_fingerprint,
      next_key_id: "archive-key-b",
      next_key_fingerprint: next_fingerprint,
      bounds: %{}
    }
  end

  defp historical(key_id, public_key, valid_from, valid_before) do
    %HistoricalPublicKey{
      key_id: key_id,
      public_key: public_key,
      valid_from: valid_from,
      valid_before: valid_before
    }
  end

  defp decode(segment), do: Base.url_decode64!(segment, padding: false)
  defp b64(value), do: Base.url_encode64(value, padding: false)
end
