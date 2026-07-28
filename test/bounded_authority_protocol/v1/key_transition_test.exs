defmodule BoundedAuthorityProtocol.V1.KeyTransitionTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V1.KeyTransitionCodec
  alias BoundedAuthorityProtocol.V1.KeyTransitionFacts

  test "produces, assembles, and verifies an authenticated standard-JWS key transition" do
    {current_public, current_private} = :crypto.generate_key(:eddsa, :ed25519)
    {next_public, _next_private} = :crypto.generate_key(:eddsa, :ed25519)
    transition = transition(current_public, next_public)

    assert {:ok, signing_input} = V1.key_transition_signing_input(transition, %{})
    assert signing_input.kind == :key_transition

    assert decode(signing_input.protected_segment) ==
             ~s({"alg":"EdDSA","kid":"archive-key-a","typ":"ba+key-transition"})

    {:ok, current_fingerprint} = Jwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = Jwk.public_key_thumbprint_raw(next_public, %{})

    assert decode(signing_input.payload_segment) ==
             ~s({"chain_id":"urn:example:chain","effective_at":2000,"from_key_fingerprint":"#{b64(current_fingerprint)}","to_key_fingerprint":"#{b64(next_fingerprint)}","to_key_id":"archive-key-b","transition_id":"urn:example:transition:a-b","v":1})

    signature = :crypto.sign(:eddsa, :none, signing_input.message, [current_private, :ed25519])
    assert {:ok, compact} = V1.assemble_compact(signing_input, signature)

    assert {:ok,
            %KeyTransitionFacts{
              verification: :authenticated_transition,
              trust: :not_evaluated,
              authorization: :not_evaluated
            } = facts} =
             V1.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert inspect(facts) == "#BoundedAuthorityProtocol.V1.KeyTransitionFacts<redacted>"
  end

  test "rejects unchanged keys, bad adjacent windows, wrong kind, fields, and signature sizes" do
    {current_public, current_private} = :crypto.generate_key(:eddsa, :ed25519)
    {next_public, _next_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, current_fingerprint} = Jwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = Jwk.public_key_thumbprint_raw(next_public, %{})

    assert {:error, :invalid} =
             V1.key_transition_signing_input(
               transition(current_public, current_public),
               %{}
             )

    {:ok, input} = V1.key_transition_signing_input(transition(current_public, next_public), %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [current_private, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)

    [protected, payload, signature_segment] = String.split(compact, ".")
    <<first, rest::binary>> = decode(signature_segment)

    tampered_compact =
      protected <>
        "." <>
        payload <>
        "." <> Base.url_encode64(<<Bitwise.bxor(first, 1)>> <> rest, padding: false)

    assert {:error, :invalid} =
             V1.verify_key_transition(
               tampered_compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert {:error, :invalid} =
             V1.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 2000),
               historical("archive-key-b", next_public, 2001, :unbounded),
               expected(current_fingerprint, next_fingerprint)
             )

    assert {:error, :invalid} =
             V1.verify_key_transition(
               compact,
               historical("archive-key-a", current_public, 1000, 3000),
               historical("archive-key-b", next_public, 1500, :unbounded),
               %{expected(current_fingerprint, next_fingerprint) | next_key_id: "archive-key-c"}
             )

    assert {:error, :invalid} = V1.assemble_compact(%{input | kind: :boundary_anchor}, signature)
    assert {:error, :invalid} = V1.assemble_compact(input, binary_part(signature, 0, 63))
    assert {:error, :invalid} = V1.assemble_compact(input, signature <> <<0>>)

    malformed_payload =
      %{input | payload_segment: Base.url_encode64(~s({"v":1}), padding: false)}

    malformed_payload = %{
      malformed_payload
      | message: malformed_payload.protected_segment <> "." <> malformed_payload.payload_segment
    }

    assert {:error, :invalid} = V1.assemble_compact(malformed_payload, signature)

    assert {:error, :invalid} =
             V1.key_transition_signing_input(
               %{transition(current_public, next_public) | current_key_id: "bad key"},
               %{}
             )

    assert {:error, :invalid} =
             V1.key_transition_signing_input(
               %{transition(current_public, next_public) | transition_id: "x:%zz"},
               %{}
             )

    assert {:error, :invalid} = KeyTransitionCodec.signing_input(%{}, %{})
    assert {:error, :invalid} = KeyTransitionCodec.verify(:invalid, %{}, %{}, %{})
    assert {:error, :invalid} = KeyTransitionCodec.parse(:invalid, Bounds.maximum())
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
