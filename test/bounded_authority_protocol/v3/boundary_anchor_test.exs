defmodule BoundedAuthorityProtocol.V3.BoundaryAnchorTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V3, as: V3
  alias BoundedAuthorityProtocol.V3.AnchorFacts
  alias BoundedAuthorityProtocol.V3.BoundaryAnchorCodec
  alias BoundedAuthorityProtocol.V3.EcJwk

  @zero_hash <<0::256>>

  test "produces, assembles, and verifies an exact v3 standard-JWS boundary anchor" do
    {public_key, private_key} = p256_keypair(<<1::256>>)
    anchor = anchor(public_key)

    assert {:ok, signing_input} = V3.boundary_anchor_signing_input(anchor, %{})
    assert signing_input.kind == :boundary_anchor

    assert decode(signing_input.protected_segment) ==
             ~s({"alg":"ES256","kid":"archive-key-a","typ":"ba+chain-anchor"})

    {:ok, fingerprint} = EcJwk.public_key_thumbprint_raw(public_key, %{})

    # The v3 payload differs from v1 only in the carried version claim.
    assert decode(signing_input.payload_segment) ==
             ~s({"anchor_id":"urn:example:anchor:start","anchored_at":1999,"chain_hash":"#{b64(@zero_hash)}","chain_id":"urn:example:chain","key_fingerprint":"#{b64(fingerprint)}","sequence":0,"v":3})

    signature = sign_es256(signing_input.message, private_key)
    assert {:ok, compact} = V3.assemble_compact(signing_input, signature)

    key = %HistoricalPublicKey{
      key_id: "archive-key-a",
      public_key: public_key,
      valid_from: 1000,
      valid_before: 2000
    }

    expected = expected_anchor(fingerprint)

    assert {:ok,
            %AnchorFacts{
              version: 3,
              anchor_id: "urn:example:anchor:start",
              anchored_at: 1999,
              chain_id: "urn:example:chain",
              sequence: 0,
              chain_hash: @zero_hash,
              key_fingerprint: ^fingerprint,
              verification: :signature_and_window,
              trust: :not_evaluated
            } = facts} = V3.verify_historical_anchor(compact, key, expected)

    assert inspect(facts) == "#BoundedAuthorityProtocol.V3.AnchorFacts<redacted>"

    assert {:ok, %AnchorFacts{}} =
             V3.verify_historical_anchor(compact, %{key | valid_from: 1999}, expected)

    assert {:error, :invalid} =
             V3.verify_historical_anchor(compact, %{key | valid_before: 1999}, expected)
  end

  test "legacy-major Ed25519 anchors are rejected by the v3 codec" do
    {public_key, private_key} = legacy_ed25519_keypair(<<1::256>>)
    {:ok, fingerprint} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {v3_key, _} = :crypto.generate_key(:ecdh, :prime256v1, <<1::256>>)
    {:ok, v3_input} = V3.boundary_anchor_signing_input(anchor(v3_key), %{})
    {:ok, v1_input} = V1.boundary_anchor_signing_input(anchor(public_key), %{})

    # The majors sign different payload bytes for the same anchor fields.
    refute v3_input.message == v1_input.message

    signature = :crypto.sign(:eddsa, :none, v1_input.message, [private_key, :ed25519])
    {:ok, v1_compact} = V1.assemble_compact(v1_input, signature)

    assert {:ok, _v1_facts} =
             V1.verify_historical_anchor(
               v1_compact,
               %HistoricalPublicKey{
                 key_id: "archive-key-a",
                 public_key: public_key,
                 valid_from: 1000,
                 valid_before: 2000
               },
               expected_anchor(fingerprint)
             )

    {:ok, v2_input} =
      BoundedAuthorityProtocol.V2.boundary_anchor_signing_input(anchor(public_key), %{})

    v2_signature = :crypto.sign(:eddsa, :none, v2_input.message, [private_key, :ed25519])
    {:ok, v2_compact} = BoundedAuthorityProtocol.V2.assemble_compact(v2_input, v2_signature)

    for compact <- [v1_compact, v2_compact] do
      assert {:error, :invalid} =
               V3.verify_historical_anchor(
                 compact,
                 %HistoricalPublicKey{
                   key_id: "archive-key-a",
                   public_key: public_key,
                   valid_from: 1000,
                   valid_before: :unbounded
                 },
                 expected_anchor(fingerprint)
               )

      assert {:error, :invalid} = BoundaryAnchorCodec.parse(compact, Bounds.maximum())
    end
  end

  test "rejects invalid genesis, windows, fingerprints, signatures, and forged signing kinds" do
    {public_key, private_key} = p256_keypair(<<1::256>>)
    {:ok, fingerprint} = EcJwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, input} = V3.boundary_anchor_signing_input(anchor(public_key), %{})
    signature = sign_es256(input.message, private_key)
    {:ok, compact} = V3.assemble_compact(input, signature)
    expected = expected_anchor(fingerprint)

    assert {:error, :invalid} =
             V3.boundary_anchor_signing_input(%{anchor(public_key) | chain_hash: <<1::256>>}, %{})

    assert {:error, :invalid} =
             V3.boundary_anchor_signing_input(
               %{anchor(public_key) | sequence: -1, chain_hash: @zero_hash},
               %{}
             )

    # Shrunken segment bounds force the anchor assembly bound to fail closed.
    assert {:error, :invalid} =
             V3.boundary_anchor_signing_input(anchor(public_key), %{encoded_segment_bytes: 8})

    assert {:error, :invalid} =
             V3.verify_historical_anchor(
               compact,
               %HistoricalPublicKey{
                 key_id: "archive-key-a",
                 public_key: public_key,
                 valid_from: 1999,
                 valid_before: 1999
               },
               expected
             )

    assert {:error, :invalid} =
             V3.verify_historical_anchor(
               compact,
               %HistoricalPublicKey{
                 key_id: "archive-key-a",
                 public_key: public_key,
                 valid_from: 1999,
                 valid_before: 1999
               },
               %{expected | anchored_at: 1998}
             )

    assert {:error, :invalid} =
             V3.verify_historical_anchor(
               compact,
               %HistoricalPublicKey{
                 key_id: "archive-key-a",
                 public_key: public_key,
                 valid_from: 1000,
                 valid_before: :unbounded
               },
               %{expected | key_fingerprint: <<0::256>>}
             )

    tampered = tamper_signature_byte_32(compact)

    assert {:error, :invalid} =
             V3.verify_historical_anchor(
               tampered,
               %HistoricalPublicKey{
                 key_id: "archive-key-a",
                 public_key: public_key,
                 valid_from: 1000,
                 valid_before: :unbounded
               },
               expected
             )

    assert {:error, :invalid} = V3.assemble_compact(%{input | kind: :key_transition}, signature)

    malformed_payload =
      %{input | payload_segment: Base.url_encode64(~s({"v":3}), padding: false)}

    malformed_payload = %{
      malformed_payload
      | message: malformed_payload.protected_segment <> "." <> malformed_payload.payload_segment
    }

    assert {:error, :invalid} = V3.assemble_compact(malformed_payload, signature)

    assert {:error, :invalid} =
             V3.boundary_anchor_signing_input(%{anchor(public_key) | key_id: "bad key"}, %{})

    assert {:error, :invalid} =
             V3.boundary_anchor_signing_input(%{anchor(public_key) | anchor_id: "x:%zz"}, %{})

    assert {:error, :invalid} = BoundaryAnchorCodec.signing_input(%{}, %{})
    assert {:error, :invalid} = BoundaryAnchorCodec.verify(:invalid, %{}, %{})
    assert {:error, :invalid} = BoundaryAnchorCodec.parse(:invalid, Bounds.maximum())
    assert {:error, :invalid} = BoundaryAnchorCodec.parse("", Bounds.maximum())
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

  defp anchor(public_key) do
    %BoundaryAnchor{
      anchor_id: "urn:example:anchor:start",
      anchored_at: 1999,
      chain_id: "urn:example:chain",
      sequence: 0,
      chain_hash: @zero_hash,
      key_id: "archive-key-a",
      public_key: public_key
    }
  end

  defp expected_anchor(fingerprint) do
    %ExpectedAnchor{
      anchor_id: "urn:example:anchor:start",
      anchored_at: 1999,
      chain_id: "urn:example:chain",
      sequence: 0,
      chain_hash: @zero_hash,
      key_id: "archive-key-a",
      key_fingerprint: fingerprint,
      bounds: %{}
    }
  end

  defp decode(segment), do: Base.url_decode64!(segment, padding: false)
  defp b64(value), do: Base.url_encode64(value, padding: false)

  defp tamper_signature_byte_32(compact) do
    [protected, payload, signature_segment] = String.split(compact, ".")
    signature = Base.url_decode64!(signature_segment, padding: false)
    <<prefix::binary-size(32), byte, suffix::binary>> = signature
    tampered = prefix <> <<Bitwise.bxor(byte, 1)>> <> suffix
    protected <> "." <> payload <> "." <> Base.url_encode64(tampered, padding: false)
  end
end
