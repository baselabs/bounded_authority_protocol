defmodule BoundedAuthorityProtocol.ContentAssertion.V1Test do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion.V1
  alias BoundedAuthorityProtocol.V1.{Bounds, CompactJws, HistoricalPublicKey}

  test "content digest binds exact bytes under its own tightenable ceiling" do
    expected = :crypto.hash(:sha256, <<"BAP1-CONTENT", 0, "document">>)
    assert {:ok, ^expected} = V1.content_digest("document", %{})
    assert {:error, :invalid} = V1.content_digest("", %{})
    assert {:error, :invalid} = V1.content_digest("document", %{content_bytes: 7})
    assert {:ok, ^expected} = V1.content_digest("document", %{content_bytes: 8})
    assert {:error, :invalid} = V1.content_digest("document", %{content_bytes: 65_537})
    assert {:error, :invalid} = V1.content_digest(:not_bytes, %{})
    refute V1.content_digest("document", %{}) == V1.content_digest("document ", %{})
  end

  test "real Ed25519 signature verifies only the complete expected context" do
    c = context()
    assert {:ok, facts} = V1.verify_assertion(c.compact, c.expected)

    for value <- [c.producer, c.expected] do
      assert inspect(value) =~ "<redacted>"
      refute inspect(value) =~ "issuer-key"
    end

    assert {:error, :invalid} = V1.assertion_signing_input(%{}, %{})
    assert {:error, :invalid} = V1.verify_assertion(c.compact, %{})
    assert {:error, :invalid} = V1.verify_assertion(c.compact, %{c.expected | attestor: nil})

    assert {:error, :invalid} =
             V1.assertion_signing_input(%{c.producer | attestor_key_id: "bad/key"}, %{})

    assert facts.trust == :not_evaluated
    refute Map.has_key?(facts, :authorization)
    assert facts.digest == :crypto.hash(:sha256, c.compact)
    assert inspect(facts) =~ "<redacted>"
    assert {:ok, decoded} = V1.decode_assertion(c.compact, %{})
    assert decoded.verification == :not_evaluated
    assert inspect(decoded) =~ "<redacted>"
    refute inspect(decoded) =~ "issuer-key"
    assert {:ok, facts.digest} == V1.assertion_digest(c.compact, %{})

    for field <- [:issuer, :audience, :subject, :profile] do
      assert {:error, :invalid} =
               V1.verify_assertion(c.compact, Map.put(c.expected, field, "wrong"))
    end

    for field <- [:profile_digest, :content_digest] do
      assert {:error, :invalid} =
               V1.verify_assertion(c.compact, Map.put(c.expected, field, <<1::256>>))
    end

    for field <- Map.keys(Map.from_struct(c.expected)) do
      assert {:error, :invalid} = V1.verify_assertion(c.compact, Map.delete(c.expected, field))
    end
  end

  test "time and issuer window containment are enforced at their exact edges" do
    c = context()
    assert {:ok, _} = V1.verify_assertion(c.compact, %{c.expected | now: 10})
    assert {:error, :invalid} = V1.verify_assertion(c.compact, %{c.expected | now: 30})
    assert {:error, :invalid} = V1.verify_assertion(c.compact, %{c.expected | now: 9})

    for key <- [
          %{c.expected.attestor | valid_from: 6},
          %{c.expected.attestor | valid_before: 29},
          %{c.expected.attestor | key_id: "wrong"},
          %{c.expected.attestor | public_key: elem(:crypto.generate_key(:eddsa, :ed25519), 0)}
        ] do
      assert {:error, :invalid} = V1.verify_assertion(c.compact, %{c.expected | attestor: key})
    end
  end

  test "producer and parser enforce genesis and structural time symmetry" do
    c = context()

    for changes <- [
          %{gen: 0},
          %{gen: 1, prev: <<1::256>>},
          %{gen: 2, prev: <<0::256>>},
          %{iat: 11},
          %{nbf: 30},
          %{exp: 10},
          %{profile_digest: <<1>>},
          %{content_digest: <<1>>},
          %{prev: <<1>>},
          %{aud: ["audience"]}
        ] do
      assert {:error, :invalid} = V1.assertion_signing_input(Map.merge(c.producer, changes), %{})
    end

    for field <- Map.keys(Map.from_struct(c.producer)) do
      assert {:error, :invalid} = V1.assertion_signing_input(Map.delete(c.producer, field), %{})
    end
  end

  test "renewal verifies pairwise after predecessor expiration and through key rotation" do
    c = context()
    assert {:ok, previous} = V1.verify_assertion(c.compact, c.expected)
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)

    producer = %{
      c.producer
      | attestor_key_id: "rotated",
        jti: "assertion-2",
        gen: 2,
        prev: previous.digest,
        iat: 25,
        nbf: 30,
        exp: 50
    }

    compact = sign(producer, private)

    expected = %{
      c.expected
      | now: 31,
        attestor: %HistoricalPublicKey{
          key_id: "rotated",
          public_key: public,
          valid_from: 20,
          valid_before: 50
        }
    }

    assert {:ok, successor} = V1.verify_assertion(compact, expected)
    assert :ok = V1.verify_successor(previous, successor, %{})
    assert {:error, :invalid} = V1.verify_assertion(c.compact, %{c.expected | now: 31})

    for changes <- [
          %{iss: "other"},
          %{aud: "other"},
          %{sub: "other"},
          %{profile: "other"},
          %{profile_digest: <<1::256>>},
          %{gen: 3},
          %{prev: <<1::256>>},
          %{iat: 4},
          %{jti: previous.jti},
          %{verification: :not_evaluated},
          %{trust: :evaluated}
        ] do
      assert {:error, :invalid} =
               V1.verify_successor(previous, Map.merge(successor, changes), %{})
    end

    maximum = Bounds.maximum().integer_magnitude

    assert {:error, :invalid} =
             V1.verify_successor(%{previous | iat: -maximum - 1}, successor, %{})

    for field <- Map.keys(Map.from_struct(previous)) do
      assert {:error, :invalid} = V1.verify_successor(Map.delete(previous, field), successor, %{})
      assert {:error, :invalid} = V1.verify_successor(previous, Map.delete(successor, field), %{})
    end

    assert {:ok, decoded} = V1.decode_assertion(c.compact, %{})
    assert {:error, :invalid} = V1.verify_successor(decoded, successor, %{})
    assert {:error, :invalid} = V1.verify_successor(previous, successor, %{integer_magnitude: 1})
  end

  test "signature tampering and foreign profile assemblers fail closed" do
    c = context()
    [header, payload, sig] = String.split(c.compact, ".")
    <<first, rest::binary>> = Base.url_decode64!(sig, padding: false)
    changed = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)

    assert {:error, :invalid} =
             V1.verify_assertion(header <> "." <> payload <> "." <> changed, c.expected)

    assert {:error, :invalid} = BoundedAuthorityProtocol.V1.decode_grant(c.compact, %{})
    assert {:error, :invalid} = BoundedAuthorityProtocol.V2.decode_grant(c.compact, %{})
    assert {:error, :invalid} = BoundedAuthorityProtocol.V3.decode_grant(c.compact, %{})

    assert {:error, :invalid} =
             BoundedAuthorityProtocol.RoleAttestation.V1.decode_attestation(c.compact, %{})

    assert {:ok, input} = V1.assertion_signing_input(c.producer, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [c.private, :ed25519])
    assert {:error, :invalid} = BoundedAuthorityProtocol.V1.assemble_compact(input, signature)
    assert {:error, :invalid} = V1.assemble_compact(%{input | kind: :role_attestation}, signature)
  end

  test "assembly revalidates each protected header member after signing-input construction" do
    c = context()
    assert {:ok, input} = V1.assertion_signing_input(c.producer, %{})
    header = Base.url_decode64!(input.protected_segment, padding: false)
    signature = :crypto.sign(:eddsa, :none, input.message, [c.private, :ed25519])
    assert {:ok, _} = CompactJws.assemble(input, signature, %{})
    assert {:ok, _} = V1.assemble_compact(input, signature)

    for {original, replacement} <- [
          {~s("EdDSA"), ~s("ES256")},
          {~s("ba+content-assertion"), ~s("ba+role-attestation")},
          {~s("issuer-key"), "false"}
        ] do
      changed_header = String.replace(header, original, replacement)
      refute changed_header == header
      protected = Base.url_encode64(changed_header, padding: false)
      message = protected <> "." <> input.payload_segment
      changed = %{input | protected_segment: protected, message: message}
      signature = :crypto.sign(:eddsa, :none, message, [c.private, :ed25519])

      assert {:error, :invalid} =
               CompactJws.assemble(changed, signature, %{})

      assert {:error, :invalid} = V1.assemble_compact(changed, signature)
    end
  end

  defp context do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, digest} = V1.content_digest("document", %{})

    producer =
      struct!(V1.ContentAssertion,
        attestor_key_id: "issuer-key",
        jti: "assertion-1",
        iss: "issuer",
        aud: "audience",
        sub: "lineage",
        profile: "urn:example:profile:1",
        profile_digest: :crypto.hash(:sha256, "schema"),
        content_digest: digest,
        gen: 1,
        prev: <<0::256>>,
        iat: 5,
        nbf: 10,
        exp: 30
      )

    expected =
      struct!(V1.ExpectedContentAssertion,
        attestor: %HistoricalPublicKey{
          key_id: "issuer-key",
          public_key: public,
          valid_from: 5,
          valid_before: 30
        },
        issuer: producer.iss,
        audience: producer.aud,
        subject: producer.sub,
        profile: producer.profile,
        profile_digest: producer.profile_digest,
        content_digest: producer.content_digest,
        now: 20,
        bounds: %{}
      )

    %{producer: producer, expected: expected, compact: sign(producer, private), private: private}
  end

  defp sign(producer, private) do
    {:ok, input} = V1.assertion_signing_input(producer, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end
end
