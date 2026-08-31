defmodule BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1Test do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1
  alias BoundedAuthorityProtocol.UriPath
  alias BoundedAuthorityProtocol.V1, as: StandardV1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.CompactJws
  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V1.Proof
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.TrustedIssuer

  @certified_index_sha256 "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4"

  describe "normalize_uri/2" do
    test "accepts only canonical IPv4 and IPv6 loopback HTTP targets" do
      assert {:ok, "http://127.0.0.1/invoke"} =
               V1.normalize_uri("HTTP://127.0.0.1:80/a/../invoke", %{})

      assert {:ok, "http://127.0.0.1:4000/invoke"} =
               V1.normalize_uri("http://127.0.0.1:4000/invoke", %{})

      assert {:ok, "http://[::1]/invoke"} =
               V1.normalize_uri("HTTP://[::1]:80/invoke", %{})

      assert {:ok, "http://127.0.0.1:443/invoke"} =
               V1.normalize_uri("http://127.0.0.1:443/invoke", %{})
    end

    test "rejects non-loopback, ambiguous, and non-HTTP targets" do
      for invalid <- [
            "https://127.0.0.1/invoke",
            "http://localhost/invoke",
            "http://127.0.0.2/invoke",
            "http://127.1/invoke",
            "http://2130706433/invoke",
            "http://[::ffff:127.0.0.1]/invoke",
            "http://[::1%25lo0]/invoke",
            "http://user@127.0.0.1/invoke",
            "http://127.0.0.1/invoke?query=true",
            "http://127.0.0.1/invoke#fragment",
            "http://127.0.0.1/[]"
          ] do
        assert {:error, :invalid} = V1.normalize_uri(invalid, %{}), invalid
      end
    end

    test "covers empty, non-binary, scheme-less, path-less, and shared-path boundaries" do
      assert {:ok, "http://127.0.0.1/"} = V1.normalize_uri("http://127.0.0.1", %{})
      assert {:ok, "http://[::1]/"} = V1.normalize_uri("http://[::1]", %{})
      assert {:error, :invalid} = V1.normalize_uri("", %{})
      assert {:error, :invalid} = V1.normalize_uri("127.0.0.1/invoke", %{})
      assert {:error, :invalid} = V1.normalize_uri(:not_a_uri, %{})
      assert {:error, :invalid} = UriPath.normalize("relative")
    end
  end

  test "proof production and compact decoding are byte-distinct from standard DPoP" do
    context = proof_context()

    assert {:ok, signing_input} = V1.proof_signing_input(context.proof, %{})
    assert signing_input.kind == :local_loopback_http_proof

    header = decode_segment(signing_input.protected_segment)
    assert header["alg"] == "EdDSA"
    assert header["typ"] == "ba+loopback-proof"
    assert Map.keys(header) |> Enum.sort() == ~w(alg jwk typ)

    assert {:error, :invalid} = StandardV1.proof_signing_input(context.proof, %{})
    assert {:error, :invalid} = V1.proof_signing_input(%{context.proof | nonce: nil}, %{})

    signature =
      :crypto.sign(:eddsa, :none, signing_input.message, [context.holder_private, :ed25519])

    assert {:ok, compact} = V1.assemble_compact(signing_input, signature, %{})
    assert {:ok, decoded} = V1.decode_proof(compact, %{})
    assert decoded.target_uri == "http://127.0.0.1:4000/invoke"
    assert decoded.nonce == "challenge-local-001"
    assert decoded.verification == :not_evaluated

    assert {:error, :invalid} = StandardV1.decode_proof(compact, %{})
    assert {:error, :invalid} = StandardV1.assemble_compact(signing_input, signature, %{})
  end

  test "all local public surfaces and assembly defenses fail closed" do
    context = proof_context()
    {:ok, %SigningInput{} = signing_input} = V1.proof_signing_input(context.proof, %{})

    signature =
      :crypto.sign(:eddsa, :none, signing_input.message, [context.holder_private, :ed25519])

    assert {:ok, compact} = V1.assemble_compact(signing_input, signature)
    assert {:error, :invalid} = V1.proof_signing_input(:not_a_proof, %{})
    assert {:error, :invalid} = V1.assemble_compact(:not_an_input, signature, %{})
    assert {:error, :invalid} = V1.decode_proof(:not_a_compact, %{})
    assert {:error, :invalid} = V1.check_envelope(:not_credentials, :not_expected)

    assert {:error, :invalid} =
             V1.assemble_compact(%{signing_input | kind: :proof}, signature, %{})

    empty_payload = Base.url_encode64("{}", padding: false)

    malformed_payload = %{
      signing_input
      | payload_segment: empty_payload,
        message: signing_input.protected_segment <> "." <> empty_payload
    }

    assert {:error, :invalid} = V1.assemble_compact(malformed_payload, signature, %{})

    protected = decode_segment(signing_input.protected_segment)

    for invalid_header <- [
          Map.put(protected, "typ", "unknown+jwt"),
          Map.put(protected, "jwk", %{"kty" => "OKP"})
        ] do
      protected_segment = encode_segment(invalid_header)

      invalid_input = %SigningInput{
        signing_input
        | protected_segment: protected_segment,
          message: protected_segment <> "." <> signing_input.payload_segment
      }

      assert {:error, :invalid} = CompactJws.assemble(invalid_input, signature, %{})
    end

    assert {:error, :invalid} =
             CompactJws.assemble(%{signing_input | kind: :unknown}, signature, %{})

    without_nonce =
      rewrite_payload(compact, fn payload -> Map.delete(payload, "nonce") end)

    assert {:error, :invalid} = V1.decode_proof(without_nonce, %{})

    non_string_nonce =
      rewrite_payload(compact, fn payload -> Map.put(payload, "nonce", 1) end)

    assert {:error, :invalid} = V1.decode_proof(non_string_nonce, %{})
  end

  test "envelope verification requires the exact local target and a server nonce" do
    context = proof_context()
    {:ok, proof_input} = V1.proof_signing_input(context.proof, %{})

    proof_signature =
      :crypto.sign(:eddsa, :none, proof_input.message, [context.holder_private, :ed25519])

    {:ok, proof_compact} = V1.assemble_compact(proof_input, proof_signature, %{})
    credentials = %Credentials{grant: context.grant_compact, proof: proof_compact}

    expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{
        key_id: "issuer-local-1",
        public_key: context.issuer_public
      },
      issuer: "urn:example:issuer:local",
      audience: "urn:example:audience:local",
      method: context.proof.method,
      target_uri: context.proof.target_uri,
      invocation_id: context.proof.invocation_id,
      operation: context.proof.operation,
      cast_arguments: context.proof.cast_arguments,
      evaluation_time: context.proof.issued_at,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, context.proof.nonce},
      bounds: Bounds.maximum()
    }

    assert {:ok, facts} = V1.check_envelope(credentials, expected)
    assert facts.target_uri == "http://127.0.0.1:4000/invoke"
    assert facts.authorization == :not_evaluated

    assert {:error, :invalid} = StandardV1.check_envelope(credentials, expected)
    assert {:error, :invalid} = V1.check_envelope(credentials, %{expected | nonce: :not_required})

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{expected | nonce: {:required, "wrong-nonce"}})

    <<first, rest::binary>> = context.issuer_public

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{
               expected
               | trusted_issuer: %{
                   expected.trusted_issuer
                   | public_key: <<Bitwise.bxor(first, 1), rest::binary>>
                 }
             })

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{
               expected
               | invocation_id: "550e8400-e29b-41d4-a716-446655440001"
             })

    assert {:error, :invalid} =
             V1.check_envelope(credentials, %{
               expected
               | target_uri: "https://127.0.0.1:4000/invoke"
             })
  end

  test "the certified language-neutral corpus drives URI, decode, and envelope verdicts" do
    root =
      Path.expand(
        "../../../../priv/conformance/application-profiles/local-loopback-http/v1",
        __DIR__
      )

    index_bytes = root |> Path.join("index.json") |> File.read!()

    assert :sha256 |> :crypto.hash(index_bytes) |> Base.encode16(case: :lower) ==
             @certified_index_sha256

    index = :json.decode(index_bytes)
    assert index["profile"] == "bap-application-proof/local-loopback-http/1"
    assert index["revision"] == 1
    assert index["proof_cases"] == 8
    assert index["uri_cases"] == 36
    assert Enum.map(index["files"], & &1["path"]) == ["profile.json", "proof-cases.json"]

    for %{"path" => path, "sha256" => expected_sha} <- index["files"] do
      actual_sha =
        root
        |> Path.join(path)
        |> File.read!()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      assert actual_sha == expected_sha
    end

    profile = root |> Path.join("profile.json") |> File.read!() |> :json.decode()
    assert length(profile["uri_cases"]) == index["uri_cases"]

    for uri_case <- profile["uri_cases"] do
      actual = V1.normalize_uri(uri_case["input"], %{})

      if uri_case["valid"] do
        assert actual == {:ok, uri_case["normalized"]}, uri_case["id"]
      else
        assert actual == {:error, :invalid}, uri_case["id"]
      end
    end

    {:ok, issuer_public} = Base.url_decode64(profile["issuer"]["public_key"], padding: false)
    {:ok, holder_public} = Base.url_decode64(profile["holder_public_key"], padding: false)

    expected = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{
        key_id: profile["issuer"]["key_id"],
        public_key: issuer_public
      },
      issuer: profile["issuer"]["issuer"],
      audience: profile["issuer"]["audience"],
      method: profile["request"]["method"],
      target_uri: profile["proofs"]["ipv4"]["target_uri"],
      invocation_id: profile["request"]["invocation_id"],
      operation: profile["request"]["operation"],
      cast_arguments: {:object, [{"record_id", {:string, "record-1"}}]},
      evaluation_time: profile["request"]["evaluation_time"],
      clock_skew: profile["request"]["clock_skew"],
      proof_max_age: profile["request"]["proof_max_age"],
      nonce: {:required, profile["proofs"]["ipv4"]["nonce"]},
      bounds: Bounds.maximum()
    }

    for {_family, certified} <- profile["proofs"] do
      proof = %Proof{
        holder_public_key: holder_public,
        proof_id: certified["proof_id"],
        method: profile["request"]["method"],
        target_uri: certified["target_uri"],
        issued_at: profile["request"]["evaluation_time"],
        nonce: certified["nonce"],
        invocation_id: profile["request"]["invocation_id"],
        operation: profile["request"]["operation"],
        grant_compact: profile["grant_compact"],
        cast_arguments: {:object, [{"record_id", {:string, "record-1"}}]}
      }

      [protected, payload, signature] = String.split(certified["compact"], ".")
      assert {:ok, signing_input} = V1.proof_signing_input(proof, %{})
      assert signing_input.protected_segment == protected
      assert signing_input.payload_segment == payload
      {:ok, signature_bytes} = Base.url_decode64(signature, padding: false)

      assert {:ok, assembled} = V1.assemble_compact(signing_input, signature_bytes, %{})
      assert assembled == certified["compact"]

      assert {:ok, _decoded} = V1.decode_proof(certified["compact"], %{})

      certified_expected = %{
        expected
        | target_uri: certified["target_uri"],
          nonce: {:required, certified["nonce"]}
      }

      assert {:ok, _facts} =
               V1.check_envelope(
                 %Credentials{grant: profile["grant_compact"], proof: certified["compact"]},
                 certified_expected
               )
    end

    cases = root |> Path.join("proof-cases.json") |> File.read!() |> :json.decode()
    assert length(cases) == index["proof_cases"]

    assert Enum.map(cases, & &1["id"]) |> Enum.take(-2) == [
             "local-wrong-issuer-trust",
             "local-wrong-invocation-binding"
           ]

    for proof_case <- cases do
      local_decode = match?({:ok, _}, V1.decode_proof(proof_case["compact"], %{}))
      standard_decode = match?({:ok, _}, StandardV1.decode_proof(proof_case["compact"], %{}))

      case_expected =
        case Map.get(proof_case, "expected_overrides", %{}) do
          overrides when map_size(overrides) == 0 ->
            expected

          %{"trusted_issuer_public_key" => encoded} = overrides when map_size(overrides) == 1 ->
            {:ok, public_key} = Base.url_decode64(encoded, padding: false)

            %{
              expected
              | trusted_issuer: %{expected.trusted_issuer | public_key: public_key}
            }

          %{"invocation_id" => invocation_id} = overrides when map_size(overrides) == 1 ->
            %{expected | invocation_id: invocation_id}

          overrides ->
            flunk("unsupported expected_overrides: #{inspect(overrides)}")
        end

      envelope =
        match?(
          {:ok, _},
          V1.check_envelope(
            %Credentials{grant: profile["grant_compact"], proof: proof_case["compact"]},
            case_expected
          )
        )

      assert local_decode == proof_case["decode_local"], proof_case["id"]
      assert standard_decode == proof_case["decode_standard"], proof_case["id"]
      assert envelope == proof_case["envelope_local"], proof_case["id"]
    end
  end

  test "every normative profile requirement is present in the requirement map" do
    spec = File.read!("spec/bap-local-loopback-http-v1.md")
    requirement_map = File.read!("docs/design/local-loopback-http-requirement-map.md")

    certified_ids =
      "test/fixtures/durable_identifier_local_loopback_requirements.txt"
      |> File.read!()
      |> String.split()
      |> MapSet.new()

    spec_ids =
      ~r/\bREQ-LLH1-[A-Za-z0-9-]+\b/
      |> Regex.scan(spec)
      |> Enum.map(fn [id] -> id end)
      |> MapSet.new()

    mapped_ids =
      ~r/`([A-Z]+-[A-Za-z0-9-]+)`/
      |> Regex.scan(requirement_map, capture: :all_but_first)
      |> Enum.map(fn [suffix] -> "REQ-LLH1-" <> suffix end)
      |> MapSet.new()

    assert spec_ids == certified_ids
    assert mapped_ids == certified_ids
  end

  defp proof_context do
    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)

    {holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)

    {:ok, holder_thumbprint} = Jwk.public_key_thumbprint_raw(holder_public, %{})

    grant = %Grant{
      key_id: "issuer-local-1",
      issuer: "urn:example:issuer:local",
      grant_id: "urn:example:grant:local",
      audiences: ["urn:example:audience:local"],
      issued_at: 1_735_689_600,
      not_before: 1_735_689_600,
      expires_at: 1_735_690_200,
      holder_thumbprint: holder_thumbprint,
      operations: [%Operation{name: "read_record", selectors: [:all]}]
    }

    {:ok, grant_input} = StandardV1.grant_signing_input(grant, %{})

    grant_signature =
      :crypto.sign(:eddsa, :none, grant_input.message, [issuer_private, :ed25519])

    {:ok, grant_compact} = StandardV1.assemble_compact(grant_input, grant_signature, %{})

    proof = %Proof{
      holder_public_key: holder_public,
      proof_id: "urn:example:proof:local",
      method: "POST",
      target_uri: "http://127.0.0.1:4000/invoke",
      issued_at: 1_735_689_660,
      nonce: "challenge-local-001",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "read_record",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"record_id", {:string, "record-1"}}]}
    }

    %{
      proof: proof,
      holder_private: holder_private,
      issuer_public: issuer_public,
      grant_compact: grant_compact
    }
  end

  defp decode_segment(segment) do
    segment
    |> Base.url_decode64!(padding: false)
    |> :json.decode()
  end

  defp encode_segment(value) do
    value
    |> :json.encode()
    |> IO.iodata_to_binary()
    |> Base.url_encode64(padding: false)
  end

  defp rewrite_payload(compact, rewrite) do
    [protected, payload, signature] = String.split(compact, ".")
    rewritten_payload = payload |> decode_segment() |> rewrite.() |> encode_segment()
    Enum.join([protected, rewritten_payload, signature], ".")
  end
end
