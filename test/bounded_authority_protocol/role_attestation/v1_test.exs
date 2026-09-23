defmodule BoundedAuthorityProtocol.RoleAttestation.V1Test do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.RoleAttestation.V1
  alias BoundedAuthorityProtocol.V1, as: StandardV1
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V2, as: StandardV2
  alias BoundedAuthorityProtocol.V3, as: StandardV3

  @certified_index_sha256 "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

  describe "attestation_signing_input/2 and assemble_compact/{2,3}" do
    test "produces the exact closed profile bytes" do
      context = attestation_context()

      assert {:ok, signing_input} = V1.attestation_signing_input(context.attestation, %{})
      assert signing_input.kind == :role_attestation

      header = decode_segment(signing_input.protected_segment)
      assert header["alg"] == "EdDSA"
      assert header["typ"] == "ba+role-attestation"
      assert header["kid"] == context.attestor_key_id
      assert Map.keys(header) |> Enum.sort() == ~w(alg kid typ)

      payload = decode_segment(signing_input.payload_segment)
      assert payload["v"] == 1
      assert payload["jti"] == "urn:example:attestation:1"
      assert payload["key_id"] == context.subject_key_id
      assert payload["public_key"] == Base.url_encode64(context.subject_public, padding: false)
      assert payload["role"] == "issuer"
      assert payload["nbf"] == 1_735_689_600
      assert payload["exp"] == 1_735_693_200
      assert Map.keys(payload) |> Enum.sort() == ~w(exp jti key_id nbf public_key role v)

      assert {:ok, compact} = V1.assemble_compact(signing_input, context.signature)
      assert byte_size(compact) > 0
      assert {:ok, ^compact} = V1.assemble_compact(signing_input, context.signature, %{})

      assert {:error, :invalid} = StandardV1.decode_grant(compact, %{})
      assert {:error, :invalid} = StandardV1.decode_proof(compact, %{})
      assert {:error, :invalid} = StandardV2.decode_grant(compact, %{})
      assert {:error, :invalid} = StandardV3.decode_grant(compact, %{})
    end

    test "rejects malformed producer inputs and assembly defects" do
      context = attestation_context()

      {:ok, %SigningInput{} = signing_input} =
        V1.attestation_signing_input(context.attestation, %{})

      assert {:error, :invalid} = V1.attestation_signing_input(:not_an_attestation, %{})

      for invalid <- [
            %{context.attestation | role: "admin"},
            %{context.attestation | role: :issuer},
            %{context.attestation | jti: ""},
            %{context.attestation | key_id: "not a kid!"},
            %{context.attestation | public_key: <<0::248>>},
            %{context.attestation | nbf: 1_735_693_200},
            %{context.attestation | exp: 1_735_689_600},
            %{context.attestation | nbf: 1.0},
            %{context.attestation | attestor_key_id: ""}
          ] do
        assert {:error, :invalid} = V1.attestation_signing_input(invalid, %{}), inspect(invalid)
      end

      assert {:error, :invalid} = V1.assemble_compact(:not_an_input, context.signature, %{})

      assert {:error, :invalid} =
               V1.assemble_compact(%{signing_input | kind: :proof}, context.signature, %{})

      wrong_typ_header =
        encode_segment(%{"alg" => "EdDSA", "kid" => context.attestor_key_id, "typ" => "ba+cap"})

      wrong_typ_input = %SigningInput{
        signing_input
        | protected_segment: wrong_typ_header,
          message: wrong_typ_header <> "." <> signing_input.payload_segment
      }

      assert {:error, :invalid} =
               V1.assemble_compact(wrong_typ_input, context.signature, %{})

      # A structurally assembled input whose payload violates profile member rules
      # (non-canonical member order) must not become a compact artifact: assembly
      # revalidates the payload under this profile (REQ-RA1-API-assembly-revalidate).
      payload = decode_segment(signing_input.payload_segment)

      non_canonical_payload =
        ~s({"v":1,"jti":"#{payload["jti"]}","key_id":"#{payload["key_id"]}","public_key":"#{payload["public_key"]}","role":"#{payload["role"]}","nbf":#{payload["nbf"]},"exp":#{payload["exp"]}})

      non_canonical_segment = Base.url_encode64(non_canonical_payload, padding: false)

      non_canonical_input = %SigningInput{
        signing_input
        | payload_segment: non_canonical_segment,
          message: signing_input.protected_segment <> "." <> non_canonical_segment
      }

      non_canonical_message_signature =
        :crypto.sign(:eddsa, :none, non_canonical_input.message, [
          context.attestor_private,
          :ed25519
        ])

      assert {:error, :invalid} =
               V1.assemble_compact(non_canonical_input, non_canonical_message_signature, %{})

      assert {:error, :invalid} = V1.assemble_compact(signing_input, <<0, 1, 2>>, %{})

      wrong_kind = %SigningInput{signing_input | kind: :unknown}
      assert {:error, :invalid} = V1.assemble_compact(wrong_kind, context.signature, %{})
    end
  end

  describe "decode_attestation/2" do
    test "decodes bounded without evaluating trust" do
      context = attestation_context()

      assert {:ok, decoded} = V1.decode_attestation(context.compact, %{})
      assert decoded.version == 1
      assert decoded.attestor_key_id == context.attestor_key_id
      assert decoded.jti == "urn:example:attestation:1"
      assert decoded.key_id == context.subject_key_id
      assert decoded.public_key == context.subject_public
      assert decoded.role == "issuer"
      assert decoded.nbf == 1_735_689_600
      assert decoded.exp == 1_735_693_200
      assert decoded.verification == :not_evaluated

      assert {:error, :invalid} = V1.decode_attestation(:not_a_compact, %{})
      assert {:error, :invalid} = V1.decode_attestation("", %{})

      grant_like =
        mint_compact(
          %{"alg" => "EdDSA", "kid" => context.attestor_key_id, "typ" => "ba+cap"},
          %{
            "v" => 1,
            "jti" => "x"
          },
          context.attestor_private
        )

      assert {:error, :invalid} = V1.decode_attestation(grant_like, %{})
    end
  end

  describe "verify_attestation/2" do
    test "proves signature, subject binding, containment, and window; returns anchor-postured facts" do
      context = attestation_context()
      {:ok, attestor_fp} = Jwk.public_key_thumbprint_raw(context.attestor_public, %{})
      {:ok, subject_fp} = Jwk.public_key_thumbprint_raw(context.subject_public, %{})

      assert {:ok, facts} = V1.verify_attestation(context.compact, context.expected)

      assert facts.version == 1
      assert facts.attestor_key_id == context.attestor_key_id
      assert facts.attestor_key_fingerprint == attestor_fp
      assert facts.subject_key_id == context.subject_key_id
      assert facts.subject_key_fingerprint == subject_fp
      assert facts.role == "issuer"
      assert facts.jti == "urn:example:attestation:1"
      assert facts.nbf == 1_735_689_600
      assert facts.exp == 1_735_693_200
      assert facts.verification == :signature_and_window
      assert facts.trust == :not_evaluated

      assert facts |> Map.from_struct() |> Map.keys() |> Enum.sort() ==
               ~w(attestor_key_fingerprint attestor_key_id exp jti nbf role subject_key_fingerprint subject_key_id trust verification version)a

      assert inspect(facts) =~ "<redacted>"

      assert {:error, :invalid} = V1.verify_attestation(:not_a_compact, context.expected)
      assert {:error, :invalid} = V1.verify_attestation(context.compact, :not_expected)
    end

    test "a holder-role attestation verifies with the same mechanics" do
      context = attestation_context(%{role: "holder"})

      assert {:ok, facts} = V1.verify_attestation(context.compact, context.expected)
      assert facts.role == "holder"
    end

    test "rejects closed-set, canonical-byte, and signature defects" do
      context = attestation_context()

      header = %{
        "alg" => "EdDSA",
        "kid" => context.attestor_key_id,
        "typ" => "ba+role-attestation"
      }

      payload = valid_payload(context)

      invalid_variants = [
        {"unknown header member",
         mint_compact(Map.put(header, "cty", "json"), payload, context.attestor_private)},
        {"missing header member",
         mint_compact(Map.delete(header, "kid"), payload, context.attestor_private)},
        {"unknown alg",
         mint_compact(%{header | "alg" => "ES256"}, payload, context.attestor_private)},
        {"wrong typ",
         mint_compact(%{header | "typ" => "ba+cap"}, payload, context.attestor_private)},
        {"unknown payload member",
         mint_compact(header, Map.put(payload, "scope", "everything"), context.attestor_private)},
        {"v is 2", mint_compact(header, %{payload | "v" => 2}, context.attestor_private)},
        {"role outside closed set",
         mint_compact(header, %{payload | "role" => "auditor"}, context.attestor_private)},
        {"public_key wrong width",
         mint_compact(
           header,
           %{payload | "public_key" => Base.url_encode64(<<0::248>>, padding: false)},
           context.attestor_private
         )},
        {"inverted window",
         mint_compact(
           header,
           %{payload | "nbf" => payload["exp"], "exp" => payload["nbf"]},
           context.attestor_private
         )},
        {"empty window",
         mint_compact(header, %{payload | "exp" => payload["nbf"]}, context.attestor_private)},
        {"fractional float numeric date", float_member_compact(context, "nbf", "1735689600.5")},
        {"whole float v lexeme", float_member_compact(context, "v", "1.0")},
        {"non-canonical payload order", non_canonical_compact(context)},
        {"duplicate member", duplicate_member_compact(context)},
        {"wrong attestor kid",
         mint_compact(%{header | "kid" => "other-attestor"}, payload, context.attestor_private)},
        {"signature by another key", mint_compact(header, payload, context.other_private)},
        {"tampered signature", flip_signature_byte(context.compact)},
        {"truncated compact", String.slice(context.compact, 0..(byte_size(context.compact) - 2))},
        {"not a compact", "not-a-compact"}
      ]

      for {label, compact} <- invalid_variants do
        assert {:error, :invalid} = V1.verify_attestation(compact, context.expected), label
      end
    end

    test "rejects every missing payload member" do
      context = attestation_context()
      payload = valid_payload(context)

      header = %{
        "alg" => "EdDSA",
        "kid" => context.attestor_key_id,
        "typ" => "ba+role-attestation"
      }

      for member <- Map.keys(payload) do
        compact = mint_compact(header, Map.delete(payload, member), context.attestor_private)

        assert {:error, :invalid} = V1.verify_attestation(compact, context.expected),
               "missing #{member}"
      end
    end

    test "rejects subject-binding mismatches" do
      context = attestation_context()

      wrong_key_id = %{context.expected | subject_key_id: "different-subject"}
      assert {:error, :invalid} = V1.verify_attestation(context.compact, wrong_key_id)

      <<first, rest::binary>> = context.subject_public

      wrong_key = %{
        context.expected
        | subject_public_key: <<Bitwise.bxor(first, 1), rest::binary>>
      }

      assert {:error, :invalid} = V1.verify_attestation(context.compact, wrong_key)
    end

    test "rejects self-attestation structurally" do
      context = attestation_context()

      same_material =
        mint_compact(
          %{
            "alg" => "EdDSA",
            "kid" => context.attestor_key_id,
            "typ" => "ba+role-attestation"
          },
          %{
            valid_payload(context)
            | "key_id" => context.attestor_key_id,
              "public_key" => Base.url_encode64(context.attestor_public, padding: false)
          },
          context.attestor_private
        )

      assert {:error, :invalid} =
               V1.verify_attestation(same_material, %{
                 context.expected
                 | subject_key_id: context.attestor_key_id,
                   subject_public_key: context.attestor_public
               })

      same_key_id =
        mint_compact(
          %{
            "alg" => "EdDSA",
            "kid" => context.attestor_key_id,
            "typ" => "ba+role-attestation"
          },
          %{valid_payload(context) | "key_id" => context.attestor_key_id},
          context.attestor_private
        )

      assert {:error, :invalid} =
               V1.verify_attestation(same_key_id, %{
                 context.expected
                 | subject_key_id: context.attestor_key_id
               })
    end

    test "window containment: bounded attestor windows bound the attestation window" do
      context = attestation_context()

      assert {:ok, _facts} = V1.verify_attestation(context.compact, context.expected)

      # nbf == attestor.valid_from is containment and accepts.
      edge = attestation_context(%{attestor_window: {1_735_689_600, 1_735_694_000}})
      assert {:ok, _facts} = V1.verify_attestation(edge.compact, edge.expected)

      # exp == attestor.valid_before is containment and accepts.
      edge_exp = attestation_context(%{attestor_window: {1_735_689_000, 1_735_693_200}})
      assert {:ok, _facts} = V1.verify_attestation(edge_exp.compact, edge_exp.expected)

      # nbf before the attestor window opens.
      early = attestation_context(%{attestor_window: {1_735_689_601, 1_735_694_000}})
      assert {:error, :invalid} = V1.verify_attestation(early.compact, early.expected)

      # exp beyond the attestor window close: the retired-key backdating attack.
      outliving = attestation_context(%{attestor_window: {0, 1_735_689_599}})
      assert {:error, :invalid} = V1.verify_attestation(outliving.compact, outliving.expected)

      # an unbounded attestor window contains any attestation window.
      unbounded = attestation_context(%{attestor_window: {0, :unbounded}})
      assert {:ok, _facts} = V1.verify_attestation(unbounded.compact, unbounded.expected)
    end

    test "now window is half-open [nbf, exp)" do
      context = attestation_context()

      assert {:ok, _facts} = V1.verify_attestation(context.compact, context.expected)

      at_nbf = %{context.expected | now: 1_735_689_600}
      assert {:ok, _facts} = V1.verify_attestation(context.compact, at_nbf)

      before_window = %{context.expected | now: 1_735_689_599}

      assert {:error, :invalid} =
               V1.verify_attestation(context.compact, before_window)

      at_exp = %{context.expected | now: 1_735_693_200}
      assert {:error, :invalid} = V1.verify_attestation(context.compact, at_exp)

      inside = %{context.expected | now: 1_735_691_400}
      assert {:ok, _facts} = V1.verify_attestation(context.compact, inside)

      assert {:error, :invalid} =
               V1.verify_attestation(context.compact, %{context.expected | now: 1.5})
    end
  end

  test "the certified language-neutral corpus drives decode and verify verdicts" do
    root =
      Path.expand("../../../priv/conformance/attestation-profiles/role-attestation/v1", __DIR__)

    index_bytes = root |> Path.join("index.json") |> File.read!()

    assert :sha256 |> :crypto.hash(index_bytes) |> Base.encode16(case: :lower) ==
             @certified_index_sha256

    index = :json.decode(index_bytes)
    assert index["profile"] == "bap-role-attestation/1"
    assert index["revision"] == 1
    assert index["attestation_cases"] > 0
    assert Enum.map(index["files"], & &1["path"]) == ["profile.json", "attestation-cases.json"]

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
    expected = profile_expected(profile)

    cases = root |> Path.join("attestation-cases.json") |> File.read!() |> :json.decode()
    assert length(cases) == index["attestation_cases"]

    for attestation_case <- cases do
      case_expected =
        case Map.get(attestation_case, "expected_overrides", %{}) do
          overrides when map_size(overrides) == 0 ->
            expected

          %{"now" => now} = overrides when map_size(overrides) == 1 ->
            %{expected | now: now}

          %{"subject_public_key" => encoded} = overrides when map_size(overrides) == 1 ->
            {:ok, public_key} = Base.url_decode64(encoded, padding: false)
            %{expected | subject_public_key: public_key}

          %{"subject_key_id" => key_id} = overrides when map_size(overrides) == 1 ->
            %{expected | subject_key_id: key_id}

          %{"attestor_public_key" => encoded} = overrides when map_size(overrides) == 1 ->
            {:ok, public_key} = Base.url_decode64(encoded, padding: false)
            %{expected | attestor: %{expected.attestor | public_key: public_key}}

          %{"subject_key_id" => key_id, "subject_public_key" => encoded} = overrides
          when map_size(overrides) == 2 ->
            {:ok, public_key} = Base.url_decode64(encoded, padding: false)
            %{expected | subject_key_id: key_id, subject_public_key: public_key}

          overrides ->
            flunk("unsupported expected_overrides: #{inspect(overrides)}")
        end

      decode = match?({:ok, _}, V1.decode_attestation(attestation_case["compact"], %{}))

      verify =
        match?({:ok, _}, V1.verify_attestation(attestation_case["compact"], case_expected))

      v1_grant = match?({:ok, _}, StandardV1.decode_grant(attestation_case["compact"], %{}))

      assert decode == attestation_case["decode"], attestation_case["id"]
      assert verify == attestation_case["verify"], attestation_case["id"]
      assert v1_grant == Map.get(attestation_case, "v1_grant", false), attestation_case["id"]
    end
  end

  test "every normative profile requirement is present in the requirement map" do
    spec = File.read!("spec/bap-role-attestation-v1.md")
    requirement_map = File.read!("docs/design/role-attestation-requirement-map.md")

    certified_ids =
      "test/fixtures/durable_identifier_role_attestation_requirements.txt"
      |> File.read!()
      |> String.split()
      |> MapSet.new()

    spec_ids =
      ~r/\bREQ-RA1-[A-Za-z0-9-]+\b/
      |> Regex.scan(spec)
      |> Enum.map(fn [id] -> id end)
      |> MapSet.new()

    mapped_ids =
      ~r/`([A-Z]+-[A-Za-z0-9-]+)`/
      |> Regex.scan(requirement_map, capture: :all_but_first)
      |> Enum.map(fn [suffix] -> "REQ-RA1-" <> suffix end)
      |> MapSet.new()

    assert spec_ids == certified_ids
    assert mapped_ids == certified_ids
  end

  defp attestation_context(overrides \\ %{}) do
    role = Map.get(overrides, :role, "issuer")
    now = Map.get(overrides, :now, 1_735_691_000)

    {attestor_window_from, attestor_window_before} =
      Map.get(overrides, :attestor_window, {1_735_689_000, 1_735_694_000})

    {attestor_public, attestor_private} = :crypto.generate_key(:eddsa, :ed25519)
    {subject_public, _subject_private} = :crypto.generate_key(:eddsa, :ed25519)
    {_other_public, other_private} = :crypto.generate_key(:eddsa, :ed25519)

    attestor_key_id = "attestor-1"
    subject_key_id = "holder-key-1"

    attestation = %V1.RoleAttestation{
      attestor_key_id: attestor_key_id,
      jti: "urn:example:attestation:1",
      key_id: subject_key_id,
      public_key: subject_public,
      role: role,
      nbf: 1_735_689_600,
      exp: 1_735_693_200
    }

    attestor = %HistoricalPublicKey{
      key_id: attestor_key_id,
      public_key: attestor_public,
      valid_from: attestor_window_from,
      valid_before: attestor_window_before
    }

    expected = %V1.ExpectedAttestation{
      attestor: attestor,
      subject_key_id: subject_key_id,
      subject_public_key: subject_public,
      now: now,
      bounds: %{}
    }

    {:ok, %SigningInput{} = signing_input} = V1.attestation_signing_input(attestation, %{})

    signature = :crypto.sign(:eddsa, :none, signing_input.message, [attestor_private, :ed25519])

    {:ok, compact} = V1.assemble_compact(signing_input, signature, %{})

    %{
      attestation: attestation,
      attestor: attestor,
      attestor_key_id: attestor_key_id,
      attestor_public: attestor_public,
      attestor_private: attestor_private,
      subject_key_id: subject_key_id,
      subject_public: subject_public,
      other_private: other_private,
      expected: expected,
      signature: signature,
      compact: compact
    }
  end

  defp valid_payload(context) do
    %{
      "v" => 1,
      "jti" => "urn:example:attestation:1",
      "key_id" => context.subject_key_id,
      "public_key" => Base.url_encode64(context.subject_public, padding: false),
      "role" => "issuer",
      "nbf" => 1_735_689_600,
      "exp" => 1_735_693_200
    }
  end

  defp json_value(v) when is_binary(v), do: {:string, v}
  defp json_value(v) when is_integer(v), do: {:integer, v}

  defp encode_object(map) do
    {:ok, encoded} =
      Jcs.encode({:object, Enum.map(map, fn {k, v} -> {k, json_value(v)} end)}, %{})

    encoded
  end

  defp mint_compact(header, payload, private) do
    sign_bytes(encode_object(header), encode_object(payload), private)
  end

  defp sign_bytes(protected_bytes, payload_bytes_value, private) do
    protected_segment = Base.url_encode64(protected_bytes, padding: false)
    payload_segment = Base.url_encode64(payload_bytes_value, padding: false)
    message = protected_segment <> "." <> payload_segment

    signature =
      :crypto.sign(:eddsa, :none, message, [private, :ed25519])
      |> Base.url_encode64(padding: false)

    message <> "." <> signature
  end

  defp float_member_compact(context, member, lexeme) do
    payload = valid_payload(context)

    members =
      payload
      |> Map.delete(member)
      |> Enum.map_join(",", fn {k, v} -> ~s("#{k}":#{json_lexeme(v)}) end)

    raw_payload = "{" <> members <> ",\"" <> member <> "\":" <> lexeme <> "}"

    header = %{
      "alg" => "EdDSA",
      "kid" => context.attestor_key_id,
      "typ" => "ba+role-attestation"
    }

    sign_bytes(encode_object(header), raw_payload, context.attestor_private)
  end

  defp json_lexeme(v) when is_binary(v), do: ~s("#{v}")
  defp json_lexeme(v) when is_integer(v), do: Integer.to_string(v)

  defp non_canonical_compact(context) do
    payload = valid_payload(context)

    non_canonical =
      ~s({"v":1,"jti":"#{payload["jti"]}","key_id":"#{payload["key_id"]}","public_key":"#{payload["public_key"]}","role":"#{payload["role"]}","nbf":#{payload["nbf"]},"exp":#{payload["exp"]}})

    header = %{
      "alg" => "EdDSA",
      "kid" => context.attestor_key_id,
      "typ" => "ba+role-attestation"
    }

    sign_bytes(encode_object(header), non_canonical, context.attestor_private)
  end

  defp duplicate_member_compact(context) do
    payload = valid_payload(context)

    duplicated =
      ~s({"exp":#{payload["exp"]},"jti":"#{payload["jti"]}","key_id":"#{payload["key_id"]}","nbf":#{payload["nbf"]},"public_key":"#{payload["public_key"]}","role":"#{payload["role"]}","role":"#{payload["role"]}","v":1})

    header = %{
      "alg" => "EdDSA",
      "kid" => context.attestor_key_id,
      "typ" => "ba+role-attestation"
    }

    sign_bytes(encode_object(header), duplicated, context.attestor_private)
  end

  defp flip_signature_byte(compact) do
    [protected, payload, signature] = String.split(compact, ".")
    {:ok, decoded} = Base.url_decode64(signature, padding: false)
    <<first, rest::binary>> = decoded
    flipped = <<Bitwise.bxor(first, 1), rest::binary>>
    Enum.join([protected, payload, Base.url_encode64(flipped, padding: false)], ".")
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

  defp profile_expected(profile) do
    {:ok, attestor_public} =
      Base.url_decode64(profile["attestor"]["public_key"], padding: false)

    {:ok, subject_public} = Base.url_decode64(profile["subject"]["public_key"], padding: false)

    %V1.ExpectedAttestation{
      attestor: %HistoricalPublicKey{
        key_id: profile["attestor"]["key_id"],
        public_key: attestor_public,
        valid_from: profile["attestor"]["valid_from"],
        valid_before: profile["attestor"]["valid_before"]
      },
      subject_key_id: profile["subject"]["key_id"],
      subject_public_key: subject_public,
      now: profile["now"],
      bounds: %{}
    }
  end
end
