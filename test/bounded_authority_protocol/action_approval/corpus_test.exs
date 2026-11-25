defmodule BoundedAuthorityProtocol.ActionApproval.CorpusTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.ActionApproval.V1.Record
  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1, as: ES256
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: CA1
  alias BoundedAuthorityProtocol.ContentAssertion.V1.Codec
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: Role
  alias BoundedAuthorityProtocol.V1, as: BAP1
  alias BoundedAuthorityProtocol.V2, as: BAP2
  alias BoundedAuthorityProtocol.V3, as: BAP3
  alias BoundedAuthorityProtocol.V1.{Bounds, HistoricalPublicKey, Jcs, Json}

  @es256_root "priv/conformance/attestation-profiles/content-assertion-es256/v1"
  @approval_root "priv/conformance/content-profiles/action-approval/v1"
  @es256_pin "067cbdc96a7846f55a9c50e69091096456137262741c7e59b6e5eac88531838a"
  @approval_pin "30ff68f1552ee1d5a02407c96c0f60caf381f8d89607a04e0012379fe5909be2"

  @binary_fields ~w(attestor_key_fingerprint content_digest digest prev profile_digest public_key
    revision_digest)a

  test "candidate indexes and their exact file sets are pinned" do
    for {root, pin} <- [{@es256_root, @es256_pin}, {@approval_root, @approval_pin}] do
      index = File.read!(Path.join(root, "index.json"))
      assert sha(index) == pin
      entries = :json.decode(index)["files"]
      paths = Enum.map(entries, & &1["path"])
      assert Enum.sort(File.ls!(root)) == Enum.sort(["index.json" | paths])

      all_ids =
        Enum.flat_map(entries, fn entry ->
          bytes = File.read!(Path.join(root, entry["path"]))
          assert sha(bytes) == entry["sha256"]

          case Map.fetch(entry, "cases") do
            :error ->
              []

            {:ok, count} ->
              cases = :json.decode(bytes)
              assert length(cases) == count
              Enum.map(cases, & &1["id"])
          end
        end)

      assert Enum.uniq(all_ids) == all_ids
    end
  end

  test "profile identity and approval record vectors" do
    profile = fixture(@approval_root, "profile.json")
    descriptor = File.read!("spec/profiles/bap-action-approval-v1.descriptor.json")
    preimage = <<"bap-action-approval/1", 0, descriptor::binary>>
    assert Base.encode16(preimage, case: :lower) == profile["profile_preimage_hex"]
    assert sha(preimage) == profile["profile_digest_hex"]
    assert :crypto.hash(:sha256, preimage) == Approval.profile_digest()

    for item <- fixture(@approval_root, "record-cases.json") do
      ca = fields(item["ca_bounds"])
      limits = fields(item["bounds"])

      result =
        case item do
          %{"wire" => wire} ->
            with {:ok, record} <- Approval.decode_record(raw(wire), ca, limits),
                 do: Approval.encode_record(record, ca, limits)

          %{"author" => record} ->
            record = record |> Map.delete("v") |> fields()
            Approval.encode_record(struct!(Record, record), ca, limits, item["canonicalize"])
        end

      case item["expected"] do
        "invalid" ->
          assert result == {:error, :invalid}, item["id"]

        %{"wire" => wire, "content_digest" => digest} ->
          assert result == {:ok, raw(wire)}, item["id"]
          assert ES256.content_digest(raw(wire), ca) == {:ok, raw(digest)}, item["id"]
      end
    end

    assert Approval.decode_record(nil) == {:error, :invalid}
    assert Approval.decode_record("{}", %{}, []) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{}, %{}, false) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{}, %{}, nil) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{content_bytes: 0}) == {:error, :invalid}
    assert Json.decode_approval_record("", 0, 0) == {:error, :invalid}
    assert Jcs.encode_approval_record({}, 0, 0, 0) == {:error, :invalid}
  end

  test "approval diagnostic precedence and complete verified facts" do
    for file <- ["approval-cases.json", "multi-fault-cases.json"],
        item <- fixture(@approval_root, file) do
      context = context(item["context"])
      record = raw(item["record"])
      compact = item["compact"]

      result =
        case item["suite"] do
          "es256" -> Approval.verify_es256(record, compact, context)
          "eddsa" -> Approval.verify_eddsa(record, compact, context)
        end

      case item["expected"] do
        expected when is_binary(expected) ->
          assert result == {:error, String.to_existing_atom(expected)}, item["id"]

        expected ->
          assert {:ok, facts} = result, item["id"]
          assert Map.from_struct(facts.record) == fields(Map.delete(expected["record"], "v"))
          assert Map.from_struct(facts.assertion) == fields(expected["assertion"])
          assert facts.suite == String.to_existing_atom(expected["suite"])
          assert facts.trust_domain == expected["trust_domain"]
          assert facts.trust == :not_evaluated

          rendering =
            @approval_root
            |> fixture("rendering-cases.json")
            |> Enum.find(&(&1["id"] == "verified-facts"))

          assert inspect(result) == rendering["expected"]
          assert inspect(facts.record) ==
                   "#BoundedAuthorityProtocol.ActionApproval.V1.Record<redacted>"
      end
    end

    assert Approval.verify_es256(nil, nil, nil) == {:error, :invalid_context}

    item = Enum.find(fixture(@approval_root, "approval-cases.json"), &(&1["id"] == "es256-verified"))
    context = context(item["context"])
    record = raw(item["record"])
    compact = item["compact"]
    assert {:ok, _} = Approval.verify_es256(record, compact, Map.delete(context, :max_active))

    snapshot = %{context.snapshot | entries: :unavailable}
    assert Approval.verify_es256(record, compact, %{context | snapshot: snapshot}) ==
             {:error, :trust_unavailable}

    [entry] = context.snapshot.entries
    snapshot = %{context.snapshot | entries: [%{entry | roles: :unavailable}]}
    assert Approval.verify_es256(record, compact, %{context | snapshot: snapshot}) ==
             {:error, :trust_unavailable}
  end

  test "foreign-suite inputs stop before claims, lookup or the foreign verifier" do
    for module <- [Codec, Approval], do: Code.ensure_loaded!(module)
    patterns = [{Codec, :parse_claims, 2}, {Approval, :key_entry, 2}, {Codec, :parse, 3}]
    parent = self()

    for item <- fixture(@approval_root, "approval-cases.json"),
        Map.has_key?(item, "expected_calls") do
      suite = String.to_existing_atom(item["suite"])
      context = context(item["context"])
      record = raw(item["record"])
      compact = item["compact"]

      worker =
        spawn_link(fn ->
          receive do
            :verify ->
              result =
                case suite do
                  :eddsa -> Approval.verify_eddsa(record, compact, context)
                  :es256 -> Approval.verify_es256(record, compact, context)
                end

              send(parent, {:verification, self(), result})

              receive do
                :stop -> :ok
              end
          end
        end)

      try do
        for mfa <- patterns, do: :erlang.trace_pattern(mfa, true, [:local])
        :erlang.trace(worker, true, [:call, {:tracer, parent}])
        send(worker, :verify)

        assert_receive {:verification, ^worker, {:error, :unsupported_algorithm}}, 1_000
        ref = :erlang.trace_delivered(worker)
        assert_receive {:trace_delivered, ^worker, ^ref}, 1_000

        assert_received {:trace, ^worker, :call, {Codec, :parse, [^compact, _, ^suite]}}
        refute_received {:trace, ^worker, :call, _}
      after
        send(worker, :stop)
        for mfa <- patterns, do: :erlang.trace_pattern(mfa, false, [:local])
      end
    end
  end

  test "ES256 assertion structure and compact digest" do
    for item <- fixture(@es256_root, "assertion-structure-cases.json") do
      compact = item["compact"]
      bounds = fields(item["bounds"])

      case item["expected"] do
        "invalid" ->
          assert ES256.decode_assertion(compact, bounds) == {:error, :invalid}, item["id"]
          assert ES256.assertion_digest(compact, bounds) == {:error, :invalid}, item["id"]

        expected ->
          digest = raw(expected["digest"])

          expected =
            expected
            |> Map.drop(["digest", "v"])
            |> fields()
            |> Map.merge(%{version: 1, verification: :not_evaluated})

          assert {:ok, %ES256.DecodedContentAssertion{} = artifact} =
                   ES256.decode_assertion(compact, bounds),
                 item["id"]

          assert Map.from_struct(artifact) == expected, item["id"]
          assert ES256.assertion_digest(compact, bounds) == {:ok, digest}, item["id"]

          assert inspect(artifact) ==
                   "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion<redacted>"
      end
    end

    for item <- fixture(@es256_root, "digest-cases.json") do
      data = raw(item["input"])
      bounds = fields(item["bounds"])

      expected =
        if item["expected"] == "invalid",
          do: {:error, :invalid},
          else: {:ok, raw(item["expected"])}

      assert ES256.content_digest(data, bounds) == expected, item["id"]
      assert CA1.content_digest(data, bounds) == expected, item["id"]
    end
  end

  test "ES256 strict verification and redacted facts" do
    for item <- fixture(@es256_root, "assertion-verification-cases.json") do
      context = fields(item["context"])
      key = struct!(HistoricalPublicKey, context.attestor)
      expected =
        struct!(ES256.ExpectedContentAssertion, Map.merge(context, %{attestor: key, bounds: %{}}))
      assert inspect(expected) ==
               "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ExpectedContentAssertion<redacted>"

      result = ES256.verify_assertion(item["compact"], expected)

      case item["expected"] do
        "invalid" ->
          assert result == {:error, :invalid}, item["id"]

        expected_facts ->
          assert {:ok, %ES256.ContentAssertionFacts{} = facts} = result, item["id"]
          assert Map.from_struct(facts) == fields(expected_facts), item["id"]

          assert inspect(facts) ==
                   "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts<redacted>"
      end
    end

    assert ES256.verify_assertion("", %{}) == {:error, :invalid}
  end

  test "exact signing input and strict assembly" do
    signing = fixture(@es256_root, "profile.json")["signing"]
    producer_fields = signing["payload"] |> Map.delete("v") |> fields()
    producer =
      struct!(ES256.ContentAssertion, Map.put(producer_fields, :attestor_key_id, signing["kid"]))

    assert inspect(producer) ==
             "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertion<redacted>"

    assert {:ok, input} = ES256.assertion_signing_input(producer, %{})
    assert Map.from_struct(input) == fields(signing["expected"])
    assert ES256.assemble_compact(input, raw(signing["signature"])) == {:ok, signing["compact"]}

    for item <- fixture(@es256_root, "assembly-cases.json") do
      signature = raw(item["signature"])

      case item["expected"] do
        "invalid" ->
          assert ES256.assemble_compact(input, signature, %{}) == {:error, :invalid}, item["id"]

        compact ->
          assert ES256.assemble_compact(input, signature, %{}) == {:ok, compact}, item["id"]
      end
    end

    assert ES256.assemble_compact(%{input | message: "a.b"}, raw(signing["signature"])) ==
             {:error, :invalid}

    assert CA1.assemble_compact(input, raw(signing["signature"])) == {:error, :invalid}

    wrong_kind = %{input | kind: :content_assertion}
    assert ES256.assemble_compact(wrong_kind, raw(signing["signature"])) == {:error, :invalid}

    assert ES256.assertion_signing_input(%{}, %{}) == {:error, :invalid}
  end

  test "successor checks reject mixed provenance and malformed facts" do
    for item <- fixture(@es256_root, "successor-cases.json") do
      previous = build_facts(item["previous_suite"], item["predecessor"])
      next = build_facts(item["next_suite"], item["successor"])
      verdict = if item["expected"] == "ok", do: :ok, else: {:error, :invalid}
      assert ES256.verify_successor(previous, next, %{}) == verdict, item["id"]
      assert CA1.verify_successor(previous, next, %{}) == {:error, :invalid}, item["id"]
    end
  end

  test "every distinct compact wire profile rejects the ES256 assertion and vice versa" do
    for item <- fixture(@es256_root, "separation-cases.json") do
      assert ES256.decode_assertion(item["foreign"], %{}) == {:error, :invalid}, item["id"]
      decoder = foreign_decoder(item["id"])
      assert {:ok, _} = decoder.(item["foreign"]), item["id"]
      assert decoder.(item["candidate"]) == {:error, :invalid}, item["id"]
    end
  end

  defp foreign_decoder("ca1"), do: &CA1.decode_assertion(&1, %{})
  defp foreign_decoder("loopback"), do: &Loopback.decode_proof(&1, %{})
  defp foreign_decoder("role-attestation"), do: &Role.decode_attestation(&1, %{})

  defp foreign_decoder(<<"v", major, "-", kind::binary>>) do
    facade = %{?1 => BAP1, ?2 => BAP2, ?3 => BAP3}[major]
    bounds = Bounds.maximum()

    case kind do
      "grant" ->
        &facade.decode_grant(&1, bounds)

      "proof" ->
        &facade.decode_proof(&1, bounds)

      "anchor" ->
        codec = Module.concat(facade, "BoundaryAnchorCodec")
        &codec.parse(&1, bounds)

      "transition" ->
        codec = Module.concat(facade, "KeyTransitionCodec")
        &codec.parse(&1, bounds)
    end
  end

  defp context(context) do
    context = fields(context)

    Map.update!(context, :snapshot, fn
      nil ->
        nil

      snapshot ->
        Map.update!(snapshot, :entries, fn entries ->
          Enum.map(entries, fn entry ->
            Map.update!(entry, :key, &struct!(HistoricalPublicKey, &1))
          end)
        end)
    end)
  end

  defp build_facts("es256", values), do: struct!(ES256.ContentAssertionFacts, fields(values))
  defp build_facts("eddsa", values), do: struct!(CA1.ContentAssertionFacts, fields(values))

  # These inputs are frozen, hash-pinned public fixtures.
  defp fields(value) when is_map(value) do
    Map.new(value, fn {name, value} ->
      field = String.to_atom(name)
      {field, field_value(field, value)}
    end)
  end

  defp fields(value) when is_list(value), do: Enum.map(value, &fields/1)
  defp fields(value), do: value

  defp field_value(field, value) when field in @binary_fields, do: raw(value)

  defp field_value(field, value) when field in [:kind, :suite, :trust, :verification],
    do: String.to_existing_atom(value)

  defp field_value(:valid_before, "unbounded"), do: :unbounded
  defp field_value(_, value), do: fields(value)

  defp fixture(root, path), do: root |> Path.join(path) |> File.read!() |> :json.decode()
  defp raw(value), do: Base.url_decode64!(value, padding: false)
  defp sha(value), do: :sha256 |> :crypto.hash(value) |> Base.encode16(case: :lower)
end
