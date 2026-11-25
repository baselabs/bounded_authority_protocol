defmodule BoundedAuthorityProtocol.ActionApproval.CorpusTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.ActionApproval.V1.Record
  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1, as: ES256
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: CA1
  alias BoundedAuthorityProtocol.ContentAssertion.V1.Codec
  alias BoundedAuthorityProtocol.{Ed25519, Es256}
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: Role
  alias BoundedAuthorityProtocol.V1, as: BAP1
  alias BoundedAuthorityProtocol.V1.{Base64Url, Bounds, HistoricalPublicKey, Jcs, Json}
  alias BoundedAuthorityProtocol.V2, as: BAP2
  alias BoundedAuthorityProtocol.V3, as: BAP3

  @es256_root "priv/conformance/attestation-profiles/content-assertion-es256/v1"
  @approval_root "priv/conformance/content-profiles/action-approval/v1"
  @es256_pin "d79329d431de093f162613fbd2a2fe838766b690fa67cfbc1478eafa322b3c63"
  @approval_pin "35470198349f2b03b0c5df4368569a437eae39847fa4b8df1cd1f24b33d6f826"

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

    Enum.each(fixture(@approval_root, "record-cases.json"), &assert_record_case/1)

    assert Approval.decode_record(nil) == {:error, :invalid}
    assert Approval.decode_record("{}", %{}, []) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{}, %{}, false) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{}, %{}, nil) == {:error, :invalid}
    assert Approval.encode_record(%{}, %{content_bytes: 0}) == {:error, :invalid}
    assert Json.decode_approval_record("", 0, 0) == {:error, :invalid}
    assert Jcs.encode_approval_record({}, 0, 0, 0) == {:error, :invalid}
  end

  test "record resources must contain strings and authoring preflight rejects tiny bounds" do
    item = @approval_root |> fixture("record-cases.json") |> hd()
    wire = raw(item["wire"])

    assert {:ok, %Record{} = record} = Approval.decode_record(wire)

    for resource <- ["true", "1", "null"] do
      invalid = Regex.replace(~r/"resources":\[[^\]]*\]/, wire, ~s("resources":[#{resource}]))
      assert invalid != wire
      assert Approval.decode_record(invalid) == {:error, :invalid}
    end

    assert Approval.encode_record(record, %{}, %{record_bytes: 1}) == {:error, :invalid}
  end

  test "approval diagnostic precedence and complete verified facts" do
    for file <- ["approval-cases.json", "multi-fault-cases.json"],
        item <- fixture(@approval_root, file) do
      assert_approval_case(item)
    end

    cases = fixture(@approval_root, "approval-cases.json")
    missing = Enum.find(cases, &(&1["id"] == "missing-trust"))
    missing_context = fields(missing["context"])
    assert missing_context.snapshot == nil

    assert Approval.verify_es256(raw(missing["record"]), missing["compact"], missing_context) ==
             {:error, :trust_unavailable}

    assert Approval.verify_es256(nil, nil, nil) == {:error, :invalid_context}

    item = Enum.find(cases, &(&1["id"] == "es256-verified"))
    context = fields(item["context"])
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

  test "a context missing a required request field is rejected before snapshot admission" do
    item = fixture_case!(@approval_root, "approval-cases.json", "es256-verified")
    context = fields(item["context"])
    record = raw(item["record"])
    compact = item["compact"]

    assert {:ok, _} = Approval.verify_es256(record, compact, context)

    for field <- [:audience, :action, :roles, :max_lifetime] do
      assert Approval.verify_es256(record, compact, Map.delete(context, field)) ==
               {:error, :invalid_context}
    end

    assert Approval.verify_es256(record, compact, Map.put(context, :max_active, -1)) ==
             {:error, :invalid_context}
  end

  test "foreign-suite inputs stop before claims, lookup or signature verification" do
    patterns = [
      {Codec, :parse, 3},
      {Codec, :parse_claims, 2},
      {Approval, :key_entry, 2},
      {Codec, :signature, 3},
      {Ed25519, :verify_strict, 3},
      {Es256, :verify_strict, 3}
    ]

    cases = fixture(@approval_root, "approval-cases.json")

    for {id, calls} <- [
          {"eddsa-verified", [1, 1, 1, 1, 1, 0]},
          {"es256-verified", [1, 1, 1, 1, 0, 1]},
          {"foreign-eddsa", [1, 0, 0, 0, 0, 0]},
          {"foreign-es256", [1, 0, 0, 0, 0, 0]}
        ] do
      item = Enum.find(cases, &(&1["id"] == id))

      trace_calls(patterns, fn ->
        case item["expected"] do
          "unsupported_algorithm" ->
            assert verify_case(item) == {:error, :unsupported_algorithm}
            expected = item["expected_calls"]
            [_, claims, lookup, _, eddsa, es256] = Enum.map(patterns, &call_count/1)
            assert claims == expected["payload_parser"], id
            assert lookup == expected["key_lookup"], id
            assert eddsa + es256 == expected["foreign_verifier"], id

          _verified ->
            assert {:ok, _} = verify_case(item)
        end

        assert Enum.map(patterns, &call_count/1) == calls, id
      end)
    end
  end

  test "record size preflight stops before escaping fields or encoding the tree" do
    cases = fixture(@approval_root, "record-cases.json")

    for {id, result, encoding_calls} <- [
          {"authoring-escaped-size-exact", :ok, 1},
          {"authoring-escaped-size-plus", :error, 0},
          {"escape-heavy-over", :error, 0}
        ] do
      item = Enum.find(cases, &(&1["id"] == id))
      assert_encoding_calls(item, result, encoding_calls)
    end

    assert_escaped_size_early_stop()
  end

  test "revision digest width is checked before decoding base64url" do
    assert_revision_width()
  end

  test "approval rendering redacts raw and transformed canaries" do
    cases = fixture(@approval_root, "approval-cases.json")

    for item <- fixture(@approval_root, "rendering-cases.json"),
        item["owner"] != "sdk_helper" do
      input = Enum.find(cases, &(&1["id"] == item["pure_case"]))
      result = verify_case(input)

      result =
        case {item["id"], result} do
          {"nested-record", {:ok, facts}} -> facts.record
          {"nested-assertion", {:ok, facts}} -> facts.assertion
          _other -> result
        end

      rendered = inspect(result)
      assert rendered == item["expected"], item["id"]

      for {field, forms} <- Map.get(item, "forbidden", %{}), form <- forms do
        refute String.contains?(rendered, form), "#{item["id"]}/#{field}"
      end
    end
  end

  @doc false
  def assert_mutation_witness("authoring-escaped-size-plus" = id) do
    item = fixture_case!(@approval_root, "record-cases.json", id)
    assert_encoding_calls(item, :error, 0)
  end

  def assert_mutation_witness("escaped-size-early-stop"), do: assert_escaped_size_early_stop()
  def assert_mutation_witness("revision-width-before-base64"), do: assert_revision_width()

  def assert_mutation_witness(id) do
    cases = [
      {@approval_root, "record-cases.json", &assert_record_case/1},
      {@approval_root, "approval-cases.json", &assert_approval_case/1},
      {@approval_root, "multi-fault-cases.json", &assert_approval_case/1},
      {@es256_root, "assembly-cases.json", &assert_assembly_witness/1}
    ]

    [{item, assertion}] =
      for {root, file, assertion} <- cases,
          %{"id" => ^id} = item <- fixture(root, file) do
        {item, assertion}
      end

    assertion.(item)
  end

  defp fixture_case!(root, file, id) do
    [item] = Enum.filter(fixture(root, file), &(&1["id"] == id))
    item
  end

  defp assert_assembly_witness(item) do
    signing = fixture(@es256_root, "profile.json")["signing"]
    {:ok, input} = ES256.assertion_signing_input(signing_producer(signing), %{})
    assert_assembly_case(item, input)
  end

  defp assert_encoding_calls(item, result, encoding_calls) do
    encode = {Jcs, :encode_approval_record, 4}
    escape = {Jcs, :escape_string, 1}
    record = struct!(Record, fields(Map.delete(item["author"], "v")))
    id = item["id"]

    trace_calls([encode, escape], fn ->
      assert {^result, _} = Approval.encode_record(record), id
      assert call_count(encode) == encoding_calls, id
      assert call_count(escape) > 0 == (encoding_calls == 1), id
    end)
  end

  defp assert_escaped_size_early_stop do
    escaped_size = {Jcs, :escaped_size, 3}
    escape = {Jcs, :escape_string, 1}

    trace_calls([escaped_size, escape], fn ->
      assert Jcs.escaped_string_bytes(:binary.copy(<<1>>, 1024), 7) == {:error, :invalid}
      assert call_count(escaped_size) == 2, "escaped-size-early-stop"
      assert call_count(escape) == 0
      assert Jcs.escaped_string_bytes(<<1, ?\n, ?">> <> "é", 14) == {:ok, 14}
      assert Jcs.escaped_string_bytes(<<1, ?\n, ?">> <> "é", 13) == {:error, :invalid}
    end)
  end

  defp assert_revision_width do
    base64_decode = {Base64Url, :decode, 2}
    wire = @approval_root |> fixture("record-cases.json") |> hd() |> Map.fetch!("wire") |> raw()
    [_, revision] = Regex.run(~r/"revision_digest":"([^"]+)"/, wire)

    for {value, expected, calls} <- [
          {revision, :ok, 1},
          {binary_part(revision, 0, 42), :error, 0},
          {revision <> "A", :error, 0}
        ] do
      trace_calls([base64_decode], fn ->
        assert {^expected, _} = Approval.decode_record(String.replace(wire, revision, value))
        assert call_count(base64_decode) == calls, "revision-width-before-base64"
      end)
    end
  end

  defp assert_record_case(item) do
    ca = fields(item["ca_bounds"])
    limits = fields(item["bounds"])

    case {item, item["expected"]} do
      {%{"wire" => wire}, "invalid"} ->
        assert Approval.decode_record(raw(wire), ca, limits) == {:error, :invalid}, item["id"]

      {%{"wire" => wire}, %{"wire" => exact, "content_digest" => digest}} ->
        assert {:ok, %Record{} = record} = Approval.decode_record(raw(wire), ca, limits),
               item["id"]

        assert Approval.encode_record(record, ca, limits) == {:ok, raw(exact)}, item["id"]
        assert ES256.content_digest(raw(exact), ca) == {:ok, raw(digest)}, item["id"]

      {%{"author" => record}, expected} ->
        record = struct!(Record, fields(Map.delete(record, "v")))
        result = Approval.encode_record(record, ca, limits, item["canonicalize"])

        case expected do
          "invalid" ->
            assert result == {:error, :invalid}, item["id"]

          %{"wire" => wire, "content_digest" => digest} ->
            assert result == {:ok, raw(wire)}, item["id"]
            assert ES256.content_digest(raw(wire), ca) == {:ok, raw(digest)}, item["id"]
        end
    end
  end

  defp assert_approval_case(item) do
    result = verify_case(item)

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
    end
  end

  defp signing_producer(signing) do
    fields = signing["payload"] |> Map.delete("v") |> fields()
    struct!(ES256.ContentAssertion, Map.put(fields, :attestor_key_id, signing["kid"]))
  end

  defp assert_assembly_case(item, input) do
    signature = raw(item["signature"])

    case item["expected"] do
      "invalid" ->
        assert ES256.assemble_compact(input, signature, %{}) == {:error, :invalid}, item["id"]

      compact ->
        assert ES256.assemble_compact(input, signature, %{}) == {:ok, compact}, item["id"]
    end
  end

  defp verify_case(item) do
    context = fields(item["context"])
    record = raw(item["record"])
    compact = item["compact"]

    try do
      case item["suite"] do
        "es256" -> Approval.verify_es256(record, compact, context)
        "eddsa" -> Approval.verify_eddsa(record, compact, context)
      end
    rescue
      KeyError -> {:raised, KeyError}
    end
  end

  defp trace_calls(patterns, fun) do
    try do
      for {module, _, _} = mfa <- patterns do
        Code.ensure_loaded!(module)
        assert :erlang.trace_pattern(mfa, true, [:call_count]) == 1
      end

      fun.()
    after
      for mfa <- patterns, do: :erlang.trace_pattern(mfa, false, [:call_count])
    end
  end

  defp call_count(mfa) do
    assert {:call_count, count} = :erlang.trace_info(mfa, :call_count)
    assert is_integer(count)
    count
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
    producer = signing_producer(signing)

    assert inspect(producer) ==
             "#BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertion<redacted>"

    assert {:ok, input} = ES256.assertion_signing_input(producer, %{})
    assert Map.from_struct(input) == fields(signing["expected"])
    assert ES256.assemble_compact(input, raw(signing["signature"])) == {:ok, signing["compact"]}

    for item <- fixture(@es256_root, "assembly-cases.json"), do: assert_assembly_case(item, input)

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
  defp fields(:null), do: nil
  defp fields(value), do: value

  defp field_value(field, value) when field in @binary_fields, do: raw(value)

  defp field_value(field, value) when field in [:kind, :suite, :trust, :verification],
    do: String.to_existing_atom(value)

  defp field_value(:key, value) when is_map(value),
    do: Map.put(fields(value), :__struct__, HistoricalPublicKey)

  defp field_value(:valid_before, "unbounded"), do: :unbounded
  defp field_value(_, value), do: fields(value)

  defp fixture(root, path), do: root |> Path.join(path) |> File.read!() |> :json.decode()
  defp raw(value), do: Base.url_decode64!(value, padding: false)
  defp sha(value), do: :sha256 |> :crypto.hash(value) |> Base.encode16(case: :lower)
end
