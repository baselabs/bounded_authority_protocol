defmodule BoundedAuthorityProtocol.Conformance.CorpusTest do
  @moduledoc """
  Integrity, applicability, tamper, determinism, and decoder-loadability gates for the
  portable conformance corpus. The private-material sweep closes the census window live from
  the moment corpus data exists (Task 2).

  These tests run the PURE core (`Corpus`/`Runner`/`Report`) against synthetic in-memory
  corpora (`%{path => binary}`). The escript integration (Task 3) drives the same core
  out-of-VM.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.Conformance.Runner
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias JSONSchex.Draft202012.Schemas, as: Draft202012Schemas

  @json_bytes_max 65_536

  # --- helpers -------------------------------------------------------------

  defp sha256_b64(bytes), do: Base.url_encode64(:crypto.hash(:sha256, bytes), padding: false)

  defp jcs(value), do: Jcs.encode(value, %{}) |> elem(1)

  defp decode!(bytes) do
    {:ok, value} = Json.decode(bytes, Bounds.maximum())
    value
  end

  # A minimal valid signed compact grant for the official facade, built from a
  # throwaway test-only key. Used so the Runner has a valid case to execute.
  defp signed_grant_compact(holder_thumbprint_raw) do
    alias BoundedAuthorityProtocol.V1
    {pub, priv} = ed25519_keypair(<<1::256>>)

    grant = %V1.Grant{
      key_id: "issuer-a",
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:1",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint_raw,
      operations: [
        %V1.Operation{name: "read", selectors: [:all]}
      ]
    }

    {:ok, input} = V1.grant_signing_input(grant, %{})
    signature = :crypto.sign(:eddsa, :ed25519, input.message, [priv, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    {compact, pub}
  end

  defp ed25519_keypair(seed) do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, seed)
    {pub, priv}
  end

  # Build a corpus map from a keyword of {path, binary}. The index is generated
  # by re-deriving the SHA-256 of every case file and counting cases.
  defp build_index(cases_by_path, opts \\ []) do
    files =
      cases_by_path
      |> Enum.map(fn {path, bytes} ->
        %{"path" => path, "sha256_base64url" => sha256_b64(bytes), "cases" => case_count(bytes)}
      end)
      |> Enum.sort_by(& &1["path"])

    total = Enum.reduce(files, 0, &(&1["cases"] + &2))

    applicability =
      Keyword.get(opts, :applicability) ||
        applicability_from_cases(cases_by_path)

    %{
      "format" => "bounded-authority-protocol-v1-conformance-corpus-index",
      "public_key_fingerprints" => Keyword.get(opts, :fingerprints, []),
      "files" => files,
      "total_cases" => total,
      "applicability" => applicability
    }
  end

  defp case_count(bytes) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, {:object, members}} ->
        case List.keyfind(members, "cases", 0) do
          {"cases", {:array, items}} -> length(items)
          _ -> 0
        end

      _ ->
        0
    end
  end

  defp applicability_from_cases(cases_by_path) do
    surfaces = corpus_surfaces()
    classes = corpus_classes()

    empty =
      Map.new(surfaces, fn surface ->
        {surface, Map.new(classes, fn class -> {class, 0} end)}
      end)

    counts =
      Enum.reduce(cases_by_path, empty, fn {_path, bytes}, acc ->
        Enum.reduce(extract_surface_classes(bytes), acc, fn {surface, class}, a ->
          put_in(a, [surface, class], get_in(a, [surface, class]) + 1)
        end)
      end)

    # For the synthetic tests: required cells have >=1 case, n_a cells are zero.
    Map.new(counts, fn {surface, leaves} ->
      {surface,
       Map.new(leaves, fn {class, count} ->
         {class, if(count > 0, do: count, else: "n_a")}
       end)}
    end)
  end

  defp extract_surface_classes(bytes) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, {:object, members}} -> surface_classes_from_members(members)
      _ -> []
    end
  end

  defp surface_classes_from_members(members) do
    case List.keyfind(members, "cases", 0) do
      {"cases", {:array, items}} -> Enum.map(items, &surface_class_pair/1)
      _ -> []
    end
  end

  defp surface_class_pair({:object, case_members}) do
    {surface_value(case_members), class_value(case_members)}
  end

  defp surface_value(members) do
    {"surface", {:string, surface}} = List.keyfind(members, "surface", 0)
    surface
  end

  defp class_value(members) do
    {"class", {:string, class}} = List.keyfind(members, "class", 0)
    class
  end

  defp corpus_surfaces do
    [
      "untrusted_key_locator",
      "grant_signing_input",
      "proof_signing_input",
      "encode_consumption_entry",
      "check_chain",
      "boundary_anchor_signing_input",
      "key_transition_signing_input",
      "encode_anchored_export",
      "assemble_compact",
      "decode_grant",
      "decode_proof",
      "verify_grant",
      "verify_historical_anchor",
      "verify_key_transition",
      "verify_anchored_export",
      "check_envelope",
      "request_digest",
      "jcs.encode",
      "jwk.encode_public",
      "jwk.decode_public",
      "jwk.thumbprint_preimage",
      "jwk.thumbprint",
      "jwk.thumbprint_raw",
      "jwk.public_key_thumbprint_raw",
      "uri.normalize",
      "json.decode",
      "base64url.decode",
      "bounds.new"
    ]
  end

  defp corpus_classes do
    [
      "valid",
      "boundary_near",
      "exact_bound",
      "maximum_plus_one",
      "invalid_duplicate",
      "invalid_encoding",
      "invalid_algorithm",
      "invalid_key",
      "invalid_claim",
      "invalid_time",
      "invalid_nonce",
      "invalid_uri",
      "invalid_request",
      "invalid_selector",
      "invalid_limit",
      "tamper_meaningful_byte"
    ]
  end

  # A single trivial valid case as canonical bytes (one case, json.decode, valid).
  defp trivial_case_bytes do
    jcs(
      {:object,
       [
         {"format", {:string, "bounded-authority-protocol-v1-conformance-cases"}},
         {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}},
         {"cases",
          {:array,
           [
             {:object,
              [
                {"id", {:string, "json-decode-valid-001"}},
                {"surface", {:string, "json.decode"}},
                {"class", {:string, "valid"}},
                {"input", {:object, [{"text", {:string, "{\"a\":1}"}}]}},
                {"expected",
                 {:object,
                  [
                    {"verdict", {:string, "valid"}},
                    {"value", {:object, [{"a", {:integer, 1}}]}}
                  ]}}
              ]}
           ]}}
       ]}
    )
  end

  # A full synthetic corpus exercising one surface so the Runner produces a result.
  defp synthetic_corpus(opts \\ []) do
    {grant_compact, _issuer_pub} = signed_grant_compact(holder_thumbprint())

    decode_case =
      {:object,
       [
         {"id", {:string, "json-decode-valid-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, "{\"a\":1}"}}]}},
         {"expected",
          {:object,
           [
             {"verdict", {:string, "valid"}},
             {"value", {:object, [{"a", {:integer, 1}}]}}
           ]}}
       ]}

    untrusted_case =
      {:object,
       [
         {"id", {:string, "untrusted-key-locator-valid-001"}},
         {"surface", {:string, "untrusted_key_locator"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"compact", {:string, grant_compact}}]}},
         {"expected",
          {:object,
           [
             {"verdict", {:string, "valid"}},
             {"kid", {:string, "issuer-a"}}
           ]}}
       ]}

    cases =
      [decode_case, untrusted_case] ++
        Keyword.get(opts, :extra_cases, [])

    bytes =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-cases"}},
           {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}},
           {"cases", {:array, cases}}
         ]}
      )

    %{"cases/json/trivial.json" => bytes}
  end

  defp holder_thumbprint do
    {:ok, raw} =
      V1.Jwk.public_key_thumbprint_raw(
        ed25519_keypair(<<2::256>>) |> elem(0),
        %{}
      )

    raw
  end

  defp full_corpus_map(cases_map, opts) do
    index = build_index(cases_map, opts)
    bytes = jcs(to_object(index))
    Map.put(cases_map, "index.json", bytes)
  end

  defp to_object(map) do
    {:object,
     map
     |> Enum.map(fn
       {k, v} when is_map(v) -> {k, to_object(v)}
       {k, v} when is_list(v) -> {k, {:array, Enum.map(v, &to_value/1)}}
       {k, v} -> {k, to_value(v)}
     end)
     |> Enum.sort_by(&elem(&1, 0))}
  end

  defp to_value(v) when is_map(v), do: to_object(v)
  defp to_value(v) when is_list(v), do: {:array, Enum.map(v, &to_value/1)}
  defp to_value(v) when is_integer(v), do: {:integer, v}
  defp to_value(v) when is_boolean(v), do: {:boolean, v}
  defp to_value(v) when is_binary(v), do: {:string, v}

  # --- schema-shape rejections ---------------------------------------------

  test "case schema rejects unknown members, missing members, and wrong enum values" do
    {:ok, meta} =
      Draft202012Schemas.fetch("https://json-schema.org/draft/2020-12/schema")

    {:ok, compiled_meta} = JSONSchex.compile(meta)
    schema_path = "priv/conformance/v1/schemas/conformance-case.schema.json"
    schema = schema_path |> File.read!() |> :json.decode()
    {:ok, compiled} = JSONSchex.compile(schema)
    assert :ok = JSONSchex.validate(compiled_meta, schema)

    valid = minimal_valid_case_map()

    assert :ok = JSONSchex.validate(compiled, valid)

    for invalid <- [
          Map.put(valid, "extra", true),
          Map.delete(valid, "cases"),
          put_in(valid, ["cases", Access.at(0), "surface"], "not-a-surface"),
          put_in(valid, ["cases", Access.at(0), "class"], "not-a-class"),
          Map.put(valid, "format", "wrong-format")
        ] do
      assert {:error, _} = JSONSchex.validate(compiled, invalid)
    end
  end

  test "index schema rejects unknown members, missing members, and bad shapes" do
    {:ok, meta} =
      Draft202012Schemas.fetch("https://json-schema.org/draft/2020-12/schema")

    {:ok, compiled_meta} = JSONSchex.compile(meta)
    schema_path = "priv/conformance/v1/schemas/corpus-index.schema.json"
    schema = schema_path |> File.read!() |> :json.decode()
    {:ok, compiled} = JSONSchex.compile(schema)
    assert :ok = JSONSchex.validate(compiled_meta, schema)

    valid = minimal_valid_index_map()
    assert :ok = JSONSchex.validate(compiled, valid)

    for invalid <- [
          Map.put(valid, "extra", true),
          Map.delete(valid, "applicability"),
          put_in(valid, ["files", Access.at(0)], Map.put(valid["files"] |> hd(), "extra", 1)),
          put_in(valid, ["files", Access.at(0), "cases"], -1),
          put_in(valid, ["public_key_fingerprints"], ["short"])
        ] do
      assert {:error, _} = JSONSchex.validate(compiled, invalid)
    end
  end

  defp minimal_valid_case_map do
    :json.decode(trivial_case_bytes())
  end

  defp minimal_valid_index_map do
    cases_map = %{"cases/json/trivial.json" => trivial_case_bytes()}
    index_to_map(build_index(cases_map))
  end

  defp index_to_map(index) do
    %{
      "format" => index["format"],
      "public_key_fingerprints" => index["public_key_fingerprints"],
      "files" => Enum.map(index["files"], &index_file_to_map/1),
      "total_cases" => index["total_cases"],
      "applicability" => index["applicability"]
    }
  end

  defp index_file_to_map(entry) do
    %{
      "path" => entry["path"],
      "sha256_base64url" => entry["sha256_base64url"],
      "cases" => entry["cases"]
    }
  end

  # --- decoder-loadability (R4 / C2) ---------------------------------------

  test "a 65,537-byte JSON case file is rejected at corpus load by the normative decoder" do
    # Build a raw JSON file exceeding the 65,536-byte ceiling directly (the JCS encoder's own
    # bounds reject building it through jcs/1 — that is the point: the file is over-limit).
    oversize = :binary.copy(<<" ">>, @json_bytes_max + 1)

    bytes =
      "{\"format\":\"bounded-authority-protocol-v1-conformance-cases\",\"provenance\":{\"private_material_tracked\":false},\"cases\":[{\"id\":\"oversize\",\"surface\":\"json.decode\",\"class\":\"valid\",\"input\":{\"text\":\"#{oversize}\"},\"expected\":{\"verdict\":\"invalid\"}}]}"

    map = %{"cases/json/oversize.json" => bytes, "index.json" => index_for_one_case(bytes)}

    assert {:error, :invalid} = Corpus.load(map)
  end

  test "an index declaring more than 256 files is rejected by the normative decoder" do
    # Build the files array as a raw JSON string (257 entries) so the JCS encoder's own
    # array bound does not reject it at construction — the corpus LOADER's Json.decode
    # must be the thing that trips on the 256-item array_items ceiling.
    entries =
      Enum.map_join(1..257, ",", fn i ->
        ~s({"path":"cases/x#{i}.json","sha256_base64url":"AAAA","cases":1})
      end)

    index =
      ~s({"format":"bounded-authority-protocol-v1-conformance-corpus-index","public_key_fingerprints":[],"files":[#{entries}],"total_cases":257,"applicability":{}})

    assert {:error, :invalid} = Corpus.load(%{"index.json" => index})
  end

  defp index_for_one_case(case_bytes) do
    build_index(%{"cases/json/oversize.json" => case_bytes}) |> to_object() |> jcs()
  end

  # --- per-file SHA-256 (V3) -----------------------------------------------

  test "a tampered case byte (hash mismatch) is rejected at corpus load" do
    # Isolate the hash check (V3): keep the case file valid JSON (decodeable), but make its
    # declared SHA-256 in the index wrong. A midpoint byte-flip on JCS bytes can land in a
    # structural byte and break JSON validity, so rejection would fire at decode, not the hash.
    # Here the case bytes stay byte-identical and decodeable; only the index hash is stale.
    corpus = synthetic_corpus() |> full_corpus_map([])
    index = corpus["index.json"]

    # Rewrite the index with a wrong hash for the trivial case file (keep everything else valid).
    # The index is JCS JSON; replace the real case-file hash with a different valid-shape hash.
    real_hash = sha256_b64(corpus["cases/json/trivial.json"])
    wrong_hash = sha256_b64(<<"different bytes">>)
    tampered_index = String.replace(index, real_hash, wrong_hash, global: false)

    map_with_stale_index = %{corpus | "index.json" => tampered_index}
    assert {:error, :invalid} = Corpus.load(map_with_stale_index)
  end

  # --- file-set equality both directions (V1) ------------------------------

  test "a missing case file (declared in index, absent from corpus) is rejected" do
    corpus = synthetic_corpus() |> full_corpus_map([])
    # Remove a case file but keep the index referencing it.
    dropped = Map.delete(corpus, "cases/json/trivial.json")
    assert {:error, :invalid} = Corpus.load(dropped)
  end

  test "an unlisted case file (present in corpus, absent from index) is rejected" do
    corpus = synthetic_corpus() |> full_corpus_map([])
    extra = Map.put(corpus, "cases/extra/unlisted.json", trivial_case_bytes())
    assert {:error, :invalid} = Corpus.load(extra)
  end

  # --- counts (V1) ---------------------------------------------------------

  test "an index total_cases that disagrees with the files is rejected" do
    cases_map = synthetic_corpus()
    index = build_index(cases_map) |> Map.put("total_cases", 999)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a per-file case count that disagrees with the file is rejected" do
    cases_map = synthetic_corpus()

    index =
      build_index(cases_map)
      |> put_in(["files", Access.at(0), "cases"], 999)

    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  # --- applicability totality (V2, both directions) ------------------------

  test "a missing applicability surface member is rejected" do
    cases_map = synthetic_corpus()

    applicability =
      applicability_from_cases(cases_map)
      |> Map.delete("json.decode")

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a required applicability cell declared but with zero executed cases is rejected" do
    cases_map = synthetic_corpus()

    applicability =
      applicability_from_cases(cases_map)
      |> put_in(["json.decode", "valid"], 5)
      |> put_in(["jcs.encode", "valid"], "n_a")

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "an n_a applicability cell with a landed case is rejected" do
    # json.decode valid exists; mark it n_a -> mismatch.
    cases_map = synthetic_corpus()

    applicability =
      applicability_from_cases(cases_map)
      |> put_in(["json.decode", "valid"], "n_a")

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a class leaf missing from a surface is rejected (not 16 members)" do
    cases_map = synthetic_corpus()

    applicability =
      applicability_from_cases(cases_map)
      |> put_in(["json.decode"], Map.delete(applicability_leaf("json.decode"), "valid"))

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  defp applicability_leaf(_surface) do
    Map.new(corpus_classes(), &{&1, "n_a"})
  end

  # --- case-id uniqueness (corpus-wide) ------------------------------------

  test "a duplicate case id across files is rejected" do
    dup = trivial_case_bytes()
    cases_map = %{"cases/json/a.json" => dup, "cases/json/b.json" => dup}
    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  # --- tamper self-check (Q25 / V5) ----------------------------------------

  test "a tamper case whose verbatim artifact disagrees with the derived bytes is rejected" do
    base_case_id = "json-decode-valid-001"

    # base input text: {"a":1}. Derived tamper at byte index 2 (the 'a'), xor 0x20 -> {"A":1}.
    base_bytes = "{\"a\":1}"

    # Verbatim artifact stored in the case does NOT equal the derived bytes (Z != A).
    <<head::binary-size(2), _::binary-size(1), tail::binary>> = base_bytes
    wrong_verbatim = head <> <<"Z">> <> tail

    case_obj =
      {:object,
       [
         {"id", {:string, "json-decode-tamper-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"text", {:string, wrong_verbatim}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, base_case_id}},
             {"target", {:string, "input.text"}},
             {"byte_index", {:integer, 2}},
             {"xor", {:integer, 32}},
             {"meaning", {:string, "member-name byte"}}
           ]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/json/tamper.json", jcs_case([case_obj]))
    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a tamper case using the base64url input form with matching derived bytes loads" do
    # base input: base64url("hello") = "aGVsbG8". Tamper byte index 0 xor 0x01 -> "bGVsbG8" region.
    base_b64 = Base.url_encode64(<<"hello">>, padding: false)
    base_bin = Base.url_decode64!(base_b64, padding: false)
    # flip byte 0 of the decoded bytes
    <<first, rest::binary>> = base_bin
    tampered_bin = <<Bitwise.bxor(first, 0x01)>> <> rest
    tampered_b64 = Base.url_encode64(tampered_bin, padding: false)

    # The derived bytes (base with byte 0 flipped) must equal the tampered verbatim artifact, so
    # the tamper case references a distinct base case whose input is the untampered base64url.
    base_case_obj =
      {:object,
       [
         {"id", {:string, "json-decode-tamper-b64-base"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"base64url", {:string, base_b64}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    # Rewrite the tamper case to reference the base case.
    tamper_case =
      {:object,
       [
         {"id", {:string, "json-decode-tamper-b64-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"base64url", {:string, tampered_b64}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "json-decode-tamper-b64-base"}},
             {"target", {:string, "input.base64url"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first decoded byte"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/json/tamper-b64.json", jcs_case([base_case_obj, tamper_case]))

    map = full_corpus_map(cases_map, [])
    assert {:ok, _corpus} = Corpus.load(map)
  end

  # --- tamper target resolution (Task 2: compact / grant / proof / rows[i] / chunks[i]) ------

  test "a compact-target tamper re-derives against input.compact (not input.text) and loads" do
    {grant_compact, _pub} = signed_grant_compact(holder_thumbprint())

    # Flip the last byte of the compact JWS string (inside the signature segment).
    idx = byte_size(grant_compact) - 1
    <<pre::binary-size(^idx), last>> = grant_compact
    tampered = pre <> <<Bitwise.bxor(last, 0x01)>>

    base_case =
      {:object,
       [
         {"id", {:string, "decode-grant-compact-base"}},
         {"surface", {:string, "decode_grant"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"compact", {:string, grant_compact}}]}},
         {"expected",
          {:object, [{"verdict", {:string, "valid"}}, {"key_id", {:string, "issuer-a"}}]}}
       ]}

    tamper_case =
      {:object,
       [
         {"id", {:string, "decode-grant-compact-tamper"}},
         {"surface", {:string, "decode_grant"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"compact", {:string, tampered}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "decode-grant-compact-base"}},
             {"target", {:string, "compact"}},
             {"byte_index", {:integer, idx}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "last byte of the signature segment"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/grant/compact-tamper.json", jcs_case([base_case, tamper_case]))

    map = full_corpus_map(cases_map, [])
    assert {:ok, _corpus} = Corpus.load(map)
  end

  test "a compact-target tamper whose byte_index disagrees with the verbatim flip is rejected" do
    {grant_compact, _pub} = signed_grant_compact(holder_thumbprint())

    idx = byte_size(grant_compact) - 1
    <<pre::binary-size(^idx), last>> = grant_compact
    tampered = pre <> <<Bitwise.bxor(last, 0x01)>>

    base_case =
      {:object,
       [
         {"id", {:string, "decode-grant-compact-base"}},
         {"surface", {:string, "decode_grant"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"compact", {:string, grant_compact}}]}},
         {"expected",
          {:object, [{"verdict", {:string, "valid"}}, {"key_id", {:string, "issuer-a"}}]}}
       ]}

    # byte_index points one byte before the actual flip: the re-derived bytes differ from verbatim.
    tamper_case =
      {:object,
       [
         {"id", {:string, "decode-grant-compact-tamper-wrong-index"}},
         {"surface", {:string, "decode_grant"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"compact", {:string, tampered}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "decode-grant-compact-base"}},
             {"target", {:string, "compact"}},
             {"byte_index", {:integer, idx - 1}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "wrong index (does not match the verbatim flip)"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/grant/compact-tamper.json", jcs_case([base_case, tamper_case]))

    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a rows[i]-target tamper re-derives against the decoded i-th base64url row and loads" do
    row0 = Base.url_encode64("row-zero-bytes", padding: false)
    base_row1_bin = "row-one-bytes!!"
    <<first, rest::binary>> = base_row1_bin
    tampered_row1_bin = <<Bitwise.bxor(first, 0x01)>> <> rest

    base_case =
      {:object,
       [
         {"id", {:string, "check-chain-rows-base"}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"rows",
              {:array,
               [
                 {:string, row0},
                 {:string, Base.url_encode64(base_row1_bin, padding: false)}
               ]}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}

    tamper_case =
      {:object,
       [
         {"id", {:string, "check-chain-rows-tamper"}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input",
          {:object,
           [
             {"rows",
              {:array,
               [
                 {:string, row0},
                 {:string, Base.url_encode64(tampered_row1_bin, padding: false)}
               ]}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "check-chain-rows-base"}},
             {"target", {:string, "rows[1]"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first decoded byte of the second row"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/chain/rows-tamper.json", jcs_case([base_case, tamper_case]))

    map = full_corpus_map(cases_map, [])
    assert {:ok, _corpus} = Corpus.load(map)
  end

  test "tamper target resolution rejects every malformed / unresolvable target" do
    # Exercise each tamper_target_bytes error branch: a target the loader cannot resolve makes the
    # verbatim-vs-derived audit mismatch, so the corpus fails to load. (The nil-target legacy path
    # is exercised by the "loads" case below.)
    base = fn id, input ->
      {:object,
       [
         {"id", {:string, id}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "valid"}},
         {"input", input},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}
    end

    tamper = fn id, base_id, input, target ->
      {:object,
       [
         {"id", {:string, id}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", input},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, base_id}},
             {"target", {:string, target}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "error-branch coverage"}}
           ]}}
       ]}
    end

    rows = fn list -> {:object, [{"rows", {:array, Enum.map(list, &{:string, &1})}}]} end
    valid_row = Base.url_encode64("row-bytes-abc", padding: false)

    load = fn base_obj, tamper_obj ->
      cases_map =
        synthetic_corpus() |> Map.put("cases/chain/e.json", jcs_case([base_obj, tamper_obj]))

      Corpus.load(full_corpus_map(cases_map, []))
    end

    no_target_tamper = fn id, base_id, input ->
      {:object,
       [
         {"id", {:string, id}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", input},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, base_id}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "no target member -> legacy path"}}
           ]}}
       ]}
    end

    # nil target + input.base64url (legacy base64url arm) -> audits and loads
    b64_input = fn s ->
      {:object, [{"base64url", {:string, Base.url_encode64(s, padding: false)}}]}
    end

    <<first, brest::binary>> = "xyz"

    assert {:ok, _} =
             load.(
               base.("b8", b64_input.("xyz")),
               no_target_tamper.("t8", "b8", b64_input.(<<Bitwise.bxor(first, 1)>> <> brest))
             )

    # nil target + neither text nor base64url (legacy fall-through) -> reject
    assert {:error, :invalid} =
             load.(
               base.("b9", {:object, [{"compact", {:string, "abc"}}]}),
               no_target_tamper.("t9", "b9", {:object, [{"compact", {:string, "abd"}}]})
             )

    # unknown target (the case-do catch-all)
    assert {:error, :invalid} =
             load.(
               base.("b1", rows.([valid_row])),
               tamper.("t1", "b1", rows.([valid_row]), "not-a-target")
             )

    # base case with no "input" (the second tamper_target_bytes clause)
    no_input_base =
      {:object,
       [
         {"id", {:string, "b2"}},
         {"surface", {:string, "check_chain"}},
         {"class", {:string, "valid"}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}

    assert {:error, :invalid} =
             load.(no_input_base, tamper.("t2", "b2", rows.([valid_row]), "rows[0]"))

    # rows[i] where the input member is not a list
    assert {:error, :invalid} =
             load.(
               base.("b3", {:object, [{"rows", {:string, "not-a-list"}}]}),
               tamper.("t3", "b3", {:object, [{"rows", {:string, "not-a-list"}}]}, "rows[0]")
             )

    # rows[] with an empty index (parse_index_suffix rejects seen=false)
    assert {:error, :invalid} =
             load.(
               base.("b4", rows.([valid_row])),
               tamper.("t4", "b4", rows.([valid_row]), "rows[]")
             )

    # rows[9] out of range (list_at walks off the end)
    assert {:error, :invalid} =
             load.(
               base.("b5", rows.([valid_row])),
               tamper.("t5", "b5", rows.([valid_row]), "rows[9]")
             )

    # rows[0] whose element is not valid base64url (b64_decode :error)
    assert {:error, :invalid} =
             load.(
               base.("b6", rows.(["!!!not-base64!!!"])),
               tamper.("t6", "b6", rows.(["!!!not-base64!!!"]), "rows[0]")
             )

    # nil target (no "target" member) falls to the legacy text path and audits correctly -> loads
    legacy_base =
      {:object,
       [
         {"id", {:string, "b7"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, "abc"}}]}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}

    legacy_tamper =
      {:object,
       [
         {"id", {:string, "t7"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"text", {:string, <<0x60, ?b, ?c>>}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "b7"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "no target member -> legacy text path"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/json/legacy.json", jcs_case([legacy_base, legacy_tamper]))

    assert {:ok, _} = Corpus.load(full_corpus_map(cases_map, []))
  end

  test "a tamper case with a present-but-dangling base_case is rejected (not loaded unaudited)" do
    # A present tamper block whose base_case does not resolve must FAIL the load — the case cannot
    # be proven a genuine single-byte flip, so it is corruption, not a case to wave through. This
    # matches the independent Node audit (which asserts the base is present) and closes the
    # divergence where the Elixir loader would otherwise load such a case unaudited.
    tamper_case =
      {:object,
       [
         {"id", {:string, "decode-grant-dangling-tamper"}},
         {"surface", {:string, "decode_grant"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"compact", {:string, "aaa.bbb.ccc"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "no-such-base-case"}},
             {"target", {:string, "compact"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "dangling base_case reference"}}
           ]}}
       ]}

    cases_map =
      synthetic_corpus()
      |> Map.put("cases/grant/dangling-tamper.json", jcs_case([tamper_case]))

    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  defp jcs_case(cases) do
    jcs(
      {:object,
       [
         {"format", {:string, "bounded-authority-protocol-v1-conformance-cases"}},
         {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}},
         {"cases", {:array, cases}}
       ]}
    )
  end

  # --- .raw hash binding (C2 sidecar) --------------------------------------

  test "a.raw sidecar whose hash disagrees with the index entry is rejected" do
    raw_bytes = :crypto.strong_rand_bytes(64)

    case_obj =
      {:object,
       [
         {"id", {:string, "json-decode-raw-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/payload.raw"}},
             {"sha256_base64url", {:string, sha256_b64(raw_bytes)}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/json/payload-case.json", jcs_case([case_obj]))
    # The .raw bytes are different from what the index declares.
    index = build_index(Map.put(cases_map, "cases/json/payload.raw", raw_bytes))

    tampered_index =
      put_in(index, ["files", Access.at(0), "sha256_base64url"], sha256_b64(<<"different">>))

    # Construct corpus where the .raw exists but index hash is wrong.
    corpus_with_raw = Map.put(cases_map, "cases/json/payload.raw", raw_bytes)
    bytes = jcs(to_object(tampered_index))
    map = Map.put(corpus_with_raw, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "a VALID.raw-bearing corpus loads and the runner feeds sidecar bytes to the facade" do
    # A .raw sidecar carrying raw JSON bytes 'false' — fed to json.decode (verdict: invalid because
    # 'false' alone is valid JSON, but we declare invalid to isolate the load+dispatch path; the
    # point of this test is that the corpus LOADS with a .raw file present and the runner reads it).
    raw_bytes = "{\"raw\":1}"

    case_obj =
      {:object,
       [
         {"id", {:string, "json-decode-raw-valid-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/payload.raw"}},
             {"sha256_base64url", {:string, sha256_b64(raw_bytes)}}
           ]}},
         {"expected",
          {:object,
           [
             {"verdict", {:string, "valid"}},
             {"value", {:object, [{"raw", {:integer, 1}}]}}
           ]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/json/payload-case.json", jcs_case([case_obj]))
    corpus_with_raw = Map.put(cases_map, "cases/json/payload.raw", raw_bytes)
    map = full_corpus_map(corpus_with_raw, [])

    # F1 regression: the corpus loads despite the .raw entry in index["files"].
    assert {:ok, corpus} = Corpus.load(map)

    # F2 regression: the runner reads the sidecar bytes and feeds them to json.decode.
    results = Runner.run(corpus)
    all_results = Enum.flat_map(results, &elem(&1, 1))
    raw_result = Enum.find(all_results, &(&1.case_id == "json-decode-raw-valid-001"))
    assert raw_result.agree == true
  end

  test "a bounds.new case with string-keyed overrides converts and agrees (regression)" do
    # tighten compact_bytes to its exact maximum = valid (Bounds.new accepts it).
    case_obj =
      {:object,
       [
         {"id", {:string, "bounds-new-valid-001"}},
         {"surface", {:string, "bounds.new"}},
         {"class", {:string, "exact_bound"}},
         {"bound_profile",
          {:object, [{"tightened", {:object, [{"compact_bytes", {:integer, 65_536}}]}}]}},
         {"input",
          {:object,
           [
             {"overrides", {:object, [{"compact_bytes", {:integer, 65_536}}]}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/bounds/new.json", jcs_case([case_obj]))
    map = full_corpus_map(cases_map, [])
    assert {:ok, corpus} = Corpus.load(map)

    results = Runner.run(corpus)
    all_results = Enum.flat_map(results, &elem(&1, 1))
    bounds_result = Enum.find(all_results, &(&1.case_id == "bounds-new-valid-001"))
    assert bounds_result.agree == true
  end

  test "a bounds.new case with an unknown override key fails (negative)" do
    case_obj =
      {:object,
       [
         {"id", {:string, "bounds-new-invalid-001"}},
         {"surface", {:string, "bounds.new"}},
         {"class", {:string, "invalid_limit"}},
         {"input",
          {:object,
           [
             {"overrides", {:object, [{"not_a_bounds_key", {:integer, 1}}]}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/bounds/invalid.json", jcs_case([case_obj]))
    map = full_corpus_map(cases_map, [])
    assert {:ok, corpus} = Corpus.load(map)

    results = Runner.run(corpus)
    all_results = Enum.flat_map(results, &elem(&1, 1))
    bounds_result = Enum.find(all_results, &(&1.case_id == "bounds-new-invalid-001"))
    assert bounds_result.agree == true
  end

  # --- runner agreement -----------------------------------------------------

  test "Runner runs a loaded corpus and Report builds an agreement result" do
    # Include a json.decode valid case whose decoded value is a STRING, so the Runner's value
    # projection exercises the string arm of its tagged->plain comparison.
    string_case =
      {:object,
       [
         {"id", {:string, "json-decode-valid-string"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, ~s("hi")}}]}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}, {"value", {:string, "hi"}}]}}
       ]}

    corpus_map = synthetic_corpus(extra_cases: [string_case]) |> full_corpus_map([])
    {:ok, corpus} = Corpus.load(corpus_map)
    results = Runner.run(corpus)
    report = Report.build(corpus, results)

    assert report.agreement == true
    assert is_integer(report.exit_status)
    assert report.exit_status == 0
  end

  test "a zero-case run is NOT agreement (exit 1) — the empty-corpus vacuous-green floor" do
    corpus_map = synthetic_corpus() |> full_corpus_map([])
    {:ok, corpus} = Corpus.load(corpus_map)
    # A structurally-valid corpus that executed zero cases verifies nothing: agreement requires
    # at least one executed case AND zero disagreements, so exit is 1, not 0.
    report = Report.build(corpus, [])

    assert report.total == 0
    assert report.agreement == false
    assert report.exit_status == 1
  end

  test "Report emits deterministic bytes for identical corpus input" do
    corpus_map = synthetic_corpus() |> full_corpus_map([])
    {:ok, corpus} = Corpus.load(corpus_map)
    results = Runner.run(corpus)

    {:ok, bytes_a} = Report.to_bytes(corpus, results)
    {:ok, bytes_b} = Report.to_bytes(corpus, results)
    assert bytes_a == bytes_b
  end

  test "a case whose verdict disagrees with expectation yields non-agreement and exit 1" do
    # json.decode valid case expecting a value that won't match.
    wrong_case =
      {:object,
       [
         {"id", {:string, "json-decode-disagree-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, "{\"a\":1}"}}]}},
         {"expected",
          {:object,
           [
             {"verdict", {:string, "valid"}},
             {"value", {:object, [{"a", {:integer, 2}}]}}
           ]}}
       ]}

    cases_map = synthetic_corpus(extra_cases: [wrong_case])
    # Need to drop the existing json.decode valid case to avoid a duplicate-surface issue;
    # rebuild the trivial file with only the disagreeing case.
    cases_map = Map.put(cases_map, "cases/json/trivial.json", jcs_case([wrong_case]))
    corpus_map = full_corpus_map(cases_map, [])
    {:ok, corpus} = Corpus.load(corpus_map)
    results = Runner.run(corpus)
    report = Report.build(corpus, results)

    assert report.agreement == false
    assert report.exit_status == 1
  end

  # --- shipped corpus: official-side agreement gate (Task 2 deliverable) ---

  @shipped_corpus "priv/conformance/v1/corpus"

  test "the shipped corpus loads and the official side agrees on every case (exit 0)" do
    map = shipped_corpus_map()
    assert {:ok, corpus} = Corpus.load(map)
    results = Runner.run(corpus)
    report = Report.build(corpus, results)
    assert report.agreement == true
    assert report.exit_status == 0
    assert report.disagreed == 0
    assert report.total > 0
  end

  test "the shipped corpus report is deterministic JCS bytes binding the index SHA-256" do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)
    results = Runner.run(corpus)
    {:ok, bytes_a} = Report.to_bytes(corpus, results)
    {:ok, bytes_b} = Report.to_bytes(corpus, results)
    assert bytes_a == bytes_b
    # The report carries the index SHA-256.
    assert is_binary(corpus.index_bytes)

    expected_identity =
      Base.url_encode64(:crypto.hash(:sha256, corpus.index_bytes), padding: false)

    assert bytes_a =~ expected_identity
  end

  test "every shipped corpus JSON file is normative-decoder-loadable and under the byte ceiling" do
    for path <- Path.wildcard(Path.join(@shipped_corpus, "**/*.json")) do
      bytes = File.read!(path)
      assert byte_size(bytes) <= 65_536, "#{path}: over the 65,536-byte ceiling"
      assert {:ok, _} = Json.decode(bytes, Bounds.maximum())
    end
  end

  # --- corpus-expansion pins (V5 subsumption, Q29 n_a reasons, Q31 bounds pinning) ---

  # The total is pinned so a dropped class cannot retreat into code silently (V1/V2): removing
  # any case changes the total and this pin goes red.
  test "the shipped corpus total_cases is pinned at the expanded count" do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)
    assert corpus.index["total_cases"] == 283
    assert MapSet.size(corpus.case_ids) == 283
  end

  test "the crypto verifying surfaces carry the mandated invalid classes (vacuity closed)" do
    # BAP-05 hardening: the review found the corpus was vacuous on the security-critical surfaces
    # (zero algorithm-confusion cases, no meaningful-byte tampers on signed surfaces,
    # verify_anchored_export with zero invalid cases). This pin asserts those cells are now
    # populated so a regression that empties them turns red.
    {:ok, corpus} = Corpus.load(shipped_corpus_map())
    app = corpus.index["applicability"]

    required? = fn surface, class ->
      leaf = app[surface][class]
      is_integer(leaf) and leaf >= 1
    end

    # algorithm confusion (alg:"none") on every surface that decodes/verifies a compact header
    for surface <- [
          "verify_grant",
          "decode_grant",
          "decode_proof",
          "check_envelope",
          "verify_historical_anchor",
          "verify_key_transition"
        ] do
      assert required?.(surface, "invalid_algorithm"),
             "#{surface}/invalid_algorithm must be populated (alg:none vector)"
    end

    # meaningful-byte signature/commitment/anchor tamper on every signed verifying surface
    for surface <- [
          "verify_grant",
          "check_envelope",
          "verify_historical_anchor",
          "verify_key_transition",
          "verify_anchored_export",
          "check_chain"
        ] do
      assert required?.(surface, "tamper_meaningful_byte"),
             "#{surface}/tamper_meaningful_byte must be populated"
    end

    # verify_anchored_export previously had ZERO invalid cases
    assert required?.("verify_anchored_export", "invalid_claim")
    assert required?.("verify_anchored_export", "invalid_encoding")
    assert required?.("verify_anchored_export", "invalid_key")

    # check_envelope request/time/nonce bindings (the profile requires them; the runner now checks)
    for class <- ["invalid_request", "invalid_time", "invalid_nonce"] do
      assert required?.("check_envelope", class),
             "check_envelope/#{class} must be populated"
    end

    # invalid_selector is now POPULATED (BAP-05 selector remediation): the former escalation
    # candidate was closed by re-signing a non-trivial-selector grant + a selector-rejecting proof,
    # so the cell carries a real count, not an n_a label.
    assert required?.("check_envelope", "invalid_selector")

    # invalid_claim is now POPULATED (BAP-05 selector closeout). Its n_a reason had ended in
    # "re-signing, out of scope" — the same constraint the selector remediation lifted — while the
    # holder (cnf.jkt), grant (ath), and request-argument (ba_req) bindings it covers had no case
    # isolating them: neutralizing any one of the three left the whole corpus green. The cell now
    # carries three one-defect cases, one per binding, each proven red by its own mutation entry.
    assert required?.("check_envelope", "invalid_claim")
  end

  test "every n_a applicability leaf carries a falsifiable reason (obligation)" do
    # The n_a half of the matrix is derived, not authored: a cell may be n_a ONLY when the
    # surface's input algebra cannot express the class. Each n_a leaf carries a one-line
    # reason so flipping a required cell to n_a requires writing a falsifiable impossibility
    # claim. This pin asserts the shape + that reasons are present (non-empty strings).
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    n_a? = fn
      "n_a" -> true
      %{"n_a" => reason} when is_binary(reason) -> true
      _ -> false
    end

    n_a_cells =
      for {surface, leaves} <- corpus.index["applicability"],
          {class, leaf} <- leaves,
          n_a?.(leaf),
          reduce: [] do
        acc -> [{surface, class, leaf} | acc]
      end

    assert n_a_cells != [], "the corpus must carry n_a cells (else the matrix is vacuous)"

    for {surface, class, leaf} <- n_a_cells do
      %{"n_a" => reason} = leaf

      assert is_binary(reason) and byte_size(reason) > 0,
             "#{surface}/#{class}: n_a leaf must be {\"n_a\": <non-empty reason>}, got #{inspect(leaf)}"
    end
  end

  test "the n_a leaf object shape is schema-valid and the loader treats it as not-applicable" do
    # The index schema accepts {"n_a": "<reason>"} as a leaf (in addition to integer / bare "n_a"),
    # and Corpus.load treats it identically to the bare "n_a" string (zero executed cases).
    {:ok, meta} = Draft202012Schemas.fetch("https://json-schema.org/draft/2020-12/schema")
    {:ok, compiled_meta} = JSONSchex.compile(meta)
    schema = File.read!("priv/conformance/v1/schemas/corpus-index.schema.json") |> :json.decode()
    {:ok, compiled} = JSONSchex.compile(schema)
    assert :ok = JSONSchex.validate(compiled_meta, schema)

    valid = minimal_valid_index_map()
    # Rewrite one n_a leaf to the object form; the schema must still accept it.
    valid =
      put_in(valid, ["applicability", "json.decode", "invalid_algorithm"], %{"n_a" => "no field"})

    assert :ok = JSONSchex.validate(compiled, valid)

    # The loader treats the object n_a form as not-applicable (the synthetic corpus has zero
    # json.decode/invalid_algorithm cases, so this cell must load).
    cases_map = %{"cases/json/trivial.json" => trivial_case_bytes()}
    applicability = applicability_from_cases(cases_map)

    applicability =
      put_in(applicability, ["json.decode", "invalid_algorithm"], %{"n_a" => "no field"})

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:ok, _corpus} = Corpus.load(map)
  end

  test "the n_a reason object shape with a missing reason is rejected by the loader" do
    # A malformed n_a object (e.g. empty or wrong key) is NOT a valid not-applicable marker —
    # it falls through leaf_matches? to the catch-all -> {:error, :invalid}. This keeps the
    # reason obligation machine-enforced: only the exact {"n_a": <string>} shape is honored.
    cases_map = %{"cases/json/trivial.json" => trivial_case_bytes()}
    applicability = applicability_from_cases(cases_map)

    applicability =
      put_in(applicability, ["json.decode", "invalid_algorithm"], %{"reason" => "nope"})

    index = build_index(cases_map, applicability: applicability)
    bytes = jcs(to_object(index))
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  # Legacy-depth subsumption (V5): the 18 legacy URI byte-values from
  # conformance/grant_proof_independent.mjs:22-41 appear as corpus data. The 6 VALID (idempotent)
  # + 5 normalizable-but-non-idempotent appear as valid uri.normalize cases; the 6 rejected
  # by both implementations appear as invalid_uri. https://[:::]/ is implementation-divergent
  # (Elixir rejects, Node accepts) and is omitted — recorded in ADR 0005. 17 of 18 ported.
  test "the corpus subsumes the 17 port-able legacy URI byte-values " do
    legacy_inputs = [
      "https://example.com/",
      "https://example.com/a/~",
      "https://example.com:8443/a%2Fb",
      "https://[2001:db8::1]/",
      "https://[v1.a:b]/",
      "https://192.0.2.1/",
      "https://example.com:0443/",
      "https://EXAMPLE.com/",
      "https://example.com:443/",
      "https://example.com/%7e",
      "https://example.com/a/../b",
      "https://example.com/?q=1",
      "https://example.com:/",
      "https://[v.a]/",
      "https://01.2.3.4/",
      "https://256.2.3.4/",
      "http://example.com/"
    ]

    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    uri_inputs =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.filter(&(&1["surface"] == "uri.normalize"))
      |> Enum.map(& &1["input"]["text"])
      |> MapSet.new()

    for legacy <- legacy_inputs do
      assert MapSet.member?(uri_inputs, legacy),
             "legacy URI #{inspect(legacy)} not subsumed as corpus data"
    end
  end

  test "the corpus subsumes the legacy duplicate-member case " do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    dup_inputs =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.filter(&(&1["surface"] == "json.decode" and &1["class"] == "invalid_duplicate"))
      |> Enum.map(& &1["input"]["text"])
      |> MapSet.new()

    # The legacy grant_proof duplicate-member target was a JWS header with a duplicated "alg" member.
    assert MapSet.member?(dup_inputs, "{\"alg\":\"EdDSA\",\"alg\":\"none\"}")
  end

  # bounds.new constant-pinning (Q31): every maxima-table key has a tighten-to-exact-max (valid)
  # pin; every key EXCEPT integer_magnitude/float_magnitude has a tighten-to-max-plus-one (invalid)
  # pin. The two-key exception is mechanically forced (the max+1 literal exceeds the decoder's own
  # magnitude ceiling and cannot appear in a corpus JSON file) — recorded in ADR 0005.
  test "bounds.new pins every maxima key (exact_bound + maximum_plus_one), modulo the two-key exception" do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    bounds_cases =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.filter(&(&1["surface"] == "bounds.new"))

    # Every key of Bounds.maximum/0 carries an exact_bound (valid) pin.
    for key <- Map.from_struct(Bounds.maximum()) |> Map.keys() do
      key_str = Atom.to_string(key)

      assert Enum.any?(
               bounds_cases,
               &(&1["class"] == "exact_bound" and &1["bound_profile"]["tightened"][key_str])
             ),
             "missing exact_bound pin for #{key_str}"
    end

    # Every TIGHTENABLE key carries a maximum_plus_one (invalid) pin. Excluded:
    # - integer_magnitude/float_magnitude: the max+1 literal exceeds the decoder magnitude ceiling.
    # - digest_bytes/public_key_bytes/signature_bytes: fixed-width keys. A fixed-width key cannot be
    #   tightened OR widened, so a max+1 value is a fixed-width CHANGE (invalid_limit), not a
    #   tightening-contract violation (maximum_plus_one) — those are pinned as invalid_limit-*-above.
    no_max_plus_one = [
      :integer_magnitude,
      :float_magnitude,
      :digest_bytes,
      :public_key_bytes,
      :signature_bytes
    ]

    for key <- Map.from_struct(Bounds.maximum()) |> Map.keys(),
        key not in no_max_plus_one do
      key_str = Atom.to_string(key)

      assert Enum.any?(
               bounds_cases,
               &(&1["class"] == "maximum_plus_one" and &1["bound_profile"]["tightened"][key_str])
             ),
             "missing maximum_plus_one pin for #{key_str}"
    end

    # The excepted keys carry NO maximum_plus_one pin (magnitude: exceeds the decoder ceiling;
    # fixed-width: a max+1 is a fixed-width-change invalid_limit case, not a maximum_plus_one).
    for key <- no_max_plus_one do
      key_str = Atom.to_string(key)

      refute Enum.any?(
               bounds_cases,
               &(&1["class"] == "maximum_plus_one" and &1["bound_profile"]["tightened"][key_str])
             ),
             "#{key_str} must NOT carry a maximum_plus_one pin"
    end

    # The magnitude ceiling itself is still portably pinned via the json.decode maximum_plus_one
    # .raw sidecar (9007199254740992 raw JSON bytes -> invalid).
    assert Enum.any?(
             corpus.cases |> Enum.flat_map(&elem(&1, 1)),
             &(&1["surface"] == "json.decode" and &1["class"] == "maximum_plus_one")
           )
  end

  test "bounds.new fixed-width keys carry change-rejection (invalid_limit) cases" do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    bounds_cases =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.filter(&(&1["surface"] == "bounds.new" and &1["class"] == "invalid_limit"))

    for key <- [:digest_bytes, :public_key_bytes, :signature_bytes] do
      key_str = Atom.to_string(key)

      assert Enum.any?(bounds_cases, &(&1["input"]["overrides"][key_str] != nil)),
             "missing fixed-width invalid_limit pin for #{key_str}"
    end
  end

  # tamper_meaningful_byte (Q25): the class is exercised on the byte-bearing surfaces whose
  # dispatch input IS input.text (JSON/text). The byte-bearing compact/segment/structured-input
  # surfaces are n_a (the tamper loader reads input.text/base64url, which they do not expose).
  test "tamper_meaningful_byte is exercised on text-input surfaces and n_a elsewhere" do
    map = shipped_corpus_map()
    {:ok, corpus} = Corpus.load(map)

    tamper_surfaces =
      corpus.cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.filter(&(&1["class"] == "tamper_meaningful_byte"))
      |> Enum.map(& &1["surface"])
      |> MapSet.new()

    # The genuinely byte-bearing text-input surfaces carry tampers.
    for surface <- [
          "json.decode",
          "jcs.encode",
          "uri.normalize",
          "jwk.decode_public",
          "jwk.thumbprint_preimage",
          "jwk.thumbprint",
          "jwk.thumbprint_raw"
        ] do
      assert MapSet.member?(tamper_surfaces, surface),
             "missing tamper_meaningful_byte case for #{surface}"
    end

    # base64url.decode is n_a (canonical segment closed under single-byte flip).
    refute MapSet.member?(tamper_surfaces, "base64url.decode")
  end

  defp shipped_corpus_map do
    Path.wildcard(Path.join(@shipped_corpus, "**/*"))
    |> Enum.filter(&File.regular?/1)
    |> Enum.map(fn path ->
      {Path.relative_to(path, @shipped_corpus), File.read!(path)}
    end)
    |> Map.new()
  end

  # --- private-material sweep (closes census window until Task 4) ----------

  test "no corpus JSON file under the current conformance corpus carries a private key or seed" do
    corpus_dir = "priv/conformance/v1/corpus"

    if File.dir?(corpus_dir) do
      Path.wildcard(Path.join(corpus_dir, "**/*.json"))
      |> Enum.each(fn path ->
        bytes = File.read!(path)

        keys = collect_keys(decode!(bytes))

        refute "d" in keys, "#{path}: forbidden private key field 'd'"

        refute Enum.any?(keys, &String.contains?(&1, "private_key")),
               "#{path}: forbidden private_key field"

        refute Enum.any?(keys, &String.contains?(&1, "seed")),
               "#{path}: forbidden seed field"
      end)
    end
  end

  # --- coverage: Corpus loader defensive/error arms ---

  test "load_raw_entry halts when an indexed.raw file is absent from the map " do
    # An index that declares a .raw file, but the corpus map does not carry that path, trips
    # load_raw_entry's `{:halt, {:error, :invalid}}` arm during the files reduce.
    raw_bytes = :crypto.strong_rand_bytes(64)

    case_obj =
      {:object,
       [
         {"id", {:string, "raw-absent-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/absent.raw"}},
             {"sha256_base64url", {:string, sha256_b64(raw_bytes)}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    cases_map = Map.put(synthetic_corpus(), "cases/json/absent-case.json", jcs_case([case_obj]))
    # Index references the .raw, but the map omits it.
    index = build_index(Map.put(cases_map, "cases/json/absent.raw", raw_bytes))
    bytes = jcs(to_object(index))
    # NOTE: deliberately do NOT add absent.raw to the map.
    map = Map.put(cases_map, "index.json", bytes)
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "count_surface_class skips a case with non-binary surface/class " do
    # A case whose surface/class are not binaries is skipped by count_surface_class (else -> acc),
    # so it does NOT increment the observed applicability. The declared applicability therefore
    # matches the valid synthetic cases only (the malformed one is invisible to the census). This
    # proves the skip: if it were counted, the observed surface would be an unknown integer key and
    # the surface-set check would reject the corpus.
    malformed_case =
      {:object,
       [
         {"id", {:string, "bad-surface-001"}},
         {"surface", {:integer, 1}},
         {"class", {:integer, 2}},
         {"input", {:object, [{"text", {:string, "1"}}]}},
         {"expected", {:object, [{"verdict", {:string, "valid"}}]}}
       ]}

    cases_map =
      Map.put(synthetic_corpus(), "cases/json/bad-surface.json", jcs_case([malformed_case]))

    # Declared applicability = the valid synthetic cases only (malformed case is skipped, so it
    # contributes nothing to the observed census).
    declared = applicability_from_cases(synthetic_corpus())
    map = full_corpus_map(cases_map, applicability: declared)
    assert {:ok, _corpus} = Corpus.load(map)
  end

  test "tamper_source_bytes:error arm via a base case with malformed base64url" do
    # tamper_source_bytes decodes the BASE case's input; a malformed base64url in the base hits
    # `:error -> :error` (L389). The tamper case references this base, so verify_tampers runs
    # tamper_source_bytes(base) -> :error -> the with short-circuits -> load fails closed.
    base_bad_b64 =
      {:object,
       [
         {"id", {:string, "tamper-source-bad-base"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"base64url", {:string, "!!!not-base64!!!"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    tamper_ref =
      {:object,
       [
         {"id", {:string, "tamper-source-bad"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"text", {:string, "x"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "tamper-source-bad-base"}},
             {"target", {:string, "input.text"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first byte"}}
           ]}}
       ]}

    cases_map =
      Map.merge(synthetic_corpus(), %{
        "cases/json/tamper-source-bad.json" => jcs_case([base_bad_b64, tamper_ref])
      })

    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "tamper_derived_bytes:error and true arms via a tamper case with no byte key" do
    # A tamper case whose input has neither text nor base64url hits the `true -> :error` arm of
    # tamper_derived_bytes; the base64url `:error -> :error` arm is hit by a malformed b64 input.
    # Both are reached during corpus load's verify_raw_bindings/tamper derivation pass.
    tamper_no_key =
      {:object,
       [
         {"id", {:string, "tamper-no-key-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"other", {:string, "x"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "tamper-no-key-001"}},
             {"target", {:string, "input.text"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first byte"}}
           ]}}
       ]}

    cases_map =
      Map.put(synthetic_corpus(), "cases/json/tamper-no-key.json", jcs_case([tamper_no_key]))

    map = full_corpus_map(cases_map, [])
    # A tamper case whose derived bytes cannot be computed fails corpus load (fail-closed).
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "tamper_verbatim_bytes:error and true arms via a tamper case whose verbatim input is malformed" do
    # tamper_verbatim_matches? runs tamper_source_bytes(base) THEN tamper_verbatim_bytes(case).
    # The verbatim :error/true arms (L405/L408) are only reached when the BASE has valid bytes
    # (so source succeeds) but the tamper CASE's own input is malformed. Build a valid base case
    # plus a tamper case whose input has a malformed base64url (-> :error) and a no-key variant.
    base_case =
      {:object,
       [
         {"id", {:string, "tamper-verbatim-base"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, "{\"a\":1}"}}]}},
         {"expected",
          {:object,
           [{"verdict", {:string, "valid"}}, {"value", {:object, [{"a", {:integer, 1}}]}}]}}
       ]}

    tamper_bad_b64 =
      {:object,
       [
         {"id", {:string, "tamper-verbatim-bad-b64"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"base64url", {:string, "!!!not-base64!!!"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "tamper-verbatim-base"}},
             {"target", {:string, "input.text"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first byte"}}
           ]}}
       ]}

    cases_map =
      Map.merge(synthetic_corpus(), %{
        "cases/json/tamper-verbatim.json" => jcs_case([base_case, tamper_bad_b64])
      })

    map = full_corpus_map(cases_map, [])
    # base source bytes succeed; verbatim bytes fail to decode -> mismatch -> load fails closed.
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "tamper_verbatim_bytes true arm via a tamper case whose verbatim input has no byte key" do
    # The `true -> :error` arm fires when the tamper case input has neither text nor base64url.
    base_case =
      {:object,
       [
         {"id", {:string, "tamper-verbatim-nokey-base"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input", {:object, [{"text", {:string, "{\"a\":1}"}}]}},
         {"expected",
          {:object,
           [{"verdict", {:string, "valid"}}, {"value", {:object, [{"a", {:integer, 1}}]}}]}}
       ]}

    tamper_no_key =
      {:object,
       [
         {"id", {:string, "tamper-verbatim-nokey"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "tamper_meaningful_byte"}},
         {"input", {:object, [{"other", {:string, "x"}}]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}},
         {"tamper",
          {:object,
           [
             {"base_case", {:string, "tamper-verbatim-nokey-base"}},
             {"target", {:string, "input.text"}},
             {"byte_index", {:integer, 0}},
             {"xor", {:integer, 1}},
             {"meaning", {:string, "first byte"}}
           ]}}
       ]}

    cases_map =
      Map.merge(synthetic_corpus(), %{
        "cases/json/tamper-verbatim-nokey.json" => jcs_case([base_case, tamper_no_key])
      })

    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "check_raw_binding error passthrough when a prior raw binding already errored" do
    # verify_raw_bindings reduces cases; if the first raw-bearing case's binding errors, the
    # accumulator carries the error and check_raw_binding/3's `error -> error` arm fires for
    # subsequent cases. Build two raw-bearing cases: the first with a wrong hash, the second valid.
    raw_bytes = :crypto.strong_rand_bytes(64)
    other_raw = :crypto.strong_rand_bytes(64)

    first_case =
      {:object,
       [
         {"id", {:string, "raw-passthrough-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/a.raw"}},
             # WRONG hash for a.raw -> verify_raw_entry errors -> accumulator becomes {:error,_}
             {"sha256_base64url", {:string, sha256_b64(<<"wrong">>)}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    second_case =
      {:object,
       [
         {"id", {:string, "raw-passthrough-002"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/b.raw"}},
             {"sha256_base64url", {:string, sha256_b64(other_raw)}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    base =
      Map.merge(synthetic_corpus(), %{
        "cases/json/passthrough-cases.json" => jcs_case([first_case, second_case]),
        "cases/json/a.raw" => raw_bytes,
        "cases/json/b.raw" => other_raw
      })

    map = full_corpus_map(base, [])
    # The first case's hash mismatches -> binding errors; the reduce short-circuits the
    # accumulator, exercising check_raw_binding/3's error passthrough.
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "verify_raw_entry missing-path arm when a raw_file is not in the loaded raws" do
    # A case references a raw_file whose path was never registered in raws (e.g., a .raw that
    # the index did not declare, or a typo). verify_raw_entry's `_ -> {:error, :invalid}` fires.
    case_obj =
      {:object,
       [
         {"id", {:string, "raw-missing-path-001"}},
         {"surface", {:string, "json.decode"}},
         {"class", {:string, "valid"}},
         {"input",
          {:object,
           [
             {"raw_file", {:string, "cases/json/never-registered.raw"}},
             {"sha256_base64url", {:string, sha256_b64(:crypto.strong_rand_bytes(64))}}
           ]}},
         {"expected", {:object, [{"verdict", {:string, "invalid"}}]}}
       ]}

    cases_map =
      Map.put(synthetic_corpus(), "cases/json/missing-raw-case.json", jcs_case([case_obj]))

    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  test "member/2 nil arm via a case file object missing the queried key" do
    # member/2 returns nil when List.keyfind finds nothing (key absent from the object). The
    # case-file decoder calls member(members, "format") and member(members, "cases"); a case
    # file whose decoded object lacks the "cases" key reaches member's `nil -> nil` arm and the
    # subsequent pattern match fails -> file load errors -> corpus load fails closed.
    malformed_file =
      jcs({:object,
       [
         {"format", {:string, "bounded-authority-protocol-v1-conformance-cases"}},
         {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}}
         # NOTE: "cases" key intentionally absent -> member(members, "cases") -> nil -> L459
       ]})

    cases_map = Map.put(synthetic_corpus(), "cases/json/no-cases-key.json", malformed_file)
    # The index declares this file with case_count 0; the file lacks "cases", so member hits nil.
    map = full_corpus_map(cases_map, [])
    assert {:error, :invalid} = Corpus.load(map)
  end

  defp collect_keys(value, acc \\ []) do
    case value do
      {:object, members} ->
        Enum.reduce(members, acc, fn {k, v}, a -> collect_keys(v, [k | a]) end)

      {:array, items} ->
        Enum.reduce(items, acc, &collect_keys(&1, &2))

      _ ->
        acc
    end
  end
end
