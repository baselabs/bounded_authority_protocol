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

  test "a .raw sidecar whose hash disagrees with the index entry is rejected" do
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

  test "a VALID .raw-bearing corpus loads and the runner feeds sidecar bytes to the facade" do
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

  test "a bounds.new case with string-keyed overrides converts and agrees (F3 regression)" do
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

  test "a bounds.new case with an unknown override key fails (F3 negative)" do
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
    corpus_map = synthetic_corpus() |> full_corpus_map([])
    {:ok, corpus} = Corpus.load(corpus_map)
    results = Runner.run(corpus)
    report = Report.build(corpus, results)

    assert report.agreement == true
    assert is_integer(report.exit_status)
    assert report.exit_status == 0
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

  # --- private-material sweep (closes census window until Task 4) ----------

  test "no corpus JSON file under priv/conformance/v1/corpus carries a private key or seed" do
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
