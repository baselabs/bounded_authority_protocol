defmodule BoundedAuthorityProtocol.Conformance.RunnerErrorPathsTest do
  @moduledoc """
  Exercises the Runner dispatch error branches (malformed inputs -> {:error, :invalid}) and
  the Corpus integrity-check error branches that the happy-path corpus + synthetic tests do
  not reach. These close the 100% coverage gap on the conformance modules.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json

  defp sha256_b64(bytes), do: Base.url_encode64(:crypto.hash(:sha256, bytes), padding: false)

  defp jcs(value), do: Jcs.encode(value, %{}) |> elem(1)

  # --- Corpus integrity error branches (the with-chain else clauses) ---

  test "non-binary index is rejected" do
    assert {:error, :invalid} = Corpus.load(%{})
  end

  test "index with wrong format is rejected" do
    bad =
      jcs(
        {:object,
         [
           {"format", {:string, "wrong"}},
           {"public_key_fingerprints", {:array, []}},
           {"files", {:array, []}},
           {"total_cases", {:integer, 0}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"index.json" => bad})
  end

  test "index file entry missing required field is rejected" do
    bad_entry =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-corpus-index"}},
           {"public_key_fingerprints", {:array, []}},
           {"files", {:array, [{:object, [{"path", {:string, "x"}}]}]}},
           {"total_cases", {:integer, 0}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"index.json" => bad_entry})
  end

  test "case file with wrong format is rejected" do
    case_bytes =
      jcs(
        {:object,
         [
           {"format", {:string, "wrong"}},
           {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}},
           {"cases", {:array, []}}
         ]}
      )

    idx =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-corpus-index"}},
           {"public_key_fingerprints", {:array, []}},
           {"files",
            {:array,
             [
               {:object,
                [
                  {"path", {:string, "c.json"}},
                  {"sha256_base64url", {:string, sha256_b64(case_bytes)}},
                  {"cases", {:integer, 0}}
                ]}
             ]}},
           {"total_cases", {:integer, 0}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"c.json" => case_bytes, "index.json" => idx})
  end

  test "a .json file with a .raw extension in the index is rejected" do
    idx =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-corpus-index"}},
           {"public_key_fingerprints", {:array, []}},
           {"files",
            {:array,
             [
               {:object,
                [
                  {"path", {:string, "cases/x.txt"}},
                  {"sha256_base64url", {:string, "AA"}},
                  {"cases", {:integer, 0}}
                ]}
             ]}},
           {"total_cases", {:integer, 0}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"index.json" => idx})
  end

  test "applicability with a bad leaf type is rejected" do
    case_bytes =
      "{\"format\":\"bounded-authority-protocol-v1-conformance-cases\",\"provenance\":{\"private_material_tracked\":false},\"cases\":[]}"

    idx_map = %{
      "format" => "bounded-authority-protocol-v1-conformance-corpus-index",
      "public_key_fingerprints" => [],
      "files" => [
        %{"path" => "c.json", "sha256_base64url" => sha256_b64(case_bytes), "cases" => 0}
      ],
      "total_cases" => 0,
      "applicability" => bad_applicability_with_wrong_leaf()
    }

    idx = jcs(to_obj(idx_map))
    assert {:error, :invalid} = Corpus.load(%{"c.json" => case_bytes, "index.json" => idx})
  end

  defp bad_applicability_with_wrong_leaf do
    surfaces = corpus_surfaces()
    classes = corpus_classes()

    Map.new(surfaces, fn s ->
      {s, Map.new(classes, fn c -> {c, if(c == "valid", do: "bad_value", else: "n_a")} end)}
    end)
  end

  defp to_obj(map) do
    {:object, map |> Enum.map(fn {k, v} -> {k, to_val(v)} end) |> Enum.sort_by(&elem(&1, 0))}
  end

  defp to_val(v) when is_map(v), do: to_obj(v)
  defp to_val(v) when is_list(v), do: {:array, Enum.map(v, &to_val/1)}
  defp to_val(v) when is_integer(v), do: {:integer, v}
  defp to_val(v) when is_float(v), do: {:float, v}
  defp to_val(v) when is_boolean(v), do: {:boolean, v}
  defp to_val(v) when is_binary(v), do: {:string, v}
  defp to_val(nil), do: :null

  defp full_corpus_map(cases_map) do
    index = build_index(cases_map)
    Map.put(cases_map, "index.json", jcs(to_obj(index)))
  end

  defp build_index(cases_map) do
    surfaces = corpus_surfaces()
    classes = corpus_classes()

    counts =
      Enum.reduce(
        cases_map,
        Map.new(surfaces, fn s -> {s, Map.new(classes, &{&1, 0})} end),
        fn {_path, bytes}, acc ->
          Enum.reduce(extract_surface_classes(bytes), acc, fn {s, c}, a ->
            put_in(a, [s, c], get_in(a, [s, c]) + 1)
          end)
        end
      )

    appl =
      Map.new(counts, fn {s, leaves} ->
        {s, Map.new(leaves, fn {c, n} -> {c, if(n > 0, do: n, else: "n_a")} end)}
      end)

    total = cases_map |> Map.values() |> Enum.map(&case_count/1) |> Enum.sum()

    %{
      "format" => "bounded-authority-protocol-v1-conformance-corpus-index",
      "public_key_fingerprints" => [],
      "files" =>
        Enum.map(cases_map, fn {path, bytes} ->
          %{"path" => path, "sha256_base64url" => sha256_b64(bytes), "cases" => case_count(bytes)}
        end),
      "total_cases" => total,
      "applicability" => appl
    }
  end

  defp case_count(bytes) do
    {:ok, {:object, members}} = Json.decode(bytes, Bounds.maximum())
    {"cases", {:array, items}} = List.keyfind(members, "cases", 0)
    length(items)
  end

  defp extract_surface_classes(bytes) do
    {:ok, {:object, members}} = Json.decode(bytes, Bounds.maximum())
    {"cases", {:array, items}} = List.keyfind(members, "cases", 0)

    Enum.map(items, fn {:object, cm} ->
      {"surface", {:string, s}} = List.keyfind(cm, "surface", 0)
      {"class", {:string, c}} = List.keyfind(cm, "class", 0)
      {s, c}
    end)
  end

  defp corpus_surfaces,
    do:
      ~w(untrusted_key_locator grant_signing_input proof_signing_input encode_consumption_entry check_chain boundary_anchor_signing_input key_transition_signing_input encode_anchored_export assemble_compact decode_grant decode_proof verify_grant verify_historical_anchor verify_key_transition verify_anchored_export check_envelope request_digest jcs.encode jwk.encode_public jwk.decode_public jwk.thumbprint_preimage jwk.thumbprint jwk.thumbprint_raw jwk.public_key_thumbprint_raw uri.normalize json.decode base64url.decode bounds.new)

  # --- Runner agreement mismatch branches (agrees? valid-vs-error, invalid-vs-ok) ---

  alias BoundedAuthorityProtocol.Conformance.Runner

  defp run_one(case_obj) do
    cases_map = %{"c.json" => case_file_bytes([case_obj])}
    map = full_corpus_map(cases_map)
    {:ok, corpus} = Corpus.load(map)
    results = Runner.run(corpus)
    {_path, [result]} = hd(results)
    result
  end

  defp case_file_bytes(cases) do
    jcs(
      {:object,
       [
         {"format", {:string, "bounded-authority-protocol-v1-conformance-cases"}},
         {"provenance", {:object, [{"private_material_tracked", {:boolean, false}}]}},
         {"cases", {:array, cases}}
       ]}
    )
  end

  defp case_obj(id, surface, class, input, expected) do
    {:object,
     [
       {"id", {:string, id}},
       {"surface", {:string, surface}},
       {"class", {:string, class}},
       {"input", to_obj(input)},
       {"expected", to_obj(expected)}
     ]}
  end

  test "agrees? valid-verdict-where-dispatch-errors returns disagree" do
    # A json.decode case with malformed input but verdict:valid — dispatch errors, agrees? valid-vs-error.
    result =
      run_one(
        case_obj("mismatch-valid-where-error", "json.decode", "valid", %{"text" => "{bad}"}, %{
          "verdict" => "valid",
          "value" => %{}
        })
      )

    assert result.agree == false
  end

  test "agrees? invalid-verdict-where-dispatch-succeeds returns disagree" do
    # A json.decode case with valid input but verdict:invalid — dispatch succeeds, agrees? invalid-vs-ok.
    result =
      run_one(
        case_obj(
          "mismatch-invalid-where-ok",
          "json.decode",
          "invalid_encoding",
          %{"text" => "{\"a\":1}"},
          %{"verdict" => "invalid"}
        )
      )

    assert result.agree == false
  end

  test "agrees? valid-verdict-with-field-mismatch returns disagree" do
    # valid input, valid verdict, but wrong expected value — matches_expected? fails.
    result =
      run_one(
        case_obj("mismatch-field-value", "json.decode", "valid", %{"text" => "{\"a\":1}"}, %{
          "verdict" => "valid",
          "value" => %{"a" => 2}
        })
      )

    assert result.agree == false
  end

  # --- Corpus non-map guard + structure branches ---

  test "Corpus.load with a non-map argument is rejected" do
    assert {:error, :invalid} = Corpus.load("not a map")
    assert {:error, :invalid} = Corpus.load(nil)
  end

  test "Corpus.load rejects an index whose files value is not a list" do
    bad =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-corpus-index"}},
           {"public_key_fingerprints", {:array, []}},
           {"files", {:string, "not-a-list"}},
           {"total_cases", {:integer, 0}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"index.json" => bad})
  end

  test "Corpus.load rejects an index whose total_cases is not an integer" do
    bad =
      jcs(
        {:object,
         [
           {"format", {:string, "bounded-authority-protocol-v1-conformance-corpus-index"}},
           {"public_key_fingerprints", {:array, []}},
           {"files", {:array, []}},
           {"total_cases", {:string, "x"}},
           {"applicability", {:object, []}}
         ]}
      )

    assert {:error, :invalid} = Corpus.load(%{"index.json" => bad})
  end

  test "Runner builder error branches surface as dispatch-error disagreement" do
    # A grant_signing_input case missing required fields — builder fails, dispatch errors.
    result =
      run_one(
        case_obj(
          "builder-error-missing-fields",
          "grant_signing_input",
          "valid",
          %{"key_id" => "k"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "assemble_compact with an unknown kind is a dispatch error" do
    result =
      run_one(
        case_obj(
          "assemble-unknown-kind",
          "assemble_compact",
          "valid",
          %{
            "kind" => "unknown",
            "protected_segment" => "A",
            "payload_segment" => "B",
            "signature" => Base.url_encode64(<<0::512>>, padding: false)
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "a malformed operation entry fails the operations builder" do
    alias BoundedAuthorityProtocol.V1

    {:ok, hk} =
      V1.Jwk.public_key_thumbprint_raw(
        :crypto.generate_key(:eddsa, :ed25519, <<9::256>>) |> elem(0),
        %{}
      )

    result =
      run_one(
        case_obj(
          "grant-malformed-op",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "k",
            "issuer" => "https://i.test",
            "grant_id" => "urn:g:1",
            "audiences" => ["https://r.test"],
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => Base.url_encode64(hk, padding: false),
            "operations" => [%{"name" => "read", "selectors" => [%{"kind" => "bogus"}]}]
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "check_chain with a non-list rows field is a dispatch error" do
    result =
      run_one(
        case_obj(
          "chain-bad-rows",
          "check_chain",
          "valid",
          %{
            "rows" => "not-a-list",
            "chain_id" => "urn:c:1",
            "first_sequence" => 1,
            "last_sequence" => 1,
            "row_count" => 1,
            "previous_hash" => Base.url_encode64(<<0::256>>, padding: false),
            "last_hash" => Base.url_encode64(<<0::256>>, padding: false)
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "verify_anchored_export with non-list keys is a dispatch error" do
    result =
      run_one(
        case_obj(
          "export-bad-keys",
          "verify_anchored_export",
          "valid",
          %{
            "chunks" => [Base.url_encode64(<<"BAP1-ARCHIVE", 0, "EXPORT", 0>>, padding: false)],
            "version" => "v1",
            "keys" => "not-a-list",
            "expected" => %{}
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "encode_anchored_export with non-list rows is a dispatch error" do
    result =
      run_one(
        case_obj(
          "encode-export-bad-rows",
          "encode_anchored_export",
          "valid",
          %{
            "rows" => "x",
            "start_anchor" => "s",
            "transitions" => [],
            "end_anchor" => "e",
            "expected" => %{}
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "assemble_compact with proof/boundary/transition kinds reach signing_input_kind clauses" do
    for kind <- ["proof", "boundary_anchor", "key_transition"] do
      result =
        run_one(
          case_obj(
            "assemble-kind-#{kind}",
            "assemble_compact",
            "valid",
            %{
              "kind" => kind,
              "protected_segment" => "A",
              "payload_segment" => "B",
              "signature" => Base.url_encode64(<<0::512>>, padding: false)
            },
            %{"verdict" => "valid"}
          )
        )

      assert result.agree == false
    end
  end

  test "build_operation with a non-map entry hits the catch-all error clause" do
    alias BoundedAuthorityProtocol.V1

    {:ok, hk} =
      V1.Jwk.public_key_thumbprint_raw(
        :crypto.generate_key(:eddsa, :ed25519, <<9::256>>) |> elem(0),
        %{}
      )

    result =
      run_one(
        case_obj(
          "grant-bad-op-entry",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "k",
            "issuer" => "https://i.test",
            "grant_id" => "urn:g:1",
            "audiences" => ["https://r.test"],
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => Base.url_encode64(hk, padding: false),
            "operations" => ["not-a-map"]
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "to_tagged float and true branches via json.decode" do
    result_f =
      run_one(
        case_obj("json-float-tagged", "json.decode", "valid", %{"text" => "2.5"}, %{
          "verdict" => "valid",
          "value" => 2.5
        })
      )

    assert result_f.agree == true

    result_t =
      run_one(
        case_obj("json-true-tagged", "json.decode", "valid", %{"text" => "true"}, %{
          "verdict" => "valid",
          "value" => true
        })
      )

    assert result_t.agree == true
  end

  test "valid_before unbounded branch via verify_historical_anchor with null valid_before" do
    alias BoundedAuthorityProtocol.V1
    {pub_anchor, priv_anchor} = :crypto.generate_key(:eddsa, :ed25519, <<11::256>>)
    zero = <<0::256>>

    anchor = %V1.BoundaryAnchor{
      anchor_id: "urn:a:1",
      anchored_at: 1_000,
      chain_id: "urn:c:1",
      sequence: 0,
      chain_hash: zero,
      key_id: "ka",
      public_key: pub_anchor
    }

    {:ok, si} = V1.boundary_anchor_signing_input(anchor, %{})
    sig = :crypto.sign(:eddsa, :ed25519, si.message, [priv_anchor, :ed25519])
    {:ok, compact} = V1.assemble_compact(si, sig)
    {:ok, fp} = V1.Jwk.public_key_thumbprint_raw(pub_anchor, %{})

    result =
      run_one(
        case_obj(
          "anchor-unbounded-key",
          "verify_historical_anchor",
          "valid",
          %{
            "compact" => compact,
            "key" => %{
              "key_id" => "ka",
              "public_key" => Base.url_encode64(pub_anchor, padding: false),
              "valid_from" => 0
            },
            "expected" => %{
              "anchor_id" => "urn:a:1",
              "anchored_at" => 1_000,
              "chain_id" => "urn:c:1",
              "sequence" => 0,
              "chain_hash" => Base.url_encode64(zero, padding: false),
              "key_id" => "ka",
              "key_fingerprint" => Base.url_encode64(fp, padding: false)
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == true
  end

  test "to_tagged float/bool branches via request_digest cast_arguments" do
    alias BoundedAuthorityProtocol.V1
    {:ok, d_float} = V1.request_digest("read", {:object, [{"x", {:float, 2.5}}]}, %{})
    {:ok, d_bool} = V1.request_digest("read", {:object, [{"x", {:boolean, true}}]}, %{})

    result_f =
      run_one(
        case_obj(
          "digest-float-arg",
          "request_digest",
          "valid",
          %{"operation" => "read", "cast_arguments" => %{"x" => 2.5}},
          %{"verdict" => "valid", "digest" => d_float}
        )
      )

    assert result_f.agree == true

    result_b =
      run_one(
        case_obj(
          "digest-bool-arg",
          "request_digest",
          "valid",
          %{"operation" => "read", "cast_arguments" => %{"x" => true}},
          %{"verdict" => "valid", "digest" => d_bool}
        )
      )

    assert result_b.agree == true
  end

  test "compare? no-projection fallback via an unknown expected field" do
    result =
      run_one(
        case_obj("unknown-expected-field", "json.decode", "valid", %{"text" => "{\"a\":1}"}, %{
          "verdict" => "valid",
          "unknown_field" => "x"
        })
      )

    assert result.agree == false
  end

  test "expected_transitions empty branch via encode_anchored_export with no transitions" do
    alias BoundedAuthorityProtocol.V1
    {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<21::256>>)
    zero = <<0::256>>

    e1 = %V1.ConsumptionEntry{
      chain_id: "urn:c:e",
      sequence: 1,
      previous_hash: zero,
      commitment: :crypto.hash(:sha256, "c")
    }

    {:ok, enc1} = V1.encode_consumption_entry(e1, %{})

    anchor_start = %V1.BoundaryAnchor{
      anchor_id: "urn:a:s",
      anchored_at: 1_000,
      chain_id: "urn:c:e",
      sequence: 0,
      chain_hash: zero,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, ssi} = V1.boundary_anchor_signing_input(anchor_start, %{})
    ssig = :crypto.sign(:eddsa, :ed25519, ssi.message, [priv_a, :ed25519])
    {:ok, start_c} = V1.assemble_compact(ssi, ssig)

    anchor_end = %V1.BoundaryAnchor{
      anchor_id: "urn:a:e",
      anchored_at: 2_000,
      chain_id: "urn:c:e",
      sequence: 1,
      chain_hash: enc1.hash,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, esi} = V1.boundary_anchor_signing_input(anchor_end, %{})
    esig = :crypto.sign(:eddsa, :ed25519, esi.message, [priv_a, :ed25519])
    {:ok, end_c} = V1.assemble_compact(esi, esig)
    {:ok, sfp} = V1.Jwk.public_key_thumbprint_raw(pub_a, %{})

    export_input = %V1.AnchoredExportInput{
      rows: [enc1.bytes],
      start_anchor: start_c,
      transitions: [],
      end_anchor: end_c
    }

    expected = %V1.ExpectedExport{
      chain: %V1.ExpectedChain{
        chain_id: "urn:c:e",
        first_sequence: 1,
        last_sequence: 1,
        row_count: 1,
        previous_hash: zero,
        last_hash: enc1.hash,
        bounds: %{}
      },
      start_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:s",
        anchored_at: 1_000,
        chain_id: "urn:c:e",
        sequence: 0,
        chain_hash: zero,
        key_id: "ka",
        key_fingerprint: sfp,
        bounds: %{}
      },
      transitions: [],
      end_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:e",
        anchored_at: 2_000,
        chain_id: "urn:c:e",
        sequence: 1,
        chain_hash: enc1.hash,
        key_id: "ka",
        key_fingerprint: sfp,
        bounds: %{}
      },
      bounds: %{}
    }

    {:ok, encoded} = V1.encode_anchored_export(export_input, expected)

    result =
      run_one(
        case_obj(
          "encode-export-no-transitions",
          "encode_anchored_export",
          "valid",
          %{
            "rows" => [Base.url_encode64(enc1.bytes, padding: false)],
            "start_anchor" => start_c,
            "transitions" => [],
            "end_anchor" => end_c,
            "expected" => %{
              "chain" => %{
                "chain_id" => "urn:c:e",
                "first_sequence" => 1,
                "last_sequence" => 1,
                "row_count" => 1,
                "previous_hash" => Base.url_encode64(zero, padding: false),
                "last_hash" => Base.url_encode64(enc1.hash, padding: false)
              },
              "start_anchor" => %{
                "anchor_id" => "urn:a:s",
                "anchored_at" => 1_000,
                "chain_id" => "urn:c:e",
                "sequence" => 0,
                "chain_hash" => Base.url_encode64(zero, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "end_anchor" => %{
                "anchor_id" => "urn:a:e",
                "anchored_at" => 2_000,
                "chain_id" => "urn:c:e",
                "sequence" => 1,
                "chain_hash" => Base.url_encode64(enc1.hash, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "transitions" => []
            }
          },
          %{
            "verdict" => "valid",
            "digest" => Base.url_encode64(encoded.digest, padding: false),
            "byte_count" => encoded.byte_count
          }
        )
      )

    assert result.agree == true
  end

  test "a selector-bearing grant_signing_input case builds and agrees" do
    alias BoundedAuthorityProtocol.V1

    {:ok, hk} =
      V1.Jwk.public_key_thumbprint_raw(
        :crypto.generate_key(:eddsa, :ed25519, <<9::256>>) |> elem(0),
        %{}
      )

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:s",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [
        %V1.Operation{
          name: "read",
          selectors: [
            {:equals, ["region"], {:string, "us"}},
            {:one_of, ["tier"], [{:string, "gold"}, {:string, "silver"}]}
          ]
        }
      ]
    }

    {:ok, si} = V1.grant_signing_input(grant, %{})

    result =
      run_one(
        case_obj(
          "grant-signing-selectors",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "issuer",
            "issuer" => "https://issuer.example.test",
            "grant_id" => "urn:example:grant:s",
            "audiences" => ["https://resource.example.test"],
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => Base.url_encode64(hk, padding: false),
            "operations" => [
              %{
                "name" => "read",
                "selectors" => [
                  %{"kind" => "equals", "path" => ["region"], "value" => "us"},
                  %{"kind" => "one_of", "path" => ["tier"], "values" => ["gold", "silver"]}
                ]
              }
            ]
          },
          %{
            "verdict" => "valid",
            "protected_segment" => si.protected_segment,
            "payload_segment" => si.payload_segment,
            "message" => si.message
          }
        )
      )

    assert result.agree == true
  end

  test "jwk dispatch error branches (facade rejects malformed input)" do
    short_key = Base.url_encode64(<<0, 1, 2>>, padding: false)

    for {id, surface, input} <- [
          {"jwk-encode-bad-pk", "jwk.encode_public", %{"public_key" => short_key}},
          {"jwk-decode-bad-text", "jwk.decode_public", %{"text" => "not-a-jwk"}},
          {"jwk-thumbprint-bad-text", "jwk.thumbprint", %{"text" => "not-a-jwk"}},
          {"jwk-thumbprint-raw-bad-text", "jwk.thumbprint_raw", %{"text" => "not-a-jwk"}},
          {"jwk-preimage-bad-text", "jwk.thumbprint_preimage", %{"text" => "not-a-jwk"}},
          {"jwk-pk-thumbprint-bad-pk", "jwk.public_key_thumbprint_raw",
           %{"public_key" => short_key}}
        ] do
      result =
        run_one(case_obj(id, surface, "invalid_encoding", input, %{"verdict" => "invalid"}))

      assert result.agree == true, "#{id} should agree (facade rejects -> invalid)"
    end
  end

  test "base64url.decode fallback segment branch via text input" do
    # A base64url.decode case with a 'text' input (not 'base64url') hits the fallback_segment path.
    result =
      run_one(
        case_obj(
          "base64url-text-fallback",
          "base64url.decode",
          "valid",
          %{"text" => "aGVsbG8"},
          %{"verdict" => "valid", "decoded" => "hello"}
        )
      )

    assert result.agree == true
  end

  test "check_envelope with a required nonce hits expected_nonce required branch" do
    # Covers Runner.expected_nonce/1's %{"required" => encoded} clause AND the V1
    # nonce_matches?(nonce, {:required, expected}) success arm. A genuine agreement:
    # the proof carries a UTF-8 nonce that equals the expected-required nonce, the
    # envelope verifies to {:ok, facts}, expected verdict is "valid", and agreement is
    # a non-trivial facts comparison. (The prior form used a sha256 nonce — raw bytes
    # that fail valid_nonce?'s String.valid? bound — and a nonceless proof, so verify
    # returned {:error, :invalid} matching an "invalid" verdict -> agree == true, which
    # defeated the disagreement the test asserted and exercised no nonce-match path.)
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<31::256>>)
    {pub_h, priv_h} = :crypto.generate_key(:eddsa, :ed25519, <<32::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})
    # valid_nonce? requires is_binary + byte_size in 1..512 + String.valid?; a plain
    # UTF-8 string satisfies it, and matching the expected nonce makes verify succeed.
    nonce = "nonce-value-within-bound"

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:n",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, gc} = V1.assemble_compact(gsi, gsig)

    proof = %V1.Proof{
      holder_public_key: pub_h,
      proof_id: "urn:p:n",
      method: "POST",
      target_uri: "https://resource.example.test/invoke",
      issued_at: 1_100,
      nonce: nonce,
      invocation_id: "550e8400-e29b-41d4-a716-446655440002",
      operation: "read",
      grant_compact: gc,
      cast_arguments: {:object, [{"a", {:integer, 1}}]}
    }

    {:ok, psi} = V1.proof_signing_input(proof, %{})
    psig = :crypto.sign(:eddsa, :ed25519, psi.message, [priv_h, :ed25519])
    {:ok, pc} = V1.assemble_compact(psi, psig)

    result =
      run_one(
        case_obj(
          "envelope-required-nonce",
          "check_envelope",
          "valid",
          %{
            "grant" => gc,
            "proof" => pc,
            "expected" => %{
              "trusted_issuer" => %{
                "key_id" => "issuer",
                "public_key" => Base.url_encode64(pub_i, padding: false)
              },
              "issuer" => "https://issuer.example.test",
              "audience" => "https://resource.example.test",
              "method" => "POST",
              "target_uri" => "https://resource.example.test/invoke",
              "invocation_id" => "550e8400-e29b-41d4-a716-446655440002",
              "operation" => "read",
              "cast_arguments" => %{"a" => 1},
              "evaluation_time" => 1_150,
              "clock_skew" => 60,
              "proof_max_age" => 300,
              "nonce" => %{"required" => Base.url_encode64(nonce, padding: false)}
            }
          },
          %{"verdict" => "valid"}
        )
      )

    # Proof nonce matches the expected-required nonce -> envelope verifies -> facts agree.
    assert result.agree == true
  end

  # --- facade error-passthrough arms (dispatch error -> error) ---------------
  # Each facade can reject input with {:error, :invalid}; the dispatch's `error -> error`
  # arm must surface it. Driven with input the facade accepts enough to build but rejects
  # at the operation, so the case-clause reaches the error arm rather than the with-chain.

  test "jcs.encode dispatch-error via Json.decode magnitude rejection" do
    # The jcs.encode dispatch is a single `with` chain: input_bytes -> Json.decode -> Jcs.encode.
    # An integer at 2^53+1 (9007199254740993) exceeds the integer_magnitude bound, so Json.decode
    # rejects it and the with-chain returns {:error, :invalid}; against a valid verdict, agree
    # is false. (Note: this exercises the Json.decode step, not a separate Jcs.encode error arm —
    # the dispatch has no distinct JCS error passthrough; any value that decodes under the shared
    # magnitude bound also JCS-encodes.)
    result =
      run_one(
        case_obj(
          "jcs-encode-magnitude-reject",
          "jcs.encode",
          "valid",
          # 9007199254740993 exceeds the integer_magnitude ceiling (9_007_199_254_740_991).
          %{"text" => "9007199254740993"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "signing-input facade-error passthrough (L255) via grant_signing_input with too many audiences" do
    # The facade's valid_string_list? enforces the audiences COUNT bound (max 64). A list of
    # 65 audiences trips it AFTER build_grant constructs the struct, so the dispatch reaches
    # its `error -> error` arm rather than the with-chain's fetch failures.
    alias BoundedAuthorityProtocol.V1

    {:ok, hk} =
      V1.Jwk.public_key_thumbprint_raw(
        :crypto.generate_key(:eddsa, :ed25519, <<9::256>>) |> elem(0),
        %{}
      )

    too_many_audiences = Enum.map(1..65, &"https://r#{&1}.test")

    result =
      run_one(
        case_obj(
          "signing-input-facade-error",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "k",
            "issuer" => "https://i.test",
            "grant_id" => "urn:g:1",
            "audiences" => too_many_audiences,
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => Base.url_encode64(hk, padding: false),
            "operations" => [%{"name" => "read", "selectors" => ["all"]}]
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "check_chain facade-error passthrough (L341)" do
    # Build a chain whose row hashes are internally inconsistent so verify_chain rejects it.
    alias BoundedAuthorityProtocol.V1
    zero = <<0::256>>

    row = %{
      "chain_id" => "urn:c:facade",
      "sequence" => 1,
      "previous_hash" => Base.url_encode64(zero, padding: false),
      # arbitrary non-matching commitment
      "commitment" => Base.url_encode64(:crypto.hash(:sha256, "x"), padding: false)
    }

    result =
      run_one(
        case_obj(
          "chain-facade-error",
          "check_chain",
          "valid",
          %{
            "rows" => [row],
            "expected" => %{
              "chain_id" => "urn:c:facade",
              "first_sequence" => 1,
              "last_sequence" => 1,
              "row_count" => 1,
              "previous_hash" => Base.url_encode64(zero, padding: false),
              "last_hash" => Base.url_encode64(:crypto.hash(:sha256, "y"), padding: false)
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "verify_anchored_export facade-error passthrough (L409)" do
    # Encode a real export, then build a verify case whose expected digest deliberately
    # disagrees with the archive's digest -> the facade returns {:error, :invalid} and the
    # dispatch `error -> error` arm fires. The chunks/version come from the real encoded
    # export so build_verify_export succeeds; only the digest is corrupted.
    alias BoundedAuthorityProtocol.V1
    {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<41::256>>)
    zero = <<0::256>>

    e1 = %V1.ConsumptionEntry{
      chain_id: "urn:c:ae",
      sequence: 1,
      previous_hash: zero,
      commitment: :crypto.hash(:sha256, "c")
    }

    {:ok, enc1} = V1.encode_consumption_entry(e1, %{})

    anchor_start = %V1.BoundaryAnchor{
      anchor_id: "urn:a:as",
      anchored_at: 1_000,
      chain_id: "urn:c:ae",
      sequence: 0,
      chain_hash: zero,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, ssi} = V1.boundary_anchor_signing_input(anchor_start, %{})
    ssig = :crypto.sign(:eddsa, :ed25519, ssi.message, [priv_a, :ed25519])
    {:ok, start_c} = V1.assemble_compact(ssi, ssig)

    anchor_end = %V1.BoundaryAnchor{
      anchor_id: "urn:a:ae",
      anchored_at: 2_000,
      chain_id: "urn:c:ae",
      sequence: 1,
      chain_hash: enc1.hash,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, esi} = V1.boundary_anchor_signing_input(anchor_end, %{})
    esig = :crypto.sign(:eddsa, :ed25519, esi.message, [priv_a, :ed25519])
    {:ok, end_c} = V1.assemble_compact(esi, esig)
    {:ok, sfp} = V1.Jwk.public_key_thumbprint_raw(pub_a, %{})

    export_input = %V1.AnchoredExportInput{
      rows: [enc1.bytes],
      start_anchor: start_c,
      transitions: [],
      end_anchor: end_c
    }

    expected_struct = %V1.ExpectedExport{
      chain: %V1.ExpectedChain{
        chain_id: "urn:c:ae",
        first_sequence: 1,
        last_sequence: 1,
        row_count: 1,
        previous_hash: zero,
        last_hash: enc1.hash,
        bounds: %{}
      },
      start_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:as",
        anchored_at: 1_000,
        chain_id: "urn:c:ae",
        sequence: 0,
        chain_hash: zero,
        key_id: "ka",
        key_fingerprint: sfp,
        bounds: %{}
      },
      transitions: [],
      end_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:ae",
        anchored_at: 2_000,
        chain_id: "urn:c:ae",
        sequence: 1,
        chain_hash: enc1.hash,
        key_id: "ka",
        key_fingerprint: sfp,
        bounds: %{}
      },
      bounds: %{}
    }

    {:ok, export} = V1.encode_anchored_export(export_input, expected_struct)

    # The archive's object_version is the integer the encoder embedded (1). The verify
    # builder reads input["version"] as a binary and validate_object_versions compares it
    # against expected.object_version; "v1" is the convention the corpus uses.
    result =
      run_one(
        case_obj(
          "anchored-export-facade-error",
          "verify_anchored_export",
          "valid",
          %{
            "chunks" => Enum.map(export.chunks, &Base.url_encode64(&1, padding: false)),
            "version" => "v1",
            "keys" => [
              %{
                "key_id" => "ka",
                "public_key" => Base.url_encode64(pub_a, padding: false),
                "valid_from" => 0
              }
            ],
            "expected" => %{
              "chain" => %{
                "chain_id" => "urn:c:ae",
                "first_sequence" => 1,
                "last_sequence" => 1,
                "row_count" => 1,
                "previous_hash" => Base.url_encode64(zero, padding: false),
                "last_hash" => Base.url_encode64(enc1.hash, padding: false)
              },
              "start_anchor" => %{
                "anchor_id" => "urn:a:as",
                "anchored_at" => 1_000,
                "chain_id" => "urn:c:ae",
                "sequence" => 0,
                "chain_hash" => Base.url_encode64(zero, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "end_anchor" => %{
                "anchor_id" => "urn:a:ae",
                "anchored_at" => 2_000,
                "chain_id" => "urn:c:ae",
                "sequence" => 1,
                "chain_hash" => Base.url_encode64(enc1.hash, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "transitions" => [],
              # deliberately wrong digest -> facade rejects -> dispatch error arm (L409)
              "digest" =>
                Base.url_encode64(:crypto.hash(:sha256, "wrong-digest"), padding: false),
              "object_version" => "v1"
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "request_digest facade-error passthrough (L427)" do
    # cast_arguments as an operation+args whose digest bound is tripped: an oversized operation name.
    result =
      run_one(
        case_obj(
          "request-digest-facade-error",
          "request_digest",
          "valid",
          %{"operation" => String.duplicate("x", 300), "cast_arguments" => %{}},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  # --- input_bytes / raw_bytes error arms -----------------------------------

  test "input_bytes true->error arm (L451): input with no recognized byte key" do
    # json.decode with an input map missing text/base64url/raw_file -> input_bytes errors.
    result =
      run_one(
        case_obj("input-bytes-no-key", "json.decode", "valid", %{"other" => "x"}, %{
          "verdict" => "valid"
        })
      )

    assert result.agree == false
  end

  test "raw_bytes nil->error arm (L458): raw_file path absent from raws" do
    # A raw_file input whose path is not present in the loaded raws -> raw_bytes errors.
    # The corpus loader only registers raws declared in the index, so a path that wasn't
    # indexed is missing at run time.
    result =
      run_one(
        case_obj(
          "raw-bytes-missing-path",
          "json.decode",
          "valid",
          %{"raw_file" => "cases/json/never-indexed.raw"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  # --- compare? branches ----------------------------------------------------

  test "compare? value-via-json tag (L510) via a json.decode valid agreement" do
    # Already covered indirectly by other value-agreement tests, but pin the {:json, actual}
    # clause explicitly: a valid json.decode case whose expected compares a JSON value.
    result =
      run_one(
        case_obj("compare-value-json", "json.decode", "valid", %{"text" => "[1,2,3]"}, %{
          "verdict" => "valid",
          "value" => [1, 2, 3]
        })
      )

    assert result.agree == true
  end

  test "compare? bounds clause (L514) via bounds.new with bounds in expected" do
    # bounds.new dispatch returns %{"bounds" => %Bounds{}}; an expected "bounds" key projects
    # the actual to the %Bounds{} struct and hits compare?("bounds", _, %Bounds{}) -> true.
    # Any expected value works since the clause returns true unconditionally (the bounds struct
    # is opaque to the corpus; agreement is on its presence + verdict).
    result =
      run_one(
        case_obj(
          "bounds-new-compare",
          "bounds.new",
          "valid",
          %{"overrides" => %{}},
          %{"verdict" => "valid", "bounds" => %{}}
        )
      )

    assert result.agree == true
  end

  test "byte_string_compare :error arm (L525): expected not base64url-decodable" do
    # A verify_grant case where the case-expected grant_id is not base64url and differs from
    # the actual grant_id -> byte_string_compare's decode fails (:error) and falls back to a
    # direct == that is false. build_verify_grant reads its inputs from FLAT top-level keys
    # (compact/key_id/public_key/issuer/audience/evaluation_time/clock_skew), NOT nested maps.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<61::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<62::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:bsc",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, gc} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "byte-string-compare-error",
          "verify_grant",
          "valid",
          %{
            "compact" => gc,
            "key_id" => "issuer",
            "public_key" => Base.url_encode64(pub_i, padding: false),
            "issuer" => "https://issuer.example.test",
            "audience" => "https://resource.example.test",
            "evaluation_time" => 1_500,
            "clock_skew" => 60
          },
          # grant_id is not base64url-decodable AND differs from actual -> :error arm -> false
          %{"verdict" => "valid", "grant_id" => "not-b64-and-wrong!!!"}
        )
      )

    assert result.agree == false
  end

  # --- proof_nonce / build_operations / int_field / decode_b64_item / json_field / to_tagged(null) ---

  test "proof_nonce encoded arm (L602) via proof_signing_input with a nonce" do
    # proof_signing_input's build_proof reads input["nonce"] through proof_nonce/1; a present
    # base64url nonce hits the `encoded when is_binary` clause and decodes into the Proof.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<70::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<71::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})
    nonce = "nonce-within-bound"

    # proof_signing_input threads grant_compact through CompactJws.ath, so it must be a real
    # signed grant compact — mint one rather than passing a placeholder.
    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:pn",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, grant_compact} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "proof-signing-nonce",
          "proof_signing_input",
          "valid",
          %{
            "holder_public_key" => Base.url_encode64(pub_h, padding: false),
            "proof_id" => "urn:p:pn",
            "method" => "POST",
            "target_uri" => "https://resource.example.test/invoke",
            "issued_at" => 1_100,
            "nonce" => Base.url_encode64(nonce, padding: false),
            "invocation_id" => "550e8400-e29b-41d4-a716-446655440099",
            "operation" => "read",
            "grant_compact" => grant_compact,
            "cast_arguments" => %{"a" => 1}
          },
          %{"verdict" => "valid"}
        )
      )

    # build_proof succeeds; proof_signing_input produces a signing input (agree on verdict valid
    # requires dispatch {:ok, _}, which confirms the encoded-nonce arm ran without error).
    assert result.agree == true
  end

  test "proof_nonce catch-all non-binary arm (L603) via proof_signing_input with non-string nonce" do
    # input["nonce"] present but not a binary (an integer) -> proof_nonce's `_ -> nil` clause.
    # build_proof still succeeds (nonce becomes nil), and proof_signing_input produces output.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<70::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<72::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:pnn",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, grant_compact} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "proof-signing-nonce-nonbinary",
          "proof_signing_input",
          "valid",
          %{
            "holder_public_key" => Base.url_encode64(pub_h, padding: false),
            "proof_id" => "urn:p:pnn",
            "method" => "POST",
            "target_uri" => "https://resource.example.test/invoke",
            "issued_at" => 1_100,
            # non-binary nonce -> `_ -> nil` arm of proof_nonce
            "nonce" => 12_345,
            "invocation_id" => "550e8400-e29b-41d4-a716-446655440100",
            "operation" => "read",
            "grant_compact" => grant_compact,
            "cast_arguments" => %{"a" => 1}
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == true
  end

  test "proof_nonce malformed-b64 arm (L612) normalizes to nil (fail-closed)" do
    # input["nonce"] is a binary but not valid base64url -> proof_nonce's :error -> nil arm.
    # The proof builds with nonce: nil; proof_signing_input succeeds (nil nonce is valid when
    # not required by the envelope). This is the fail-closed normalization replacing the prior
    # raising Base.url_decode64! — verified non-crashing here.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<70::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<74::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:pnb",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, grant_compact} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "proof-nonce-malformed-b64",
          "proof_signing_input",
          "valid",
          %{
            "holder_public_key" => Base.url_encode64(pub_h, padding: false),
            "proof_id" => "urn:p:pnb",
            "method" => "POST",
            "target_uri" => "https://resource.example.test/invoke",
            "issued_at" => 1_100,
            # malformed base64url nonce -> :error -> nil (proof builds with nil nonce)
            "nonce" => "!!!not-base64!!!",
            "invocation_id" => "550e8400-e29b-41d4-a716-446655440102",
            "operation" => "read",
            "grant_compact" => grant_compact,
            "cast_arguments" => %{"a" => 1}
          },
          %{"verdict" => "valid"}
        )
      )

    # nil nonce is valid for a proof_signing_input (no expected-request constraint here).
    assert result.agree == true
  end

  test "expected_nonce malformed-b64 arm (L1017) returns :malformed sentinel (fail-closed)" do
    # A check_envelope case whose expected.nonce.required is malformed base64url -> expected_nonce's
    # :error -> :malformed arm. The :malformed sentinel fails valid_nonce_expectation? (catch-all
    # false) and nonce_matches? (catch-all false), so verify returns {:error, :invalid} -> agree
    # false on a valid verdict. This replaces the prior raising Base.url_decode64!.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<31::256>>)
    {pub_h, priv_h} = :crypto.generate_key(:eddsa, :ed25519, <<32::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:enm",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, gc} = V1.assemble_compact(gsi, gsig)

    proof = %V1.Proof{
      holder_public_key: pub_h,
      proof_id: "urn:p:enm",
      method: "POST",
      target_uri: "https://resource.example.test/invoke",
      issued_at: 1_100,
      nonce: "nonce-within-bound",
      invocation_id: "550e8400-e29b-41d4-a716-446655440103",
      operation: "read",
      grant_compact: gc,
      cast_arguments: {:object, [{"a", {:integer, 1}}]}
    }

    {:ok, psi} = V1.proof_signing_input(proof, %{})
    psig = :crypto.sign(:eddsa, :ed25519, psi.message, [priv_h, :ed25519])
    {:ok, pc} = V1.assemble_compact(psi, psig)

    result =
      run_one(
        case_obj(
          "envelope-malformed-required-nonce",
          "check_envelope",
          "valid",
          %{
            "grant" => gc,
            "proof" => pc,
            "expected" => %{
              "trusted_issuer" => %{
                "key_id" => "issuer",
                "public_key" => Base.url_encode64(pub_i, padding: false)
              },
              "issuer" => "https://issuer.example.test",
              "audience" => "https://resource.example.test",
              "method" => "POST",
              "target_uri" => "https://resource.example.test/invoke",
              "invocation_id" => "550e8400-e29b-41d4-a716-446655440103",
              "operation" => "read",
              "cast_arguments" => %{"a" => 1},
              "evaluation_time" => 1_150,
              "clock_skew" => 60,
              "proof_max_age" => 300,
              # malformed base64url required nonce -> :error -> :malformed -> verify fails closed
              "nonce" => %{"required" => "!!!not-base64!!!"}
            }
          },
          %{"verdict" => "valid"}
        )
      )

    # :malformed sentinel -> valid_nonce_expectation? false -> verify {:error, :invalid} -> disagree.
    assert result.agree == false
  end

  test "build_operations non-list arm (L610) via grant_signing_input" do
    alias BoundedAuthorityProtocol.V1

    {:ok, hk} =
      V1.Jwk.public_key_thumbprint_raw(
        :crypto.generate_key(:eddsa, :ed25519, <<81::256>>) |> elem(0),
        %{}
      )

    result =
      run_one(
        case_obj(
          "grant-ops-not-list",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "k",
            "issuer" => "https://i.test",
            "grant_id" => "urn:g:nl",
            "audiences" => ["https://r.test"],
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => Base.url_encode64(hk, padding: false),
            "operations" => "not-a-list"
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "int_field non-integer arm (L1128) via verify_grant with non-int evaluation_time" do
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<91::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<92::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:if",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, gc} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "int-field-non-int",
          "verify_grant",
          "valid",
          %{
            "compact" => gc,
            "key_id" => "issuer",
            "public_key" => Base.url_encode64(pub_i, padding: false),
            "issuer" => "https://issuer.example.test",
            "audience" => "https://resource.example.test",
            "evaluation_time" => "not-an-int",
            "clock_skew" => 60
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "decode_b64_item :error arm (L1166) via check_chain with a malformed-b64 row" do
    # byte_list reduces rows via decode_b64_item; a binary element that fails base64url decode
    # hits decode_b64_item's :error -> {:error, :invalid} arm.
    result =
      run_one(
        case_obj(
          "decode-b64-item-malformed",
          "check_chain",
          "valid",
          %{
            "rows" => ["!!!not-base64!!!"],
            "expected" => %{
              "chain_id" => "urn:c:dbn",
              "first_sequence" => 1,
              "last_sequence" => 1,
              "row_count" => 1,
              "previous_hash" => Base.url_encode64(<<0::256>>, padding: false),
              "last_hash" => Base.url_encode64(<<0::256>>, padding: false)
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "decode_b64_item non-binary catch-all (L1171) via check_chain with a non-string row" do
    # byte_list reduces rows via decode_b64_item; a non-binary element hits decode_b64_item(_).
    result =
      run_one(
        case_obj(
          "decode-b64-item-nonbinary",
          "check_chain",
          "valid",
          %{
            "rows" => [12_345],
            "expected" => %{
              "chain_id" => "urn:c:dbnb",
              "first_sequence" => 1,
              "last_sequence" => 1,
              "row_count" => 1,
              "previous_hash" => Base.url_encode64(<<0::256>>, padding: false),
              "last_hash" => Base.url_encode64(<<0::256>>, padding: false)
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "json_field nil arm (L1162) via proof_signing_input missing cast_arguments" do
    alias BoundedAuthorityProtocol.V1
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<93::256>>)

    result =
      run_one(
        case_obj(
          "json-field-nil",
          "proof_signing_input",
          "valid",
          %{
            "holder_public_key" => Base.url_encode64(pub_h, padding: false),
            "proof_id" => "urn:p:jf",
            "method" => "POST",
            "target_uri" => "https://resource.example.test/i",
            "issued_at" => 1_100,
            "invocation_id" => "id-jf",
            "operation" => "read",
            "grant_compact" => "eyJhbGciOiJFZERTQSJ9.e30.signature"
            # cast_arguments intentionally absent -> json_field nil arm
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "to_tagged null arm (L1200) via proof_signing_input with a nested null in cast_arguments" do
    # to_tagged/1 recurses into map/list values via json_field. A JSON null NESTED inside an
    # object (e.g. cast_arguments: {"n": null}) loads as Elixir nil at the leaf, and the top-level
    # object passes json_field's nil guard; recursion then calls to_tagged(nil) -> the `true ->`
    # catch-all (none of the is_* guards match nil). A top-level null is guarded out by json_field
    # before to_tagged runs, so the nested form is the reachable path.
    alias BoundedAuthorityProtocol.V1
    {pub_i, priv_i} = :crypto.generate_key(:eddsa, :ed25519, <<70::256>>)
    {pub_h, _} = :crypto.generate_key(:eddsa, :ed25519, <<73::256>>)
    {:ok, hk} = V1.Jwk.public_key_thumbprint_raw(pub_h, %{})

    grant = %V1.Grant{
      key_id: "issuer",
      issuer: "https://issuer.example.test",
      grant_id: "urn:g:ttn",
      audiences: ["https://resource.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: hk,
      operations: [%V1.Operation{name: "read", selectors: [:all]}]
    }

    {:ok, gsi} = V1.grant_signing_input(grant, %{})
    gsig = :crypto.sign(:eddsa, :ed25519, gsi.message, [priv_i, :ed25519])
    {:ok, grant_compact} = V1.assemble_compact(gsi, gsig)

    result =
      run_one(
        case_obj(
          "to-tagged-null-nested",
          "proof_signing_input",
          "valid",
          %{
            "holder_public_key" => Base.url_encode64(pub_h, padding: false),
            "proof_id" => "urn:p:ttn",
            "method" => "POST",
            "target_uri" => "https://resource.example.test/invoke",
            "issued_at" => 1_100,
            "invocation_id" => "550e8400-e29b-41d4-a716-446655440101",
            "operation" => "read",
            "grant_compact" => grant_compact,
            # nested null -> json_field passes the object; recursion hits to_tagged(nil) -> L1200
            "cast_arguments" => %{"n" => nil}
          },
          %{"verdict" => "valid"}
        )
      )

    # to_tagged(nil) ran during build; the facade accepts a null-valued member (null digests),
    # so dispatch succeeds and agreement is on the verdict.
    assert result.agree == true
  end

  test "decode_b64_value :error arm (L456) via json.decode with malformed base64url" do
    # input_bytes decodes input["base64url"]; a malformed (non-base64url) string hits
    # decode_b64_value's :error -> {:error, :invalid} arm.
    result =
      run_one(
        case_obj(
          "decode-b64-value-error",
          "json.decode",
          "valid",
          %{"base64url" => "!!!not-base64url!!!"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "decode_b64_value success arm (L455) via json.decode with valid base64url" do
    # input_bytes decodes input["base64url"]; a valid base64url string hits the
    # {:ok, decoded} success arm and the facade decodes the underlying JSON.
    result =
      run_one(
        case_obj(
          "decode-b64-value-success",
          "json.decode",
          "valid",
          %{"base64url" => Base.url_encode64("{\"a\":1}", padding: false)},
          %{"verdict" => "valid", "value" => %{"a" => 1}}
        )
      )

    assert result.agree == true
  end

  test "fallback_segment error arm (L477) via base64url.decode with no recognized byte key" do
    # base64url.decode with no base64url/text/raw_file -> b64url_segment falls through to
    # fallback_segment -> input_bytes errors -> `_ -> ""` returns an empty string, which the
    # facade then rejects.
    result =
      run_one(
        case_obj(
          "fallback-segment-error",
          "base64url.decode",
          "valid",
          %{"other" => "x"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "input_public_key :error arm (L485) via jwk.encode_public with malformed b64" do
    # jwk.encode_public builds via input_public_key, which decodes input["public_key"]; a
    # malformed base64url hits the :error -> {:error, :invalid} arm.
    result =
      run_one(
        case_obj(
          "input-public-key-error",
          "jwk.encode_public",
          "valid",
          %{"public_key" => "!!!not-base64!!!"},
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "b64_field :error arm (L1141) via grant_signing_input with malformed holder_thumbprint" do
    # build_grant decodes holder_thumbprint via b64_field; malformed base64url hits :error arm.
    result =
      run_one(
        case_obj(
          "b64-field-error",
          "grant_signing_input",
          "valid",
          %{
            "key_id" => "k",
            "issuer" => "https://i.test",
            "grant_id" => "urn:g:b64",
            "audiences" => ["https://r.test"],
            "issued_at" => 1_000,
            "not_before" => 1_000,
            "expires_at" => 2_000,
            "holder_thumbprint" => "!!!not-base64!!!",
            "operations" => [%{"name" => "read", "selectors" => ["all"]}]
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "encode_anchored_export facade-error passthrough (L339) via a transition whose bytes mismatch" do
    # encode_anchored_export dispatch: build_encode_export succeeds but encode_anchored_export
    # rejects (e.g., a transition compact that does not parse) -> the `error -> error` arm fires.
    alias BoundedAuthorityProtocol.V1
    {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<31::256>>)
    zero = <<0::256>>

    e1 = %V1.ConsumptionEntry{
      chain_id: "urn:c:enc",
      sequence: 1,
      previous_hash: zero,
      commitment: :crypto.hash(:sha256, "c")
    }

    {:ok, enc1} = V1.encode_consumption_entry(e1, %{})

    anchor_start = %V1.BoundaryAnchor{
      anchor_id: "urn:a:encs",
      anchored_at: 1_000,
      chain_id: "urn:c:enc",
      sequence: 0,
      chain_hash: zero,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, ssi} = V1.boundary_anchor_signing_input(anchor_start, %{})
    ssig = :crypto.sign(:eddsa, :ed25519, ssi.message, [priv_a, :ed25519])
    {:ok, start_c} = V1.assemble_compact(ssi, ssig)

    anchor_end = %V1.BoundaryAnchor{
      anchor_id: "urn:a:ence",
      anchored_at: 2_000,
      chain_id: "urn:c:enc",
      sequence: 1,
      chain_hash: enc1.hash,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, esi} = V1.boundary_anchor_signing_input(anchor_end, %{})
    esig = :crypto.sign(:eddsa, :ed25519, esi.message, [priv_a, :ed25519])
    {:ok, end_c} = V1.assemble_compact(esi, esig)
    {:ok, sfp} = V1.Jwk.public_key_thumbprint_raw(pub_a, %{})

    result =
      run_one(
        case_obj(
          "encode-export-facade-error",
          "encode_anchored_export",
          "valid",
          %{
            "rows" => [Base.url_encode64(enc1.bytes, padding: false)],
            "start_anchor" => start_c,
            # A transition referencing an unknown (garbage) compact -> encode rejects.
            "transitions" => ["!!!not-a-compact!!!"],
            "end_anchor" => end_c,
            "expected" => %{
              "chain" => %{
                "chain_id" => "urn:c:enc",
                "first_sequence" => 1,
                "last_sequence" => 1,
                "row_count" => 1,
                "previous_hash" => Base.url_encode64(zero, padding: false),
                "last_hash" => Base.url_encode64(enc1.hash, padding: false)
              },
              "start_anchor" => %{
                "anchor_id" => "urn:a:encs",
                "anchored_at" => 1_000,
                "chain_id" => "urn:c:enc",
                "sequence" => 0,
                "chain_hash" => Base.url_encode64(zero, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "end_anchor" => %{
                "anchor_id" => "urn:a:ence",
                "anchored_at" => 2_000,
                "chain_id" => "urn:c:enc",
                "sequence" => 1,
                "chain_hash" => Base.url_encode64(enc1.hash, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(sfp, padding: false)
              },
              "transitions" => []
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == false
  end

  test "expected_transitions empty verify-side arm (L941) via verify_anchored_export without transitions" do
    # expected with NO "transitions" key -> expected_transitions(nil) -> [] (L951/L941). The
    # archive has no transitions, so verify still succeeds and agreement is on the facts.
    alias BoundedAuthorityProtocol.V1
    {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<101::256>>)
    zero = <<0::256>>

    e1 = %V1.ConsumptionEntry{
      chain_id: "urn:c:et",
      sequence: 1,
      previous_hash: zero,
      commitment: :crypto.hash(:sha256, "c")
    }

    {:ok, enc1} = V1.encode_consumption_entry(e1, %{})

    anchor_start = %V1.BoundaryAnchor{
      anchor_id: "urn:a:ets",
      anchored_at: 1_000,
      chain_id: "urn:c:et",
      sequence: 0,
      chain_hash: zero,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, ssi} = V1.boundary_anchor_signing_input(anchor_start, %{})
    ssig = :crypto.sign(:eddsa, :ed25519, ssi.message, [priv_a, :ed25519])
    {:ok, start_c} = V1.assemble_compact(ssi, ssig)

    anchor_end = %V1.BoundaryAnchor{
      anchor_id: "urn:a:ete",
      anchored_at: 2_000,
      chain_id: "urn:c:et",
      sequence: 1,
      chain_hash: enc1.hash,
      key_id: "ka",
      public_key: pub_a
    }

    {:ok, esi} = V1.boundary_anchor_signing_input(anchor_end, %{})
    esig = :crypto.sign(:eddsa, :ed25519, esi.message, [priv_a, :ed25519])
    {:ok, end_c} = V1.assemble_compact(esi, esig)
    {:ok, fp} = V1.Jwk.public_key_thumbprint_raw(pub_a, %{})

    export_input = %V1.AnchoredExportInput{
      rows: [enc1.bytes],
      start_anchor: start_c,
      transitions: [],
      end_anchor: end_c
    }

    expected_struct = %V1.ExpectedExport{
      chain: %V1.ExpectedChain{
        chain_id: "urn:c:et",
        first_sequence: 1,
        last_sequence: 1,
        row_count: 1,
        previous_hash: zero,
        last_hash: enc1.hash,
        bounds: %{}
      },
      start_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:ets",
        anchored_at: 1_000,
        chain_id: "urn:c:et",
        sequence: 0,
        chain_hash: zero,
        key_id: "ka",
        key_fingerprint: fp,
        bounds: %{}
      },
      transitions: [],
      end_anchor: %V1.ExpectedAnchor{
        anchor_id: "urn:a:ete",
        anchored_at: 2_000,
        chain_id: "urn:c:et",
        sequence: 1,
        chain_hash: enc1.hash,
        key_id: "ka",
        key_fingerprint: fp,
        bounds: %{}
      },
      bounds: %{}
    }

    {:ok, export} = V1.encode_anchored_export(export_input, expected_struct)

    # NOTE: expected omits "transitions" entirely -> expected_transitions(nil) -> [] (L941).
    result =
      run_one(
        case_obj(
          "verify-export-empty-transitions",
          "verify_anchored_export",
          "valid",
          %{
            "chunks" => Enum.map(export.chunks, &Base.url_encode64(&1, padding: false)),
            "version" => "v1",
            "keys" => [
              %{
                "key_id" => "ka",
                "public_key" => Base.url_encode64(pub_a, padding: false),
                "valid_from" => 0
              }
            ],
            "expected" => %{
              "chain" => %{
                "chain_id" => "urn:c:et",
                "first_sequence" => 1,
                "last_sequence" => 1,
                "row_count" => 1,
                "previous_hash" => Base.url_encode64(zero, padding: false),
                "last_hash" => Base.url_encode64(enc1.hash, padding: false)
              },
              "start_anchor" => %{
                "anchor_id" => "urn:a:ets",
                "anchored_at" => 1_000,
                "chain_id" => "urn:c:et",
                "sequence" => 0,
                "chain_hash" => Base.url_encode64(zero, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(fp, padding: false)
              },
              "end_anchor" => %{
                "anchor_id" => "urn:a:ete",
                "anchored_at" => 2_000,
                "chain_id" => "urn:c:et",
                "sequence" => 1,
                "chain_hash" => Base.url_encode64(enc1.hash, padding: false),
                "key_id" => "ka",
                "key_fingerprint" => Base.url_encode64(fp, padding: false)
              },
              "digest" => Base.url_encode64(export.digest, padding: false),
              "object_version" => "v1"
            }
          },
          %{"verdict" => "valid"}
        )
      )

    assert result.agree == true
  end

  defp corpus_classes,
    do:
      ~w(valid boundary_near exact_bound maximum_plus_one invalid_duplicate invalid_encoding invalid_algorithm invalid_key invalid_claim invalid_time invalid_nonce invalid_uri invalid_request invalid_selector invalid_limit tamper_meaningful_byte)
end
