defmodule BoundedAuthorityProtocol.ArchitectureGate do
  @moduledoc false

  @approved_dependencies %{
    credo: {"~> 1.7", [:dev, :test]},
    dialyxir: {"~> 1.4", [:dev, :test]},
    ex_doc: {"~> 0.40.3", [:dev, :test]},
    jsonschex: {"~> 0.8.1", [:dev, :test]},
    mix_audit: {"~> 2.1", [:dev, :test]},
    sbom: {"~> 0.10.0", [:dev, :test]},
    stream_data: {"~> 1.1", [:dev, :test]}
  }

  @compiled_dynamic_allowances %{
    "Elixir.BoundedAuthorityProtocol.V1.AnchorFacts.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportFacts.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportInput.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportCodec.beam" => %{
      {:encode, 2} => %{variable_call: 13},
      {:parse_archive, 2} => %{variable_call: 10},
      {:parse_expected_transitions, 5} => %{variable_call: 2},
      {:parse_header, 2} => %{variable_call: 18},
      {:read_frame, 2} => %{variable_call: 3},
      {:read_transition_frames, 5} => %{variable_call: 2},
      {:validate_expected_anchored_export, 2} => %{variable_call: 3},
      {:validate_expected_export, 2} => %{variable_call: 18},
      {:validate_expected_key_path, 6} => %{variable_call: 3},
      {:validate_key_chain, 5} => %{variable_call: 4},
      {:verify, 3} => %{variable_call: 20},
      {:verify_transitions, 7} => %{variable_call: 2}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ArchivedObject.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Bounds.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchor.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchorCodec.beam" => %{
      {:parse, 2} => %{variable_call: 27},
      {:signing_input, 2} => %{variable_call: 5},
      {:validate_anchor, 2} => %{variable_call: 3},
      {:verify, 3} => %{variable_call: 16}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ChainFacts.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ChainInput.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ConsumptionEntry.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ConsumptionChain.beam" => %{
      {:check, 2} => %{variable_call: 5},
      {:check_rows, 5} => %{variable_call: 4},
      {:encode, 2} => %{variable_call: 4},
      {:parse_row, 2} => %{variable_call: 10}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ContextValidation.beam" => %{
      {:expected_transition, 2} => %{variable_call: 2}
    },
    "Elixir.BoundedAuthorityProtocol.V1.EncodedAnchoredExport.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.EncodedConsumptionEntry.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchor.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchoredExport.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ExpectedChain.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ExpectedExport.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.ExpectedKeyTransition.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.HistoricalKeyChain.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.HistoricalPublicKey.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Json.Container.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Json.JsonValue.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Json.Root.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.KeyLocator.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.KeyTransition.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionCodec.beam" => %{
      {:parse, 2} => %{variable_call: 27},
      {:signing_input, 2} => %{variable_call: 6},
      {:validate_transition_input, 2} => %{variable_call: 5},
      {:verify, 4} => %{variable_call: 21}
    },
    "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionFacts.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Violation.beam" => %{
      {:__struct__, 1} => %{enum_reduce: 1}
    },
    "Elixir.BoundedAuthorityProtocol.V1.beam" => %{
      {:untrusted_key_locator, 2} => %{variable_call: 8}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Base64Url.beam" => %{
      {:decode, 2} => %{variable_call: 7}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Json.beam" => %{
      {:decode, 2} => %{variable_call: 2},
      {:parse_unsigned_number, 1} => %{variable_call: 3}
    },
    "Elixir.BoundedAuthorityProtocol.V1.Runtime.beam" => %{
      {:decode_audiences, 2} => %{variable_call: 2},
      {:decode_grant_fields, 3} => %{variable_call: 23},
      {:decode_proof_fields, 3} => %{variable_call: 25},
      {:encode_operation, 2} => %{variable_call: 3},
      {:encode_operations, 2} => %{variable_call: 3},
      {:encode_selector, 2} => %{variable_call: 5},
      {:fixed, 1} => %{variable_call: 1},
      {:grant_json, 2} => %{variable_call: 8},
      {:map_ok, 3} => %{variable_call: 1},
      {:operation, 2} => %{variable_call: 6},
      {:operations, 2} => %{variable_call: 2},
      {:proof_json, 2} => %{variable_call: 13},
      {:selector, 2} => %{variable_call: 7},
      {:validate_expected_request, 2} => %{variable_call: 10},
      {:verify_grant_parsed, 4} => %{variable_call: 8},
      {:verify_proof_parsed, 5} => %{variable_call: 15}
    }
  }

  @bap04_struct_beams ~w(
    Elixir.BoundedAuthorityProtocol.V1.AnchorFacts.beam
    Elixir.BoundedAuthorityProtocol.V1.AnchoredExportFacts.beam
    Elixir.BoundedAuthorityProtocol.V1.AnchoredExportInput.beam
    Elixir.BoundedAuthorityProtocol.V1.ArchivedObject.beam
    Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchor.beam
    Elixir.BoundedAuthorityProtocol.V1.ChainFacts.beam
    Elixir.BoundedAuthorityProtocol.V1.ChainInput.beam
    Elixir.BoundedAuthorityProtocol.V1.ConsumptionEntry.beam
    Elixir.BoundedAuthorityProtocol.V1.EncodedAnchoredExport.beam
    Elixir.BoundedAuthorityProtocol.V1.EncodedConsumptionEntry.beam
    Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchor.beam
    Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchoredExport.beam
    Elixir.BoundedAuthorityProtocol.V1.ExpectedChain.beam
    Elixir.BoundedAuthorityProtocol.V1.ExpectedExport.beam
    Elixir.BoundedAuthorityProtocol.V1.ExpectedKeyTransition.beam
    Elixir.BoundedAuthorityProtocol.V1.HistoricalKeyChain.beam
    Elixir.BoundedAuthorityProtocol.V1.HistoricalPublicKey.beam
    Elixir.BoundedAuthorityProtocol.V1.KeyTransition.beam
    Elixir.BoundedAuthorityProtocol.V1.KeyTransitionFacts.beam
  )
  @struct_exports [
    __info__: 1,
    __struct__: 0,
    __struct__: 1,
    module_info: 0,
    module_info: 1
  ]

  @compiled_export_allowances Map.merge(
                                %{
                                  "Elixir.BoundedAuthorityProtocol.V1.beam" => [
                                    __info__: 1,
                                    assemble_compact: 2,
                                    assemble_compact: 3,
                                    boundary_anchor_signing_input: 2,
                                    check_chain: 2,
                                    check_envelope: 2,
                                    decode_grant: 2,
                                    decode_proof: 2,
                                    encode_anchored_export: 2,
                                    encode_consumption_entry: 2,
                                    grant_signing_input: 2,
                                    key_transition_signing_input: 2,
                                    module_info: 0,
                                    module_info: 1,
                                    proof_signing_input: 2,
                                    request_digest: 3,
                                    untrusted_key_locator: 1,
                                    untrusted_key_locator: 2,
                                    verify_anchored_export: 3,
                                    verify_grant: 3,
                                    verify_historical_anchor: 3,
                                    verify_key_transition: 4
                                  ],
                                  "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportCodec.beam" =>
                                    [
                                      __info__: 1,
                                      encode: 2,
                                      module_info: 0,
                                      module_info: 1,
                                      verify: 3
                                    ],
                                  "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchorCodec.beam" =>
                                    [
                                      __info__: 1,
                                      module_info: 0,
                                      module_info: 1,
                                      parse: 2,
                                      signing_input: 2,
                                      verify: 3
                                    ],
                                  "Elixir.BoundedAuthorityProtocol.V1.ConsumptionChain.beam" => [
                                    __info__: 1,
                                    check: 2,
                                    encode: 2,
                                    module_info: 0,
                                    module_info: 1,
                                    parse_row: 2
                                  ],
                                  "Elixir.BoundedAuthorityProtocol.V1.ContextValidation.beam" => [
                                    __info__: 1,
                                    distinct_fingerprints: 3,
                                    expected_anchor: 2,
                                    expected_chain: 2,
                                    expected_transition: 2,
                                    historical_key: 2,
                                    module_info: 0,
                                    module_info: 1
                                  ],
                                  "Elixir.BoundedAuthorityProtocol.V1.FixedBytes.beam" => [
                                    __info__: 1,
                                    equal?: 2,
                                    module_info: 0,
                                    module_info: 1
                                  ],
                                  "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionCodec.beam" =>
                                    [
                                      __info__: 1,
                                      module_info: 0,
                                      module_info: 1,
                                      parse: 2,
                                      signing_input: 2,
                                      verify: 4
                                    ],
                                  "Elixir.BoundedAuthorityProtocol.V1.StringOrUri.beam" => [
                                    __info__: 1,
                                    module_info: 0,
                                    module_info: 1,
                                    valid?: 1
                                  ],
                                  "Elixir.BoundedAuthorityProtocol.V1.Runtime.beam" => [
                                    __info__: 1,
                                    assemble_compact: 3,
                                    boundary_anchor_signing_input: 2,
                                    check_chain: 2,
                                    check_envelope: 2,
                                    decode_grant: 2,
                                    decode_proof: 2,
                                    encode_anchored_export: 2,
                                    encode_consumption_entry: 2,
                                    grant_signing_input: 2,
                                    key_transition_signing_input: 2,
                                    module_info: 0,
                                    module_info: 1,
                                    proof_signing_input: 2,
                                    verify_anchored_export: 3,
                                    verify_grant: 3,
                                    verify_historical_anchor: 3,
                                    verify_key_transition: 4
                                  ]
                                },
                                Map.new(@bap04_struct_beams, &{&1, @struct_exports})
                              )

  @module_categories %{
    "Ecto" => :database,
    "Postgrex" => :database,
    "Req" => :http,
    "Finch" => :http,
    "Mint" => :http,
    "Plug" => :http,
    "Ash" => :product,
    "Beamline" => :product,
    "QorPay" => :product,
    "Qorpay" => :product,
    "BoundedAuthority" => :private_runtime,
    "Oban" => :private_runtime,
    "Reactor" => :private_runtime,
    "File" => :filesystem,
    "IO" => :filesystem,
    "Port" => :process,
    "GenServer" => :otp_service,
    "Supervisor" => :otp_service,
    "DynamicSupervisor" => :otp_service,
    "Agent" => :otp_service,
    "Task" => :otp_service,
    "Registry" => :otp_service,
    "Access" => :dynamic_dispatch,
    "Enum" => :dynamic_dispatch,
    "Stream" => :dynamic_dispatch,
    "Enumerable" => :dynamic_dispatch,
    "Collectable" => :dynamic_dispatch,
    "Node" => :network
  }

  @fact_source_paths [
    "lib/bounded_authority_protocol/v1/anchor_facts.ex",
    "lib/bounded_authority_protocol/v1/anchored_export_facts.ex",
    "lib/bounded_authority_protocol/v1/chain_facts.ex",
    "lib/bounded_authority_protocol/v1/envelope_facts.ex",
    "lib/bounded_authority_protocol/v1/grant_facts.ex",
    "lib/bounded_authority_protocol/v1/key_transition_facts.ex"
  ]

  @chain_codec_source_paths [
    "lib/bounded_authority_protocol/v1/anchored_export_codec.ex",
    "lib/bounded_authority_protocol/v1/boundary_anchor_codec.ex",
    "lib/bounded_authority_protocol/v1/consumption_chain.ex",
    "lib/bounded_authority_protocol/v1/key_transition_codec.ex"
  ]

  @erlang_module_categories %{
    diameter: :network,
    diameter_config: :network,
    diameter_peer: :network,
    diameter_sctp: :network,
    diameter_service: :network,
    diameter_tcp: :network,
    erl_epmd: :network,
    erpc: :network,
    file: :filesystem,
    filelib: :filesystem,
    ftp: :network,
    gen_sctp: :network,
    gen_tcp: :network,
    gen_udp: :network,
    httpd: :network,
    ssl: :network,
    socket: :network,
    ssh: :network,
    ssh_connection: :network,
    tftp: :network,
    httpc: :network,
    inets: :network,
    inet: :network,
    inet6_tcp: :network,
    inet6_udp: :network,
    inet_db: :network,
    inet_dns: :network,
    inet_res: :network,
    inet_tcp: :network,
    inet_udp: :network,
    net_adm: :network,
    net_kernel: :network,
    rpc: :network,
    gen_tcp_socket: :network,
    gen_udp_socket: :network,
    socket_registry: :network,
    telemetry: :telemetry,
    atomics: :process,
    counters: :process,
    ets: :process,
    dets: :process,
    global: :process,
    persistent_term: :process,
    pg: :process,
    mnesia: :database,
    os: :system_env,
    rand: :randomness
  }

  @application_env_functions ~w(delete_env fetch_env fetch_env! get_all_env get_env put_env)a
  @system_env_functions ~w(delete_env fetch_env fetch_env! get_env put_env)a
  @system_clock_functions ~w(monotonic_time os_time system_time unique_integer)a
  @process_dictionary_functions ~w(delete get get_keys put)a
  @process_functions ~w(alive? cancel_timer demonitor exit flag info link list monitor read_timer register send_after sleep unlink unregister whereis)a
  @erlang_clock_functions ~w(monotonic_time system_time unique_integer)a
  @erlang_process_functions ~w(demonitor exit group_leader link make_ref monitor monitor_node open_port port_close port_command port_connect port_control port_info port_to_list ports process_display process_flag process_info processes register registered send send_after spawn spawn_link spawn_monitor suspend_process system_flag trace trace_delivered trace_info trace_pattern unlink unregister whereis)a
  @erlang_dictionary_functions ~w(erase get get_keys put)a
  @code_evaluation_functions ~w(compile_file eval_file eval_quoted eval_string load_file require_file)a
  @dynamic_module_functions ~w(concat create safe_concat)a
  @crypto_random_functions ~w(generate_key generate_key_nif rand_seed rand_seed_alg rand_uniform strong_rand_bytes)a
  @public_key_random_functions ~w(generate_key)a
  @local_process_functions ~w(exit make_ref self send spawn spawn_link spawn_monitor)a
  @local_protocol_dispatch_functions ~w(inspect to_string)a
  @implicit_execution_attributes ~w(after_compile after_verify before_compile behaviour compile derive external_resource on_definition on_load)a
  @kernel_callback_functions ~w(get_and_update_in get_in pop_in tap then update_in)a
  @map_callback_functions ~w(filter get_and_update get_and_update! get_lazy merge new put_new_lazy reject replace_lazy update update!)a
  @map_set_callback_functions ~w(filter reject)a
  @keyword_callback_functions ~w(filter get_and_update get_and_update! get_lazy merge new pop_lazy put_new_lazy reject replace_lazy update update!)a
  @list_callback_functions ~w(myers_difference update_at)a
  @string_callback_functions ~w(replace)a
  @erlang_callback_functions %{
    lists:
      ~w(all any dropwhile filter filtermap flatlength flatmap foldl foldr foreach keymap map mapfoldl mapfoldr merge predmerge partition search sort splitwith takewhile uniq usort zipwith zipwith3)a,
    maps:
      ~w(filter filtermap fold foreach groups_from_list intersect_with map merge_with update_with)a
  }
  @approved_erlang_runtime_functions %{
    binary: ~w(copy split)a,
    crypto: ~w(hash hash_equals hash_final hash_init hash_update verify)a,
    erlang:
      ~w(+ - * / ++ -- < <= == === =:= > >= and band binary_part binary_to_float binary_to_integer bnot bor bsl bsr bxor byte_size div element error get_module_info hd integer_to_binary is_atom is_binary is_bitstring is_boolean is_float is_function is_integer is_list is_map is_map_key is_number is_pid is_port is_reference is_tuple length map_get map_size max min not or raise rem round setelement size tl trunc tuple_size xor)a,
    json: ~w(decode)a,
    maps: ~w(find merge put to_list)a,
    elixir_erl_pass: ~w(no_parens_remote)a
  }

  @approved_local_aliases ~w(AnchorFacts AnchoredExportCodec AnchoredExportFacts
    AnchoredExportInput ArchivedObject Base64Url BoundaryAnchor BoundaryAnchorCodec Bounds
    ChainFacts ChainInput CompactJws ConsumptionChain ConsumptionEntry Container ContextValidation Credentials
    Corpus DecodedGrant DecodedProof EncodedAnchoredExport EncodedConsumptionEntry EnvelopeFacts
    ExpectedAnchor ExpectedAnchoredExport ExpectedChain ExpectedExport ExpectedGrant
    ExpectedKeyTransition ExpectedRequest FixedBytes Grant GrantFacts HistoricalKeyChain
    HistoricalPublicKey Jcs Json JsonValue Jwk KeyLocator KeyTransition KeyTransitionCodec
    KeyTransitionFacts Operation Proof Report RequestDigest Root Runner Runtime Selector SigningInput
    TrustedIssuer Uri Violation)
  @approved_struct_fields ~w(array_items compact_bytes count decoded_segment_bytes depth
    encoded_segment_bytes float_magnitude integer_magnitude json_bytes key_bytes kid_bytes kind
    level nodes number_lexeme_bytes object_members seen string_bytes total_nodes value values
    audiences clock_skew digest_bytes identifier_bytes method_bytes nonce_bytes one_of_values
    operation_bytes operations path_segments proof_max_age public_key_bytes selectors signature_bytes
    uri_bytes message payload_segment protected_segment audience bounds cast_arguments evaluation_time
    invocation_id issuer method nonce operation target_uri trusted_issuer public_key key_id expires_at
    grant_id holder_thumbprint issued_at not_before decoded grant_hash jcs_bytes proof_id request_hash
    proof_issued_at signature grant_compact holder_public_key anchor_bytes archive_bytes
    archive_chunks archive_header_bytes chain_row_bytes chain_rows key_transitions
    object_version_bytes anchor_id anchored_at chain_hash chain_id commitment previous_hash
    sequence bytes hash rows first_sequence last_sequence row_count last_hash key_fingerprint
    current_key_id current_key_fingerprint current_public_key next_key_id next_key_fingerprint
    next_public_key transition_id effective_at start_anchor end_anchor transitions chunks digest
    byte_count keys valid_from valid_before verification trust authorization start_anchor_id
    start_anchored_at start_key_fingerprint end_anchor_id end_anchored_at end_key_fingerprint
    transition_count object_version version chain header start_anchor_parsed end_anchor_parsed
    transition_parsed index index_bytes cases raws case_ids id surface class input expected
    bound_profile tamper verdict agree agreed disagreed agreement exit_status total kid
    issuer_key_fingerprint matched_audience)a

  def check(root, opts \\ []) do
    root = Path.expand(root)

    violations =
      project_violations(root) ++
        source_violations(root) ++
        if Keyword.get(opts, :compiled, true),
          do: check_compiled(root),
          else: []

    violations
    |> Enum.uniq()
    |> Enum.sort_by(&{&1.category, &1.path, &1.detail})
  end

  def check_compiled(root) do
    root
    |> Path.expand()
    |> Path.join("_build/*/lib/bounded_authority_protocol/ebin")
    |> Path.wildcard()
    |> case do
      [] ->
        [
          violation(
            :compiled_artifact,
            "_build",
            "compiled bounded_authority_protocol application is missing"
          )
        ]

      ebin_paths ->
        ebin_paths
        |> Enum.flat_map(&compiled_violations/1)
        |> Enum.uniq()
        |> Enum.sort_by(&{&1.category, &1.path, &1.detail})
    end
  end

  def format(violations) do
    Enum.map_join(violations, "\n", fn violation ->
      "#{violation.category} #{violation.path}: #{violation.detail}"
    end)
  end

  defp project_violations(root) do
    path = Path.join(root, "mix.exs")

    with {:ok, source} <- File.read(path),
         {:ok, ast} <- Code.string_to_quoted(source, file: path),
         {:ok, dependencies} <- dependencies_from_ast(ast) do
      application_violations(ast) ++
        dependency_violations(dependencies) ++
        ignore_modules_violations(ast)
    else
      {:error, reason} ->
        [
          violation(
            :project_parse_failure,
            "mix.exs",
            inspect(reason, limit: 10, printable_limit: 200)
          )
        ]
    end
  end

  # C1 carve-out pin (plan-review F6): the test_coverage ignore_modules list must equal EXACTLY
  # [BoundedAuthorityProtocol.Conformance.Cli.Main] — the escript entry whose only behavior is
  # System.halt (untestable in-VM). A second entry or a missing entry is a violation: a second
  # entry hides untested code, a missing entry fails the coverage threshold.
  @cli_main_module "BoundedAuthorityProtocol.Conformance.Cli.Main"

  # The CLI I/O carve-out module. A fully-qualified reference to it (or a submodule) from OUTSIDE
  # the conformance directory leaks the impure CLI into the pure core; the bare-alias form is
  # already caught by the module-allowance discipline, but the fully-qualified form otherwise passes
  # through the blanket `root == "BoundedAuthorityProtocol"` allow. Only Cli.Main (the escript entry,
  # itself inside conformance/) and in-conformance/ references are exempt.
  @conformance_dir "lib/bounded_authority_protocol/conformance/"

  defp ignore_modules_violations(ast) do
    case ignore_modules_from_ast(ast) do
      {:ok, [@cli_main_module]} ->
        []

      {:ok, other} ->
        [
          violation(
            :ignore_modules_drift,
            "mix.exs",
            "test_coverage ignore_modules must equal exactly [#{@cli_main_module}], got: #{inspect(other)}"
          )
        ]

      :error ->
        [
          violation(
            :ignore_modules_drift,
            "mix.exs",
            "test_coverage ignore_modules is missing or unparseable"
          )
        ]
    end
  end

  defp ignore_modules_from_ast(ast) do
    {_ast, ignore} =
      Macro.prewalk(ast, nil, fn
        # In a keyword-list literal (`[test_coverage: [...]]`), keyword pairs are 2-tuples.
        {:test_coverage, opts} = node, _acc when is_list(opts) ->
          {node, Keyword.get(opts, :ignore_modules)}

        node, acc ->
          {node, acc}
      end)

    case ignore do
      nil -> :error
      value -> {:ok, ignore_module_names(value)}
    end
  end

  defp ignore_module_names({:__aliases__, _, segments}) do
    [Enum.join(segments, ".")]
  end

  defp ignore_module_names(list) when is_list(list) do
    Enum.map(list, fn
      {:__aliases__, _, segments} -> Enum.join(segments, ".")
      name when is_atom(name) -> Atom.to_string(name)
    end)
  end

  defp ignore_module_names(_), do: []

  defp dependencies_from_ast(ast) do
    {_ast, bodies} =
      Macro.prewalk(ast, [], fn
        {:defp, _meta, [{:deps, _call_meta, args}, [do: body]]} = node, acc
        when args in [nil, []] ->
          {node, [body | acc]}

        node, acc ->
          {node, acc}
      end)

    case bodies do
      [body] when is_list(body) ->
        body
        |> Enum.map(&dependency_from_ast/1)
        |> collect_ok()

      [] ->
        {:error, :missing_deps_function}

      _many ->
        {:error, :ambiguous_deps_function}
    end
  end

  defp dependency_from_ast({:{}, _meta, [app, requirement, options]})
       when is_atom(app) and is_binary(requirement) and is_list(options) do
    if Keyword.keyword?(options) do
      {:ok, %{app: app, requirement: requirement, options: options}}
    else
      {:error, {:invalid_dependency_options, app}}
    end
  end

  defp dependency_from_ast({app, requirement})
       when is_atom(app) and is_binary(requirement) do
    {:ok, %{app: app, requirement: requirement, options: []}}
  end

  defp dependency_from_ast(other), do: {:error, {:invalid_dependency, Macro.to_string(other)}}

  defp collect_ok(results) do
    case Enum.find(results, &match?({:error, _reason}, &1)) do
      nil -> {:ok, Enum.map(results, fn {:ok, value} -> value end)}
      error -> error
    end
  end

  defp application_violations(ast) do
    {_ast, findings} =
      Macro.prewalk(ast, [], fn
        {kind, _meta, [{:application, _call_meta, _args}, [do: body]]} = node, acc
        when kind in [:def, :defp] ->
          if body == [extra_applications: [:crypto]] do
            {node, acc}
          else
            {node,
             [
               violation(
                 :application_callback,
                 "mix.exs",
                 "application/0 must be exactly [extra_applications: [:crypto]]"
               )
               | acc
             ]}
          end

        {:mod, _value} = node, acc ->
          {node,
           [
             violation(:application_callback, "mix.exs", "application mod entry is forbidden")
             | acc
           ]}

        node, acc ->
          {node, acc}
      end)

    findings
  end

  defp dependency_violations(dependencies) do
    by_app = Map.new(dependencies, &{&1.app, &1})

    unexpected =
      dependencies
      |> Enum.reject(&Map.has_key?(@approved_dependencies, &1.app))
      |> Enum.map(fn dependency ->
        violation(
          :dependency_policy,
          "mix.exs",
          "unapproved dependency #{inspect(dependency.app)}"
        )
      end)

    missing =
      @approved_dependencies
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(by_app, &1))
      |> Enum.map(fn app ->
        violation(
          :dependency_policy,
          "mix.exs",
          "approved development tool #{inspect(app)} is missing"
        )
      end)

    invalid =
      dependencies
      |> Enum.flat_map(fn dependency ->
        case Map.fetch(@approved_dependencies, dependency.app) do
          :error ->
            []

          {:ok, {requirement, environments}} ->
            dependency_option_violations(dependency, requirement, environments)
        end
      end)

    unexpected ++ missing ++ invalid
  end

  defp dependency_option_violations(dependency, requirement, environments) do
    options = dependency.options
    only = options |> Keyword.get(:only) |> List.wrap() |> Enum.sort()
    expected_only = Enum.sort(environments)

    checks = [
      {dependency.requirement == requirement,
       "requirement must be #{inspect(requirement)}, got #{inspect(dependency.requirement)}"},
      {only == expected_only, "only must be #{inspect(expected_only)}, got #{inspect(only)}"},
      {Keyword.get(options, :runtime) == false, "runtime must be false"},
      {not Keyword.has_key?(options, :path), "path dependencies are forbidden"},
      {not Keyword.has_key?(options, :git), "git dependencies are forbidden"},
      {not Keyword.has_key?(options, :github), "GitHub dependencies are forbidden"}
    ]

    for {passed?, detail} <- checks,
        not passed? do
      violation(
        :dependency_policy,
        "mix.exs",
        "#{inspect(dependency.app)} #{detail}"
      )
    end
  end

  defp source_violations(root) do
    [
      Path.join(root, "lib/bounded_authority_protocol.ex"),
      Path.join(root, "lib/bounded_authority_protocol/**/*.ex")
    ]
    |> Enum.flat_map(&Path.wildcard(&1, match_dot: true))
    |> Enum.sort()
    |> Enum.flat_map(&source_file_violations(&1, root))
  end

  defp source_file_violations(path, root) do
    relative = Path.relative_to(path, root)

    with {:ok, source} <- File.read(path),
         {:ok, ast} <- Code.string_to_quoted(source, file: path) do
      {_ast, violations} =
        Macro.prewalk(ast, [], fn node, acc ->
          {node, node_violations(node, relative) ++ acc}
        end)

      violations ++
        source_dynamic_allowance_violations(ast, relative) ++
        source_contract_violations(ast, relative)
    else
      {:error, reason} ->
        [
          violation(
            :parse_failure,
            relative,
            inspect(reason, limit: 10, printable_limit: 200)
          )
        ]
    end
  end

  defp source_dynamic_allowance_violations(
         ast,
         "lib/bounded_authority_protocol/v1/runtime.ex" = path
       ) do
    {_ast, count} =
      Macro.prewalk(ast, 0, fn
        {{:., _dot_meta, [_callable_ast]}, _meta, args} = node, count when is_list(args) ->
          {node, count + 1}

        node, count ->
          {node, count}
      end)

    if count == 2 do
      []
    else
      [
        violation(
          :dynamic_dispatch,
          path,
          "source dynamic-call allowance expected 2, got #{count}"
        )
      ]
    end
  end

  defp source_dynamic_allowance_violations(_ast, _path), do: []

  defp source_contract_violations(
         ast,
         "lib/bounded_authority_protocol/v1/fixed_bytes.ex" = path
       ) do
    {_ast, counts} =
      Macro.prewalk(ast, %{hash_equals: 0, ordinary_equality: 0}, fn
        {{:., _dot_meta, [:crypto, :hash_equals]}, _call_meta, [_left, _right]} = node, counts ->
          {node, %{counts | hash_equals: counts.hash_equals + 1}}

        {operator, _meta, [_left, _right]} = node, counts when operator in [:==, :===] ->
          {node, %{counts | ordinary_equality: counts.ordinary_equality + 1}}

        node, counts ->
          {node, counts}
      end)

    if counts == %{hash_equals: 1, ordinary_equality: 1} do
      []
    else
      [
        violation(
          :crypto_contract,
          path,
          "fixed-byte equality must contain one length equality and exactly one :crypto.hash_equals/2"
        )
      ]
    end
  end

  defp source_contract_violations(_ast, _path), do: []

  defp node_violations({:__aliases__, _meta, segments}, path) do
    root = alias_root(segments)
    name = alias_name(segments)

    category =
      cond do
        conformance_cli_leak?(name, path) -> :unapproved_runtime
        root == "BoundedAuthorityProtocol" -> nil
        root == :dynamic -> :dynamic_module
        root in @approved_local_aliases -> nil
        approved_source_module?(path, root) -> nil
        root in ~w(ArgumentError Base ErlangError Exception Kernel Map) -> nil
        category = module_category(root) -> category
        true -> :unapproved_runtime
      end

    category_violation(category, path, "forbidden module #{name}")
  end

  defp node_violations({:alias, _meta, [target, options]}, path) when is_list(options) do
    alias_shadow_violations(target, options, path)
  end

  defp node_violations({:alias, _meta, [target]}, path) do
    alias_shadow_violations(target, [], path)
  end

  defp node_violations({directive, _meta, [target | _options]}, path)
       when directive in [:import, :require, :use] do
    target_name = module_name(target)

    if package_owned_module?(target_name) do
      []
    else
      category_violation(
        :unapproved_runtime,
        path,
        "external #{directive} is forbidden"
      )
    end
  end

  defp node_violations(
         {:@, _meta, [{attribute, _attribute_meta, _arguments}]},
         path
       )
       when attribute in @implicit_execution_attributes do
    category_violation(
      :unapproved_runtime,
      path,
      "implicit execution hook @#{attribute} is forbidden"
    )
  end

  defp node_violations(
         {{:., _dot_meta, [{variable, _variable_meta, context}, field]}, _meta, []},
         _path
       )
       when is_atom(variable) and is_atom(context) and field in @approved_struct_fields,
       do: []

  defp node_violations(
         {{:., _dot_meta, [{:__aliases__, _alias_meta, [:Map]}, :merge]}, _meta, args},
         _path
       )
       when length(args) == 2,
       do: []

  defp node_violations({{:., _dot_meta, [module_ast, function]}, _meta, _args}, path)
       when is_atom(function) do
    module = module_name(module_ast)

    cond do
      approved_source_call?(path, module, function) ->
        []

      conformance_cli_leak?(module, path) ->
        category_violation(
          :unapproved_runtime,
          path,
          "forbidden call #{format_call(module_ast, function)}"
        )

      true ->
        module
        |> mfa_category(function)
        |> category_violation(path, "forbidden call #{format_call(module_ast, function)}")
    end
  end

  defp node_violations({{:., _dot_meta, [_callable_ast]}, _meta, args}, path)
       when is_list(args) do
    if path in [
         "lib/bounded_authority_protocol/v1/runtime.ex",
         "lib/bounded_authority_protocol/conformance/runner.ex",
         "lib/bounded_authority_protocol/conformance/corpus.ex",
         "lib/bounded_authority_protocol/conformance/report.ex",
         "lib/bounded_authority_protocol/conformance/cli.ex"
       ] do
      []
    else
      category_violation(
        :dynamic_dispatch,
        path,
        "forbidden first-class function invocation/#{length(args)}"
      )
    end
  end

  defp node_violations({function, _meta, args}, path)
       when is_atom(function) and is_list(args) do
    category =
      cond do
        function in @local_process_functions -> :process
        function == :receive -> :process
        function in @kernel_callback_functions -> :dynamic_dispatch
        function in @local_protocol_dispatch_functions -> :dynamic_dispatch
        function == :apply -> :dynamic_dispatch
        function in [:binary_to_atom, :list_to_atom] -> :dynamic_module
        true -> nil
      end

    if function == :inspect and path in @fact_source_paths do
      []
    else
      category_violation(category, path, "forbidden local call #{function}/#{length(args)}")
    end
  end

  defp node_violations(_node, _path), do: []

  defp alias_shadow_violations(target, options, path) do
    target_name = module_name(target)
    binding_name = alias_binding_name(target, options)

    if binding_name == "BoundedAuthorityProtocol" and not package_owned_module?(target_name) do
      category_violation(
        :unapproved_runtime,
        path,
        "external alias cannot shadow BoundedAuthorityProtocol"
      )
    else
      []
    end
  end

  defp package_owned_module?(module) do
    module = to_string(module)

    module == "BoundedAuthorityProtocol" or
      String.starts_with?(module, "BoundedAuthorityProtocol.") or
      String.starts_with?(module, "Inspect.BoundedAuthorityProtocol.")
  end

  defp module_name({:__aliases__, _meta, segments}), do: alias_name(segments)
  defp module_name(module) when is_atom(module), do: module
  defp module_name(_dynamic), do: :dynamic

  defp alias_root([{:__MODULE__, _meta, _context} | _rest]), do: "BoundedAuthorityProtocol"
  defp alias_root([segment | _rest]) when is_atom(segment), do: Atom.to_string(segment)
  defp alias_root(_segments), do: :dynamic

  defp alias_name(segments) do
    Enum.map_join(segments, ".", fn
      {:__MODULE__, _meta, _context} -> "BoundedAuthorityProtocol"
      segment when is_atom(segment) -> Atom.to_string(segment)
      segment -> Macro.to_string(segment)
    end)
  end

  # A fully-qualified BoundedAuthorityProtocol.Conformance.Cli(.Sub) reference from OUTSIDE the
  # conformance directory. Cli.Main (the escript entry) and any reference from within conformance/
  # are exempt. The bare-alias form is caught separately by the module-allowance discipline; this
  # closes the fully-qualified form that would otherwise pass the blanket BoundedAuthorityProtocol.*
  # allow.
  defp conformance_cli_leak?(module, path) when is_binary(module) do
    cli_carveout_module?(module) and not String.starts_with?(path, @conformance_dir)
  end

  defp conformance_cli_leak?(_module, _path), do: false

  # The Cli carve-out AND its Cli.Main escript entry (which does System.halt + delegates to Cli).
  # Cli.Main is NOT exempted here: nothing in lib legitimately references it (the escript entry
  # point is wired via mix.exs config, which the gate does not scan), so exempting it would let a
  # core module call Cli.Main.main/1 and reach System.halt through the pure core. In-conformance
  # references are exempted by the caller's path check, not by module identity.
  defp cli_carveout_module?(module) do
    module == "BoundedAuthorityProtocol.Conformance.Cli" or
      String.starts_with?(module, "BoundedAuthorityProtocol.Conformance.Cli.")
  end

  defp alias_binding_name(target, options) when is_list(options) do
    case Keyword.get(options, :as) do
      nil ->
        target
        |> module_name()
        |> to_string()
        |> String.split(".")
        |> List.last()

      alias_ast ->
        alias_ast |> module_name() |> to_string() |> String.split(".") |> List.last()
    end
  end

  defp alias_binding_name(target, _options), do: alias_binding_name(target, [])

  defp mfa_category(:dynamic, _function), do: :dynamic_dispatch
  defp mfa_category(module, _function) when module in @approved_local_aliases, do: nil

  defp mfa_category(module, _function) when is_atom(module) and module in [:file, :filelib],
    do: :filesystem

  defp mfa_category(module, _function)
       when is_atom(module) and
              module in [
                :diameter,
                :diameter_config,
                :diameter_peer,
                :diameter_sctp,
                :diameter_service,
                :diameter_tcp,
                :erl_epmd,
                :erpc,
                :ftp,
                :gen_sctp,
                :gen_tcp,
                :gen_tcp_socket,
                :gen_udp,
                :gen_udp_socket,
                :httpc,
                :httpd,
                :inets,
                :inet,
                :inet6_tcp,
                :inet6_udp,
                :inet_db,
                :inet_dns,
                :inet_res,
                :inet_tcp,
                :inet_udp,
                :net_adm,
                :net_kernel,
                :rpc,
                :socket,
                :socket_registry,
                :ssh,
                :ssh_connection,
                :ssl,
                :tftp
              ],
       do: :network

  defp mfa_category(:telemetry, _function), do: :telemetry

  defp mfa_category(module, _function)
       when module in [:atomics, :counters, :dets, :ets, :global, :persistent_term, :pg],
       do: :process

  defp mfa_category(:mnesia, _function), do: :database
  defp mfa_category(:os, _function), do: :system_env
  defp mfa_category(:rand, _function), do: :randomness

  defp mfa_category("Application", function) when function in @application_env_functions,
    do: :application_env

  defp mfa_category("Application", _function), do: :otp_service

  defp mfa_category("System", function) when function in @system_env_functions, do: :system_env
  defp mfa_category("System", function) when function in @system_clock_functions, do: :clock
  defp mfa_category("System", :cmd), do: :process
  defp mfa_category("System", :shell), do: :process

  defp mfa_category("DateTime", function) when function in [:now, :now!, :utc_now],
    do: :clock

  defp mfa_category("NaiveDateTime", :utc_now), do: :clock
  defp mfa_category("Date", :utc_today), do: :clock
  defp mfa_category("Time", :utc_now), do: :clock

  defp mfa_category("Process", function) when function in @process_dictionary_functions,
    do: :process_dictionary

  defp mfa_category("Process", function) when function in @process_functions, do: :process
  defp mfa_category("Process", _function), do: :process
  defp mfa_category("Kernel", :apply), do: :dynamic_dispatch
  defp mfa_category("Base", function) when function in [:url_decode64, :url_encode64], do: nil
  defp mfa_category("String", :valid?), do: nil
  defp mfa_category("URI", :new), do: nil

  defp mfa_category("Map", function)
       when function in [:fetch, :from_struct, :has_key?, :put, :to_list],
       do: nil

  defp mfa_category("Kernel", function) when function in [:struct!, :inspect], do: nil
  defp mfa_category("List", :delete), do: nil
  defp mfa_category("ArgumentError", :exception), do: nil
  defp mfa_category("ErlangError", _function), do: nil
  defp mfa_category("Exception", function) when function in [:exception, :normalize], do: nil
  defp mfa_category("Kernel.Utils", :raise), do: nil

  defp mfa_category("Kernel", function) when function in @local_process_functions,
    do: :process

  defp mfa_category("Kernel", function) when function in @kernel_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category("Kernel", function) when function in @local_protocol_dispatch_functions,
    do: :dynamic_dispatch

  defp mfa_category("Function", :capture), do: :dynamic_dispatch

  defp mfa_category("Map", function) when function in @map_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category("Keyword", function) when function in @keyword_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category("List", function) when function in @list_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category("MapSet", function) when function in @map_set_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category("String", function) when function in @string_callback_functions,
    do: :dynamic_dispatch

  defp mfa_category(:erlang, function) when function in @erlang_clock_functions, do: :clock

  defp mfa_category(:erlang, function) when function in @erlang_dictionary_functions,
    do: :process_dictionary

  defp mfa_category(:erlang, function) when function in [:apply, :make_fun],
    do: :dynamic_dispatch

  defp mfa_category(:erlang, function) when function in @erlang_process_functions, do: :process

  defp mfa_category(:crypto, function) when function in @crypto_random_functions,
    do: :randomness

  defp mfa_category(:public_key, function) when function in @public_key_random_functions,
    do: :randomness

  defp mfa_category(module, function) when is_atom(module) do
    cond do
      function in Map.get(@erlang_callback_functions, module, []) ->
        :dynamic_dispatch

      category = Map.get(@erlang_module_categories, module) ->
        category

      function in Map.get(@approved_erlang_runtime_functions, module, []) ->
        nil

      true ->
        :unapproved_runtime
    end
  end

  defp mfa_category("Code", function) when function in @code_evaluation_functions,
    do: :code_evaluation

  defp mfa_category("Module", function) when function in @dynamic_module_functions,
    do: :dynamic_module

  defp mfa_category("String", function) when function in [:to_atom, :to_existing_atom],
    do: :dynamic_module

  defp mfa_category(module, _function) when is_binary(module) do
    root = module |> String.split(".") |> List.first()

    cond do
      category = module_category(root) -> category
      root == "BoundedAuthorityProtocol" -> nil
      true -> :unapproved_runtime
    end
  end

  defp module_category(root), do: Map.get(@module_categories, root)

  defp approved_source_module?(path, root), do: root in approved_source_modules(path)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/jcs.ex"),
    do: ~w(Enum Integer MapSet String)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/request_digest.ex"),
    do: ~w(Enum)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/runtime.ex"),
    do: ~w(Access Enum MapSet String StringOrUri URI)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/selector.ex"),
    do: ~w(Enum List MapSet String)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/string_or_uri.ex"),
    do: ~w(String URI)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/context_validation.ex"),
    do: ~w(String StringOrUri)

  defp approved_source_modules("lib/bounded_authority_protocol/v1/uri.ex"),
    do: ~w(Enum Integer List)

  defp approved_source_modules(path) when path in @fact_source_paths, do: ~w(Inspect)

  defp approved_source_modules(path) when path in @chain_codec_source_paths,
    do: ~w(Access Enum Map String StringOrUri URI)

  defp approved_source_modules("lib/bounded_authority_protocol/conformance/corpus.ex"),
    do: ~w(Access Bitwise Enum List Map MapSet String)

  defp approved_source_modules("lib/bounded_authority_protocol/conformance/runner.ex"),
    do: ~w(Enum Map String)

  defp approved_source_modules("lib/bounded_authority_protocol/conformance/report.ex"),
    do: ~w(Enum)

  defp approved_source_modules("lib/bounded_authority_protocol/conformance/cli.ex"),
    do: ~w(File IO Path)

  defp approved_source_modules("lib/bounded_authority_protocol/conformance/cli/main.ex"),
    do: ~w(Cli System)

  defp approved_source_modules(_path), do: []

  defp approved_source_call?(
         "lib/bounded_authority_protocol/v1/compact_jws.ex",
         module,
         function
       ),
       do: {module, function} in [{:binary, :match}, {"Map", :new}]

  defp approved_source_call?("lib/bounded_authority_protocol/v1/jcs.ex", module, function),
    do:
      {module, function} in [
        {:binary, :at},
        {:erlang, :float_to_binary},
        {:erlang, :iolist_size},
        {:erlang, :iolist_to_binary},
        {:unicode, :characters_to_binary},
        {"Enum", :map},
        {"Enum", :map_reduce},
        {"Enum", :sort_by},
        {"Integer", :to_string},
        {"MapSet", :new},
        {"MapSet", :size},
        {"String", :downcase},
        {"String", :pad_leading},
        {"String", :valid?}
      ]

  defp approved_source_call?("lib/bounded_authority_protocol/v1/jwk.ex", module, function),
    do: function == :to_string or {module, function} == {"Map", :new}

  defp approved_source_call?(
         "lib/bounded_authority_protocol/v1/string_or_uri.ex",
         module,
         function
       ),
       do: {module, function} in [{:binary, :split}, {"String", :valid?}, {"URI", :new}]

  defp approved_source_call?(
         "lib/bounded_authority_protocol/v1/context_validation.ex",
         module,
         function
       ),
       do: {module, function} in [{"String", :valid?}, {"StringOrUri", :valid?}]

  defp approved_source_call?(path, module, function)
       when path in @chain_codec_source_paths do
    function == :get or
      {module, function} in [
        {:erlang, :iolist_to_binary},
        {"Access", :get},
        {"Enum", :map},
        {"Enum", :sort},
        {"Map", :new},
        {"String", :contains?},
        {"String", :valid?},
        {"StringOrUri", :valid?},
        {"URI", :new}
      ]
  end

  defp approved_source_call?(
         "lib/bounded_authority_protocol/v1/request_digest.ex",
         module,
         function
       ),
       do:
         {module, function} in [
           {:binary, :bin_to_list},
           {"Enum", :all?},
           {"Enum", :reverse}
         ]

  defp approved_source_call?("lib/bounded_authority_protocol/v1/runtime.ex", module, function),
    do:
      {module, function} in [
        {:binary, :bin_to_list},
        {"Access", :get},
        {"Enum", :all?},
        {"Enum", :any?},
        {"Enum", :filter},
        {"Enum", :find_value},
        {"Enum", :map},
        {"Enum", :reverse},
        {"Enum", :sort},
        {"Map", :new},
        {"MapSet", :new},
        {"MapSet", :size},
        {"String", :contains?},
        {"String", :valid?},
        {"StringOrUri", :valid?},
        {"URI", :new}
      ] or
        (module == :dynamic and function in [:name, :public_key]) or
        function == :get

  defp approved_source_call?("lib/bounded_authority_protocol/v1/selector.ex", module, function),
    do:
      {module, function} in [
        {"Enum", :all?},
        {"Enum", :any?},
        {"Enum", :map},
        {"Enum", :zip},
        {"List", :keyfind},
        {"MapSet", :new},
        {"MapSet", :size},
        {"String", :valid?}
      ]

  defp approved_source_call?("lib/bounded_authority_protocol/v1/uri.ex", module, function),
    do:
      {module, function} in [
        {:binary, :at},
        {:binary, :bin_to_list},
        {:binary, :match},
        {:binary, :matches},
        {:erlang, :iolist_to_binary},
        {"Enum", :all?},
        {"Enum", :any?},
        {"Enum", :reverse},
        {"Integer", :to_string},
        {"List", :last}
      ]

  defp approved_source_call?(path, "Inspect.Algebra", :string)
       when path in @fact_source_paths,
       do: true

  # CLI I/O carve-out (C1): exact-path + exact-function allowances. cli.ex may use File.read/1,
  # File.ls/1, File.write/2, File.dir?/1, IO.binwrite/2, and Path.join/2 (the only filesystem/io
  # calls in the verification tool's loader/output path). No halt here.
  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/cli.ex",
         module,
         function
       ),
       do:
         {module, function} in [
           {"File", :read},
           {"File", :ls},
           {"File", :write},
           {"File", :dir?},
           {"IO", :binwrite},
           {"Path", :join}
         ]

  # cli/main.ex is the escript entry: System.halt/1 only (delegates to Cli.run, which is an
  # approved_source_module above). No File/IO here — the two-line entry.
  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/cli/main.ex",
         "System",
         :halt
       ),
       do: true

  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/cli/main.ex",
         "Cli",
         :run
       ),
       do: true

  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/corpus.ex",
         module,
         function
       ),
       do:
         {module, function} in [
           {"Bitwise", :bxor},
           {"Enum", :all?},
           {"Enum", :flat_map},
           {"Enum", :map},
           {"Enum", :reduce},
           {"Enum", :reduce_while},
           {"Enum", :reject},
           {"Enum", :sort_by},
           {"List", :keyfind},
           {"Map", :delete},
           {"Map", :fetch!},
           {"Map", :get},
           {"Map", :keys},
           {"Map", :new},
           {"Map", :update},
           {"MapSet", :equal?},
           {"MapSet", :new},
           {"MapSet", :size},
           {"String", :ends_with?}
         ] or function == :get

  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/runner.ex",
         module,
         function
       ),
       do:
         {module, function} in [
           {"Base", :url_decode64!},
           {"Enum", :all?},
           {"Enum", :map},
           {"Enum", :reduce_while},
           {"Enum", :reverse},
           {"Enum", :sort_by},
           {"Map", :delete},
           {"Map", :get},
           {"Map", :new},
           {"String", :ends_with?}
         ] or function == :get

  defp approved_source_call?(
         "lib/bounded_authority_protocol/conformance/report.ex",
         module,
         function
       ),
       do:
         {module, function} in [
           {"Enum", :count},
           {"Enum", :flat_map}
         ]

  defp approved_source_call?(_path, _module, _function), do: false

  defp category_violation(nil, _path, _detail), do: []
  defp category_violation(category, path, detail), do: [violation(category, path, detail)]

  defp format_call(module_ast, function) do
    "#{Macro.to_string(module_ast)}.#{function}"
  end

  defp compiled_violations(ebin_path) do
    app_path = Path.join(ebin_path, "bounded_authority_protocol.app")

    app_metadata_violations(app_path) ++
      (ebin_path
       |> Path.join("*.beam")
       |> Path.wildcard()
       |> Enum.flat_map(&beam_violations/1))
  end

  defp app_metadata_violations(app_path) do
    case :file.consult(String.to_charlist(app_path)) do
      {:ok, [{:application, :bounded_authority_protocol, properties}]} ->
        applications = properties |> Keyword.get(:applications, []) |> Enum.sort()
        modules = properties |> Keyword.get(:modules, []) |> Enum.sort()

        [
          if(applications == [:crypto, :elixir, :kernel, :stdlib],
            do: nil,
            else:
              violation(
                :compiled_artifact,
                app_path,
                "applications must be [:crypto, :elixir, :kernel, :stdlib], got #{inspect(applications)}"
              )
          ),
          if(
            BoundedAuthorityProtocol in modules and
              Enum.all?(modules, fn module ->
                module
                |> Atom.to_string()
                |> String.replace_prefix("Elixir.", "")
                |> package_owned_module?()
              end),
            do: nil,
            else:
              violation(
                :compiled_artifact,
                app_path,
                "modules must remain inside BoundedAuthorityProtocol, got #{inspect(modules)}"
              )
          ),
          if(Keyword.has_key?(properties, :mod),
            do:
              violation(
                :application_callback,
                app_path,
                "compiled application contains a mod callback"
              ),
            else: nil
          )
        ]
        |> Enum.reject(&is_nil/1)

      {:ok, other} ->
        [
          violation(
            :compiled_artifact,
            app_path,
            "unexpected application metadata #{inspect(other, limit: 5)}"
          )
        ]

      {:error, reason} ->
        [
          violation(
            :compiled_artifact,
            app_path,
            "cannot read application metadata: #{inspect(reason)}"
          )
        ]
    end
  end

  defp beam_violations(path) do
    case :beam_lib.chunks(String.to_charlist(path), [:imports, :exports, :abstract_code]) do
      {:ok,
       {_module,
        [
          imports: imports,
          exports: exports,
          abstract_code: {:raw_abstract_v1, forms}
        ]}} ->
        import_violations(imports, path) ++
          export_violations(exports, path) ++
          abstract_violations(forms, path) ++ dynamic_allowance_violations(forms, path)

      {:error, _module, reason} ->
        [violation(:compiled_artifact, path, "cannot inspect BEAM imports: #{inspect(reason)}")]

      {:ok, {_module, _chunks}} ->
        [
          violation(
            :compiled_artifact,
            path,
            "compiled module is missing inspectable abstract code"
          )
        ]
    end
  end

  defp export_violations(exports, path) do
    case Map.fetch(@compiled_export_allowances, Path.basename(path)) do
      {:ok, expected} ->
        if Enum.sort(exports) == Enum.sort(expected) do
          []
        else
          [
            violation(
              :public_surface,
              path,
              "compiled exports must equal #{inspect(Enum.sort(expected))}, got #{inspect(Enum.sort(exports))}"
            )
          ]
        end

      :error ->
        []
    end
  end

  defp import_violations(imports, path) do
    Enum.flat_map(imports, fn {module, function, arity} ->
      case compiled_import_category(module, function, path) do
        nil ->
          []

        category ->
          [
            violation(
              category,
              path,
              "compiled import #{inspect(module)}.#{function}/#{arity}"
            )
          ]
      end
    end)
  end

  defp compiled_import_category(Elixir.Enum, :reduce, path) do
    if Path.basename(path) in [
         "Elixir.BoundedAuthorityProtocol.V1.AnchorFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportInput.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ArchivedObject.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Bounds.beam",
         "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchor.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ChainFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ChainInput.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ConsumptionEntry.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Credentials.beam",
         "Elixir.BoundedAuthorityProtocol.V1.DecodedGrant.beam",
         "Elixir.BoundedAuthorityProtocol.V1.DecodedProof.beam",
         "Elixir.BoundedAuthorityProtocol.V1.EncodedAnchoredExport.beam",
         "Elixir.BoundedAuthorityProtocol.V1.EncodedConsumptionEntry.beam",
         "Elixir.BoundedAuthorityProtocol.V1.EnvelopeFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchor.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedAnchoredExport.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedChain.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedExport.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedGrant.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedKeyTransition.beam",
         "Elixir.BoundedAuthorityProtocol.V1.ExpectedRequest.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Grant.beam",
         "Elixir.BoundedAuthorityProtocol.V1.GrantFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.HistoricalKeyChain.beam",
         "Elixir.BoundedAuthorityProtocol.V1.HistoricalPublicKey.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.Container.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.JsonValue.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.Root.beam",
         "Elixir.BoundedAuthorityProtocol.V1.KeyLocator.beam",
         "Elixir.BoundedAuthorityProtocol.V1.KeyTransition.beam",
         "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionFacts.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Operation.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Proof.beam",
         "Elixir.BoundedAuthorityProtocol.V1.SigningInput.beam",
         "Elixir.BoundedAuthorityProtocol.V1.TrustedIssuer.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Violation.beam",
         "Elixir.BoundedAuthorityProtocol.Conformance.Corpus.beam",
         "Elixir.BoundedAuthorityProtocol.Conformance.Runner.beam",
         "Elixir.BoundedAuthorityProtocol.Conformance.Report.beam"
       ],
       do: nil,
       else: :dynamic_dispatch
  end

  defp compiled_import_category(module, function, path) do
    module_string = module |> Atom.to_string() |> String.replace_prefix("Elixir.", "")

    cond do
      # Symmetric with the source-AST conformance_cli_leak? check (parallel construction paths must
      # enforce the same invariant): a compiled import of the Cli carve-out from a NON-conformance
      # beam leaks the CLI into the pure core. Catches a macro/codegen-emitted reference the source
      # scan cannot see. Cli.Main and in-conformance beams are exempt (as in the source path).
      cli_carveout_module?(module_string) and not conformance_beam?(path) ->
        :unapproved_runtime

      approved_compiled_import?(Path.basename(path), module, function) ->
        nil

      true ->
        compiled_mfa_category(module, function)
    end
  end

  defp conformance_beam?(path) do
    String.starts_with?(
      Path.basename(path),
      "Elixir.BoundedAuthorityProtocol.Conformance."
    )
  end

  defp approved_compiled_import?(beam, module, function) do
    {module, function} in case beam do
      "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportCodec.beam" ->
        [
          {Access, :get},
          {Enum, :map},
          {Enum, :sort},
          {Map, :new},
          {:erlang, :iolist_to_binary}
        ]

      codec_beam
      when codec_beam in [
             "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchorCodec.beam",
             "Elixir.BoundedAuthorityProtocol.V1.ConsumptionChain.beam",
             "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionCodec.beam"
           ] ->
        [
          {Access, :get},
          {Enum, :__in__},
          {Enum, :map},
          {Enum, :member?},
          {Enum, :sort},
          {Function, :identity},
          {Map, :new},
          {Range, :new},
          {String, :contains?},
          {String, :valid?},
          {URI, :new}
        ]

      "Elixir.BoundedAuthorityProtocol.V1.CompactJws.beam" ->
        [{Map, :new}, {:binary, :match}]

      "Elixir.BoundedAuthorityProtocol.V1.Jcs.beam" ->
        [
          {Enum, :map},
          {Enum, :map_reduce},
          {Enum, :sort_by},
          {MapSet, :new},
          {MapSet, :size},
          {String, :downcase},
          {String, :pad_leading},
          {String, :valid?},
          {:binary, :at},
          {:erlang, :float_to_binary},
          {:erlang, :iolist_size},
          {:erlang, :iolist_to_binary},
          {:unicode, :characters_to_binary}
        ]

      "Elixir.BoundedAuthorityProtocol.V1.Jwk.beam" ->
        [{Map, :new}, {String.Chars, :to_string}]

      "Elixir.BoundedAuthorityProtocol.V1.RequestDigest.beam" ->
        [
          {Enum, :all?},
          {Enum, :__in__},
          {Enum, :member?},
          {Enum, :reverse},
          {Function, :identity},
          {Range, :new},
          {:binary, :bin_to_list}
        ]

      "Elixir.BoundedAuthorityProtocol.V1.Runtime.beam" ->
        [
          {Access, :get},
          {Enum, :all?},
          {Enum, :any?},
          {Enum, :filter},
          {Enum, :find_value},
          {Enum, :__in__},
          {Enum, :map},
          {Enum, :member?},
          {Enum, :reverse},
          {Enum, :sort},
          {Function, :identity},
          {Map, :new},
          {MapSet, :new},
          {MapSet, :size},
          {String, :contains?},
          {String, :valid?},
          {URI, :new},
          {Range, :new},
          {:binary, :bin_to_list},
          {:lists, :member}
        ]

      "Elixir.BoundedAuthorityProtocol.V1.Selector.beam" ->
        [
          {Enum, :all?},
          {Enum, :any?},
          {Enum, :__in__},
          {Enum, :map},
          {Enum, :member?},
          {Enum, :zip},
          {Function, :identity},
          {List, :keyfind},
          {MapSet, :new},
          {MapSet, :size},
          {String, :valid?},
          {Range, :new}
        ]

      "Elixir.BoundedAuthorityProtocol.V1.Uri.beam" ->
        [
          {Enum, :all?},
          {Enum, :any?},
          {Enum, :__in__},
          {Enum, :member?},
          {Enum, :reverse},
          {List, :last},
          {:binary, :at},
          {:binary, :bin_to_list},
          {:binary, :match},
          {:binary, :matches},
          {:erlang, :"=/="},
          {:erlang, :iolist_to_binary},
          {:lists, :member}
        ]

      "Elixir.BoundedAuthorityProtocol.Conformance.Corpus.beam" ->
        [
          {:maps, :keys},
          {:maps, :remove},
          {:maps, :to_list},
          {Access, :get},
          {Bitwise, :bxor},
          {Enum, :all?},
          {Enum, :flat_map},
          {Enum, :map},
          {Enum, :reduce},
          {Enum, :reduce_while},
          {Enum, :reject},
          {Enum, :sort_by},
          {List, :keyfind},
          {Map, :delete},
          {Map, :fetch!},
          {Map, :get},
          {Map, :keys},
          {Map, :new},
          {Map, :to_list},
          {Map, :update},
          {MapSet, :equal?},
          {MapSet, :new},
          {MapSet, :size},
          {String, :ends_with?}
        ]

      "Elixir.BoundedAuthorityProtocol.Conformance.Runner.beam" ->
        [
          {:maps, :remove},
          {:erlang, :binary_to_integer},
          {Access, :get},
          {Base, :url_decode64!},
          {Enum, :all?},
          {Enum, :map},
          {Enum, :reduce_while},
          {Enum, :reverse},
          {Enum, :sort_by},
          {Map, :delete},
          {Map, :get},
          {Map, :new},
          {String, :ends_with?}
        ]

      "Elixir.BoundedAuthorityProtocol.Conformance.Report.beam" ->
        [
          {Enum, :count},
          {Enum, :flat_map}
        ]

      # CLI I/O carve-out compiled imports (C1): the exact File/IO/Path functions cli.ex uses,
      # plus String.Chars.to_string (string interpolation in the relative-path joiner).
      "Elixir.BoundedAuthorityProtocol.Conformance.Cli.beam" ->
        [
          {File, :dir?},
          {File, :ls},
          {File, :read},
          {File, :write},
          {IO, :binwrite},
          {Path, :join},
          {String.Chars, :to_string}
        ]

      # cli/main.ex compiled imports: System.halt/1 only.
      "Elixir.BoundedAuthorityProtocol.Conformance.Cli.Main.beam" ->
        [
          {System, :halt}
        ]

      inspect_beam when is_binary(inspect_beam) ->
        if String.starts_with?(
             inspect_beam,
             "Elixir.Inspect.BoundedAuthorityProtocol.V1."
           ),
           do: [{Inspect.Algebra, :string}],
           else: []
    end
  end

  defp dynamic_allowance_violations(forms, path) do
    case Map.fetch(@compiled_dynamic_allowances, Path.basename(path)) do
      {:ok, expected} ->
        actual = dynamic_calls_by_function(forms)

        if actual == expected do
          []
        else
          [
            violation(
              :dynamic_dispatch,
              path,
              "compiled dynamic-call allowance expected #{inspect(expected)}, got #{inspect(actual)}"
            )
          ]
        end

      :error ->
        []
    end
  end

  defp dynamic_calls_by_function(forms) do
    Enum.reduce(forms, %{}, fn
      {:function, _line, name, arity, _clauses} = form, calls ->
        counts = dynamic_call_counts(form, %{enum_reduce: 0, variable_call: 0})
        nonzero_counts = Map.reject(counts, fn {_kind, count} -> count == 0 end)

        if nonzero_counts == %{} do
          calls
        else
          Map.put(calls, {name, arity}, nonzero_counts)
        end

      _form, calls ->
        calls
    end)
  end

  defp dynamic_call_counts(term, counts) when is_tuple(term) do
    counts =
      case term do
        {:call, _line,
         {:remote, _remote_line, {:atom, _module_line, Elixir.Enum},
          {:atom, _function_line, :reduce}}, _arguments} ->
          Map.update!(counts, :enum_reduce, &(&1 + 1))

        {:call, _line, {:var, _variable_line, _variable}, _arguments} ->
          Map.update!(counts, :variable_call, &(&1 + 1))

        _other ->
          counts
      end

    term
    |> Tuple.to_list()
    |> Enum.reduce(counts, &dynamic_call_counts/2)
  end

  defp dynamic_call_counts(term, counts) when is_list(term),
    do: Enum.reduce(term, counts, &dynamic_call_counts/2)

  defp dynamic_call_counts(_term, counts), do: counts

  defp abstract_violations(
         {:fun, _line,
          {:function, {:atom, _module_line, module}, {:atom, _function_line, function},
           {:integer, _arity_line, arity}}},
         path
       ) do
    case compiled_mfa_category(module, function) do
      nil ->
        []

      category ->
        [
          violation(
            category,
            path,
            "compiled external function #{inspect(module)}.#{function}/#{arity}"
          )
        ]
    end
  end

  defp abstract_violations(
         {:call, _line, {:var, _variable_line, _variable}, _arguments} = term,
         path
       ) do
    findings =
      if Path.basename(path) in [
           "Elixir.BoundedAuthorityProtocol.V1.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Base64Url.beam",
           "Elixir.BoundedAuthorityProtocol.V1.AnchoredExportCodec.beam",
           "Elixir.BoundedAuthorityProtocol.V1.BoundaryAnchorCodec.beam",
           "Elixir.BoundedAuthorityProtocol.V1.CompactJws.beam",
           "Elixir.BoundedAuthorityProtocol.V1.ConsumptionChain.beam",
           "Elixir.BoundedAuthorityProtocol.V1.ContextValidation.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Jcs.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Json.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Jwk.beam",
           "Elixir.BoundedAuthorityProtocol.V1.KeyTransitionCodec.beam",
           "Elixir.BoundedAuthorityProtocol.V1.RequestDigest.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Runtime.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Selector.beam",
           "Elixir.BoundedAuthorityProtocol.V1.Uri.beam",
           "Elixir.BoundedAuthorityProtocol.Conformance.Corpus.beam",
           "Elixir.BoundedAuthorityProtocol.Conformance.Runner.beam",
           "Elixir.BoundedAuthorityProtocol.Conformance.Report.beam",
           "Elixir.BoundedAuthorityProtocol.Conformance.Cli.beam"
         ],
         do: [],
         else: [violation(:dynamic_dispatch, path, "compiled variable function invocation")]

    findings ++ abstract_tuple_children(term, path)
  end

  defp abstract_violations({:receive, _line, _clauses} = term, path) do
    [violation(:process, path, "compiled mailbox receive")] ++
      abstract_tuple_children(term, path)
  end

  defp abstract_violations(
         {:receive, _line, _clauses, _timeout, _timeout_body} = term,
         path
       ) do
    [violation(:process, path, "compiled mailbox receive")] ++
      abstract_tuple_children(term, path)
  end

  defp abstract_violations({:attribute, _line, :on_load, _callback}, path) do
    [violation(:unapproved_runtime, path, "compiled module load hook")]
  end

  defp abstract_violations(term, path) when is_tuple(term) do
    abstract_tuple_children(term, path)
  end

  defp abstract_violations(term, path) when is_list(term) do
    Enum.flat_map(term, &abstract_violations(&1, path))
  end

  defp abstract_violations(_term, _path), do: []

  defp abstract_tuple_children(term, path) do
    term
    |> Tuple.to_list()
    |> Enum.flat_map(&abstract_violations(&1, path))
  end

  defp compiled_mfa_category(module, function) do
    module_name =
      module
      |> Atom.to_string()
      |> String.replace_prefix("Elixir.", "")

    mfa_category(
      if(String.starts_with?(Atom.to_string(module), "Elixir."), do: module_name, else: module),
      function
    )
  end

  defp violation(category, path, detail) do
    %{category: category, path: path, detail: detail}
  end
end
