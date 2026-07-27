defmodule BoundedAuthorityProtocol.ArchitectureGate do
  @moduledoc false

  @approved_dependencies %{
    credo: {"~> 1.7", [:dev, :test]},
    dialyxir: {"~> 1.4", [:dev, :test]},
    ex_doc: {"~> 0.40.3", [:dev, :test]},
    mix_audit: {"~> 2.1", [:dev, :test]},
    sbom: {"~> 0.10.0", [:dev, :test]}
  }

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
    binary: ~w(split)a,
    crypto: ~w(hash hash_equals hash_final hash_init hash_update verify)a,
    erlang:
      ~w(+ - * / ++ -- < <= == === > >= and band binary_to_float binary_to_integer bnot bor bsl bsr bxor byte_size div element error get_module_info hd is_atom is_binary is_bitstring is_boolean is_float is_function is_integer is_list is_map is_map_key is_number is_pid is_port is_reference is_tuple length map_get map_size max min not or raise rem round setelement size tl trunc tuple_size xor)a,
    json: ~w(decode)a,
    maps: ~w(find merge to_list)a,
    elixir_erl_pass: ~w(no_parens_remote)a
  }

  @approved_local_aliases ~w(Base64Url Bounds Container Json JsonValue KeyLocator Root Violation)
  @approved_struct_fields ~w(array_items compact_bytes count decoded_segment_bytes depth
    encoded_segment_bytes float_magnitude integer_magnitude json_bytes key_bytes kid_bytes kind
    level nodes number_lexeme_bytes object_members seen string_bytes total_nodes value values)a

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
      application_violations(ast) ++ dependency_violations(dependencies)
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
        {kind, _meta, [{:application, _call_meta, _args} | _rest]} = node, acc
        when kind in [:def, :defp] ->
          {node,
           [
             violation(
               :application_callback,
               "mix.exs",
               "application/0 is forbidden; the package has no OTP callback"
             )
             | acc
           ]}

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

      violations
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

  defp node_violations({:__aliases__, _meta, segments}, path) do
    root = alias_root(segments)
    name = alias_name(segments)

    category =
      cond do
        root == "BoundedAuthorityProtocol" -> nil
        root == :dynamic -> :dynamic_module
        root in @approved_local_aliases -> nil
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
    module_ast
    |> module_name()
    |> mfa_category(function)
    |> category_violation(path, "forbidden call #{format_call(module_ast, function)}")
  end

  defp node_violations({{:., _dot_meta, [_callable_ast]}, _meta, args}, path)
       when is_list(args) do
    category_violation(
      :dynamic_dispatch,
      path,
      "forbidden first-class function invocation/#{length(args)}"
    )
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

    category_violation(category, path, "forbidden local call #{function}/#{length(args)}")
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
      String.starts_with?(module, "BoundedAuthorityProtocol.")
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
          if(applications == [:elixir, :kernel, :stdlib],
            do: nil,
            else:
              violation(
                :compiled_artifact,
                app_path,
                "applications must be [:elixir, :kernel, :stdlib], got #{inspect(applications)}"
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
    case :beam_lib.chunks(String.to_charlist(path), [:imports, :abstract_code]) do
      {:ok, {_module, [imports: imports, abstract_code: {:raw_abstract_v1, forms}]}} ->
        import_violations(imports, path) ++ abstract_violations(forms, path)

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
         "Elixir.BoundedAuthorityProtocol.V1.Bounds.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.Container.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.JsonValue.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Json.Root.beam",
         "Elixir.BoundedAuthorityProtocol.V1.KeyLocator.beam",
         "Elixir.BoundedAuthorityProtocol.V1.Violation.beam"
       ],
       do: nil,
       else: :dynamic_dispatch
  end

  defp compiled_import_category(module, function, _path),
    do: compiled_mfa_category(module, function)

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
           "Elixir.BoundedAuthorityProtocol.V1.Json.beam"
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
