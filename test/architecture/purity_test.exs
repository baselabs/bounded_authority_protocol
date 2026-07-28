Code.require_file("../../tools/architecture_gate.exs", __DIR__)

defmodule BoundedAuthorityProtocol.Architecture.PurityTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ArchitectureGate

  @root Path.expand("../..", __DIR__)

  test "the actual runtime source and project declaration are pure" do
    assert [] == ArchitectureGate.check(@root, compiled: false)
  end

  test "the compiled application has no runtime or OTP-service surface" do
    assert [] == ArchitectureGate.check_compiled(@root)
  end

  test "the source gate rejects every prohibited surface family" do
    cases = [
      database: "Ecto.Query.from(item in Item)",
      database: ":mnesia.start()",
      database: "Postgrex.query!(nil, \"select 1\", [])",
      http: "Req.get!(\"https://example.invalid\")",
      http: "Finch.request!(nil, nil)",
      http: "Plug.Conn.fetch_query_params(nil)",
      telemetry: ":telemetry.execute([:event], %{}, %{})",
      product: "Ash.read!(nil)",
      product: "Beamline.API.run(:forbidden)",
      product: "QorPay.Authority.verify(:forbidden)",
      private_runtime: "BoundedAuthority.verify(:forbidden)",
      filesystem: "File.read!(\"secret\")",
      network: ":gen_tcp.connect(~c\"localhost\", 443, [])",
      network: ":socket.open(:inet, :stream, :tcp)",
      network: ":gen_sctp.open([])",
      network: ":rpc.call(:peer, Kernel, :node, [])",
      network: ":net_adm.ping(:peer)",
      network: ":net_kernel.connect_node(:peer)",
      network: ":erl_epmd.names(~c\"localhost\")",
      network: ":inet.getaddr(~c\"localhost\", :inet)",
      network: ":inet_tcp.connect(~c\"localhost\", 443, [], 1_000)",
      network: ":inet6_udp.open(0, [])",
      network: ":gen_tcp_socket.connect(~c\"localhost\", 443, [])",
      network: ":diameter.add_transport(:service, [])",
      application_env: "Application.fetch_env!(:app, :key)",
      otp_service: "Application.ensure_all_started(:diameter)",
      system_env: "System.fetch_env!(\"SECRET\")",
      clock: "DateTime.utc_now()",
      randomness: ":crypto.strong_rand_bytes(32)",
      randomness: ":crypto.generate_key(:ecdh, :x25519)",
      randomness: ":public_key.generate_key({:namedCurve, :secp256r1})",
      process: "spawn(fn -> :ok end)",
      process: ":persistent_term.put(:key, :value)",
      process: ":atomics.new(1, [])",
      process: ":counters.new(1, [])",
      process_dictionary: "Process.put(:key, :value)",
      otp_service: "GenServer.start_link(__MODULE__, [], [])",
      dynamic_dispatch:
        "def probe(module, function, arguments), do: Kernel.apply(module, function, arguments)",
      dynamic_dispatch:
        "def probe(module, function, arguments), do: :erlang.apply(module, function, arguments)",
      dynamic_dispatch: "def probe(function, argument), do: function.(argument)",
      dynamic_dispatch: "def probe(module, function), do: Function.capture(module, function, 0)",
      dynamic_dispatch: "def probe(items, callback), do: Enum.map(items, callback)",
      dynamic_dispatch: "def probe(items, callback), do: Enum.reduce(items, 0, callback)",
      dynamic_dispatch: "def probe(map, callback), do: Map.update(map, :key, nil, callback)",
      dynamic_dispatch: "def probe(map, callback), do: Map.get_lazy(map, :key, callback)",
      dynamic_dispatch: "def probe(left, right, callback), do: Map.merge(left, right, callback)",
      dynamic_dispatch:
        "def probe(keyword, callback), do: Keyword.update(keyword, :key, nil, callback)",
      dynamic_dispatch:
        "def probe(keyword, callback), do: Keyword.get_lazy(keyword, :key, callback)",
      dynamic_dispatch:
        "def probe(left, right, callback), do: Keyword.merge(left, right, callback)",
      dynamic_dispatch: "def probe(list, callback), do: List.update_at(list, 0, callback)",
      dynamic_dispatch:
        "def probe(left, right, callback), do: List.myers_difference(left, right, callback)",
      dynamic_dispatch: "def probe(value, callback), do: Kernel.then(value, callback)",
      dynamic_dispatch:
        "def probe(data, keys, callback), do: Kernel.get_and_update_in(data, keys, callback)",
      dynamic_dispatch: "def probe(value, callback), do: then(value, callback)",
      dynamic_dispatch: "def probe(value, callback), do: tap(value, callback)",
      dynamic_dispatch: "def probe(items, callback), do: :lists.map(callback, items)",
      dynamic_dispatch: "def probe(items, callback), do: :lists.foreach(callback, items)",
      dynamic_dispatch: "def probe(map, callback), do: :maps.map(callback, map)",
      dynamic_dispatch: "def probe(value), do: inspect(value)",
      dynamic_dispatch: "def probe(value), do: to_string(value)",
      unapproved_runtime: "String.Chars.to_string(:value)",
      unapproved_runtime: "Map.intersect(%{}, %{}, fn _key, left, _right -> left end)",
      unapproved_runtime: "Map.split_with(%{}, fn {_key, _value} -> true end)",
      unapproved_runtime: "MysteryRuntime.perform(:effect)",
      unapproved_runtime: ":json.encode(%{})",
      process: "def probe, do: receive(do: (message -> message))",
      dynamic_module: "Module.concat([\"File\"])",
      code_evaluation: "Code.eval_string(\"File.read!(secret)\")"
    ]

    Enum.each(cases, fn {category, expression} ->
      body =
        if String.starts_with?(expression, "def "),
          do: expression,
          else: "def probe, do: #{expression}"

      root = fixture_root!(body)

      assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
               violation.category == category
             end),
             "expected #{category} violation for #{expression}"
    end)
  end

  test "the project gate rejects every prohibited direct dependency" do
    Enum.each(
      [:ecto_sql, :postgrex, :req, :finch, :telemetry, :plug, :ash, :beamline, :qorpay],
      fn dependency ->
        root = copy_actual_project!()
        mix_path = Path.join(root, "mix.exs")

        mutated =
          mix_path
          |> File.read!()
          |> String.replace(
            "defp deps do\n    [",
            "defp deps do\n    [\n      {#{inspect(dependency)}, \"~> 0.0\"},",
            global: false
          )

        File.write!(mix_path, mutated)

        assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
                 violation.category == :dependency_policy and
                   violation.detail =~ inspect(dependency)
               end),
               "expected dependency policy violation for #{inspect(dependency)}"
      end
    )
  end

  test "the source gate accepts pure code and verification-only crypto" do
    root =
      fixture_root!("""
      def digest(bytes) when is_binary(bytes), do: :crypto.hash(:sha256, bytes)
      def add(left, right), do: left + right
      """)

    assert [] == ArchitectureGate.check(root, compiled: false)
  end

  test "the source gate handles local module aliases without crashing" do
    root =
      fixture_root!("""
      alias __MODULE__.Value
      def marker, do: :ok
      """)

    assert [] == ArchitectureGate.check(root, compiled: false)
  end

  test "the source gate rejects an otherwise unused external module alias" do
    root = fixture_root!("alias MysteryRuntime")

    assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
             violation.category == :unapproved_runtime and
               violation.detail == "forbidden module MysteryRuntime"
           end)
  end

  test "the source gate rejects an external alias shadowing the package root" do
    bodies = [
      """
      alias MysteryRuntime, as: BoundedAuthorityProtocol
      def effect, do: BoundedAuthorityProtocol.perform(:effect)
      """,
      """
      alias MysteryRuntime.BoundedAuthorityProtocol
      def effect, do: BoundedAuthorityProtocol.perform(:effect)
      """,
      """
      alias BoundedAuthorityProtocolEvil, as: BoundedAuthorityProtocol
      def effect, do: BoundedAuthorityProtocol.perform(:effect)
      """
    ]

    Enum.each(bodies, fn body ->
      root = fixture_root!(body)

      assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
               violation.category == :unapproved_runtime and
                 violation.detail == "external alias cannot shadow BoundedAuthorityProtocol"
             end)
    end)
  end

  test "the source gate rejects external compile-time directives" do
    bodies = [
      {"external require is forbidden",
       """
       require MysteryRuntime, as: BoundedAuthorityProtocol
       def effect, do: BoundedAuthorityProtocol.perform(:effect)
       """},
      {"external import is forbidden",
       """
       import MysteryRuntime
       def effect, do: perform(:effect)
       """},
      {"external require is forbidden",
       """
       require MysteryRuntime
       def effect, do: MysteryRuntime.perform(:effect)
       """},
      {"external use is forbidden",
       """
       use MysteryRuntime
       """}
    ]

    Enum.each(bodies, fn {expected_detail, body} ->
      root = fixture_root!(body)

      assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
               violation.category == :unapproved_runtime and
                 violation.detail == expected_detail
             end)
    end)
  end

  test "the source gate rejects compile-time hook attributes" do
    attributes = [
      "@after_compile MysteryRuntime",
      "@after_verify MysteryRuntime",
      "@before_compile MysteryRuntime",
      "@behaviour MysteryRuntime",
      "@compile {:parse_transform, MysteryRuntime}",
      "@derive MysteryRuntime",
      "@external_resource \"forbidden.txt\"",
      "@on_definition MysteryRuntime",
      "@on_load :initialize"
    ]

    Enum.each(attributes, fn attribute ->
      root = fixture_root!(attribute)

      assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
               violation.category == :unapproved_runtime and
                 violation.detail =~ "implicit execution hook @"
             end)
    end)
  end

  test "the compiled gate goes red for a forbidden BEAM import" do
    root =
      fixture_root!("""
      def read(path), do: File.read!(path)
      def transport, do: :diameter.add_transport(:service, [])
      def external_callback, do: &MysteryRuntime.perform/1
      def random, do: :crypto.strong_rand_bytes(32)
      def callback(value, function), do: then(value, function)
      def mailbox, do: receive(do: (message -> message), after: (0 -> :empty))
      @on_load :initialize
      def initialize, do: :ok
      """)

    assert {_output, 0} =
             System.cmd("mix", ["compile"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :filesystem and
               violation.detail =~ "compiled import File.read!"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :network and
               violation.detail =~ "compiled import :diameter.add_transport"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :unapproved_runtime and
               violation.detail =~ "compiled external function MysteryRuntime.perform/1"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :randomness and
               violation.detail =~ "compiled import :crypto.strong_rand_bytes/1"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :dynamic_dispatch and
               violation.detail == "compiled variable function invocation"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :process and
               violation.detail == "compiled mailbox receive"
           end)

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :unapproved_runtime and
               violation.detail == "compiled module load hook"
           end)
  end

  test "malformed runtime source fails closed" do
    root = fixture_root!("def broken(")

    assert [%{category: :parse_failure}] =
             ArchitectureGate.check(root, compiled: false)
             |> Enum.filter(&(&1.category == :parse_failure))
  end

  test "the compiled walker retains findings nested inside a forbidden node" do
    root =
      fixture_root!("""
      def nested(function) do
        receive do
          message -> function.(message)
        after
          0 -> &MysteryRuntime.perform/1
        end
      end
      """)

    assert {_output, 0} =
             System.cmd("mix", ["compile"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    violations = ArchitectureGate.check_compiled(root)

    assert Enum.any?(violations, &(&1.detail == "compiled mailbox receive"))
    assert Enum.any?(violations, &(&1.detail == "compiled variable function invocation"))

    assert Enum.any?(
             violations,
             &(&1.detail =~ "compiled external function MysteryRuntime.perform/1")
           )
  end

  test "compiled dynamic-call allowances are bound to exact existing counts" do
    root = copy_actual_project!()

    assert {_output, 0} =
             System.cmd("mix", ["compile"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    refute Enum.any?(
             ArchitectureGate.check_compiled(root),
             &(&1.category == :dynamic_dispatch)
           )

    path = Path.join(root, "lib/bounded_authority_protocol/v1/bounds.ex")
    original = File.read!(path)

    mutated =
      String.replace(
        original,
        "def new(overrides) when is_map(overrides) do",
        "def new(overrides) when is_map(overrides) do\n" <>
          "    _unexpected = Enum.reduce(Map.to_list(overrides), 0, fn {_key, value}, sum -> value + sum end)",
        global: false
      )

    assert mutated != original
    File.write!(path, mutated)

    assert {_output, 0} =
             System.cmd("mix", ["compile", "--force"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :dynamic_dispatch and
               violation.detail =~ "compiled dynamic-call allowance" and
               violation.detail =~ "{:new, 1}"
           end)

    runtime_path = Path.join(root, "lib/bounded_authority_protocol/v1/runtime.ex")
    runtime = File.read!(runtime_path)
    mutated_runtime = String.replace(runtime, "fun.()", "fun.()\n    fun.()", global: false)

    assert mutated_runtime != runtime
    File.write!(runtime_path, mutated_runtime)

    assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
             violation.category == :dynamic_dispatch and
               violation.detail == "source dynamic-call allowance expected 2, got 3"
           end)

    assert {_output, 0} =
             System.cmd("mix", ["compile", "--force"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :dynamic_dispatch and
               violation.detail =~ "compiled dynamic-call allowance" and
               violation.detail =~ "{:fixed, 1}"
           end)
  end

  test "fixed-byte comparison is pinned to constant-time crypto and is mutation-red" do
    root = copy_actual_project!()
    path = Path.join(root, "lib/bounded_authority_protocol/v1/fixed_bytes.ex")
    original = File.read!(path)

    mutated =
      String.replace(
        original,
        ":crypto.hash_equals(left, right)",
        "left == right",
        global: false
      )

    assert mutated != original
    File.write!(path, mutated)

    assert Enum.any?(ArchitectureGate.check(root, compiled: false), fn violation ->
             violation.category == :crypto_contract and
               violation.detail =~ "exactly one :crypto.hash_equals/2"
           end)
  end

  test "new protocol mechanics have exact compiled public exports" do
    root = copy_actual_project!()

    assert {_output, 0} =
             System.cmd("mix", ["compile"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    refute Enum.any?(
             ArchitectureGate.check_compiled(root),
             &(&1.category == :public_surface)
           )

    path = Path.join(root, "lib/bounded_authority_protocol/v1/anchor_facts.ex")
    original = File.read!(path)

    mutated =
      String.replace(
        original,
        "defstruct @enforce_keys",
        "defstruct @enforce_keys\n\n  def unexpected_export, do: :forbidden",
        global: false
      )

    assert mutated != original
    File.write!(path, mutated)

    assert {_output, 0} =
             System.cmd("mix", ["compile", "--force"],
               cd: root,
               env: [{"MIX_ENV", "prod"}],
               stderr_to_stdout: true
             )

    assert Enum.any?(ArchitectureGate.check_compiled(root), fn violation ->
             violation.category == :public_surface and
               violation.detail =~ "unexpected_export"
           end)
  end

  test "chain facts expose no generic collection or string protocol and no raw evidence fields" do
    modules = [
      BoundedAuthorityProtocol.V1.AnchorFacts,
      BoundedAuthorityProtocol.V1.AnchoredExportFacts,
      BoundedAuthorityProtocol.V1.ChainFacts,
      BoundedAuthorityProtocol.V1.KeyTransitionFacts
    ]

    forbidden_fields = [
      :bytes,
      :chunks,
      :commitment,
      :object_version,
      :public_key,
      :rows,
      :signature
    ]

    for module <- modules do
      value = module.__struct__()

      assert Inspect.impl_for(value)
      refute Enumerable.impl_for(value)
      refute Collectable.impl_for(value)
      refute String.Chars.impl_for(value)
      refute function_exported?(module, :fetch, 2)
      refute Enum.any?(forbidden_fields, &Map.has_key?(value, &1))
    end
  end

  test "the CI entrypoint goes red for a planted forbidden dependency and green after removal" do
    root = copy_actual_project!()
    script = Path.join(@root, "scripts/check_architecture.exs")

    assert {green_output, 0} =
             System.cmd("elixir", [script, "--root", root, "--skip-compiled"],
               stderr_to_stdout: true
             )

    assert green_output =~ "architecture boundary passed"

    mix_path = Path.join(root, "mix.exs")
    original = File.read!(mix_path)

    mutated =
      String.replace(
        original,
        "defp deps do\n    [",
        "defp deps do\n    [\n      {:ecto_sql, \"~> 3.0\"},",
        global: false
      )

    File.write!(mix_path, mutated)

    assert {red_output, status} =
             System.cmd("elixir", [script, "--root", root, "--skip-compiled"],
               stderr_to_stdout: true
             )

    assert status != 0
    assert red_output =~ "dependency_policy"

    File.write!(mix_path, original)

    assert {_restored_output, 0} =
             System.cmd("elixir", [script, "--root", root, "--skip-compiled"],
               stderr_to_stdout: true
             )
  end

  defp fixture_root!(body) do
    root = tmp_root!()
    File.mkdir_p!(Path.join(root, "lib"))

    File.write!(
      Path.join(root, "lib/bounded_authority_protocol.ex"),
      """
      defmodule BoundedAuthorityProtocol do
        #{body}
      end
      """
    )

    File.cp!(Path.join(@root, "mix.exs"), Path.join(root, "mix.exs"))
    root
  end

  defp copy_actual_project! do
    root = tmp_root!()
    File.cp!(Path.join(@root, "mix.exs"), Path.join(root, "mix.exs"))
    File.cp_r!(Path.join(@root, "lib"), Path.join(root, "lib"))

    root
  end

  defp tmp_root! do
    template = Path.join(System.tmp_dir!(), "bounded-authority-architecture.XXXXXX")

    root =
      case System.cmd("mktemp", ["-d", template], stderr_to_stdout: true) do
        {path, 0} ->
          String.trim(path)

        {output, status} ->
          raise "mktemp exited with status #{status}: #{String.trim(output)}"
      end

    on_exit(fn -> File.rm_rf!(root) end)
    root
  end
end
