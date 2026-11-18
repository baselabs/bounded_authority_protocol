# This consumer fixture is explicitly loaded, rather than discovered as a root test.
# credo:disable-for-this-file Credo.Check.Warning.WrongTestFilename

# Compile the exact documented modules before compiling tests that call them.
for {code, _prose} <- File.read!("recipes.etf") |> :erlang.binary_to_term([:safe]),
    String.starts_with?(code, "defmodule ") do
  Code.eval_string(code, [], file: "recipes.md")
end

defmodule BapReader.MiddlewareTest do
  # This fixture is copied to the consumer as middleware_test.exs; root suites must not load it.
  # credo:disable-for-next-line Credo.Check.Warning.WrongTestFilename
  use ExUnit.Case, async: false

  test "every recipe block runs without warnings and the real middleware assigns or halts" do
    assert Application.spec(:bounded_authority_protocol, :applications) --
             [:kernel, :stdlib, :elixir, :crypto] == []

    examples = File.read!("recipes.etf") |> :erlang.binary_to_term([:safe])

    {{_values, {binding, _env}}, warnings} =
      ExUnit.CaptureIO.with_io(:stderr, fn ->
        Enum.map_reduce(examples, {[], Code.env_for_eval(file: "recipes.md")}, fn {code, prose},
                                                                                  {binding, env} ->
          quoted = Code.string_to_quoted!(code, file: "recipes.md")
          # Module definitions above already ran; evaluate their trailing expressions here.
          quoted =
            case quoted do
              {:__block__, meta, expressions} ->
                {:__block__, meta, Enum.reject(expressions, &match?({:defmodule, _, _}, &1))}

              other ->
                other
            end

          {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)

          claims =
            Regex.scan(~r/\b(?:value|result) is\s+`([^`]+)`/, prose, capture: :all_but_first)

          entries = Regex.scan(~r/\bEach entry is\s+`([^`]+)`/, prose, capture: :all_but_first)
          assert claims != [] or entries != [], "Recipe block states no expected value"
          for [term] <- claims, do: assert(value == elem(Code.eval_string(term), 0))

          for [term] <- entries do
            expected = elem(Code.eval_string(term), 0)
            assert is_list(value) and Enum.all?(value, &(&1 == expected))
          end

          {value, {binding, env}}
        end)
      end)

    refute warnings =~ "warning:"
    check_middleware(binding)
  end

  defp check_middleware(binding) do
    alias BoundedAuthorityProtocol.V1
    # call/2 reads the actual clock. Sign an actual live grant and proof; no clock is replaced.
    now = System.os_time(:second)
    grant = %{binding[:grant] | issued_at: now - 1, not_before: now - 1, expires_at: now + 3600}
    {:ok, input} = V1.grant_signing_input(grant, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [binding[:issuer_private], :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    proof = %{binding[:proof] | grant_compact: compact, issued_at: now}
    {:ok, input} = V1.proof_signing_input(proof, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [binding[:holder_private], :ed25519])
    {:ok, proof_compact} = V1.assemble_compact(input, signature)

    previous = Application.fetch_env(:my_app, MyAppWeb.BoundedAuthority)
    Application.put_env(:my_app, MyAppWeb.BoundedAuthority, Map.to_list(binding[:options]))

    on_exit(fn ->
      case previous do
        {:ok, config} -> Application.put_env(:my_app, MyAppWeb.BoundedAuthority, config)
        :error -> Application.delete_env(:my_app, MyAppWeb.BoundedAuthority)
      end
    end)

    headers = [
      {"authorization", "DPoP " <> compact},
      {"dpop", proof_compact},
      {"invocation-id", proof.invocation_id}
    ]

    conn = %{
      Plug.Test.conn(:post, "https://data.example/exports")
      | req_headers: headers,
        body_params: binding[:params]
    }

    opts = MyAppWeb.BoundedAuthority.init(operation: "export_dataset")
    verified = MyAppWeb.BoundedAuthority.call(conn, opts)
    assert %Plug.Conn{} = verified
    refute verified.halted
    assert verified.state == :unset
    facts = verified.assigns.bounded_authority_facts
    assert facts.operation == proof.operation
    assert facts.invocation_id == proof.invocation_id
    assert facts.authorization == :not_evaluated

    # Every credential header must be present exactly once.
    for {name, value} <- headers do
      reject(%{conn | req_headers: List.keydelete(headers, name, 0)}, opts)
      reject(%{conn | req_headers: [{name, value} | headers]}, opts)
    end

    reject(%{conn | body_params: Map.put(binding[:params], "rows", 500.0)}, opts)
    reject(%{conn | body_params: Map.put(binding[:params], "dataset", "salinity")}, opts)
    reject(%{conn | body_params: %{"rows" => {500}}}, opts)

    reject(
      %{
        conn
        | req_headers:
            List.keyreplace(headers, "authorization", 0, {"authorization", "Bearer " <> compact})
      },
      opts
    )

    reject(%{conn | method: "GET"}, opts)
    # The untrusted Host header does not select the expected origin.
    assert MyAppWeb.BoundedAuthority.call(%{conn | host: "attacker.example"}, opts).assigns.bounded_authority_facts ==
             facts

    assert {:ok, {:object, [{"rows", {:integer, 500}}]}} = MyApp.CastArguments.tag(%{rows: 500})
    assert {:error, :invalid} = MyApp.CastArguments.tag(%{:rows => 500, "rows" => 500})
  end

  defp reject(conn, opts) do
    conn = %{
      Plug.Test.conn(conn.method, "https://data.example" <> conn.request_path)
      | req_headers: conn.req_headers,
        body_params: conn.body_params
    }

    rejected = MyAppWeb.BoundedAuthority.call(conn, opts)
    assert rejected.halted
    assert rejected.status == 401
    assert rejected.state == :sent
    assert rejected.resp_body == ""
    assert {401, _headers, ""} = Plug.Test.sent_resp(rejected)
    refute Map.has_key?(rejected.assigns, :bounded_authority_facts)
  end
end
