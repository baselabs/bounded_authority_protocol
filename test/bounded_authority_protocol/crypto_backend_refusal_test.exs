defmodule BoundedAuthorityProtocol.CryptoBackendRefusalTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.{Ed25519, Es256}

  @vectors Path.expand(
             "../../priv/conformance/content-profiles/action-approval/v1/approval-cases.json",
             __DIR__
           )

  @probe ~S"""
  alias BoundedAuthorityProtocol.{Ed25519, Es256}

  [vectors, coverage_file] = System.argv()

  if coverage_file != "" do
    {:ok, _pid} = :cover.start()
    :ok = :cover.local_only()
    {:ok, Ed25519} = :cover.compile_beam(Ed25519)
    {:ok, Es256} = :cover.compile_beam(Es256)
  end

  cases = vectors |> File.read!() |> :json.decode()
  decode = &Base.url_decode64!(&1, padding: false)

  for {id, verifier, algorithm, digest, curve} <- [
        {"eddsa-verified", Ed25519, :eddsa, :none, :ed25519},
        {"es256-verified", Es256, :ecdsa, :sha256, :prime256v1}
      ] do
    item = Enum.find(cases, &(&1["id"] == id))
    [header, payload, signature] = String.split(item["compact"], ".")
    message = header <> "." <> payload
    signature = decode.(signature)
    [entry] = item["context"]["snapshot"]["entries"]
    key = decode.(entry["key"]["public_key"])

    backend_signature =
      case algorithm do
        :eddsa ->
          signature

        :ecdsa ->
          <<r::256, s::256>> = signature
          :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
      end

    failure =
      try do
        :crypto.verify(algorithm, digest, message, backend_signature, [key, curve])
      rescue
        _error in [ArgumentError, ErlangError] -> :backend_error
      end

    :backend_error = failure
    false = verifier.verify_strict(message, signature, key)
  end

  if coverage_file != "", do: :ok = :cover.export(String.to_charlist(coverage_file))
  """

  @tag :tmp_dir
  test "verifiers fail closed when the native backend cannot fetch signature algorithms", %{
    tmp_dir: dir
  } do
    on_exit(fn -> File.rm_rf!(dir) end)
    config = Path.join(dir, "openssl.cnf")

    File.write!(config, """
    config_diagnostics = 1
    openssl_conf = openssl_init

    [openssl_init]
    alg_section = algorithm_properties

    [algorithm_properties]
    default_properties = provider=bap_unavailable
    """)

    # OpenSSL reads its properties in the child VM. Import the lines it actually executes
    # when this suite is measuring coverage.
    coverage? = Process.whereis(:cover_server) != nil
    coverage_file = if coverage?, do: Path.join(dir, "crypto.coverdata"), else: ""

    if coverage? do
      assert {:file, _} = :cover.is_compiled(Ed25519)
      assert {:file, _} = :cover.is_compiled(Es256)
    end

    {output, status} =
      System.cmd(
        "elixir",
        [
          "--erl",
          "+S 2:2",
          "-pa",
          Mix.Project.compile_path(),
          "-e",
          @probe,
          "--",
          @vectors,
          coverage_file
        ],
        env: [{"OPENSSL_CONF", config}],
        stderr_to_stdout: true
      )

    assert status == 0, output

    if coverage? do
      assert :ok = :cover.import(String.to_charlist(coverage_file))
    end
  end
end
