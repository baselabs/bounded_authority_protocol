# Run through `mix run --no-start`. The stock sbom.cyclonedx task starts :sbom
# recursively, including hex_core's :ssh dependency. Generation uses hex_core's
# modules, not its application lifecycle, so keep it code-only and start the
# remaining SBOM dependencies and supervisor explicitly.
defmodule BoundedAuthorityProtocol.SbomGenerator do
  def run!(arguments) do
    assert_no_ssh_startup!()

    case Application.load(:sbom) do
      :ok -> :ok
      {:error, {:already_loaded, :sbom}} -> :ok
    end

    {:ok, dependencies} = :application.get_key(:sbom, :applications)

    for app <- dependencies -- [:kernel, :stdlib, :elixir, :hex_core] do
      {:ok, _started} = Application.ensure_all_started(app)
    end

    {:ok, _supervisor} = SBoM.Application.start(:normal, [])
    load_ca_certificates!()
    SBoM.CLI.run(["cyclonedx" | arguments], :mix)

    assert_no_ssh_startup!()
    IO.puts("SBOM generated; hex_core=stopped, ssh=stopped")
  end

  defp load_ca_certificates! do
    case :public_key.cacerts_load() do
      :ok ->
        :ok

      {:error, _reason} ->
        # If the system trust store cannot load, reuse the real CA certificates
        # Hex uses for dependency downloads. Keep TLS verification enabled for
        # sbom's Hex API metadata requests.
        certificates =
          Enum.map(Hex.HTTP.SSL.get_ca_certs(), &{:Certificate, &1, :not_encrypted})

        path =
          Path.join(System.tmp_dir!(), "bap-sbom-ca-#{System.unique_integer([:positive])}.pem")

        try do
          File.write!(path, :public_key.pem_encode(certificates))
          :ok = :public_key.cacerts_load(String.to_charlist(path))
        after
          File.rm(path)
        end
    end
  end

  defp assert_no_ssh_startup! do
    started = Application.started_applications() |> Enum.map(&elem(&1, 0))

    if :hex_core in started or :ssh in started do
      raise "SBOM generation must not start hex_core or ssh applications"
    end
  end
end

BoundedAuthorityProtocol.SbomGenerator.run!(System.argv())
