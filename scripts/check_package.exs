Code.require_file("../tools/architecture_gate.exs", __DIR__)

defmodule BoundedAuthorityProtocol.PackageCheck do
  @moduledoc false

  alias BoundedAuthorityProtocol.ArchitectureGate

  @expected_files MapSet.new([
                    ".formatter.exs",
                    "CHANGELOG.md",
                    "LICENSE",
                    "NOTICE",
                    "README.md",
                    "SECURITY.md",
                    "docs/adr/0001-public-protocol-verifier-boundary.md",
                    "docs/adr/0002-normative-v1-parsing-profile.md",
                    "docs/protocol-v1.md",
                    "docs/design/conformance-contract.md",
                    "docs/design/protocol-charter.md",
                    "docs/design/threat-model.md",
                    "hex_metadata.config",
                    "lib/bounded_authority_protocol.ex",
                    "lib/bounded_authority_protocol/v1.ex",
                    "lib/bounded_authority_protocol/v1/base64url.ex",
                    "lib/bounded_authority_protocol/v1/bounds.ex",
                    "lib/bounded_authority_protocol/v1/json.ex",
                    "lib/bounded_authority_protocol/v1/key_locator.ex",
                    "lib/bounded_authority_protocol/v1/violation.ex",
                    "mix.exs",
                    "priv/conformance/v1/schemas/grant-header.schema.json",
                    "priv/conformance/v1/schemas/json-value.schema.json",
                    "usage-rules.md"
                  ])

  def run! do
    source_root = Path.expand("..", __DIR__)
    scratch_root = unique_tmp_root!()
    package_root = Path.join(scratch_root, "package")
    archive_path = Path.join(scratch_root, "bounded_authority_protocol-0.1.0.tar")
    consumer_root = Path.join(scratch_root, "consumer")

    try do
      run!("mix", ["hex.build", "--output", archive_path], source_root, [])
      assert_regular_nonempty!(archive_path)

      Hex.Tar.unpack!(archive_path, package_root)

      check_exact_files!(package_root)
      check_metadata!(package_root)
      compile_package!(package_root)
      check_architecture!(package_root)
      compile_consumer!(consumer_root, package_root)

      IO.puts("package archive boundary passed")
    after
      File.rm_rf!(scratch_root)
    end
  end

  defp unique_tmp_root! do
    template = Path.join(System.tmp_dir!(), "bounded-authority-package.XXXXXX")

    case System.cmd("mktemp", ["-d", template], stderr_to_stdout: true) do
      {path, 0} ->
        path = String.trim(path)

        if File.dir?(path),
          do: path,
          else: fail!("mktemp returned a missing directory")

      {output, status} ->
        fail!("mktemp exited with status #{status}: #{String.trim(output)}")
    end
  end

  defp check_exact_files!(package_root) do
    actual =
      package_root
      |> Path.join("**/*")
      |> Path.wildcard(match_dot: true)
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&Path.relative_to(&1, package_root))
      |> MapSet.new()

    unless actual == @expected_files do
      missing = MapSet.difference(@expected_files, actual) |> Enum.sort()
      unexpected = MapSet.difference(actual, @expected_files) |> Enum.sort()

      fail!(
        "package file census mismatch; missing=#{inspect(missing)} " <>
          "unexpected=#{inspect(unexpected)}"
      )
    end
  end

  defp check_metadata!(package_root) do
    path = Path.join(package_root, "hex_metadata.config")

    metadata =
      case :file.consult(String.to_charlist(path)) do
        {:ok, terms} -> Map.new(terms)
        {:error, reason} -> fail!("cannot read Hex metadata: #{inspect(reason)}")
      end

    expected = %{
      "app" => "bounded_authority_protocol",
      "build_tools" => ["mix"],
      "licenses" => ["Apache-2.0"],
      "name" => "bounded_authority_protocol",
      "requirements" => [],
      "version" => "0.1.0"
    }

    Enum.each(expected, fn {key, expected_value} ->
      actual_value = metadata |> Map.get(key) |> decode_metadata()

      unless actual_value == expected_value do
        fail!(
          "Hex metadata #{key} must be #{inspect(expected_value)}, " <>
            "got #{inspect(actual_value)}"
        )
      end
    end)
  end

  defp decode_metadata(value) when is_binary(value), do: value
  defp decode_metadata(value) when is_list(value), do: Enum.map(value, &decode_metadata/1)

  defp decode_metadata({left, right}),
    do: {decode_metadata(left), decode_metadata(right)}

  defp decode_metadata(value), do: value

  defp compile_package!(package_root) do
    environment = [{"MIX_ENV", "prod"}]
    run!("mix", ["deps.get", "--only", "prod"], package_root, environment)
    run!("mix", ["compile", "--warnings-as-errors"], package_root, environment)
  end

  defp check_architecture!(package_root) do
    case ArchitectureGate.check(package_root) do
      [] -> :ok
      violations -> fail!(ArchitectureGate.format(violations))
    end
  end

  defp compile_consumer!(consumer_root, package_root) do
    File.mkdir_p!(Path.join(consumer_root, "lib"))

    File.write!(
      Path.join(consumer_root, "mix.exs"),
      """
      defmodule BoundedAuthorityProtocolConsumer.MixProject do
        use Mix.Project

        def project do
          [
            app: :bounded_authority_protocol_consumer,
            version: "0.0.0",
            elixir: "~> 1.18",
            deps: [
              {:bounded_authority_protocol, path: #{inspect(package_root)}}
            ]
          ]
        end
      end
      """
    )

    consumer_source =
      """
      defmodule BoundedAuthorityProtocolConsumer do
        @moduledoc false

        def package_contract? do
          header =
            Base.url_encode64(
              ~s({"alg":"EdDSA","typ":"ba+cap","kid":"package-proof"}),
              padding: false
            )

          Code.ensure_loaded?(BoundedAuthorityProtocol) and
            match?(
              {:ok,
               %BoundedAuthorityProtocol.V1.KeyLocator{
                 kid: "package-proof",
                 trust: :not_evaluated
               }},
              BoundedAuthorityProtocol.V1.untrusted_key_locator(header <> "..")
            )
        end

        def decoder_contract? do
          with {:ok, "package-proof"} <-
                 BoundedAuthorityProtocol.V1.Base64Url.decode("cGFja2FnZS1wcm9vZg", %{}),
               {:error, :invalid} <-
                 BoundedAuthorityProtocol.V1.Base64Url.decode("cGFja2FnZS1wcm9vZg=", %{}),
               {:ok, {:object, [{"answer", {:integer, 42}}]}} <-
                 BoundedAuthorityProtocol.V1.Json.decode(~s({"answer":42}), %{}),
               {:error, :invalid} <-
                 BoundedAuthorityProtocol.V1.Json.decode(
                   ~s({"answer":42,"answer":43}),
                   %{}
                 ) do
            true
          else
            _failure -> false
          end
        end
      end
      """

    check_decoder_contract_calls!(consumer_source)

    File.write!(
      Path.join(consumer_root, "lib/bounded_authority_protocol_consumer.ex"),
      consumer_source
    )

    environment = [{"MIX_ENV", "prod"}]
    run!("mix", ["deps.get"], consumer_root, environment)
    run!("mix", ["compile", "--warnings-as-errors"], consumer_root, environment)

    run!(
      "mix",
      [
        "run",
        "--no-start",
        "-e",
        "unless BoundedAuthorityProtocolConsumer.package_contract?() and " <>
          "BoundedAuthorityProtocolConsumer.decoder_contract?(), do: System.halt(1)"
      ],
      consumer_root,
      environment
    )
  end

  defp check_decoder_contract_calls!(consumer_source) do
    expected_calls = [
      {[:BoundedAuthorityProtocol, :V1, :Base64Url], :decode, 2},
      {[:BoundedAuthorityProtocol, :V1, :Json], :decode, 2}
    ]

    target_modules = expected_calls |> Enum.map(&elem(&1, 0)) |> MapSet.new()
    quoted = Code.string_to_quoted!(consumer_source)

    {_quoted, actual_calls} =
      Macro.prewalk(quoted, %{}, fn
        {{:., _dot_meta, [{:__aliases__, _alias_meta, module}, function]}, _call_meta, arguments} =
            node,
        counts ->
          key = {module, function, length(arguments)}

          if function == :decode and MapSet.member?(target_modules, module) do
            {node, Map.update(counts, key, 1, &(&1 + 1))}
          else
            {node, counts}
          end

        node, counts ->
          {node, counts}
      end)

    expected_counts = Map.new(expected_calls, &{&1, 2})

    unless actual_calls == expected_counts do
      fail!(
        "packed consumer decoder calls must be #{inspect(expected_counts)}, " <>
          "got #{inspect(actual_calls)}"
      )
    end
  end

  defp assert_regular_nonempty!(path) do
    unless File.regular?(path) and File.stat!(path).size > 0 do
      fail!("package archive is missing or empty")
    end
  end

  defp run!(command, arguments, directory, environment) do
    options = [
      cd: directory,
      env: environment,
      into: IO.stream(:stdio, :line),
      stderr_to_stdout: true
    ]

    case System.cmd(command, arguments, options) do
      {_output, 0} -> :ok
      {_output, status} -> fail!("#{command} exited with status #{status}")
    end
  end

  defp fail!(message), do: raise("package check failed: #{message}")
end

BoundedAuthorityProtocol.PackageCheck.run!()
