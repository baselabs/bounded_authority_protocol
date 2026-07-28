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
                    "docs/adr/0003-standard-jws-and-verified-grant-results.md",
                    "docs/protocol-v1.md",
                    "docs/design/conformance-contract.md",
                    "docs/design/protocol-charter.md",
                    "docs/design/threat-model.md",
                    "hex_metadata.config",
                    "lib/bounded_authority_protocol.ex",
                    "lib/bounded_authority_protocol/v1.ex",
                    "lib/bounded_authority_protocol/v1/base64url.ex",
                    "lib/bounded_authority_protocol/v1/bounds.ex",
                    "lib/bounded_authority_protocol/v1/compact_jws.ex",
                    "lib/bounded_authority_protocol/v1/credentials.ex",
                    "lib/bounded_authority_protocol/v1/decoded_grant.ex",
                    "lib/bounded_authority_protocol/v1/decoded_proof.ex",
                    "lib/bounded_authority_protocol/v1/envelope_facts.ex",
                    "lib/bounded_authority_protocol/v1/expected_grant.ex",
                    "lib/bounded_authority_protocol/v1/expected_request.ex",
                    "lib/bounded_authority_protocol/v1/grant.ex",
                    "lib/bounded_authority_protocol/v1/grant_facts.ex",
                    "lib/bounded_authority_protocol/v1/jcs.ex",
                    "lib/bounded_authority_protocol/v1/json.ex",
                    "lib/bounded_authority_protocol/v1/jwk.ex",
                    "lib/bounded_authority_protocol/v1/key_locator.ex",
                    "lib/bounded_authority_protocol/v1/operation.ex",
                    "lib/bounded_authority_protocol/v1/proof.ex",
                    "lib/bounded_authority_protocol/v1/request_digest.ex",
                    "lib/bounded_authority_protocol/v1/runtime.ex",
                    "lib/bounded_authority_protocol/v1/selector.ex",
                    "lib/bounded_authority_protocol/v1/signing_input.ex",
                    "lib/bounded_authority_protocol/v1/trusted_issuer.ex",
                    "lib/bounded_authority_protocol/v1/uri.ex",
                    "lib/bounded_authority_protocol/v1/violation.ex",
                    "mix.exs",
                    "priv/conformance/v1/schemas/grant-payload.schema.json",
                    "priv/conformance/v1/schemas/grant-header.schema.json",
                    "priv/conformance/v1/schemas/json-value.schema.json",
                    "priv/conformance/v1/schemas/proof-header.schema.json",
                    "priv/conformance/v1/schemas/proof-payload.schema.json",
                    "priv/conformance/v1/schemas/public-okp-jwk.schema.json",
                    "priv/conformance/v1/schemas/selector.schema.json",
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
      compile_consumer!(consumer_root, package_root, source_root)

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

  defp compile_consumer!(consumer_root, package_root, source_root) do
    File.mkdir_p!(Path.join(consumer_root, "lib"))

    fixture =
      source_root
      |> Path.join("priv/conformance/v1/vectors/grant-holder-proof.json")
      |> File.read!()
      |> :json.decode()

    context = fixture["expected_context"]

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

        @grant #{inspect(fixture["grant"]["compact"])}
        @proof #{inspect(fixture["proof"]["compact"])}

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

        def bap03_contract? do
          alias BoundedAuthorityProtocol.V1
          alias BoundedAuthorityProtocol.V1.Bounds
          alias BoundedAuthorityProtocol.V1.Credentials
          alias BoundedAuthorityProtocol.V1.ExpectedGrant
          alias BoundedAuthorityProtocol.V1.ExpectedRequest
          alias BoundedAuthorityProtocol.V1.TrustedIssuer

          bounds = Bounds.maximum()

          trusted = %TrustedIssuer{
            key_id: #{inspect(context["trusted_issuer"]["key_id"])},
            public_key:
              Base.url_decode64!(
                #{inspect(context["trusted_issuer"]["public_key_base64url"])},
                padding: false
              )
          }

          expected_grant = %ExpectedGrant{
            issuer: #{inspect(context["issuer"])},
            audience: #{inspect(context["audience"])},
            evaluation_time: #{inspect(context["evaluation_time"])},
            clock_skew: #{inspect(context["clock_skew"])},
            bounds: bounds
          }

          arguments =
            {:object,
             [
               {"record",
                {:object,
                 [
                   {"tier", {:string, "gold"}},
                   {"region", {:string, "us-east"}}
                 ]}},
               {"limit", {:integer, 10}}
             ]}

          expected_request = %ExpectedRequest{
            trusted_issuer: trusted,
            issuer: #{inspect(context["issuer"])},
            audience: #{inspect(context["audience"])},
            method: #{inspect(context["method"])},
            target_uri: #{inspect(context["target_uri"])},
            invocation_id: #{inspect(context["invocation_id"])},
            operation: #{inspect(context["operation"])},
            cast_arguments: arguments,
            evaluation_time: #{inspect(context["evaluation_time"])},
            clock_skew: #{inspect(context["clock_skew"])},
            proof_max_age: #{inspect(context["proof_max_age"])},
            nonce: {:required, #{inspect(context["nonce"]["required"])}},
            bounds: bounds
          }

          credentials = %Credentials{grant: @grant, proof: @proof}

          with {:ok, decoded_grant} <- V1.decode_grant(@grant, bounds),
               true <- decoded_grant.verification == :not_evaluated,
               {:ok, decoded_proof} <- V1.decode_proof(@proof, bounds),
               true <- decoded_proof.verification == :not_evaluated,
               {:ok, grant_facts} <- V1.verify_grant(@grant, trusted, expected_grant),
               true <- grant_facts.authorization == :not_evaluated,
               {:ok, envelope_facts} <- V1.check_envelope(credentials, expected_request),
               true <- envelope_facts.authorization == :not_evaluated,
               {:ok, _digest} <- V1.request_digest("read_record", arguments, bounds),
               {:error, :invalid} <- V1.decode_grant(@proof, bounds),
               {:error, :invalid} <-
                 V1.check_envelope(%{credentials | proof: @grant}, expected_request) do
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
          "BoundedAuthorityProtocolConsumer.decoder_contract?() and " <>
          "BoundedAuthorityProtocolConsumer.bap03_contract?(), do: System.halt(1)"
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
