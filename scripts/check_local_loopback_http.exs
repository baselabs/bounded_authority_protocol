alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: LoopbackV1
alias BoundedAuthorityProtocol.V1, as: StandardV1
alias BoundedAuthorityProtocol.V1.Bounds
alias BoundedAuthorityProtocol.V1.Credentials
alias BoundedAuthorityProtocol.V1.ExpectedRequest
alias BoundedAuthorityProtocol.V1.Grant
alias BoundedAuthorityProtocol.V1.Jwk
alias BoundedAuthorityProtocol.V1.Operation
alias BoundedAuthorityProtocol.V1.Proof
alias BoundedAuthorityProtocol.V1.TrustedIssuer

defmodule LocalLoopbackHttpDrill do
  @moduledoc false

  def run do
    source_head_sha =
      System.cmd("git", ["rev-parse", "HEAD"], stderr_to_stdout: true) |> elem(0) |> String.trim()

    source_tree_clean =
      System.cmd("git", ["status", "--porcelain=v1", "--untracked-files=all"],
        stderr_to_stdout: true
      )
      |> elem(0)
      |> String.trim()
      |> then(&(&1 == <<>>))

    corpus_index =
      "priv/conformance/application-profiles/local-loopback-http/v1/index.json"
      |> File.read!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    results = [
      exercise(:ipv4, :valid),
      exercise(:ipv4, :wrong_nonce),
      exercise(:ipv4, :misleading_authority_headers),
      exercise(:ipv6, :valid),
      exercise(:ipv6, :wrong_nonce),
      exercise(:ipv6, :misleading_authority_headers)
    ]

    unless Enum.all?(results, fn result ->
             (result.scenario in ["valid", "misleading_authority_headers"] and
                result.status == 204 and result.verdict == "verified") or
               (result.scenario == "wrong_nonce" and result.status == 401 and
                  result.verdict == "rejected")
           end) do
      raise "local-loopback HTTP drill failed: #{inspect(results)}"
    end

    receipt = %{
      profile: "bap-application-proof/local-loopback-http/1",
      source_head_sha: source_head_sha,
      source_tree_clean: source_tree_clean,
      corpus_index_sha256: corpus_index,
      elixir: System.version(),
      transport: "real_gen_tcp_http",
      keys: "ephemeral_in_memory",
      credentials_retained: false,
      results: results
    }

    IO.puts(:json.encode(receipt))
  end

  defp exercise(family, scenario) do
    ip = if family == :ipv4, do: {127, 0, 0, 1}, else: {0, 0, 0, 0, 0, 0, 0, 1}
    family_options = if family == :ipv4, do: [], else: [:inet6]

    {:ok, listener} =
      :gen_tcp.listen(
        0,
        [:binary, active: false, packet: :raw, reuseaddr: true, ip: ip] ++ family_options
      )

    {:ok, {^ip, port}} = :inet.sockname(listener)
    host = if family == :ipv4, do: "127.0.0.1", else: "[::1]"
    target_uri = "http://#{host}:#{port}/invoke"
    context = credentials(target_uri)

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        request = recv_headers(socket, <<>>)
        [request_line | header_lines] = :binary.split(request, "\r\n", [:global])
        [method, path, "HTTP/1.1"] = String.split(request_line, " ")
        headers = parse_headers(header_lines)

        direct_target = expected_target(host, port, path, headers)

        expected_nonce =
          if scenario == :wrong_nonce, do: "wrong-#{context.nonce}", else: context.nonce

        expected = %ExpectedRequest{
          trusted_issuer: %TrustedIssuer{
            key_id: "issuer-loopback-drill",
            public_key: context.issuer_public
          },
          issuer: "urn:example:issuer:loopback-drill",
          audience: "urn:example:audience:loopback-drill",
          method: method,
          target_uri: direct_target,
          invocation_id: context.invocation_id,
          operation: "read_record",
          cast_arguments: {:object, [{"record_id", {:string, "record-1"}}]},
          evaluation_time: context.issued_at,
          clock_skew: 0,
          proof_max_age: 30,
          nonce: {:required, expected_nonce},
          bounds: Bounds.maximum()
        }

        verdict =
          if System.get_env("BAP_LOOPBACK_MUTANT") == "bypass" do
            {:ok, :bypassed}
          else
            LoopbackV1.check_envelope(
              %Credentials{grant: headers["bap-grant"], proof: headers["bap-proof"]},
              expected
            )
          end

        status = if match?({:ok, _}, verdict), do: 204, else: 401

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 #{status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )

        :gen_tcp.close(socket)
        %{status: status, verdict: if(status == 204, do: "verified", else: "rejected")}
      end)

    {:ok, client} = :gen_tcp.connect(ip, port, [:binary, active: false] ++ family_options, 5_000)

    request =
      "POST /invoke HTTP/1.1\r\n" <>
        request_authority_headers(host, port, scenario) <>
        "BAP-Grant: #{context.grant}\r\n" <>
        "BAP-Proof: #{context.proof}\r\n" <>
        "Connection: close\r\n\r\n"

    :ok = :gen_tcp.send(client, request)
    {:ok, response} = :gen_tcp.recv(client, 0, 5_000)
    :gen_tcp.close(client)
    :gen_tcp.close(listener)
    %{status: status, verdict: verdict} = Task.await(server, 5_000)
    true = String.starts_with?(response, "HTTP/1.1 #{status}")

    %{
      address: host,
      family: Atom.to_string(family),
      port: port,
      scenario: Atom.to_string(scenario),
      status: status,
      verdict: verdict,
      target_source: "listener_sockname_plus_request_line"
    }
  end

  defp expected_target(host, port, path, headers) do
    direct_target = "http://#{host}:#{port}#{path}"

    case System.get_env("BAP_LOOPBACK_MUTANT") do
      "host_header" ->
        "http://#{headers["host"]}#{path}"

      "forwarded_headers" ->
        "#{headers["x-forwarded-proto"] || "http"}://#{headers["x-forwarded-host"] || "#{host}:#{port}"}#{path}"

      _ ->
        direct_target
    end
  end

  defp request_authority_headers(_host, _port, :misleading_authority_headers) do
    "Host: attacker.example:9443\r\n" <>
      "Forwarded: for=192.0.2.1;host=attacker.example:9443;proto=https\r\n" <>
      "X-Forwarded-Host: attacker.example:9443\r\n" <>
      "X-Forwarded-Proto: https\r\n" <>
      "X-Forwarded-Port: 9443\r\n" <>
      "X-Original-Host: attacker.example:9443\r\n"
  end

  defp request_authority_headers(host, port, _scenario), do: "Host: #{host}:#{port}\r\n"

  defp credentials(target_uri) do
    {issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
    {holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, holder_thumbprint} = Jwk.public_key_thumbprint_raw(holder_public, %{})
    issued_at = System.system_time(:second)
    invocation_id = uuid4()
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    grant = %Grant{
      key_id: "issuer-loopback-drill",
      issuer: "urn:example:issuer:loopback-drill",
      grant_id: "urn:example:grant:#{invocation_id}",
      audiences: ["urn:example:audience:loopback-drill"],
      issued_at: issued_at - 1,
      not_before: issued_at - 1,
      expires_at: issued_at + 60,
      holder_thumbprint: holder_thumbprint,
      operations: [%Operation{name: "read_record", selectors: [:all]}]
    }

    {:ok, grant_input} = StandardV1.grant_signing_input(grant, %{})
    grant_signature = :crypto.sign(:eddsa, :none, grant_input.message, [issuer_private, :ed25519])
    {:ok, grant_compact} = StandardV1.assemble_compact(grant_input, grant_signature, %{})

    proof = %Proof{
      holder_public_key: holder_public,
      proof_id: "urn:example:proof:#{invocation_id}",
      method: "POST",
      target_uri: target_uri,
      issued_at: issued_at,
      nonce: nonce,
      invocation_id: invocation_id,
      operation: "read_record",
      grant_compact: grant_compact,
      cast_arguments: {:object, [{"record_id", {:string, "record-1"}}]}
    }

    {:ok, proof_input} = LoopbackV1.proof_signing_input(proof, %{})
    proof_signature = :crypto.sign(:eddsa, :none, proof_input.message, [holder_private, :ed25519])
    {:ok, proof_compact} = LoopbackV1.assemble_compact(proof_input, proof_signature, %{})

    %{
      grant: grant_compact,
      proof: proof_compact,
      issuer_public: issuer_public,
      invocation_id: invocation_id,
      issued_at: issued_at,
      nonce: nonce
    }
  end

  defp recv_headers(socket, acc) do
    if :binary.match(acc, "\r\n\r\n") == :nomatch do
      {:ok, bytes} = :gen_tcp.recv(socket, 0, 5_000)
      recv_headers(socket, acc <> bytes)
    else
      acc
    end
  end

  defp parse_headers(lines) do
    Enum.reduce(lines, %{}, fn line, acc ->
      case String.split(line, ": ", parts: 2) do
        [name, value] -> Map.put(acc, String.downcase(name), value)
        _ -> acc
      end
    end)
  end

  defp uuid4 do
    <<a::32, b::16, c::16, d::16, e::48>> = :crypto.strong_rand_bytes(16)
    c = Bitwise.bor(Bitwise.band(c, 0x0FFF), 0x4000)
    d = Bitwise.bor(Bitwise.band(d, 0x3FFF), 0x8000)

    :io_lib.format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", [a, b, c, d, e])
    |> IO.iodata_to_binary()
  end
end

LocalLoopbackHttpDrill.run()
