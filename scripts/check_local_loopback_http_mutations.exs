mutations = [
  {"bypass", "verifier_bypass"},
  {"host_header", "host_header_authority"},
  {"forwarded_headers", "forwarded_header_authority"}
]

Enum.each(mutations, fn {env_value, mutation} ->
  {output, status} =
    System.cmd("mix", ["run", "scripts/check_local_loopback_http.exs"],
      env: [{"BAP_LOOPBACK_MUTANT", env_value}],
      stderr_to_stdout: true
    )

  if status == 0 do
    raise "local-loopback #{mutation} mutation did not make the real-socket drill fail"
  end

  unless String.contains?(output, "local-loopback HTTP drill failed") do
    raise "local-loopback #{mutation} mutation failed for an unexpected reason:\n#{output}"
  end

  IO.puts(
    :json.encode(%{
      check: "local_loopback_http_mutation",
      mutation: mutation,
      result: "red_proven_on_real_ipv4_and_ipv6_socket_drill"
    })
  )
end)
