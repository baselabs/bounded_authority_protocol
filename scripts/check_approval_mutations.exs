Code.require_file("../tools/build_path.exs", __DIR__)

approval = "lib/bounded_authority_protocol/action_approval/v1.ex"
assertion = "lib/bounded_authority_protocol/content_assertion/v1/codec.ex"
record = "lib/bounded_authority_protocol/action_approval/v1/record_codec.ex"

mutations = [
  {approval, "snapshot-freshness", "age >= 0 and age <= cap", "is_integer(age) and is_integer(cap)"},
  {record, "wire-canonicality", "{:ok, ^bytes} <- encode(record, bounds, ca, false)",
   "{:ok, _} <- encode(record, bounds, ca, false)"},
  {record, "strict-resource-set", "previous < name", "previous <= name"},
  {approval, "key-window", ":ok <- Codec.key_window(parsed, entry.key),", ""},
  {approval, "issuer", ":ok <- check(parsed.iss == entry.issuer, :issuer_mismatch),", ""},
  {approval, "audience", ":ok <- check(parsed.aud == context.audience, :audience_mismatch),", ""},
  {approval, "request", ":ok <- request_binding(parsed, record, context),",
   ":ok <- request_binding(parsed, record, Map.put(context, :request_id, record.request_id)),"},
  {approval, "expected-role",
   ":ok <- check(Enum.member?(context.roles, record.approver_role), :role_not_permitted),", ""},
  {approval, "signature-before-key-window",
   """
            :ok <- Codec.signature(parsed, entry.key, suite),
            :ok <- Codec.key_window(parsed, entry.key),
   """,
   """
            :ok <- Codec.key_window(parsed, entry.key),
            :ok <- Codec.signature(parsed, entry.key, suite),
   """},
  {approval, "issuer-before-audience",
   """
            :ok <- check(parsed.iss == entry.issuer, :issuer_mismatch),
            :ok <- check(parsed.aud == context.audience, :audience_mismatch),
   """,
   """
            :ok <- check(parsed.aud == context.audience, :audience_mismatch),
            :ok <- check(parsed.iss == entry.issuer, :issuer_mismatch),
   """},
  {assertion, "suite-before-payload",
   """
       with {:ok, framed} <- frame(compact, bounds),
            :ok <- admit_suite(framed, suite) do
         parse_claims(framed, bounds)
   """,
   """
       with {:ok, framed} <- frame(compact, bounds),
            {:ok, parsed} <- parse_claims(framed, bounds),
            :ok <- admit_suite(framed, suite) do
         {:ok, parsed}
   """},
  {assertion, "scalar-gate", "true <- Es256.canonical_signature?(signature),",
   "true <- is_binary(signature),"}
]

args =
  Path.expand("..", __DIR__)
  |> BoundedAuthorityProtocol.BuildPath.resolve("test")
  |> Path.join("lib/*/ebin")
  |> Path.wildcard()
  |> Enum.flat_map(&["-pa", &1])

run = fn source, label, expected_exit ->
  code = """
  Code.compiler_options(ignore_module_conflict: true)
  Code.compile_string(#{inspect(source, limit: :infinity, printable_limit: :infinity)})
  ExUnit.start(autorun: false, seed: 42)
  Code.require_file("test/bounded_authority_protocol/action_approval/corpus_test.exs")
  result = ExUnit.run()
  IO.puts("APPROVAL_MUTATION_RESULT total=" <> Integer.to_string(result.total))
  System.halt(cond do
    result.total != 9 -> 1
    result.failures > 0 -> 42
    true -> 0
  end)
  """

  {output, status} = System.cmd("elixir", args ++ ["-e", code], stderr_to_stdout: true)

  unless status == expected_exit and String.contains?(output, "APPROVAL_MUTATION_RESULT total=9") do
    IO.puts(output)
    raise "approval mutation #{label} did not produce expected test verdict: #{status}"
  end

  IO.puts("#{label}: #{if status == 0, do: "control passed", else: "mutation killed"}")
end

run.(File.read!(approval), "unmodified", 0)

for {file, label, before, after_mutation} <- mutations do
  source = File.read!(file)

  unless length(:binary.matches(source, before)) == 1,
    do: raise("approval mutation #{label} does not have exactly one target")

  run.(String.replace(source, before, after_mutation, global: false), label, 42)
end
