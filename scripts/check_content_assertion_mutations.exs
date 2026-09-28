# Each mutant is compiled only in a fresh VM's memory. The checkout and loaded
# application of the parent process remain unchanged; no application copy is made.
source = File.read!("lib/bounded_authority_protocol/content_assertion/v1/codec.ex")

mutations = [
  {"signature", ":crypto.verify(:eddsa", "true or :crypto.verify(:eddsa"},
  {"successor-context", "[:iss, :aud, :sub, :profile]", "[]"},
  {"facts-completeness", "shape?(f, @facts_fields, ContentAssertionFacts)", "true"},
  {"content-byte-bound", "byte_size(bytes) <= bounds.content_bytes", "true"},
  {"nonempty-content", "byte_size(bytes) > 0", "true"},
  {"content-domain", "<<\"BAP1-CONTENT\", 0>>", "<<\"BAP1-CONTENT\">>"},
  {"expected-content", "FixedBytes.equal?(p.content_digest, e.content_digest)", "true"},
  {"expected-schema", "FixedBytes.equal?(p.profile_digest, e.profile_digest)", "true"},
  {"expected-issuer", "p.iss == e.issuer", "true"},
  {"expected-audience", "p.aud == e.audience", "true"},
  {"expected-subject", "p.sub == e.subject", "true"},
  {"expected-profile", "p.profile == e.profile", "true"},
  {"expected-key", "p.attestor_key_id == key.key_id", "true"},
  {"current-window", "parsed.nbf <= expected.now and expected.now < parsed.exp", "true"},
  {"key-lower-window", "p.iat >= key.valid_from and p.nbf >= key.valid_from", "true"},
  {"key-upper-window", "p.exp <= key.valid_before", "true"},
  {"closed-members", "Enum.sort(Enum.map(members, &elem(&1, 0))) == keys", "true"},
  {"canonical-bytes", "canonical == bytes", "true"},
  {"genesis-pair", "value.gen == 1 == (value.prev == @zero)", "true"},
  {"structural-window", "value.iat <= value.nbf and value.nbf < value.exp", "true"},
  {"negative-magnitude", "value >= -bounds.integer_magnitude", "true"},
  {"successor-schema", "FixedBytes.equal?(previous.profile_digest, next.profile_digest)", "true"},
  {"successor-generation", "next.gen == previous.gen + 1", "true"},
  {"successor-digest", "FixedBytes.equal?(next.prev, previous.digest)", "true"},
  {"successor-time", "next.iat >= previous.iat", "true"},
  {"successor-identity", "next.jti != previous.jti", "true"},
  {"facts-verification", "f.verification == :signature_and_window", "true"},
  {"facts-trust", "f.trust == :not_evaluated", "true"},
  {"facts-digest-width", "digest?(f.digest)", "true"}
]

paths = Path.wildcard("_build/test/lib/*/ebin")
args = Enum.flat_map(paths, &["-pa", &1])

run = fn changed, label, expected_exit ->
  code = """
  Code.compiler_options(ignore_module_conflict: true)
  Code.compile_string(#{inspect(changed, limit: :infinity, printable_limit: :infinity)})
  ExUnit.start(autorun: false, seed: 42)
  Code.require_file("test/bounded_authority_protocol/content_assertion/v1_test.exs")
  Code.require_file("test/bounded_authority_protocol/content_assertion/corpus_test.exs")
  result = ExUnit.run()
  IO.puts("CONTENT_MUTATION_RESULT total=" <> Integer.to_string(result.total) <> " failures=" <> Integer.to_string(result.failures))
  System.halt(if result.total == 11 and result.failures > 0, do: 42, else: if(result.total == 11 and result.failures == 0, do: 0, else: 1))
  """

  {output, status} = System.cmd("elixir", args ++ ["-e", code], stderr_to_stdout: true)

  unless status == expected_exit and
           String.contains?(output, "CONTENT_MUTATION_RESULT total=11 failures=") do
    IO.puts(output)
    raise "content assertion mutation #{label} did not produce expected test verdict: #{status}"
  end

  IO.puts("#{label}: #{if status == 0, do: "control passed", else: "mutation killed"}")
end

run.(source, "unmodified", 0)

Enum.each(mutations, fn {label, old, replacement} ->
  unless length(:binary.matches(source, old)) == 1,
    do: raise("mutation #{label} does not have exactly one target")

  run.(String.replace(source, old, replacement, global: false), label, 42)
end)

compact_source = File.read!("lib/bounded_authority_protocol/v1/compact_jws.ex")

header_guard = """
  defp exact_signing_header?(:content_assertion, members, bounds) when length(members) == 3 do
    case Map.new(members) do
"""

unless length(:binary.matches(compact_source, header_guard)) == 1,
  do: raise("content assembly header mutation does not have exactly one target")

permissive_header =
  String.replace(header_guard, "case Map.new(members) do", "true or case Map.new(members) do")

run.(
  String.replace(compact_source, header_guard, permissive_header, global: false),
  "assembly-header",
  42
)

IO.puts("content assertion mutations: #{length(mutations) + 1}/#{length(mutations) + 1} killed")
