Code.require_file("../tools/build_path.exs", __DIR__)

approval = "lib/bounded_authority_protocol/action_approval/v1.ex"
assertion = "lib/bounded_authority_protocol/content_assertion/v1/codec.ex"
record = "lib/bounded_authority_protocol/action_approval/v1/record_codec.ex"
jcs = "lib/bounded_authority_protocol/v1/jcs.ex"

# Each edit names the independent case that must fail. A compile error, an unrelated failure,
# or a test census that cannot execute all checks cannot kill a mutation.
omissions =
  for {label, clause, case_id} <- [
        {"signed-sub-bound", "check(RecordCodec.request_id?(parsed.sub, bounds, ca), :malformed)",
         "signed-sub-over"},
        {"signature", "Codec.signature(parsed, entry.key, suite)", "bad-signature"},
        {"key-window", "Codec.key_window(parsed, entry.key)", "key-window-lower"},
        {"issuer", "check(parsed.iss == entry.issuer, :issuer_mismatch)", "issuer-mismatch"},
        {"audience", "check(parsed.aud == context.audience, :audience_mismatch)",
         "audience-mismatch"},
        {"subject", "check(record.subject == context.subject, :subject_mismatch)",
         "subject-mismatch"},
        {"action", "check(record.action == context.action, :scope_mismatch)", "action-mismatch"},
        {"resources", "check(record.resources == context.resources, :scope_mismatch)",
         "resources-mismatch"},
        {"lifetime", "check(parsed.exp - parsed.iat <= context.max_lifetime, :lifetime_too_long)",
         "lifetime-too-long"},
        {"expected-role",
         "check(Enum.member?(context.roles, record.approver_role), :role_not_permitted)",
         "role-not-required"}
      ] do
    {approval, label, "         :ok <- #{clause},\n", "", case_id}
  end

weakening = [
  {approval, "freshness-lower", "age >= 0 and age <= cap", "age <= cap", "future-trust"},
  {approval, "freshness-upper", "age >= 0 and age <= cap", "age >= 0 and is_integer(cap)",
   "old-trust"},
  {approval, "snapshot-domain", "snapshot: %{\n             trust_domain: domain,",
   "snapshot: %{\n             trust_domain: _domain,", "wrong-trust-domain"},
  {approval, "snapshot-suite", "             suite: suite,\n             provenance: provenance,",
   "             suite: _snapshot_suite,\n             provenance: provenance,",
   "wrong-trust-suite"},
  {approval, "snapshot-provenance",
   "scalar_identity?(provenance, ca) and Codec.integer?(as_of, ca)",
   "is_binary(provenance) and Codec.integer?(as_of, ca)", "malformed-provenance"},
  {approval, "duplicate-key", "false <- Map.has_key?(keys, kid)", "false <- is_nil(kid)",
   "duplicate-key-entry"},
  {approval, "historical-key-shape",
   "public_key: public_key,\n                 valid_from: _,\n                 valid_before: _",
   "public_key: public_key", "es256-missing-valid_from-selected"},
  {approval, "enrolled-role",
   "check(Enum.member?(entry.roles, record.approver_role), :role_not_permitted)",
   "check(is_list(entry.roles), :role_not_permitted)", "empty-enrolled-roles"},
  {approval, "active-duration", "is_nil(max_active) or parsed.exp - parsed.nbf <= max_active",
   "is_nil(max_active) or is_integer(max_active)", "active-too-long"},
  {approval, "record-content-digest", "FixedBytes.equal?(parsed.content_digest, digest)",
   "is_binary(digest)", "wrong-content_digest"},
  {approval, "record-profile", "parsed.profile == @profile", "is_binary(parsed.profile)",
   "wrong-profile"},
  {approval, "record-profile-digest", "FixedBytes.equal?(parsed.profile_digest, @profile_digest)",
   "is_binary(parsed.profile_digest)", "wrong-profile_digest"},
  {approval, "expected-request", "record.request_id == context.request_id",
   "is_binary(context.request_id)", "request-expected"},
  {approval, "signed-request", "record.request_id == parsed.sub", "is_binary(parsed.sub)",
   "request-signed"},
  {approval, "revision", "FixedBytes.equal?(record.revision_digest, context.revision_digest)",
   "is_binary(context.revision_digest)", "revision-mismatch"},
  {record, "wire-canonicality", "{:ok, ^bytes} <- encode(record, bounds, ca, false)",
   "{:ok, _} <- encode(record, bounds, ca, false)", "trailing-lf"},
  {record, "old-wire-success-fallthrough", "_failure -> {:error, :invalid}", "failure -> failure",
   "trailing-lf"},
  {record, "old-wire-key-set-fallthrough", "_failure -> {:error, :invalid}", "failure -> failure",
   "missing-action"},
  {record, "wire-object-root", "_failure -> {:error, :invalid}",
   "{:ok, {:string, _}} = root -> root\n      _failure -> {:error, :invalid}", "scalar-root"},
  {record, "strict-resource-set", "previous < name", "previous <= name", "duplicate-resource"},
  {record, "encoded-size-preflight", "true <- fits_encoding?(record, names, bounds.record_bytes)",
   "true <- is_list(names)", "authoring-escaped-size-plus"},
  {record, "revision-width", "<<encoded::binary-size(43)>>", "encoded",
   "revision-width-before-base64"},
  {jcs, "escaped-size-early-stop", "escaped_size(_value, size, allowance) when size > allowance",
   "escaped_size(<<>>, size, allowance) when size > allowance", "escaped-size-early-stop"},
  {assertion, "key-window-lower", "p.iat >= key.valid_from and p.nbf >= key.valid_from",
   "is_integer(key.valid_from)", "key-window-lower"},
  {assertion, "key-window-upper", "p.exp <= key.valid_before", "is_integer(p.exp)",
   "key-window-upper"},
  {assertion, "signature-width", "byte_size(signature) == bounds.signature_bytes",
   "is_binary(signature)", "signature-width-before-suite"},
  {assertion, "not-yet-valid", "parsed.nbf <= now", "is_integer(now)", "not-yet-valid"},
  {assertion, "expiry", "now < parsed.exp", "is_integer(parsed.exp)", "expired"},
  {assertion, "scalar-gate", "true <- Es256.canonical_signature?(signature),",
   "true <- is_binary(signature),", "assembly-high-s"}
]

active =
  ":ok <-\n           check(is_nil(max_active) or parsed.exp - parsed.nbf <= max_active, :active_too_long)"

ordering =
  for {label, first, second, case_id} <- [
        {"context-before-trust", "{:ok, max_active} <- preflight(context, ca, bounds)",
         "{:ok, entries, as_of} <- snapshot_context(context, suite, ca)",
         "context-before-snapshot"},
        {"trust-before-freshness",
         "{:ok, keys} <- admit_entries(entries, %{}, suite, ca, bounds)",
         ":ok <- check(fresh?(context.now - as_of, context.max_staleness), :stale_trust)",
         "stale-snapshot-null-key"},
        {"stale-before-shape",
         ":ok <- check(fresh?(context.now - as_of, context.max_staleness), :stale_trust)",
         "{:ok, parsed} <- Codec.parse(compact, ca, suite)", "stale-before-shape"},
        {"signature-before-key-window", ":ok <- Codec.signature(parsed, entry.key, suite)",
         ":ok <- Codec.key_window(parsed, entry.key)", "signature-before-times"},
        {"key-window-before-record", ":ok <- Codec.key_window(parsed, entry.key)",
         ":ok <- record_binding(parsed, bytes, ca)", "key-window-before-record-binding"},
        {"record-before-issuer", ":ok <- record_binding(parsed, bytes, ca)",
         ":ok <- check(parsed.iss == entry.issuer, :issuer_mismatch)",
         "record-binding-before-issuer"},
        {"issuer-before-audience", ":ok <- check(parsed.iss == entry.issuer, :issuer_mismatch)",
         ":ok <- check(parsed.aud == context.audience, :audience_mismatch)",
         "issuer-before-audience"},
        {"audience-before-request",
         ":ok <- check(parsed.aud == context.audience, :audience_mismatch)",
         ":ok <- request_binding(parsed, record, context)", "audience-before-request"},
        {"request-before-subject", ":ok <- request_binding(parsed, record, context)",
         ":ok <- check(record.subject == context.subject, :subject_mismatch)",
         "request-before-subject"},
        {"subject-before-scope",
         ":ok <- check(record.subject == context.subject, :subject_mismatch)",
         ":ok <- check(record.action == context.action, :scope_mismatch)",
         "subject-before-scope"},
        {"scope-before-time",
         ":ok <- check(record.resources == context.resources, :scope_mismatch)",
         ":ok <- Codec.current_window(parsed, context.now)", "scope-before-time"},
        {"time-before-lifetime", ":ok <- Codec.current_window(parsed, context.now)",
         ":ok <- check(parsed.exp - parsed.iat <= context.max_lifetime, :lifetime_too_long)",
         "window-before-duration"},
        {"lifetime-before-active",
         ":ok <- check(parsed.exp - parsed.iat <= context.max_lifetime, :lifetime_too_long)",
         active, "lifetime-before-active"},
        {"active-before-role", active,
         ":ok <- check(Enum.member?(context.roles, record.approver_role), :role_not_permitted)",
         "active-before-role"}
      ] do
    {approval, label, "         #{first},\n         #{second},",
     "         #{second},\n         #{first},", case_id}
  end

early_ordering = [
  {approval, "record-before-key",
   """
            {:ok, record} <- parse_record(bytes, bounds, ca),
            {:ok, entry} <- key_entry(keys, parsed.attestor_key_id),
   """,
   """
            {:ok, entry} <- key_entry(keys, parsed.attestor_key_id),
            {:ok, record} <- parse_record(bytes, bounds, ca),
   """, "noncanonical-record-before-key"},
  {approval, "lookup-before-signature", ":error -> {:error, :unknown_key}",
   """
   :error ->
           case Map.values(keys) do
             [entry | _] -> {:ok, entry}
             [] -> {:error, :unknown_key}
           end
   """
   |> String.trim_trailing("\n"), "unknown-key"},
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
   """, "suite-before-claims"}
]

args =
  Path.expand("..", __DIR__)
  |> BoundedAuthorityProtocol.BuildPath.resolve("test")
  |> Path.join("lib/*/ebin")
  |> Path.wildcard()
  |> Enum.flat_map(&["-pa", &1])

run = fn source, label, check, verdict, expected_exit ->
  code = """
  Code.compiler_options(ignore_module_conflict: true)
  Code.compile_string(#{inspect(source, limit: :infinity, printable_limit: :infinity)})
  ExUnit.start(autorun: false, seed: 42)
  Code.require_file("test/bounded_authority_protocol/action_approval/corpus_test.exs")
  #{check}
  """

  {output, status} = System.cmd("elixir", args ++ ["-e", code], stderr_to_stdout: true)

  results =
    output
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "APPROVAL_MUTATION_RESULT "))

  unless status == expected_exit and results == ["APPROVAL_MUTATION_RESULT " <> verdict] do
    IO.puts(output)
    raise "approval mutation #{label} did not produce expected test verdict: #{status}"
  end

  IO.puts("#{label}: #{verdict}")
end

control = """
case ExUnit.run() do
  %{total: 12, failures: 0, skipped: 0, excluded: 0} ->
    IO.puts("APPROVAL_MUTATION_RESULT control passed")

  result ->
    raise "unexpected full corpus control: " <> inspect(result)
end
"""

run.(File.read!(approval), "unmodified", control, "control passed", 0)

for {file, label, before, after_mutation, case_id} <-
      omissions ++ weakening ++ ordering ++ early_ordering do
  source = File.read!(file)

  unless length(:binary.matches(source, before)) == 1,
    do: raise("approval mutation #{label} does not have exactly one target")

  witness = """
  id = #{inspect(case_id)}

  try do
    BoundedAuthorityProtocol.ActionApproval.CorpusTest.assert_mutation_witness(id)
  rescue
    error in ExUnit.AssertionError ->
      if error.message === id do
        IO.puts("APPROVAL_MUTATION_RESULT mutation killed by " <> id)
        System.halt(42)
      end

      reraise error, __STACKTRACE__
  end
  """

  mutant = String.replace(source, before, after_mutation, global: false)
  run.(mutant, label, witness, "mutation killed by " <> case_id, 42)
end
