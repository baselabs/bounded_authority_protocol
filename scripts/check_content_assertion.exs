# The quality alias runs this after mix test. A fresh VM prevents require-file
# caching and ExUnit's completed run from turning this check into a zero-test run.
test_file =
  Path.expand("../test/bounded_authority_protocol/content_assertion/corpus_test.exs", __DIR__)

code = """
ExUnit.start(autorun: false, seed: 42)
Code.require_file(#{inspect(test_file)})
result = ExUnit.run()
if result.failures != 0 or result.total != 4, do: System.halt(1)
{head, 0} = System.cmd("git", ["rev-parse", "HEAD"])
{status, 0} = System.cmd("git", ["status", "--porcelain"])
index = File.read!("priv/conformance/attestation-profiles/content-assertion/v1/index.json")

IO.puts(
  :json.encode(%{
    profile: "bap-content-assertion/1",
    source_head: String.trim(head),
    working_tree_dirty: status != "",
    corpus_index_sha256: Base.encode16(:crypto.hash(:sha256, index), case: :lower),
    tests: result.total,
    failures: result.failures
  })
)
"""

{output, status} =
  System.cmd("elixir", ["-pa", Mix.Project.compile_path(), "-e", code], stderr_to_stdout: true)

IO.write(output)
if status != 0, do: System.halt(status)
