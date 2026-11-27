defmodule BoundedAuthorityProtocol.Conformance.VerdictDigestGateTest do
  use ExUnit.Case, async: true

  # Two `mix run` subprocesses regenerate every corpus verdict; a loaded runner can take
  # longer than ExUnit's 60-second default (seeded coverage run 44706506709 timed out).
  @moduletag timeout: 300_000

  test "the generator is red on a stale manifest and green after restoration" do
    root = Path.expand("../..", __DIR__)

    temporary =
      Path.join(System.tmp_dir!(), "bap-verdict-gate-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(temporary) end)
    scripts = Path.join(temporary, "scripts")
    File.mkdir_p!(scripts)
    manifest = Path.join(temporary, "priv/conformance/verdict-digests.json")
    File.mkdir_p!(Path.dirname(manifest))
    generator = Path.join(scripts, "regen_verdict_digests.exs")
    source = File.read!(Path.join(root, "scripts/regen_verdict_digests.exs"))

    source =
      String.replace(
        source,
        "Code.require_file(\"corpus_verdicts.exs\", __DIR__)",
        "Code.require_file(#{inspect(Path.join(root, "scripts/corpus_verdicts.exs"))})"
      )

    File.write!(generator, source)
    File.write!(manifest, "{}")

    {output, status} =
      System.cmd("mix", ["run", "--no-start", generator], cd: root, stderr_to_stdout: true)

    assert status != 0
    assert output =~ "stale corpus verdict-digests.json"
    IO.puts("RED stale verdict manifest: stale corpus verdict-digests.json")
    File.cp!(Path.join(root, "priv/conformance/verdict-digests.json"), manifest)

    {output, status} =
      System.cmd("mix", ["run", "--no-start", generator], cd: root, stderr_to_stdout: true)

    assert status == 0, output
    assert output =~ "corpus verdict digests: ok"
    IO.puts("GREEN stale verdict manifest: restored")
  end
end
