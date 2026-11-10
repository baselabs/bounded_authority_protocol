# Post-publish read-back: runs every notebook against the release on Hex, exactly as a reader
# would, and checks each cell against the value its prose states.
#
#     elixir scripts/livebook_registry_readback.exs [NOTEBOOK.livemd ...]
#
# With no arguments it reads every notebook under docs/livebooks. Each notebook runs in its own
# `elixir` VM: its own Mix.install setup cell installs the package from the public Hex registry
# (no path or Git dependency is substituted), then the shared harness
# (test_support/livebook_harness.ex) evaluates the remaining cells and compares every stated
# value. The script prints one line per notebook and exits 1 if any notebook fails.
#
# This is release evidence, not a CI gate: it needs network access to Hex, and it is meaningful
# only after the version the setup cells require has been published. Record its output with the
# release read-back.

defmodule BoundedAuthorityProtocol.LivebookRegistryReadback do
  @moduledoc false

  @root Path.expand("..", __DIR__)
  @harness Path.join(@root, "test_support/livebook_harness.ex")

  def main(arguments) do
    notebooks =
      case arguments do
        [] -> @root |> Path.join("docs/livebooks/*.livemd") |> Path.wildcard() |> Enum.sort()
        paths -> Enum.map(paths, &Path.expand/1)
      end

    if notebooks == [], do: fail("no notebooks found")

    results = Enum.map(notebooks, &read_back/1)

    for {notebook, status, output} <- results do
      label = if status == 0, do: "ok", else: "FAILED"
      IO.puts("#{label} #{Path.relative_to(notebook, @root)}")
      output |> String.split("\n", trim: true) |> Enum.each(&IO.puts("  " <> &1))
    end

    if Enum.any?(results, fn {_notebook, status, _output} -> status != 0 end),
      do: System.halt(1)
  end

  defp read_back(notebook) do
    # The child VM installs from Hex inside a fresh install cache, so a cached build of the
    # source tree can never stand in for the registry release.
    cache =
      Path.join(System.tmp_dir!(), "bap-livebook-readback-#{System.unique_integer([:positive])}")

    code = """
    Code.require_file(#{inspect(@harness)})
    alias BoundedAuthorityProtocol.TestSupport.LivebookHarness
    source = File.read!(#{inspect(notebook)})
    {:ok, setup} = LivebookHarness.setup_code(source)
    Code.eval_string(setup)
    vsn = Application.spec(:bounded_authority_protocol, :vsn)
    IO.puts("installed bounded_authority_protocol " <> to_string(vsn) <> " from Hex")

    case LivebookHarness.check(source, #{inspect(notebook)}) do
      [] -> IO.puts("every stated value agrees")
      errors ->
        IO.puts(Enum.join(errors, "\\n"))
        System.halt(1)
    end
    """

    try do
      {output, status} =
        System.cmd("elixir", ["-e", code],
          env: [{"MIX_INSTALL_DIR", cache}],
          stderr_to_stdout: true
        )

      {notebook, status, output}
    after
      File.rm_rf(cache)
    end
  end

  defp fail(message) do
    IO.puts(:stderr, "livebook read-back: #{message}")
    System.halt(1)
  end
end

BoundedAuthorityProtocol.LivebookRegistryReadback.main(System.argv())
