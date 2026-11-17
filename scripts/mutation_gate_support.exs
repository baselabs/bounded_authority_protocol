Code.require_file("../tools/build_path.exs", __DIR__)

defmodule BoundedAuthorityProtocol.MutationGateSupport do
  @moduledoc false

  # Shared by the mutation batteries (scripts/check_*_mutations.exs).
  #
  # `run_all/3` runs every entry in parallel and collects each outcome instead of relying on a
  # raise inside a task to stop the battery. It prints the battery's `ok` line only when every
  # entry was caught; otherwise it names each failed entry on stderr and halts with status 3, so
  # no `ok` line ever follows a survival.
  #
  # `require_tool_node!/0` stops a battery whose targets run the independent Node runners when
  # the `node` on PATH is not the version `.tool-versions` pins: a different Node can change a
  # runner's behavior and make a mutation look caught or survived for the wrong reason.
  #
  # `run_in_scratch!/4` gives each baseline and each mutation its own scratch checkout. The test
  # suite reads this repository's tracked files and history (test/test_helper.exs refuses to start
  # outside a git checkout), so a scratch is a detached `git worktree` of HEAD sharing this
  # repository's history, with the battery's paths overlaid from the working tree so uncommitted
  # edits are what the battery tests. The worktree and its private temporary directory are removed
  # when the run ends, whatever its outcome.

  @root Path.expand("..", __DIR__)
  @survived_status 3
  @toolchain_status 2

  @doc """
  Runs `fun` on every item (in parallel), then prints `ok_line` (nothing when it is nil) or halts
  with status 3.
  """
  def run_all(items, fun, ok_line) do
    failures =
      items
      |> Task.async_stream(&outcome(&1, fun),
        max_concurrency: System.schedulers_online(),
        ordered: false,
        timeout: :infinity
      )
      |> Enum.flat_map(fn
        {:ok, :ok} -> []
        {:ok, {:failed, name, message}} -> [{name, message}]
        {:exit, reason} -> [{"(task exit)", Exception.format_exit(reason)}]
      end)

    finish(failures, length(items), ok_line)
  end

  @doc false
  def finish([], _total, nil), do: :ok
  def finish([], _total, ok_line), do: IO.puts(ok_line)

  def finish(failures, total, _ok_line) do
    for {name, message} <- failures do
      IO.puts(:stderr, "mutation gate entry failed: #{name}\n#{message}\n")
    end

    names = Enum.map_join(failures, ", ", &elem(&1, 0))

    IO.puts(
      :stderr,
      "mutation gate FAILED: #{length(failures)} of #{total} entries did not go red as " <>
        "required (#{names})"
    )

    System.halt(@survived_status)
  end

  defp outcome(item, fun) do
    fun.(item)
    :ok
  rescue
    error -> {:failed, name(item), Exception.message(error)}
  catch
    kind, reason -> {:failed, name(item), Exception.format(kind, reason)}
  end

  defp name(%{name: name}), do: name
  defp name(item), do: inspect(item)

  @doc """
  Runs `command` (an executable followed by its arguments) with `MIX_ENV=test` in a fresh scratch
  checkout and returns `{output, status}`.

  The scratch is a detached worktree of HEAD named after `label`; each of `overlay_paths` is
  replaced by its working-tree copy, `deps` links to this checkout's, and the resolved test build is copied into an isolated build path
  so the run does not recompile from nothing. `mutation`, when given as `{path, from, to}`, is
  applied before the command runs and must match exactly once.
  """
  def run_in_scratch!(label, overlay_paths, mutation, command) do
    scratch =
      Path.join(
        System.tmp_dir!(),
        "#{label}-#{System.pid()}-#{System.unique_integer([:positive, :monotonic])}"
      )

    private_tmp = scratch <> ".tmp"
    add_worktree!(scratch)

    try do
      Enum.each(overlay_paths, &overlay!(&1, scratch))
      File.ln_s!(Path.join(@root, "deps"), Path.join(scratch, "deps"))
      build_path = copy_build!(scratch)
      File.mkdir_p!(private_tmp)

      with {path, from, to} <- mutation do
        mutate_once!(Path.join(scratch, path), from, to)
      end

      [executable | arguments] = command

      System.cmd(executable, arguments,
        cd: scratch,
        env: [{"MIX_ENV", "test"}, {"MIX_BUILD_PATH", build_path}, {"TMPDIR", private_tmp}],
        stderr_to_stdout: true
      )
    after
      File.rm_rf!(private_tmp)
      remove_worktree!(scratch)
    end
  end

  defp add_worktree!(scratch) do
    git!(["worktree", "add", "--detach", "--quiet", scratch, "HEAD"])
  end

  defp remove_worktree!(scratch) do
    git!(["worktree", "remove", "--force", scratch])
  end

  defp git!(arguments) do
    case System.cmd("git", arguments, cd: @root, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {output, status} -> raise "git #{Enum.join(arguments, " ")} exited #{status}: #{output}"
    end
  end

  defp overlay!(relative, scratch) do
    source = Path.join(@root, relative)
    target = Path.join(scratch, relative)
    File.rm_rf!(target)
    File.mkdir_p!(Path.dirname(target))
    File.cp_r!(source, target)
  end

  defp copy_build!(scratch) do
    source = BoundedAuthorityProtocol.BuildPath.resolve(@root, "test")
    target = BoundedAuthorityProtocol.BuildPath.isolated(scratch, "test")

    if File.dir?(source) do
      File.mkdir_p!(Path.dirname(target))
      File.cp_r!(source, target)
    end

    target
  end

  defp mutate_once!(path, source, replacement) do
    contents = File.read!(path)

    if length(:binary.matches(contents, source)) != 1 do
      raise "mutation anchor is not exact: #{path}"
    end

    File.write!(path, String.replace(contents, source, replacement))
  end

  @doc "Halts with status 2 unless `node --version` equals the `.tool-versions` nodejs pin."
  def require_tool_node! do
    expected = tool_node_version!()

    case node_version() do
      ^expected ->
        :ok

      actual ->
        IO.puts(
          :stderr,
          "mutation gate: Node #{expected} is required (pinned in .tool-versions), found " <>
            "#{actual}. Put Node #{expected} first on PATH and run the battery again."
        )

        System.halt(@toolchain_status)
    end
  end

  @doc false
  def tool_node_version! do
    @root
    |> Path.join(".tool-versions")
    |> File.read!()
    |> String.split("\n")
    |> Enum.find_value(fn line ->
      case String.split(line) do
        ["nodejs", version] -> version
        _other -> nil
      end
    end) || raise ".tool-versions pins no nodejs version"
  end

  defp node_version do
    case System.find_executable("node") do
      nil ->
        "no node on PATH"

      node ->
        case System.cmd(node, ["--version"], stderr_to_stdout: true) do
          {"v" <> version, 0} -> String.trim(version)
          {output, status} -> "an unreadable version (exit #{status}: #{String.trim(output)})"
        end
    end
  end
end
