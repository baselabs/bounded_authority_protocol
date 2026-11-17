defmodule BoundedAuthorityProtocol.TestSupport.GitHistory do
  @moduledoc false

  @upstream "https://github.com/baselabs/bounded_authority_protocol.git"
  @env [
    {"GIT_GRAFT_FILE", "/dev/null"},
    {"GIT_CONFIG_COUNT", "1"},
    {"GIT_CONFIG_KEY_0", "advice.graftFileDeprecated"},
    {"GIT_CONFIG_VALUE_0", "false"},
    {"GIT_TERMINAL_PROMPT", "0"}
  ]

  # Keep the source index/worktree and Git administration untouched. A shallow build snapshot
  # borrows its exact objects and refs, then fills ancestry from the public repository. Fetched
  # refs never enter the scan: only the source's refs and exact HEAD are reachable here.
  def complete!(source, upstream \\ @upstream) do
    if git!(source, ["rev-parse", "--is-shallow-repository"]) |> String.trim() == "false" do
      source
    else
      scratch =
        Path.join(System.tmp_dir!(), "bap-history-#{System.unique_integer([:positive])}")

      ExUnit.Callbacks.on_exit(fn -> File.rm_rf!(scratch) end)
      git!(source, ["init", "--bare", "--quiet", "--template=", scratch])
      git!(scratch, ["config", "maintenance.auto", "false"])
      git!(scratch, ["config", "gc.auto", "0"])

      objects =
        source
        |> git!(["rev-parse", "--path-format=absolute", "--git-path", "objects"])
        |> String.trim()

      File.write!(Path.join(scratch, "objects/info/alternates"), objects <> "\n")

      source
      |> git!(["for-each-ref", "--format=%(objectname) %(refname)"])
      |> String.split("\n", trim: true)
      |> Enum.each(fn row ->
        [sha, ref] = String.split(row, " ", parts: 2)
        git!(scratch, ["update-ref", ref, sha])
      end)

      head = source |> git!(["rev-parse", "HEAD"]) |> String.trim()
      git!(scratch, ["update-ref", "--no-deref", "HEAD", head])

      git!(scratch, [
        "fetch",
        "--refetch",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-auto-maintenance",
        "--no-recurse-submodules",
        upstream,
        "HEAD"
      ])

      # Traversal fails on any missing parent/tree/blob, including unpublished ancestors that
      # neither the source object store nor upstream supplies. Never scan a truncated graph.
      git!(scratch, ["rev-list", "--objects", "--all", "HEAD"])
      scratch
    end
  end

  defp git!(repo, args) do
    case System.cmd("git", ["--no-replace-objects", "-C", repo | args],
           stderr_to_stdout: true,
           env: @env
         ) do
      {output, 0} -> output
      {output, status} -> raise "complete Git history unavailable (exit #{status}): #{output}"
    end
  end
end
