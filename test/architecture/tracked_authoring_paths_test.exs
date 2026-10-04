defmodule BoundedAuthorityProtocol.TrackedAuthoringPathsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  # The local .kimosabe directory is never tracked. Two paths were tracked by earlier commits
  # and untracked on 2026-09-28; they remain in HEAD ancestry until that history is rewritten,
  # so the history scan admits exactly these two paths and nothing else. The index admits none.
  @historical [
    ".kimosabe/critical-surfaces",
    ".kimosabe/handoffs/2026-09-19-ap2-interop-and-ecdsa-suite.md"
  ]

  test "real index and HEAD ancestry exclude local authoring directories" do
    entries = git!(".", ["ls-files", "-z"]) |> String.split(<<0>>, trim: true)

    for positive <- [".gitleaks.toml", ".formatter.exs"] do
      assert positive in entries
    end

    for historical <- @historical do
      refute historical in entries
    end

    assert scan(".") == []
  end

  test "a formerly tracked path is a finding when tracked again" do
    for historical <- @historical do
      repo = repo!()
      put!(repo, historical, "public canary\n")
      assert scan(repo) != [], historical
    end
  end

  test "every path component is checked" do
    repo = repo!()
    assert scan(repo) == []

    paths = [
      ".kimosabe/x",
      "lib/.kimosabe/x",
      ".kimosabe",
      ".kimosabe/critical-surfaces.bak",
      "sub/.kimosabe/critical-surfaces",
      ".KIMOSABE/x",
      ".kimosabe./x",
      ".kimosabe /x"
    ]

    for path <- paths do
      put!(repo, path, "public canary\n")
      assert scan(repo) != [], path
      git!(repo, ["rm", "-f", "--", path])
    end
  end

  test "a directory gitlink or symlink entry is a finding" do
    repo = repo!()
    commit = git!(repo, ["rev-parse", "HEAD"]) |> String.trim()
    git!(repo, ["update-index", "--add", "--cacheinfo", "160000,#{commit},.kimosabe"])
    assert scan(repo) != []
    git!(repo, ["update-index", "--force-remove", ".kimosabe"])

    target = Path.join(repo, "link-target")
    File.write!(target, "public-target")
    blob = git!(repo, ["hash-object", "-w", "--", target]) |> String.trim()
    File.rm!(target)
    git!(repo, ["update-index", "--add", "--cacheinfo", "120000,#{blob},.kimosabe"])
    assert scan(repo) != []
  end

  test "deleted side-branch paths and renames remain visible after merge" do
    repo = repo!()
    git!(repo, ["switch", "-c", "side"])
    put!(repo, ".kimosabe/removed.txt", "public canary\n")
    commit!(repo)
    git!(repo, ["mv", ".kimosabe/removed.txt", "renamed.txt"])
    commit!(repo)
    git!(repo, ["switch", "main"])
    put!(repo, "main.txt", "main\n")
    commit!(repo)
    git!(repo, ["merge", "--no-edit", "side"])
    assert scan(repo) != []
  end

  test "merge-resolution-only paths remain visible after removal" do
    repo = repo!()
    git!(repo, ["switch", "-c", "side"])
    put!(repo, "side.txt", "side\n")
    commit!(repo)
    git!(repo, ["switch", "main"])
    put!(repo, "main.txt", "main\n")
    commit!(repo)
    git!(repo, ["merge", "--no-commit", "side"])
    put!(repo, ".kimosabe/merge.txt", "public canary\n")
    commit!(repo)
    git!(repo, ["rm", ".kimosabe/merge.txt"])
    commit!(repo)
    git!(repo, ["config", "log.diffMerges", "off"])
    assert scan(repo) != []
  end

  test "a history path outside the two historical paths is a finding" do
    repo = repo!()
    put!(repo, ".kimosabe/handoffs/2026-09-19-other.md", "public canary\n")
    commit!(repo)
    git!(repo, ["rm", "-f", "--", ".kimosabe/handoffs/2026-09-19-other.md"])
    commit!(repo)
    assert scan(repo) != []
  end

  test "unavailable history and Git errors fail closed" do
    repo = repo!()
    head = git!(repo, ["rev-parse", "HEAD"]) |> String.trim()
    File.write!(Path.join(repo, ".git/shallow"), head <> "\n")

    assert_raise RuntimeError, ~r/full history/, fn ->
      scan(repo)
    end

    assert_raise RuntimeError, ~r/Git failed/, fn ->
      scan(Path.join(repo, "nonexistent"))
    end
  end

  # Read the index, never the contents of a tracked file. History is HEAD ancestry,
  # including both parents of merges; unrelated refs are an owner audit.
  def scan(repo) do
    unless String.trim(git!(repo, ["rev-parse", "--is-shallow-repository"])) == "false" do
      raise "full history is required"
    end

    tip =
      git!(repo, ["ls-files", "-z"])
      |> String.split(<<0>>, trim: true)
      |> Enum.filter(&forbidden_path?/1)
      |> Enum.map(fn _path -> :tracked_path end)

    history =
      git!(repo, [
        "log",
        "--format=",
        "--name-only",
        "-z",
        "--no-renames",
        "--diff-merges=separate",
        "HEAD"
      ])
      |> String.split(<<0>>, trim: true)
      |> Enum.map(&String.trim_leading(&1, "\n"))
      |> Enum.filter(&(&1 not in @historical and forbidden_path?(&1)))
      |> Enum.map(fn _path -> :historical_path end)

    tip ++ history
  end

  defp forbidden_path?(path) do
    path
    |> String.split("/")
    |> Enum.any?(fn component ->
      Regex.replace(~r/[. ]+$/, ascii_lowercase(component), "") == ".kimosabe"
    end)
  end

  defp ascii_lowercase(component) do
    for <<byte <- component>>, into: <<>> do
      if byte in ?A..?Z, do: <<byte + 32>>, else: <<byte>>
    end
  end

  defp repo! do
    repo = Path.join(System.tmp_dir!(), "bap-path-guard-#{System.unique_integer([:positive])}")
    File.mkdir_p!(repo)
    on_exit(fn -> File.rm_rf!(repo) end)
    git!(repo, ["init", "--initial-branch=main"])
    git!(repo, ["config", "user.email", "path-guard@example.invalid"])
    git!(repo, ["config", "user.name", "Path Guard"])
    git!(repo, ["config", "core.hooksPath", "/dev/null"])
    git!(repo, ["config", "core.excludesFile", "/dev/null"])
    git!(repo, ["config", "core.ignoreCase", "false"])
    put!(repo, "README.md", "public\n")
    commit!(repo)
    repo
  end

  defp put!(repo, path, content) do
    File.mkdir_p!(Path.dirname(Path.join(repo, path)))
    File.write!(Path.join(repo, path), content)
    git!(repo, ["add", "--", path])
  end

  defp commit!(repo), do: git!(repo, ["commit", "-m", "public path probe"])

  defp git!(repo, args) do
    case System.cmd("git", ["--no-replace-objects", "-C", repo | args],
           stderr_to_stdout: true,
           env: [
             {"GIT_GRAFT_FILE", "/dev/null"},
             {"GIT_CONFIG_COUNT", "1"},
             {"GIT_CONFIG_KEY_0", "advice.graftFileDeprecated"},
             {"GIT_CONFIG_VALUE_0", "false"}
           ]
         ) do
      {output, 0} -> output
      {_output, status} -> raise "Git failed with exit #{status}"
    end
  end
end
