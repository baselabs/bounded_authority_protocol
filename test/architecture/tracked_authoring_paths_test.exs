defmodule BoundedAuthorityProtocol.TrackedAuthoringPathsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  @manifest """
  lib/bounded_authority_protocol.ex
  lib/bounded_authority_protocol/**
  priv/conformance/**
  test/conformance/**
  docs/protocol-v1.md
  docs/governance.md
  docs/design/protocol-charter.md
  docs/design/conformance-contract.md
  docs/design/standards-track.md
  docs/design/threat-model.md
  usage-rules.md
  docs/adr/**
  SECURITY.md
  sdks/**
  """
  @exception ".kimosabe/critical-surfaces"

  test "real index and HEAD ancestry exclude local authoring directories" do
    entries = git!(".", ["ls-files", "-z"]) |> String.split(<<0>>, trim: true)

    for positive <- [".gitleaks.toml", ".formatter.exs", @exception] do
      assert positive in entries
    end

    assert scan(".") == []
  end

  test "exact regular manifest passes; every path component is checked" do
    repo = repo!()
    assert scan(repo) == []

    for path <- [
          "lib/.kimosabe/x",
          ".KIMOSABE/x",
          ".kimosabe./x",
          ".forge /x",
          ".forge",
          ".kimosabe/critical-surfaces.bak",
          "sub/.kimosabe/critical-surfaces"
        ] do
      put!(repo, path, "public canary\n")
      assert scan(repo) != [], path
      git!(repo, ["rm", "-f", "--", path])
    end

    git!(repo, ["rm", "-f", "--", @exception])
    put!(repo, @exception <> "/x", "public canary\n")
    assert scan(repo) != []
  end

  test "the exception pins bytes and modes without following links" do
    repo = repo!()

    for content <- [
          @manifest <> "x",
          String.replace(@manifest, "\n", "\r\n"),
          <<239, 187, 191>> <> @manifest
        ] do
      put!(repo, @exception, content)
      assert scan(repo) != []
    end

    put!(repo, @exception, @manifest)
    blob = git!(repo, ["rev-parse", ":" <> @exception]) |> String.trim()
    commit = git!(repo, ["rev-parse", "HEAD"]) |> String.trim()

    for {mode, object} <- [{"120000", blob}, {"100755", blob}, {"160000", commit}] do
      git!(repo, ["update-index", "--cacheinfo", "#{mode},#{object},#{@exception}"])
      assert scan(repo) != []
    end

    git!(repo, ["update-index", "--cacheinfo", "100644,#{blob},#{@exception}"])
    File.rm!(Path.join(repo, @exception))
    File.ln_s!("/nonexistent-public-probe", Path.join(repo, @exception))
    assert scan(repo) != []
    git!(repo, ["update-index", "--force-remove", @exception])
    git!(repo, ["update-index", "--add", "--cacheinfo", "160000,#{commit},.kimosabe"])
    assert scan(repo) != []
  end

  test "deleted side-branch paths and renames remain visible after merge" do
    repo = repo!()
    git!(repo, ["switch", "-c", "side"])
    put!(repo, ".forge/removed.txt", "public canary\n")
    commit!(repo)
    git!(repo, ["mv", ".forge/removed.txt", "renamed.txt"])
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
    put!(repo, ".forge/merge.txt", "public canary\n")
    commit!(repo)
    git!(repo, ["rm", ".forge/merge.txt"])
    commit!(repo)
    git!(repo, ["config", "log.diffMerges", "off"])
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

  test "unreadable working manifest fails closed and a linked parent is rejected" do
    repo = repo!()
    manifest = Path.join(repo, @exception)
    File.rm!(manifest)
    assert_raise File.Error, fn -> scan(repo) end
    File.write!(manifest, @manifest)
    File.chmod!(manifest, 0o755)
    assert scan(repo) != []
    File.chmod!(manifest, 0o644)
    assert scan(repo) == []
    File.rename!(Path.dirname(manifest), Path.join(repo, "public-target"))
    File.ln_s!("public-target", Path.dirname(manifest))
    assert scan(repo) != []
  end

  # Read the index and its blobs, never the contents of a tracked symlink. History is
  # HEAD ancestry, including both parents of merges; unrelated refs are an owner audit.
  def scan(repo) do
    unless String.trim(git!(repo, ["rev-parse", "--is-shallow-repository"])) == "false" do
      raise "full history is required"
    end

    tip =
      git!(repo, ["ls-files", "-s", "-z"])
      |> String.split(<<0>>, trim: true)
      |> Enum.flat_map(&index_findings(repo, &1))

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
      |> Enum.filter(&(&1 != @exception and forbidden_path?(&1)))
      |> Enum.map(fn _path -> :historical_path end)

    tip ++ history
  end

  defp index_findings(repo, entry) do
    [metadata, path] = String.split(entry, "\t", parts: 2)
    [mode, blob, stage] = String.split(metadata, " ")

    cond do
      path == @exception ->
        if mode == "100644" and stage == "0" and
             git!(repo, ["cat-file", "blob", blob]) == @manifest and
             regular_manifest?(Path.join(repo, path)) do
          []
        else
          [:manifest]
        end

      forbidden_path?(path) ->
        [:tracked_path]

      true ->
        []
    end
  end

  defp regular_manifest?(path) do
    with %{type: :directory} <- File.lstat!(Path.dirname(path)),
         %{type: :regular, mode: mode} <- File.lstat!(path) do
      Bitwise.band(mode, 0o111) == 0 and File.read!(path) == @manifest
    else
      _ -> false
    end
  end

  defp forbidden_path?(path) do
    path
    |> String.split("/")
    |> Enum.any?(fn component ->
      Regex.replace(~r/[. ]+$/, ascii_lowercase(component), "") in [".forge", ".kimosabe"]
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
    put!(repo, @exception, @manifest)
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
