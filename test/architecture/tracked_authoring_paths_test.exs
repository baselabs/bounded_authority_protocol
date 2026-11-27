defmodule BoundedAuthorityProtocol.TrackedAuthoringPathsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  # Only these dot-prefixed components occur in the project's tracked configuration.
  # Match exact spellings at every depth; new configuration requires an explicit review.
  @allowed_dot_components [
    ".config",
    ".formatter.exs",
    ".gitattributes",
    ".github",
    ".gitignore",
    ".gitleaks.toml",
    ".tool-versions"
  ]

  test "the current tree and index contain only approved dot-prefixed components" do
    entries = git!(".", ["ls-files", "-z"]) |> String.split(<<0>>, trim: true)

    actual =
      entries
      |> Enum.flat_map(&String.split(&1, "/"))
      |> Enum.filter(&String.starts_with?(&1, "."))
      |> MapSet.new()

    assert actual == MapSet.new(@allowed_dot_components)
    assert scan(".") == []
  end

  test "approved dot-prefixed configuration is accepted at every depth" do
    repo = repo!()

    paths =
      [".github/workflows/ci.yml", "sdks/rust/.config/nextest.toml"] ++
        Enum.map(@allowed_dot_components, &"fixtures/#{&1}/config.txt")

    for path <- paths do
      put!(repo, path, "public configuration\n")
    end

    assert scan(repo) == []
    commit!(repo)
    assert scan(repo) == []
  end

  test "every unapproved dot-prefixed path component is checked" do
    repo = repo!()
    assert scan(repo) == []

    paths = [
      ".local-notes/x",
      "lib/.local-notes/x",
      ".local-notes",
      ".local-notes/config.bak",
      "sub/.local-notes/config",
      ".LOCAL-NOTES/x",
      ".local-notes./x",
      ".local-notes /x",
      ".GITHUB/x",
      ".github./x",
      ".github /x",
      "fixtures/.unlisted.json"
    ]

    for path <- paths do
      put!(repo, path, "public canary\n")
      assert {:index, path} in scan(repo), path
      git!(repo, ["rm", "-f", "--", path])
      assert scan(repo) == []
    end
  end

  test "a directory gitlink or symlink entry is a finding in the index and tree" do
    for mode <- ["160000", "120000"] do
      repo = repo!()

      object =
        case mode do
          "160000" -> git!(repo, ["rev-parse", "HEAD"]) |> String.trim()
          "120000" -> git!(repo, ["rev-parse", "HEAD:README.md"]) |> String.trim()
        end

      git!(repo, ["update-index", "--add", "--cacheinfo", "#{mode},#{object},.local-notes"])
      assert {:index, ".local-notes"} in scan(repo)
      commit!(repo)
      git!(repo, ["update-index", "--force-remove", ".local-notes"])
      assert scan(repo) == [{:tree, ".local-notes"}]
    end
  end

  test "renames into and out of an unapproved directory check both current snapshots" do
    repo = repo!()
    File.mkdir_p!(Path.join(repo, ".local-notes"))
    git!(repo, ["mv", "README.md", ".local-notes/renamed.txt"])
    assert scan(repo) == [{:index, ".local-notes/renamed.txt"}]
    commit!(repo)
    git!(repo, ["mv", ".local-notes/renamed.txt", "renamed.txt"])
    assert scan(repo) == [{:tree, ".local-notes/renamed.txt"}]
    commit!(repo)
    assert scan(repo) == []
  end

  test "merged side-branch paths are checked until their removal is committed" do
    repo = repo!()
    git!(repo, ["switch", "-c", "side"])
    put!(repo, ".local-notes/side.txt", "public canary\n")
    commit!(repo)
    git!(repo, ["switch", "main"])
    put!(repo, "main.txt", "main\n")
    commit!(repo)
    assert scan(repo) == []
    git!(repo, ["merge", "--no-edit", "side"])
    assert {:tree, ".local-notes/side.txt"} in scan(repo)
    git!(repo, ["rm", ".local-notes/side.txt"])
    assert scan(repo) == [{:tree, ".local-notes/side.txt"}]
    commit!(repo)
    assert scan(repo) == []
  end

  test "merge-resolution-only paths are checked without rewriting history" do
    repo = repo!()
    git!(repo, ["switch", "-c", "side"])
    put!(repo, "side.txt", "side\n")
    commit!(repo)
    git!(repo, ["switch", "main"])
    put!(repo, "main.txt", "main\n")
    commit!(repo)
    git!(repo, ["merge", "--no-commit", "side"])
    put!(repo, ".local-notes/merge.txt", "public canary\n")
    assert scan(repo) == [{:index, ".local-notes/merge.txt"}]
    commit!(repo)
    git!(repo, ["config", "log.diffMerges", "off"])
    assert {:tree, ".local-notes/merge.txt"} in scan(repo)
    git!(repo, ["rm", ".local-notes/merge.txt"])
    commit!(repo)
    assert scan(repo) == []
  end

  test "historical paths under other refs do not change current-tree findings" do
    repo = repo!()
    put!(repo, ".local-notes/archive/other.md", "public canary\n")
    commit!(repo)
    git!(repo, ["tag", "-a", "historical-path", "-m", "historical path probe"])
    git!(repo, ["rm", "--", ".local-notes/archive/other.md"])
    assert scan(repo) == [{:tree, ".local-notes/archive/other.md"}]
    commit!(repo)
    assert scan(repo) == []
  end

  test "a shallow checkout still checks its current tree and index" do
    source = repo!()
    put!(source, "second.txt", "public canary\n")
    commit!(source)
    shallow = source <> "-shallow"
    on_exit(fn -> File.rm_rf!(shallow) end)
    git!(source, ["clone", "--depth=1", "--no-local", source, shallow])
    assert String.trim(git!(shallow, ["rev-parse", "--is-shallow-repository"])) == "true"
    assert scan(shallow) == []
    put!(shallow, ".local-notes/shallow.txt", "public canary\n")
    assert scan(shallow) == [{:index, ".local-notes/shallow.txt"}]
  end

  test "Git errors fail closed" do
    repo = repo!()

    assert_raise RuntimeError, ~r/Git failed/, fn ->
      scan(Path.join(repo, "nonexistent"))
    end
  end

  # Inspect both snapshots, including staged removals, gitlinks, and symlinks.
  # Historical trees stay unchanged and are not publication candidates.
  def scan(repo) do
    for {source, args} <- [
          {:index, ["ls-files", "-z"]},
          {:tree, ["ls-tree", "-r", "--name-only", "-z", "HEAD"]}
        ],
        path <- git!(repo, args) |> String.split(<<0>>, trim: true),
        forbidden_path?(path),
        do: {source, path}
  end

  defp forbidden_path?(path) do
    path
    |> String.split("/")
    |> Enum.any?(fn component ->
      String.starts_with?(component, ".") and component not in @allowed_dot_components
    end)
  end

  defp repo! do
    repo = Path.join(System.tmp_dir!(), "bap-path-guard-#{System.unique_integer([:positive])}")
    File.mkdir_p!(repo)
    on_exit(fn -> File.rm_rf!(repo) end)
    git!(repo, ["init", "--initial-branch=main"])
    # Disable background maintenance so cleanup cannot race a detached repack.
    git!(repo, ["config", "maintenance.auto", "false"])
    git!(repo, ["config", "gc.auto", "0"])
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
