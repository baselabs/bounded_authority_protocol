defmodule BoundedAuthorityProtocol.ScratchGitMaintenanceTest do
  @moduledoc """
  Scratch-repository maintenance gate: every script or test that runs a git
  command which starts git's automatic maintenance (`commit`, `merge`, `fetch`,
  `pull`, `push`, `am`, `rebase`, `clone`, `cherry-pick`, `revert`) also turns
  that maintenance off for the repositories it drives: `maintenance.auto` false
  and `gc.auto` 0.

  From git 2.54 the default maintenance strategy is "geometric", and those
  commands start `git maintenance run --auto --detach` (a push into a local
  bare remote starts it in the remote, from its receive-pack): a repack that
  keeps writing into `.git` after the command returns. Removing the throwaway
  repository (`File.rm_rf!/1`, `shutil.rmtree`, `rm -rf`) then races that
  process and fails intermittently with "directory not empty". Hosted CI runs
  git 2.55, so the failure appears there and not on older local git.

  The scan reads every tracked or untracked, non-ignored Elixir, Python, and
  shell file, so it covers `scripts/`, `test/`, `lib/`, `tools/`, and `sdks/`
  alike.

  Goes RED on: a file that drives such a git command without setting both
  values; a scan that no longer sees the four known drivers, which would make
  the gate vacuous.
  """

  use ExUnit.Case, async: true

  @self "test/architecture/scratch_git_maintenance_test.exs"
  @known_drivers [
    "scripts/secret_scan.sh",
    "scripts/test_private_identifier_guard.py",
    "test/architecture/public_surface_privacy_test.exs",
    "test/architecture/tracked_authoring_paths_test.exs"
  ]

  @subcommands "commit|merge|fetch|pull|push|am|rebase|clone|cherry-pick|revert"

  # A git invocation whose subcommand starts automatic maintenance:
  #   Elixir   git!(repo, ["commit", ...])
  #   Python   git(repo, "commit", ...)  and  run("git", "commit", ...)
  #   shell    git -C "$repo" -c key=value commit ...  (at the start of a line)
  @maintenance_invocations [
    ~r/\[\s*"(?:#{@subcommands})"/,
    ~r/(?:\bgit\(\s*[\w.]+\s*,\s*|"git"\s*,\s*)"(?:#{@subcommands})"/,
    ~r/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*git\b[^\n#]*?\s(?:#{@subcommands})(?:\s|$)/m
  ]

  # The settings themselves, as git config keys with their values (a comment
  # naming a key does not count): a git config argument list, a -c option, or
  # a GIT_CONFIG_KEY_n/GIT_CONFIG_VALUE_n pair.
  @maintenance_off ~r/"maintenance\.auto"\s*,\s*"false"|maintenance\.auto=false\b|=maintenance\.auto\s+GIT_CONFIG_VALUE_\d+=false\b/
  @gc_off ~r/"gc\.auto"\s*,\s*"0"|gc\.auto=0\b|=gc\.auto\s+GIT_CONFIG_VALUE_\d+=0\b/

  test "every scratch git repository that commits, merges, fetches, or pushes disables automatic maintenance" do
    {listing, 0} =
      System.cmd("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])

    # Each file is read once. Another async test may create and remove a
    # transient file in the tree between the listing and the read; a file
    # that is gone by then is skipped rather than failing the scan.
    drivers =
      for path <- String.split(listing, <<0>>, trim: true),
          Path.extname(path) in [".ex", ".exs", ".py", ".sh"],
          path != @self,
          {:ok, content} <- [File.read(path)],
          Enum.any?(@maintenance_invocations, &(content =~ &1)),
          do: {path, content}

    paths = Enum.map(drivers, &elem(&1, 0))

    assert Enum.sort(@known_drivers -- paths) == [],
           "the scan no longer sees the known git drivers #{inspect(@known_drivers -- paths)}"

    offenders =
      for {path, content} <- drivers,
          not (content =~ @maintenance_off and content =~ @gc_off),
          do: path

    assert offenders == [],
           "these files run git commands that start detached background maintenance " <>
             "without setting maintenance.auto false and gc.auto 0: #{inspect(offenders)}"
  end
end
