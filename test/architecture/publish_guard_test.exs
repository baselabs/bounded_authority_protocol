defmodule BoundedAuthorityProtocol.Architecture.PublishGuardTest do
  @moduledoc """
  Non-vacuity + scope tests for `scripts/check_sdk_publish_infra.sh` (ADR 0015 Decision 5: no SDK
  publishes from the monorepo). The guard is invoked with `<content-on-stdin> | script <path>`;
  these drive it directly with crafted (content, path) pairs.

  The broadened scan (workflows + composite actions + SDK shell scripts / Makefiles / justfiles +
  root Makefile/justfile) closes the gap where a registry-publish command hid in an executable
  surface that is not a workflow or manifest. The shell-script scan is scoped to `sdks/`
  deliberately — the guard and the pre-commit hook carry the publish-command patterns as literal
  data, so a repo-wide `*.sh` scan would self-match them; these tests pin BOTH the reach (a
  publish command in an SDK script/Makefile/composite action is caught) AND the non-self-match.
  """

  use ExUnit.Case, async: true

  @script Path.expand("../../scripts/check_sdk_publish_infra.sh", __DIR__)
  @guard_source Path.expand("../../scripts/check_sdk_publish_infra.sh", __DIR__)

  defp run(content, path) do
    tmp = Path.join(System.tmp_dir!(), "pubguard-#{System.unique_integer([:positive])}")
    File.write!(tmp, content)

    try do
      # The guard reads content on stdin; feed it from the temp file (System.cmd has no stdin
      # option on this Elixir). @script and path carry no shell metacharacters in these cases.
      {_out, status} =
        System.cmd("sh", ["-c", "#{@script} #{path} < #{tmp}"], stderr_to_stdout: true)

      status
    after
      File.rm(tmp)
    end
  end

  test "a registry-publish command in an SDK release script is caught" do
    assert run("npm publish --access public\n", "sdks/typescript/scripts/release.sh") == 1
  end

  test "a registry-publish command in an SDK Makefile is caught" do
    assert run("publish:\n\ttwine upload dist/*\n", "sdks/python/Makefile") == 1
  end

  test "a registry-publish command in an SDK justfile is caught" do
    assert run("publish:\n    cargo publish\n", "sdks/rust/justfile") == 1
  end

  test "a registry-publish command in a composite action is caught" do
    action = "runs:\n  using: composite\n  steps:\n    - run: cargo publish\n"
    assert run(action, ".github/actions/release/action.yml") == 1
  end

  test "a registry-publish command in a workflow is caught (unchanged)" do
    assert run("jobs:\n  x:\n    steps:\n      - run: npm publish\n", ".github/workflows/x.yml") ==
             1
  end

  test "the guard does not self-match its own literal pattern list" do
    # The guard file carries every publish command string as data; scanning it must NOT red.
    assert run(File.read!(@guard_source), "scripts/check_sdk_publish_infra.sh") == 0
  end

  test "publish commands with flags/args between tool and subcommand are caught" do
    # grep -F contiguous matching missed these; the flag-tolerant regex catches them.
    for cmd <- [
          "cargo +stable publish",
          "npm --access public publish",
          "yarn -s publish",
          "twine --repository x upload dist/*"
        ] do
      assert run(cmd <> "\n", "sdks/rust/scripts/release.sh") == 1, "expected #{cmd} caught"
    end
  end

  test "publish-adjacent but non-publishing commands are not false-positives" do
    for cmd <- [
          "npm run publish-docs",
          "npm version patch",
          "mix hex.build",
          "echo publishing",
          "npm run build"
        ] do
      assert run(cmd <> "\n", "sdks/typescript/scripts/build.sh") == 0, "expected #{cmd} allowed"
    end
  end

  test "a clean SDK script exits 0" do
    assert run("#!/bin/sh\nnpm run build\n", "sdks/typescript/scripts/build.sh") == 0
  end

  test "an out-of-scope file carrying a publish string is not scanned" do
    assert run("do not run `npm publish` here\n", "docs/notes.md") == 0
  end
end
