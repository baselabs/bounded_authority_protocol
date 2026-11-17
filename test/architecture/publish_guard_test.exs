defmodule BoundedAuthorityProtocol.Architecture.PublishGuardTest do
  @moduledoc """
  Non-vacuity + scope tests for `scripts/check_sdk_publish_infra.sh` (ADR 0015 Decision 5: no SDK
  publishes from the monorepo). The guard is invoked with `<content-on-stdin> | script <path>`;
  these drive it directly with crafted (content, path) pairs.

  The broadened scan (workflows + composite actions + SDK shell scripts / Makefiles / justfiles +
  root Makefile/justfile) closes the gap where a registry-publish command hid in an executable
  surface that is not a workflow or manifest. The shell-script scan is scoped to `sdks/`
  deliberately: the guard and the pre-commit hook carry the publish-command patterns as literal
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

  test "only the canonical Hex workflow may publish the Elixir package" do
    content = "      - run: mix hex.publish --yes\n"
    assert run(content, ".github/workflows/publish.yml") == 0

    for path <- [
          ".github/workflows/ci.yml",
          ".github/workflows/release.yml",
          ".github/workflows/publish.yaml",
          ".github/workflows/nested/publish.yml",
          ".github/actions/publish/action.yml",
          "sdks/elixir/release.sh",
          "Makefile"
        ] do
      assert run(content, path) == 1, path
    end
  end

  test "the Hex workflow exception never permits other registry commands or actions" do
    for command <- [
          "npm publish",
          "pnpm publish",
          "yarn -s publish",
          "cargo +stable publish",
          "hatch publish",
          "flit publish",
          "uv publish",
          "twine upload dist/*",
          "cargo-release publish",
          "pypa/gh-action-pypi-publish",
          "JS-DevTools/npm-publish",
          "JS-DevTools/action-publish",
          "crate-ci/cargo-release"
        ] do
      content = "run: mix hex.publish --yes\nrun: #{command}\n"
      assert run(content, ".github/workflows/publish.yml") == 1, command
    end
  end

  test "the committed Hex workflow is allowed by the shared guard" do
    path = ".github/workflows/publish.yml"
    assert run(File.read!(path), path) == 0
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

  test "path-qualified publish commands are caught (the tool boundary includes /)" do
    # A `/` before the tool is a boundary, so an absolute or relative executable path does not
    # bypass the guard.
    for cmd <- [
          "/usr/local/bin/npm publish",
          "./node_modules/.bin/npm publish",
          "/opt/homebrew/bin/cargo publish",
          "/usr/bin/twine upload dist/*"
        ] do
      assert run(cmd <> "\n", "sdks/rust/scripts/release.sh") == 1, "expected #{cmd} caught"
    end
  end

  test "an alnum/`-` run before the tool name is not a false boundary" do
    # `foocargo`/`cargo-release` must not be read as `cargo` by the regex (the latter's contiguous
    # form is caught by the fixed list, verified elsewhere).
    assert run("foocargo publish\n", "sdks/rust/scripts/build.sh") == 0
  end

  test "publish-adjacent but non-publishing commands are not false-positives" do
    for cmd <- [
          "npm run publish-docs",
          "npm version patch",
          "mix hex.build",
          "echo publishing",
          "npm run build"
        ] do
      assert run(cmd <> "\n", "sdks/typescript/scripts/build.sh") == 0,
             "expected #{cmd} allowed"
    end
  end

  test "a clean SDK script exits 0" do
    assert run("#!/bin/sh\nnpm run build\n", "sdks/typescript/scripts/build.sh") == 0
  end

  test "an out-of-scope file carrying a publish string is not scanned" do
    assert run("do not run `npm publish` here\n", "docs/notes.md") == 0
  end

  test "the CI caller feeds every executable and manifest path class to the checker" do
    root = Path.join(System.tmp_dir!(), "publish-caller-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(root) end)
    File.mkdir_p!(Path.join(root, "scripts"))
    File.cp!(@script, Path.join(root, "scripts/check_sdk_publish_infra.sh"))
    {_, 0} = System.cmd("git", ["init", "--quiet"], cd: root)
    source = File.read!(".github/workflows/sdk-publish-guard.yml")
    [_, body] = String.split(source, "        run: |\n", parts: 2)

    body =
      body
      |> String.split("\n")
      |> Enum.map_join("\n", &String.replace_prefix(&1, "          ", ""))

    invoke = fn ->
      System.cmd("bash", ["-c", body],
        cd: root,
        env: [{"CHECKER", "scripts/check_sdk_publish_infra.sh"}],
        stderr_to_stdout: true
      )
    end

    for path <- [
          ".github/workflows/publish.yml",
          ".github/workflows/release.yml",
          ".github/actions/release/action.yml",
          "sdks/rust/release.sh",
          "sdks/rust/Makefile",
          "sdks/rust/justfile",
          "Makefile",
          "justfile",
          "sdks/javascript/package.json",
          "sdks/python/pyproject.toml",
          "sdks/python/setup.py",
          "sdks/python/setup.cfg",
          "sdks/rust/Cargo.toml"
        ] do
      full = Path.join(root, path)
      File.mkdir_p!(Path.dirname(full))
      File.write!(full, "run: cargo publish\n")
      {_, 0} = System.cmd("git", ["add", "--", path], cd: root)
      {output, status} = invoke.()
      assert status != 0, path
      assert output =~ "#{path}: registry-publish command", output
      IO.puts("RED publish caller #{path}: registry-publish command")
      File.write!(full, "# clean\n")
      {output, status} = invoke.()
      assert status == 0, output
      IO.puts("GREEN publish caller #{path}: restored")
    end
  end
end
