#!/usr/bin/env python3
"""Real-Git acceptance tests for the local private-identifier guard."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUARD = PROJECT_ROOT / "scripts" / "private_identifier_guard.py"
INSTALLER = PROJECT_ROOT / "scripts" / "install-hooks.sh"
EXPECTATION_REL = Path(
    ".kimosabe/evidence/privacy-remediation/local-guard/"
    "private-identifier-expectation.json"
)
ACTIVATION_REL = Path(
    ".kimosabe/evidence/privacy-remediation/local-guard/private-identifier-active"
)
ACTIVATION_CONFIG_KEY = "bap.privateIdentifierGuard.active"
ZERO_OID = "0" * 40


def run(
    *args: str,
    cwd: Path,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    for name in tuple(command_env):
        if name.startswith("GIT_"):
            command_env.pop(name)
    command_env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if env:
        command_env.update(env)
    return subprocess.run(
        args,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        env=command_env,
        check=False,
    )


def git(repo: Path, *args: str, input_text: str | None = None) -> str:
    result = run("git", *args, cwd=repo, input_text=input_text)
    if result.returncode != 0:
        raise AssertionError("real git command failed")
    return result.stdout.strip()


class PrivateIdentifierGuardTest(unittest.TestCase):
    maxDiff = 1600

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="bap-local-guard-test."))
        self.repo = self.scratch / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "guard@example.invalid")
        git(self.repo, "config", "user.name", "Guard Test")
        self.pattern = "public-synthetic-orchid"
        self.other_pattern = "public-synthetic-cobalt"
        self.patterns = (
            self.pattern,
            self.other_pattern,
            "public-synthetic-amber",
            "public-synthetic-birch",
            "public-synthetic-coral",
            "public-synthetic-delta",
        )
        self.write_manifest(*self.patterns)
        self.initialize(len(self.patterns))
        critical_surfaces = self.repo / ".kimosabe" / "critical-surfaces"
        critical_surfaces.write_text("public fixture\n", encoding="utf-8")
        (self.repo / "baseline.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "baseline.txt", ".kimosabe/critical-surfaces")
        git(self.repo, "commit", "-qm", "baseline")

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch)

    def write_manifest(self, *patterns: str) -> None:
        manifest = self.repo / ".kimosabe" / "private-identifiers"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("\n".join(patterns) + "\n", encoding="utf-8")

    def initialize(self, count: int) -> None:
        result = self.guard("initialize", "--expected-count", str(count))
        self.assertEqual(result.returncode, 0, "expectation initialization failed")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        expectation = self.repo / EXPECTATION_REL
        self.assertTrue(expectation.is_file())
        parsed = json.loads(expectation.read_text(encoding="utf-8"))
        self.assertEqual(parsed["entry_count"], count)
        self.assertEqual(set(parsed), {"entry_count", "manifest_sha256"})
        self.assertEqual((self.repo / ACTIVATION_REL).read_bytes(), b"enabled\n")
        self.assertEqual(
            git(self.repo, "config", "--local", "--bool", "--get", ACTIVATION_CONFIG_KEY),
            "true",
        )

    def copy_hook_sources(self) -> None:
        scripts = self.repo / "scripts"
        scripts.mkdir(exist_ok=True)
        shutil.copy2(GUARD, scripts / GUARD.name)
        shutil.copy2(
            PROJECT_ROOT / "scripts" / "check_sdk_publish_infra.sh",
            scripts / "check_sdk_publish_infra.sh",
        )
        shutil.copy2(INSTALLER, scripts / "install-hooks.sh")
        shutil.copytree(PROJECT_ROOT / "scripts" / "hooks", scripts / "hooks")

    def install_real_hooks(self) -> None:
        self.write_manifest(*self.patterns)
        self.copy_hook_sources()
        (self.repo / EXPECTATION_REL).unlink()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        result = run(
            "sh",
            "../scripts/install-hooks.sh",
            "--initialize-private-identifier-expectation",
            str(len(self.patterns)),
            cwd=subdirectory,
        )
        self.assertEqual(result.returncode, 0, "real hook installation failed")
        result = run("sh", "../scripts/install-hooks.sh", cwd=subdirectory)
        self.assertEqual(result.returncode, 0, "routine hook validation failed")

    def guard(
        self,
        mode: str,
        *args: str,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            sys.executable,
            str(GUARD),
            "--repo",
            str(self.repo),
            mode,
            *args,
            cwd=self.repo,
            input_text=input_text,
            env=env,
        )

    def assert_safe_output(self, result: subprocess.CompletedProcess[str]) -> None:
        output = (result.stdout + result.stderr).casefold()
        for pattern in self.patterns:
            self.assertNotIn(pattern.casefold(), output)
        self.assertNotIn("secret payload", output)
        self.assertNotIn("secret message", output)

    def test_manifest_state_fails_closed(self) -> None:
        manifest = self.repo / ".kimosabe" / "private-identifiers"
        expectation = self.repo / EXPECTATION_REL
        activation = self.repo / ACTIVATION_REL

        manifest.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(*self.patterns)
        manifest.chmod(0)
        result = self.guard("pre-commit")
        manifest.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(self.pattern)
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(
            self.pattern,
            self.other_pattern + "-changed",
            *self.patterns[2:],
        )
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(*self.patterns)
        expectation.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.initialize(len(self.patterns))
        activation.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.initialize(len(self.patterns))
        activation.write_text("invalid\n", encoding="ascii")
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_policy_parent_symlink_fails_closed(self) -> None:
        evidence = self.repo / ".kimosabe" / "evidence"
        held = self.repo / ".kimosabe" / "evidence-held"
        evidence.rename(held)
        evidence.symlink_to(held.name, target_is_directory=True)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_persistent_activation_denies_removed_ignored_policy(self) -> None:
        (self.repo / ".kimosabe" / "private-identifiers").unlink()
        shutil.rmtree(self.repo / ".kimosabe" / "evidence")
        self.assertEqual(
            git(self.repo, "config", "--local", "--bool", "--get", ACTIVATION_CONFIG_KEY),
            "true",
        )
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_pre_commit_scans_staged_blob_and_path_without_leaking(self) -> None:
        path = self.repo / "content.txt"
        path.write_text(f"secret payload {self.pattern.upper()}\n", encoding="utf-8")
        git(self.repo, "add", "content.txt")
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("pattern=1", result.stderr)
        self.assertIn("line=1", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "reset", "-q", "HEAD", "--", "content.txt")
        path.unlink()
        secret_path = f"notes-{self.other_pattern}.txt"
        (self.repo / secret_path).write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", secret_path)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("pattern=2", result.stderr)
        self.assertIn("index-entry=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_commit_scans_symlink_blob_without_following_target(self) -> None:
        target = f"missing-{self.pattern}-target"
        os.symlink(target, self.repo / "link.txt")
        git(self.repo, "add", "link.txt")
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_commit_message_is_scanned_without_leaking(self) -> None:
        message = self.scratch / "COMMIT_EDITMSG"
        message.write_text(f"secret message {self.pattern}\n", encoding="utf-8")
        result = self.guard("commit-msg", str(message))
        self.assertEqual(result.returncode, 1)
        self.assertIn("message-file line=1 pattern=1", result.stderr)
        self.assert_safe_output(result)

    def make_remote(self) -> tuple[Path, str]:
        remote = self.scratch / "remote.git"
        remote.mkdir()
        git(remote, "init", "--bare", "-q")
        git(self.repo, "remote", "add", "origin", str(remote))
        head = git(self.repo, "rev-parse", "HEAD")
        result = self.guard(
            "pre-push",
            "origin",
            str(remote),
            input_text=f"refs/heads/main {head} refs/heads/main {ZERO_OID}\n",
        )
        self.assertEqual(result.returncode, 0)
        git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/main")
        git(self.repo, "fetch", "-q", "origin")
        return remote, head

    def pre_push(
        self,
        remote: Path,
        local_ref: str,
        local_oid: str,
        remote_ref: str,
        remote_oid: str,
    ) -> subprocess.CompletedProcess[str]:
        return self.guard(
            "pre-push",
            "origin",
            str(remote),
            input_text=f"{local_ref} {local_oid} {remote_ref} {remote_oid}\n",
        )

    def rewind_main(self, oid: str) -> None:
        git(self.repo, "checkout", "-q", "--detach", oid)
        git(self.repo, "branch", "-f", "main", oid)
        git(self.repo, "checkout", "-q", "main")

    def test_pre_push_scans_outgoing_content_message_and_path(self) -> None:
        remote, remote_oid = self.make_remote()

        (self.repo / "outgoing.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "outgoing.txt")
        git(self.repo, "commit", "-qm", "content change")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        self.rewind_main(remote_oid)
        (self.repo / "message.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "message.txt")
        git(self.repo, "commit", "-qm", f"secret message {self.pattern}")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("commit=", result.stderr)
        self.assert_safe_output(result)

        self.rewind_main(remote_oid)
        secret_path = f"outgoing-{self.other_pattern}.txt"
        (self.repo / secret_path).write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", secret_path)
        git(self.repo, "commit", "-qm", "path change")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tree-entry=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_annotated_tag_message(self) -> None:
        remote, _remote_oid = self.make_remote()
        git(self.repo, "tag", "-a", "release-test", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/release-test")
        result = self.pre_push(
            remote,
            "refs/tags/release-test",
            tag_oid,
            "refs/tags/release-test",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_remote_ref_name_and_tag_object_from_oid(self) -> None:
        remote, remote_oid = self.make_remote()
        result = self.pre_push(
            remote,
            "HEAD",
            remote_oid,
            f"refs/heads/{self.pattern}",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("push-ref=", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "safe-tag", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/safe-tag")
        result = self.pre_push(
            remote,
            tag_oid,
            tag_oid,
            "refs/tags/safe-target",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_symlink_blob_without_following_target(self) -> None:
        remote, remote_oid = self.make_remote()
        target = f"missing-{self.pattern}-target"
        os.symlink(target, self.repo / "outgoing-link.txt")
        git(self.repo, "add", "outgoing-link.txt")
        git(self.repo, "commit", "-qm", "symlink target probe")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_new_ref_scans_history_present_only_under_remote_pull_ref(self) -> None:
        remote, _remote_oid = self.make_remote()
        (self.repo / "pull-only.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "pull-only.txt")
        git(self.repo, "commit", "-qm", "pull-only disclosure")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "push", "-q", "origin", "HEAD:refs/pull/1/head")

        result = self.pre_push(
            remote,
            "refs/heads/promoted",
            local_oid,
            "refs/heads/promoted",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_direct_blob_tree_and_tag_terminals(self) -> None:
        remote, _remote_oid = self.make_remote()
        blob_oid = git(
            self.repo,
            "hash-object",
            "-w",
            "--stdin",
            input_text=f"secret payload {self.pattern}\n",
        )
        result = self.pre_push(
            remote, blob_oid, blob_oid, "refs/tags/blob-target", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        tree_oid = git(
            self.repo,
            "mktree",
            input_text=f"100644 blob {blob_oid}\tclean.txt\n",
        )
        result = self.pre_push(
            remote, tree_oid, tree_oid, "refs/tags/tree-target", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "blob-terminal", blob_oid, "-m", "clean tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/blob-terminal")
        result = self.pre_push(
            remote, tag_oid, tag_oid, "refs/tags/tagged-blob", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_excludes_unrelated_local_ref(self) -> None:
        remote, remote_oid = self.make_remote()
        git(self.repo, "checkout", "-qb", "unrelated")
        (self.repo / "unrelated.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "unrelated.txt")
        git(self.repo, "commit", "-qm", "unrelated")
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "clean-outgoing.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "clean-outgoing.txt")
        git(self.repo, "commit", "-qm", "clean outgoing")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_pre_push_fails_closed_for_shallow_replace_and_grafts(self) -> None:
        remote, remote_oid = self.make_remote()
        (self.repo / "clean-outgoing.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "clean-outgoing.txt")
        git(self.repo, "commit", "-qm", "clean outgoing")
        local_oid = git(self.repo, "rev-parse", "HEAD")

        shallow = Path(git(self.repo, "rev-parse", "--git-path", "shallow"))
        if not shallow.is_absolute():
            shallow = self.repo / shallow
        shallow.write_text(remote_oid + "\n", encoding="ascii")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        shallow.unlink()
        self.assertNotEqual(result.returncode, 0)

        git(self.repo, "replace", remote_oid, local_oid)
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        git(self.repo, "replace", "-d", remote_oid)
        self.assertNotEqual(result.returncode, 0)

        grafts = Path(git(self.repo, "rev-parse", "--git-path", "info/grafts"))
        if not grafts.is_absolute():
            grafts = self.repo / grafts
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(local_oid + " " + remote_oid + "\n", encoding="ascii")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        grafts.unlink()
        self.assertNotEqual(result.returncode, 0)

    def test_git_and_history_environment_failures_fail_closed(self) -> None:
        index = Path(git(self.repo, "rev-parse", "--git-path", "index"))
        if not index.is_absolute():
            index = self.repo / index
        held = index.with_name("index-held")
        index.rename(held)
        index.mkdir()
        result = self.guard("pre-commit")
        index.rmdir()
        held.rename(index)
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

        head = git(self.repo, "rev-parse", "HEAD")
        graft_file = self.scratch / "environment-graft"
        graft_file.write_text(head + "\n", encoding="ascii")
        remote = self.scratch / "environment-remote.git"
        remote.mkdir()
        git(remote, "init", "--bare", "-q")
        result = self.guard(
            "pre-push",
            "environment-origin",
            str(remote),
            input_text=f"refs/heads/main {head} refs/heads/main {ZERO_OID}\n",
            env={"GIT_GRAFT_FILE": str(graft_file)},
        )
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_remote_audit_reports_counts_only(self) -> None:
        remote, _remote_oid = self.make_remote()
        git(self.repo, "checkout", "-qb", "audit-source")
        (self.repo / "audit.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "audit.txt")
        git(self.repo, "commit", "-qm", "audit")
        git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/audit-source")
        git(
            self.repo,
            "push",
            "-q",
            "origin",
            f"HEAD:refs/heads/{self.other_pattern}",
        )
        git(self.repo, "fetch", "-q", "origin")
        result = self.guard("audit-remotes")
        self.assertEqual(result.returncode, 1)
        self.assertRegex(result.stdout, r"^findings=[1-9][0-9]* ")
        self.assert_safe_output(result)
        self.assertNotIn("audit-source", result.stdout + result.stderr)
        self.assertNotIn(str(remote), result.stdout + result.stderr)

    def test_real_git_commit_message_and_push_commands_are_guarded(self) -> None:
        self.install_real_hooks()

        staged = self.repo / "guarded.txt"
        staged.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        result = run("git", "commit", "-m", "clean message", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        git(self.repo, "restore", "--staged", "guarded.txt")
        staged.unlink()
        staged.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        result = run(
            "git", "commit", "-m", f"secret message {self.pattern}", cwd=self.repo
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "commit", "-qm", "clean message")

        remote = self.scratch / "command-remote.git"
        remote.mkdir()
        git(remote, "init", "--bare", "-q")
        git(self.repo, "remote", "add", "command-origin", str(remote))
        result = run(
            "git",
            "push",
            "-q",
            "command-origin",
            "HEAD:refs/heads/main",
            cwd=self.repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(
            "git",
            "push",
            "command-origin",
            f"HEAD:refs/heads/{self.pattern}",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "safe-object-tag", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/safe-object-tag")
        result = run(
            "git",
            "push",
            "command-origin",
            f"{tag_oid}:refs/tags/safe-target",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        staged.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        git(self.repo, "commit", "--no-verify", "-qm", "synthetic push probe")
        result = run(
            "git",
            "push",
            "command-origin",
            "HEAD:refs/heads/main",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_real_git_commit_a_and_pathspec_use_the_selected_index(self) -> None:
        self.install_real_hooks()
        tracked_a = self.repo / "tracked-a.txt"
        tracked_path = self.repo / "tracked-path.txt"
        unrelated = self.repo / "unrelated-staged.txt"
        for path in (tracked_a, tracked_path, unrelated):
            path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "tracked-a.txt", "tracked-path.txt", "unrelated-staged.txt")
        git(self.repo, "commit", "-qm", "tracked setup")

        tracked_a.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        result = run("git", "commit", "-am", "commit-a probe", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "restore", "tracked-a.txt")

        tracked_path.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        result = run(
            "git",
            "commit",
            "-m",
            "pathspec deny probe",
            "--",
            "tracked-path.txt",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "restore", "tracked-path.txt")

        unrelated.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "unrelated-staged.txt")
        tracked_path.write_text("clean update\n", encoding="utf-8")
        result = run(
            "git",
            "commit",
            "-m",
            "pathspec allow probe",
            "--",
            "tracked-path.txt",
            cwd=self.repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            git(self.repo, "diff", "--cached", "--name-only"),
            "unrelated-staged.txt",
        )

    def test_real_git_commit_cleanup_and_retained_messages(self) -> None:
        removable = self.repo / f"remove-{self.pattern}.txt"
        verbose_removable = self.repo / f"verbose-{self.pattern}.txt"
        for path in (removable, verbose_removable):
            path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", removable.name, verbose_removable.name)
        git(self.repo, "commit", "-qm", "seed cleanup paths")
        self.install_real_hooks()

        git(self.repo, "rm", "-q", removable.name)
        result = run(
            "git", "commit", "--cleanup=strip", "-m", "clean removal", cwd=self.repo
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        clean = self.repo / "clean-message-probe.txt"
        for cleanup in ("verbatim", "whitespace"):
            clean.write_text(f"clean {cleanup}\n", encoding="utf-8")
            git(self.repo, "add", clean.name)
            result = run(
                "git",
                "commit",
                f"--cleanup={cleanup}",
                "-m",
                f"# secret message {self.pattern}",
                cwd=self.repo,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assert_safe_output(result)
            git(self.repo, "restore", "--staged", clean.name)

        git(self.repo, "rm", "-q", verbose_removable.name)
        editor = self.scratch / "clean-editor.sh"
        editor.write_text(
            "#!/bin/sh\nprintf 'clean editor removal\\n' > \"$1\"\n",
            encoding="utf-8",
        )
        editor.chmod(0o700)
        result = run(
            "git",
            "commit",
            "-v",
            "--cleanup=strip",
            cwd=self.repo,
            env={"GIT_EDITOR": str(editor)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_routine_installer_does_not_repin_changed_manifest(self) -> None:
        self.install_real_hooks()
        expectation = self.repo / EXPECTATION_REL
        before = expectation.read_bytes()
        self.write_manifest(
            self.pattern,
            self.other_pattern + "-changed",
            *self.patterns[2:],
        )
        result = run("sh", "scripts/install-hooks.sh", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(expectation.read_bytes(), before)

    def test_installer_refuses_unknown_hook_without_overwriting(self) -> None:
        self.write_manifest(*self.patterns)
        self.initialize(len(self.patterns))
        self.copy_hook_sources()
        scripts = self.repo / "scripts"
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho preserved\n", encoding="utf-8")
        before = hook.read_bytes()
        result = run("sh", str(scripts / "install-hooks.sh"), cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing hook collision", result.stderr)
        self.assertEqual(hook.read_bytes(), before)

    def test_public_contributor_installs_sdk_hook_without_private_state(self) -> None:
        (self.repo / ".kimosabe" / "private-identifiers").unlink()
        shutil.rmtree(self.repo / ".kimosabe" / "evidence")
        git(self.repo, "config", "--local", "--unset-all", ACTIVATION_CONFIG_KEY)
        self.assertTrue((self.repo / ".kimosabe" / "critical-surfaces").is_file())
        self.copy_hook_sources()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        result = run("sh", "../scripts/install-hooks.sh", cwd=subdirectory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("pre-commit", "commit-msg", "pre-push"):
            self.assertTrue((self.repo / ".git" / "hooks" / name).is_symlink())

        path = self.repo / "public-clean.txt"
        path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", path.name)
        result = run("git", "commit", "-m", "public clean", cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("owner policy is not configured", result.stderr)

    def test_installer_refuses_linked_worktree_before_writing(self) -> None:
        self.copy_hook_sources()
        git(self.repo, "add", "scripts")
        git(self.repo, "commit", "-qm", "fixture hook sources")
        git(self.repo, "config", "--local", "--unset-all", ACTIVATION_CONFIG_KEY)
        linked = self.scratch / "linked"
        git(self.repo, "worktree", "add", "-q", "-b", "linked-fixture", str(linked))
        destinations = [
            self.repo / ".git" / "hooks" / name
            for name in ("pre-commit", "commit-msg", "pre-push")
        ]
        self.assertTrue(all(not path.exists() for path in destinations))
        result = run("sh", "scripts/install-hooks.sh", cwd=linked)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("linked worktree detected", result.stderr)
        self.assertTrue(all(not path.exists() for path in destinations))

    def test_installer_refuses_global_hooks_path_before_writing(self) -> None:
        self.copy_hook_sources()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        configured_hooks = self.scratch / "configured-hooks"
        global_config = self.scratch / "global-gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {configured_hooks}\n", encoding="utf-8"
        )
        destinations = [
            self.repo / ".git" / "hooks" / name
            for name in ("pre-commit", "commit-msg", "pre-push")
        ]
        self.assertTrue(all(not path.exists() for path in destinations))
        result = run(
            "sh",
            "../scripts/install-hooks.sh",
            cwd=subdirectory,
            env={"GIT_CONFIG_GLOBAL": str(global_config)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.hooksPath is configured", result.stderr)
        self.assertTrue(all(not path.exists() for path in destinations))
        self.assertFalse(configured_hooks.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
