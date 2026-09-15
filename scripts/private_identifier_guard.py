#!/usr/bin/env python3
"""Fail-closed local guard for confidential fixed identifiers in Git objects."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


MANIFEST_REL = Path(".kimosabe/private-identifiers")
EXPECTATION_REL = Path(
    ".kimosabe/evidence/privacy-remediation/local-guard/"
    "private-identifier-expectation.json"
)
ACTIVATION_REL = Path(
    ".kimosabe/evidence/privacy-remediation/local-guard/private-identifier-active"
)
ACTIVATION_CONFIG_KEY = "bap.privateIdentifierGuard.active"
MAX_POLICY_BYTES = 1_048_576
ASCII_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)
SAFE_REF_RE = re.compile(rb"\Arefs/[!-~]+\Z")
SAFE_LOCAL_REF_RE = re.compile(rb"\A[!-~]+\Z")


class GuardError(Exception):
    """A condition that must deny without exposing its underlying data."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, order=True)
class Finding:
    source: str
    line: int
    pattern: int


class Guard:
    def __init__(self, repo: Path):
        self.repo = repo.resolve()
        selected_index = os.environ.get("GIT_INDEX_FILE")
        self.git_env = os.environ.copy()
        for name in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_REPLACE_REF_BASE",
            "GIT_SHALLOW_FILE",
            "GIT_GRAFT_FILE",
        ):
            self.git_env.pop(name, None)
        self.git_env.update(
            {
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_PAGER": "cat",
                "LC_ALL": "C",
                "LANG": "C",
            }
        )
        top = self.git("rev-parse", "--show-toplevel").decode(
            "utf-8", "surrogateescape"
        ).rstrip("\n")
        if Path(top).resolve() != self.repo:
            raise GuardError("repository-resolution")
        if selected_index is not None:
            git_dir_raw = self.git("rev-parse", "--absolute-git-dir").strip()
            git_dir = Path(git_dir_raw.decode("utf-8", "surrogateescape")).resolve()
            index_path = Path(selected_index)
            if not index_path.is_absolute():
                index_path = Path(os.path.abspath(Path.cwd() / index_path))
            else:
                index_path = Path(os.path.abspath(index_path))
            try:
                index_stat = index_path.lstat()
            except OSError as error:
                raise GuardError("selected-index") from error
            if index_path.parent.resolve() != git_dir or not stat.S_ISREG(index_stat.st_mode):
                raise GuardError("selected-index")
            self.git_env["GIT_INDEX_FILE"] = os.fspath(index_path)
        self.object_hex_length = {
            b"sha1": 40,
            b"sha256": 64,
        }.get(self.git("rev-parse", "--show-object-format").strip())
        if self.object_hex_length is None:
            raise GuardError("object-format")

    def git(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
    ) -> bytes:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", os.fspath(self.repo), *args],
            input=input_bytes,
            capture_output=True,
            env=self.git_env,
            check=False,
        )
        if result.returncode != 0 and not allow_failure:
            raise GuardError("git-operation")
        if result.returncode != 0:
            return b""
        return result.stdout

    @staticmethod
    def read_regular(path: Path, code: str) -> bytes:
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise GuardError(f"{code}-not-regular")
            if before.st_mode & 0o444 == 0:
                raise GuardError(f"{code}-unreadable")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                after = os.fstat(descriptor)
                if not stat.S_ISREG(after.st_mode):
                    raise GuardError(f"{code}-not-regular")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, 65_536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_POLICY_BYTES:
                        raise GuardError(f"{code}-oversize")
                    chunks.append(chunk)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise GuardError(f"{code}-changed")
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        except GuardError:
            raise
        except OSError as error:
            raise GuardError(f"{code}-unreadable") from error

    @staticmethod
    def parse_patterns(raw: bytes) -> list[bytes]:
        patterns: list[bytes] = []
        for raw_line in raw.splitlines():
            entry = raw_line.split(b"#", 1)[0].strip()
            if entry:
                patterns.append(entry.translate(ASCII_LOWER))
        if not patterns:
            raise GuardError("manifest-empty")
        if len(set(patterns)) != len(patterns):
            raise GuardError("manifest-duplicate")
        return patterns

    def manifest(self) -> tuple[bytes, list[bytes]]:
        raw = self.read_regular(self.repo / MANIFEST_REL, "manifest")
        return raw, self.parse_patterns(raw)

    def ensure_policy_directories(self, create: bool) -> None:
        current = self.repo
        for component in EXPECTATION_REL.parent.parts:
            current /= component
            try:
                metadata = current.lstat()
                if not stat.S_ISDIR(metadata.st_mode):
                    raise GuardError("policy-directory")
            except FileNotFoundError:
                if not create:
                    raise GuardError("policy-directory-missing")
                try:
                    current.mkdir(mode=0o700)
                except OSError as error:
                    raise GuardError("policy-directory") from error

    def policy_present(self) -> bool:
        paths = (
            self.repo / MANIFEST_REL,
            self.repo / EXPECTATION_REL,
            self.repo / ACTIVATION_REL,
        )
        present = False
        for path in paths:
            try:
                path.lstat()
                present = True
            except FileNotFoundError:
                continue
            except OSError as error:
                raise GuardError("policy-state") from error
        return present

    def initialize(self, expected_count: int) -> None:
        self.ensure_policy_directories(create=True)
        raw, patterns = self.manifest()
        if len(patterns) != expected_count:
            raise GuardError("manifest-count")
        destination = self.repo / EXPECTATION_REL
        try:
            existing = destination.lstat()
            if not stat.S_ISREG(existing.st_mode):
                raise GuardError("expectation-not-regular")
        except FileNotFoundError:
            pass
        payload = json.dumps(
            {
                "entry_count": len(patterns),
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        descriptor, temporary = tempfile.mkstemp(
            prefix=".private-identifier-expectation.", dir=destination.parent
        )
        temporary_path = Path(temporary)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, destination)
            activation = self.repo / ACTIVATION_REL
            activation_descriptor, activation_temporary = tempfile.mkstemp(
                prefix=".private-identifier-active.", dir=activation.parent
            )
            activation_temporary_path = Path(activation_temporary)
            try:
                os.fchmod(activation_descriptor, 0o600)
                with os.fdopen(activation_descriptor, "wb") as stream:
                    stream.write(b"enabled\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(activation_temporary_path, activation)
            finally:
                try:
                    activation_temporary_path.unlink()
                except FileNotFoundError:
                    pass
            self.git("config", "--local", ACTIVATION_CONFIG_KEY, "true")
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    def validated_patterns(self) -> list[bytes]:
        self.ensure_policy_directories(create=False)
        raw, patterns = self.manifest()
        expectation_raw = self.read_regular(
            self.repo / EXPECTATION_REL, "expectation"
        )
        try:
            expectation = json.loads(expectation_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GuardError("expectation-invalid") from error
        if not isinstance(expectation, dict) or set(expectation) != {
            "entry_count",
            "manifest_sha256",
        }:
            raise GuardError("expectation-invalid")
        count = expectation.get("entry_count")
        digest = expectation.get("manifest_sha256")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise GuardError("expectation-invalid")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise GuardError("expectation-invalid")
        if count != len(patterns):
            raise GuardError("manifest-count-changed")
        if not hmac.compare_digest(digest, hashlib.sha256(raw).hexdigest()):
            raise GuardError("manifest-digest-changed")
        activation = self.read_regular(self.repo / ACTIVATION_REL, "activation")
        if activation != b"enabled\n":
            raise GuardError("activation-invalid")
        return patterns

    def active_patterns(self) -> list[bytes] | None:
        result = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                os.fspath(self.repo),
                "config",
                "--local",
                "--bool",
                "--get",
                ACTIVATION_CONFIG_KEY,
            ],
            capture_output=True,
            env=self.git_env,
            check=False,
        )
        if result.returncode == 1:
            if self.policy_present():
                raise GuardError("activation-config-missing")
            return None
        if result.returncode != 0 or result.stdout.strip() != b"true":
            raise GuardError("activation-config-invalid")
        return self.validated_patterns()

    @staticmethod
    def match_lines(
        data: bytes, patterns: list[bytes], source: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, raw_line in enumerate(data.splitlines(), start=1):
            line = raw_line.translate(ASCII_LOWER)
            for ordinal, pattern in enumerate(patterns, start=1):
                if pattern in line:
                    findings.append(Finding(source, line_number, ordinal))
        return findings

    @staticmethod
    def match_path(
        path: bytes, patterns: list[bytes], source: str
    ) -> list[Finding]:
        lowered = path.translate(ASCII_LOWER)
        return [
            Finding(source, 0, ordinal)
            for ordinal, pattern in enumerate(patterns, start=1)
            if pattern in lowered
        ]

    def blob_findings(
        self, oid: bytes, patterns: list[bytes], source: str
    ) -> list[Finding]:
        oid_text = self.valid_oid(oid)
        blob = self.git("cat-file", "blob", oid_text)
        return self.match_lines(blob, patterns, source)

    def valid_oid(self, oid: bytes) -> str:
        if len(oid) != self.object_hex_length or re.fullmatch(rb"[0-9a-f]+", oid) is None:
            raise GuardError("object-id")
        return oid.decode("ascii")

    def pre_commit(self, patterns: list[bytes]) -> list[Finding]:
        changed = self.git(
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMRTUXB",
            "--no-renames",
            "--",
        ).split(b"\0")
        changed_paths = {path for path in changed if path}
        index = self.git("ls-files", "--cached", "--stage", "-z", "--")
        entries: dict[bytes, tuple[bytes, bytes]] = {}
        for raw_entry in index.split(b"\0"):
            if not raw_entry:
                continue
            try:
                metadata, path = raw_entry.split(b"\t", 1)
                mode, oid, stage = metadata.split(b" ")
            except ValueError as error:
                raise GuardError("index-format") from error
            if path not in changed_paths:
                continue
            if stage != b"0" or path in entries:
                raise GuardError("index-unmerged")
            entries[path] = (mode, oid)
        if set(entries) != changed_paths:
            raise GuardError("index-enumeration")

        findings: list[Finding] = []
        seen_blobs: set[bytes] = set()
        for entry_number, path in enumerate(sorted(entries), start=1):
            mode, oid = entries[path]
            findings.extend(
                self.match_path(path, patterns, f"index-entry={entry_number}")
            )
            if mode in (b"100644", b"100755", b"120000") and oid not in seen_blobs:
                seen_blobs.add(oid)
                findings.extend(
                    self.blob_findings(
                        oid,
                        patterns,
                        f"blob={self.valid_oid(oid)}",
                    )
                )
            elif mode not in (b"100644", b"100755", b"120000", b"160000"):
                raise GuardError("index-mode")
        return sorted(set(findings))

    def commit_message(self, message_path: Path, patterns: list[bytes]) -> list[Finding]:
        message = self.read_regular(message_path, "message")
        return sorted(set(self.match_lines(message, patterns, "message-file")))

    def ensure_history_integrity(self) -> None:
        for name in ("GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE"):
            if name in os.environ:
                raise GuardError("git-history-environment")
        shallow = self.git("rev-parse", "--is-shallow-repository").strip()
        if shallow != b"false":
            raise GuardError("shallow-repository")
        replacements = self.git(
            "for-each-ref", "--format=%(refname)", "refs/replace"
        )
        if replacements:
            raise GuardError("replace-refs")
        graft_path_raw = self.git("rev-parse", "--git-path", "info/grafts").strip()
        try:
            graft_path = Path(graft_path_raw.decode("utf-8", "surrogateescape"))
            if not graft_path.is_absolute():
                graft_path = self.repo / graft_path
            graft_stat = graft_path.lstat()
            if not stat.S_ISREG(graft_stat.st_mode) or graft_stat.st_size != 0:
                raise GuardError("grafts")
        except FileNotFoundError:
            pass
        except OSError as error:
            raise GuardError("grafts") from error

    def object_type(self, oid: bytes) -> bytes:
        return self.git("cat-file", "-t", self.valid_oid(oid)).strip()

    def peel_commit(self, oid: bytes) -> bytes | None:
        oid_text = self.valid_oid(oid)
        result = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                os.fspath(self.repo),
                "rev-parse",
                "--verify",
                f"{oid_text}^{{commit}}",
            ],
            capture_output=True,
            env=self.git_env,
            check=False,
        )
        if result.returncode != 0:
            return None
        peeled = result.stdout.strip()
        self.valid_oid(peeled)
        return peeled

    def parse_push_updates(self, raw: bytes) -> list[tuple[bytes, bytes, bytes, bytes]]:
        updates: list[tuple[bytes, bytes, bytes, bytes]] = []
        zero = b"0" * self.object_hex_length
        for line in raw.splitlines():
            fields = line.split(b" ")
            if len(fields) != 4:
                raise GuardError("push-input")
            local_ref, local_oid, remote_ref, remote_oid = fields
            local_ref_valid = SAFE_LOCAL_REF_RE.fullmatch(local_ref) is not None
            if not local_ref_valid or SAFE_REF_RE.fullmatch(remote_ref) is None:
                raise GuardError("push-ref")
            if local_oid != zero:
                self.valid_oid(local_oid)
            if remote_oid != zero:
                self.valid_oid(remote_oid)
            updates.append((local_ref, local_oid, remote_ref, remote_oid))
        if not updates:
            raise GuardError("push-input-empty")
        return updates

    def outgoing_commits(
        self,
        updates: list[tuple[bytes, bytes, bytes, bytes]],
    ) -> list[bytes]:
        zero = b"0" * self.object_hex_length
        commits: set[bytes] = set()
        for _local_ref, local_oid, _remote_ref, remote_oid in updates:
            if local_oid == zero:
                continue
            local_commit = self.peel_commit(local_oid)
            if local_commit is None:
                continue
            revision_input = local_commit + b"\n"
            if remote_oid != zero:
                remote_commit = self.peel_commit(remote_oid)
                if remote_commit is not None:
                    revision_input += b"^" + remote_commit + b"\n"
            raw_commits = self.git(
                "rev-list", "--topo-order", "--stdin", input_bytes=revision_input
            )
            commits.update(line for line in raw_commits.splitlines() if line)
        for oid in commits:
            self.valid_oid(oid)
        return sorted(commits)

    def scan_commits(
        self, commits: list[bytes], patterns: list[bytes]
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_blobs: set[bytes] = set()
        for commit_oid in commits:
            commit_text = self.valid_oid(commit_oid)
            raw_commit = self.git("cat-file", "commit", commit_text)
            message = raw_commit.partition(b"\n\n")[2]
            findings.extend(
                self.match_lines(message, patterns, f"commit={commit_text}")
            )
            tree = self.git("ls-tree", "-rz", "--full-tree", commit_text)
            entries = [entry for entry in tree.split(b"\0") if entry]
            for entry_number, raw_entry in enumerate(entries, start=1):
                try:
                    metadata, path = raw_entry.split(b"\t", 1)
                    mode, object_type, oid = metadata.split(b" ")
                except ValueError as error:
                    raise GuardError("tree-format") from error
                findings.extend(
                    self.match_path(
                        path,
                        patterns,
                        f"commit={commit_text} tree-entry={entry_number}",
                    )
                )
                if mode in (b"100644", b"100755", b"120000") and object_type == b"blob":
                    if oid not in seen_blobs:
                        seen_blobs.add(oid)
                        findings.extend(
                            self.blob_findings(
                                oid,
                                patterns,
                                f"blob={self.valid_oid(oid)}",
                            )
                        )
                elif mode == b"160000" and object_type == b"commit":
                    continue
                else:
                    raise GuardError("tree-mode")
        return sorted(set(findings))

    def scan_outgoing_tags(
        self,
        updates: list[tuple[bytes, bytes, bytes, bytes]],
        patterns: list[bytes],
    ) -> list[Finding]:
        findings: list[Finding] = []
        zero = b"0" * self.object_hex_length
        seen: set[bytes] = set()
        for _local_ref, local_oid, _remote_ref, _remote_oid in updates:
            if local_oid == zero:
                continue
            current = local_oid
            while current not in seen and self.object_type(current) == b"tag":
                seen.add(current)
                oid_text = self.valid_oid(current)
                raw_tag = self.git("cat-file", "tag", oid_text)
                header, separator, message = raw_tag.partition(b"\n\n")
                if not separator:
                    raise GuardError("tag-format")
                findings.extend(
                    self.match_lines(message, patterns, f"tag={oid_text}")
                )
                target = next(
                    (line[7:] for line in header.splitlines() if line.startswith(b"object ")),
                    None,
                )
                if target is None:
                    raise GuardError("tag-format")
                self.valid_oid(target)
                current = target
        return sorted(set(findings))

    def scan_terminal_objects(
        self,
        updates: list[tuple[bytes, bytes, bytes, bytes]],
        patterns: list[bytes],
    ) -> list[Finding]:
        zero = b"0" * self.object_hex_length
        findings: list[Finding] = []
        seen_blobs: set[bytes] = set()
        for update_number, (_local_ref, local_oid, _remote_ref, _remote_oid) in enumerate(
            updates, start=1
        ):
            if local_oid == zero:
                continue
            current = local_oid
            seen_tags: set[bytes] = set()
            object_type = self.object_type(current)
            while object_type == b"tag":
                if current in seen_tags:
                    raise GuardError("tag-cycle")
                seen_tags.add(current)
                raw_tag = self.git("cat-file", "tag", self.valid_oid(current))
                header = raw_tag.partition(b"\n\n")[0]
                target = next(
                    (line[7:] for line in header.splitlines() if line.startswith(b"object ")),
                    None,
                )
                if target is None:
                    raise GuardError("tag-format")
                self.valid_oid(target)
                current = target
                object_type = self.object_type(current)
            if object_type == b"commit":
                continue
            if object_type == b"blob":
                if current not in seen_blobs:
                    seen_blobs.add(current)
                    findings.extend(
                        self.blob_findings(
                            current,
                            patterns,
                            f"blob={self.valid_oid(current)}",
                        )
                    )
                continue
            if object_type != b"tree":
                raise GuardError("terminal-object-type")
            tree = self.git("ls-tree", "-rz", "--full-tree", self.valid_oid(current))
            for entry_number, raw_entry in enumerate(
                (entry for entry in tree.split(b"\0") if entry), start=1
            ):
                try:
                    metadata, path = raw_entry.split(b"\t", 1)
                    mode, entry_type, oid = metadata.split(b" ")
                except ValueError as error:
                    raise GuardError("tree-format") from error
                findings.extend(
                    self.match_path(
                        path,
                        patterns,
                        f"push-object={update_number} tree-entry={entry_number}",
                    )
                )
                if mode in (b"100644", b"100755", b"120000") and entry_type == b"blob":
                    if oid not in seen_blobs:
                        seen_blobs.add(oid)
                        findings.extend(
                            self.blob_findings(
                                oid, patterns, f"blob={self.valid_oid(oid)}"
                            )
                        )
                elif mode == b"160000" and entry_type == b"commit":
                    continue
                else:
                    raise GuardError("tree-mode")
        return sorted(set(findings))

    def pre_push(
        self, _remote: str, raw_updates: bytes, patterns: list[bytes]
    ) -> list[Finding]:
        self.ensure_history_integrity()
        updates = self.parse_push_updates(raw_updates)
        commits = self.outgoing_commits(updates)
        ref_findings: list[Finding] = []
        for update_number, (_local_ref, _local_oid, remote_ref, _remote_oid) in enumerate(
            updates, start=1
        ):
            ref_findings.extend(
                self.match_path(remote_ref, patterns, f"push-ref={update_number}")
            )
        return sorted(
            set(
                ref_findings
                + self.scan_commits(commits, patterns)
                + self.scan_outgoing_tags(updates, patterns)
                + self.scan_terminal_objects(updates, patterns)
            )
        )

    def audit_remotes(self, patterns: list[bytes]) -> tuple[list[Finding], int]:
        self.ensure_history_integrity()
        raw = self.git(
            "for-each-ref", "--format=%(objectname) %(refname)", "refs/remotes"
        )
        roots: list[bytes] = []
        ref_findings: list[Finding] = []
        for ref_number, line in enumerate(raw.splitlines(), start=1):
            if not line:
                continue
            try:
                oid, ref = line.split(b" ", 1)
            except ValueError as error:
                raise GuardError("remote-ref-format") from error
            self.valid_oid(oid)
            if SAFE_REF_RE.fullmatch(ref) is None:
                raise GuardError("remote-ref-format")
            ref_findings.extend(
                self.match_path(ref, patterns, f"remote-ref={ref_number}")
            )
            peeled = self.peel_commit(oid)
            if peeled is not None:
                roots.append(peeled)
        if not roots:
            return sorted(set(ref_findings)), 0
        revision_input = b"\n".join(sorted(set(roots))) + b"\n"
        commits = [
            line
            for line in self.git(
                "rev-list", "--topo-order", "--stdin", input_bytes=revision_input
            ).splitlines()
            if line
        ]
        for oid in commits:
            self.valid_oid(oid)
        return sorted(set(ref_findings + self.scan_commits(commits, patterns))), len(commits)


def emit_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(
            "private-identifier-guard: deny "
            f"source={finding.source} line={finding.line} pattern={finding.pattern}",
            file=sys.stderr,
        )
    print(
        f"private-identifier-guard: deny findings={len(findings)}",
        file=sys.stderr,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(add_help=True)
    result.add_argument("--repo", required=True)
    subcommands = result.add_subparsers(dest="mode", required=True)
    initialize = subcommands.add_parser("initialize")
    initialize.add_argument("--expected-count", type=int, required=True)
    subcommands.add_parser("pre-commit")
    subcommands.add_parser("validate-policy")
    commit_message = subcommands.add_parser("commit-msg")
    commit_message.add_argument("message_file")
    pre_push = subcommands.add_parser("pre-push")
    pre_push.add_argument("remote_name")
    pre_push.add_argument("remote_url")
    subcommands.add_parser("audit-remotes")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        guard = Guard(Path(args.repo))
        if args.mode == "initialize":
            if args.expected_count <= 0:
                raise GuardError("expected-count")
            guard.initialize(args.expected_count)
            return 0

        patterns = guard.active_patterns()
        if patterns is None:
            print(
                "private-identifier-guard: inactive; owner policy is not configured",
                file=sys.stderr,
            )
            if args.mode == "audit-remotes":
                print("status=inactive findings=0 scanned_commits=0")
            return 0
        if args.mode == "validate-policy":
            return 0
        if args.mode == "pre-commit":
            findings = guard.pre_commit(patterns)
        elif args.mode == "commit-msg":
            findings = guard.commit_message(Path(args.message_file), patterns)
        elif args.mode == "pre-push":
            findings = guard.pre_push(args.remote_url, sys.stdin.buffer.read(), patterns)
        elif args.mode == "audit-remotes":
            findings, commit_count = guard.audit_remotes(patterns)
            print(f"findings={len(findings)} scanned_commits={commit_count}")
            return 1 if findings else 0
        else:
            raise GuardError("mode")
        if findings:
            emit_findings(findings)
            return 1
        return 0
    except GuardError as error:
        print(
            f"private-identifier-guard: deny guard-state={error.code}",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            "private-identifier-guard: deny guard-state=unexpected-local-error",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
