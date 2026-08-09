#!/bin/sh
# install-hooks.sh — install this repo's tracked git hooks into .git/hooks/.
#
# The hooks live tracked under scripts/hooks/ so they ship with the repo and are
# reviewable in PRs; git itself never tracks .git/hooks/, so a symlink is the
# install step. Idempotent: re-running refreshes the symlink. Coexists with the
# graphify post-commit/post-checkout hooks (different filenames, no collision).
#
# Why a relative symlink: the target is resolved relative to .git/hooks/, so the
# link survives the repo being moved or the worktree root changing.
#
# Bypass / removal: the hook can be bypassed per-commit with 'git commit --no-verify'
# (documented in CONTRIBUTING.md). To uninstall entirely, remove the symlink from
# .git/hooks/.

set -eu

die() { printf 'install-hooks.sh: %s\n' "$*" >&2; exit 1; }

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a git work tree"
hooks_dir="$repo_root/.git/hooks"
tracked_dir="$repo_root/scripts/hooks"
mkdir -p "$hooks_dir"

installed=0
for src in "$tracked_dir"/*; do
  [ -f "$src" ] || continue
  name="$(basename "$src")"
  link="$hooks_dir/$name"
  # Relative target as seen from .git/hooks/: up two levels to repo root, then in.
  relative_target="../../scripts/hooks/$name"
  ln -sfn "$relative_target" "$link"
  chmod +x "$src"
  printf 'linked %s -> %s\n' "$link" "$relative_target"
  installed=$((installed + 1))
done

if [ "$installed" -eq 0 ]; then
  die "no hooks found under $tracked_dir"
fi

printf '\n%s hook(s) installed. Bypass a single commit with: git commit --no-verify\n' "$installed"
