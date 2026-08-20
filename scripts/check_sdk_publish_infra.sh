#!/bin/sh
# check_sdk_publish_infra.sh — single source of truth for the SDK publish guard.
#
# Called by scripts/hooks/pre-commit (on staged blobs via stdin) and by the
# .github/workflows/sdk-publish-guard.yml CI job (on checked-out files via stdin).
# One set of patterns, two callers, so the hook and CI cannot drift apart.
#
# Usage:  <content-on-stdin> | check_sdk_publish_infra.sh <path>
# Exit 0: the file is clean (or not a scanned surface).
# Exit 1: publish infrastructure found; one stderr line per hit names the file,
#         the matched pattern, and cites ADR 0015.
#
# What it blocks, and why (ADR 0015 Decision 5): no SDK publishes from this
# monorepo. Each SDK graduates to its own per-SDK repo on first publication. This
# script catches the ENABLING change — registry-publish commands, registry-publish
# GitHub Actions, and npm publish lifecycle hooks committed to manifests or
# workflows. Scope is SDK-only per ADR 0015; the Elixir package is not scanned
# here (its publish path, if any, is a separate decision under BAP-07).
#
# Honesty limit: this catches publish infrastructure STAGED/COMMITTED. It cannot
# catch a literal ad-hoc 'npm publish' typed at a working tree — that is a runtime
# act no commit gate sees. CI on main is the hard gate for committed infrastructure;
# the local hook is honor-system for contributors. The deliberate-admin bypass is
# 'git commit --no-verify' (documented in CONTRIBUTING.md).

set -u

path="${1:-}"
if [ -z "$path" ]; then
  printf 'check_sdk_publish_infra.sh: usage: <content-on-stdin> | %s <path>\n' "$0" >&2
  exit 2
fi

# Classify by path to decide which pattern set applies. A file that is neither a
# scanned executable surface nor an SDK manifest is not scanned — exit 0 immediately.
# Scanned surfaces run the publish-command check; only manifests add the
# publish-lifecycle-key check.
#
# Executable surfaces where a registry-publish command can hide (a workflow `run:`
# step is not the only place): GitHub workflows AND composite actions; any shell
# script, Makefile, or justfile UNDER sdks/ (an SDK release script — the review's
# `sdks/typescript/scripts/release.sh` gap); and a repo-root Makefile/justfile (a
# top-level target that publishes an SDK). NOTE the shell-script scan is scoped to
# `sdks/` deliberately: this guard script and scripts/hooks/pre-commit both carry the
# publish-command patterns as literal data, and a repo-wide `*.sh` scan would
# self-match them. SDK release scripts live under sdks/, so that scope has the reach
# without the self-match.
is_sdk_manifest=0
case "$path" in
  .github/workflows/*.yml | .github/workflows/*.yaml) ;;
  .github/actions/*action.yml | .github/actions/*action.yaml) ;;
  sdks/*.sh | sdks/*Makefile | sdks/*makefile | sdks/*justfile | sdks/*Justfile) ;;
  Makefile | makefile | justfile | Justfile) ;;
  sdks/*/package.json | sdks/*/pyproject.toml | sdks/*/setup.py | sdks/*/setup.cfg | sdks/*/Cargo.toml)
    is_sdk_manifest=1 ;;
  *) exit 0 ;;
esac

status=0

# Read stdin once; the two checks below both read from this variable.
content="$(cat)"

# Registry-publish commands AND registry-publish GitHub Actions — blocked on every
# scanned surface. Fixed-string match (grep -F), so '.', '@', '/', and spaces are
# literal. The action references (pypa/gh-action-pypi-publish, etc.) catch the
# idiomatic GitHub-Actions publish path that contains no CLI command string —
# without them, a workflow `uses: pypa/gh-action-pypi-publish@...` would pass the
# gate while being exactly the registry-publish CI step ADR 0015 forbids.
# Deliberately does NOT include 'npm version' (version bumping is allowed in the
# monorepo), 'mix hex.build' (building an unpublished archive is allowed;
# supply-chain.yml does this), or 'gh release create' (a release may accompany a
# non-publish artifact). Adding a real publish command or action here is the one
# edit both callers pick up.
publish_cmds='npm publish
pnpm publish
yarn publish
twine upload
hatch publish
flit publish
uv publish
cargo publish
cargo release publish
cargo-release publish
mix hex.publish
pypa/gh-action-pypi-publish
JS-DevTools/npm-publish
JS-DevTools/action-publish
crate-ci/cargo-release'

# npm publish lifecycle hooks + publishConfig — publish infrastructure specific to
# SDK manifests. Checked on manifests only (meaningless in a workflow).
manifest_keys='prepublishOnly
prepack
prepublish
publishConfig'

# Publish commands: every scanned surface.
while IFS= read -r cmd; do
  [ -n "$cmd" ] || continue
  if printf '%s' "$content" 2>/dev/null | grep -qF -- "$cmd"; then
    printf '%s: publish signal "%s" — SDKs must not publish from the monorepo (ADR 0015)\n' \
      "$path" "$cmd" >&2
    status=1
  fi
done <<EOF
$publish_cmds
EOF

# Manifest-only: publish lifecycle keys.
if [ "$is_sdk_manifest" = 1 ]; then
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    if printf '%s' "$content" 2>/dev/null | grep -qF -- "$key"; then
      printf '%s: publish lifecycle key "%s" — SDKs must not publish from the monorepo (ADR 0015)\n' \
        "$path" "$key" >&2
      status=1
    fi
  done <<EOF
$manifest_keys
EOF
fi

exit "$status"
