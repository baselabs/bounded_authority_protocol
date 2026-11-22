# Maintainer checks

The local confidential-term checks that maintainers run in addition to the public CI gates.
Contributors do not need them; the hooks print an inactive notice without the local policy.

Maintainer checks for confidential terms require an ignored identifier inventory, integrity policy,
and activation marker, plus activation recorded in local Git configuration. The inventory owner
stores the inventory at `<git-common-dir>/info/private-identifiers`, where
`git rev-parse --path-format=absolute --git-common-dir` resolves `<git-common-dir>`.
The integrity policy and activation marker live beside it under
`info/private-identifier-guard/`. These files stay outside tracked worktrees and are shared
by every linked worktree. The inventory owner then initializes its policy with
`python3 scripts/private_identifier_guard.py --repo "$PWD" initialize --expected-count COUNT`,
using the verified entry count. Install with `bash scripts/install-hooks.sh`. Routine installation
validates the existing policy; it does not accept a changed inventory. After activation, missing
or changed inputs fail closed even if the entire ignored policy directory is removed. Partial
owner-policy state without activation also denies. Contributor mode prints an inactive notice.
The installer refuses a configured alternate hooks path or a linked worktree before writing hooks.
Explicit initialization can accept an updated
inventory; the local owner remains trusted. Do not share the inventory or its digest in source,
reviews, issues, or CI.

The three top-level hooks are generic. After the identifier guard succeeds, pre-commit runs
every entry in `scripts/hooks/pre-commit.d/` in byte-sorted order, including hidden entries.
Entries must be readable, executable regular files, not symlinks; an invalid entry or the first
failing check stops the commit. A missing or empty directory is valid. The installer links only
the top-level hook files. This repository keeps its staged SDK publication check in
`scripts/hooks/pre-commit.d/sdk-publish-infra`, using the same checker as its CI backstop.
The standalone `python3 scripts/test_private_identifier_guard.py` tests only the generic files
with synthetic identifiers and real temporary Git repositories. CI runs it through
`mix privacy.hooks`, included in `mix quality.source`.

These hooks check staged bytes and raw pending messages. Before a push, they check each outgoing
commit's message and the paths and blobs it introduces relative to its parents, along with pushed
refs, tags, and terminal objects. Automatic merge, cherry-pick, rebase, and mail-application commits
can skip the commit checks; the pre-push check is their local backstop. For an existing remote ref,
the commit scan excludes ancestry reachable from its current remote object. For a new remote ref,
it excludes commits already reachable from `refs/remotes/<remote>/*`, using the exact configured
remote name passed to the hook. An unconfigured name or URL, or a remote without tracking refs,
keeps the full-ancestry scan. Tracking refs for other remotes never exclude commits.

The message hook rejects confidential terms even in editor comments, verbose diffs, or templates:
Git does not tell this hook which cleanup mode will later remove those bytes. For deletion-only
cleanup, stage the removal with `git rm -- path` and use an explicit clean message with
`git commit -m 'Remove obsolete material'`. Avoid including confidential paths in the message.

The public CI checks
directory classes and generic secret signatures; it cannot attest to confidential-term coverage.
Inventory-owner confirmation of confidential-term coverage remains necessary. Other hosts, web
edits, provider merge actions, and bypassed hooks remain outside local enforcement.
