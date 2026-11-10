# Maintainer checks

The local confidential-term checks that maintainers run in addition to the public CI gates.
Contributors do not need them; the hooks print an inactive notice without the local policy.

Maintainer checks for confidential terms require an ignored identifier inventory, integrity policy,
and activation marker, plus activation recorded in local Git configuration. The inventory owner
prepares the inventory locally, then initializes its policy with
`python3 scripts/private_identifier_guard.py --repo "$PWD" initialize --expected-count COUNT`,
using the verified entry count. Install with `sh scripts/install-hooks.sh`. Routine installation
validates the existing policy; it does not accept a changed inventory. After activation, missing
or changed inputs fail closed even if the entire ignored policy directory is removed. Partial
owner-policy state without activation also denies. Contributor mode prints an inactive notice.
The installer refuses a configured alternate hooks path or a linked worktree before writing hooks.
Explicit initialization can accept an updated
inventory; the local owner remains trusted. Do not share the inventory or its digest in source,
reviews, issues, or CI.

These hooks check staged bytes, raw pending messages, and outgoing Git objects. Automatic merge,
cherry-pick, rebase, and mail-application commits can skip the commit checks; the pre-push check
is their local backstop. Creating a new remote ref scans its full ancestry, including commits
already retained under another remote ref.

The message hook rejects confidential terms even in editor comments, verbose diffs, or templates:
Git does not tell this hook which cleanup mode will later remove those bytes. For deletion-only
cleanup, stage the removal with `git rm -- path` and use an explicit clean message with
`git commit -m 'Remove obsolete material'`. Avoid including confidential paths in the message.

The public CI checks
directory classes and generic secret signatures; it cannot attest to confidential-term coverage.
Inventory-owner confirmation of confidential-term coverage remains necessary. Other hosts, web
edits, provider merge actions, and bypassed hooks remain outside local enforcement.
