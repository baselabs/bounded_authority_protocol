# 23. Public-history privacy boundary

Date: 2026-08-24

## Status

Accepted.

## Context

This repository is public. Earlier documentation and commit descriptions named private product
repositories and described their deployment topology. Removing those words only from the current
tree would leave them reachable through public branches, tags, commit messages, and historical
blobs.

The public/private product boundary must also be unambiguous. `bounded_authority` is BaseLabs'
private commercial authority application. The public artifact is this protocol library, not the
stateful application.

## Decision

1. Public source, documentation, tests, release metadata, and reachable Git history do not identify
   private product repositories or describe their product-specific deployment topology.
2. Public material may state the generic relationship: private applications consume this public,
   stateless protocol and must obtain operational authority from a private stateful runtime.
3. `bounded_authority` must never be published as a public Hex package. Any
   private-Hex release requires both an active paid subscription and fresh owner approval for the
   exact release; readiness or a prior approval is not publication authority.
4. The public branches and release tags are rewritten in place to remove the historical disclosure
   while preserving their names and release content. Rewritten refs stop pointing at the old
   object identifiers; that does not invalidate copies retained by the hosting provider.
5. A repository gate scans the tracked tree, reachable commit messages, merge-aware historical
   paths, every reachable commit snapshot, and annotated-tag messages for the prohibited topology
   class. Exact private identifiers live only in the ignored local guard manifest; publishing their
   plaintext or unsalted hashes would create a confirmation oracle.
6. Hosting-provider cached object pages and pull-request references are outside Git's ref rewrite.
   They remain open until the provider confirms garbage collection and anonymous requests for the
   affected old identifiers return `404`.
7. The structural architecture gate rejects local authoring-tool directories at any tracked path
   depth and in HEAD ancestry, including merge-only and subsequently removed paths. Its sole
   current-tree exception is the root critical-surface manifest, pinned to regular-file mode and
   exact public bytes. Shallow history and failed Git reads are errors. The package hygiene gate
   includes hidden files and checks its scan roots against the package declaration.
8. CI secret detection uses a pinned, checksum-verified Gitleaks binary in a separate job. Public
   fixture exceptions are restricted by detector, path, and observed fixture form; exceptions for
   removed fixtures are also restricted to their historical commits. These checks cover generic
   secret signatures and directory classes, not confidential or patent terms.
9. Exact confidential-term enforcement belongs to the owner-host local guard. Its manifest and
   integrity policy and activation marker remain ignored local state; activation is also recorded
   in local Git configuration so removing ignored files cannot silently disable the guard.
   Contributor installation works without owner-policy inputs or activation and reports that it
   is inactive. Missing, changed, or partial owner-policy state denies local commit and push checks.
   Explicit initialization accepts an owner-approved inventory change;
   the local owner remains trusted. Raw message checks include editor comments and templates
   because Git does not supply its later cleanup mode to the hook. The pre-push check covers
   local automatic commits that skip commit hooks and scans full ancestry for new remote refs.
   This does not cover web edits, provider merge actions, automated
   dependency commits, fork pull-request contents, issue or pull-request text, other hosts, or
   bypassed local hooks. Patent-term coverage requires an inventory-owner receipt. CI workflow
   and scanner edits remain subject to review and required-check configuration; job isolation
   does not prevent a pull-request author from proposing changes to those checks.

## Consequences

- Protocol bytes, schemas, public APIs, conformance vectors, SDK behavior, package versions, and
  existing Hex artifacts do not change.
- Every clone must re-clone or reconcile deliberately after the force-update; old commit IDs no
  longer identify the public lineage.
- Private product details stay in their owning private repositories.
- A successful local history gate proves only reachable local refs. Provider-cache removal requires
  a separate externally observed receipt.
