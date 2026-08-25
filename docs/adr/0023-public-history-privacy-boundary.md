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
3. `bounded_authority` must never be published as a public Hex package. It is not currently
   distributed through private Hex because there is no paid private-package subscription. A future
   private-Hex release requires both an active paid subscription and fresh owner approval for the
   exact release; readiness or a prior approval is not publication authority.
4. The public branches and release tags are rewritten in place to remove the historical disclosure
   while preserving their names and release content. Old object identifiers are invalidated.
5. A repository gate scans the tracked tree, reachable commit messages, merge-aware historical
   paths, every reachable commit snapshot, and annotated-tag messages for the prohibited topology
   class. Exact private identifiers live only in the ignored local guard manifest; publishing their
   plaintext or unsalted hashes would create a confirmation oracle.
6. Hosting-provider cached object pages and pull-request references are outside Git's ref rewrite.
   They remain open until the provider confirms garbage collection and anonymous requests for the
   affected old identifiers return `404`.

## Consequences

- Protocol bytes, schemas, public APIs, conformance vectors, SDK behavior, package versions, and
  existing Hex artifacts do not change.
- Every clone must re-clone or reconcile deliberately after the force-update; old commit IDs no
  longer identify the public lineage.
- Private product details stay in their owning private repositories.
- A successful local history gate proves only reachable local refs. Provider-cache removal requires
  a separate externally observed receipt.
