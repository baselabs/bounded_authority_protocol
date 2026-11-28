# Verification facts and host authorization

A successful verification means only that supplied bytes satisfy the supplied trusted inputs
and expected context. `GrantFacts`, `EnvelopeFacts`, and `AnchoredExportFacts` expose
`authorization: :not_evaluated`. Chain, anchor, transition, role and custody attestation,
content-assertion, and action-approval facts expose `trust: :not_evaluated`. The host uses those
facts as evidence when applying its own authorization policy.

The host selects trust, authenticates the request's origin, derives the operation and cast
arguments, verifies raw credentials, checks live revocation, reserves the execution identity,
and applies current authorization policy before performing an effect. Coordinate reservations,
policy, and effects through the host's authoritative transaction or execution protocol. A
verification result cannot replace that transaction, a caller identity, or a policy decision.

Decoders establish no signature validity. Producers and compact assembly establish no trust.
The suite-specific content assertion `verify_successor/3` checks consistency between two supplied facts values;
verify both assertions first and retain durable lineage state to detect forks or rollback. Facts
are ordinary values, so constructing a facts struct yourself never grants their provenance.

Redacted inspection is a logging boundary, not an access-control mechanism. Read only named
properties needed by the application. Do not convert facts to maps for logging or use
`inspect(value, structs: false)`, generic serialization, or exception dumps of request bindings.
See the [result matrix](api-stability.md#result-families) and [integration security](integration-security.md).

Approval facts bind one request revision and exact effect. The host applies the approver role
policy, compares the current revision, and claims the approval and request identities in the
same transaction as the effect or durable delivery intent. See the [approval recipe](recipes.md#verify-an-action-approval).
