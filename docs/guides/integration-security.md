# Integration security

Protect the complete admission path, including every host instance. Verification is one pure
step and cannot repair an untrusted expected context, an unauthenticated trust source, or a
non-atomic replay check.

| Boundary | Integrator responsibility |
|---|---|
| Transport | Authenticate the peer and configured external origin; enforce TLS except for the explicit direct-loopback profile |
| Parsing | Preserve exact compact bytes, reject duplicate credentials and JSON members, enforce size limits before expensive work |
| Trust | Authenticate key distribution, enforce enrollment subgroup policy, bound trust freshness, and check live revocation |
| Context | Derive audience, method, target, operation and cast arguments from the host's authenticated contract |
| Time and nonce | Supply trustworthy Unix seconds and the exact challenge; retire challenges in durable host state |
| Replay | Atomically reserve issuer/grant/invocation identity before effects through grant expiry plus maximum host skew |
| Authorization | Apply current host policy; verified facts never imply permission |
| Evidence | Pin historical trust and object versions; maintain lineage high-water state and archival retention policy |
| Logs | Record fixed outcome classes and bounded measurements; omit credentials, signatures, nonces, argument values and private keys |

Refuse when a required host dependency cannot establish trust, revocation, or reservation.
A temporary store outage is not permission to execute. Do not retry a failed verifier with
looser limits, a different clock, another key, or another profile. Diagnose your own test inputs
with [troubleshooting](troubleshooting.md), away from the production response path.

Read the [threat model](../design/threat-model.md) for protocol assumptions and
[SECURITY](../../SECURITY.md) for reporting vulnerabilities and verifying source attestations.
