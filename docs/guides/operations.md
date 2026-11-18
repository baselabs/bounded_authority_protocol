# Operations

The library has no supervisor, application callback, store, network client, health endpoint,
clock, randomness, or telemetry. Deploy the pinned package inside the host and monitor the
host's request path and dependencies. The conformance CLI is a documented offline file-I/O tool,
not a health probe or an authority service.

At startup, the host validates its selected profile, trusted-key configuration, audience,
external origin, bounds, time policy, and durable reservation backend. Monitor key refresh
age, clock offset, revocation freshness, reservation failures, and evidence import failures.
Do not convert a failing dependency into a successful verification or an authorization decision.

Alert on a change in the rate of closed verifier refusals and host admission failures. Keep
those classes separate: an invalid credential is not a store outage. Avoid request-specific
metric labels. Use a new immutable package version for upgrades, qualify it against the
certified corpora and your own host tests, and retain the old artifact for an explicit rollback.
Never mutate a frozen profile to loosen a refusal.

On incident, stop effects when trust or replay guarantees are uncertain. Preserve the host's
authoritative execution and revocation records, authenticate replacement keys outside the
verifier, and reconcile execution outcomes before retrying. The package cannot certify deletion,
retention, recovery, or the latest content generation.

See [caller-side observability](observability.md), [testing](testing-your-integration.md),
and [upgrading](upgrading.md).
