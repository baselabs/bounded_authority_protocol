# Testing your integration

Execute your integration against the real host parser, trusted-key configuration, signer,
revocation source, and authoritative reservation store. The package's conformance suite proves
protocol byte behavior; it cannot prove the correctness of your route mapping or transaction.

For each selected profile, create a valid request, verify it through the real request boundary,
and prove the effect occurs once. Then independently change the audience, method, external
target, invocation id, operation, argument value and numeric tag, holder key, grant signature,
nonce value, and time boundary. Each must refuse before any effect. Include duplicate headers,
unknown profiles, unknown issuer key ids, tightened limits, and an ambiguous proxy origin.

Repeat the same invocation concurrently across host instances and after a restart. After its
first proof expires, sign a fresh proof for that same invocation under a still-valid grant;
execution must still be refused. Simulate outages by actually stopping or isolating the host's
throwaway dependencies, then verify refusal and cleanup; never replace a required service with
a fake success. Use isolated test data and remove it through the harness that created it.

For evidence, test changed bytes, missing and reordered rows, wrong expected object versions,
key-history gaps, expired attestations, and content lineage forks. Pairwise successor success
cannot replace a durable high-water check.

The [service notebook](../notebooks/service-integration.livemd) is a sequential explanation of
retention and ordering; its map is not a concurrent or durable store. Your host tests establish
those properties against your real backend. CI also executes the exact documented Plug recipe
against the real Plug dependency in a fresh package consumer.
