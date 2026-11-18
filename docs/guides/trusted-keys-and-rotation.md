# Trusted keys and rotation

Choose public keys from an authenticated, host-owned trust configuration. An untrusted `kid`
returned by `untrusted_key_locator/2` is a lookup hint into that configuration. It cannot name a
URL to fetch, install a key, or turn an embedded JWK into a trusted issuer. Missing or ambiguous
ids are host refusals; never try every available key or profile until one verifies.

During rotation, install the next key before accepting its grants. Keep an overlap for the
old key's outstanding validity windows and your permitted skew. Stop accepting newly issued
credentials from the old key according to your issuer policy; remove trust when that policy
requires it, including emergency revocation. Verification does not contact the issuer or consult
revocation state. Refresh and authenticate the trust set outside the package and refuse when
freshness or trust cannot be established.

For Ed25519 enrollment, call `Ed25519.torsion_free?/1` before installing a key or comparing it
with deny lists. The protocol's key-acceptance rule intentionally permits some non-small-order
torsioned points; thumbprints alone do not collapse these variants. Historical archive keys have
explicit validity windows. A valid key transition authenticates a link under caller-supplied
history; it does not discover the root of trust.

The [service notebook](../notebooks/service-integration.livemd) executes overlap, an unknown
key, and a grant mislabeled with the new key id. See [evidence](evidence.md) for historical keys.
