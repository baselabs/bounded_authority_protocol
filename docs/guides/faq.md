# FAQ

### Does a successful verification mean the request is allowed?

No. It means the bytes you supplied satisfy the keys and expectations you supplied. Before you
act, your service still selects which keys it trusts, reserves the invocation id against
replay, checks that the grant is not revoked, and applies its own policy. Every facts struct
says so in its `authorization: :not_evaluated` or `trust: :not_evaluated` field.

### Why does credential verification always reject with `{:error, :invalid}`?

So a rejection tells an attacker nothing about which check failed. To debug your own
credentials, use the [troubleshooting checklist](troubleshooting.md), which compares the decoded
claims with your expectations.

This is the credential-verifier error contract. Public crypto predicates return booleans instead;
`ContentAssertion.V1.verify_successor/3` returns `:ok` or `{:error, :invalid}`;
`Bounds.maximum/0` returns bounds directly. `Conformance.Cli.run/1` returns exit status
`0`, `1`, or `2`. The [API stability page](api-stability.md) distinguishes each function family's result shape.

### Why does the package not sign anything?

Signing needs a private key, and a verification library that never sees one cannot leak one.
The package computes the exact bytes to sign and assembles the result from a signature you
supply. For production signing, use
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
in Elixir or `@bounded-authority-protocol/signer` in TypeScript, both of which sign through your
KMS, HSM, or key store.

### Is this a payments protocol?

No. A grant can authorize any named operation with constrained arguments: deploying a service,
reading a file, exporting a dataset, rendering a job, or charging a card. The examples in these
guides span several domains for that reason.

### How is this different from OAuth access tokens or plain DPoP?

OAuth 2.0 is an authorization framework for delegated, scoped access, not a proof of identity.
BAP complements OAuth by expressing operation and argument constraints in a holder-bound grant
and binding its proof to the exact request context and canonical argument bytes. OAuth scopes,
DPoP, and BAP overlap in limiting access and proving possession; your resource server's policy
decides how they compose. The proof format follows DPoP
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) and adds a digest of the operation and its
typed arguments, so a proof for one set of arguments never verifies for another. The wire
profile is closed: there is no algorithm negotiation and no unknown member is ignored. Pure
verification returns facts, not permission to execute. Trusted-key selection, replay reservation,
revocation checks, and the authorization decision remain the host's responsibility.

### Which contract-major should I use?

Contract-major 1 unless you need numeric range selectors (contract-major 2) or P-256 keys
(contract-major 3). See [Choosing a profile](choosing-a-profile.md).

### Can I loosen a bound because a legitimate payload exceeded it?

No. The bounds are part of the wire contract and you can only tighten them. A payload over a
bound is non-conforming; the producer that made it needs fixing.

### Why is my whole-number selector value refused?

A grant producer refuses a float-tagged whole number such as `{:float, 2.0}` in a selector,
because canonical JSON writes it as `2`, which decodes as an integer. Tag it `{:integer, 2}`.
See [erratum 6](../errata.md) and [Recipes](recipes.md#tag-numbers-by-what-they-are).

### My KMS returns a DER ECDSA signature. What do I pass to `assemble_compact/2`?

The raw 64-byte `r || s` with low S: `Es256.der_to_raw/1`, then `Es256.normalize_low_s/1`.
See [Recipes](recipes.md#es256-from-a-kms-or-hsm).

### Does the verifier check revocation or replay?

No. The package is stateless: it reads no clock, store, or network. Revocation and replay belong
to your service or a stateful authority runtime. Reserve the issuer/grant/invocation execution
identity atomically before any effect, in durable storage shared by every service instance.
Keep it through grant expiry plus the maximum clock skew your service permits, or retain an
authoritative execution record longer. A proof's freshness window is not a safe retention
period, since the holder can sign another proof for the same invocation. The
[service notebook](../notebooks/service-integration.livemd) executes that case.

### How do I rotate issuer keys?

Trust both keys during an overlap, select the key by the grant's `kid` from your own key ring,
then remove the old key. See [Recipes](recipes.md#rotate-issuer-keys).

### Can I accept two contract-majors at the same endpoint?

Yes, if your routing decides which one each request uses, for example from the client's
registration. Never try one and fall back to another after a rejection.

### Will 1.x break my code?

No: within package 1.x, the stable surface keeps its modules, functions, struct fields, return
shapes, and error value. See [API stability and versioning](api-stability.md).

### What happens when a verifier bug is found?

If the fix only rejects inputs no conforming producer emits, it ships as a soundness repair in a
minor release, recorded in the [errata registry](../errata.md). Any other verdict change needs a
new contract-major. [Governance](../governance.md) has the rules, and
[`SECURITY.md`](https://github.com/baselabs/bounded_authority_protocol/blob/main/SECURITY.md)
how to report a vulnerability.

### Is there a verifier for my language?

TypeScript, Python, Rust, and Go; see [Other languages](other-languages.md).

### Which profile should I choose for a P-256 content signature?

Use `ContentAssertion.ES256.V1` for standalone content, such as a signed dataset
revision. Use `V3` for P-256 capability grants and holder-bound requests. For an
exact-action approval, use `ActionApproval.V1` with the host-selected suite. For
a signed statement about the holder key's custody, use `HolderCustodyAttestation.V1`.
See [Choosing a profile](choosing-a-profile.md).
