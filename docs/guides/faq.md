# FAQ

### Does a successful verification mean the request is allowed?

No. It means the bytes you supplied satisfy the keys and expectations you supplied. Before you
act, your service still selects which keys it trusts, reserves the invocation id against
replay, checks that the grant is not revoked, and applies its own policy. Every facts struct
says so in its `authorization: :not_evaluated` or `trust: :not_evaluated` field.

### Why does every failure return the same `{:error, :invalid}`?

So a rejection tells an attacker nothing about which check failed. To debug your own
credentials, use the [troubleshooting checklist](troubleshooting.md), which compares the decoded
claims with your expectations.

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

An access token says who may call; a grant also says which operations, with which argument
values, and binds every request to one holder key. The proof format follows DPoP
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) and adds a digest of the operation and its
typed arguments, so a proof for one set of arguments never verifies for another. The wire
profile is closed: there is no algorithm negotiation and no unknown member is ignored.

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
to your service or a stateful authority runtime.

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
