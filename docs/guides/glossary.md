# Glossary

**All selector** (`:all`). A selector that places no restriction on the arguments. An operation
whose only selector is `:all` accepts any arguments.

**Anchored export.** One archive object that holds a consumption chain's rows, its start and end
boundary anchors, and any key transitions, verified as a whole to the exact end of the object,
its digest, and an out-of-band object version. See [Evidence](evidence.md).

**Archive key.** A key that signs boundary anchors and key transitions. It has a validity window
and is passed to the verifier as a `HistoricalPublicKey`.

**Assemble.** Combine a signing input and a signature into the compact JWS (`assemble_compact/2`).
Assembly checks the signature's form and refuses one no conforming signer emits; it never
verifies the signature and never rewrites it.

**Audience** (`aud`). The services a grant is valid for. The verifier checks that the audience
you expect is one of the grant's audiences, exactly.

**Boundary anchor.** A signed statement (`typ: "ba+chain-anchor"`) that a chain had a given
sequence and head at a given time.

**Bounds.** The resource limits applied while decoding and verifying (`BoundedAuthorityProtocol.V1.Bounds`).
Each has a protocol maximum; a caller may only tighten them.

**Cast arguments.** The operation's arguments after the service has parsed and cast them to the
operation's declared types, in the tagged JSON form. The proof binds a digest of the operation
and the cast arguments.

**Certified corpus.** A conformance corpus whose `index.json` SHA-256 is pinned by the CLI and
every implementation. Every case states its expected verdict or output.

**Compact (JWS).** The three-part `header.payload.signature` form, each part base64url-encoded,
in which grants, proofs, anchors, transitions, attestations, and assertions travel.

**Consumption chain.** Hash-linked rows, one per accepted invocation, each carrying a 32-byte
commitment the host computes.

**Content assertion.** A sibling attestation profile (`typ: "ba+content-assertion"`) that binds
the digest of exact content bytes to a context and a lineage.

**Contract-major.** A complete, closed wire profile, numbered 1, 2, and 3 so far, with its own
namespace (`V1`, `V2`, `V3`), suite, specification, and corpus. Not a package version: one
package release carries several contract-majors.

**Facts.** The redacted result of a successful verification, such as `GrantFacts` or
`EnvelopeFacts`. Facts carry identifiers, digests, and times, never raw keys, signatures,
nonces, or arguments, and they are never an authorization: `authorization: :not_evaluated` or
`trust: :not_evaluated`.

**Grant.** A capability the issuer signs (`typ: "ba+cap"`): the holder's key thumbprint, the
audiences, a validity window, and the operations the holder may invoke, each with selectors.

**Holder.** The party that holds the key a grant names and signs a proof for each request.

**Holder thumbprint** (`cnf.jkt`). The RFC 7638 SHA-256 thumbprint of the holder's public key.
The package handles it as raw 32 bytes.

**Invocation id.** A fresh identifier per request, carried in the proof. The host reserves it in
its replay store; the package only checks that it matches what you expect.

**Issuer.** The party that signs grants. The verifier trusts an issuer key only because you pass
it in `TrustedIssuer`.

**Key acceptance.** The check a public key passes before it may enter a verification input:
`Ed25519.acceptable_public_key?/1` or `Es256.acceptable_public_key?/1`.

**Key transition.** A signed statement (`typ: "ba+key-transition"`) in which the current archive
key authenticates its successor.

**Low S.** For ES256, the canonical member of each pair of valid signatures `(r, s)` and
`(r, n - s)`: the one with `s <= n/2`. Contract-major 3 accepts only low-S signatures.

**Nonce.** An optional server-issued challenge the proof must carry when the service requires
one. The local-loopback profile always requires it.

**Operation.** A named action a grant permits, with its selectors. The service maps its own route
to the operation name; the client never chooses it.

**Package 1.x.** A release line of the Hex package. The [API stability](api-stability.md) page
lists what it promises.

**Proof** (proof of possession). A per-request signature by the holder (`typ: "dpop+jwt"`) that
binds the grant, the method, the target URI, the invocation id, the operation, the argument
digest, and the time.

**Profile.** A closed wire format with its own `typ` or `v` value, specification, and corpus: a
contract-major or a sibling profile.

**Role attestation.** A sibling attestation profile (`typ: "ba+role-attestation"`) in which an
attestor key binds a subject key to the `issuer` or `holder` role.

**Selector.** A restriction on one argument path: `equals`, `one_of`, `all`, and, from
contract-major 2, `lte` and `gte`.

**Sibling profile.** A byte-distinct profile beside the contract-majors, with its own protected
`typ` and API: local-loopback HTTP proofs, role attestations, and content assertions.

**Signing input.** The exact bytes to sign for a protocol object (`message`), returned by the
`*_signing_input/2` producers.

**Soundness repair.** An erratum that changes verdicts only from accept to reject, on inputs no
conforming producer emits, under the conditions in [governance](../governance.md).

**Strict Ed25519.** The one Ed25519 verification rule every surface applies: canonical
encodings, no small-order key or `R`, `S` below the group order, and the cofactorless equation.

**Suite.** The named combination of signature algorithm, digest, and domain separators of a
contract-major: `BAP1-Ed25519-SHA256`, `BAP2-Ed25519-SHA256`, `BAP3-ES256-SHA256`.

**Tagged JSON.** The package's JSON value form, which keeps integers and floats apart and
preserves member order: `:null`, `{:boolean, b}`, `{:integer, i}`, `{:float, f}`,
`{:string, s}`, `{:array, values}`, and `{:object, members}`.

**Torsion-free.** An Ed25519 key with no small-order component. Hosts check it with
`Ed25519.torsion_free?/1` at enrollment, at trust install, and before revocation comparisons.

**Untrusted key locator.** `untrusted_key_locator/2`: reads only the `kid` from a compact's
protected header, as a lookup hint with `trust: :not_evaluated`.
