# Protocol charter

## Objective

Define and deterministically verify the bytes for one issuer-bounded, holder-proven remote
invocation and for its value-free append-only evidence. Operational authorization remains outside
this package.

## Verification chain

1. The caller supplies raw credentials and an expected issuer context to the stateful runtime.
2. The library's bounded `untrusted_key_locator/2` returns only the protected-header `kid` as an
   explicitly untrusted lookup hint.
3. The runtime combines expected issuer context with that hint and resolves a candidate public-key
   snapshot.
4. Outside a database transaction, the library verifies a closed capability grant against that
   snapshot, expected audience/instance,
   explicit time, and explicit bounds.
5. The grant binds an Ed25519 holder key through `cnf.jkt`.
6. The library verifies an RFC 9449 DPoP proof against the verified grant and server-derived method,
   normalized URI, invocation ID, operation, and cast-argument digest.
7. The library returns closed `EnvelopeFacts` with `authorization: :not_evaluated`, or the single
   fixed production error `:invalid`.
8. The stateful authority then begins one transaction, re-resolves and locks current key/revocation
   facts, fingerprint-matches the verified snapshot, requires current eligibility, checks replay,
   and records a decision and execution
   claim, and the host independently authorizes the business effect.

## Grant

Protocol v1 uses compact JWS with `alg: EdDSA`, `typ: ba+cap`, an issuer-controlled `kid`, and a
closed claim schema. Claims cover issuer, audience/consumer instance, grant/token IDs, time
window, operations, provider-neutral subject and field restrictions through selector paths and
values, and holder binding. Traversal depth and explicit resource limits are parser/context
bounds, not additional grant claims.

Unknown versions, algorithms, critical headers, claims, selectors, holder modes, duplicate keys,
invalid UTF-8, and over-limit structures fail closed. The public verifier does not use `kid` to
discover trust.

## Holder proof

Each invocation supplies compact RFC 9449 DPoP:

- protected header: `typ: dpop+jwt`, `alg: EdDSA`, public Ed25519 `jwk`;
- claims: `jti`, server-derived `htm` and normalized `htu`, `iat`, capability hash `ath`,
  optional challenged `nonce`, invocation UUID `ba_inv`, stable operation `ba_op`, and request
  digest `ba_req`;
- `ba_req = SHA-256("BAP1-REQUEST\0" || JCS([operation, cast_arguments]))`, where the quoted
  prefix is the exact ASCII domain-separator byte string including its final zero byte.

No unprotected security parameter, embedded private JWK value, caller-selected expected context,
or bearer fallback is accepted.

## Evidence verification

Chain and archive functions verify canonical row bytes, sequence, previous-link hashes, anchors,
public-key rollover, archive coverage, and truncation/omission evidence. They do not read live
storage, append a row, create an anchor, submit a witness, certify archival deletion, or decide
retention.

## Verification result

`EnvelopeFacts` is immutable, closed, bounded, value-free, redacted on inspection, and has no
generic JSON encoder. It carries the exact protocol version and canonical identifiers needed by a
stateful runtime, plus `authorization: :not_evaluated`. It is not an operational authorization
decision and cannot grant an effect without adjacent live-state and host-policy checks.

The private runtime accepts raw credential bytes at its public boundary and produces
`EnvelopeFacts` internally. A caller-provided facts struct is never an execution credential.
