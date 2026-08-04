# Protocol charter

## Objective

Define and deterministically verify the exact bytes for one issuer-bounded, holder-proven remote
invocation. The package returns cryptographic/contextual facts; operational authorization and live
state remain outside it.

## Standards posture

The protocol is on a standards track governed by the
[standards track charter](standards-track.md) and
[ADR 0006](../adr/0006-standards-evolution-suite-identity-and-delegation-posture.md): the closed
wire profile is permanent and evolution happens above it through parallel contract-majors; the
current profile is the named suite `BAP1-Ed25519-SHA256` with a specified post-quantum succession
and cross-suite evidence-attestation path; names for delegation (`ba_dlg`,
`ba+cap-delegated`), principal binding (`ba_obo`), and status checking are reserved in the
[registries](registries.md) with their designs decided; governance, errata, and deprecation
policy are published. Nothing in that posture changes a byte, bound, or verdict of this charter's
verification chain.

## Verification chain

1. The caller supplies raw credentials and expected issuer/request context to the private runtime.
2. The bounded `untrusted_key_locator/2` returns only the protected grant `kid` as an explicitly
   untrusted lookup hint.
3. The runtime combines expected issuer context with that hint and resolves a candidate public-key
   snapshot.
4. Outside a database transaction, `verify_grant/3` verifies the raw compact grant against the
   exact candidate key, issuer, audience, explicit time, skew, and bounds. It returns redacted
   `GrantFacts{authorization: :not_evaluated}`.
5. The grant binds an Ed25519 holder key through `cnf.jkt`.
6. `check_envelope/2` accepts raw grant and proof bytes, re-verifies the raw grant rather than
   accepting the facts, verifies the RFC 9449 proof, and binds holder, grant, method, normalized
   HTTPS URI, invocation ID, operation, cast-argument digest, time, nonce, and selectors.
7. The library returns redacted `EnvelopeFacts{authorization: :not_evaluated}`, or exactly
   `{:error, :invalid}`.
8. The stateful authority then begins one transaction, re-resolves and locks current
   key/revocation facts, fingerprint-matches the verified snapshot, requires current eligibility,
   checks replay, and records its decision/execution claim. The host independently authorizes the
   business effect.

Neither a decoded struct nor caller-provided `GrantFacts`/`EnvelopeFacts` is accepted as
credentials.

## Grant

Protocol v1 uses standard compact JWS with exact RFC 7515 signing bytes, `alg: EdDSA`,
`typ: ba+cap`, an issuer-controlled `kid`, and a closed claim schema. Claims cover issuer,
audience, grant ID, coherent times, unique operations, ordered selectors, and holder binding.
Deterministic producers emit JCS protected/payload bytes and return a signing input; the package
never accepts private key material, a signer, or a signing callback.

Unknown versions, algorithms, headers, claims, selectors, duplicate keys, encodings, or
over-limit structures fail closed. The verifier does not use `kid` to discover trust.

## Holder proof

Each invocation supplies compact RFC 9449 DPoP:

- protected header: exact `typ: dpop+jwt`, `alg: EdDSA`, and public Ed25519 JWK;
- claims: `jti`, server-derived `htm` and normalized hierarchical HTTPS `htu`, `iat`, grant hash
  `ath`, optional challenged `nonce`, invocation UUID `ba_inv`, operation `ba_op`, and request
  digest `ba_req`;
- `ba_req = base64url(SHA-256("BAP1-REQUEST\0" ||
  JCS([operation, typed(cast_arguments)])))`, where the prefix is exact ASCII including its final
  zero byte and the closed recursive `typed/1` projection preserves every tagged JSON variant,
  including integer versus integral-float identity.

Arguments may be any tagged JSON value. `all` matches any root; path selectors traverse objects
only and compare tagged JSON semantically, including unordered object members. No unprotected
security parameter, private JWK member, caller-selected expected context, or bearer fallback is
accepted.

## Verification results

`GrantFacts` and `EnvelopeFacts` are immutable, closed, bounded, value-bearing, and redacted. Their
fixed inspection does not expose fields, and they implement no generic encoder. They contain only
the exact identifiers, times, fingerprints, and hashes required by the private runtime, plus
`authorization: :not_evaluated`; they exclude arguments, selector values, raw credentials,
signatures, JWK containers, and nonces.

Those facts are not operational decisions. The private runtime accepts raw credential bytes at
its public boundary and produces facts internally; it never treats a caller-provided facts struct
as an execution credential.

## Evidence verification

BAP-04 chain/archive functions verify canonical row bytes, sequence, previous-link hashes,
caller-supplied range boundaries, signed boundary anchors, authenticated historical-key rollover,
complete archive framing/digest/EOF, and exact out-of-band object version. Historical keys and
expected context are caller supplied; the package performs no lookup or current-key fallback.

Chain consistency does not certify deletion absence. A separately valid shortened or relinked
archive fails only against the original expected boundaries. The package does not read storage,
append rows, hold or select keys, create or submit anchors, submit witnesses, remove archives,
certify retention, or decide operational authority.
