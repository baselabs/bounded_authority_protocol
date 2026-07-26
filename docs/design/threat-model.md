# Threat model

## Protected properties

- A malformed or altered grant/proof cannot verify.
- A proof cannot be reused as valid protocol bytes for another grant, request, operation,
  endpoint, holder, or invocation.
- Equivalent-looking but noncanonical encodings cannot produce ambiguous signing inputs,
  request digests, or chain links.
- Unknown versions, fields, algorithms, and extensions cannot become permissive compatibility.
- Untrusted input cannot select a trusted issuer key or expected server context through this API.
- Product/private dependencies cannot enter the public package unnoticed.
- Errors, fixtures, logs, and test output remain value-free and contain no private key material.

## Primary adversaries

- a caller controlling token/proof bytes and model-selected arguments;
- a bearer-token thief without the holder private key;
- a holder attempting request, operation, URI, algorithm, header, claim, encoding, or clock
  substitution;
- a consumer accidentally treating pure verification as live operational authority;
- a contributor introducing filesystem, network, environment, process, clock, randomness,
  database, private-package, or product-vocabulary dependencies;
- a producer emitting vectors that only its own implementation accepts.

## Required controls

- closed bounded decoding before expensive cryptography;
- explicit already-trusted public-key and expected-context inputs;
- exact JCS, JWS, JWK-thumbprint, DPoP, URI-normalization, and hash-chain rules;
- no trust discovery, private-key input, live state, side effects, or implicit clock;
- fixed value-free errors;
- meaningful-byte tamper, duplicate-key, invalid-encoding, property/fuzz, timing, allocation, and
  mutation-red gates;
- language-neutral normative fixtures verified by an independent implementation;
- package architecture tests rejecting runtime/product/private dependencies.

## Adjacent controls outside this library

Trusted-key resolution, key custody, issuance, revocation ordering, replay reservation, execution
claims, evidence appends, archive privileges, witnesses, readiness, transport authentication, and
host business authorization are required, but are owned by the private runtime or consuming host.
