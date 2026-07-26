# Conformance contract

## Normative artifacts

Each released protocol major ships language-neutral JSON fixtures containing:

- exact input bytes and explicit verification context;
- exact canonical/signing/digest bytes where applicable;
- expected closed verified output or fixed error code;
- valid boundary-near cases;
- invalid duplicate, encoding, algorithm, key, claim, binding, limit, truncation, reorder,
  omission, and meaningful-byte tamper cases.

Fixtures contain public keys only and no production values. Their schema and ordering are
versioned with the protocol major.

The manifest's public test-key fingerprint set must equal, not merely contain, the fingerprints of
every key reachable from vectors, fixtures, generators, and the independent implementation. A
corpus gate derives both sets independently, compares them exactly, and is tamper-proved by
removing one listed fingerprint while leaving its keyed fixture reachable.

## Independent implementation rule

A vector is normative only after a second implementation, built without importing this library,
produces or verifies the exact bytes and verdict. A self-round-trip proves only internal
consistency.

## Public verifier API constraints

Conforming APIs:

- expose a separately bounded `untrusted_key_locator/2` returning only an explicitly untrusted
  closed `kid` hint, with duplicate/encoding/size failures mapped to `:invalid`;
- accept explicit public keys, expected context, evaluation time, and limits;
- return closed verified values or fixed errors;
- perform no I/O, trust discovery, randomness, clock reads, replay/state checks, or effects;
- reject unknown extensions and ambiguous encodings;
- expose the protocol major in all verified outputs.

## Nonconforming claims

Passing the public vectors does not certify live revocation, replay prevention, key custody,
issuance, database correctness, evidence durability, archive deletion, witnesses, transport
authentication, host policy, or business-effect safety. Those require separate runtime
conformance and operational testing.

The normative successful result is `EnvelopeFacts` with `authorization: :not_evaluated`, redacted
inspection, and no generic encoder. The only production invalid result is `{:error, :invalid}`;
diagnostic vector tooling may classify failures offline but those classes cannot widen the runtime
surface.
