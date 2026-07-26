# bounded_authority_protocol

Public Apache-2.0 protocol, deterministic verifier, and conformance suite for cryptographically
bounded proof-of-possession authority.

## Status

Repository initialization and the public/private boundary are active under
[`BAP-00`](docs/ROADMAP.md). The Mix package and protocol implementation are not yet available.
After the public remote and closeout gates are verified, `BAP-01` establishes the package, CI,
quality gates, and architecture tests before protocol behavior is implemented.

## Public contract

The planned library will provide:

- closed, versioned capability-grant and RFC 9449 DPoP data types;
- RFC 8785 JCS request digests and exact signing inputs;
- compact EdDSA grant and holder-proof decoding and verification;
- consumption-chain and archive verification;
- normative fixtures, independent conformance vectors, and a verifier CLI;
- fixed, value-free errors and explicit resource limits.

All verification inputs are explicit: already-trusted public key, expected audience and instance,
server-derived method, normalized URI, invocation ID, operation, cast arguments, evaluation time,
and limits. A successful result means only that the supplied bytes satisfy those supplied inputs.

The public package also exposes a bounded `untrusted_key_locator/2` preparse that returns only the
closed protected-header `kid` as an explicitly untrusted lookup hint. It never selects or marks a
key trusted. The stateful runtime combines that hint with its expected issuer context, resolves a
candidate-key snapshot, and verifies the complete envelope outside a database transaction. It then
opens the state transaction, re-resolves and locks the current key/revocation rows, requires the
same key fingerprint and current eligibility, and only then reserves replay or claims execution.

## Deliberate exclusions

This package does not discover trust, issue grants, hold keys, read a database, reserve replay,
check live revocation state, claim an execution, authorize a business effect, append outcomes or
consumptions, remove archived evidence, submit witnesses, or run an OTP service.

Those stateful responsibilities belong to the private
[`bounded_authority`](https://github.com/baselabs/bounded_authority) runtime. Product integration
belongs to the consuming host. QorPay and `Qorpay.ScopeAxis` are unchanged and are not protocol
compatibility targets.

## Dependency direction

```text
bounded_authority          -> bounded_authority_protocol
retired_private_consumer               -> beamline + bounded_authority + ash + ash_ai
bounded_authority_protocol -> no private or product package
```

See the [protocol charter](docs/design/protocol-charter.md), [threat model](docs/design/threat-model.md),
[conformance contract](docs/design/conformance-contract.md), and
[ADR 0001](docs/adr/0001-public-protocol-verifier-boundary.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
