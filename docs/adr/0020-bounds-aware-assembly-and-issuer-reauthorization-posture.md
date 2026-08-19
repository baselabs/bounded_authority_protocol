# ADR 0020: Bounds-aware assembly and issuer-mediated reauthorization posture

- Status: accepted
- Date: 2026-08-19
- Track: T2
- Refines: [ADR 0008](0008-release-candidate-contract.md) (additive public API lock),
  [ADR 0010](0010-delegation-with-attenuation.md) (current-major versus successor-major boundary),
  [ADR 0018](0018-sdk-bounds-contract.md) (assembly bounds parity)

## Context

The runtime assembly primitive already accepts caller-tightenable bounds and applies them to the
encoded protected/payload segments, final compact size, and kind-specific reparse. The public Elixir
facade exposed only `assemble_compact/2`, hardwiring `%{}` and preventing a consumer from using the
same resolved bounds for signing-input production and assembly. The three verifier SDKs already
closed the corresponding divergence with an optional bounds argument.

The connected authority design also needs a precise current-major posture. A private authority may
compare a requested child against an existing grant and, as the original issuer, issue a new
current-v1 `ba+cap` to a different holder. That operational relationship must not be confused with
ADR 0010's portable holder-signed delegation protocol.

## Decision

1. Add `BoundedAuthorityProtocol.V1.assemble_compact/3`. It delegates directly to the existing
   `Runtime.assemble_compact/3`; the public facade adds no second bounds implementation.
2. Retain `assemble_compact/2` exactly as `/3` with `%{}`. Equal effective bounds produce equal
   bytes for all four current-v1 signing kinds: grant, proof, boundary anchor, and key transition.
3. Bounds remain local resource ceilings. This addition changes no protected header, claim,
   signature input, compact byte, maximum, or verification verdict. The portable corpus therefore
   remains unchanged; native facade tests and the unpacked-package consumer exercise the new arity.
4. A stateful authority MAY issue an independently valid, nonwidening current-v1 `ba+cap` to a new
   holder after applying its own policy and live-state checks. BAP supplies deterministic assembly
   only; it does not compare parent and child, select keys, issue, store lineage, revoke, or grant
   operational authority.
5. Such a child compact carries no parent reference and proves no lineage offline. It verifies as
   an ordinary issuer-signed grant. Any parent-child edge, ancestor-revocation rule, depth/fan-out
   policy, and audit binding are private-runtime state and require online enforcement.
6. The current v1 profile continues to reject `ba_dlg` and `ba+cap-delegated`. Holder-signed,
   cryptographically parent-bound delegation remains the successor-contract-major mechanism in
   ADR 0010. This ADR does not activate or partially implement it.

## Alternatives considered

- **Make bounds required by changing `/2`.** Rejected: it breaks the locked candidate API when an
  additive arity preserves the existing maximum-default contract.
- **Reimplement assembly checks in the facade.** Rejected: duplicated validation would drift from
  the runtime primitive and could silently omit a kind or ceiling.
- **Put operational lineage into current-v1 claims.** Rejected: it changes the closed wire profile
  and would partially activate the successor-major delegation design without its chain verifier.
- **Describe issuer-mediated reauthorization as portable delegation.** Rejected: the child bytes
  contain no parent proof, so an offline verifier cannot establish ancestry or ancestor revocation.

## Consequences

- Consumers can resolve one bounds value and use it for signing-input production and assembly.
- Existing `/2` consumers retain identical bytes and behavior.
- The facade export lock, normative API listing, release-candidate contract, package consumer, and
  changelog carry the additive arity in the same landing.
- Current-major issuer-mediated children are intentionally online-governed; ADR 0010 remains the
  only design for portable holder-signed delegation.
