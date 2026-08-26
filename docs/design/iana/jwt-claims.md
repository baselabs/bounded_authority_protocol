# JWT Claims Registry — ready-to-file entries

Rendered from `jwt-claims.json` (the machine-readable source; rule 7 of the spec-facts
gate proves the source agrees with `docs/design/registries.md` exactly). Filing is
externally gated.

## Claim Name: `ba_inv` (active)

- **Claim Description:** Invocation UUID
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), Claims section

## Claim Name: `ba_op` (active)

- **Claim Description:** Operation name
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), Claims section

## Claim Name: `ba_req` (active)

- **Claim Description:** Request digest
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), Signing and digest inputs section

## Claim Name: `ba_dlg` (reserved)

- **Claim Description:** Delegation parent-grant hash (reserved)
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), typ registry section

  (Reserved by this profile; NOT filed with IANA until its activating
  contract-major.)

## Claim Name: `ba_offline` (reserved)

- **Claim Description:** Offline floor limits (reserved)
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), typ registry section

  (Reserved by this profile; NOT filed with IANA until its activating
  contract-major.)

## Claim Name: `ba_sut` (reserved)

- **Claim Description:** Suite-attestation payload binding (reserved)
- **Change Controller:** IETF
- **Reference:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile), typ registry section

  (Reserved by this profile; NOT filed with IANA until its activating
  contract-major.)
