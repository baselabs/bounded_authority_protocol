# Media type registrations — ready-to-file entries

Rendered from `media-types.json` (RFC 6838 section 5.6 field order). The wire `typ`
header values are unchanged; the media-type namespace is distinct from the wire `typ`.
Filing is externally gated.

## application/ba-cap+jwt (active)

- **Type name:** application
- **Subtype name:** ba-cap+jwt
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Compact JWS (RFC 7515) serialization of a closed JSON object; UTF-8; base64url segments; binary-safe
- **Security considerations:** See the Security Considerations of the Bounded Authority Protocol v1 Wire Profile
- **Interoperability considerations:** The payload is a closed profile; unknown members are non-conforming
- **Published specification:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile)
- **Applications that use this media type:** Bounded proof-of-possession authority verification
- **Fragment identifier considerations:** N/A
- **Intended usage:** LIMITED USE
- **Restrictions on usage:** None
- **Author:** Bounded Authority Protocol maintainers
- **Change controller:** Bounded Authority Protocol maintainers
- **Wire `typ`:** `ba+cap`

## application/ba-chain-anchor+jwt (active)

- **Type name:** application
- **Subtype name:** ba-chain-anchor+jwt
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Compact JWS (RFC 7515) serialization of a closed JSON object; UTF-8; base64url segments; binary-safe
- **Security considerations:** See the Security Considerations of the Bounded Authority Protocol v1 Wire Profile
- **Interoperability considerations:** The payload is a closed profile; unknown members are non-conforming
- **Published specification:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile)
- **Applications that use this media type:** Signed consumption-chain boundary anchors
- **Fragment identifier considerations:** N/A
- **Intended usage:** LIMITED USE
- **Restrictions on usage:** None
- **Author:** Bounded Authority Protocol maintainers
- **Change controller:** Bounded Authority Protocol maintainers
- **Wire `typ`:** `ba+chain-anchor`

## application/ba-key-transition+jwt (active)

- **Type name:** application
- **Subtype name:** ba-key-transition+jwt
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Compact JWS (RFC 7515) serialization of a closed JSON object; UTF-8; base64url segments; binary-safe
- **Security considerations:** See the Security Considerations of the Bounded Authority Protocol v1 Wire Profile
- **Interoperability considerations:** The payload is a closed profile; unknown members are non-conforming
- **Published specification:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile)
- **Applications that use this media type:** Authenticated historical-key transitions
- **Fragment identifier considerations:** N/A
- **Intended usage:** LIMITED USE
- **Restrictions on usage:** None
- **Author:** Bounded Authority Protocol maintainers
- **Change controller:** Bounded Authority Protocol maintainers
- **Wire `typ`:** `ba+key-transition`

## application/ba-cap-delegated+jwt (reserved)

- **Type name:** application
- **Subtype name:** ba-cap-delegated+jwt
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Compact JWS (RFC 7515) serialization of a closed JSON object
- **Security considerations:** See the Security Considerations of the Bounded Authority Protocol v1 Wire Profile
- **Interoperability considerations:** Reserved for a successor contract-major; not currently registered
- **Published specification:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile)
- **Applications that use this media type:** Delegated attenuated grants (successor contract-major)
- **Fragment identifier considerations:** N/A
- **Intended usage:** LIMITED USE
- **Restrictions on usage:** Reserved
- **Author:** Bounded Authority Protocol maintainers
- **Change controller:** Bounded Authority Protocol maintainers
- **Wire `typ`:** `ba+cap-delegated`

  (Reserved for a successor contract-major; NOT filed.)

## application/ba-suite-attestation+jwt (reserved)

- **Type name:** application
- **Subtype name:** ba-suite-attestation+jwt
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Compact JWS (RFC 7515) serialization of a closed JSON object
- **Security considerations:** See the Security Considerations of the Bounded Authority Protocol v1 Wire Profile
- **Interoperability considerations:** Reserved for a successor contract-major; not currently registered
- **Published specification:** spec/bap-v1.md (Bounded Authority Protocol v1 Wire Profile)
- **Applications that use this media type:** Cross-suite content-covering countersignatures (successor contract-major)
- **Fragment identifier considerations:** N/A
- **Intended usage:** LIMITED USE
- **Restrictions on usage:** Reserved
- **Author:** Bounded Authority Protocol maintainers
- **Change controller:** Bounded Authority Protocol maintainers
- **Wire `typ`:** `ba+suite-attestation`

  (Reserved for a successor contract-major; NOT filed.)
