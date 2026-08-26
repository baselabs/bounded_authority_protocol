# IANA registration templates (ready-to-file sources)

This directory holds the machine-readable sources and rendered ready-to-file markdown for the
IANA registrations named by the specification's IANA considerations section. **Filing is
externally gated** (the BAP-08 official-submission preconditions) — these templates make the
package readiness verifiable in-repo; they make no submission claim.

Contents:

- `jwt-claims.json` — the machine-readable source for the JSON Web Token Claims Registry
  entries. `active` entries are ready to file (Claim Name / Description / Change Controller /
  Reference, per that registry's published format and its Specification Required policy).
  `reserved` entries are NOT filed: they are the profile's reserved names, recorded here so the
  registries document and the templates cannot drift apart (the spec-facts gate's rule 7
  enforces the exact match). `ba_obo` is reserved in the registries document WITHOUT an IANA
  template by design (an issuer-asserted principal identifier with no wire presence in any
  current or named-future profile section).
- `media-types.json` — the machine-readable source for the `application/*+jwt` media type
  registrations, one entry per RFC 6838 section 5.6 field set. The drafted `ba+*` `typ` values
  are NOT registrable as-is (`+cap` is not a registered structured suffix; `+jwt` is), so the
  media types register under the `application/ba-<name>+jwt` forms below. **The wire `typ`
  header values are unchanged** — zero wire change; the media-type name and the wire `typ` are
  related but distinct namespaces.
- `jwt-claims.md` / `media-types.md` — the rendered ready-to-file forms.

Regeneration: the markdown renders are derived from the JSON sources by hand-authoring rules
(one line/section per source field); the spec-facts gate (rule 7) proves the SOURCES agree with
`docs/design/registries.md` exactly (names, statuses, purposes) in both directions. The
rendered markdown is reviewed with the sources at every change.
