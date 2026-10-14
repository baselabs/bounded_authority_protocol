# Errata registry

Numbered errata against published normative documents, per the governance policy (published in
[governance.md](governance.md); authoritative source in the
[standards track charter](design/standards-track.md) § Governance). An erratum may clarify prose,
correct non-normative text, or add conformance cases. **No erratum may change a verdict of an
existing certified corpus**: any change that would alter such an accept/reject outcome is a
contract-major change and follows the evolution contract, never this registry. The one exception
is a soundness repair ([governance § Soundness repairs](governance.md#soundness-repairs),
[ADR 0040](adr/0040-strict-ed25519-soundness-erratum.md)): it changes verdicts only from accept to
reject on producer-impossible inputs, adds its cases in a new additive corpus, and leaves every
existing corpus verdict unchanged.

Each entry records: number, date, affected document and versions, the correction, and its
conformance-corpus impact (which must be additive or none).

| # | Date | Document | Correction | Corpus impact |
|---|---|---|---|---|
| 1 | 2026-08-24 | `docs/protocol-v1.md` and the standalone/embedded selector schemas as published in package versions 0.1.0–0.1.2 | An `all` selector is valid on exactly the three recognized selector member sets; `path` and `value`/`values` are inert when present. No other member set is accepted. See ADR 0021. | None: corpus bytes, 283 verdicts, and the certified index SHA are unchanged. |
| E-2026-09-17-1 | 2026-09-17 | README.md (published Hex 0.4.1) | The 0.4.1 package's README records checksum `8544a9ff…358a9` (the pre-publish `mix hex.build` inner-tar checksum) where the registry checksum belongs. The 0.4.1 registry checksum is `4648f545f681d540c965d460411133cf6188066439dbc37fc869288f9fcad1cf` (read back from the Hex release API); README on `main` is corrected. Consumers verify package identity against the registry, not the shipped README string. | none |
| 2 | 2026-10-12 | `spec/bap-v1.md`, `spec/bap-v2.md`, and the local-loopback, role-attestation, and content-assertion profile specifications, as published through package version 0.7.0 | Soundness repair (ADR 0040): Ed25519 verification is strict. Point encodings must be canonical, small-order keys and `R` values are rejected, `S` must be below the group order, and the cofactorless equation is mandatory; public keys must pass key acceptance; hosts must check torsion-freedom at enrollment, trust install, and deny-list comparison. See the security advisory. | Additive: the new `bap-strict-ed25519/1` corpus (2,410 cases; index SHA-256 `732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`). Every existing corpus index, its cases, and its verdicts are unchanged. |
| 3 | 2026-10-14 | `spec/bap-v1.md` § 16 (and its `docs/protocol-v1.md` view), `spec/bap-v2.md`, `spec/bap-v3.md` § 3.2, and the local-loopback, role-attestation, and content-assertion profile specifications, as published through package version 0.8.0 | Compact assembly and anchored-export encoding are producer surfaces: they frame a signature and verify none (§ 16 lists them among the public surfaces because they are public). Each MUST refuse a signature that no conforming signer emits: under contract-major 3, `r` or `s` outside `0 < r < n`, `0 < s ≤ ⌊n/2⌋`; under Ed25519, `S ≥ L`, or `R` non-canonical or of small order. Each MUST emit accepted signature bytes unchanged and never normalizes. Every BAP verifier already rejected these signatures, so no verification verdict changes. Requirement ids `REQ1-SIGNING-ed25519-producer-canonical`, `REQ2-SIGNING-ed25519-producer-canonical`, and `REQ3-SIGNING-producer-canonical`; the sibling profiles' assembly requirements carry the same clause. | Additive: the new `bap-producer-canonicality/1` corpus (75 cases; index SHA-256 `99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601`). Every existing corpus index, its cases, and its verdicts are unchanged. |
| 4 | 2026-10-14 | `spec/bap-v1.md` § 14.1 (and its `docs/protocol-v1.md` view), as published through package version 0.8.0 | Editorial: the torsion paragraph said one secret can sign under "up to eight distinct mixed-order encodings" of its key. The eight encodings `A + T` over the eight small-order points `T` include `T = O`, the prime-order key itself, so they are the prime-order key and up to seven mixed-order variants. The requirement (`REQ1-HOST-ed25519-torsion-free`) and every verdict are unchanged. | None: no corpus, case, or verdict changes. |
