# Errata registry

Numbered errata against published normative documents, per the governance policy (published in
[governance.md](governance.md); authoritative source in the
[standards track charter](design/standards-track.md) § Governance). An erratum may clarify prose,
correct non-normative text, or add conformance cases. **No erratum may change a conformance
verdict**: any change that would alter an accept/reject outcome is a contract-major change and
follows the evolution contract, never this registry.

Each entry records: number, date, affected document and versions, the correction, and its
conformance-corpus impact (which must be additive or none).

| # | Date | Document | Correction | Corpus impact |
|---|---|---|---|---|
| 1 | 2026-08-24 | `docs/protocol-v1.md` and the standalone/embedded selector schemas as published in package versions 0.1.0–0.1.2 | An `all` selector is valid on exactly the three recognized selector member sets; `path` and `value`/`values` are inert when present. No other member set is accepted. See ADR 0021. | None: corpus bytes, 283 verdicts, and the certified index SHA are unchanged. |
