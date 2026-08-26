# Formal-analysis findings ledger

Schema (checked by scripts/run_formal.sh; an entry violating it fails CI):

```
## F<n>: <one-line description>
- discovered: <where the finding surfaced>
- class: model | spec
- analysis: <what was investigated>
- disposition: refuted | documented | escalated
- resolution: <what closed it; for escalated: owner-routing via SECURITY.md — BLOCKS the
  program done-claim until the owner rules>
```

Exactly one terminal disposition per finding. `refuted` = a modeling error, closed by model
correction. `documented` = a spec edit citing the REQ id in the same slice (Doc-Revision bump).
`escalated` = a potential wire flaw: under zero-wire-change there is no in-program fix.

## Ledger

The first analysis run (proverif 2.05, model pinned to spec rev 1) proves all four properties
true; the model's load-bearing status is proven by mutation (removing the REQ1-CLAIM-ath check
makes P1 unprovable). Findings from that run:

## F1: the first model's P1 query correlated on the proof's own ath, not the presented grant
- discovered: model non-vacuity testing during the initial run
- class: model
- analysis: with the weak query, dropping the ath check left P1 provable — the correspondence
  could not see cross-grant replay because replicated grants were also byte-identical (the
  issuer process minted structurally equal terms). Two model defects, not spec defects: the
  event carried the attacker-influenceable value, and the issuer lacked per-issuance freshness
  (the wire's unique jti provides exactly that distinctness; REQ1-CLAIM-case-sensitive).
- disposition: refuted
- resolution: the verifier event now carries the digest of the grant IT was presented, and the
  issuer process takes a fresh seed per issuance. With both fixes the property holds and the
  ath-drop mutation makes it unprovable — the model catches cross-grant replay.

No open findings. No escalated findings.
