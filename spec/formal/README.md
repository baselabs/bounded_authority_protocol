# Formal-analysis companions

- `attacker-model.md` — the attacker, properties P1-P4, and the symbolic assumptions; pinned to
  the spec Doc-Revision (spec-facts rule 8).
- `proverif/bap-core.pv` — the stateless-core model (ProVerif 2.05). Every verifier step
  carries its REQ id; the CI harness pins the critical annotations.
- `expected-summary.txt` — the frozen RESULT lines; the non-regression diff target.
- `FINDINGS.md` — the findings ledger. Every finding carries exactly one terminal disposition:
  `refuted`, `documented`, or `escalated`. An escalated finding routes to the owner via
  SECURITY.md and blocks the program's done-claim until ruled (ADR 0025).

Re-run locally: `scripts/run_formal.sh` (or `mix formal`), with ProVerif 2.05 on PATH
(`opam install proverif.2.05`).

Follow-on (not started): a Tamarin treatment of the chain/archive ORDERING surface — triggered
by the first ordering lemma need or an escalated finding requiring state reasoning (ADR 0025's
recorded trigger).
