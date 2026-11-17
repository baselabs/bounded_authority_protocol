# Formal-analysis companions

- `attacker-model.md` defines the attacker, properties P1-P4, and symbolic assumptions; pinned to
  the spec Doc-Revision (spec-facts rule 8).
- `proverif/bap-core.pv` contains the stateless-core model (ProVerif 2.05). Every verifier step
  carries its REQ id; the CI harness pins the critical annotations.
- `expected-summary.txt` contains the frozen RESULT lines used as the non-regression diff target.
- `FINDINGS.md` is the findings ledger. Every finding carries exactly one terminal disposition:
  `refuted`, `documented`, or `escalated`. An escalated finding routes to the owner via
  SECURITY.md and blocks the program's done-claim until ruled.

Re-run locally: `scripts/run_formal.sh` (or `mix formal`), with ProVerif 2.05 on PATH
(`opam install proverif.2.05`).

Follow-on (not started): a Tamarin treatment of the chain/archive ORDERING surface, triggered
by the first ordering lemma need or an escalated finding requiring state reasoning.
