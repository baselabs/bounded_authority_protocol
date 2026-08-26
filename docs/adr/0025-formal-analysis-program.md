# ADR 0025: The formal-analysis program

- Status: accepted
- Date: 2026-08-26

## Context

BAP is a payment-grade authorization protocol candidate: its binding claims (a proof binds one
grant, one request, one context) are exactly the class of property formal analysis exists to
check beyond test coverage. The corpus proves input-output behavior on 283 cases and the
mutation gates prove the checks load-bearing; neither proves the ABSENCE of an interleaving or
confusion the case set did not think of.

The tool decision had open evidence: no published machine-checked formal model of a DPoP-family
protocol exists (the FAPI 2.0 CCS 2024 analysis explicitly defers formal models to future
work), so the choice could not be made by precedent.

## Decision

1. **ProVerif** is the standing tool: automation fit on a stateless core (the verification
   surfaces are pure functions — no persistent state to model), first-class Dolev-Yao
   attacker, and query-based property checking match P1-P4 directly. **Tamarin** is the named
   follow-on, on a recorded trigger: the first need for a chain/archive ORDERING lemma or a
   genuine timepoint argument (Tamarin's loop detection and dense time are the fit there;
   ProVerif's abstraction is not).
2. **The model and its companion posture**: `spec/formal/proverif/bap-core.pv` models the
   stateless core; `spec/formal/attacker-model.md` records the attacker, the properties, and
   the symbolic assumptions (perfect cryptography; time abstracted to ordered predicates;
   canonicalization as injective encoding — sound because the typed projection is a free term
   algebra). Both are pinned to the specification's Doc-Revision; the spec-facts gate's rule 8
   reds if either side drifts alone.
3. **Standing CI posture**: a pinned ProVerif re-run job diffs the tool's summary against
   `spec/formal/expected-summary.txt` (all P1-P4 queries proven true), and a coverage check
   asserts every modeled step name appears in the requirement map's id set — the model cannot
   silently model something the requirements do not name, or vice versa. Local re-run:
   `scripts/run_formal.sh`.
4. **Findings-ledger disposition contract** (`spec/formal/FINDINGS.md`): every finding gets
   exactly ONE terminal disposition — `refuted` (a modeling error, closed by model
   correction), `documented` (a spec edit citing the REQ id, same slice, Doc-Revision bump),
   or `escalated` (a potential wire flaw). Under the program's zero-wire-change contract
   there is no in-program fix for an escalated finding: it routes to the owner via
   SECURITY.md and **blocks the program's done-claim until the owner rules**. The coupling is
   stated here rather than hidden in a risk block.
5. **Tool decision recorded as decided-with-open-evidence**: the absence of a published
   DPoP-family machine-checked model is the recorded evidence gap; the revisit triggers are
   the Tamarin trigger above, the next OAuth-family RFC shipping a formal appendix, and any
   escalated finding whose resolution needs state reasoning.

## Consequences

- The binding properties carry machine-checked proofs at every CI run; the archive-ordering
  surface stays corpus-proven until its trigger fires.
- A formal finding is engineering work (refuted/documented) or an owner decision (escalated) —
  never prose.
- The model adds no wire surface, dependency, or runtime behavior; it is a companion artifact
  pinned to the spec revision.
