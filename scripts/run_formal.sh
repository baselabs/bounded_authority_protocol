#!/usr/bin/env bash
# Formal-analysis re-run (ADR 0025): pinned ProVerif execution + three checks.
#
#   1. run the model and diff the RESULT lines against spec/formal/expected-summary.txt
#      (non-regression: a model edit changing any verdict line reds);
#   2. REQ-id coverage: every REQ1-* annotation in the model exists in the requirement map;
#   3. findings ledger: every F<n> entry in spec/formal/FINDINGS.md carries exactly one
#      terminal disposition (refuted | documented | escalated).
#
# Any escalated disposition is printed loudly: it blocks the program's done-claim until the
# owner rules (routed via SECURITY.md).
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL=spec/formal/proverif/bap-core.pv
SUMMARY=spec/formal/expected-summary.txt
LEDGER=spec/formal/FINDINGS.md
MAP=docs/design/requirement-map.md

fail=0

if ! command -v proverif >/dev/null 2>&1; then
  # The mix-quality invocation is optionally-skippable (the toolchain is opam-local and the
  # dedicated CI formal job is the fail-closed enforcement); a direct invocation fails closed.
  if [ "${BAP_FORMAL_OPTIONAL:-0}" = 1 ]; then
    echo "run_formal: SKIP — proverif not found (opam pin proverif.2.05); the CI formal-analysis job enforces this run"
    exit 0
  fi
  echo "run_formal: proverif not found (opam pin proverif.2.05; ADR 0025)" >&2
  exit 2
fi

# --- 1. non-regression summary diff -------------------------------------------
proverif "$MODEL" 2>&1 | grep -E '^RESULT' > /tmp/formal-results.txt || true
expected=$(grep -E '^RESULT' "$SUMMARY")
actual=$(cat /tmp/formal-results.txt)

if [ "$expected" != "$actual" ]; then
  echo "run_formal: FAILED — model output diverges from the frozen summary:" >&2
  diff <(echo "$expected") <(echo "$actual") >&2 || true
  fail=1
else
  echo "run_formal: summary ok ($(echo "$actual" | grep -c 'is true')/$(echo "$actual" | wc -l | tr -d ' ') queries true)"
  if echo "$actual" | grep -q 'cannot be proved'; then
    echo "run_formal: FAILED — at least one query is NOT proved" >&2
    fail=1
  fi
fi

# --- 2. REQ-id coverage --------------------------------------------------------
map_ids=$(grep -o 'REQ1-[A-Z0-9]*-[a-z0-9-]*' "$MAP" | sort -u)
# The pinned annotation set: the verifier steps whose requirement mapping is load-bearing for
# the model's claims. Dropping an annotation reds; adding a mapped one is fine.
PINNED="REQ1-CLAIM-ath REQ1-SIGNING-backend-reject REQ1-SIGNING-digest-prefix
REQ1-HEADER-thumbprint REQ1-HEADER-proof-jwk REQ1-VERIFY-grant-exact
REQ1-VERIFY-envelope-binding REQ1-VERIFY-facts-redacted REQ1-VERIFY-return-shape
REQ1-VERIFY-time-bounds REQ1-CLAIM-case-sensitive"
missing=0
for id in $(grep -o 'REQ1-[A-Z0-9]*-[a-z0-9-]*' "$MODEL" | sort -u); do
  if ! echo "$map_ids" | grep -qx "$id"; then
    echo "run_formal: FAILED — model annotates $id which is not in the requirement map" >&2
    missing=1
  fi
done
# Exact step-annotation form "(* <id> *)" — declaration prose that merely mentions ids does
# not satisfy the pin; the annotation must ride a code line.
for id in $PINNED; do
  if ! grep -q "(\* $id \*)" "$MODEL"; then
    echo "run_formal: FAILED — pinned annotation $id dropped from the model" >&2
    missing=1
  fi
done
[ "$missing" = 0 ] && echo "run_formal: coverage ok ($(grep -o 'REQ1-[A-Z0-9]*-[a-z0-9-]*' "$MODEL" | sort -u | wc -l | tr -d ' ') annotated ids all mapped; pinned set intact)"

# --- 3. findings ledger schema --------------------------------------------------
python3 - "$LEDGER" <<'PYEOF'
import re, sys
text = open(sys.argv[1]).read()
entries = re.findall(r'^## F\d+:.*?(?=^## |\Z)', text, re.S | re.M)
problems = []
escalated = 0
for e in entries:
    m = re.search(r'^- disposition:\s*(\w+)', e, re.M)
    if not m:
        problems.append("entry without disposition line: " + e.split("\n")[0])
    elif m.group(1) not in ("refuted", "documented", "escalated"):
        problems.append("non-terminal disposition: " + m.group(1))
    if m and m.group(1) == "escalated":
        escalated += 1
if problems:
    print("run_formal: FAILED — ledger schema violations:\n  " + "\n  ".join(problems), file=sys.stderr)
    sys.exit(1)
print(f"run_formal: ledger ok ({len(entries)} findings, all terminally dispositioned, {escalated} escalated)")
if escalated:
    print(f"run_formal: *** {escalated} ESCALATED finding(s) — BLOCKS the program done-claim until the owner rules (SECURITY.md routing) ***", file=sys.stderr)
PYEOF

exit $((fail + missing))
